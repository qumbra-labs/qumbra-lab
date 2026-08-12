//! The wallet directory: a seed file and an index cursor, nothing else.
//!
//! ```text
//!   <dir>/wallet.seed     33 bytes: [mnemonic-format version, 32B entropy], 0600
//!   <dir>/addresses.v1    text: the allocated diversifier INDICES
//! ```
//!
//! **The plain 33 bytes above are still the only format this binary reads or
//! writes** (issue #348). What changed is what it says about a file that is
//! *not* those 33 bytes: [`crate::envelope`] reserves a self-describing header,
//! so a second format — the desktop shell's key-store wrap, a passphrase
//! fallback — is refused **by name and platform** instead of being reported as a
//! damaged wallet. See [`WalletDir::open`].
//!
//! **The position (task-book item 1): the CLI persists indices, not
//! diversifiers.** A diversifier is index-deterministic
//! (`Wallet::diversifier_at_index`, issue #43's managed rule), so the address
//! file is a cursor, not state — losing it costs a re-derivation of indices
//! `0..N`, never funds, and there is no byte format to migrate. Both files are
//! versioned and reject-unknown, the same persistence discipline as the node's.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qlab_wallet::Wallet;

pub const SEED_FILE: &str = "wallet.seed";
pub const ADDR_FILE: &str = "addresses.v1";
const ADDR_HEADER: &str = "qumbra-wallet addresses v1";

/// The HD account this CLI derives. 0 is the conventional primary wallet
/// (the faucet deliberately uses 1 for the same constant's opposite reason).
pub const HD_ACCOUNT: u32 = 0;

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// Refusal to overwrite key material — move it aside first.
    SeedExists(PathBuf),
    /// No wallet here: `keygen` or `restore` first.
    NoWallet(PathBuf),
    /// A seed file whose length or version this binary does not know. Never
    /// guessed at, never migrated silently.
    ///
    /// **This variant means DAMAGED**, and its remedy is restore-from-mnemonic.
    /// A record that is merely unopenable here gets one of the two variants
    /// below instead — never this one (issue #348).
    BadSeedFile(String),
    /// A well-formed seed envelope wrapped by a key store this binary cannot
    /// unwrap. **Not a damaged file**: the record is intact and this machine is
    /// simply not the one that can open it.
    SeedWrappedElsewhere { format: &'static str, protection: &'static str },
    /// A well-formed seed envelope carrying a format or protection id this
    /// binary does not know. **Not a damaged file**: it was written by a newer
    /// tool, and reject-unknown is the house rule for every versioned format
    /// here.
    SeedFromNewerTool { format: u8, protection: u8 },
    /// An address file with an unknown header or an unparsable line.
    BadAddrFile(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "{e}"),
            StoreError::SeedExists(p) => write!(
                f,
                "{} already exists. Refusing to overwrite key material — move it aside first.",
                p.display()
            ),
            StoreError::NoWallet(p) => write!(
                f,
                "no wallet at {} (missing {SEED_FILE}). Run `qumbra-wallet keygen` or `restore`.",
                p.display()
            ),
            StoreError::BadSeedFile(why) => write!(f, "unreadable seed file: {why}"),
            // The two vocabularies issue #348 exists for. Neither says
            // "unreadable" and neither suggests restoring from the mnemonic:
            // damaged ⇒ restore, wrapped ⇒ elsewhere, and telling a user with an
            // intact wallet to restore it is the confusion this replaces.
            StoreError::SeedWrappedElsewhere { format, protection } => write!(
                f,
                "this seed file is wrapped by {protection} (envelope format `{format}`), and \
                 this binary has no unwrap support for it. The wallet itself is fine and this \
                 file is NOT damaged — open it with a build that can unwrap {protection}, on \
                 the machine that wrapped it."
            ),
            StoreError::SeedFromNewerTool { format, protection } => write!(
                f,
                "this seed file was written by a newer tool: envelope format id {format}, \
                 protection id {protection}. This binary knows format ids [{}] and protection \
                 ids [{}]. The file is NOT damaged and NOT corrupt — open it with the tool that \
                 wrote it, or upgrade this one.",
                crate::envelope::known_format_ids(),
                crate::envelope::known_protection_ids(),
            ),
            StoreError::BadAddrFile(why) => write!(f, "unreadable address file: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// An open wallet directory: the seed, and the allocated address indices.
pub struct WalletDir {
    pub dir: PathBuf,
    pub seed: MasterSeed,
    /// Allocated diversifier indices, ascending, no duplicates.
    pub allocated: Vec<u64>,
}

impl WalletDir {
    /// Create a fresh wallet dir around `seed`, allocating index 0. Refuses an
    /// existing seed file — this function never overwrites key material.
    pub fn create(dir: &Path, seed: MasterSeed) -> Result<WalletDir, StoreError> {
        let seed_path = dir.join(SEED_FILE);
        if seed_path.exists() {
            return Err(StoreError::SeedExists(seed_path));
        }
        std::fs::create_dir_all(dir)?;
        let mut bytes = Vec::with_capacity(1 + ENTROPY_LEN);
        bytes.push(seed.version());
        bytes.extend_from_slice(seed.entropy());
        write_secret(&seed_path, &bytes)?;
        let w = WalletDir { dir: dir.to_path_buf(), seed, allocated: vec![0] };
        w.save_addresses()?;
        Ok(w)
    }

    /// Open an existing wallet dir, verifying both files' versions.
    pub fn open(dir: &Path) -> Result<WalletDir, StoreError> {
        let seed_path = dir.join(SEED_FILE);
        if !seed_path.exists() {
            return Err(StoreError::NoWallet(dir.to_path_buf()));
        }
        let bytes = std::fs::read(&seed_path)?;
        if bytes.len() != 1 + ENTROPY_LEN {
            // The ONE extra branch of issue #348. The plain path below is
            // untouched and unreachable from here, so a valid seed file cannot
            // enter the envelope check — see `envelope`'s collision note.
            return Err(not_the_plain_format(&bytes));
        }
        let mut entropy = [0u8; ENTROPY_LEN];
        entropy.copy_from_slice(&bytes[1..]);
        // The version gate, explicit (#246 finding): a mnemonic round-trip does
        // NOT validate this byte — the phrase carries entropy+checksum only and
        // decodes at the CURRENT version. The byte is a derivation-domain
        // separator, so a wrong byte silently derives a DIFFERENT wallet, which
        // a user reads as vanished funds. Compare, don't round-trip.
        if bytes[0] != qlab_wallet::seed::SEED_VERSION {
            return Err(StoreError::BadSeedFile(format!(
                "version {} refused: this binary derives at version {} only, and a \
                 different byte would silently derive a different wallet",
                bytes[0],
                qlab_wallet::seed::SEED_VERSION
            )));
        }
        let seed = MasterSeed::with_version(bytes[0], entropy);

        Self::from_seed_and_cursor(dir, seed)
    }

    /// Open a wallet whose seed file is a registered wrapped envelope, using
    /// seed material already authenticated and decrypted by its platform
    /// provider.
    ///
    /// This is deliberately not a generic "override the seed" seam: a plain,
    /// damaged, truncated, or unknown envelope is refused. The provider owns
    /// ciphertext authentication and must only pass the plaintext recovered
    /// from this directory's envelope. The core continues to own seed-version
    /// validation, the address cursor, and all derivation.
    pub fn open_wrapped(dir: &Path, seed: MasterSeed) -> Result<WalletDir, StoreError> {
        let seed_path = dir.join(SEED_FILE);
        if !seed_path.exists() {
            return Err(StoreError::NoWallet(dir.to_path_buf()));
        }
        let bytes = std::fs::read(&seed_path)?;
        if bytes.len() == 1 + ENTROPY_LEN {
            return Err(StoreError::BadSeedFile(
                "an external unwrap provider cannot override a plain seed file".to_string(),
            ));
        }
        match crate::envelope::inspect(&bytes) {
            crate::envelope::Verdict::Wrapped { .. } => {}
            crate::envelope::Verdict::NotAnEnvelope
            | crate::envelope::Verdict::TruncatedHeader { .. }
            | crate::envelope::Verdict::Unknown { .. } => return Err(not_the_plain_format(&bytes)),
        }
        if seed.version() != qlab_wallet::seed::SEED_VERSION {
            return Err(StoreError::BadSeedFile(format!(
                "unwrapped version {} refused: this binary derives at version {} only",
                seed.version(),
                qlab_wallet::seed::SEED_VERSION
            )));
        }

        Self::from_seed_and_cursor(dir, seed)
    }

    fn from_seed_and_cursor(dir: &Path, seed: MasterSeed) -> Result<WalletDir, StoreError> {
        let allocated = match std::fs::read_to_string(dir.join(ADDR_FILE)) {
            Ok(text) => parse_addresses(&text)?,
            // A missing cursor is not an error — it is index 0, the same state
            // a restore lands in. Addresses are derivable; the file is comfort.
            Err(e) if e.kind() == io::ErrorKind::NotFound => vec![0],
            Err(e) => return Err(e.into()),
        };
        Ok(WalletDir {
            dir: dir.to_path_buf(),
            seed,
            allocated,
        })
    }

    pub fn wallet(&self) -> Wallet {
        Wallet::from_master_seed(&self.seed, HD_ACCOUNT)
    }

    /// Allocate the next index, persist, and return it.
    pub fn allocate_next(&mut self) -> Result<u64, StoreError> {
        let next = self.allocated.iter().max().map(|m| m + 1).unwrap_or(0);
        self.allocated.push(next);
        self.save_addresses()?;
        Ok(next)
    }

    fn save_addresses(&self) -> Result<(), StoreError> {
        let mut text = String::from(ADDR_HEADER);
        text.push('\n');
        for i in &self.allocated {
            text.push_str(&i.to_string());
            text.push('\n');
        }
        std::fs::write(self.dir.join(ADDR_FILE), text)?;
        Ok(())
    }
}

/// Decide what a seed file that is **not** the plain length actually is
/// (issue #348). Three vocabularies, held to the standard of the version gate
/// above:
///
/// * no magic ⇒ today's corrupt/truncated message, **verbatim** — a clobbered
///   or half-written plain file is still the common case and its remedy is
///   unchanged;
/// * a nameable envelope ⇒ refused by format and platform, never as damage;
/// * an envelope from a registry this binary does not have ⇒ "a newer tool".
///
/// Refusal strings are contract in this crate and all three are test-locked.
fn not_the_plain_format(bytes: &[u8]) -> StoreError {
    use crate::envelope::{self, Verdict};
    match envelope::inspect(bytes) {
        // Unchanged, deliberately including the "exactly one format" clause:
        // this binary can still open exactly one format, and the file in hand
        // is not an envelope claiming otherwise.
        Verdict::NotAnEnvelope => StoreError::BadSeedFile(format!(
            "{} bytes; this binary knows exactly one format: 1 version byte + {ENTROPY_LEN} \
             entropy bytes",
            bytes.len()
        )),
        // Damaged, like the arm above — but it can say more, because the magic
        // survived and the header did not. A record too short to name itself is
        // not recoverable from itself, so the mnemonic is the remedy.
        Verdict::TruncatedHeader { len } => StoreError::BadSeedFile(format!(
            "{len} bytes: the Qumbra seed-envelope magic followed by too few bytes to carry its \
             {}-byte header, so this record cannot even name itself. That is damage, not a \
             format this binary lacks — restore from the mnemonic",
            envelope::HEADER_LEN
        )),
        Verdict::Wrapped { format, protection } => {
            StoreError::SeedWrappedElsewhere { format, protection }
        }
        Verdict::Unknown { format, protection } => {
            StoreError::SeedFromNewerTool { format, protection }
        }
    }
}

fn parse_addresses(text: &str) -> Result<Vec<u64>, StoreError> {
    let mut lines = text.lines();
    match lines.next() {
        Some(h) if h == ADDR_HEADER => {}
        other => {
            return Err(StoreError::BadAddrFile(format!(
                "header {other:?}; this binary knows `{ADDR_HEADER}` only"
            )))
        }
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let idx: u64 = line
            .parse()
            .map_err(|_| StoreError::BadAddrFile(format!("not an index: {line:?}")))?;
        if out.contains(&idx) {
            return Err(StoreError::BadAddrFile(format!("duplicate index {idx}")));
        }
        out.push(idx);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.sort_unstable();
    Ok(out)
}

/// Write a file with owner-only permissions where the platform has them —
/// the faucet's `write_secret`, kept identical on purpose.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if path.exists() {
        return Err(StoreError::SeedExists(path.to_path_buf()));
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Read a mnemonic phrase from a reader (stdin in the binary — NEVER argv),
/// mapping every mnemonic-layer refusal to the one message that matters: this
/// wordlist is deliberately not BIP-39.
pub fn seed_from_phrase(reader: &mut impl Read) -> Result<MasterSeed, StoreError> {
    let mut phrase = String::new();
    reader.read_to_string(&mut phrase)?;
    let phrase = phrase.trim();
    MasterSeed::from_mnemonic(phrase).map_err(|e| {
        StoreError::BadSeedFile(format!(
            "not a Qumbra mnemonic ({e:?}). Note: Qumbra's wordlist is deliberately NOT BIP-39 \
             (lab PR #44) — a phrase from another wallet cannot restore here, and this tool will \
             not guess at near-matches."
        ))
    })
}

/// The mnemonic for `backup --reveal` — the ONLY function in this crate that
/// returns key material as a string, and `main` prints it exactly once behind
/// the flag.
pub fn reveal_mnemonic(w: &WalletDir) -> String {
    w.seed.to_mnemonic()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_wallet_{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn keygen_restore_roundtrip_reproduces_address_zero() {
        let d1 = tmp("rt1");
        let entropy = [7u8; ENTROPY_LEN];
        let w1 = WalletDir::create(&d1, MasterSeed::from_entropy(entropy)).unwrap();
        let addr1 = w1.wallet().address_at_index(0).encode();
        let phrase = reveal_mnemonic(&w1);

        let d2 = tmp("rt2");
        let seed2 = seed_from_phrase(&mut phrase.as_bytes()).unwrap();
        let w2 = WalletDir::create(&d2, seed2).unwrap();
        assert_eq!(w2.wallet().address_at_index(0).encode(), addr1);
        assert_eq!(w2.seed.entropy(), &entropy, "the mnemonic carries the whole seed");
    }

    #[test]
    fn a_bip39_phrase_is_refused_and_the_refusal_says_why() {
        // The canonical BIP-39 test phrase — MUST NOT restore here.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        let e = seed_from_phrase(&mut phrase.as_bytes()).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("NOT BIP-39"), "{msg}");
        assert!(msg.contains("will not guess"), "{msg}");
    }

    #[test]
    fn the_seed_file_is_0600_and_never_overwritten() {
        let d = tmp("perm");
        let w = WalletDir::create(&d, MasterSeed::from_entropy([1; ENTROPY_LEN])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(SEED_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only");
        }
        let again = WalletDir::create(&d, MasterSeed::from_entropy([2; ENTROPY_LEN]));
        assert!(matches!(again, Err(StoreError::SeedExists(_))));
        drop(w);
    }

    #[test]
    fn the_address_cursor_survives_reopen_and_its_loss_is_only_a_cursor() {
        let d = tmp("cursor");
        let mut w = WalletDir::create(&d, MasterSeed::from_entropy([3; ENTROPY_LEN])).unwrap();
        assert_eq!(w.allocated, vec![0]);
        assert_eq!(w.allocate_next().unwrap(), 1);
        assert_eq!(w.allocate_next().unwrap(), 2);

        let re = WalletDir::open(&d).unwrap();
        assert_eq!(re.allocated, vec![0, 1, 2]);
        // Same index, same address, ledger or no ledger — the derivation is the truth.
        assert_eq!(
            re.wallet().address_at_index(2).encode(),
            w.wallet().address_at_index(2).encode()
        );

        // Deleting the cursor loses nothing but the cursor.
        std::fs::remove_file(d.join(ADDR_FILE)).unwrap();
        let re2 = WalletDir::open(&d).unwrap();
        assert_eq!(re2.allocated, vec![0], "back to index 0 — funds unaffected");
    }

    #[test]
    fn an_unknown_file_version_is_refused_not_guessed() {
        let d = tmp("ver");
        WalletDir::create(&d, MasterSeed::from_entropy([4; ENTROPY_LEN])).unwrap();
        std::fs::write(d.join(ADDR_FILE), "qumbra-wallet addresses v9\n0\n").unwrap();
        assert!(matches!(WalletDir::open(&d), Err(StoreError::BadAddrFile(_))));

        std::fs::write(d.join(ADDR_FILE), format!("{ADDR_HEADER}\n0\n")).unwrap();
        let mut seed = std::fs::read(d.join(SEED_FILE)).unwrap();
        seed.push(0xFF);
        std::fs::remove_file(d.join(SEED_FILE)).unwrap();
        std::fs::write(d.join(SEED_FILE), seed).unwrap();
        assert!(matches!(WalletDir::open(&d), Err(StoreError::BadSeedFile(_))));
    }

    #[test]
    fn a_flipped_version_byte_is_refused_not_silently_a_different_wallet() {
        // The #246 finding: length-preserving corruption of byte[0] must be a
        // named refusal — with_version derives DIFFERENT keys per byte, so a
        // pass here would render someone's funds as vanished.
        let d = tmp("verbyte");
        WalletDir::create(&d, MasterSeed::from_entropy([5; ENTROPY_LEN])).unwrap();
        let mut seed = std::fs::read(d.join(SEED_FILE)).unwrap();
        seed[0] = 0xEE;
        std::fs::remove_file(d.join(SEED_FILE)).unwrap();
        std::fs::write(d.join(SEED_FILE), seed).unwrap();
        let e = match WalletDir::open(&d) {
            Err(e) => e,
            Ok(_) => panic!("a flipped version byte must be refused"),
        };
        let msg = e.to_string();
        assert!(msg.contains("version 238 refused"), "{msg}");
        assert!(msg.contains("different wallet"), "{msg}");
    }

    // ---- issue #348: the reserved envelope, one test per arm ----------------

    /// Overwrite the seed file in an existing wallet dir. `create` refuses to
    /// touch key material, so the bad bytes go in by hand — exactly how a real
    /// second-format file would arrive: written by another tool.
    fn put_seed(dir: &Path, bytes: &[u8]) {
        let p = dir.join(SEED_FILE);
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, bytes).unwrap();
    }

    fn wallet_dir_with_seed_bytes(tag: &str, bytes: &[u8]) -> PathBuf {
        let d = tmp(tag);
        WalletDir::create(&d, MasterSeed::from_entropy([9; ENTROPY_LEN])).unwrap();
        put_seed(&d, bytes);
        d
    }

    /// `Result::unwrap_err` wants `Debug` on the Ok side, and `WalletDir`
    /// deliberately has none — it holds key material and must never be
    /// formattable into a log or a panic message.
    fn open_err(dir: &Path) -> StoreError {
        match WalletDir::open(dir) {
            Err(e) => e,
            Ok(_) => panic!("this seed file must be refused, not opened"),
        }
    }

    fn open_wrapped_err(dir: &Path, seed: MasterSeed) -> StoreError {
        match WalletDir::open_wrapped(dir, seed) {
            Err(e) => e,
            Ok(_) => panic!("the external seed provider must not open this seed file"),
        }
    }

    fn envelope_bytes(format: u8, protection: u8, payload_len: usize) -> Vec<u8> {
        let mut v = crate::envelope::MAGIC.to_vec();
        v.push(format);
        v.push(protection);
        v.extend(std::iter::repeat_n(0xCD, payload_len));
        assert_ne!(v.len(), 1 + ENTROPY_LEN, "the fixture must reach the non-plain arm");
        v
    }

    /// ARM (a). The pre-#348 behaviour, string for string — including the
    /// example rendered in the issue body. A wrong-length file with no magic is
    /// the ordinary damaged file and its message must not drift.
    #[test]
    fn a_wrong_length_file_without_magic_keeps_todays_corrupt_message_verbatim() {
        let d = wallet_dir_with_seed_bytes("i348_corrupt", &[0x5C; 41]);
        let e = open_err(&d);
        assert!(matches!(e, StoreError::BadSeedFile(_)), "{e:?}");
        assert_eq!(
            e.to_string(),
            "unreadable seed file: 41 bytes; this binary knows exactly one format: \
             1 version byte + 32 entropy bytes",
            "the corrupt vocabulary is locked to the byte"
        );
    }

    /// ARM (b). The situation the issue was filed for: an intact wallet, held
    /// by a key store this machine cannot ask. It must never read as damage and
    /// must name the platform.
    #[test]
    fn a_wrapped_envelope_is_refused_by_name_and_platform_never_as_corrupt() {
        let d = wallet_dir_with_seed_bytes("i348_wrapped", &envelope_bytes(0x01, 0x01, 96));
        let e = open_err(&d);
        assert!(
            matches!(
                e,
                StoreError::SeedWrappedElsewhere {
                    format: "wrapped-seed-v1",
                    protection: "macOS Keychain (Secure-Enclave-held key)"
                }
            ),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(msg.contains("wrapped by macOS Keychain"), "{msg}");
        assert!(msg.contains("the machine that wrapped it"), "{msg}");
        assert!(msg.contains("The wallet itself is fine"), "{msg}");
        assert!(msg.contains("NOT damaged"), "{msg}");
        // The two things this refusal exists to stop saying.
        assert!(!msg.contains("unreadable"), "{msg}");
        assert!(!msg.contains("mnemonic"), "wrapped ⇒ elsewhere, not restore: {msg}");

        // Every reserved platform is nameable through the real open path, not
        // just the one this rig runs on.
        for id in [0x02u8, 0x03, 0x04, 0x05] {
            let d = wallet_dir_with_seed_bytes(
                &format!("i348_wrapped_{id}"),
                &envelope_bytes(0x01, id, 40),
            );
            let e = open_err(&d);
            let p = match e {
                StoreError::SeedWrappedElsewhere { protection, .. } => protection,
                other => panic!("protection {id} must be nameable, got {other:?}"),
            };
            assert!(e.to_string().contains(p), "the name must reach the message");
        }
    }

    #[test]
    fn a_platform_provider_can_open_a_registered_envelope_without_duplicating_the_cursor() {
        let d = tmp("i348_provider");
        let seed = MasterSeed::from_entropy([0x42; ENTROPY_LEN]);
        let mut plain = WalletDir::create(&d, seed.clone()).unwrap();
        plain.allocate_next().unwrap();
        let expected = plain.wallet().address_at_index(1).encode();
        put_seed(&d, &envelope_bytes(0x01, 0x01, 96));

        let wrapped = WalletDir::open_wrapped(&d, seed).unwrap();

        assert_eq!(wrapped.allocated, vec![0, 1]);
        assert_eq!(wrapped.wallet().address_at_index(1).encode(), expected);
    }

    #[test]
    fn the_platform_provider_cannot_override_plain_or_unknown_seed_files() {
        let plain = tmp("i348_provider_plain");
        WalletDir::create(&plain, MasterSeed::from_entropy([1; ENTROPY_LEN])).unwrap();
        let error = open_wrapped_err(&plain, MasterSeed::from_entropy([2; ENTROPY_LEN]));
        assert!(
            error
                .to_string()
                .contains("cannot override a plain seed file"),
            "{error}"
        );

        let unknown =
            wallet_dir_with_seed_bytes("i348_provider_unknown", &envelope_bytes(0x7f, 0x01, 96));
        assert!(matches!(
            open_wrapped_err(&unknown, MasterSeed::from_entropy([9; ENTROPY_LEN])),
            StoreError::SeedFromNewerTool {
                format: 0x7f,
                protection: 0x01
            }
        ));
    }

    #[test]
    fn the_platform_provider_cannot_bypass_the_seed_version_gate() {
        let d =
            wallet_dir_with_seed_bytes("i348_provider_version", &envelope_bytes(0x01, 0x02, 96));

        let error = open_wrapped_err(&d, MasterSeed::with_version(2, [9; ENTROPY_LEN]));

        assert!(
            error.to_string().contains("unwrapped version 2 refused"),
            "{error}"
        );
    }

    /// ARM (c). A record from a registry this binary does not have. "Corrupt"
    /// would be a lie about someone's intact wallet; reject-unknown is the
    /// house rule.
    #[test]
    fn an_envelope_from_a_newer_registry_is_refused_as_newer_never_as_corrupt() {
        for (format, protection) in [(0x7Fu8, 0x01u8), (0x01, 0x7F), (0x00, 0x00)] {
            let d = wallet_dir_with_seed_bytes(
                &format!("i348_newer_{format}_{protection}"),
                &envelope_bytes(format, protection, 64),
            );
            let e = open_err(&d);
            assert!(
                matches!(e, StoreError::SeedFromNewerTool { format: f, protection: p }
                         if f == format && p == protection),
                "{e:?}"
            );
            let msg = e.to_string();
            assert!(msg.contains("written by a newer tool"), "{msg}");
            assert!(msg.contains(&format!("format id {format}")), "{msg}");
            assert!(msg.contains(&format!("protection id {protection}")), "{msg}");
            assert!(msg.contains("knows format ids [1]"), "{msg}");
            assert!(msg.contains("protection ids [1, 2, 3, 4, 5]"), "{msg}");
            assert!(!msg.contains("unreadable"), "{msg}");
            assert!(!msg.contains("corrupt") || msg.contains("NOT corrupt"), "{msg}");
        }
    }

    /// The fourth case, which the acceptance sketch does not name but the code
    /// must answer: our magic, then nothing that can name itself. That is
    /// damage — and it says so in envelope terms rather than length terms.
    #[test]
    fn a_truncated_envelope_header_is_damage_not_a_missing_format() {
        let mut bytes = crate::envelope::MAGIC.to_vec();
        bytes.push(0x01);
        let d = wallet_dir_with_seed_bytes("i348_trunc", &bytes);
        let e = open_err(&d);
        assert!(matches!(e, StoreError::BadSeedFile(_)), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains("cannot even name itself"), "{msg}");
        assert!(msg.contains("restore from the mnemonic"), "{msg}");
    }

    /// "Never a fresh start" is half of the acceptance bar, and it is a
    /// property of `create`, not of `open`: a wrapped wallet dir must not be
    /// silently re-keyed by someone running `keygen` after a refusal.
    #[test]
    fn an_envelope_seed_file_is_never_overwritten_by_a_fresh_keygen() {
        let d = wallet_dir_with_seed_bytes("i348_nofresh", &envelope_bytes(0x01, 0x03, 80));
        let before = std::fs::read(d.join(SEED_FILE)).unwrap();
        match WalletDir::create(&d, MasterSeed::from_entropy([1; ENTROPY_LEN])) {
            Err(StoreError::SeedExists(_)) => {}
            Err(other) => panic!("keygen must refuse by SeedExists, got {other:?}"),
            Ok(_) => panic!("keygen must NEVER re-key a dir holding an envelope"),
        }
        assert_eq!(std::fs::read(d.join(SEED_FILE)).unwrap(), before, "bytes untouched");
    }

    /// The golden path, locked at the byte: #348 must be invisible to an
    /// existing wallet dir. 33 bytes, version first, entropy verbatim, and the
    /// same seed back out — no envelope code on this path at all.
    #[test]
    fn the_plain_33_byte_format_is_byte_identical_and_still_the_only_one_read() {
        let d = tmp("i348_plain");
        let entropy = [0x2B; ENTROPY_LEN];
        WalletDir::create(&d, MasterSeed::from_entropy(entropy)).unwrap();

        let raw = std::fs::read(d.join(SEED_FILE)).unwrap();
        assert_eq!(raw.len(), 1 + ENTROPY_LEN, "33 bytes, unchanged");
        assert_eq!(raw[0], qlab_wallet::seed::SEED_VERSION);
        assert_eq!(&raw[1..], &entropy);

        let re = WalletDir::open(&d).unwrap();
        assert_eq!(re.seed.entropy(), &entropy);
        assert_eq!(re.seed.version(), qlab_wallet::seed::SEED_VERSION);
        assert_eq!(re.allocated, vec![0]);
    }
}
