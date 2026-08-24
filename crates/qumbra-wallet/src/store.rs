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

/// **What this platform actually did to the secret file** — one short phrase, so
/// the CLI can state the truth instead of printing `0600` everywhere (lab #478).
///
/// Before the Windows port every surface said "0600" because every supported
/// platform was a unix. On Windows that sentence is false: there is no mode bit,
/// [`write_secret`]'s hardening step does not run, and the file gets whatever the
/// parent directory's ACL hands down. A wallet that claims a protection it does
/// not have is worse than one that names the gap, so this is a `const fn` and not
/// a comment.
pub const fn secret_file_protection() -> &'static str {
    #[cfg(unix)]
    {
        "0600 — owner-only"
    }
    #[cfg(not(unix))]
    {
        "inherited NTFS ACL — this build sets NO explicit permission (see below)"
    }
}

/// The long form of [`secret_file_protection`]'s gap, printed once at the moment
/// the seed is created. `None` where the platform really does have owner-only
/// modes, so unix output is byte-identical to what it always was.
pub const fn secret_file_protection_note() -> Option<&'static str> {
    #[cfg(unix)]
    {
        None
    }
    #[cfg(not(unix))]
    {
        Some(
            "⚠️  Windows has no chmod, and this build does not set a DACL on the seed file.\n\
             \x20   Its protection is whatever it inherits from the folder you chose, and this\n\
             \x20   message CANNOT TELL YOU WHAT THAT IS. Under your own profile\n\
             \x20   (%USERPROFILE%\\.qumbra-wallet) it is usually you + SYSTEM + Administrators —\n\
             \x20   already NOT owner-only, and NOT what the unix builds get. A folder outside\n\
             \x20   your profile commonly inherits far more: a freshly-installed Windows 11 was\n\
             \x20   MEASURED granting `Authenticated Users: Modify` on a seed file — every\n\
             \x20   account that can log in could read AND alter it (lab #637).\n\
             \x20   CHECK yours first — read-only, one command:\n\
             \x20     icacls \"<the --dir you passed>\"\n\
             \x20   Every name it lists can reach the seed. `(M)` means Modify: that account\n\
             \x20   can overwrite your seed, not only read it.\n\
             \x20   Then, to make it owner-only, run this once in the same shell — on THAT\n\
             \x20   SAME directory, not on a path copied from this message:\n\
             \x20     icacls \"<the --dir you passed>\" /inheritance:r /grant:r \"%USERNAME%:(OI)(CI)F\"\n\
             \x20   Anyone who can read the seed file owns every coin this wallet holds.",
        )
    }
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
    // 🔴 NOT-UNIX: THE ABSENCE IS DELIBERATE AND IS NOT SILENT (lab #478).
    //
    // Windows has no mode bits. The honest equivalents were both priced and both
    // declined for this baton: a `SetNamedSecurityInfoW` DACL means hand-building
    // an ACL in `unsafe` inside a wallet's key-writing path — the one function in
    // this crate where a bug is unrecoverable — and shelling out to `icacls` puts
    // a wallet's secret protection at the mercy of PATH. So the position taken is
    // the task book's other option, stated rather than implied: the gap is
    // *reported* by `secret_file_protection{,_note}` above, printed at creation
    // by the CLI, and written into the join doc's Windows section.
    //
    // If this ever becomes a DACL, delete the note with it — a stale reassurance
    // is the failure this block exists to prevent.
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

/// What [`create_from_os_entropy_gated`] did: a wallet, or nothing at all.
///
/// `Refused` means the gate said no and **nothing was written** — not a wallet
/// that exists and is unconfirmed. That distinction is the whole point of the
/// gate: a seed file on disk whose mnemonic its owner never acknowledged is
/// exactly the state Bitcoin Core's auto-`wallet.dat` era is remembered for.
pub enum GatedCreate {
    Created(WalletDir),
    Refused,
}

/// Generate a wallet from OS entropy, show the caller its mnemonic, and write
/// the seed **only if the gate returns `true`**.
///
/// 🔴 **The one place in this workspace that mints wallet key material.** Until
/// lab #475 it lived in this crate's `main.rs`, so the "kernel" had no
/// generation entry point at all and a second binary that wanted a wallet had
/// to re-implement entropy → seed → address-0. `qumbra-node mine` is that
/// second binary. Entropy, the `MasterSeed`, and the seed file stay inside this
/// crate; a caller sees the mnemonic string (it must — showing it is the whole
/// job) and the resulting [`WalletDir`], never the entropy.
///
/// The gate runs **before** the write for the same reason: an abort must leave
/// no seed file behind. A mnemonic shown for a wallet that was then not written
/// costs nothing — the phrase carries the whole seed, so restoring from it
/// reproduces the same wallet — while an unacknowledged seed file costs the
/// operator a wallet they do not know they own.
///
/// A failure of the OS CSPRNG is fatal rather than degraded: a seed from a weak
/// source is a key somebody else can derive (the faucet's rule, kept).
pub fn create_from_os_entropy_gated(
    dir: &Path,
    gate: impl FnOnce(&str) -> bool,
) -> Result<GatedCreate, StoreError> {
    use rand::Rng;

    // Refuse before minting anything if a wallet is already here, so a caller
    // cannot be shown a mnemonic for a wallet that was never going to be
    // written. `WalletDir::create` refuses too; this is the earlier, quieter no.
    let seed_path = dir.join(SEED_FILE);
    if seed_path.exists() {
        return Err(StoreError::SeedExists(seed_path));
    }
    let mut entropy = [0u8; ENTROPY_LEN];
    rand::rng().fill_bytes(&mut entropy);
    let seed = MasterSeed::from_entropy(entropy);
    if !gate(&seed.to_mnemonic()) {
        return Ok(GatedCreate::Refused);
    }
    Ok(GatedCreate::Created(WalletDir::create(dir, seed)?))
}

/// The `miner_rkm` a node config carries so a mining node's coinbase pays THIS
/// wallet: 64 hex characters = 32 bytes, lane-major little-endian, the form
/// `qumbra_node::config::rkm_lanes_from_hex` parses.
///
/// 🔴 **One derivation, not two** — lab #425's rule, one level out. This
/// expression used to live in `qumbra-wallet`'s `main.rs`; `qumbra-node mine`
/// (lab #475) needs the same value from the same seed, and a payout key is the
/// worst possible place for two implementations that merely agree today. Both
/// callers run this function, so the node's `miner_rkm` is the wallet's rkm by
/// construction rather than by two expressions matching.
///
/// `index` is an **address index**, not a diversifier: the diversifier is
/// index-deterministic ([`WalletDir`]'s cursor note), and index 0 is the
/// identity this wallet already displays.
pub fn miner_rkm_hex(wallet: &Wallet, index: u64) -> String {
    let d = wallet.diversifier_at_index(index);
    qlab_note::hash::digest_bytes(&wallet.rkm(d)).iter().map(|b| format!("{b:02x}")).collect()
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

    /// Lab #478: what the CLI *says* about the seed file's protection must match
    /// what this platform's `write_secret` actually does. The two used to be one
    /// hard-coded "0600" on every platform, which the Windows port made false.
    ///
    /// The pairing is the test, in both directions: a unix build must claim the
    /// mode it sets and must NOT print the Windows note; a non-unix build must
    /// not claim a mode, and must print the note.
    #[test]
    fn the_stated_protection_matches_what_this_platform_actually_does() {
        let claim = secret_file_protection();
        let note = secret_file_protection_note();
        #[cfg(unix)]
        {
            assert!(claim.contains("0600"), "unix must state the mode it sets: {claim:?}");
            assert!(
                note.is_none(),
                "unix sets an owner-only mode, so there is no gap to narrate: {note:?}"
            );
        }
        #[cfg(not(unix))]
        {
            assert!(
                !claim.contains("0600"),
                "this platform sets no mode — claiming 0600 is the defect this test exists for: \
                 {claim:?}"
            );
            let note = note.expect("a platform with no owner-only mode must narrate the gap");
            assert!(note.contains("icacls"), "the note must name the fix: {note:?}");

            // lab #637. The note already named the fix and the consequence; what it
            // could not do was tell the reader what THEIR folder grants. It said what
            // is "usually" true under %USERPROFILE% — and a freshly-installed Windows
            // 11 was measured granting `Authenticated Users: Modify` on a seed file,
            // which is broader than the example and is what a folder outside the
            // profile commonly inherits. The person who hit it read the note and did
            // not act; they acted on `icacls` output.
            //
            // So three properties, each of which a future tidy-up would otherwise be
            // free to drop:
            assert!(
                note.contains("CANNOT TELL YOU WHAT THAT IS"),
                "the note must not let 'usually' stand in for the reader's own ACL: {note:?}"
            );
            assert!(
                note.contains("Authenticated Users: Modify"),
                "the note must carry the MEASURED grant, not only the typical one — a \
                 consequence without a magnitude is what left this unacted on: {note:?}"
            );
            assert!(
                note.matches("icacls").count() >= 2,
                "the note must give a read-only CHECK as well as the fix — a remedy with no \
                 way to observe the condition assumes the reader already believes it: {note:?}"
            );
            assert!(
                note.contains("owns every coin this wallet holds"),
                "the consequence line is the reason any of this is read at all: {note:?}"
            );

            // Measured on Windows 11 (Ryzen 7, fresh install) against a wallet in
            // `C:\qumbra`, i.e. OUTSIDE the profile — which is what the operator
            // guides tell people to do:
            //
            //   before: Administrators / SYSTEM / Users(RX) / Authenticated Users(M)
            //   after:  <the account>:(I)(F)   — a single entry
            //
            // Both commands were run verbatim and both work. The failure the earlier
            // wording had was subtler than being wrong: the FIX hard-coded
            // `%USERPROFILE%\.qumbra-wallet` while the CHECK was already generic, so a
            // reader whose wallet lives anywhere else repairs a directory they are not
            // using — and `icacls` prints "Successfully processed 1 files" while doing
            // it. A confident success on the wrong target is worse than no advice,
            // because it retires the reader's sense that anything is outstanding.
            assert!(
                !note.contains("icacls \"%USERPROFILE%"),
                "the FIX must not hard-code a path: it succeeds loudly against a directory \
                 the reader may not be using, leaving the real seed exactly as exposed: {note:?}"
            );
            assert!(
                note.matches("<the --dir you passed>").count() >= 2,
                "both the check AND the fix must target the directory the user actually \
                 passed — keygen knows it at the moment it prints this: {note:?}"
            );
            // `(M)` is the one token in `icacls` output a non-administrator cannot
            // decode, and it is the token that carries the worst half: not merely
            // readable by others, but writable by them.
            assert!(
                note.contains("`(M)` means Modify"),
                "the note sends the reader to icacls output, so it must decode the one \
                 field they cannot: {note:?}"
            );
        }
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

    // ── lab #475: the kernel's generation entry point + the one rkm derivation ──

    /// 🔴 **A refused gate leaves NO seed file.** This is the property the whole
    /// backup gate rests on: `qumbra-node mine` shows the mnemonic, and if the
    /// operator does not confirm, the machine must be exactly as it was — not
    /// holding a wallet nobody knows about.
    #[test]
    fn a_refused_gate_writes_nothing_at_all() {
        let d = tmp("i475_refused");
        let mut shown = String::new();
        let outcome = create_from_os_entropy_gated(&d, |m| {
            shown = m.to_string();
            false
        })
        .expect("the refusal is not an error");
        assert!(matches!(outcome, GatedCreate::Refused));
        assert!(!shown.is_empty(), "the gate is shown the mnemonic before it decides");
        assert!(!d.join(SEED_FILE).exists(), "a refused create must leave no seed file");
        assert!(!d.join(ADDR_FILE).exists(), "and no address cursor either");
    }

    /// The accepting gate writes the wallet the mnemonic it was shown belongs
    /// to — the phrase an operator writes down must restore THIS wallet.
    #[test]
    fn an_accepted_gate_writes_the_wallet_the_shown_mnemonic_restores() {
        let d = tmp("i475_accepted");
        let mut shown = String::new();
        let w = match create_from_os_entropy_gated(&d, |m| {
            shown = m.to_string();
            true
        })
        .expect("create")
        {
            GatedCreate::Created(w) => w,
            GatedCreate::Refused => panic!("the gate accepted"),
        };
        assert_eq!(reveal_mnemonic(&w), shown, "the shown phrase is this wallet's phrase");

        let restored = tmp("i475_accepted_restored");
        let seed = seed_from_phrase(&mut shown.as_bytes()).expect("the shown phrase restores");
        let w2 = WalletDir::create(&restored, seed).expect("restore");
        assert_eq!(
            w2.wallet().address_at_index(0).encode(),
            w.wallet().address_at_index(0).encode(),
        );
    }

    /// Generation refuses an occupied dir BEFORE minting anything, so no caller
    /// can be shown a mnemonic for a wallet that was never going to be written.
    #[test]
    fn generation_refuses_an_occupied_dir_without_showing_a_mnemonic() {
        let d = tmp("i475_occupied");
        WalletDir::create(&d, MasterSeed::from_entropy([5; ENTROPY_LEN])).unwrap();
        let before = std::fs::read(d.join(SEED_FILE)).unwrap();
        let mut gate_ran = false;
        match create_from_os_entropy_gated(&d, |_| {
            gate_ran = true;
            true
        }) {
            Err(StoreError::SeedExists(_)) => {}
            Err(other) => panic!("expected SeedExists, got {other:?}"),
            Ok(_) => panic!("an occupied dir must never be re-keyed"),
        }
        assert!(!gate_ran, "the gate must not run for a dir that was never going to be written");
        assert_eq!(std::fs::read(d.join(SEED_FILE)).unwrap(), before, "bytes untouched");
    }

    /// The node's `miner_rkm` is the wallet's rkm **by construction**: this test
    /// re-derives it the long way and pins the shape the node config parses
    /// (64 lowercase hex characters).
    #[test]
    fn miner_rkm_hex_is_the_wallet_kernels_own_derivation() {
        let d = tmp("i475_rkm");
        let w = WalletDir::create(&d, MasterSeed::from_entropy([9; ENTROPY_LEN])).unwrap();
        let wallet = w.wallet();
        for index in [0u64, 1, 7] {
            let got = miner_rkm_hex(&wallet, index);
            let want: String = qlab_note::hash::digest_bytes(
                &wallet.rkm(wallet.diversifier_at_index(index)),
            )
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
            assert_eq!(got, want);
            assert_eq!(got.len(), 64, "the node config's form is 64 hex characters");
            assert!(got.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        // Different indices are different payees — a copied constant would not
        // have this property and would silently pay one address forever.
        assert_ne!(miner_rkm_hex(&wallet, 0), miner_rkm_hex(&wallet, 1));
    }
}
