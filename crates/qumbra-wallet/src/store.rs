//! The wallet directory: a seed file and an index cursor, nothing else.
//!
//! ```text
//!   <dir>/wallet.seed     33 bytes: [mnemonic-format version, 32B entropy], 0600
//!   <dir>/addresses.v1    text: the allocated diversifier INDICES
//! ```
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
    BadSeedFile(String),
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
            return Err(StoreError::BadSeedFile(format!(
                "{} bytes; this binary knows exactly one format: 1 version byte + {ENTROPY_LEN} \
                 entropy bytes",
                bytes.len()
            )));
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

        let allocated = match std::fs::read_to_string(dir.join(ADDR_FILE)) {
            Ok(text) => parse_addresses(&text)?,
            // A missing cursor is not an error — it is index 0, the same state
            // a restore lands in. Addresses are derivable; the file is comfort.
            Err(e) if e.kind() == io::ErrorKind::NotFound => vec![0],
            Err(e) => return Err(e.into()),
        };
        Ok(WalletDir { dir: dir.to_path_buf(), seed, allocated })
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
        let e = WalletDir::open(&d).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("version 238 refused"), "{msg}");
        assert!(msg.contains("different wallet"), "{msg}");
    }
}
