//! **The sequencer's key** (lab #847 S5): one key file, two derived keys.
//!
//! The file is B2's `sequencer.key` convention (`qumbra_node::annulet_genesis::
//! SequencerKeyFile`): TOML, the 32-byte seed as `seed_hex`. From the seed,
//! domain-separated:
//!
//! - the **ML-DSA-65 signing key** (`SigningKey::from_seed`, as every committee
//!   and rehearsal key in this tree) — its verifying key must equal the V6
//!   genesis's `WrapperParams::sequencer_key`, or the run refuses to start;
//! - the **filler-wallet seed** (`Keccak256(FILLER_DOMAIN ‖ seed)`) — the
//!   sequencer's own L2 notes and fee unit for S3's fillers, never the run
//!   seed f5box used (#847 Q3 (iii)).
//!
//! **The file must be mode 0600 or 0400** (owner only, never executable), or
//! it is refused by name — B2's precedent: a signing seed readable by group or
//! world is a key someone else may already hold. The mode is read from the
//! open file handle the seed is then read from (no check-then-reopen race).
//!
//! **What never leaves this module**: the file's text, the seed, and any
//! parser error (a TOML error can quote the line it failed on — the seed
//! line). Every key-file failure is one fixed sentence naming no content; the
//! text, the seed and the derived filler seed are zeroized on drop. What is
//! not: the ML-DSA signing key itself, which stays in process memory for the
//! pass; the seed's by-value copies on the stack while `from_seed` and
//! `filler_seed` run; and any earlier buffer `read_to_string` left behind
//! when it grew the text.
//!
//! The parser is B2's `SequencerKeyFile::from_toml`: it accepts unknown keys
//! and upper-case hex — inherited, and left as B2 has it.
//!
//! **Rehearsal, both directions** (#847 Q-S5-1): the rehearsal key is public
//! (`keccak("qumbra:rehearsal-sequencer:v1")`), so a genesis whose
//! `sequencer_key` is the rehearsal key *is* a rehearsal genesis. The rehearsal
//! seed is refused off a rehearsal genesis, and a rehearsal genesis is refused
//! with any other seed — so nobody runs a real chain with a public key, or
//! "upgrades" the rehearsal chain with a real one by accident.

use std::io::Read;
use std::path::Path;

use ml_dsa::{Keypair, MlDsa65, SigningKey};
use zeroize::{Zeroize, Zeroizing};
use qumbra_node::annulet_genesis::SequencerKeyFile;
use qumbra_node::genesis_v6::{rehearsal_sequencer_key, rehearsal_sequencer_seed, WrapperParams};

/// The filler-wallet seed's domain.
const FILLER_DOMAIN: &[u8] = b"qumbra:sequencer:filler-wallet:v1";

/// A loaded, checked sequencer key.
pub struct SequencerKey {
    pub signer: SigningKey<MlDsa65>,
    /// The seed S3's filler wallet derives its notes from (zeroized on drop).
    pub filler_seed: Zeroizing<[u8; 32]>,
    /// Whether this is the public rehearsal key (and so a rehearsal genesis).
    pub rehearsal: bool,
}

/// The filler-wallet seed of a sequencer seed.
pub fn filler_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut msg = FILLER_DOMAIN.to_vec();
    msg.extend_from_slice(seed);
    qlab_devnet::hash::keccak256(&msg)
}

/// Check `seed` against `params` and derive the keys. Refused, by name, for a
/// seed whose key is not the genesis's, and for either half of a rehearsal
/// pairing without the other.
pub fn from_seed(seed: [u8; 32], params: &WrapperParams) -> Result<SequencerKey, String> {
    let rehearsal_genesis = params.sequencer_key == rehearsal_sequencer_key();
    let rehearsal_seed = seed == rehearsal_sequencer_seed();
    match (rehearsal_seed, rehearsal_genesis) {
        (true, false) => {
            return Err("the key file holds the public rehearsal seed, and this genesis is not a rehearsal genesis — \
                        refusing to sign a real chain with a key everyone has"
                .into())
        }
        (false, true) => {
            return Err("this is a rehearsal genesis (its sequencer key is the public rehearsal key), and the key file \
                        holds another seed — refusing to run the rehearsal chain under a real key"
                .into())
        }
        _ => {}
    }
    let signer = SigningKey::<MlDsa65>::from_seed(&seed.into());
    if signer.verifying_key().encode().as_slice() != params.sequencer_key.as_slice() {
        return Err("the key file's seed does not derive this genesis's sequencer key — refusing to start".into());
    }
    Ok(SequencerKey { signer, filler_seed: Zeroizing::new(filler_seed(&seed)), rehearsal: rehearsal_genesis })
}

/// The one sentence every key-file parse or decode failure is reported as.
const NOT_A_KEY_FILE: &str = "not a sequencer key file: TOML with seed_hex (32 bytes, hex)";

/// Load the key file at `path` (mode 0600 or 0400, B2's TOML) and check it
/// against `params`. The file is opened once: its mode is read from the
/// handle and its text from the same handle.
pub fn load(path: &Path, params: &WrapperParams) -> Result<SequencerKey, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    check_mode(&f).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut text = Zeroizing::new(String::new());
    f.read_to_string(&mut text).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed = Zeroizing::new(parse_seed(&text).map_err(|e| format!("{}: {e}", path.display()))?);
    from_seed(*seed, params).map_err(|e| format!("{}: {e}", path.display()))
}

/// The seed from the file's text; any failure is [`NOT_A_KEY_FILE`], never
/// the parser's own error (which can quote the text).
fn parse_seed(text: &str) -> Result<[u8; 32], &'static str> {
    let mut file = SequencerKeyFile::from_toml(text).map_err(|_| NOT_A_KEY_FILE)?;
    let seed = file.seed().map_err(|_| NOT_A_KEY_FILE);
    file.seed_hex.zeroize();
    seed
}

/// Owner-only and never executable: 0600 or 0400.
#[cfg(unix)]
fn check_mode(f: &std::fs::File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = f.metadata().map_err(|e| e.to_string())?.permissions().mode() & 0o777;
    if mode != 0o600 && mode != 0o400 {
        return Err(format!("mode {mode:o} — a sequencer key file must be 600 or 400 (owner only, not executable)"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_f: &std::fs::File) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_for(key: Vec<u8>) -> WrapperParams {
        WrapperParams::v1(1, key, [0; 4])
    }

    fn key_of(seed: [u8; 32]) -> Vec<u8> {
        SigningKey::<MlDsa65>::from_seed(&seed.into()).verifying_key().encode().to_vec()
    }

    #[test]
    fn the_rehearsal_pairing_holds_in_both_directions() {
        let rehearsal = params_for(rehearsal_sequencer_key());
        let k = from_seed(rehearsal_sequencer_seed(), &rehearsal).expect("rehearsal seed on a rehearsal genesis");
        assert!(k.rehearsal);
        let real_seed = [0x5e; 32];
        let real = params_for(key_of(real_seed));
        assert!(from_seed(rehearsal_sequencer_seed(), &real).err().unwrap().contains("not a rehearsal genesis"));
        assert!(from_seed(real_seed, &rehearsal).err().unwrap().contains("this is a rehearsal genesis"));
        let k = from_seed(real_seed, &real).expect("a real seed on its own genesis");
        assert!(!k.rehearsal);
    }

    #[test]
    fn a_seed_that_is_not_the_genesis_key_is_refused() {
        let real = params_for(key_of([0x5e; 32]));
        assert!(from_seed([0x5f; 32], &real).err().unwrap().contains("does not derive this genesis's sequencer key"));
    }

    /// The filler wallet's seed is the key's, domain-separated: deterministic,
    /// distinct per key, and never the signing seed itself.
    #[test]
    fn the_filler_seed_is_domain_separated() {
        let a = filler_seed(&[0x5e; 32]);
        assert_eq!(*from_seed([0x5e; 32], &params_for(key_of([0x5e; 32]))).unwrap().filler_seed, a);
        assert_eq!(a, filler_seed(&[0x5e; 32]));
        assert_ne!(a, filler_seed(&[0x5f; 32]));
        assert_ne!(a, [0x5e; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("qseq-key-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("sequencer.key");
        let seed = [0x5e; 32];
        let text = SequencerKeyFile { seed_hex: "5e".repeat(32), note: "test".into() }.to_toml();
        std::fs::write(&p, text).unwrap();
        let params = params_for(key_of(seed));
        for (mode, ok) in [(0o644, false), (0o700, false), (0o640, false), (0o600, true), (0o400, true)] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let r = load(&p, &params);
            if ok {
                assert!(r.is_ok(), "mode {mode:o}");
            } else {
                assert!(r.err().unwrap().contains(&format!("mode {mode:o}")), "mode {mode:o}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A malformed key file is one fixed sentence — never the parser's error,
    /// which could quote the seed line.
    #[cfg(unix)]
    #[test]
    fn a_malformed_key_file_names_no_content() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("qseq-key-bad-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("sequencer.key");
        let params = params_for(key_of([0x5e; 32]));
        for text in ["seed_hex = \"5e5e5e5e-not-hex\"\n", "seed_hex = 5e5e\n", "seed_hex = \"5e5e\"\n"] {
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            let err = load(&p, &params).err().unwrap();
            assert!(err.ends_with(NOT_A_KEY_FILE), "{err}");
            assert!(!err.contains("5e5e"), "the error quoted the file: {err}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
