//! Lab #896 G: the Candidate A authorization journal (`auth.v1`). The journal
//! itself lives in [`qlab_remote_auth::annulet::journal`] (seam H, so the
//! faucet shares it); this module re-exports it and keeps the wallet-shaped entry
//! points.

pub use qlab_remote_auth::annulet::journal::*;

/// Generation `g`'s authorization-tree root for `wallet` — what its v2
/// addresses bind ([`qlab_remote_auth::annulet::journal::generation_root`] over the
/// wallet's authorization secret).
pub fn generation_root(wallet: &qlab_wallet::Wallet, g: u32) -> [u64; 4] {
    qlab_remote_auth::annulet::journal::generation_root(&wallet.auth_secret(), g)
}

/// The probe set: generations `0 .. PROBE_GENERATIONS` with their roots.
pub fn probe_roots(wallet: &qlab_wallet::Wallet) -> Vec<(u32, [u64; 4])> {
    qlab_remote_auth::annulet::journal::probe_roots(&wallet.auth_secret())
}

/// Lab #937 cut-over (D-C3): **a wallet born in this process, with its first
/// journal** — `keygen --candidate-a`, the CLI's twin of the kernel's
/// `qmb_auth_first_fresh`. A seed drawn here has signed nowhere, so generation
/// 0 is fresh and active at birth, offline, with no chain read: its version-2
/// addresses are ready before any Candidate A net exists (a prover's payee
/// wallet is made before the genesis that pins it).
///
/// **Only for a seed drawn here.** A restored or existing wallet may have
/// signed elsewhere and keeps `migrate`'s checked path; so a directory that
/// already holds a seed or an `auth.v1` is refused by name, before any
/// entropy is drawn, and nothing is written.
///
/// The seed is written first, then the journal. Should the journal's write
/// fail after the seed's, the directory holds a seed with no journal: a
/// second `keygen --candidate-a` is refused (`SeedExists`), and `migrate`
/// on a Candidate A net writes the journal by its checked path.
pub fn create_fresh_candidate_a(
    dir: &std::path::Path,
) -> Result<(crate::store::WalletDir, AuthJournal), Box<dyn std::error::Error>> {
    if dir.join(AUTH_FILE).exists() {
        return Err(format!(
            "{} exists: this directory already has a Candidate A journal (keygen writes a new wallet only)",
            dir.join(AUTH_FILE).display()
        )
        .into());
    }
    let w = match crate::store::create_from_os_entropy_gated(dir, |_mnemonic| true)? {
        crate::store::GatedCreate::Created(w) => w,
        crate::store::GatedCreate::Refused => unreachable!("the gate always accepts"),
    };
    let journal = AuthJournal::fresh(generation_root(&w.wallet(), 0));
    journal.save(dir)?;
    Ok((w, journal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{WalletDir, SEED_FILE};
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_fresh_ca_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// D-C3: an empty directory gets a seed and generation 0 fresh and
    /// active, bound to the seed's own generation-0 root; the journal reads
    /// back through `load` (what every Candidate A command opens) unchanged.
    #[test]
    fn keygen_candidate_a_writes_generation_0_fresh() {
        let d = tmp("ok");
        let (w, j) = create_fresh_candidate_a(&d).expect("an empty directory");
        let back = AuthJournal::load(&d).expect("readable").expect("written");
        assert_eq!(back, j);
        assert_eq!(back, AuthJournal::fresh(generation_root(&w.wallet(), 0)));
        let a = back.active();
        assert_eq!((a.g, a.next, a.auth_root), (0, 0, generation_root(&w.wallet(), 0)));
        assert_eq!(back.generations().len(), 1);
        assert_eq!(back.checked_heights(), vec![]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A restored (or any existing) wallet never gets a journal this way: it
    /// may have signed elsewhere. Refused before anything is written.
    #[test]
    fn keygen_candidate_a_refuses_an_existing_seed() {
        let d = tmp("seed");
        WalletDir::create(&d, MasterSeed::from_entropy([7; ENTROPY_LEN])).expect("a restored wallet");
        let before = std::fs::read(d.join(SEED_FILE)).expect("seed");
        assert!(create_fresh_candidate_a(&d).is_err());
        assert!(!d.join(AUTH_FILE).exists(), "no journal for a seed from outside");
        assert_eq!(std::fs::read(d.join(SEED_FILE)).expect("seed"), before, "the seed is untouched");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keygen_candidate_a_refuses_an_existing_journal() {
        let d = tmp("journal");
        std::fs::create_dir_all(&d).expect("dir");
        AuthJournal::fresh([1, 2, 3, 4]).save(&d).expect("a journal");
        let err = create_fresh_candidate_a(&d).err().expect("refused").to_string();
        assert!(err.contains(AUTH_FILE), "{err}");
        assert!(!d.join(SEED_FILE).exists(), "no seed is drawn");
        let _ = std::fs::remove_dir_all(&d);
    }
}
