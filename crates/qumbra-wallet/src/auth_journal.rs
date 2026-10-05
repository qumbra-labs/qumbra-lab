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
