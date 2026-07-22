//! The standing-disclosure layer (`auditable-privacy.md` §4): full and incoming
//! viewing keys, and the top-level [`Wallet`] that ties them to the spend key.
//!
//! Capability hierarchy, enforced at the TYPE level — the spend capability lives
//! ONLY in [`crate::keys::SpendingKey`] (via [`Wallet::spend_input`]); `Fvk` and
//! `Ivk` carry no `sk` and expose no spend-witness constructor:
//!
//! | Type | Holds | Can | Cannot |
//! |---|---|---|---|
//! | [`Wallet`] / `SpendingKey` | `sk` | everything, incl. produce a spend witness | — |
//! | [`Fvk`] | `nk`, `div_seed` | derive `rkm(d)`; **generate addresses**; **view spends** (`nf`); detect+decrypt incoming | spend |
//! | [`Ivk`] | `div_seed` | detect+decrypt incoming; recompute `cm` (from the decrypted note) | derive `rkm`; generate addresses; compute `nf`; spend |
//!
//! `Fvk::to_ivk` is a one-way downgrade (drops `nk`); preimage resistance means
//! an `Ivk` cannot recover `nk`, so it cannot view spends.
//!
//! **Issue #32 capability consequence.** `rkm = H(nk ‖ D_R ‖ d)` now binds `nk`
//! DIRECTLY. Anything able to derive `rkm(d)` therefore also holds enough to
//! derive `nf = H(nk ‖ ρ)` — so `rkm`-derivation (and thus diversified-address
//! GENERATION) is a full-viewing-key capability, not an incoming-viewing-key
//! one. Under the old shared `rkm = H(nk ‖ D_R)` the `Ivk` could carry the one
//! `rkm` and self-generate addresses; it no longer can. This is a strict, safe
//! narrowing: the `Ivk` keeps exactly what it needs — scanning recomputes `cm`
//! from the DECRYPTED note's `rkm`, never from the key (see `qlab-note::scan`),
//! so detection/decryption are unaffected. The wallet owner (`Fvk`) generates
//! diversified addresses and hands the full address to an `Ivk` holder (e.g. an
//! exchange), which scans them.
//!
//! The ML-KEM keypair for a diversifier `d` is derived deterministically from
//! `div_seed` (carried by both keys), so both can regenerate any `dk_d` to scan.
//! `div_seed` and the keypair seed use ASCII domain strings (wallet-only KDFs —
//! the circuit-bound `nk`/`rkm`/`nf` derivations live in `keys`).

use qlab_note::hash::{digest_bytes, keccak256};
use qlab_note::kem::{ek_to_bytes, generate_keypair, Keypair};
use qlab_note::scan::{scan, DetectedNote, EncryptedOutputs, ScanMode};
use rand::{rngs::StdRng, SeedableRng};

use crate::address::{Address, Diversifier};
use crate::keys::{derive_nf, derive_rkm, Lanes, SpendingKey};

/// Domain string: `div_seed = Keccak256(DS_DIV_SEED ‖ sk_bytes)`.
pub const DS_DIV_SEED: &[u8] = b"qumbra:wallet:div-seed:v1";
/// Domain string: diversified ML-KEM keypair seed
/// `= Keccak256(DS_MLKEM_DIV ‖ div_seed ‖ d)`.
pub const DS_MLKEM_DIV: &[u8] = b"qumbra:wallet:mlkem-div:v1";

/// Derive the diversifier seed that seeds every diversified ML-KEM keypair.
fn div_seed_from_sk(sk_lanes: &Lanes) -> [u8; 32] {
    let mut input = Vec::with_capacity(DS_DIV_SEED.len() + 32);
    input.extend_from_slice(DS_DIV_SEED);
    input.extend_from_slice(&digest_bytes(sk_lanes));
    keccak256(&input)
}

/// Deterministically derive the ML-KEM-768 keypair for diversifier `d` from
/// `div_seed`. Reproducible by anyone holding `div_seed` (i.e. fvk/ivk), so a
/// viewing key can regenerate `dk_d` to scan and `ek_d` to build the address.
fn diversified_keypair(div_seed: &[u8; 32], d: &Diversifier) -> Keypair {
    let mut input = Vec::with_capacity(DS_MLKEM_DIV.len() + 32 + d.as_bytes().len());
    input.extend_from_slice(DS_MLKEM_DIV);
    input.extend_from_slice(div_seed);
    input.extend_from_slice(d.as_bytes());
    let seed = keccak256(&input);
    let mut rng = StdRng::from_seed(seed);
    generate_keypair(&mut rng)
}

/// Full viewing key — the compliance/audit hook. Sees ALL activity (incoming
/// notes AND spends) but cannot spend.
#[derive(Clone)]
pub struct Fvk {
    nk: Lanes,
    div_seed: [u8; 32],
}

impl Fvk {
    /// The recipient key material `rkm = H(nk ‖ D_R ‖ d)` for diversifier `d`
    /// (issue #32: per-address, so this wallet's addresses are unlinkable).
    pub fn rkm(&self, d: Diversifier) -> Lanes {
        derive_rkm(&self.nk, &d.lanes())
    }

    /// **View spends:** the nullifier `nf = H(nk ‖ ρ)` for a note seed `ρ`.
    /// This is the capability `Ivk` lacks (it has no `nk`).
    pub fn nullifier(&self, rho: &Lanes) -> Lanes {
        derive_nf(&self.nk, rho)
    }

    /// Downgrade to an incoming viewing key (one-way: `nk` is dropped — an `Ivk`
    /// cannot recover `nk`, so it can neither view spends nor, since issue #32,
    /// derive `rkm(d)`; it retains only detect+decrypt).
    pub fn to_ivk(&self) -> Ivk {
        Ivk {
            div_seed: self.div_seed,
        }
    }

    /// The diversified address for diversifier `d`. Generating it needs `rkm(d)`
    /// and hence `nk` — a full-viewing-key capability (issue #32).
    pub fn address(&self, d: Diversifier) -> Address {
        let kp = diversified_keypair(&self.div_seed, &d);
        Address::new(d, self.rkm(d), &kp.ek)
    }

    /// Detect + decrypt incoming notes at diversifier `d`.
    pub fn scan(&self, d: &Diversifier, outputs: &EncryptedOutputs, mode: ScanMode) -> Vec<DetectedNote> {
        let kp = diversified_keypair(&self.div_seed, d);
        scan(&kp.dk, outputs, mode)
    }
}

/// Incoming viewing key — the standing hook handed to e.g. an exchange to credit
/// deposits. Detects + decrypts incoming notes; cannot view spends, cannot spend.
///
/// Since issue #32 it holds ONLY `div_seed`: `rkm = H(nk ‖ D_R ‖ d)` binds `nk`,
/// so `rkm`-derivation and address GENERATION are full-viewing-key capabilities.
/// Scanning is unaffected — it recomputes `cm` from the decrypted note's `rkm`,
/// not from the key (see [`qlab_note::scan`]).
#[derive(Clone)]
pub struct Ivk {
    div_seed: [u8; 32],
}

impl Ivk {
    /// Detect + decrypt incoming notes at diversifier `d` (the ML-KEM keypair
    /// `dk_d` is regenerated from `div_seed`).
    pub fn scan(&self, d: &Diversifier, outputs: &EncryptedOutputs, mode: ScanMode) -> Vec<DetectedNote> {
        let kp = diversified_keypair(&self.div_seed, d);
        scan(&kp.dk, outputs, mode)
    }

    // NOTE: there is deliberately NO `nullifier(...)`, NO `spend_input(...)`, and
    // (since issue #32) NO `rkm(...)`/`address(...)` on `Ivk` — it holds neither
    // `nk` nor `sk`. That absence IS the type-level capability boundary (see the
    // crate-level compile_fail doc-tests).
}

/// A Qumbra wallet — the root of the key hierarchy. Owns the [`SpendingKey`] and
/// derives every subordinate key/address from it. This is the ONLY type that can
/// produce a spend witness for the circuit.
#[derive(Clone)]
pub struct Wallet {
    sk: SpendingKey,
    div_seed: [u8; 32],
}

impl Wallet {
    /// Build a wallet from a raw 256-bit spending secret. (HD-seed / mnemonic
    /// derivation of `sk` from a master seed is out of M7 scope — see the plan.)
    pub fn from_seed_lanes(sk: Lanes) -> Self {
        Self::from_spending_key(SpendingKey::from_lanes(sk))
    }

    /// Build a wallet around an existing spending key.
    pub fn from_spending_key(sk: SpendingKey) -> Self {
        let div_seed = div_seed_from_sk(&sk.sk_lanes());
        Self { sk, div_seed }
    }

    /// The nullifier key `nk`.
    pub fn nk(&self) -> Lanes {
        self.sk.nk()
    }

    /// The recipient key material `rkm = H(nk ‖ D_R ‖ d)` for diversifier `d`
    /// (issue #32: per-address).
    pub fn rkm(&self, d: Diversifier) -> Lanes {
        self.sk.rkm(&d.lanes())
    }

    /// The full viewing key (compliance hook: sees everything, cannot spend).
    pub fn fvk(&self) -> Fvk {
        Fvk {
            nk: self.sk.nk(),
            div_seed: self.div_seed,
        }
    }

    /// The incoming viewing key (detect+decrypt incoming only).
    pub fn ivk(&self) -> Ivk {
        self.fvk().to_ivk()
    }

    /// The diversified ML-KEM keypair for diversifier `d` (the wallet holds the
    /// secret `dk_d` to spend/scan; `ek_d` goes in the address).
    pub fn diversified_keypair(&self, d: &Diversifier) -> Keypair {
        diversified_keypair(&self.div_seed, d)
    }

    /// The wallet's diversified address for diversifier `d`.
    pub fn address(&self, d: Diversifier) -> Address {
        let kp = self.diversified_keypair(&d);
        Address::new(d, self.rkm(d), &kp.ek)
    }

    /// The nullifier `nf = H(nk ‖ ρ)` (the wallet can also view its own spends).
    pub fn nullifier(&self, rho: &Lanes) -> Lanes {
        self.sk.nullifier(rho)
    }

    /// **Spend capability:** produce the circuit spend witness for a note
    /// received at diversifier `d` (the circuit re-derives `rkm(d)`, so `d` must
    /// be the note's address diversifier — issue #32). This method exists ONLY
    /// here and on `SpendingKey`; `Fvk`/`Ivk` cannot.
    pub fn spend_input(
        &self,
        value: u64,
        rho: Lanes,
        rseed: Lanes,
        d: Diversifier,
    ) -> qlab_air::narrow::TxInput {
        self.sk.spend_input(value, rho, rseed, d.lanes())
    }

    /// The serialized ek for diversifier `d` (convenience for tests/tools).
    pub fn ek_bytes(&self, d: &Diversifier) -> [u8; qlab_note::kem::EK_LEN] {
        ek_to_bytes(&self.diversified_keypair(d).ek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: Lanes = [0x1234, 0x5678, 0x9abc, 0xdef0];

    #[test]
    fn fvk_views_spends_matching_spending_key() {
        let w = Wallet::from_seed_lanes(SK);
        let fvk = w.fvk();
        let rho: Lanes = [7, 8, 9, 10];
        // fvk computes the SAME nullifier the spend key would — it views spends.
        assert_eq!(fvk.nullifier(&rho), w.nullifier(&rho));
    }

    #[test]
    fn fvk_derives_rkm_matching_wallet() {
        let w = Wallet::from_seed_lanes(SK);
        let fvk = w.fvk();
        // The fvk derives the SAME per-diversifier rkm the wallet does (it holds
        // nk); the downgrade to ivk drops that capability (issue #32).
        for d in [Diversifier::default(), Diversifier::from_bytes([3u8; 16])] {
            assert_eq!(fvk.rkm(d), w.rkm(d), "fvk rkm(d) == wallet rkm(d)");
        }
    }

    #[test]
    fn fvk_and_wallet_produce_the_same_address() {
        // The wallet and its full viewing key produce byte-identical addresses;
        // the ivk can no longer self-generate one (it lacks nk to derive rkm(d),
        // issue #32) — it is handed the full address to scan.
        let w = Wallet::from_seed_lanes(SK);
        let d = Diversifier::from_bytes([3u8; 16]);
        let a_wallet = w.address(d).to_raw_bytes();
        let a_fvk = w.fvk().address(d).to_raw_bytes();
        assert_eq!(a_wallet, a_fvk, "fvk address == wallet address");
    }

    #[test]
    fn addresses_of_one_wallet_are_unlinkable() {
        // Issue #32 core guarantee at the key layer: two diversified addresses
        // of ONE wallet carry DISTINCT rkm (the linkability M7 flagged is gone),
        // while sharing the same underlying nk.
        let w = Wallet::from_seed_lanes(SK);
        let d0 = Diversifier::from_bytes([0u8; 16]);
        let d1 = Diversifier::from_bytes([1u8; 16]);
        assert_ne!(w.rkm(d0), w.rkm(d1), "distinct diversifiers -> distinct rkm");
        assert_ne!(
            w.address(d0).rkm_lanes(),
            w.address(d1).rkm_lanes(),
            "the two addresses carry distinct rkm on the wire"
        );
    }

    #[test]
    fn diversified_keypairs_differ_but_are_deterministic() {
        let w = Wallet::from_seed_lanes(SK);
        let d0 = Diversifier::from_bytes([0u8; 16]);
        let d1 = Diversifier::from_bytes([1u8; 16]);
        // Deterministic: same d -> same ek.
        assert_eq!(w.ek_bytes(&d0), w.ek_bytes(&d0));
        // Distinct diversifiers -> distinct ML-KEM keypairs (the diversification
        // that Option 1 DOES provide).
        assert_ne!(w.ek_bytes(&d0), w.ek_bytes(&d1));
    }

    #[test]
    fn different_wallets_have_different_keys() {
        let w1 = Wallet::from_seed_lanes(SK);
        let w2 = Wallet::from_seed_lanes([1, 1, 1, 1]);
        let d = Diversifier::default();
        assert_ne!(w1.nk(), w2.nk());
        assert_ne!(w1.rkm(d), w2.rkm(d));
        assert_ne!(w1.fvk().div_seed, w2.fvk().div_seed);
    }
}
