//! The key hierarchy — root `sk` -> `nk` -> `rkm`, and the nullifier `nf`.
//!
//! Every derivation here is byte-for-byte what the spend circuit checks
//! (`qlab_air::narrow` roles `ROLE_ANK`/`ROLE_ARKM`/`ROLE_NF`; host path in
//! `build_bucket`, `narrow.rs:935-966`). Each is a single-block Keccak-f[1600]
//! over a `[u64; 25]` state (lane `i` = a 64-bit little-endian word); the digest
//! is output lanes 0..3. If any of these drifts from the circuit, a wallet-made
//! note becomes unspendable — so the tests regression-lock them against the
//! PUBLIC outputs of `build_bucket` (same precedent as `qlab-note`'s cm lock).
//!
//! ## Domain separation
//!
//! The circuit separates the `nk` and `rkm` domains with a single MARKER BIT at
//! lane 4 (`z0` for domain "N", `z1` for domain "R") — NOT an ASCII prefix,
//! because the in-circuit absorb was optimised to one block. We reproduce that
//! exactly. (The wallet-only KDFs — ML-KEM seeds, short-address — use ASCII
//! domain strings à la `qlab-note`; they live in `address`/`viewing`.)
//!
//! - `nk  = H(sk ‖ D_N)`  — msg lanes 0..3 = sk, marker `1<<0` at lane 4.
//! - `rkm = H(nk ‖ D_R)`  — msg lanes 0..3 = nk, marker `1<<1` at lane 4.
//! - `nf  = H(nk ‖ ρ)`    — msg lanes 0..3 = nk, 4..7 = ρ (512-bit message).

use qlab_air::reference::keccak_f;

/// A 256-bit value as four little-endian 64-bit lanes — the representation the
/// circuit and `qlab-note` share for keys, seeds, commitments, and nullifiers.
pub type Lanes = [u64; 4];

/// `nk` domain marker: bit `z0` set at lane 4 (value `1<<0`). Matches
/// `narrow.rs:938` (`nk_in[4] = 1`).
pub const D_N_MARKER: u64 = 1 << 0;
/// `rkm` domain marker: bit `z1` set at lane 4 (value `1<<1`). Matches
/// `narrow.rs:952` (`rkm_in[4] = 1 << 1`).
pub const D_R_MARKER: u64 = 1 << 1;

/// `nk = H(sk ‖ D_N)`. State: `st[0..4]=sk`, `st[4]=1<<0` (domain N), then
/// original pad10*1 (`st[5]=1` at bit 320, `st[16]=1<<63` at bit 1087).
/// Byte-identical to `build_bucket`'s `nk_in` packing (narrow.rs:936-941).
pub fn derive_nk(sk: &Lanes) -> Lanes {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(sk);
    st[4] = D_N_MARKER;
    st[5] = 1;
    st[16] = 1 << 63;
    let d = keccak_f(&st);
    d[..4].try_into().expect("state has >= 4 lanes")
}

/// `rkm = H(nk ‖ D_R)`. State: `st[0..4]=nk`, `st[4]=1<<1` (domain R), same
/// pad. Byte-identical to `build_bucket`'s `rkm_in` packing (narrow.rs:950-955).
pub fn derive_rkm(nk: &Lanes) -> Lanes {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(nk);
    st[4] = D_R_MARKER;
    st[5] = 1;
    st[16] = 1 << 63;
    let d = keccak_f(&st);
    d[..4].try_into().expect("state has >= 4 lanes")
}

/// `nf = H(nk ‖ ρ)`. State: `st[0..4]=nk`, `st[4..8]=ρ`, pad10*1 at bit 512
/// (`st[8]=1`) and bit 1087 (`st[16]=1<<63`) — the same wiring as a Merkle
/// node `H(left ‖ right)`. Byte-identical to `build_bucket`'s `nf_in` packing
/// (narrow.rs:943-948).
pub fn derive_nf(nk: &Lanes, rho: &Lanes) -> Lanes {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(nk);
    st[4..8].copy_from_slice(rho);
    st[8] = 1;
    st[16] = 1 << 63;
    let d = keccak_f(&st);
    d[..4].try_into().expect("state has >= 4 lanes")
}

/// The root spending key `sk`. Holds the ONLY capability that can produce a
/// spend witness for the circuit (see [`SpendingKey::spend_input`]); `Fvk`/`Ivk`
/// deliberately cannot (type-level separation). This crate takes `sk` as a given
/// 256-bit secret — HD-seed / mnemonic derivation is out of M7 scope.
#[derive(Clone)]
pub struct SpendingKey {
    sk: Lanes,
}

impl SpendingKey {
    /// Wrap a raw 256-bit secret as the spending key.
    pub fn from_lanes(sk: Lanes) -> Self {
        Self { sk }
    }

    /// The nullifier key `nk = H(sk ‖ D_N)`.
    pub fn nk(&self) -> Lanes {
        derive_nk(&self.sk)
    }

    /// The recipient key material `rkm = H(nk ‖ D_R)` bound into every note's
    /// commitment for this wallet.
    pub fn rkm(&self) -> Lanes {
        derive_rkm(&self.nk())
    }

    /// The nullifier `nf = H(nk ‖ ρ)` for a note with uniqueness seed `ρ`.
    pub fn nullifier(&self, rho: &Lanes) -> Lanes {
        derive_nf(&self.nk(), rho)
    }

    /// Produce the spend witness the circuit consumes — the type-level SPEND
    /// CAPABILITY. Only `SpendingKey` exposes this; a `Fvk`/`Ivk` holder has no
    /// `sk` and no path to a `TxInput`, so it cannot author a spend. (Proving
    /// the witness is out of scope; this is the key-layer boundary.)
    pub fn spend_input(&self, value: u64, rho: Lanes, rseed: Lanes) -> qlab_air::narrow::TxInput {
        qlab_air::narrow::TxInput {
            sk: self.sk,
            value,
            rho,
            rseed,
        }
    }

    /// Raw `sk` lanes — only for callers that already hold the `SpendingKey`
    /// (e.g. seeding the wallet's ML-KEM keypair). Kept crate-visible so the
    /// secret does not leak through the public API by accident.
    pub(crate) fn sk_lanes(&self) -> Lanes {
        self.sk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::{build_bucket, TxInput, TxOutput};
    use qlab_air::reference::{keccak_f, merkle_node_state};
    use qlab_note::note::note_commitment;

    // A balanced 2x2 bucket whose two inputs use the wallet's spend keys, so
    // its PUBLIC outputs (nf[], anchor) externally witness our derivations.
    fn balanced_bucket() -> (
        [TxInput; 2],
        [TxOutput; 2],
        u64,
        qlab_air::narrow::BucketInstance,
    ) {
        let sk0: Lanes = [0xdead, 0xbeef, 0xcafe, 0xf00d];
        let sk1: Lanes = [1, 2, 3, 4];
        let rho0: Lanes = [11, 22, 33, 44];
        let rho1: Lanes = [55, 66, 77, 88];
        let rseed0: Lanes = [101, 102, 103, 104];
        let rseed1: Lanes = [201, 202, 203, 204];
        let fee = 7u64;
        // Outputs: give output rkm the wallet-derived rkm of sk0 (exercises the
        // output cm path with a real recipient key material too).
        let out_rkm = SpendingKey::from_lanes(sk0).rkm();
        let outputs = [
            TxOutput { value: 300, rkm: out_rkm, rho: [9; 4], rseed: [8; 4] },
            TxOutput { value: 400, rkm: [7; 4], rho: [6; 4], rseed: [5; 4] },
        ];
        let total_out = 300 + 400 + fee;
        let inputs = [
            TxInput { sk: sk0, value: total_out - 250, rho: rho0, rseed: rseed0 },
            TxInput { sk: sk1, value: 250, rho: rho1, rseed: rseed1 },
        ];
        let inst = build_bucket(18, &inputs, &outputs, fee);
        (inputs, outputs, fee, inst)
    }

    /// LOCK 1 (nk path, external): `nf = H(nk ‖ ρ)` computed by the wallet must
    /// equal the circuit builder's public `nf[i]`. Since `nk = H(sk ‖ D_N)` is a
    /// preimage of `nf`, any drift in the nk derivation (packing, domain bit,
    /// pad) flips `nf`. Locks `sk -> nk -> nf` to qlab-air.
    #[test]
    fn nk_nf_path_locked_to_build_bucket() {
        let (inputs, _out, _fee, inst) = balanced_bucket();
        for (i, inp) in inputs.iter().enumerate() {
            let sk = SpendingKey::from_lanes(inp.sk);
            assert_eq!(
                sk.nullifier(&inp.rho),
                inst.nf[i],
                "wallet nf must match circuit nf[{i}] (locks sk->nk->nf)"
            );
        }
    }

    /// LOCK 2 (rkm path, external via anchor): rebuild the shared Merkle tree
    /// from wallet-derived input commitments (`cm = H(value ‖ rkm ‖ ρ ‖ rseed)`,
    /// `rkm = H(nk ‖ D_R)`) using the SAME sibling schedule as `build_bucket`,
    /// and assert the root equals the circuit's public `anchor`. The anchor
    /// depends on the input cm -> rkm -> nk, so this locks the rkm derivation to
    /// qlab-air. (Mirrors `build_bucket`'s tree; if that tree changes, this test
    /// intentionally breaks to force re-verification.)
    #[test]
    fn rkm_path_locked_via_anchor() {
        use qlab_air::narrow::MERKLE_DEPTH;
        let (inputs, _out, _fee, inst) = balanced_bucket();

        // Wallet-derived input commitments (this is the rkm-dependent value).
        let cm = |inp: &TxInput| {
            let rkm = SpendingKey::from_lanes(inp.sk).rkm();
            note_commitment(inp.value, &rkm, &inp.rho, &inp.rseed)
        };
        let cm0 = cm(&inputs[0]);
        let cm1 = cm(&inputs[1]);

        // Same deterministic upper-sibling schedule as build_bucket.
        let mut x = 0xa5a5_5a5a_dead_beefu64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let upper: Vec<Lanes> = (1..MERKLE_DEPTH).map(|_| [rnd(), rnd(), rnd(), rnd()]).collect();

        // Leaf 0's path: node(cm0, cm1) then fold in each upper sibling.
        let mut d = merkle_node_state(&cm0, &cm1);
        for sib in &upper {
            let dd: Lanes = d[..4].try_into().unwrap();
            d = merkle_node_state(&dd, sib);
        }
        let root: Lanes = d[..4].try_into().unwrap();
        assert_eq!(root, inst.anchor, "wallet-derived root must match circuit anchor (locks rkm)");
    }

    /// LOCK 3 (rkm packing, belt-and-suspenders): a byte-identical replication
    /// of `narrow.rs:950-955`'s `rkm_in` packing must equal `derive_rkm`. Catches
    /// a transcription slip in this crate even independently of the anchor lock.
    #[test]
    fn rkm_packing_byte_identical() {
        let nk: Lanes = [0x1111, 0x2222, 0x3333, 0x4444];
        let mut rkm_in = [0u64; 25];
        rkm_in[..4].copy_from_slice(&nk);
        rkm_in[4] = 1 << 1; // domain R (z1) — literal, as in narrow.rs
        rkm_in[5] = 1;
        rkm_in[16] = 1 << 63;
        let expected: Lanes = keccak_f(&rkm_in)[..4].try_into().unwrap();
        assert_eq!(derive_rkm(&nk), expected);
    }

    /// Determinism + domain non-collision of the three derivations.
    #[test]
    fn derivations_deterministic_and_separated() {
        let sk: Lanes = [5, 6, 7, 8];
        let nk = derive_nk(&sk);
        assert_eq!(derive_nk(&sk), nk, "nk deterministic");
        let rkm = derive_rkm(&nk);
        assert_eq!(derive_rkm(&nk), rkm, "rkm deterministic");
        // nk and rkm differ only by the lane-4 marker; outputs must differ.
        assert_ne!(nk, rkm, "nk and rkm must be domain-separated");
        // nf over rho=nk-lanes must not collide with rkm (different pad length).
        let nf = derive_nf(&nk, &sk);
        assert_ne!(nf, rkm);
        assert_ne!(nf, nk);
    }

    /// The spend witness carries `sk` verbatim into the circuit's `TxInput`.
    #[test]
    fn spend_input_carries_sk() {
        let sk: Lanes = [9, 10, 11, 12];
        let w = SpendingKey::from_lanes(sk);
        let inp = w.spend_input(42, [1; 4], [2; 4]);
        assert_eq!(inp.sk, sk);
        assert_eq!(inp.value, 42);
    }
}
