//! The L2 note and its commitment — [`crate::note::Note`]'s L2 twin (W3,
//! lab #700; design `l2-own-circuit-decision.md` §2.1).
//!
//! An L2 note is `(value, asset, rkm, rho, rseed)` = 112 B, still one Keccak
//! block. `asset 0` is the fee asset. `note_commitment_l2` recomputes the
//! commitment by CALLING `qlab_air::l2::l2_cm` — the exact packing the
//! shape-S circuit binds (`st[0]=value, st[1]=asset, st[2..6]=rkm,
//! st[6..10]=rho, st[10..14]=rseed, pad st[14]=1, st[16]=1<<63`). It is not
//! a fork: the test below regression-locks it byte-for-byte to
//! `build_bucket_l2`'s output commitments, exactly as
//! `note::tests::commitment_matches_qlab_air_build_bucket` locks the L1 twin.
//!
//! Nothing else in this crate changes for L2 yet: the ML-KEM discovery
//! payload grows by the 8-B asset field "with one field added" (§2.1), which
//! is wallet/serving work outside W3.

use qlab_air::l2::l2_cm;

/// Serialized L2 note plaintext length: the L1's 104 plus the 8-B asset.
pub const L2_NOTE_PLAINTEXT_LEN: usize = crate::note::NOTE_PLAINTEXT_LEN + 8;

/// An L2 output note.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct L2Note {
    pub value: u64,
    pub asset: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

/// `cm = H(value ‖ asset ‖ rkm ‖ rho ‖ rseed)` in the shape-S packing.
pub fn note_commitment_l2(
    value: u64,
    asset: u64,
    rkm: &[u64; 4],
    rho: &[u64; 4],
    rseed: &[u64; 4],
) -> [u64; 4] {
    l2_cm(value, asset, rkm, rho, rseed)
}

impl L2Note {
    pub fn commitment(&self) -> [u64; 4] {
        note_commitment_l2(self.value, self.asset, &self.rkm, &self.rho, &self.rseed)
    }

    /// Fixed-width plaintext: value, asset, then rkm/rho/rseed, all lanes
    /// little-endian — the L1 layout with `asset` inserted after `value`.
    pub fn to_plaintext(&self) -> [u8; L2_NOTE_PLAINTEXT_LEN] {
        let mut out = [0u8; L2_NOTE_PLAINTEXT_LEN];
        out[0..8].copy_from_slice(&self.value.to_le_bytes());
        out[8..16].copy_from_slice(&self.asset.to_le_bytes());
        let mut off = 16;
        for arr in [&self.rkm, &self.rho, &self.rseed] {
            for lane in arr {
                out[off..off + 8].copy_from_slice(&lane.to_le_bytes());
                off += 8;
            }
        }
        out
    }

    pub fn from_plaintext(b: &[u8]) -> Option<L2Note> {
        if b.len() != L2_NOTE_PLAINTEXT_LEN {
            return None;
        }
        let rd = |off: usize| {
            let mut l = [0u8; 8];
            l.copy_from_slice(&b[off..off + 8]);
            u64::from_le_bytes(l)
        };
        let value = rd(0);
        let asset = rd(8);
        let mut arrs = [[0u64; 4]; 3];
        let mut off = 16;
        for arr in arrs.iter_mut() {
            for lane in arr.iter_mut() {
                *lane = rd(off);
                off += 8;
            }
        }
        Some(L2Note { value, asset, rkm: arrs[0], rho: arrs[1], rseed: arrs[2] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u64, asset: u64) -> L2Note {
        let lane = |k: u64| {
            core::array::from_fn::<u64, 4, _>(|i| {
                seed.wrapping_mul(0x9e3779b97f4a7c15)
                    .wrapping_add(k << 8)
                    .wrapping_add(i as u64 + 1)
            })
        };
        L2Note { value: 1000 + seed, asset, rkm: lane(1), rho: lane(2), rseed: lane(3) }
    }

    #[test]
    fn l2_plaintext_roundtrip() {
        let n = sample(7, 3);
        let pt = n.to_plaintext();
        assert_eq!(pt.len(), 112, "the 112-B L2 note of §2.1");
        assert_eq!(L2Note::from_plaintext(&pt), Some(n));
        assert_eq!(L2Note::from_plaintext(&pt[..111]), None);
    }

    /// The asset is INSIDE the commitment: two notes equal in everything but
    /// `asset` commit differently, and asset 0 vs the L1 packing are not the
    /// same function (lanes moved — `st[1]` is the asset, `rkm` starts at 2).
    #[test]
    fn l2_asset_is_committed_and_the_packing_is_not_the_l1s() {
        let a = sample(1, 0);
        let mut b = a;
        b.asset = 1;
        assert_ne!(a.commitment(), b.commitment());
        let l1 = crate::note::note_commitment(a.value, &a.rkm, &a.rho, &a.rseed);
        assert_ne!(a.commitment(), l1, "an asset-0 L2 note is not an L1 note");
    }

    /// THE lock: `note_commitment_l2` is byte-identical to what shape S binds
    /// as the output commitment. Carries the option-4 seed derivation exactly
    /// as the L1 lock does (`rho` read off `nf_0`).
    #[test]
    fn l2_commitment_matches_qlab_air_build_bucket_l2() {
        use qlab_air::l2::{build_bucket_l2, L2TxInput, L2TxOutput, SHAPE_S_LOG_HEIGHT};
        use qlab_air::narrow::derive_output_rho;

        let out0 = sample(11, 0);
        let out1 = sample(22, 7);
        let fee = 10u64;
        let inputs = [
            L2TxInput {
                sk: [1, 2, 3, 4],
                value: out0.value + fee,
                asset: 0,
                rho: [5, 6, 7, 8],
                rseed: [9, 10, 11, 12],
                d: [0, 0],
            },
            L2TxInput {
                sk: [13, 14, 15, 16],
                value: out1.value,
                asset: 7,
                rho: [17, 18, 19, 20],
                rseed: [21, 22, 23, 24],
                d: [0, 0],
            },
        ];
        let outputs = [
            L2TxOutput { value: out0.value, asset: 0, rkm: out0.rkm, rho: out0.rho, rseed: out0.rseed },
            L2TxOutput { value: out1.value, asset: 7, rkm: out1.rkm, rho: out1.rho, rseed: out1.rseed },
        ];
        let inst = build_bucket_l2(SHAPE_S_LOG_HEIGHT, &inputs, &outputs, fee);
        let recovered = |n: &L2Note, j: usize| L2Note { rho: derive_output_rho(&inst.nf[0], j), ..*n };
        assert_eq!(recovered(&out0, 0).commitment(), inst.cm_out[0], "output 0 cm must match circuit");
        assert_eq!(recovered(&out1, 1).commitment(), inst.cm_out[1], "output 1 cm must match circuit");
    }
}
