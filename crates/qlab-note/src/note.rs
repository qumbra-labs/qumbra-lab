//! The note object and its commitment.
//!
//! A note is `(value, rkm, rho, rseed)` — exactly the tuple
//! `transaction-model-and-anonymity-set.md` §4 defines as
//! `note = (value, recipient_key_material, ρ, rseed)`, with `cm = H(note)`.
//!
//! `note_commitment` recomputes the commitment by CALLING qlab-air's
//! permutation (`qlab_air::reference::keccak_f`) with the EXACT state packing
//! the circuit binds (`crates/qlab-air/src/narrow.rs` `build_bucket` output
//! `cm_out`). It is NOT a fork: a test regression-locks it byte-for-byte to
//! `build_bucket`. This is the FO-skip path's authenticity anchor.

use qlab_air::reference::keccak_f;

/// Serialized note plaintext length: `value` (8) + rkm/rho/rseed (32 each).
pub const NOTE_PLAINTEXT_LEN: usize = 8 + 32 + 32 + 32;

/// An output note. `rkm` (recipient key material) is what the address's key
/// hierarchy binds; `rho` is the Orchard-style uniqueness seed; `rseed` the
/// randomness seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    pub value: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

/// `cm = H(value ‖ rkm ‖ rho ‖ rseed)` in qlab-air's exact packing:
/// lane 0 = value, lanes 1..5 = rkm, 5..9 = rho, 9..13 = rseed, then the
/// original pad10*1 (`st[13]=1`, `st[16]=1<<63`); digest = permuted lanes 0..4.
/// Calls `qlab_air::reference::keccak_f` — the same primitive the consensus
/// circuit uses. Regression-locked to `build_bucket` in tests.
pub fn note_commitment(value: u64, rkm: &[u64; 4], rho: &[u64; 4], rseed: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[0] = value;
    st[1..5].copy_from_slice(rkm);
    st[5..9].copy_from_slice(rho);
    st[9..13].copy_from_slice(rseed);
    st[13] = 1;
    st[16] = 1 << 63;
    let d = keccak_f(&st);
    d[..4].try_into().expect("state has >= 4 lanes")
}

impl Note {
    /// The note commitment `cm` (as qlab-air's `[u64; 4]` digest).
    pub fn commitment(&self) -> [u64; 4] {
        note_commitment(self.value, &self.rkm, &self.rho, &self.rseed)
    }

    /// Fixed-width plaintext: value then rkm/rho/rseed, all lanes little-endian.
    pub fn to_plaintext(&self) -> [u8; NOTE_PLAINTEXT_LEN] {
        let mut out = [0u8; NOTE_PLAINTEXT_LEN];
        out[0..8].copy_from_slice(&self.value.to_le_bytes());
        let lanes = [&self.rkm, &self.rho, &self.rseed];
        let mut off = 8;
        for arr in lanes {
            for lane in arr {
                out[off..off + 8].copy_from_slice(&lane.to_le_bytes());
                off += 8;
            }
        }
        out
    }

    /// Parse a plaintext produced by `to_plaintext`. Returns `None` on a
    /// length mismatch (e.g. a truncated/garbled AEAD plaintext).
    pub fn from_plaintext(b: &[u8]) -> Option<Note> {
        if b.len() != NOTE_PLAINTEXT_LEN {
            return None;
        }
        let rd = |off: usize| {
            let mut l = [0u8; 8];
            l.copy_from_slice(&b[off..off + 8]);
            u64::from_le_bytes(l)
        };
        let value = rd(0);
        let mut arrs = [[0u64; 4]; 3];
        let mut off = 8;
        for arr in arrs.iter_mut() {
            for lane in arr.iter_mut() {
                *lane = rd(off);
                off += 8;
            }
        }
        Some(Note {
            value,
            rkm: arrs[0],
            rho: arrs[1],
            rseed: arrs[2],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u64) -> Note {
        let lane = |k: u64| {
            core::array::from_fn::<u64, 4, _>(|i| {
                seed.wrapping_mul(0x9e3779b97f4a7c15)
                    .wrapping_add(k << 8)
                    .wrapping_add(i as u64 + 1)
            })
        };
        Note {
            value: 1000 + seed,
            rkm: lane(1),
            rho: lane(2),
            rseed: lane(3),
        }
    }

    #[test]
    fn plaintext_roundtrip() {
        let n = sample(7);
        let pt = n.to_plaintext();
        assert_eq!(pt.len(), NOTE_PLAINTEXT_LEN);
        assert_eq!(Note::from_plaintext(&pt), Some(n));
        // Wrong length rejected.
        assert_eq!(Note::from_plaintext(&pt[..NOTE_PLAINTEXT_LEN - 1]), None);
    }

    /// THE hard-line guarantee: `note_commitment` is byte-identical to what
    /// qlab-air's `build_bucket` binds as the output commitment. If qlab-air's
    /// packing ever changes, this test breaks — the recompute cannot drift.
    #[test]
    fn commitment_matches_qlab_air_build_bucket() {
        use qlab_air::narrow::{build_bucket, TxInput, TxOutput};

        let out0 = sample(11);
        let out1 = sample(22);
        // Balanced bucket: sum(in) = sum(out) + fee.
        let fee = 10u64;
        let total_out = out0.value + out1.value + fee;
        let inputs = [
            TxInput {
                sk: [1, 2, 3, 4],
                value: total_out - 50,
                rho: [5, 6, 7, 8],
                rseed: [9, 10, 11, 12],
                d: [0, 0],
            },
            TxInput {
                sk: [13, 14, 15, 16],
                value: 50,
                rho: [17, 18, 19, 20],
                rseed: [21, 22, 23, 24],
                d: [0, 0],
            },
        ];
        let outputs = [
            TxOutput { value: out0.value, rkm: out0.rkm, rho: out0.rho, rseed: out0.rseed },
            TxOutput { value: out1.value, rkm: out1.rkm, rho: out1.rho, rseed: out1.rseed },
        ];
        let inst = build_bucket(18, &inputs, &outputs, fee);

        assert_eq!(out0.commitment(), inst.cm_out[0], "output 0 cm must match circuit");
        assert_eq!(out1.commitment(), inst.cm_out[1], "output 1 cm must match circuit");
    }
}
