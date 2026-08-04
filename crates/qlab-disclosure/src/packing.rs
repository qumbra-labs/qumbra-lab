//! The two hash packings the disclosure statement proves, computed in the
//! clear — the semantic authority the AIR (air.rs) must reproduce in-circuit,
//! and the STOP-POINT cross-check against qlab-air / qlab-wallet.
//!
//! The disclosure claim (wallet-interop-spec §3, claim 0x01) is, for one
//! on-chain output note:
//!
//! ```text
//!   public:  cm               the note commitment on-chain at (tx_ref, output_index)
//!            value            the disclosed amount
//!            addr_commitment  Keccak256(recipient's full raw address)
//!   witness: rkm, rho, rseed  the note opening
//!            version, d, ek   the recipient address fields
//!   prove:   cm              == H_commit(value ‖ rkm ‖ rho ‖ rseed)   [qlab-air packing]
//!        ∧   addr_commitment == Keccak256(version ‖ d ‖ rkm ‖ ek)     [qlab-wallet layout]
//! ```
//!
//! The shared `rkm` is what binds "this payment (cm) went to THAT address
//! (addr_commitment)": it is the note's recipient key material AND the
//! address's `rkm` field. Change the address and its `rkm` changes, so no
//! other cm opens to it.

use qlab_air::reference::keccak_f;

/// A 256-bit digest in qlab-air's lane representation (`[u64; 4]`, lane-major
/// little-endian). `cm` is carried this way on the wire and in the AIR.
pub type Digest = [u64; 4];

/// `H_commit(value ‖ rkm ‖ rho ‖ rseed)` — the note commitment, packed
/// EXACTLY as `qlab_air::narrow::build_bucket`'s ROLE_ACM / ROLE_ACMOUT
/// perm packs it (narrow.rs lines 123–129, 1019–1044):
///
/// ```text
///   lane 0      = value               (u64)
///   lanes 1..5  = rkm                  (4 words)
///   lanes 5..9  = rho                  (4 words)
///   lanes 9..13 = rseed                (4 words)
///   lane 13     = 1                    (pad10*1 start, bit 832)
///   lane 16     = 1 << 63              (pad10*1 end,   bit 1087)
///   cm          = keccak_f(state)[..4]
/// ```
///
/// The message is 8 + 32 + 32 + 32 = 104 bytes < the 136-byte Keccak rate, so
/// this is a single permutation. Equivalently (locked in tests): `cm ==
/// keccak256(value_le ‖ rkm_le ‖ rho_le ‖ rseed_le)`.
pub fn note_commitment(value: u64, rkm: &Digest, rho: &Digest, rseed: &Digest) -> Digest {
    let mut st = [0u64; 25];
    st[0] = value;
    st[1..5].copy_from_slice(rkm);
    st[5..9].copy_from_slice(rho);
    st[9..13].copy_from_slice(rseed);
    st[13] = 1; // pad10*1 start (bit 832)
    st[16] = 1 << 63; // pad10*1 end (bit 1087)
    let out = keccak_f(&st);
    out[..4].try_into().unwrap()
}

/// `Keccak256(version ‖ d ‖ rkm ‖ ek)` — the recipient address commitment,
/// which is plain `Keccak256(Address::to_raw_bytes())` over the 1,233-byte
/// raw address (wallet-interop-spec §3: `recipient_addr_commitment (32 B =
/// Keccak256(full address))`). This is NOT qlab-wallet's short-address form
/// (that is domain-separated `Keccak256(DS_SHORTADDR ‖ raw)[..16]`).
///
/// Delegates to `qlab_note::hash::keccak256` so the sponge is the one
/// primitive shared across the whole stack — no fork.
pub fn addr_commitment(raw_address: &[u8]) -> [u8; 32] {
    qlab_note::hash::keccak256(raw_address)
}

/// The `rkm` slice inside a raw address's byte layout: `version(1) ‖ d(16) ‖
/// rkm(32) ‖ ek(1184)`, so `rkm` occupies bytes 17..49. Used by the AIR trace
/// builder to place the bound `rkm` into address sponge block 0, and by tests
/// to confirm the byte offset the binding relies on.
pub const ADDR_RKM_OFFSET: usize = 1 + 16;
pub const ADDR_RKM_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::{build_bucket, derive_output_rho, TxInput, TxOutput};
    use qlab_note::hash::{digest_bytes, keccak256};
    use qlab_wallet::address::{Address, Diversifier};
    use qlab_wallet::keys::Lanes;
    use rand::{rngs::StdRng, SeedableRng};

    /// STOP-POINT lock 1: `note_commitment` reproduces `build_bucket`'s output
    /// commitment byte-for-byte. If qlab-air's ROLE_ACMOUT packing ever moves,
    /// this breaks and the disclosure statement shape is a spec question.
    ///
    /// 🔴 Issue #215 (i) moved it — not the packing, the **seed**: `rho'` is now
    /// derived (`rho'_0 = nf_0`, `rho'_1 = H(nf_0 ‖ D_P)`) and `build_bucket`
    /// overrides any `TxOutput::rho` a caller supplies. So the disclosure path
    /// must open the commitment at the DERIVED seed, which is what a discloser
    /// actually has: `nf_0` is `PV_NF1` and therefore public. The packing itself
    /// is unchanged, and this lock still says so.
    #[test]
    fn note_commitment_matches_build_bucket() {
        // Deterministic pseudo-random instance (mirrors narrow_bench).
        let mut x = 0xfeed_face_cafe_beefu64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let inputs = [
            TxInput {
                sk: [rnd(), rnd(), rnd(), rnd()],
                value: 50_000,
                rho: [rnd(), rnd(), rnd(), rnd()],
                rseed: [rnd(), rnd(), rnd(), rnd()],
                d: [0, 0],
            },
            TxInput {
                sk: [rnd(), rnd(), rnd(), rnd()],
                value: 30_000,
                rho: [rnd(), rnd(), rnd(), rnd()],
                rseed: [rnd(), rnd(), rnd(), rnd()],
                d: [0, 0],
            },
        ];
        let outputs = [
            TxOutput {
                value: 60_000,
                rkm: [rnd(), rnd(), rnd(), rnd()],
                rho: [rnd(), rnd(), rnd(), rnd()],
                rseed: [rnd(), rnd(), rnd(), rnd()],
            },
            TxOutput {
                value: 19_000,
                rkm: [rnd(), rnd(), rnd(), rnd()],
                rho: [rnd(), rnd(), rnd(), rnd()],
                rseed: [rnd(), rnd(), rnd(), rnd()],
            },
        ];
        let inst = build_bucket(18, &inputs, &outputs, 1_000);
        for (i, o) in outputs.iter().enumerate() {
            let rho = derive_output_rho(&inst.nf[0], i);
            let cm = note_commitment(o.value, &o.rkm, &rho, &o.rseed);
            assert_eq!(
                cm, inst.cm_out[i],
                "note_commitment must match build_bucket's output commitment {i}"
            );
        }
    }

    /// The direct-perm packing equals the byte-sponge Keccak-256 of the
    /// little-endian message — an independent path to the same digest, so a
    /// transcription slip in either can't self-validate.
    #[test]
    fn note_commitment_equals_keccak256_of_le_bytes() {
        let value: u64 = 0x0123_4567_89ab_cdef;
        let rkm: Digest = [1, 2, 3, 4];
        let rho: Digest = [5, 6, 7, 8];
        let rseed: Digest = [9, 10, 11, 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&value.to_le_bytes());
        msg.extend_from_slice(&digest_bytes(&rkm));
        msg.extend_from_slice(&digest_bytes(&rho));
        msg.extend_from_slice(&digest_bytes(&rseed));
        assert_eq!(msg.len(), 104);
        let via_bytes = keccak256(&msg);
        let via_perm = digest_bytes(&note_commitment(value, &rkm, &rho, &rseed));
        assert_eq!(via_perm, via_bytes);
    }

    fn sample_address(seed: u64, d: [u8; 16]) -> Address {
        let mut rng = StdRng::seed_from_u64(seed);
        let kp = qlab_note::kem::generate_keypair(&mut rng);
        let rkm: Lanes = [seed, seed ^ 0xff, seed.wrapping_mul(3), 42];
        Address::new(Diversifier::from_bytes(d), rkm, &kp.ek)
    }

    /// STOP-POINT lock 2: `addr_commitment` is plain Keccak256 of the full
    /// 1,233-byte raw address (§3 definition), and the `rkm` field sits at the
    /// byte offset the in-circuit binding depends on.
    #[test]
    fn addr_commitment_is_keccak256_of_raw() {
        let a = sample_address(7, [3u8; 16]);
        let raw = a.to_raw_bytes();
        assert_eq!(raw.len(), 1233, "raw address is version(1)+d(16)+rkm(32)+ek(1184)");
        assert_eq!(addr_commitment(&raw), keccak256(&raw));
        // The rkm bytes are exactly where the AIR expects them (bytes 17..49).
        assert_eq!(&raw[ADDR_RKM_OFFSET..ADDR_RKM_OFFSET + ADDR_RKM_LEN], &a.rkm);
        // And it is NOT the short-address (domain-separated, 16-byte) form.
        assert_ne!(&addr_commitment(&raw)[..16], &a.short().hash);
    }

    /// The shared-`rkm` binding is real: an address's `rkm` lanes are the same
    /// value the note commitment consumes, so a note sent to that address and
    /// the address commitment reference one `rkm`.
    #[test]
    fn shared_rkm_binds_note_to_address() {
        let a = sample_address(11, [1u8; 16]);
        let rkm = a.rkm_lanes();
        // rkm read from the raw bytes (as the AIR block-0 witness sees it)
        // equals rkm the note commitment is built from.
        let from_bytes = qlab_note::hash::digest_from_bytes(
            a.to_raw_bytes()[ADDR_RKM_OFFSET..ADDR_RKM_OFFSET + ADDR_RKM_LEN]
                .try_into()
                .unwrap(),
        );
        assert_eq!(from_bytes, rkm, "block-0 rkm bytes decode to the address rkm lanes");
    }
}
