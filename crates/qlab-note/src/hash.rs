//! Keccak-256 sponge built on qlab-air's `reference::keccak_f`.
//!
//! Qumbra's stance is conservative-hash-everywhere; the note commitment and
//! Merkle layer are Keccak-256 with the ORIGINAL (Ethereum-style) pad10*1
//! (`qlab_air::reference::merkle_node_state`). This module reuses the SAME
//! permutation for the KEM key-schedule / detection-tag derivation, so the
//! whole M5 path stays on one hash family and one permutation implementation.
//!
//! Rate = 1088 bits (136 bytes), capacity = 512 bits, output = 256 bits.
//! Byte↔lane convention matches qlab-air: lane `i` holds bytes `8i..8i+8`
//! little-endian; the digest is lanes 0..4. Cross-checked against the
//! independent `tiny-keccak` implementation in tests so a sponge transcription
//! bug cannot silently self-validate.

use qlab_air::reference::keccak_f;

/// Keccak-256 rate in bytes (17 lanes).
const RATE: usize = 136;

/// XOR a full 136-byte rate block into the first 17 lanes of the state.
fn xor_rate(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (i, lane) in state.iter_mut().take(17).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *lane ^= u64::from_le_bytes(b);
    }
}

/// Keccak-256 (original pad10*1) of `input`, returning the 32-byte digest.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut chunks = input.chunks_exact(RATE);
    for block in &mut chunks {
        let arr: &[u8; RATE] = block.try_into().expect("chunks_exact yields RATE");
        xor_rate(&mut state, arr);
        state = keccak_f(&state);
    }
    // Final padded block: original Keccak pad10*1 (0x01 start, 0x80 end).
    let rem = chunks.remainder();
    let mut last = [0u8; RATE];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    xor_rate(&mut state, &last);
    state = keccak_f(&state);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// A 256-bit digest as `[u64; 4]` (qlab-air's cm representation) → 32 bytes,
/// lane-major little-endian. Used to feed a commitment into the derivation.
pub fn digest_bytes(d: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&d[i].to_le_bytes());
    }
    out
}

/// Inverse of [`digest_bytes`]: 32 little-endian bytes → `[u64; 4]` lanes.
/// The on-wire `cm` is bytes; scanning converts it back to qlab-air's lane
/// form to recompute the tag / commitment.
pub fn digest_from_bytes(b: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(&b[i * 8..i * 8 + 8]);
        u64::from_le_bytes(lane)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known Keccak-256 vectors (Ethereum-style, original padding — NOT SHA3).
    #[test]
    fn known_vectors() {
        // keccak256("")
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // keccak256("abc")
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    /// Cross-check against the independent tiny-keccak implementation across a
    /// range of lengths spanning the rate boundary (135/136/137 bytes) and
    /// multi-block inputs — a transcription bug in the sponge cannot survive.
    #[test]
    fn matches_tiny_keccak() {
        use tiny_keccak::{Hasher, Keccak};
        for len in [0usize, 1, 55, 135, 136, 137, 271, 272, 500] {
            let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
            let mut k = Keccak::v256();
            k.update(&msg);
            let mut expected = [0u8; 32];
            k.finalize(&mut expected);
            assert_eq!(keccak256(&msg), expected, "mismatch at len {len}");
        }
    }

    /// `digest_bytes` must equal `keccak256`-style little-endian lane packing:
    /// feeding the same 256 bits either way agrees.
    #[test]
    fn digest_bytes_roundtrip() {
        let d = [0x0123456789abcdefu64, 0xfedcba9876543210, 1, u64::MAX];
        let b = digest_bytes(&d);
        // Reconstruct lanes from bytes.
        for i in 0..4 {
            let mut lane = [0u8; 8];
            lane.copy_from_slice(&b[i * 8..i * 8 + 8]);
            assert_eq!(u64::from_le_bytes(lane), d[i]);
        }
    }

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
