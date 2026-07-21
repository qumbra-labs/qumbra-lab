//! Keccak-256 sponge built on `qlab_air::reference::keccak_f`.
//!
//! "Conservative hash everywhere in consensus" (performance-budget §2): the devnet
//! hashes headers, PoW preimages, and (later) committee-vote messages with the
//! same Keccak permutation the whole Qumbra consensus stack uses. The permutation
//! is `qlab_air::reference::keccak_f` — the sponge below is a thin wrapper, never
//! a fork of the primitive. The `keccak256_matches_tiny_keccak` test cross-checks
//! it against an independent implementation so a transcription bug can't
//! self-validate (same discipline as qlab-note).

use qlab_air::reference::keccak_f;

/// Keccak-256 rate in bytes (17 × 64-bit lanes).
const RATE: usize = 136;

/// XOR a full 136-byte rate block into the first 17 lanes of the state.
fn xor_rate(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (i, lane) in state.iter_mut().take(17).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *lane ^= u64::from_le_bytes(b);
    }
}

/// Keccak-256 (original `pad10*1`, 0x01 domain byte) of `input` → 32-byte digest.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check the sponge against an independent Keccak-256 (tiny-keccak) over
    /// a spread of lengths spanning the rate boundary (empty, sub-rate, exactly
    /// RATE, multi-block, non-aligned) — a transcription bug shows up here.
    #[test]
    fn keccak256_matches_tiny_keccak() {
        use tiny_keccak::{Hasher, Keccak};

        for len in [0usize, 1, 135, 136, 137, 200, 272, 273, 500] {
            let input: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();

            let ours = keccak256(&input);

            let mut k = Keccak::v256();
            k.update(&input);
            let mut theirs = [0u8; 32];
            k.finalize(&mut theirs);

            assert_eq!(ours, theirs, "keccak256 mismatch at len {len}");
        }
    }

    #[test]
    fn keccak256_is_deterministic() {
        assert_eq!(keccak256(b"qumbra"), keccak256(b"qumbra"));
        assert_ne!(keccak256(b"qumbra"), keccak256(b"qumbrb"));
    }
}
