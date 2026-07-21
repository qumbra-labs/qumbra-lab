//! Proof-of-work behind a trait, with a Keccak-based **placeholder**.
//!
//! The exact PoW algorithm is an **OPEN design question** (consensus-and-network.md
//! §10: CPU-friendly RandomX-class, "adopt vs specify anew — needs its own
//! evaluation"). This crate therefore does NOT decide it: PoW is abstracted behind
//! [`PowEngine`], and the only implementation shipped is [`KeccakPow`], a
//! stand-in. RandomX is deliberately not integrated. Swapping in a real algorithm
//! later means adding a `PowEngine` impl — no code here presumes the answer.
//!
//! ## Sim difficulty model
//!
//! A real target is a 256-bit threshold. The devnet uses a scalar simplification:
//! interpret the PoW hash's leading 8 bytes as a big-endian `u64`, and require it
//! `≤ u64::MAX / difficulty`. Higher difficulty ⇒ smaller threshold ⇒ more work,
//! and a block's `difficulty` doubles as its heaviest-chain weight (棒 1). This is
//! a sim convenience, not a consensus rule proposal.

use crate::header::{BlockHeader, Hash32};
use crate::params_devnet;

/// The PoW algorithm, abstracted so the placeholder can be swapped for a real
/// RandomX-class design without any caller change (and without this crate ever
/// deciding the algorithm — consensus §10).
pub trait PowEngine {
    /// Human-readable algorithm name (surfaced in logs / reports).
    fn name(&self) -> &'static str;

    /// The PoW hash of `header`. Mining varies `header.nonce` and re-hashes until
    /// [`satisfies_target`] holds for `header.difficulty`.
    fn pow_hash(&self, header: &BlockHeader) -> Hash32;
}

/// DEVNET PLACEHOLDER PoW: Keccak-256 of the header preimage.
///
/// Not a design decision (consensus §10). A stand-in behind [`PowEngine`] so the
/// rest of the devnet — mining loop, validation, fork choice — can be built and
/// measured while the real CPU-friendly algorithm remains an open question.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakPow;

impl PowEngine for KeccakPow {
    fn name(&self) -> &'static str {
        "keccak-devnet-placeholder"
    }

    fn pow_hash(&self, header: &BlockHeader) -> Hash32 {
        header.header_hash()
    }
}

/// Interpret a PoW hash's leading 8 bytes as a big-endian `u64` work value.
pub fn hash_to_work_value(hash: &Hash32) -> u64 {
    u64::from_be_bytes(hash[..8].try_into().expect("Hash32 has ≥ 8 bytes"))
}

/// The sim target threshold at `difficulty`: `u64::MAX / max(difficulty, 1)`.
/// Monotonically non-increasing in difficulty — more difficulty, harder target.
pub fn target_threshold(difficulty: u64) -> u64 {
    u64::MAX / difficulty.max(1)
}

/// Whether a PoW hash satisfies the target at `difficulty`.
pub fn satisfies_target(hash: &Hash32, difficulty: u64) -> bool {
    hash_to_work_value(hash) <= target_threshold(difficulty)
}

/// Retarget difficulty from the observed vs expected timespan of a window.
///
/// `new = clamp(current * target_timespan / actual_timespan,
///              current / F, current * F)`, with `F =
/// params_devnet::MAX_DIFFICULTY_ADJUST_FACTOR`. Faster-than-expected blocks
/// (`actual < target`) raise difficulty; slower blocks lower it. Computed in
/// `u128` to avoid overflow, then clamped back into `u64`.
pub fn next_difficulty(current: u64, actual_timespan: u64, target_timespan: u64) -> u64 {
    let current = current.max(1) as u128;
    let actual = actual_timespan.max(1) as u128;
    let target = target_timespan.max(1) as u128;
    let f = params_devnet::MAX_DIFFICULTY_ADJUST_FACTOR.max(1) as u128;

    let raw = current * target / actual;
    let lo = (current / f).max(1);
    let hi = current * f;
    let clamped = raw.clamp(lo, hi).min(u64::MAX as u128);
    clamped as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_monotone_in_difficulty() {
        // Higher difficulty ⇒ strictly-not-larger threshold.
        assert!(target_threshold(1) >= target_threshold(10));
        assert!(target_threshold(10) >= target_threshold(1_000));
        assert!(target_threshold(1_000) >= target_threshold(1_000_000));
        // Difficulty 0 is treated as 1 (no divide-by-zero).
        assert_eq!(target_threshold(0), target_threshold(1));
    }

    #[test]
    fn a_mined_nonce_actually_satisfies_the_target() {
        // At a low difficulty a valid nonce is found in a handful of tries; the
        // found header must satisfy the target under the same engine.
        let pow = KeccakPow;
        let mut h = BlockHeader::genesis(4, 0); // easy target
        let mut found = None;
        for nonce in 0..100_000u64 {
            h.nonce = nonce;
            let hash = pow.pow_hash(&h);
            if satisfies_target(&hash, h.difficulty) {
                found = Some(nonce);
                break;
            }
        }
        let nonce = found.expect("must find a valid nonce at difficulty 4");
        h.nonce = nonce;
        assert!(satisfies_target(&pow.pow_hash(&h), h.difficulty));
    }

    #[test]
    fn retarget_raises_on_fast_blocks_and_lowers_on_slow() {
        // Blocks came in twice as fast as target ⇒ difficulty roughly doubles.
        assert!(next_difficulty(1_000, 50, 100) > 1_000);
        // Blocks came in twice as slow ⇒ difficulty roughly halves.
        assert!(next_difficulty(1_000, 200, 100) < 1_000);
        // On-target ⇒ unchanged.
        assert_eq!(next_difficulty(1_000, 100, 100), 1_000);
    }

    #[test]
    fn retarget_is_clamped_to_the_max_factor() {
        let f = params_devnet::MAX_DIFFICULTY_ADJUST_FACTOR;
        // Absurdly fast blocks: clamp at current * F, not more.
        assert_eq!(next_difficulty(1_000, 1, 1_000_000), 1_000 * f);
        // Absurdly slow blocks: clamp at current / F, not less.
        assert_eq!(next_difficulty(1_000, 1_000_000, 1), 1_000 / f);
    }

    #[test]
    fn engine_name_is_marked_placeholder() {
        assert!(KeccakPow.name().contains("placeholder"));
    }
}
