//! Block-header validation — the consensus checks a node runs before accepting a
//! header, plus the difficulty-retarget rule that fixes what `difficulty` a block
//! is *allowed* to carry.
//!
//! ## Difficulty rule (sim)
//!
//! A **per-block sliding window**: after a warmup of `DIFFICULTY_WINDOW_BLOCKS`
//! blocks (during which difficulty holds at the parent's), each block retargets
//! from the wall-time the trailing `window` blocks actually took versus the
//! expected `window × target_block_time`, clamped by
//! [`crate::pow::next_difficulty`]. This is a sim choice — the real algorithm and
//! its parameters (window, block time, clamp) are OPEN (consensus §10 /
//! consensus-parameters appendix); the placeholders live in `params_devnet`.
//!
//! Timestamp rule is intentionally minimal (non-decreasing vs parent): no
//! median-time-past, no future-time bound. Those are real-consensus concerns, not
//! needed to exercise the devnet mechanics.

use crate::chain::ChainState;
use crate::header::BlockHeader;
use crate::params_devnet::DIFFICULTY_WINDOW_BLOCKS;
use crate::pow::{next_difficulty, satisfies_target, PowEngine};

/// Why a header was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// The parent hash is not known to the chain.
    UnknownParent,
    /// `height` is not `parent.height + 1`.
    BadHeight,
    /// Timestamp is strictly less than the parent's (time went backwards).
    NonMonotonicTimestamp,
    /// `difficulty` does not equal the value the retarget rule mandates here.
    WrongDifficulty { expected: u64, got: u64 },
    /// The PoW hash does not meet the target at the header's difficulty.
    PowUnsatisfied,
}

/// The difficulty a child of `parent_hash` MUST carry, per the sliding-window
/// retarget rule. `None` if `parent_hash` is unknown.
pub fn expected_difficulty(
    chain: &ChainState,
    parent_hash: &[u8; 32],
    target_block_time: u64,
) -> Option<u64> {
    let parent = chain.header(parent_hash)?;
    let child_height = parent.height + 1;
    let window = DIFFICULTY_WINDOW_BLOCKS;

    // Warmup: not enough history to retarget — hold the parent's difficulty.
    // First retarget is at child_height == window + 1 (so `ancestor(parent, window)`
    // reaches genesis, height 0).
    if window == 0 || child_height <= window {
        return Some(parent.difficulty);
    }

    // The block `window` steps before the parent bounds the trailing window.
    let anchor_hash = chain.ancestor(parent_hash, window)?;
    let anchor = chain.header(&anchor_hash)?;
    let actual_timespan = parent.timestamp.saturating_sub(anchor.timestamp);
    let target_timespan = window.saturating_mul(target_block_time);

    Some(next_difficulty(parent.difficulty, actual_timespan, target_timespan))
}

/// Run the full header validation for `header` against `chain`: parent present,
/// height, timestamp monotonicity, mandated difficulty, and PoW.
pub fn validate_header<P: PowEngine>(
    chain: &ChainState,
    pow: &P,
    header: &BlockHeader,
    target_block_time: u64,
) -> Result<(), ValidationError> {
    let parent = chain
        .header(&header.prev)
        .ok_or(ValidationError::UnknownParent)?;

    if header.height != parent.height + 1 {
        return Err(ValidationError::BadHeight);
    }
    if header.timestamp < parent.timestamp {
        return Err(ValidationError::NonMonotonicTimestamp);
    }

    let expected = expected_difficulty(chain, &header.prev, target_block_time)
        .ok_or(ValidationError::UnknownParent)?;
    if header.difficulty != expected {
        return Err(ValidationError::WrongDifficulty {
            expected,
            got: header.difficulty,
        });
    }

    if !satisfies_target(&pow.pow_hash(header), header.difficulty) {
        return Err(ValidationError::PowUnsatisfied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ZERO_HASH;
    use crate::mining::mine;
    use crate::params_devnet::{DIFFICULTY_WINDOW_BLOCKS as W, GENESIS_DIFFICULTY};
    use crate::pow::KeccakPow;

    const EASY: u64 = 8; // low difficulty so mining is instant in tests

    fn easy_genesis() -> BlockHeader {
        BlockHeader::genesis(EASY, 0)
    }

    /// During warmup the mandated difficulty is just the parent's.
    #[test]
    fn warmup_holds_parent_difficulty() {
        let c = ChainState::new(easy_genesis());
        let g = c.genesis_hash();
        assert_eq!(expected_difficulty(&c, &g, 2), Some(EASY));
    }

    /// Build a chain whose blocks arrive exactly on target; once past warmup the
    /// difficulty stays put (on-target ⇒ no change).
    #[test]
    fn on_target_keeps_difficulty_stable() {
        let block_time = 2;
        let pow = KeccakPow;
        let mut c = ChainState::new(BlockHeader::genesis(GENESIS_DIFFICULTY, 0));
        // Mine well past the warmup window at a steady on-target cadence.
        for _ in 0..(W + 3) {
            let tip = c.tip_hash();
            let parent = *c.header(&tip).unwrap();
            let diff = expected_difficulty(&c, &tip, block_time).unwrap();
            let header = BlockHeader::child_of(&parent, parent.timestamp + block_time, diff, ZERO_HASH);
            // Mine at the mandated difficulty (GENESIS_DIFFICULTY is low enough to
            // find a nonce within the budget in a few thousand tries).
            let mined = mine(&pow, header, 5_000_000).expect("mine on-target block");
            c.insert_header(mined).unwrap();
        }
        // The last mandated difficulty equals the genesis difficulty (on-target).
        let tip = c.tip_hash();
        assert_eq!(expected_difficulty(&c, &tip, block_time), Some(GENESIS_DIFFICULTY));
    }

    /// Faster-than-target blocks past warmup raise the mandated difficulty;
    /// slower blocks lower it.
    #[test]
    fn retarget_responds_to_block_rate() {
        let block_time = 100;
        // Fast chain: each block 1s apart (100× faster than target) ⇒ diff up.
        let fast = build_linear_chain(EASY, 1, W + 2);
        let fast_next = expected_difficulty(&fast, &fast.tip_hash(), block_time).unwrap();
        assert!(fast_next > EASY, "fast blocks must raise difficulty ({fast_next})");

        // Slow chain: each block 1000s apart (10× slower) ⇒ diff down.
        let slow = build_linear_chain(EASY, 1_000, W + 2);
        let slow_next = expected_difficulty(&slow, &slow.tip_hash(), block_time).unwrap();
        assert!(slow_next < EASY, "slow blocks must lower difficulty ({slow_next})");
    }

    /// A correctly-mined, correctly-difficultied header validates; tampering with
    /// difficulty, height, timestamp, or the PoW nonce each rejects.
    #[test]
    fn validate_accepts_good_and_rejects_bad() {
        let block_time = 2;
        let pow = KeccakPow;
        let mut c = ChainState::new(easy_genesis());
        let tip = c.tip_hash();
        let parent = *c.header(&tip).unwrap();
        let diff = expected_difficulty(&c, &tip, block_time).unwrap();
        let good = mine(
            &pow,
            BlockHeader::child_of(&parent, block_time, diff, ZERO_HASH),
            5_000_000,
        )
        .unwrap();
        assert_eq!(validate_header(&c, &pow, &good, block_time), Ok(()));

        // Wrong difficulty (mandated is EASY; claim something else).
        let mut wrong_diff = good;
        wrong_diff.difficulty = EASY + 1;
        assert!(matches!(
            validate_header(&c, &pow, &wrong_diff, block_time),
            Err(ValidationError::WrongDifficulty { .. })
        ));

        // Bad height.
        let mut bad_height = good;
        bad_height.height = 5;
        assert_eq!(
            validate_header(&c, &pow, &bad_height, block_time),
            Err(ValidationError::BadHeight)
        );

        // Unknown parent.
        let mut orphan = good;
        orphan.prev = [0xEE; 32];
        assert_eq!(
            validate_header(&c, &pow, &orphan, block_time),
            Err(ValidationError::UnknownParent)
        );

        // PoW not satisfied: keep the mandated difficulty but pick a nonce that
        // misses the easy target (search for a definitely-failing one so the test
        // is deterministic).
        let mut bad_pow = good;
        for nonce in 0..10_000u64 {
            bad_pow.nonce = nonce;
            if !satisfies_target(&pow.pow_hash(&bad_pow), bad_pow.difficulty) {
                break;
            }
        }
        assert_eq!(
            validate_header(&c, &pow, &bad_pow, block_time),
            Err(ValidationError::PowUnsatisfied)
        );

        // Keep the good block, then test the timestamp rule on a child of it
        // (whose parent now has timestamp = block_time > 0).
        let good_hash = c.insert_header(good).unwrap();
        assert_eq!(c.tip_height(), 1);
        let child_diff = expected_difficulty(&c, &good_hash, block_time).unwrap();
        let mut back = BlockHeader::child_of(&good, 0, child_diff, ZERO_HASH); // ts 0 < parent's block_time
        back.nonce = 0; // height/timestamp checks run before PoW, so the nonce is irrelevant here
        assert_eq!(
            validate_header(&c, &pow, &back, block_time),
            Err(ValidationError::NonMonotonicTimestamp)
        );
    }

    /// Helper: a linear mined chain of `n` blocks after genesis, each spaced
    /// `spacing` seconds apart, all at difficulty `diff`.
    fn build_linear_chain(diff: u64, spacing: u64, n: u64) -> ChainState {
        let pow = KeccakPow;
        let mut c = ChainState::new(BlockHeader::genesis(diff, 0));
        for i in 1..=n {
            let tip = c.tip_hash();
            let parent = *c.header(&tip).unwrap();
            let header = BlockHeader::child_of(&parent, i * spacing, diff, ZERO_HASH);
            let mined = mine(&pow, header, 5_000_000).expect("mine linear-chain block");
            c.insert_header(mined).unwrap();
        }
        c
    }
}
