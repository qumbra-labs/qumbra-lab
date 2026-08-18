//! Block-header validation — the consensus checks a node runs before accepting a
//! header, plus the difficulty-retarget rule (LWMA-120) that fixes what
//! `difficulty` a block is *allowed* to carry, and the RandomX key-block seed that
//! keys its PoW hash.
//!
//! ## Difficulty rule — LWMA-120 (M9-N3)
//!
//! Every block retargets from the trailing window of up to
//! [`LWMA_WINDOW_BLOCKS`] blocks via [`qlab_pow::lwma_next_difficulty`] (Zawy's
//! LWMA-1). No multi-block warmup hold: the retarget engages from the second
//! block (the first block below a full window uses whatever partial window
//! exists, which for an on-target chain is still a fixed point). The child of
//! genesis has no solvetime yet, so it holds the genesis difficulty. `T` is the
//! node's `block_time_secs` — the frozen 75 s on a real net, an accelerated value
//! in the sim (same algorithm, different `T`).
//!
//! ## RandomX key-block seed
//!
//! RandomX is keyed; [`pow_seed`] resolves the key for a block at a given height
//! to the hash of its key block (see `qlab_pow::keyblock`), walking the branch the
//! header extends. The Keccak placeholder ignores the seed; RandomX consumes it.
//!
//! Timestamp rule is intentionally minimal (non-decreasing vs parent): no
//! median-time-past, no future-time bound. Those are real-consensus concerns, not
//! needed to exercise the devnet mechanics.

use qlab_pow::keyblock::KeyBlockSchedule;
use qlab_pow::lwma_next_difficulty;

use crate::chain::ChainState;
use crate::forms::ChainRules;
use crate::halt::pow_value;
use crate::header::{BlockHeader, Hash32};
use crate::params_devnet::LWMA_WINDOW_BLOCKS;
use crate::pow::{satisfies_target, PowEngine};

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
    /// The RandomX key-block seed for this header could not be resolved (its key
    /// block is not reachable on the branch — should not happen for a well-linked
    /// header).
    UnknownSeed,
}

/// The RandomX **key-block seed** (RandomX key) for a block at `height` whose
/// parent is `parent_hash`, under key-block `schedule`.
///
/// The seed is the hash of the block at `schedule.seed_height(height)` on the
/// branch ending at `parent_hash`. During the initial epoch+lag blocks that
/// resolves to the branch's genesis hash (the bootstrap key). `None` if the key
/// block is not reachable (broken links / unknown parent).
pub fn pow_seed(
    chain: &ChainState,
    parent_hash: &Hash32,
    height: u64,
    schedule: KeyBlockSchedule,
) -> Option<Vec<u8>> {
    let parent = chain.header(parent_hash)?;
    // parent.height == height - 1; the seed block sits at seed_height ≤ parent.height.
    let seed_height = schedule.seed_height(height);
    let depth = parent.height.checked_sub(seed_height)?;
    let seed_block = chain.ancestor(parent_hash, depth)?;
    Some(seed_block.to_vec())
}

/// The difficulty a child of `parent_hash` MUST carry, per the LWMA-120 retarget
/// over the trailing window (`T = target_block_time`). `None` if `parent_hash` is
/// unknown.
pub fn expected_difficulty(
    chain: &ChainState,
    parent_hash: &Hash32,
    target_block_time: u64,
) -> Option<u64> {
    let parent = *chain.header(parent_hash)?;

    // Window = the min(N, parent.height) most-recent solvetimes ending at parent.
    // (parent.height is exactly how many intervals exist back to genesis.)
    let n = (LWMA_WINDOW_BLOCKS as u64).min(parent.height) as usize;
    if n == 0 {
        // Child of genesis: no solvetime yet — hold the genesis difficulty.
        return Some(parent.difficulty);
    }

    // Collect `n+1` headers ending at parent (newest→oldest), then reverse to
    // oldest-first for LWMA: timestamps[0..=n], difficulties of the n closing
    // blocks (heights parent-n+1 ..= parent).
    let mut timestamps = Vec::with_capacity(n + 1);
    let mut difficulties = Vec::with_capacity(n);
    for k in 0..=(n as u64) {
        let h = chain.ancestor(parent_hash, k)?;
        let hdr = chain.header(&h)?;
        timestamps.push(hdr.timestamp);
        if k < n as u64 {
            // k = 0..n are the n newest blocks (parent .. parent-n+1) — their
            // difficulties are the window's per-block difficulties.
            difficulties.push(hdr.difficulty);
        }
    }
    timestamps.reverse();
    difficulties.reverse();

    Some(lwma_next_difficulty(&timestamps, &difficulties, target_block_time))
}

/// Run the full header validation for `header` against `chain` under the **v1.0
/// rules**: parent present, height, timestamp monotonicity, mandated difficulty
/// (LWMA), and PoW under the resolved RandomX key-block seed.
///
/// This is the pre-halt rule set and is byte-for-byte what it always was. A node
/// running a release that resumes past an upgrade boundary calls
/// [`validate_header_under`] instead (issue #74).
pub fn validate_header<P: PowEngine>(
    chain: &ChainState,
    pow: &P,
    header: &BlockHeader,
    target_block_time: u64,
    schedule: KeyBlockSchedule,
) -> Result<(), ValidationError> {
    validate_header_under(chain, pow, header, target_block_time, schedule, &ChainRules::V1_0)
}

/// [`validate_header`] under an explicit [`ChainRules`] (issue #74; form-keyed
/// since lab #470 — the header preimage the PoW hashes is the layout
/// `rules.form` selects, so a v4 header on a v5 net fails PoW even before the
/// codec refuses its bytes by length).
///
/// The only difference from the v1.0 rules is the PoW **value**: above an upgrade
/// boundary the engine's PoW hash is domain-separated by the active revision
/// before the target check ([`crate::halt::pow_value`]). At and below the boundary
/// the two functions are identical, so no pre-halt block ever changes meaning.
///
/// Note what this function deliberately does **not** do: it does not reject blocks
/// above a halt height. Halting is a property of the *release*, enforced where a
/// node decides to mine or ingest; header validation stays a pure statement about
/// the chain, so a halted node can still be asked "would this header have been
/// valid?" while refusing to act on it.
pub fn validate_header_under<P: PowEngine>(
    chain: &ChainState,
    pow: &P,
    header: &BlockHeader,
    target_block_time: u64,
    schedule: KeyBlockSchedule,
    rules: &ChainRules,
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

    let seed =
        pow_seed(chain, &header.prev, header.height, schedule).ok_or(ValidationError::UnknownSeed)?;
    // Issue #74: above an upgrade boundary the PoW value is domain-separated by the
    // active revision. At and below it, this is byte-identical to the v1.0 rule.
    let value = pow_value(pow.pow_hash(rules.form, header, &seed), header.height, &rules.halt);
    if !satisfies_target(&value, header.difficulty) {
        return Err(ValidationError::PowUnsatisfied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ZERO_HASH;
    use crate::mining::mine;
    use crate::params_devnet::GENESIS_DIFFICULTY;
    use crate::pow::KeccakPow;

    const EASY: u64 = 8; // low difficulty so mining is instant in tests

    /// The default (Monero-shape) key-block schedule.
    fn sched() -> KeyBlockSchedule {
        KeyBlockSchedule::default()
    }

    fn easy_genesis() -> BlockHeader {
        BlockHeader::genesis(EASY, 0)
    }

    /// A child of genesis has no solvetime yet ⇒ the mandated difficulty holds at
    /// the parent's (the only "warmup" LWMA needs).
    #[test]
    fn child_of_genesis_holds_parent_difficulty() {
        let c = ChainState::new(easy_genesis());
        let g = c.genesis_block_hash();
        assert_eq!(expected_difficulty(&c, &g, 2), Some(EASY));
    }

    /// An on-target chain is an LWMA fixed point: past the first block the mandated
    /// difficulty stays at the genesis difficulty.
    #[test]
    fn on_target_keeps_difficulty_stable() {
        let block_time = 2;
        let pow = KeccakPow;
        let mut c = ChainState::new(BlockHeader::genesis(GENESIS_DIFFICULTY, 0));
        for _ in 0..20 {
            let tip = c.tip_hash();
            let parent = *c.header(&tip).unwrap();
            let diff = expected_difficulty(&c, &tip, block_time).unwrap();
            let header = BlockHeader::child_of(&parent, parent.timestamp + block_time, diff, ZERO_HASH);
            let mined = mine(&pow, header, 5_000_000, &[]).expect("mine on-target block");
            c.insert_header(mined).unwrap();
        }
        let tip = c.tip_hash();
        assert_eq!(expected_difficulty(&c, &tip, block_time), Some(GENESIS_DIFFICULTY));
    }

    /// Faster-than-target blocks raise the mandated difficulty; slower blocks lower
    /// it — from the very next retarget (no multi-block warmup hold).
    #[test]
    fn retarget_responds_to_block_rate() {
        let block_time = 100;
        // Fast chain: blocks 1 s apart (100× faster than target) ⇒ diff up.
        let fast = build_linear_chain(EASY, 1, 30);
        let fast_next = expected_difficulty(&fast, &fast.tip_hash(), block_time).unwrap();
        assert!(fast_next > EASY, "fast blocks must raise difficulty ({fast_next})");

        // Slow chain: blocks 1000 s apart (10× slower) ⇒ diff down.
        let slow = build_linear_chain(EASY, 1_000, 30);
        let slow_next = expected_difficulty(&slow, &slow.tip_hash(), block_time).unwrap();
        assert!(slow_next < EASY, "slow blocks must lower difficulty ({slow_next})");
    }

    /// The wiring matches the pure LWMA: `expected_difficulty` over a hand-built
    /// chain equals `lwma_next_difficulty` fed the same window directly.
    #[test]
    fn expected_difficulty_matches_pure_lwma_over_the_window() {
        let block_time = 50;
        // A chain with a deliberately irregular cadence so the window is non-trivial.
        let spacings = [40u64, 60, 55, 45, 70, 30, 50, 50, 65, 35];
        let pow = KeccakPow;
        let mut c = ChainState::new(BlockHeader::genesis(EASY, 0));
        let mut ts = 0u64;
        for &s in &spacings {
            let tip = c.tip_hash();
            let parent = *c.header(&tip).unwrap();
            ts += s;
            let diff = expected_difficulty(&c, &tip, block_time).unwrap();
            let header = BlockHeader::child_of(&parent, ts, diff, ZERO_HASH);
            c.insert_header(mine(&pow, header, 5_000_000, &[]).unwrap()).unwrap();
        }
        // Rebuild the exact window `expected_difficulty` would use for the next block.
        let tip = c.tip_hash();
        let parent = *c.header(&tip).unwrap();
        let n = (LWMA_WINDOW_BLOCKS as u64).min(parent.height) as usize;
        let mut want_ts = Vec::new();
        let mut want_d = Vec::new();
        for k in 0..=(n as u64) {
            let h = c.ancestor(&tip, k).unwrap();
            let hdr = c.header(&h).unwrap();
            want_ts.push(hdr.timestamp);
            if k < n as u64 {
                want_d.push(hdr.difficulty);
            }
        }
        want_ts.reverse();
        want_d.reverse();
        assert_eq!(
            expected_difficulty(&c, &tip, block_time),
            Some(lwma_next_difficulty(&want_ts, &want_d, block_time)),
        );
    }

    /// A correctly-mined, correctly-difficultied header validates; tampering with
    /// difficulty, height, parent, timestamp, or the PoW nonce each rejects.
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
            &[],
        )
        .unwrap();
        assert_eq!(validate_header(&c, &pow, &good, block_time, sched()), Ok(()));

        // Wrong difficulty (mandated is EASY; claim something else).
        let mut wrong_diff = good;
        wrong_diff.difficulty = EASY + 1;
        assert!(matches!(
            validate_header(&c, &pow, &wrong_diff, block_time, sched()),
            Err(ValidationError::WrongDifficulty { .. })
        ));

        // Bad height.
        let mut bad_height = good;
        bad_height.height = 5;
        assert_eq!(
            validate_header(&c, &pow, &bad_height, block_time, sched()),
            Err(ValidationError::BadHeight)
        );

        // Unknown parent.
        let mut orphan = good;
        orphan.prev = [0xEE; 32];
        assert_eq!(
            validate_header(&c, &pow, &orphan, block_time, sched()),
            Err(ValidationError::UnknownParent)
        );

        // PoW not satisfied: keep the mandated difficulty but pick a nonce that
        // misses the easy target (search for a definitely-failing one so the test
        // is deterministic).
        let mut bad_pow = good;
        for nonce in 0..10_000u64 {
            bad_pow.nonce = nonce;
            if !satisfies_target(&pow.pow_hash(crate::forms::GenesisForm::V4, &bad_pow, &[]), bad_pow.difficulty) {
                break;
            }
        }
        assert_eq!(
            validate_header(&c, &pow, &bad_pow, block_time, sched()),
            Err(ValidationError::PowUnsatisfied)
        );

        // Keep the good block, then test the timestamp rule on a child of it.
        let good_hash = c.insert_header(good).unwrap();
        assert_eq!(c.tip_height(), 1);
        let child_diff = expected_difficulty(&c, &good_hash, block_time).unwrap();
        let mut back = BlockHeader::child_of(&good, 0, child_diff, ZERO_HASH); // ts 0 < parent's
        back.nonce = 0; // height/timestamp checks run before PoW, so the nonce is irrelevant here
        assert_eq!(
            validate_header(&c, &pow, &back, block_time, sched()),
            Err(ValidationError::NonMonotonicTimestamp)
        );
    }

    /// The key-block seed is the branch's genesis hash during warmup, and rotates
    /// to the right ancestor once past epoch+lag — with a tiny schedule.
    #[test]
    fn pow_seed_bootstraps_from_genesis_then_rotates() {
        let small = KeyBlockSchedule::new(2, 1); // epoch 2, lag 1
        let c = build_linear_chain(EASY, 2, 8);
        let chain = &c;
        let genesis = chain.genesis_block_hash();

        // A block extending the tip at height H uses seed = hash at seed_height(H).
        let tip = chain.tip_hash();
        let tip_h = chain.tip_height();

        // Warmup: for a child at height 1..=epoch+lag the seed is genesis.
        // height 1 → child of genesis; walk from genesis.
        assert_eq!(
            pow_seed(chain, &genesis, 1, small).unwrap(),
            genesis.to_vec(),
            "warmup seed must be the genesis hash",
        );

        // Past warmup: a child at height = tip_h + 1 seeds from seed_height(tip_h+1).
        let child_height = tip_h + 1;
        let expected_seed_h = small.seed_height(child_height);
        let expected_hash = chain.ancestor(&tip, tip_h - expected_seed_h).unwrap();
        assert_eq!(
            pow_seed(chain, &tip, child_height, small).unwrap(),
            expected_hash.to_vec(),
        );
        // And that seed is NOT genesis anymore once we are well past epoch+lag.
        assert!(child_height > small.epoch + small.lag);
        assert_ne!(pow_seed(chain, &tip, child_height, small).unwrap(), genesis.to_vec());
    }

    /// M10-T0-3 item 0 (wall-clock timestamps): the LWMA difficulty trace is FLAT
    /// under a constant mining clock (the exact T0-1 defect — every solvetime == T
    /// ⇒ difficulty never leaves genesis) and NON-CONSTANT under wall-clock-like
    /// variable solvetimes (what makes T0's item-4 difficulty-trace measurement
    /// meaningful). This is the retarget half of the wall-clock change; the seam
    /// itself is covered in `qlab-p2p`'s `mining_clock_*` test.
    #[test]
    fn lwma_trace_is_flat_under_a_constant_clock_and_moves_under_variable_solvetimes() {
        // Pure LWMA-trace walk: record the mandated difficulty at each height over a
        // chain built with the given inter-block spacings. `expected_difficulty` and
        // `insert_header` read only timestamp/difficulty/linkage, so no PoW is needed.
        fn trace(spacings: &[u64], t: u64) -> Vec<u64> {
            let mut c = ChainState::new(BlockHeader::genesis(1_000_000, 0));
            let mut ts = 0u64;
            let mut out = Vec::new();
            for &s in spacings {
                let tip = c.tip_hash();
                let parent = *c.header(&tip).unwrap();
                let diff = expected_difficulty(&c, &tip, t).unwrap();
                out.push(diff);
                ts += s;
                c.insert_header(BlockHeader::child_of(&parent, ts, diff, ZERO_HASH)).unwrap();
            }
            out
        }

        let t = 75; // the frozen 75 s cadence
        // Constant clock ⇒ every solvetime == T ⇒ the trace never leaves genesis.
        let constant = vec![t; 150];
        let flat: std::collections::BTreeSet<u64> = trace(&constant, t).into_iter().collect();
        assert_eq!(flat.len(), 1, "constant clock ⇒ flat LWMA trace (got {flat:?})");
        assert!(flat.contains(&1_000_000), "flat at the genesis difficulty");

        // Wall-clock-like jittered solvetimes ⇒ the trace is non-constant.
        let jitter = [40u64, 120, 30, 200, 60, 75, 15, 300, 90, 50];
        let variable: Vec<u64> = (0..150).map(|i| jitter[i % jitter.len()]).collect();
        let moved: std::collections::BTreeSet<u64> = trace(&variable, t).into_iter().collect();
        assert!(
            moved.len() > 1,
            "variable solvetimes ⇒ non-constant LWMA trace (got {} distinct)",
            moved.len()
        );
    }

    /// Helper: a linear mined chain of `n` blocks after genesis, each spaced
    /// `spacing` seconds apart, all mined at the LWMA-mandated difficulty seeded
    /// from `start_diff` genesis. (KeccakPow ignores the seed, so `&[]` suffices.)
    fn build_linear_chain(start_diff: u64, spacing: u64, n: u64) -> ChainState {
        let pow = KeccakPow;
        let mut c = ChainState::new(BlockHeader::genesis(start_diff, 0));
        for i in 1..=n {
            let tip = c.tip_hash();
            let parent = *c.header(&tip).unwrap();
            // Use a fixed difficulty per block for a clean, predictable window; the
            // retarget-direction tests read expected_difficulty at the tip.
            let header = BlockHeader::child_of(&parent, i * spacing, start_diff, ZERO_HASH);
            let mined = mine(&pow, header, 5_000_000, &[]).expect("mine linear-chain block");
            c.insert_header(mined).unwrap();
        }
        c
    }
}
