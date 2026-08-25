//! The mining loop: search for a nonce whose PoW hash meets the difficulty target.
//!
//! Deliberately trivial — vary `header.nonce`, re-hash via the [`PowEngine`] under
//! the block's RandomX key `seed`, and stop at the first nonce satisfying
//! [`crate::pow::satisfies_target`]. With the Keccak placeholder (which ignores the
//! seed) and the low sim difficulties in `params_devnet`, a valid nonce is found in
//! a handful of iterations; a real RandomX-class engine slots in behind the same
//! trait with no change here.

use std::time::Instant;

use crate::forms::ChainRules;
use crate::halt::pow_value;
use crate::header::BlockHeader;
use crate::pow::{satisfies_target_for, PowEngine};

/// Budget for one [`grind_slice`] call (lab #651).
///
/// Both bounds exist because each one alone rebuilds a known defect:
/// - `max_hashes` alone is the original mine-phase defect with a smaller
///   constant — a hash count cannot bound wall-clock blocking on a machine
///   whose per-hash cost is unknown (the measured Windows node spent 9.4
///   minutes inside one nonce-bounded call).
/// - `deadline` alone cannot be tested reproducibly — a time-bounded slice
///   hashes a different number of nonces on every run.
///
/// Whichever bound hits first ends the slice. The deadline is checked after
/// every hash, and a slice always makes **at least one nonce of progress**
/// (so a caller pacing on an already-expired deadline can never park a grind
/// that silently stops hashing); the caller's blocking is therefore bounded
/// by the deadline plus one hash.
#[derive(Clone, Copy, Debug)]
pub struct SliceBudget {
    /// Max nonces hashed in this slice (the determinism bound; treated as ≥ 1).
    pub max_hashes: u64,
    /// Wall-clock cut-off (the blackout bound). `None` = count-bounded only —
    /// the [`mine_under`] wrapper's mode, where no `Instant` is ever read and
    /// the result is a pure function of its inputs.
    pub deadline: Option<Instant>,
}

/// One [`grind_slice`] call's verdict. The three cases are deliberately
/// distinct — the caller announces on `Found`, re-assembles a fresh template
/// on `Exhausted`, and parks the cursor on `Yielded`; collapsing any two of
/// them is how the lab #651 defect gets rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrindOutcome {
    /// A satisfying nonce was found — the returned header differs from the
    /// template only in `nonce`, byte-identical to what an unsliced grind
    /// would have produced at the same nonce.
    Found(BlockHeader),
    /// The template's whole nonce space `[0, nonce_end)` is spent with no hit.
    /// The template is dead for good — resuming it cannot succeed.
    Exhausted,
    /// The slice budget ran out first. `next_nonce` is the resume point:
    /// nonces `[.., next_nonce)` are spent, the search continues there.
    Yielded {
        /// First nonce the next slice should try.
        next_nonce: u64,
    },
}

/// One bounded slice of the nonce search (lab #651): try nonces from
/// `from_nonce` toward `nonce_end`, stopping at the first hit, at the end of
/// the nonce space, or when `budget` runs out — whichever comes first.
///
/// The per-nonce work is **identical** to [`mine_under`]'s loop body —
/// [`pow_value`] over the header preimage under `rules.form`, checked by
/// [`satisfies_target_for`] — so a grind resumed across any number of slices
/// visits the same nonces in the same order and produces the same header as
/// one unsliced call. Consensus (miner/validator agreement) is untouched.
pub fn grind_slice<P: PowEngine>(
    pow: &P,
    header: &BlockHeader,
    seed: &[u8],
    rules: &ChainRules,
    from_nonce: u64,
    nonce_end: u64,
    budget: SliceBudget,
) -> GrindOutcome {
    if from_nonce >= nonce_end {
        return GrindOutcome::Exhausted;
    }
    let slice_end = from_nonce.saturating_add(budget.max_hashes.max(1)).min(nonce_end);
    let mut candidate = *header;
    let mut nonce = from_nonce;
    loop {
        candidate.nonce = nonce;
        let value =
            pow_value(pow.pow_hash(rules.form, &candidate, seed), candidate.height, &rules.halt);
        if satisfies_target_for(&value, candidate.difficulty, rules.form) {
            return GrindOutcome::Found(candidate);
        }
        nonce += 1;
        if nonce >= slice_end {
            break;
        }
        if let Some(deadline) = budget.deadline {
            if Instant::now() >= deadline {
                break;
            }
        }
    }
    if nonce >= nonce_end {
        GrindOutcome::Exhausted
    } else {
        GrindOutcome::Yielded { next_nonce: nonce }
    }
}

/// Mine `header` in place-ish: try nonces `0..nonce_budget`, hashing under the
/// key-block `seed`, and return the header with the first satisfying nonce set, or
/// `None` if the budget is exhausted.
///
/// `header.difficulty` fixes the target; the miner never changes it (difficulty is
/// a consensus input, checked by validation). `seed` is the RandomX key for this
/// block (the key-block hash — [`crate::validation::pow_seed`]); it is constant
/// across the nonce search. The returned header differs from the input only in
/// `nonce`.
pub fn mine<P: PowEngine>(
    pow: &P,
    header: BlockHeader,
    nonce_budget: u64,
    seed: &[u8],
) -> Option<BlockHeader> {
    mine_under(pow, header, nonce_budget, seed, &ChainRules::V1_0)
}

/// [`mine`] under an explicit [`ChainRules`] (issue #74; form-keyed since lab
/// #470). Above an upgrade boundary the miner searches for a nonce satisfying
/// the **post-halt** PoW value ([`pow_value`]) — the same value the validator
/// checks, so miner and validator can never disagree about which rules a height
/// is under. At and below the boundary the two functions are byte-identical.
/// The PoW message is the header preimage under `rules.form`, so miner and
/// validator can never disagree about the layout either.
///
/// Since lab #651 this is a wrapper over [`grind_slice`]: one count-only,
/// deadline-free slice covering the whole budget. The observable behaviour —
/// nonces `0..nonce_budget` in order, first hit wins, `None` on exhaustion —
/// is unchanged; the simulator, `qlab-bench`'s n7soak and every existing test
/// depend on its reproducibility. The resumable, time-bounded path is the
/// node loop's, via [`grind_slice`] directly.
pub fn mine_under<P: PowEngine>(
    pow: &P,
    header: BlockHeader,
    nonce_budget: u64,
    seed: &[u8],
    rules: &ChainRules,
) -> Option<BlockHeader> {
    let budget = SliceBudget { max_hashes: u64::MAX, deadline: None };
    match grind_slice(pow, &header, seed, rules, 0, nonce_budget, budget) {
        GrindOutcome::Found(mined) => Some(mined),
        GrindOutcome::Exhausted => None,
        // A deadline-free slice whose hash budget covers the whole nonce space
        // can only end in Found or Exhausted.
        GrindOutcome::Yielded { .. } => {
            unreachable!("count-only full-budget slice cannot yield")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::KeccakPow;

    #[test]
    fn mines_a_valid_block_at_low_difficulty() {
        let pow = KeccakPow;
        let header = BlockHeader::genesis(8, 0);
        let mined = mine(&pow, header, 1_000_000, &[]).expect("must mine at difficulty 8");
        assert!(crate::pow::satisfies_target(
            &pow.pow_hash(crate::forms::GenesisForm::V4, &mined, &[]),
            mined.difficulty
        ));
        // Difficulty and structural fields are untouched — only the nonce moved.
        assert_eq!(mined.difficulty, header.difficulty);
        assert_eq!(mined.height, header.height);
        assert_eq!(mined.prev, header.prev);
    }

    #[test]
    fn exhausted_budget_returns_none() {
        let pow = KeccakPow;
        // Astronomically high difficulty ⇒ a tiny nonce budget cannot find a hit.
        let header = BlockHeader::genesis(u64::MAX, 0);
        assert!(mine(&pow, header, 4, &[]).is_none());
    }

    // ---- lab #651: the resumable primitive ---------------------------------

    /// A grind that cannot finish yields at its hash budget instead of
    /// blocking, and the resume point is a real cursor: the next slice picks
    /// up exactly where the last one stopped.
    #[test]
    fn grind_slice_yields_at_the_hash_budget_and_resumes_at_the_cursor() {
        let pow = KeccakPow;
        let header = BlockHeader::genesis(u64::MAX, 0);
        let budget = SliceBudget { max_hashes: 1_000, deadline: None };
        let out = grind_slice(&pow, &header, &[], &ChainRules::V1_0, 0, 1 << 26, budget);
        assert_eq!(out, GrindOutcome::Yielded { next_nonce: 1_000 });
        let out = grind_slice(&pow, &header, &[], &ChainRules::V1_0, 1_000, 1 << 26, budget);
        assert_eq!(out, GrindOutcome::Yielded { next_nonce: 2_000 });
    }

    /// The deadline bound: a slice whose deadline has already passed still
    /// makes exactly one nonce of progress — never zero (a zero-progress
    /// slice would let a deadline-pacing caller park a grind that silently
    /// stops hashing), and never a full hash budget (the deadline is real).
    #[test]
    fn an_expired_deadline_yields_after_one_nonce() {
        let pow = KeccakPow;
        let header = BlockHeader::genesis(u64::MAX, 0);
        let budget = SliceBudget { max_hashes: 1_000, deadline: Some(Instant::now()) };
        let out = grind_slice(&pow, &header, &[], &ChainRules::V1_0, 7, 1 << 26, budget);
        assert_eq!(out, GrindOutcome::Yielded { next_nonce: 8 });
    }

    /// `Exhausted` is the end of the template's nonce space, distinct from a
    /// yield — including when the caller resumes at (or past) the end.
    #[test]
    fn grind_slice_reports_exhaustion_at_the_end_of_the_nonce_space() {
        let pow = KeccakPow;
        let header = BlockHeader::genesis(u64::MAX, 0);
        let budget = SliceBudget { max_hashes: 1_000, deadline: None };
        // The slice reaches nonce_end before its hash budget: exhausted.
        let out = grind_slice(&pow, &header, &[], &ChainRules::V1_0, 3, 4, budget);
        assert_eq!(out, GrindOutcome::Exhausted);
        // A resume at the end of the space is exhausted without hashing.
        let out = grind_slice(&pow, &header, &[], &ChainRules::V1_0, 4, 4, budget);
        assert_eq!(out, GrindOutcome::Exhausted);
    }

    /// 🔴 Progress accumulates: a grind resumed one nonce at a time walks the
    /// same nonce sequence as one unsliced [`mine_under`] call and finds the
    /// **byte-identical header** — the cursor is load-bearing, not decorative,
    /// and slicing cannot change what the miner produces (consensus is
    /// untouched).
    #[test]
    fn sliced_grind_finds_the_same_header_as_the_unsliced_wrapper() {
        let pow = KeccakPow;
        // Difficulty high enough that the winning nonce is (overwhelmingly
        // likely) well past nonce 0, so the walk really resumes; the
        // assertions below hold for ANY winning nonce, so the test does not
        // depend on the draw.
        let header = BlockHeader::genesis(10_000, 0);
        let unsliced = mine_under(&pow, header, 1 << 26, &[], &ChainRules::V1_0)
            .expect("KeccakPow finds a nonce at difficulty 10k within 2^26");
        let budget = SliceBudget { max_hashes: 1, deadline: None };
        let mut cursor = 0u64;
        let sliced = loop {
            match grind_slice(&pow, &header, &[], &ChainRules::V1_0, cursor, 1 << 26, budget) {
                GrindOutcome::Found(h) => break h,
                GrindOutcome::Yielded { next_nonce } => {
                    assert_eq!(next_nonce, cursor + 1, "one nonce per slice");
                    cursor = next_nonce;
                }
                GrindOutcome::Exhausted => panic!("the unsliced grind found a nonce here"),
            }
        };
        assert_eq!(
            cursor, unsliced.nonce,
            "the sliced walk visited exactly the nonces the unsliced grind spent"
        );
        assert_eq!(sliced, unsliced, "byte-identical header at the same nonce");
    }
}
