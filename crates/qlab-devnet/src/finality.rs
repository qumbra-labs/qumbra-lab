//! Finalized-root tracking and the anchors-from-finalized-only API
//! (consensus-and-network.md §6).
//!
//! A checkpoint becomes final when ≥ the committee's ⅔ quorum of distinct,
//! valid ML-DSA-65 votes back it (consensus §5). Once final, it is irreversible —
//! that single property is what kills the §2 rental double-spend: a hashrate
//! renter can grief short forks near the tip but can never reorg past finality.
//!
//! **Anchors reference finalized roots only** (§6): users prove membership
//! against roots that can never reorg, so no reorg — griefed, rented, or
//! accidental — can invalidate an in-flight transaction's anchor. This module
//! exposes that rule as [`FinalityTracker::is_root_final`] /
//! [`FinalityTracker::newest_anchor`].
//!
//! Scope: this is the finality *subsystem*. Enforcing it against fork choice
//! ("no reorg past a finalized checkpoint EVER") and degraded-mode / equivocation
//! handling are 棒 3. The ≤24 h / 10-min-bucket anchor-age window (§8) is a policy
//! layer on top of the finalized-only gate and is a later refinement — noted, not
//! yet built.

use std::collections::HashSet;

use crate::committee::{Checkpoint, Committee, Vote};
use crate::header::Hash32;

/// Whether `height` is a checkpoint slot under a given `cadence` — a non-genesis
/// height on the cadence grid (protocol-spec §7 / consensus §4). The frozen
/// prototype cadence is 8 blocks = **one 10-min anchor bucket** at 75 s
/// ([`crate::params_devnet::CHECKPOINT_CADENCE_BLOCKS`]); **testnet-tunable, NOT
/// frozen** (§7 flags the cadence `[full-M8]`).
pub fn is_checkpoint_height(height: u64, cadence: u64) -> bool {
    cadence != 0 && height != 0 && height % cadence == 0
}

/// The next checkpoint slot the committee should target: the **first cadence
/// multiple strictly after `finalized`** (or the first slot `cadence` if nothing
/// is finalized), provided it is `<= tip`; else `None`. Successive slots
/// (…, 8, 16, 24, …) realize "propose a checkpoint every `cadence` blocks" — the
/// scheduling that sets the minutes-class finality latency. A stalled committee
/// simply stops calling this (Ebb-and-Flow degradation).
pub fn next_checkpoint_height(finalized: Option<u64>, tip: u64, cadence: u64) -> Option<u64> {
    if cadence == 0 {
        return None;
    }
    // First slot strictly after the finalized head (or slot 1·cadence at genesis).
    let next_slot = match finalized {
        Some(f) => (f / cadence + 1) * cadence,
        None => cadence,
    };
    if next_slot <= tip {
        Some(next_slot)
    } else {
        None
    }
}

/// Why a finalization attempt was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeError {
    /// A vote names a signer index outside the committee.
    UnknownSigner { signer: usize },
    /// A vote's signature does not verify against the checkpoint.
    InvalidVote { signer: usize },
    /// The same signer appears twice in the vote set (must be distinct).
    DuplicateSigner { signer: usize },
    /// Fewer than the ⅔ quorum of distinct valid votes.
    InsufficientQuorum { have: usize, need: usize },
    /// The checkpoint does not strictly advance finality (height ≤ current).
    NotAdvancing { finalized_height: u64, proposed_height: u64 },
}

/// Tracks the chain of finalized checkpoints and answers anchor-validity queries.
#[derive(Clone, Debug, Default)]
pub struct FinalityTracker {
    /// Finalized checkpoints in ascending height order. (Real nodes bound this to
    /// ~144 roots per the §8 ≤24 h / 10-min-bucket window; the devnet keeps all.)
    finalized: Vec<Checkpoint>,
}

impl FinalityTracker {
    /// A fresh tracker with nothing finalized yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rehydrate a tracker from one checkpoint already established before this
    /// process started.
    ///
    /// Recovery is deliberately not routed through [`Self::try_finalize`]: no new
    /// quorum event occurs at startup, and the durable node state has already
    /// proved this exact checkpoint against its reconstructed main chain. Keeping
    /// the constructor named prevents a restore from masquerading as a live vote.
    pub fn from_restored_checkpoint(checkpoint: Checkpoint) -> Self {
        Self { finalized: vec![checkpoint] }
    }

    /// Attempt to finalize `cp` given `votes` and the `committee`.
    ///
    /// Requires: `cp` strictly advances finality (height > current finalized);
    /// every vote is by a distinct in-range signer with a valid signature; and
    /// the count of such votes meets the committee's ⅔ quorum. On success `cp`
    /// becomes the new finalized head.
    pub fn try_finalize(
        &mut self,
        cp: &Checkpoint,
        votes: &[Vote],
        committee: &Committee,
    ) -> Result<(), FinalizeError> {
        if let Some(latest) = self.finalized.last() {
            if cp.height <= latest.height {
                return Err(FinalizeError::NotAdvancing {
                    finalized_height: latest.height,
                    proposed_height: cp.height,
                });
            }
        }

        let mut seen: HashSet<usize> = HashSet::with_capacity(votes.len());
        for vote in votes {
            if committee.member(vote.signer).is_none() {
                return Err(FinalizeError::UnknownSigner { signer: vote.signer });
            }
            if !seen.insert(vote.signer) {
                return Err(FinalizeError::DuplicateSigner { signer: vote.signer });
            }
            if !committee.verify_vote(cp, vote) {
                return Err(FinalizeError::InvalidVote { signer: vote.signer });
            }
        }

        let need = committee.quorum_threshold();
        let have = seen.len();
        if have < need {
            return Err(FinalizeError::InsufficientQuorum { have, need });
        }

        self.finalized.push(*cp);
        Ok(())
    }

    /// The most recently finalized checkpoint, if any.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.finalized.last()
    }

    /// The height of the finalized head (finality lag = minimum anchor age, §6).
    pub fn finalized_height(&self) -> Option<u64> {
        self.finalized.last().map(|c| c.height)
    }

    /// The newest finalized commitment root — the newest usable anchor (§6).
    pub fn finalized_root(&self) -> Option<Hash32> {
        self.finalized.last().map(|c| c.root)
    }

    /// Alias for [`Self::finalized_root`], read as the anchors API: the newest
    /// root a new transaction may anchor to.
    pub fn newest_anchor(&self) -> Option<Hash32> {
        self.finalized_root()
    }

    /// **The anchors-from-finalized-only rule (§6):** is `root` a finalized root?
    /// Only `true` roots are valid anchors. (Finalized-only, no age gate — the
    /// ≤24 h window is [`Self::is_anchor_acceptable`].)
    pub fn is_root_final(&self, root: &Hash32) -> bool {
        self.finalized.iter().any(|c| &c.root == root)
    }

    /// Age (in blocks) of a finalized `root` = `finalized_head − root_height`,
    /// or `None` if `root` was never finalized. If the same root was finalized at
    /// more than one height (unusual), the freshest (smallest age) wins.
    pub fn anchor_age(&self, root: &Hash32) -> Option<u64> {
        let head = self.finalized.last()?.height;
        self.finalized
            .iter()
            .filter(|c| &c.root == root)
            .map(|c| head.saturating_sub(c.height))
            .min()
    }

    /// **The full §6 + §8 anchor gate:** is `root` an acceptable anchor right
    /// now — finalized AND within the ≤24 h window (`age ≤ max_age_blocks`)?
    /// A never-finalized root is rejected (not final); a finalized-but-too-old
    /// root is rejected as **expired**. Pass
    /// [`crate::params_devnet::MAX_ANCHOR_AGE_BLOCKS`] for the real ceiling (or a
    /// smaller window in the accelerated sim).
    pub fn is_anchor_acceptable(&self, root: &Hash32, max_age_blocks: u64) -> bool {
        self.anchor_age(root)
            .is_some_and(|age| age <= max_age_blocks)
    }

    /// Whether everything up to `height` is finalized (height ≤ finalized head).
    pub fn is_height_final(&self, height: u64) -> bool {
        self.finalized_height().is_some_and(|fh| height <= fh)
    }

    /// Number of finalized checkpoints on record.
    pub fn count(&self) -> usize {
        self.finalized.len()
    }

    /// The last `n` finalized checkpoints, ascending — the whole record when it
    /// holds fewer than `n`.
    ///
    /// Additive read accessor for the explorer's checkpoint ticker (lab #486 R2,
    /// coordinator-ruled seam): lab-internal Rust API, no wire, no consensus read.
    /// Before this the record was **unenumerable** from outside — the public
    /// surface answered `latest()`/`count()` and membership queries only — so the
    /// alternative was a second copy of this Vec sampled from a run loop, which
    /// could only ever see checkpoints that were the head at a loop tick.
    ///
    /// The caller's serving bound is the caller's; this returns a borrow and
    /// copies nothing. (The devnet Vec itself is unbounded — the ~144-root bound
    /// noted on the field is not implemented, pre-existing, #135-adjacent.)
    pub fn finalized_tail(&self, n: usize) -> &[Checkpoint] {
        &self.finalized[self.finalized.len().saturating_sub(n)..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::devnet_committee;
    use crate::header::ZERO_HASH;
    use crate::node::{Node, SimConfig};
    use crate::pow::KeccakPow;

    fn easy_cfg() -> SimConfig {
        SimConfig { block_time_secs: 2, genesis_difficulty: 8, mine_nonce_budget: 5_000_000, ..SimConfig::default() }
    }

    /// End-to-end: mine a PoW chain, then a ⅔ quorum of the committee finalizes a
    /// checkpoint on it; the anchors API then reports that root as final.
    #[test]
    fn quorum_finalizes_and_anchor_becomes_valid() {
        // Mine a short chain (heights 0..=5) with the single-node PoW engine.
        let mut node = Node::new(KeccakPow, easy_cfg());
        for _ in 0..5 {
            node.mine_next(ZERO_HASH).unwrap();
        }
        let chain = node.chain().main_chain();
        let cp_height = 4u64;
        let block_hash = chain[cp_height as usize];
        // 棒 2 root stand-in = the finalized block hash (棒 5 supplies the real root).
        let cp = Checkpoint::new(cp_height, block_hash, block_hash);

        let (committee, validators) = devnet_committee(7); // quorum = 5
        assert_eq!(committee.quorum_threshold(), 5);

        // Exactly quorum-many distinct validators sign.
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();

        let mut fin = FinalityTracker::new();
        assert_eq!(fin.newest_anchor(), None);
        fin.try_finalize(&cp, &votes, &committee).unwrap();

        assert_eq!(fin.finalized_height(), Some(4));
        assert_eq!(fin.newest_anchor(), Some(block_hash));
        // Anchors-from-finalized-only: the finalized root is a valid anchor; a
        // never-finalized root is not.
        assert!(fin.is_root_final(&block_hash));
        assert!(!fin.is_root_final(&[0xAB; 32]));
        assert!(fin.is_height_final(4) && fin.is_height_final(3));
        assert!(!fin.is_height_final(5));
    }

    #[test]
    fn restored_checkpoint_rehydrates_without_claiming_a_new_quorum_event() {
        let checkpoint = Checkpoint::new(8, [0x08; 32], [0x08; 32]);
        let tracker = FinalityTracker::from_restored_checkpoint(checkpoint);

        assert_eq!(tracker.latest(), Some(&checkpoint));
        assert_eq!(tracker.finalized_height(), Some(8));
        assert_eq!(tracker.count(), 1);
    }

    /// The lab #486 R2 accessor: the tail is ascending, bounded by what is asked
    /// for, whole when the record is shorter, and empty on a fresh tracker.
    #[test]
    fn finalized_tail_returns_the_last_n_ascending() {
        let (committee, validators) = devnet_committee(7); // quorum = 5
        let mut fin = FinalityTracker::new();
        assert!(fin.finalized_tail(4).is_empty(), "nothing finalized yet");

        for h in [8u64, 16, 24, 32] {
            let cp = Checkpoint::new(h, [h as u8; 32], [h as u8; 32]);
            let votes: Vec<Vote> =
                validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            fin.try_finalize(&cp, &votes, &committee).unwrap();
        }

        let tail = fin.finalized_tail(2);
        assert_eq!(tail.iter().map(|c| c.height).collect::<Vec<_>>(), vec![24, 32]);
        assert_eq!(
            fin.finalized_tail(100).iter().map(|c| c.height).collect::<Vec<_>>(),
            vec![8, 16, 24, 32],
            "asking for more than the record holds returns the whole record"
        );
        assert!(fin.finalized_tail(0).is_empty());
    }

    #[test]
    fn below_quorum_is_rejected() {
        let (committee, validators) = devnet_committee(7); // quorum = 5
        let cp = Checkpoint::new(1, [1u8; 32], [1u8; 32]);
        let votes: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let mut fin = FinalityTracker::new();
        assert_eq!(
            fin.try_finalize(&cp, &votes, &committee),
            Err(FinalizeError::InsufficientQuorum { have: 4, need: 5 })
        );
        assert_eq!(fin.count(), 0);
    }

    #[test]
    fn forged_vote_is_rejected() {
        let (committee, validators) = devnet_committee(7);
        let cp = Checkpoint::new(1, [1u8; 32], [1u8; 32]);
        // Five signers, but one vote's signature is for a DIFFERENT checkpoint
        // (a forged/replayed vote) — must be caught as InvalidVote.
        let other = Checkpoint::new(2, [9u8; 32], [9u8; 32]);
        let mut votes: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        votes.push(validators[4].sign_checkpoint(&other)); // signer 4, wrong message
        let mut fin = FinalityTracker::new();
        assert_eq!(
            fin.try_finalize(&cp, &votes, &committee),
            Err(FinalizeError::InvalidVote { signer: 4 })
        );
    }

    #[test]
    fn duplicate_and_unknown_signers_are_rejected() {
        let (committee, validators) = devnet_committee(7);
        let cp = Checkpoint::new(1, [1u8; 32], [1u8; 32]);

        // Duplicate signer.
        let mut dup: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        dup.push(validators[2].sign_checkpoint(&cp)); // signer 2 again
        let mut fin = FinalityTracker::new();
        assert_eq!(
            fin.try_finalize(&cp, &dup, &committee),
            Err(FinalizeError::DuplicateSigner { signer: 2 })
        );

        // Unknown signer index (a validator not in this 7-member committee).
        let outsider = crate::committee::Validator::from_seed(99, [0xEE; 32]);
        let bad = vec![outsider.sign_checkpoint(&cp)]; // signer index 99
        assert_eq!(
            fin.try_finalize(&cp, &bad, &committee),
            Err(FinalizeError::UnknownSigner { signer: 99 })
        );
    }

    /// Issue #39 / §8: the anchor-age window. A finalized root within the window
    /// is acceptable; a never-finalized root is rejected (not final); a finalized
    /// root older than the window is rejected as EXPIRED.
    #[test]
    fn anchor_age_window_accepts_fresh_rejects_expired_and_nonfinal() {
        let (committee, validators) = devnet_committee(4); // quorum = 3
        let mut fin = FinalityTracker::new();

        // Finalize three commitment roots at heights 2, 5, 9 (root stands in for
        // the commitment-tree root, as the demo wires it).
        for (h, r) in [(2u64, [0x22u8; 32]), (5, [0x55; 32]), (9, [0x99; 32])] {
            let cp = Checkpoint::new(h, [h as u8; 32], r);
            let votes: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            fin.try_finalize(&cp, &votes, &committee).unwrap();
        }
        // Finalized head is height 9.
        assert_eq!(fin.finalized_height(), Some(9));
        assert_eq!(fin.anchor_age(&[0x99; 32]), Some(0)); // the head itself
        assert_eq!(fin.anchor_age(&[0x55; 32]), Some(4)); // 9 - 5
        assert_eq!(fin.anchor_age(&[0x22; 32]), Some(7)); // 9 - 2
        assert_eq!(fin.anchor_age(&[0xAB; 32]), None); // never finalized

        // Window = 5 blocks: heights 5 and 9 are fresh; height 2 (age 7) expired.
        assert!(fin.is_anchor_acceptable(&[0x99; 32], 5), "head root is fresh");
        assert!(fin.is_anchor_acceptable(&[0x55; 32], 5), "age 4 ≤ 5 is fresh");
        assert!(!fin.is_anchor_acceptable(&[0x22; 32], 5), "age 7 > 5 is EXPIRED");
        // Non-finalized root: rejected regardless of window.
        assert!(!fin.is_anchor_acceptable(&[0xAB; 32], u64::MAX), "never-finalized rejected");
        // A generous window keeps even the oldest finalized root.
        assert!(fin.is_anchor_acceptable(&[0x22; 32], 100), "age 7 ≤ 100 accepted");
    }

    #[test]
    fn checkpoint_cadence_grid_and_next_slot() {
        use crate::params_devnet::CHECKPOINT_CADENCE_BLOCKS as C; // 8

        assert!(!is_checkpoint_height(0, C), "genesis is never a slot");
        assert!(is_checkpoint_height(8, C) && is_checkpoint_height(16, C));
        assert!(!is_checkpoint_height(7, C) && !is_checkpoint_height(9, C));

        // Nothing finalized yet, tip at 10 → target slot 8.
        assert_eq!(next_checkpoint_height(None, 10, C), Some(8));
        // Tip below the first slot → nothing to do.
        assert_eq!(next_checkpoint_height(None, 7, C), None);
        // Already finalized 8, tip 15 → no fresh slot (next is 16).
        assert_eq!(next_checkpoint_height(Some(8), 15, C), None);
        // Tip reaches 16 → target 16.
        assert_eq!(next_checkpoint_height(Some(8), 16, C), Some(16));
        // Exactly on a slot with nothing finalized.
        assert_eq!(next_checkpoint_height(None, 8, C), Some(8));
        // Far behind: successive slots, not a jump to the latest (8 comes first).
        assert_eq!(next_checkpoint_height(None, 20, C), Some(8));
        assert_eq!(next_checkpoint_height(Some(8), 20, C), Some(16));
        assert_eq!(next_checkpoint_height(Some(16), 20, C), None);
    }

    #[test]
    fn finalization_must_strictly_advance() {
        let (committee, validators) = devnet_committee(4); // quorum = 3
        let mut fin = FinalityTracker::new();

        let cp5 = Checkpoint::new(5, [5u8; 32], [5u8; 32]);
        let votes5: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp5)).collect();
        fin.try_finalize(&cp5, &votes5, &committee).unwrap();

        // A checkpoint at the same or lower height can't re-finalize.
        let cp3 = Checkpoint::new(3, [3u8; 32], [3u8; 32]);
        let votes3: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp3)).collect();
        assert_eq!(
            fin.try_finalize(&cp3, &votes3, &committee),
            Err(FinalizeError::NotAdvancing { finalized_height: 5, proposed_height: 3 })
        );

        // A strictly-higher checkpoint advances.
        let cp8 = Checkpoint::new(8, [8u8; 32], [8u8; 32]);
        let votes8: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp8)).collect();
        fin.try_finalize(&cp8, &votes8, &committee).unwrap();
        assert_eq!(fin.finalized_height(), Some(8));
        assert_eq!(fin.count(), 2);
        // Both finalized roots remain valid anchors.
        assert!(fin.is_root_final(&[5u8; 32]) && fin.is_root_final(&[8u8; 32]));
    }
}
