//! A single devnet node: chain state + a PoW engine + a sim clock, with
//! `mine_next` (produce a block on the tip) and `submit` (validate + accept a
//! block from elsewhere — the hook 棒 4's gossip will drive). Fork choice is the
//! heaviest-chain rule inherited from [`ChainState`]; `submit`ting a heavier
//! competing branch reorgs the tip automatically.
//!
//! The **block time is configurable** ([`SimConfig::block_time_secs`]) — the
//! "accelerated block time for the sim" the M6 mandate asks for. The real decided
//! block time is 60–75 s (consensus §7); the devnet runs a compressed clock and
//! never pretends the accelerated value is a design number.

use crate::chain::{ChainState, InsertError};
use crate::header::{BlockHeader, Hash32};
use crate::chain::FinalizeMarkError;
use crate::committee::{Checkpoint, CommitteeState, Vote};
use crate::ebbflow::{finality_status, FinalityStatus};
use crate::finality::{FinalityTracker, FinalizeError};
use crate::mining::mine;
use crate::params_devnet::{
    DEGRADED_MODE_LAG_BLOCKS, GENESIS_DIFFICULTY, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG,
    SIM_BLOCK_TIME_SECS,
};
use crate::pow::PowEngine;
use crate::validation::{expected_difficulty, pow_seed, validate_header, ValidationError};
use qlab_pow::keyblock::KeyBlockSchedule;

/// Sim knobs for a node. All placeholders / sim conveniences — none is a design
/// decision (see `params_devnet`).
#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    /// Accelerated per-block time, in sim seconds. Drives the sim clock and the
    /// difficulty-retarget target timespan. Real target is 60–75 s (consensus §7).
    pub block_time_secs: u64,
    /// Genesis difficulty for a freshly-started node.
    pub genesis_difficulty: u64,
    /// Max nonces the mining loop tries per block before giving up.
    pub mine_nonce_budget: u64,
    /// RandomX key-block epoch length, in blocks (sim knob; default = the
    /// `params_devnet` value). A small value exercises key rotation in tests.
    pub key_epoch_blocks: u64,
    /// RandomX key-block lag, in blocks (sim knob; default = `params_devnet`).
    pub key_epoch_lag: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            block_time_secs: SIM_BLOCK_TIME_SECS,
            genesis_difficulty: GENESIS_DIFFICULTY,
            mine_nonce_budget: 1 << 26,
            key_epoch_blocks: SEEDHASH_EPOCH_BLOCKS,
            key_epoch_lag: SEEDHASH_EPOCH_LAG,
        }
    }
}

/// Why producing or accepting a block failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeError {
    /// The mining loop exhausted its nonce budget without a hit.
    MiningExhausted,
    /// The (mined or submitted) header failed validation.
    Invalid(ValidationError),
    /// The chain rejected the insert (duplicate / unknown parent / bad height).
    Insert(InsertError),
    /// The checkpoint's block is not on this node's main chain (not an ancestor
    /// of the tip) — a node only finalizes blocks on its own best chain.
    NotOnMainChain,
    /// The finality quorum/vote check rejected the checkpoint.
    Finalize(FinalizeError),
    /// Marking the block finalized in the chain was rejected.
    FinalizeMark(FinalizeMarkError),
}

impl From<ValidationError> for NodeError {
    fn from(e: ValidationError) -> Self {
        NodeError::Invalid(e)
    }
}
impl From<InsertError> for NodeError {
    fn from(e: InsertError) -> Self {
        NodeError::Insert(e)
    }
}

/// A single node.
pub struct Node<P: PowEngine> {
    chain: ChainState,
    pow: P,
    config: SimConfig,
    /// The node's sim clock — advanced by `block_time_secs` each mined block.
    clock: u64,
    /// The node's finalized-checkpoint view (drives the anchors API; the chain's
    /// own finalized pointer drives fork choice, kept in sync by `finalize`).
    finality: FinalityTracker,
}

impl<P: PowEngine> Node<P> {
    /// Start a node from a fresh genesis (`prev = 0`, `height = 0`, `timestamp 0`).
    pub fn new(pow: P, config: SimConfig) -> Self {
        let genesis = BlockHeader::genesis(config.genesis_difficulty, 0);
        Self {
            chain: ChainState::new(genesis),
            pow,
            config,
            clock: 0,
            finality: FinalityTracker::new(),
        }
    }

    /// Mine and accept the next block on the current tip, carrying `tx_body_commitment`.
    /// Advances the sim clock, computes the mandated difficulty, mines a valid
    /// nonce, and inserts. Returns the new tip hash.
    pub fn mine_next(&mut self, tx_body_commitment: Hash32) -> Result<Hash32, NodeError> {
        self.mine_on(self.chain.tip_hash(), tx_body_commitment)
    }

    /// The RandomX key-block schedule this node runs (from its sim config).
    fn schedule(&self) -> KeyBlockSchedule {
        KeyBlockSchedule::new(self.config.key_epoch_blocks, self.config.key_epoch_lag)
    }

    /// Mine and accept a child of an arbitrary known `parent_hash` (lets a caller
    /// grow a competing fork; also what a miner does when extending a branch it
    /// just received). Returns the new block's hash.
    pub fn mine_on(&mut self, parent_hash: Hash32, tx_body_commitment: Hash32) -> Result<Hash32, NodeError> {
        let parent = *self
            .chain
            .header(&parent_hash)
            .ok_or(NodeError::Insert(InsertError::UnknownParent))?;
        let difficulty = expected_difficulty(&self.chain, &parent_hash, self.config.block_time_secs)
            .ok_or(NodeError::Insert(InsertError::UnknownParent))?;
        // Advance the sim clock; keep it at least one tick past the parent so
        // timestamps are non-decreasing even when mining on an old branch.
        self.clock = (self.clock + self.config.block_time_secs).max(parent.timestamp + self.config.block_time_secs);
        let candidate = BlockHeader::child_of(&parent, self.clock, difficulty, tx_body_commitment);
        // The RandomX key-block seed for this height on this branch.
        let seed = pow_seed(&self.chain, &parent_hash, candidate.height, self.schedule())
            .ok_or(NodeError::Insert(InsertError::UnknownParent))?;
        let mined = mine(&self.pow, candidate, self.config.mine_nonce_budget, &seed)
            .ok_or(NodeError::MiningExhausted)?;
        // Self-check: a block we produced must pass our own validation.
        validate_header(&self.chain, &self.pow, &mined, self.config.block_time_secs, self.schedule())?;
        Ok(self.chain.insert_header(mined)?)
    }

    /// Validate and accept a header produced elsewhere. Heaviest-chain fork choice
    /// applies on insert — a heavier branch reorgs the tip. Returns the block hash.
    pub fn submit(&mut self, header: BlockHeader) -> Result<Hash32, NodeError> {
        validate_header(&self.chain, &self.pow, &header, self.config.block_time_secs, self.schedule())?;
        Ok(self.chain.insert_header(header)?)
    }

    /// The current tip hash.
    pub fn tip_hash(&self) -> Hash32 {
        self.chain.tip_hash()
    }
    /// The current tip height.
    pub fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }
    /// Total accumulated work at the tip.
    pub fn tip_work(&self) -> u128 {
        self.chain.tip_work()
    }
    /// Read-only access to the chain state.
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }

    // ── Finality (棒 2/3) ──────────────────────────────────────────────────

    /// Build a checkpoint for the main-chain block at `height`, if it exists.
    /// Devnet root stand-in = the block hash (棒 5 binds the real M3 anchor).
    pub fn checkpoint_at(&self, height: u64) -> Option<Checkpoint> {
        let chain = self.chain.main_chain();
        chain
            .get(height as usize)
            .map(|&block_hash| Checkpoint::new(height, block_hash, block_hash))
    }

    /// Finalize `cp` given `votes` and the committee `cstate`. The checkpoint's
    /// block must be on this node's main chain; votes from tombstoned/jailed
    /// members are dropped before the ⅔-quorum check; on success the chain's
    /// finalized pointer advances (enforcing "no reorg past finality").
    pub fn finalize(
        &mut self,
        cp: &Checkpoint,
        votes: &[Vote],
        cstate: &CommitteeState,
    ) -> Result<(), NodeError> {
        // The checkpoint block must be an ancestor of (or equal to) the tip.
        if !self.chain.is_descendant_of(&self.chain.tip_hash(), &cp.block_hash, cp.height) {
            return Err(NodeError::NotOnMainChain);
        }
        // Only currently-active members count toward quorum.
        let active: Vec<Vote> = votes
            .iter()
            .filter(|v| cstate.is_active(v.signer, cp.height))
            .cloned()
            .collect();
        self.finality
            .try_finalize(cp, &active, cstate.committee())
            .map_err(NodeError::Finalize)?;
        self.chain.set_finalized(cp.block_hash).map_err(NodeError::FinalizeMark)?;
        Ok(())
    }

    /// The finalized height, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.finality.finalized_height()
    }

    /// The newest finalized root — the newest usable anchor (§6).
    pub fn newest_anchor(&self) -> Option<Hash32> {
        self.finality.newest_anchor()
    }

    /// The anchors-from-finalized-only rule (§6): is `root` a finalized root?
    pub fn is_anchor_final(&self, root: &Hash32) -> bool {
        self.finality.is_root_final(root)
    }

    /// The node's finality regime (Final vs degraded probabilistic mode), from the
    /// tip-vs-finalized lag against the placeholder [`DEGRADED_MODE_LAG_BLOCKS`].
    pub fn finality_status(&self) -> FinalityStatus {
        finality_status(self.tip_height(), self.finalized_height(), DEGRADED_MODE_LAG_BLOCKS)
    }

    /// Read-only access to the finalized-checkpoint tracker.
    pub fn finality(&self) -> &FinalityTracker {
        &self.finality
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ZERO_HASH;
    use crate::pow::KeccakPow;

    fn cfg() -> SimConfig {
        // Low difficulty so mining is instant; small block time.
        SimConfig {
            block_time_secs: 2,
            genesis_difficulty: 8,
            mine_nonce_budget: 5_000_000,
            ..SimConfig::default()
        }
    }

    #[test]
    fn mines_a_linear_chain_and_advances_height() {
        let mut node = Node::new(KeccakPow, cfg());
        assert_eq!(node.tip_height(), 0);
        for h in 1..=5 {
            node.mine_next(ZERO_HASH).unwrap();
            assert_eq!(node.tip_height(), h);
        }
        // Work accumulated = sum of block difficulties along the main chain.
        assert!(node.tip_work() >= 8 * 6);
        assert_eq!(node.chain().main_chain().len(), 6);
    }

    #[test]
    fn mined_blocks_are_self_valid_and_distinct() {
        let mut node = Node::new(KeccakPow, cfg());
        let a = node.mine_next([1u8; 32]).unwrap();
        let b = node.mine_next([2u8; 32]).unwrap();
        assert_ne!(a, b);
        assert_eq!(node.tip_hash(), b);
    }

    /// Heaviest-chain fork choice: a competing branch that accumulates MORE work
    /// reorgs the tip, even though the first branch was seen first. (Under LWMA the
    /// per-block difficulty varies with cadence, so "longer" no longer implies
    /// "heavier" — we extend B until its cumulative work actually overtakes A, then
    /// assert the reorg lands on the B branch.)
    #[test]
    fn heavier_fork_reorgs_the_tip() {
        let mut node = Node::new(KeccakPow, cfg());
        let genesis = node.tip_hash();

        // Branch A: two blocks on genesis (tip advances to A2).
        node.mine_on(genesis, [0xA1; 32]).unwrap();
        let a2 = node.mine_next([0xA2; 32]).unwrap();
        assert_eq!(node.tip_hash(), a2);
        assert_eq!(node.tip_height(), 2);
        let a_work = node.tip_work();

        // Branch B from genesis: extend until its cumulative work overtakes A. The
        // tip flips to B exactly when B's work first exceeds A's.
        let mut b_parent = genesis;
        let mut last_b = genesis;
        let mut reorged = false;
        for i in 0..20u8 {
            b_parent = node.mine_on(b_parent, [0xB0 + i; 32]).unwrap();
            last_b = b_parent;
            if node.tip_hash() == last_b {
                reorged = true;
                break;
            }
            // Until it overtakes A, the tip must remain A2 (finality-free tie/less).
            assert_eq!(node.tip_hash(), a2, "must not reorg to a lighter B prefix");
        }
        assert!(reorged, "B must eventually accumulate more work than A and reorg");
        assert_eq!(node.tip_hash(), last_b, "the heavier B branch wins");
        assert!(node.tip_work() > a_work, "the new tip carries strictly more work");
        // A2 is still a known side block, just off the main chain.
        assert!(node.chain().header(&a2).is_some());
        assert_eq!(node.chain().main_chain().last(), Some(&last_b));
    }

    /// A node accepts a valid block mined by a peer via `submit`, and rejects a
    /// tampered one.
    #[test]
    fn submit_accepts_valid_and_rejects_tampered() {
        // Producer node mines a block.
        let mut producer = Node::new(KeccakPow, cfg());
        let good_hash = producer.mine_next([9u8; 32]).unwrap();
        let good = *producer.chain().header(&good_hash).unwrap();

        // A fresh consumer node (same genesis/config) accepts it.
        let mut consumer = Node::new(KeccakPow, cfg());
        assert_eq!(consumer.submit(good), Ok(good.header_hash()));
        assert_eq!(consumer.tip_height(), 1);

        // Tampering the body commitment leaves height/difficulty/timestamp intact
        // but breaks the PoW (the hash for `good`'s nonce no longer meets target).
        // At the easy test difficulty a random body has a non-trivial chance of
        // *still* meeting target, so search for one that provably fails — the
        // rejection under test is deterministic, not probabilistic.
        use crate::pow::satisfies_target;
        use crate::validation::ValidationError;
        let mut consumer2 = Node::new(KeccakPow, cfg());
        let mut tampered = good;
        for i in 0u8..=255 {
            tampered.tx_body_commitment = [i; 32];
            if tampered.tx_body_commitment != good.tx_body_commitment
                && !satisfies_target(&KeccakPow.pow_hash(&tampered, &[]), tampered.difficulty)
            {
                break;
            }
        }
        assert_eq!(
            consumer2.submit(tampered),
            Err(NodeError::Invalid(ValidationError::PowUnsatisfied))
        );
        assert_eq!(consumer2.tip_height(), 0);
    }

    // ── 棒 3: finality integration (Ebb-and-Flow at the node) ───────────────

    use crate::committee::{devnet_committee, CommitteeState, Vote};
    use crate::ebbflow::FinalityStatus;
    use crate::params_devnet::{BOND_AMOUNT, DEGRADED_MODE_LAG_BLOCKS};

    /// Committee stall → the chain keeps growing in degraded probabilistic mode;
    /// finality resumes cleanly when the committee finalizes again (consensus §4).
    #[test]
    fn stall_degrades_then_recovers_while_chain_keeps_growing() {
        let mut node = Node::new(KeccakPow, cfg());
        let (committee, validators) = devnet_committee(7); // quorum 5
        let cstate = CommitteeState::new(committee, BOND_AMOUNT);

        for _ in 0..10 {
            node.mine_next(ZERO_HASH).unwrap();
        }
        assert_eq!(node.tip_height(), 10);
        // Never finalized ⇒ degraded probabilistic mode.
        assert_eq!(node.finalized_height(), None);
        assert_eq!(node.finality_status(), FinalityStatus::Degraded);

        // Finalize height 8 with a ⅔ quorum.
        let cp8 = node.checkpoint_at(8).unwrap();
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp8)).collect();
        node.finalize(&cp8, &votes, &cstate).unwrap();
        assert_eq!(node.finalized_height(), Some(8));
        assert_eq!(node.finality_status(), FinalityStatus::Final);
        assert!(node.is_anchor_final(&cp8.root));
        assert_eq!(node.newest_anchor(), Some(cp8.root));

        // Committee STALLS: keep mining (no finalization) past the degraded lag.
        let before = node.tip_height();
        while node.tip_height() - node.finalized_height().unwrap() <= DEGRADED_MODE_LAG_BLOCKS {
            node.mine_next(ZERO_HASH).unwrap();
        }
        assert!(node.tip_height() > before, "PoW keeps producing blocks during stall");
        assert_eq!(node.finality_status(), FinalityStatus::Degraded);

        // RECOVERY: finalize a fresh checkpoint near the tip.
        let h = node.tip_height() - 1;
        let cp = node.checkpoint_at(h).unwrap();
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        node.finalize(&cp, &votes, &cstate).unwrap();
        assert_eq!(node.finalized_height(), Some(h));
        assert_eq!(node.finality_status(), FinalityStatus::Final, "finality resumes cleanly");
    }

    /// At the node level too: once a checkpoint is finalized, a longer/heavier
    /// competing branch cannot reorg the tip past it.
    #[test]
    fn node_does_not_reorg_past_finalized_checkpoint() {
        let mut node = Node::new(KeccakPow, cfg());
        let (committee, validators) = devnet_committee(7);
        let cstate = CommitteeState::new(committee, BOND_AMOUNT);
        let genesis = node.tip_hash();

        // Main branch A: 3 blocks.
        let a1 = node.mine_on(genesis, [0xA1; 32]).unwrap();
        let a2 = node.mine_on(a1, [0xA2; 32]).unwrap();
        let a3 = node.mine_on(a2, [0xA3; 32]).unwrap();
        assert_eq!(node.tip_hash(), a3);

        // Finalize A2 (height 2).
        let cp = Checkpoint::new(2, a2, a2);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        node.finalize(&cp, &votes, &cstate).unwrap();
        assert_eq!(node.finalized_height(), Some(2));

        // Competing branch B from genesis, LONGER (4 blocks) ⇒ more work than A —
        // but it does not contain finalized A2, so the tip must not switch.
        let b1 = node.mine_on(genesis, [0xB1; 32]).unwrap();
        let b2 = node.mine_on(b1, [0xB2; 32]).unwrap();
        let b3 = node.mine_on(b2, [0xB3; 32]).unwrap();
        let b4 = node.mine_on(b3, [0xB4; 32]).unwrap();

        assert_eq!(node.tip_hash(), a3, "no reorg past finalized A2, even to a heavier branch");
        assert!(!node.chain().descends_from_finalized(&b4));
        assert!(node.chain().header(&b4).is_some(), "the B branch is still stored");
    }

    /// A node drops votes from tombstoned members, so equivocators can't help form
    /// a quorum: if too many are tombstoned, finality stalls (degraded) rather than
    /// finalizing on bad votes.
    #[test]
    fn tombstoned_votes_do_not_count_toward_quorum() {
        use crate::ebbflow::{punish_equivocation, EquivocationEvidence};
        use crate::params_devnet::EQUIVOCATION_SLASH_AMOUNT;

        let mut node = Node::new(KeccakPow, cfg());
        let (committee, validators) = devnet_committee(7); // quorum 5
        let mut cstate = CommitteeState::new(committee, BOND_AMOUNT);
        for _ in 0..3 {
            node.mine_next(ZERO_HASH).unwrap();
        }
        let cp = node.checkpoint_at(2).unwrap();

        // Tombstone three members for equivocation, leaving only 4 active < quorum 5.
        for signer in [0usize, 1, 2] {
            let a = Checkpoint::new(99, [0xAA; 32], [0xAA; 32]);
            let b = Checkpoint::new(99, [0xBB; 32], [0xBB; 32]);
            let ev = EquivocationEvidence {
                vote_a: validators[signer].sign_checkpoint(&a),
                cp_a: a,
                vote_b: validators[signer].sign_checkpoint(&b),
                cp_b: b,
            };
            punish_equivocation(&mut cstate, &ev, EQUIVOCATION_SLASH_AMOUNT).unwrap();
        }
        assert_eq!(cstate.active_count(cp.height), 4);

        // All 7 vote, but the 3 tombstoned votes are dropped ⇒ only 4 count < 5.
        let votes: Vec<Vote> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(
            node.finalize(&cp, &votes, &cstate),
            Err(NodeError::Finalize(crate::finality::FinalizeError::InsufficientQuorum { have: 4, need: 5 }))
        );
        assert_eq!(node.finalized_height(), None);
    }
}
