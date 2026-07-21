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
use crate::mining::mine;
use crate::params_devnet::{GENESIS_DIFFICULTY, SIM_BLOCK_TIME_SECS};
use crate::pow::PowEngine;
use crate::validation::{expected_difficulty, validate_header, ValidationError};

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
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            block_time_secs: SIM_BLOCK_TIME_SECS,
            genesis_difficulty: GENESIS_DIFFICULTY,
            mine_nonce_budget: 1 << 26,
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
        }
    }

    /// Mine and accept the next block on the current tip, carrying `tx_body_commitment`.
    /// Advances the sim clock, computes the mandated difficulty, mines a valid
    /// nonce, and inserts. Returns the new tip hash.
    pub fn mine_next(&mut self, tx_body_commitment: Hash32) -> Result<Hash32, NodeError> {
        self.mine_on(self.chain.tip_hash(), tx_body_commitment)
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
        let mined = mine(&self.pow, candidate, self.config.mine_nonce_budget)
            .ok_or(NodeError::MiningExhausted)?;
        // Self-check: a block we produced must pass our own validation.
        validate_header(&self.chain, &self.pow, &mined, self.config.block_time_secs)?;
        Ok(self.chain.insert_header(mined)?)
    }

    /// Validate and accept a header produced elsewhere. Heaviest-chain fork choice
    /// applies on insert — a heavier branch reorgs the tip. Returns the block hash.
    pub fn submit(&mut self, header: BlockHeader) -> Result<Hash32, NodeError> {
        validate_header(&self.chain, &self.pow, &header, self.config.block_time_secs)?;
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

    /// Heaviest-chain fork choice: a competing branch with more cumulative work
    /// reorgs the tip, even though the first branch was seen first.
    #[test]
    fn heavier_fork_reorgs_the_tip() {
        let mut node = Node::new(KeccakPow, cfg());
        let genesis = node.tip_hash();

        // Branch A: two blocks on genesis (tip advances to A2).
        node.mine_on(genesis, [0xA1; 32]).unwrap();
        let a2 = node.mine_next([0xA2; 32]).unwrap();
        assert_eq!(node.tip_hash(), a2);
        assert_eq!(node.tip_height(), 2);

        // Branch B from genesis: three blocks ⇒ more total work ⇒ reorg.
        let b1 = node.mine_on(genesis, [0xB1; 32]).unwrap();
        // Tip is still A2 (B1 alone is lighter than A1+A2).
        assert_eq!(node.tip_hash(), a2);
        let b2 = node.mine_on(b1, [0xB2; 32]).unwrap();
        let b3 = node.mine_on(b2, [0xB3; 32]).unwrap();

        assert_eq!(node.tip_hash(), b3, "the longer/heavier B branch wins");
        assert_eq!(node.tip_height(), 3);
        // A2 is still a known side block, just off the main chain.
        assert!(node.chain().header(&a2).is_some());
        assert_eq!(node.chain().main_chain().last(), Some(&b3));
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
                && !satisfies_target(&KeccakPow.pow_hash(&tampered), tampered.difficulty)
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
}
