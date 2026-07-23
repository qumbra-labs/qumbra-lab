//! N1 boundary — **stubbed** node-state interfaces this P2P layer consumes.
//!
//! Issue #48 (N1) owns the real node-state traits (chain store, commitment tree,
//! nullifier set, restart-safe snapshots) and will publish them from
//! qlab-consensus / qlab-node. Those have not landed, so this module defines the
//! **consumer-facing** slice the P2P layer needs — read the chain to serve sync,
//! ingest received headers / txs / checkpoints — as traits, with an in-memory
//! [`StubNode`] implementation for tests. Wiring these to the real node is N7
//! (#54); the trait names/shapes here are the contract N7 satisfies.
//!
//! Kept deliberately minimal: the P2P layer builds locators and answers
//! `GetHeaders` itself (see [`crate::sync`]) from a few primitive accessors, so
//! the node interface stays small and easy for N1 to implement over real state.

use std::collections::{HashMap, HashSet};

use qlab_devnet::body::TxEntry;
use qlab_devnet::chain::{ChainState, InsertError};
use qlab_devnet::committee::{Checkpoint, CommitteeState, Vote};
use qlab_devnet::finality::{FinalityTracker, FinalizeError};
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::codec::{checkpoint_id, tx_id};

/// What happened when an object was handed to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New and accepted into node state.
    Accepted,
    /// Already known; no state change (do not re-relay).
    Duplicate,
    /// Well-formed but its parent/context is missing — caller should sync it.
    Orphan,
    /// Rejected as invalid; the peer that sent it may be penalized.
    Rejected(&'static str),
}

impl IngestOutcome {
    /// Whether this object is worth relaying onward (only genuinely-new objects).
    pub fn should_relay(&self) -> bool {
        matches!(self, IngestOutcome::Accepted)
    }
}

/// Read-only view of the chain — the primitives sync/relay/serving need.
pub trait ChainView {
    fn genesis_hash(&self) -> Hash32;
    fn tip_hash(&self) -> Hash32;
    fn tip_height(&self) -> u64;
    /// A header by its hash, if known (on any fork).
    fn header(&self, hash: &Hash32) -> Option<BlockHeader>;
    /// The main-chain block hash at `height`, if the main chain reaches it.
    fn main_chain_hash_at(&self, height: u64) -> Option<Hash32>;
    /// Whether a header is known (on any fork).
    fn has_header(&self, hash: &Hash32) -> bool;
    /// The finalized height, if any checkpoint has finalized.
    fn finalized_height(&self) -> Option<u64>;
}

/// Ingest headers received from peers.
pub trait BlockIngest {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome;
}

/// The transaction mempool, from the P2P layer's point of view.
pub trait TxPool {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome;
    fn get_tx(&self, id: &Hash32) -> Option<TxEntry>;
    fn has_tx(&self, id: &Hash32) -> bool;
    /// All mempool transactions — used by compact-block reconstruction to build
    /// the short-id → tx index. (A real node would expose a short-id lookup;
    /// snapshotting the pool is fine at prototype scale.)
    fn all_txs(&self) -> Vec<TxEntry>;
}

/// Ingest finalized-checkpoint gossip (checkpoint + committee votes).
pub trait CheckpointIngest {
    fn ingest_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) -> IngestOutcome;
    fn has_checkpoint(&self, id: &Hash32) -> bool;
}

/// Convenience super-trait: a node the P2P layer can fully drive.
pub trait NodeState: ChainView + BlockIngest + TxPool + CheckpointIngest {}
impl<T: ChainView + BlockIngest + TxPool + CheckpointIngest> NodeState for T {}

/// An in-memory node-state stub for tests — a real (devnet) [`ChainState`] +
/// finality tracker + a mempool + a seen-checkpoint set. Structural only: it does
/// **not** re-run PoW / proof verification (that is N1/N4's job); it is enough to
/// exercise gossip, sync, and relay end to end.
pub struct StubNode {
    chain: ChainState,
    mempool: HashMap<Hash32, TxEntry>,
    committee: CommitteeState,
    finality: FinalityTracker,
    seen_checkpoints: HashSet<Hash32>,
}

impl StubNode {
    /// New node from a shared genesis header and committee.
    pub fn new(genesis: BlockHeader, committee: CommitteeState) -> Self {
        StubNode {
            chain: ChainState::new(genesis),
            mempool: HashMap::new(),
            committee,
            finality: FinalityTracker::new(),
            seen_checkpoints: HashSet::new(),
        }
    }

    /// Read-only chain access (tests / assertions).
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }
    /// Current mempool size.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }
    /// The finality tracker (tests / assertions).
    pub fn finality(&self) -> &FinalityTracker {
        &self.finality
    }
}

impl ChainView for StubNode {
    fn genesis_hash(&self) -> Hash32 {
        self.chain.genesis_hash()
    }
    fn tip_hash(&self) -> Hash32 {
        self.chain.tip_hash()
    }
    fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }
    fn header(&self, hash: &Hash32) -> Option<BlockHeader> {
        self.chain.header(hash).copied()
    }
    fn main_chain_hash_at(&self, height: u64) -> Option<Hash32> {
        self.chain.main_chain().get(height as usize).copied()
    }
    fn has_header(&self, hash: &Hash32) -> bool {
        self.chain.header(hash).is_some()
    }
    fn finalized_height(&self) -> Option<u64> {
        // The finality tracker (committee checkpoints) is the source of truth for
        // finalized height — the chain store only reflects it when the finalized
        // block is also locally known.
        self.finality.finalized_height()
    }
}

impl BlockIngest for StubNode {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome {
        match self.chain.insert_header(header) {
            Ok(_) => IngestOutcome::Accepted,
            Err(InsertError::Duplicate) => IngestOutcome::Duplicate,
            Err(InsertError::UnknownParent) => IngestOutcome::Orphan,
            Err(InsertError::BadHeight) => IngestOutcome::Rejected("bad height"),
        }
    }
}

impl TxPool for StubNode {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
        let id = tx_id(&tx);
        if self.mempool.contains_key(&id) {
            return IngestOutcome::Duplicate;
        }
        self.mempool.insert(id, tx);
        IngestOutcome::Accepted
    }
    fn get_tx(&self, id: &Hash32) -> Option<TxEntry> {
        self.mempool.get(id).cloned()
    }
    fn has_tx(&self, id: &Hash32) -> bool {
        self.mempool.contains_key(id)
    }
    fn all_txs(&self) -> Vec<TxEntry> {
        self.mempool.values().cloned().collect()
    }
}

impl CheckpointIngest for StubNode {
    fn ingest_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) -> IngestOutcome {
        let id = checkpoint_id(&cp);
        if self.seen_checkpoints.contains(&id) {
            return IngestOutcome::Duplicate;
        }
        match self.finality.try_finalize(&cp, &votes, self.committee.committee()) {
            Ok(()) => {
                self.seen_checkpoints.insert(id);
                // Mark the finalized block in the chain store (best-effort: the
                // block may not be known yet on this node, which is fine — the
                // checkpoint is still recorded for anchor/age queries).
                let _ = self.chain.set_finalized(cp.block_hash);
                IngestOutcome::Accepted
            }
            Err(FinalizeError::NotAdvancing { .. }) => {
                self.seen_checkpoints.insert(id);
                IngestOutcome::Duplicate
            }
            Err(FinalizeError::InsufficientQuorum { .. }) => {
                IngestOutcome::Rejected("insufficient quorum")
            }
            Err(FinalizeError::InvalidVote { .. }) => IngestOutcome::Rejected("invalid vote"),
            Err(FinalizeError::UnknownSigner { .. }) => IngestOutcome::Rejected("unknown signer"),
            Err(FinalizeError::DuplicateSigner { .. }) => {
                IngestOutcome::Rejected("duplicate signer")
            }
        }
    }
    fn has_checkpoint(&self, id: &Hash32) -> bool {
        self.seen_checkpoints.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::devnet_committee;
    use qlab_devnet::params_devnet::BOND_AMOUNT;

    fn genesis() -> BlockHeader {
        BlockHeader::genesis(1000, 0)
    }

    fn node() -> StubNode {
        let (committee, _v) = devnet_committee(7);
        StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT))
    }

    #[test]
    fn header_ingest_accept_dup_orphan() {
        let mut n = node();
        let g = genesis();
        let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
        assert_eq!(n.ingest_header(h1), IngestOutcome::Accepted);
        assert_eq!(n.ingest_header(h1), IngestOutcome::Duplicate);
        // A header whose parent we do not have → orphan.
        let unknown_parent = BlockHeader::child_of(&h1, 150, 1000, [2; 32]);
        let orphan_child = BlockHeader::child_of(&unknown_parent, 225, 1000, [3; 32]);
        assert_eq!(n.ingest_header(orphan_child), IngestOutcome::Orphan);
    }

    #[test]
    fn tx_ingest_dedups() {
        let mut n = node();
        let tx = TxEntry {
            proof: vec![1, 2, 3],
            public: qlab_devnet::body::TxPublic {
                anchor: [0; 32],
                nullifiers: vec![],
                commitments: vec![],
                bucket: qlab_devnet::fees::ArityBucket::TwoByTwo,
                fee: 0,
            },
        };
        assert_eq!(n.ingest_tx(tx.clone()), IngestOutcome::Accepted);
        assert_eq!(n.ingest_tx(tx.clone()), IngestOutcome::Duplicate);
        assert_eq!(n.mempool_len(), 1);
        assert!(n.has_tx(&tx_id(&tx)));
    }

    #[test]
    fn checkpoint_ingest_quorum_gate() {
        let (committee, validators) = devnet_committee(7); // quorum 5
        let mut n = StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT));
        let cp = Checkpoint::new(2, [0xAA; 32], [0xAA; 32]);

        let votes4: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(
            n.ingest_checkpoint(cp, votes4),
            IngestOutcome::Rejected("insufficient quorum")
        );

        let votes5: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(n.ingest_checkpoint(cp, votes5.clone()), IngestOutcome::Accepted);
        assert_eq!(n.finalized_height(), Some(2));
        // Re-delivery is a dup.
        assert_eq!(n.ingest_checkpoint(cp, votes5), IngestOutcome::Duplicate);
    }
}
