//! The composed node: state transition, finalization, snapshots, and replay.
//!
//! [`Node`] ties the three stores ([`ChainStore`], [`CommitmentStore`],
//! [`NullifierStore`]) together and owns the **state-transition function**
//! ([`Node::apply_block`]): validate a block, then fold its effects into the
//! commitment tree and nullifier set. It is generic over the three store traits,
//! so downstream node work can swap any backend; [`MemNode`] is the default
//! all-in-memory composition.
//!
//! Durability is restart-safe by construction:
//! - [`Node::open`] resumes from the atomic snapshot (fast path) and replays any
//!   log tail past it; a missing/torn snapshot falls back to a full log replay.
//! - [`Node::replay`] rebuilds purely from the block log and is the correctness
//!   anchor: `open`'s snapshot-assisted state MUST equal `replay`'s from-scratch
//!   state (asserted in the tests).
//!
//! The node is **prover-free**: transaction-proof verification is injected as a
//! [`TxVerifier`], so the real M3 verifier (built on `qlab-consensus`) plugs in
//! without this crate depending on the prover. Only newly-admitted blocks are
//! proof-checked; replay of already-accepted log blocks trusts the log and
//! re-applies deterministically (double-spends would still surface).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use qlab_devnet::body::{validate_body, BlockBody, BodyError, TxVerifier};
use qlab_devnet::chain::InsertError;
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS;

use crate::persist::{self, LogRecord, Snapshot, FORMAT_VERSION};
use crate::store::{
    ChainStore, CommitmentStore, Hash32, MemChainStore, MemCommitmentStore, MemNullifierStore,
    NullifierStore, StoredBlock,
};

/// The default all-in-memory node composition (with optional disk durability).
pub type MemNode = Node<MemChainStore, MemNullifierStore, MemCommitmentStore>;

/// Why applying a block failed.
#[derive(Debug)]
pub enum NodeError {
    /// The block does not extend the current tip (`header.prev != tip_hash`).
    /// This skeleton applies to the tip only; fork/reorg handling is N-later.
    NotExtendingTip { expected: Hash32, got: Hash32 },
    /// Block-body validation failed (anchor not final / wrong fee / in-block
    /// double-spend / invalid proof).
    Body(BodyError),
    /// A nullifier is already in the permanent set (a cross-block double-spend).
    NullifierSpent { tx: usize },
    /// The chain store rejected the header (bad parent / height / duplicate).
    Chain(InsertError),
    /// A persistence error.
    Io(io::Error),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::NotExtendingTip { expected, got } => write!(
                f,
                "block does not extend tip: expected prev {}, got {}",
                hex8(expected),
                hex8(got)
            ),
            NodeError::Body(e) => write!(f, "block body invalid: {e:?}"),
            NodeError::NullifierSpent { tx } => {
                write!(f, "tx {tx} double-spends an already-nullified note")
            }
            NodeError::Chain(e) => write!(f, "chain store rejected block: {e:?}"),
            NodeError::Io(e) => write!(f, "persistence error: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

fn hex8(h: &Hash32) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Read-only view of the node's consensus state — the interface tx admission
/// (N2), RPC (N5), and the block pipeline (N3) read. Implemented by [`Node`].
pub trait NodeState {
    /// The fork-choice tip height.
    fn tip_height(&self) -> u64;
    /// The fork-choice tip hash.
    fn tip_hash(&self) -> Hash32;
    /// The finalized head height, if any.
    fn finalized_height(&self) -> Option<u64>;
    /// The current commitment-tree root (lane-major LE bytes) — the newest
    /// anchor candidate.
    fn commitment_root(&self) -> Hash32;
    /// Number of note commitments in the tree.
    fn commitment_count(&self) -> u64;
    /// Whether `nf` has been spent (the consensus double-spend gate).
    fn is_spent(&self, nf: &Hash32) -> bool;
    /// Number of spent nullifiers.
    fn nullifier_count(&self) -> usize;
    /// Whether `root` is a valid transaction anchor **now**: it is a commitment
    /// root that was finalized (height ≤ finalized head) and is within the
    /// `MAX_ANCHOR_AGE_BLOCKS` window of the tip (protocol-spec §4, frozen §7).
    fn is_valid_anchor(&self, root: &Hash32) -> bool;
}

/// A full node: chain store + commitment tree + nullifier set, plus the anchor
/// index and optional disk durability.
pub struct Node<C: ChainStore, N: NullifierStore, T: CommitmentStore> {
    chain: C,
    nullifiers: N,
    commitments: T,
    /// `height → commitment root after applying that height's block`. The anchor
    /// set: a finalized entry within the age window is a valid anchor.
    roots_by_height: BTreeMap<u64, Hash32>,
    /// Every appended commitment / spent nullifier, in application order — the
    /// deterministic material a snapshot serializes (a replay reproduces the
    /// exact order, so the on-disk form is stable).
    commitments_ordered: Vec<Hash32>,
    nullifiers_ordered: Vec<Hash32>,
    /// Directory backing the block log + snapshot; `None` = in-memory only.
    dir: Option<PathBuf>,
}

impl MemNode {
    /// An in-memory node from a genesis block, with no disk durability.
    pub fn in_memory(genesis: StoredBlock) -> Self {
        Self::from_genesis(genesis, None)
    }

    /// Open (or create) a disk-backed node at `dir`, resuming restart-safely:
    /// load the atomic snapshot if present, then replay any block-log records
    /// past it. A missing/torn/version-mismatched snapshot falls back to a full
    /// genesis replay of the log. `genesis` must match the log's genesis.
    pub fn open(dir: impl AsRef<Path>, genesis: StoredBlock) -> Result<Self, NodeError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(NodeError::Io)?;

        let mut node = Self::from_genesis(genesis, Some(dir.clone()));
        let records = persist::read_records(&dir).map_err(NodeError::Io)?;

        // Fast path: restore derived state (tree/nullifiers/roots) from the
        // snapshot, so log-prefix blocks only need to rebuild the chain store
        // (cheap header inserts), not re-fold the tree. Blocks past the snapshot,
        // and every finalization, are fully replayed — keeping the result
        // identical to a from-genesis `replay`. No valid snapshot ⇒ full replay.
        let applied_height = match persist::load_snapshot(&dir).map_err(NodeError::Io)? {
            Some(snap) if snap.genesis_hash == node.chain.genesis_hash() => {
                node.restore_from_snapshot(&snap);
                snap.applied_height
            }
            _ => 0,
        };
        for rec in &records {
            match rec {
                LogRecord::Block(b) if b.header.height <= applied_height => {
                    // Derived state already restored — just rebuild the chain store.
                    node.chain.put_block(b.clone()).map_err(NodeError::Chain)?;
                }
                LogRecord::Block(b) => {
                    node.apply_state(b)?;
                }
                LogRecord::Finalize(h) => {
                    node.chain.set_finalized(*h);
                }
            }
        }
        Ok(node)
    }

    /// Rebuild the node purely from the log at `dir`, ignoring any snapshot — the
    /// from-scratch correctness anchor `open` is checked against. Applies every
    /// block and replays every finalization.
    pub fn replay(dir: impl AsRef<Path>, genesis: StoredBlock) -> Result<Self, NodeError> {
        let dir = dir.as_ref().to_path_buf();
        let mut node = Self::from_genesis(genesis, Some(dir.clone()));
        for rec in persist::read_records(&dir).map_err(NodeError::Io)? {
            match rec {
                LogRecord::Block(b) => {
                    node.apply_state(&b)?;
                }
                LogRecord::Finalize(h) => {
                    node.chain.set_finalized(h);
                }
            }
        }
        Ok(node)
    }

    fn from_genesis(genesis: StoredBlock, dir: Option<PathBuf>) -> Self {
        assert_eq!(genesis.header.height, 0, "genesis height must be 0");
        let commitments = MemCommitmentStore::default();
        let chain = MemChainStore::new(genesis);
        let mut roots_by_height = BTreeMap::new();
        // Genesis carries no outputs, so the tree is empty: record its root at
        // height 0 (the empty-tree root) as the base anchor entry.
        roots_by_height.insert(0, commitments.root_bytes());
        Self {
            chain,
            nullifiers: MemNullifierStore::default(),
            commitments,
            roots_by_height,
            commitments_ordered: Vec::new(),
            nullifiers_ordered: Vec::new(),
            dir,
        }
    }

    fn restore_from_snapshot(&mut self, snap: &Snapshot) {
        for cm in &snap.commitments {
            self.commitments.append(*cm);
        }
        self.commitments_ordered = snap.commitments.clone();
        for nf in &snap.nullifiers {
            self.nullifiers.insert(*nf);
        }
        self.nullifiers_ordered = snap.nullifiers.clone();
        self.roots_by_height = snap.roots_by_height.iter().copied().collect();
    }
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> Node<C, N, T> {
    /// Validate and apply a block at the tip, persisting it to the log if the
    /// node is disk-backed. Validation: it extends the tip; the body passes
    /// (anchor finalized-and-in-window, posted fee, no in-block double-spend, and
    /// every proof verifies via `verifier`); and no nullifier is already spent.
    /// On success the commitment tree and nullifier set advance and the block
    /// hash is returned.
    pub fn apply_block<V: TxVerifier>(
        &mut self,
        header: BlockHeader,
        body: BlockBody,
        verifier: &V,
    ) -> Result<Hash32, NodeError> {
        if header.prev != self.chain.tip_hash() {
            return Err(NodeError::NotExtendingTip {
                expected: self.chain.tip_hash(),
                got: header.prev,
            });
        }
        // Read-only body validation (anchor closure borrows self immutably).
        {
            let anchor_ok = |root: &Hash32| self.is_valid_anchor(root);
            validate_body(&body, verifier, anchor_ok).map_err(NodeError::Body)?;
        }
        let block = StoredBlock::from_parts(&header, &body);
        let hash = self.apply_state(&block)?;
        if let Some(dir) = &self.dir {
            persist::append_record(dir, &LogRecord::Block(block)).map_err(NodeError::Io)?;
        }
        Ok(hash)
    }

    /// The pure state transition (no proof verification, no log write): reject
    /// cross-block/in-block double-spends, store the block, append its output
    /// commitments, insert its nullifiers, and record the resulting root at this
    /// height. Used by both [`Self::apply_block`] and replay.
    fn apply_state(&mut self, block: &StoredBlock) -> Result<Hash32, NodeError> {
        // Reject any nullifier already spent, or repeated within this block,
        // BEFORE mutating — so a rejected block leaves state untouched.
        let mut seen: Vec<Hash32> = Vec::new();
        for (i, tx) in block.txs.iter().enumerate() {
            for nf in &tx.nullifiers {
                if self.nullifiers.contains(nf) || seen.contains(nf) {
                    return Err(NodeError::NullifierSpent { tx: i });
                }
                seen.push(*nf);
            }
        }
        let hash = self
            .chain
            .put_block(block.clone())
            .map_err(NodeError::Chain)?;
        for tx in &block.txs {
            for cm in &tx.commitments {
                self.commitments.append(*cm);
                self.commitments_ordered.push(*cm);
            }
            for nf in &tx.nullifiers {
                self.nullifiers.insert(*nf);
                self.nullifiers_ordered.push(*nf);
            }
        }
        self.roots_by_height
            .insert(block.header.height, self.commitments.root_bytes());
        Ok(hash)
    }

    /// Mark `hash` finalized (delegates the no-reorg-past-finality rule to the
    /// chain store) and log it, so a restart/replay reconstructs the finalized
    /// head. Finalization is what makes a commitment root a *valid anchor* (§4).
    /// `Ok(false)` = the chain store rejected it (unknown / non-advancing /
    /// off-finality); `Err` = a persistence failure.
    pub fn finalize(&mut self, hash: Hash32) -> Result<bool, NodeError> {
        if !self.chain.set_finalized(hash) {
            return Ok(false);
        }
        if let Some(dir) = &self.dir {
            persist::append_record(dir, &LogRecord::Finalize(hash)).map_err(NodeError::Io)?;
        }
        Ok(true)
    }

    /// Persist the current derived state as an atomic snapshot (no-op for an
    /// in-memory node). After this, [`Self::open`] resumes from here.
    pub fn save_snapshot(&self) -> Result<(), NodeError> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let snap = Snapshot {
            format_version: FORMAT_VERSION,
            genesis_hash: self.chain.genesis_hash(),
            applied_height: self.chain.tip_height(),
            tip: self.chain.tip_hash(),
            finalized: self
                .chain
                .finalized_hash()
                .zip(self.chain.finalized_height()),
            commitments: self.commitments_ordered.clone(),
            nullifiers: self.nullifiers_ordered.clone(),
            roots_by_height: self.roots_by_height.iter().map(|(h, r)| (*h, *r)).collect(),
        };
        persist::save_snapshot(dir, &snap).map_err(NodeError::Io)
    }

    /// Borrow the chain store.
    pub fn chain(&self) -> &C {
        &self.chain
    }
    /// Borrow the commitment store.
    pub fn commitments(&self) -> &T {
        &self.commitments
    }
    /// Borrow the nullifier store.
    pub fn nullifiers(&self) -> &N {
        &self.nullifiers
    }
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> NodeState for Node<C, N, T> {
    fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }
    fn tip_hash(&self) -> Hash32 {
        self.chain.tip_hash()
    }
    fn finalized_height(&self) -> Option<u64> {
        self.chain.finalized_height()
    }
    fn commitment_root(&self) -> Hash32 {
        self.commitments.root_bytes()
    }
    fn commitment_count(&self) -> u64 {
        self.commitments.count()
    }
    fn is_spent(&self, nf: &Hash32) -> bool {
        self.nullifiers.contains(nf)
    }
    fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }
    fn is_valid_anchor(&self, root: &Hash32) -> bool {
        let Some(fin_height) = self.chain.finalized_height() else {
            return false; // nothing finalized ⇒ no valid anchors yet
        };
        let tip = self.chain.tip_height();
        self.roots_by_height.iter().any(|(h, r)| {
            r == root && *h <= fin_height && tip.saturating_sub(*h) <= MAX_ANCHOR_AGE_BLOCKS
        })
    }
}

/// Build the genesis [`StoredBlock`] (empty body) at the given difficulty and
/// timestamp — the base every node starts from.
pub fn genesis_block(difficulty: u64, timestamp: u64) -> StoredBlock {
    StoredBlock::from_parts(&BlockHeader::genesis(difficulty, timestamp), &BlockBody::default())
}
