//! The three consensus-state stores and their swappable-backend traits.
//!
//! A Qumbra full node keeps three pieces of state derived from the accepted
//! chain (protocol-spec §3/§6):
//!
//! 1. the **chain store** — every accepted block (header + body), plus the
//!    fork-choice tip and the finalized head (via [`ChainStore`]);
//! 2. the **commitment tree** — the depth-32 incremental Merkle tree of note
//!    commitments the M3 bucket proves membership against (via [`CommitmentStore`]);
//! 3. the **nullifier set** — the permanent hot set of spent nullifiers, the
//!    consensus double-spend gate (via [`NullifierStore`]).
//!
//! Each is a **trait** so downstream node work (M9-N2..N6 — mempool, block
//! pipeline, P2P, RPC, sync) can hold the interface and swap the backend (an
//! in-memory map today, an embedded KV store tomorrow) without touching the
//! state-transition logic in [`crate::node`]. This module ships the default
//! in-memory implementations ([`MemChainStore`], [`MemNullifierStore`],
//! [`MemCommitmentStore`]); disk durability is layered on top by
//! [`crate::node::Node`] via [`crate::persist`], not baked into the stores.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::chain::{ChainState, InsertError, RestoreFinalizedError};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::BlockHeader;

/// A 256-bit hash — block identity, commitment, nullifier, and anchor-root type
/// (byte form = lane-major LE, protocol-spec §1). Same as `qlab_devnet`'s.
pub type Hash32 = [u8; 32];

// ---------------------------------------------------------------------------
// Serializable mirrors of the qlab-devnet block types.
//
// qlab-devnet carries no serde (it is prover/IO-free by design), so the node
// defines its own on-disk representation and converts through the public fields
// — keeping "zero behavior change to existing crates" while still persisting
// real blocks. The reserved header slots are zero-sized markers reconstructed
// on load; only the hashed preimage fields are stored.
// ---------------------------------------------------------------------------

/// On-disk mirror of [`BlockHeader`]'s hashed preimage fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHeader {
    pub prev: Hash32,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub nonce: u64,
    pub tx_body_commitment: Hash32,
}

impl From<&BlockHeader> for StoredHeader {
    fn from(h: &BlockHeader) -> Self {
        Self {
            prev: h.prev,
            height: h.height,
            timestamp: h.timestamp,
            difficulty: h.difficulty,
            nonce: h.nonce,
            tx_body_commitment: h.tx_body_commitment,
        }
    }
}

impl From<&StoredHeader> for BlockHeader {
    fn from(s: &StoredHeader) -> Self {
        let mut h = BlockHeader::genesis(s.difficulty, s.timestamp);
        h.prev = s.prev;
        h.height = s.height;
        h.nonce = s.nonce;
        h.tx_body_commitment = s.tx_body_commitment;
        h
    }
}

/// On-disk mirror of a transaction's public surface + opaque proof bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTx {
    pub anchor: Hash32,
    pub nullifiers: Vec<Hash32>,
    pub commitments: Vec<Hash32>,
    /// Arity as logical-action count (2 / 4 / 8) — the bucket key.
    pub bucket_actions: u32,
    pub fee: u64,
    pub proof: Vec<u8>,
}

fn bucket_from_actions(actions: u32) -> ArityBucket {
    match actions {
        4 => ArityBucket::FourByFour,
        8 => ArityBucket::EightByEight,
        _ => ArityBucket::TwoByTwo,
    }
}

impl From<&TxEntry> for StoredTx {
    fn from(t: &TxEntry) -> Self {
        Self {
            anchor: t.public.anchor,
            nullifiers: t.public.nullifiers.clone(),
            commitments: t.public.commitments.clone(),
            bucket_actions: t.public.bucket.logical_actions(),
            fee: t.public.fee,
            proof: t.proof.clone(),
        }
    }
}

impl From<&StoredTx> for TxEntry {
    fn from(s: &StoredTx) -> Self {
        TxEntry {
            proof: s.proof.clone(),
            public: TxPublic {
                anchor: s.anchor,
                nullifiers: s.nullifiers.clone(),
                commitments: s.commitments.clone(),
                bucket: bucket_from_actions(s.bucket_actions),
                fee: s.fee,
            },
        }
    }
}

/// A whole accepted block as persisted: header mirror + body mirror.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBlock {
    pub header: StoredHeader,
    pub txs: Vec<StoredTx>,
    pub coinbase: u64,
    /// The miner's raw `rkm` for this block's coinbase note (issue #101).
    ///
    /// Persisted because the coinbase note is derived from `(height, body)` at
    /// apply time and replay must reproduce the identical leaf — a log without
    /// this field cannot rebuild the commitment tree. Adding it is an
    /// incompatible on-disk change, hence `persist::FORMAT_VERSION = 2`.
    pub coinbase_rkm: [u64; 4],
}

impl StoredBlock {
    /// Build the persisted form from a live devnet header + body.
    pub fn from_parts(header: &BlockHeader, body: &BlockBody) -> Self {
        Self {
            header: header.into(),
            txs: body.txs.iter().map(StoredTx::from).collect(),
            coinbase: body.coinbase,
            coinbase_rkm: body.coinbase_rkm,
        }
    }

    /// The live devnet header this block round-trips to.
    pub fn header(&self) -> BlockHeader {
        (&self.header).into()
    }

    /// The live devnet body this block round-trips to.
    pub fn body(&self) -> BlockBody {
        BlockBody {
            txs: self.txs.iter().map(TxEntry::from).collect(),
            coinbase: self.coinbase,
            coinbase_rkm: self.coinbase_rkm,
        }
    }
}

// ---------------------------------------------------------------------------
// Store traits — the M9-N2..N6 consumption surface.
// ---------------------------------------------------------------------------

/// Persistent block store + fork-choice / finality pointers.
///
/// Wraps the accepted-block set and the tip/finalized heads. Fork-choice and the
/// no-reorg-past-finality rule are delegated to `qlab_devnet::ChainState`; this
/// trait adds full-block (body) storage on top. Consumers: N4 (P2P block
/// serving/sync), N6 (replay), and the block pipeline (N3).
pub trait ChainStore {
    /// Store a fully-validated block, linking it to its parent and updating the
    /// tip per the heaviest-chain-gated-by-finality rule. Returns the block hash.
    fn put_block(&mut self, block: StoredBlock) -> Result<Hash32, InsertError>;
    /// The genesis block hash.
    fn genesis_hash(&self) -> Hash32;
    /// The current fork-choice tip hash.
    fn tip_hash(&self) -> Hash32;
    /// The tip height (main-chain length − 1).
    fn tip_height(&self) -> u64;
    /// The finalized head hash, if any.
    fn finalized_hash(&self) -> Option<Hash32>;
    /// The finalized head height, if any.
    fn finalized_height(&self) -> Option<u64>;
    /// Look up a stored block by hash.
    fn block(&self, hash: &Hash32) -> Option<&StoredBlock>;
    /// Whether a block with this hash is stored.
    fn contains(&self, hash: &Hash32) -> bool;
    /// Mark `hash` finalized (must be known, strictly advance, descend finality).
    fn set_finalized(&mut self, hash: Hash32) -> bool;
    /// Reinstate a finalized point from a durable snapshot. Unlike
    /// [`Self::set_finalized`], this proves one previously-established point
    /// against the reconstructed main chain rather than advancing live finality.
    fn restore_finalized(
        &mut self,
        hash: Hash32,
        height: u64,
    ) -> Result<(), RestoreFinalizedError>;
}

/// The permanent nullifier set — the consensus double-spend gate (protocol-spec
/// §6, "the nullifier set is consensus state"). Consumers: N2 (mempool admission
/// checks a candidate tx's nullifiers here), N3 (block application inserts).
pub trait NullifierStore {
    /// Insert a nullifier. Returns `false` if it was already present (a
    /// double-spend), leaving the set unchanged.
    fn insert(&mut self, nf: Hash32) -> bool;
    /// Whether `nf` has been spent.
    fn contains(&self, nf: &Hash32) -> bool;
    /// Number of spent nullifiers.
    fn len(&self) -> usize;
    /// Whether the set is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The depth-32 note-commitment tree (protocol-spec §3). Append-only; the root
/// over any prefix is derivable. Consumers: N2/N5 (read the current root + build
/// witnesses for wallets), N3 (append new output commitments on block apply).
pub trait CommitmentStore {
    /// Append a note commitment (on-wire lane bytes). Returns its leaf position.
    fn append(&mut self, cm: Hash32) -> u64;
    /// Number of appended commitments (leaves).
    fn count(&self) -> u64;
    /// The current root over all appended commitments, as lane-major LE bytes.
    fn root_bytes(&self) -> Hash32;
    /// Borrow the underlying tree (witness generation, frontier serving).
    fn tree(&self) -> &CommitmentTree;
}

// ---------------------------------------------------------------------------
// Default in-memory implementations.
// ---------------------------------------------------------------------------

/// In-memory [`ChainStore`]: a `qlab_devnet::ChainState` for headers/fork-choice
/// + a hash→block map for bodies.
#[derive(Clone)]
pub struct MemChainStore {
    chain: ChainState,
    blocks: HashMap<Hash32, StoredBlock>,
    genesis: Hash32,
}

impl MemChainStore {
    /// Start from a genesis block (its header's `prev` must be ZERO, height 0).
    pub fn new(genesis: StoredBlock) -> Self {
        let header = genesis.header();
        let chain = ChainState::new(header);
        let ghash = header.header_hash();
        let mut blocks = HashMap::new();
        blocks.insert(ghash, genesis);
        Self { chain, blocks, genesis: ghash }
    }

    /// Read-only access to the wrapped fork-choice state.
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }
}

impl ChainStore for MemChainStore {
    fn put_block(&mut self, block: StoredBlock) -> Result<Hash32, InsertError> {
        let hash = self.chain.insert_header(block.header())?;
        self.blocks.insert(hash, block);
        Ok(hash)
    }
    fn genesis_hash(&self) -> Hash32 {
        self.genesis
    }
    fn tip_hash(&self) -> Hash32 {
        self.chain.tip_hash()
    }
    fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }
    fn finalized_hash(&self) -> Option<Hash32> {
        self.chain.finalized_hash()
    }
    fn finalized_height(&self) -> Option<u64> {
        self.chain.finalized_height()
    }
    fn block(&self, hash: &Hash32) -> Option<&StoredBlock> {
        self.blocks.get(hash)
    }
    fn contains(&self, hash: &Hash32) -> bool {
        self.blocks.contains_key(hash)
    }
    fn set_finalized(&mut self, hash: Hash32) -> bool {
        self.chain.set_finalized(hash).is_ok()
    }
    fn restore_finalized(
        &mut self,
        hash: Hash32,
        height: u64,
    ) -> Result<(), RestoreFinalizedError> {
        self.chain.restore_finalized(hash, height)
    }
}

/// In-memory [`NullifierStore`] backed by a `HashSet`.
#[derive(Clone, Default)]
pub struct MemNullifierStore {
    set: std::collections::HashSet<Hash32>,
}

impl NullifierStore for MemNullifierStore {
    fn insert(&mut self, nf: Hash32) -> bool {
        self.set.insert(nf)
    }
    fn contains(&self, nf: &Hash32) -> bool {
        self.set.contains(nf)
    }
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// In-memory [`CommitmentStore`] wrapping `qlab_cbserver::CommitmentTree`.
#[derive(Clone, Default)]
pub struct MemCommitmentStore {
    tree: CommitmentTree,
}

impl CommitmentStore for MemCommitmentStore {
    fn append(&mut self, cm: Hash32) -> u64 {
        self.tree.append_bytes(&cm)
    }
    fn count(&self) -> u64 {
        self.tree.len()
    }
    fn root_bytes(&self) -> Hash32 {
        qlab_note::hash::digest_bytes(&self.tree.root())
    }
    fn tree(&self) -> &CommitmentTree {
        &self.tree
    }
}
