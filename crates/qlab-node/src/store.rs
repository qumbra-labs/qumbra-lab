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
use qlab_devnet::chain::{ChainState, FinalizeMarkError, InsertError, RestoreFinalizedError};
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
    /// # Panics
    ///
    /// On a header with an Annulet extension (lab #706): this is the **L1**
    /// stored mirror and has no place for it — its layout is frozen (the
    /// persisted-bytes verdict on #706). Unreachable from a peer; the Annulet
    /// stored form is B2/B3's.
    fn from(h: &BlockHeader) -> Self {
        assert!(
            h.ext == qlab_devnet::annulet::HeaderExt::NONE,
            "the L1 StoredHeader cannot represent an Annulet header (lab #706)"
        );
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
    /// The transaction's committed discovery group (issue #188), as the §2 group
    /// contents the block body's preimage covers.
    ///
    /// Persisted for the same reason `coinbase_rkm` is: without it
    /// [`StoredBlock::body`] rebuilds a body whose `commitment()` no longer
    /// equals the persisted header's `tx_body_commitment`, so a restart would
    /// fail its own header/body binding (#77) on every block that carries a
    /// transaction. Adding it is an incompatible on-disk change, hence
    /// `persist::FORMAT_VERSION = 3`.
    pub discovery: Vec<u8>,
    /// The transaction's name-service rider (lab #367), committed above
    /// `NAME_RULE_BOUNDARY_HEIGHT` — persisted for the same #77 reason as
    /// `discovery`: a v3 block rebuilt without it fails its own binding.
    ///
    /// **NOT an on-disk break**: `bincode` is positional, so this field never
    /// reaches a v3-era record — `persist` writes a rider-carrying block as
    /// its own additive log variant and keeps the frozen legacy layout for
    /// everything else. See `persist::WireRecord`.
    pub rider: Vec<u8>,
    /// The transaction's L2 surface (lab #708) — **in-memory only**: never
    /// written by an L1 layout (`serde(skip)`, so every L1 byte and both genesis
    /// hashes are unchanged); the Annulet log record (B2b) writes it explicitly.
    /// Absent is `[0x00]`, as on `TxEntry`.
    #[serde(skip, default = "l2_absent")]
    pub l2: Vec<u8>,
}

fn l2_absent() -> Vec<u8> {
    qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec()
}

/// What an Annulet block carries beyond the L1 stored mirror (lab #708 Q2):
/// the header extension and, for every block but genesis, the seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnuletStoredSeal {
    pub ext: qlab_devnet::annulet::AnnuletHeaderFields,
    /// `None` only for the (unsealed) genesis block.
    pub sig: Option<Box<[u8; qlab_devnet::annulet::ANNULET_SIG_LEN]>>,
}

/// The bucket a persisted `bucket_actions` value names. **Strict since lab
/// #470 stage 3** (the #233-adjacent third spelling): the old arm silently
/// coerced every unknown value to `TwoByTwo` — the empty-success pattern.
/// The complete legitimate value set, enumerated from the WRITERS rather than
/// assumed: the only producer is `From<&TxEntry> for StoredTx`, which writes
/// `ArityBucket::logical_actions()` — total over the three variants, so
/// {2, 4, 8} and nothing else, in every era (the #219 dummy latch never
/// changed `logical_actions`; a dummy-masked 2×2 wrote 2 before and after the
/// mint). `persist::read_records` refuses any other value BY NAME at datadir
/// open, so this panic is a checked invariant, not a reachable data path.
fn bucket_from_actions(actions: u32) -> ArityBucket {
    match actions {
        2 => ArityBucket::TwoByTwo,
        4 => ArityBucket::FourByFour,
        8 => ArityBucket::EightByEight,
        other => unreachable!(
            "bucket_actions {other} cannot come off a datadir: persist::read_records              refuses unknown values at open (lab #470 stage 3)"
        ),
    }
}

impl From<&TxEntry> for StoredTx {
    /// Carries the L2 surface in memory (lab #708). What the L1 *layouts* cannot
    /// represent is refused where bytes are written — `persist::WireRecord::from`
    /// asserts every L1 log record surface-free — not here.
    fn from(t: &TxEntry) -> Self {
        Self { l2: t.l2.clone(),
            anchor: t.public.anchor,
            nullifiers: t.public.nullifiers.clone(),
            commitments: t.public.commitments.clone(),
            bucket_actions: t.public.bucket.logical_actions(),
            fee: t.public.fee,
            proof: t.proof.clone(),
            discovery: t.discovery.clone(),
            rider: t.rider.clone(),
        }
    }
}

impl From<&StoredTx> for TxEntry {
    fn from(s: &StoredTx) -> Self {
        TxEntry { l2: s.l2.clone(),
            proof: s.proof.clone(),
            discovery: s.discovery.clone(),
            rider: s.rider.clone(),
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
    /// Present exactly on an Annulet net's blocks (lab #708) — **in-memory
    /// only** (`serde(skip)`): no L1 layout writes it, and the L1 log refuses a
    /// block carrying it (`persist::WireRecord::from`); the Annulet log record
    /// (B2b) writes it explicitly.
    #[serde(skip)]
    pub annulet: Option<AnnuletStoredSeal>,
}

impl StoredBlock {
    /// Build the persisted form from a live devnet header + body.
    pub fn from_parts(header: &BlockHeader, body: &BlockBody) -> Self {
        let (coinbase, coinbase_rkm) =
            body.single_payee_parts().expect("accepted body is at the current cap");
        Self { annulet: None,
            header: header.into(),
            txs: body.txs.iter().map(StoredTx::from).collect(),
            coinbase,
            coinbase_rkm,
        }
    }

    /// The live devnet header this block round-trips to.
    pub fn header(&self) -> BlockHeader {
        let mut h: BlockHeader = (&self.header).into();
        if let Some(a) = &self.annulet {
            h.ext = qlab_devnet::annulet::HeaderExt::Annulet(a.ext);
        }
        h
    }

    /// An Annulet block from its sealed header and body (lab #708): the L1
    /// mirror fields for the shared parts, the extension and seal in
    /// [`AnnuletStoredSeal`], no coinbase (the L2 has none — the body rule has
    /// already refused a payee).
    pub fn from_sealed_parts(sealed: &qlab_devnet::annulet::SealedHeader, body: &BlockBody) -> Self {
        assert!(body.coinbase_payees.is_empty(), "an Annulet body has no coinbase (lab #706)");
        Self::annulet_block(&sealed.header, body, Some(sealed.sig.clone()))
    }

    /// The (unsealed) Annulet genesis block over an empty body.
    pub fn annulet_genesis(header: &BlockHeader) -> Self {
        assert_eq!(header.height, 0, "genesis height must be 0");
        Self::annulet_block(header, &BlockBody::default(), None)
    }

    fn annulet_block(
        header: &BlockHeader,
        body: &BlockBody,
        sig: Option<Box<[u8; qlab_devnet::annulet::ANNULET_SIG_LEN]>>,
    ) -> Self {
        let qlab_devnet::annulet::HeaderExt::Annulet(ext) = header.ext else {
            panic!("an Annulet block needs an Annulet header (lab #708)")
        };
        Self {
            header: StoredHeader {
                prev: header.prev,
                height: header.height,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                nonce: header.nonce,
                tx_body_commitment: header.tx_body_commitment,
            },
            txs: body.txs.iter().map(StoredTx::from).collect(),
            coinbase: 0,
            coinbase_rkm: [0; 4],
            annulet: Some(AnnuletStoredSeal { ext, sig }),
        }
    }

    /// The sealed header, for serving an Annulet block (`None` on L1 blocks
    /// and on the unsealed Annulet genesis).
    pub fn sealed_header(&self) -> Option<qlab_devnet::annulet::SealedHeader> {
        let a = self.annulet.as_ref()?;
        Some(qlab_devnet::annulet::SealedHeader { header: self.header(), sig: a.sig.clone()? })
    }

    /// The live devnet body this block round-trips to.
    pub fn body(&self) -> BlockBody {
        BlockBody::from_single_payee(self.txs.iter().map(TxEntry::from).collect(), self.coinbase, self.coinbase_rkm)
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
    /// The genesis **block header** hash (the root of the header DAG).
    ///
    /// 🔴 Not the operational "genesis hash" (issue #206): that is
    /// `qumbra_node::genesis::GenesisFile::hash()` over the whole genesis
    /// **file**, which is what `genesis init` prints and `expected_genesis_hash`
    /// pins. The file contains the block, so the two always differ. Named
    /// `genesis_hash` before #206.
    fn genesis_block_hash(&self) -> Hash32;
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
    ///
    /// 🔴 **Returns the store's own typed refusal, not a bool** (issue #241). This
    /// returned `bool` until then, and `MemChainStore` produced it with
    /// `self.chain.set_finalized(hash).is_ok()` — throwing away a
    /// [`FinalizeMarkError`] that the layer above then had to *reconstruct* from
    /// store state in order to journal a `why=`. That reconstruction was a second
    /// implementation of this method's decision and could disagree with it: it read
    /// the checkpoint's claimed height where this reads the stored header's, and it
    /// asked the block map where this asks the header map. Issue #205 is the same
    /// defect one layer up (`let _ = set_finalized(…)`); this is the seam it left
    /// behind.
    fn set_finalized(&mut self, hash: Hash32) -> Result<(), FinalizeMarkError>;
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

/// Why a rewind of the applied chain was refused (issue #162).
///
/// Every variant is a **refusal that leaves the store untouched**. A rewind is
/// the one operation in this crate that removes accepted blocks from node state,
/// so it says no on anything it cannot prove, and it says which proof failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewindError {
    /// The target block is not in the store.
    UnknownTarget,
    /// The target is known but is not an ancestor of (or equal to) the current
    /// tip — so "rewind" would be a jump onto a branch this store never applied,
    /// which is a different operation and is not this one.
    NotAnAncestorOfTip,
    /// The target is at or below the finalized head without descending from it.
    ///
    /// **This is the no-reorg-past-finality line, enforced at the one new door
    /// that could cross it.** `qlab_devnet::finality` and [`crate::recovery`] are
    /// untouched by the rewind work precisely because the rule is checked here,
    /// before anything is dropped, rather than repaired afterwards.
    PastFinalized { target_height: u64, finalized_height: u64 },
    /// A header on the retained ancestor path has no stored block. An internal
    /// invariant break ([`MemChainStore::put_block`] writes both together), never
    /// reachable from network input — reported rather than papered over.
    MissingBlockOnPath { height: u64 },
}

impl std::fmt::Display for RewindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewindError::UnknownTarget => write!(f, "rewind target is not a known block"),
            RewindError::NotAnAncestorOfTip => {
                write!(f, "rewind target is not an ancestor of the applied tip")
            }
            RewindError::PastFinalized { target_height, finalized_height } => write!(
                f,
                "rewind to height {target_height} would cross the finalized head at \
                 height {finalized_height}"
            ),
            RewindError::MissingBlockOnPath { height } => {
                write!(f, "no stored block for the retained path at height {height}")
            }
        }
    }
}

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
    /// **v4 identities** — a v5 net starts via [`MemChainStore::new_for`].
    pub fn new(genesis: StoredBlock) -> Self {
        Self::new_for(qlab_devnet::forms::GenesisForm::V4, genesis)
    }

    /// [`MemChainStore::new`] under an explicit genesis form (lab #470 stage
    /// 4a): the inner [`ChainState`] carries the form, and every later
    /// `put_block` identity comes from it, so this is the store's ONE
    /// identity-keying point.
    pub fn new_for(form: qlab_devnet::forms::GenesisForm, genesis: StoredBlock) -> Self {
        let header = genesis.header();
        let chain = ChainState::new_for(form, header);
        let ghash = header.header_hash_for(form);
        let mut blocks = HashMap::new();
        blocks.insert(ghash, genesis);
        Self { chain, blocks, genesis: ghash }
    }

    /// Read-only access to the wrapped fork-choice state.
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// The blocks this store would **keep** on a rewind to `target`: genesis →
    /// `target` inclusive, ascending — or the reason the rewind is refused.
    ///
    /// Read-only, so a caller can establish that a rewind is permitted before it
    /// commits to one. The three refusals are checked in the order they can be
    /// answered cheapest-first, and the finality one is last because it is the one
    /// that matters: see [`RewindError::PastFinalized`].
    pub fn rewind_path(&self, target: &Hash32) -> Result<Vec<StoredBlock>, RewindError> {
        let target_height =
            self.chain.header(target).ok_or(RewindError::UnknownTarget)?.height;
        let tip_height = self.chain.tip_height();
        if target_height > tip_height
            || self.chain.ancestor(&self.chain.tip_hash(), tip_height - target_height)
                != Some(*target)
        {
            return Err(RewindError::NotAnAncestorOfTip);
        }
        if let (Some(fin_hash), Some(fin_height)) =
            (self.chain.finalized_hash(), self.chain.finalized_height())
        {
            if target_height < fin_height
                || !self.chain.is_descendant_of(target, &fin_hash, fin_height)
            {
                return Err(RewindError::PastFinalized {
                    target_height,
                    finalized_height: fin_height,
                });
            }
        }
        let mut path = Vec::with_capacity(target_height as usize + 1);
        let mut cur = *target;
        let mut height = target_height;
        loop {
            let block =
                self.blocks.get(&cur).ok_or(RewindError::MissingBlockOnPath { height })?;
            path.push(block.clone());
            if block.header.height == 0 {
                break;
            }
            cur = block.header.prev;
            height -= 1;
        }
        path.reverse();
        Ok(path)
    }

    /// Drop every block that is not an ancestor of `target`, making `target` the
    /// tip. Returns the retained path (genesis → `target`, ascending).
    ///
    /// **Rebuilt rather than pruned in place, and that is the point.**
    /// `ChainState` has no set-tip and must not grow one: its tip is the output of
    /// the heaviest-chain rule, and a store that could be told what its tip is
    /// would be a second, un-gated fork choice. Re-inserting the retained path into
    /// a fresh `ChainState` reaches the same answer *through* the rule — every
    /// insert strictly increases cumulative work, so the tip lands on `target` —
    /// and leaves `qlab_devnet::chain` byte-for-byte unchanged.
    ///
    /// The abandoned branch is dropped from the block store too. That is deliberate
    /// and is what makes re-application possible at all: while the losing sibling
    /// is still present, `insert_header` answers `Duplicate` for it and the
    /// heaviest-chain tie-break keeps it as the incumbent tip.
    ///
    /// On refusal the store is untouched.
    ///
    /// The rebuild is keyed under **this store's own genesis form** (lab #521).
    /// Until 2026-08-20 it used [`Self::new`] — hard-coded v4 identities — so on
    /// a v5 net the fresh `ChainState` registered genesis under its v4 hash and
    /// the very first re-insert (whose `prev` is the v5 genesis hash) failed
    /// `UnknownParent` into the expect below: a T2 node could not reopen a
    /// datadir it had itself written, the moment its snapshot prefix carried a
    /// live rewind. On a v4 net `new_for(V4, …)` is what `new` did, byte for
    /// byte.
    pub fn rewind_to(&mut self, target: Hash32) -> Result<Vec<StoredBlock>, RewindError> {
        let kept = self.rewind_path(&target)?;
        let finalized = self.chain.finalized_hash().zip(self.chain.finalized_height());
        let mut rebuilt = Self::new_for(self.chain.form(), kept[0].clone());
        for block in &kept[1..] {
            rebuilt
                .put_block(block.clone())
                .expect("a retained ancestor path re-inserts in ascending order");
        }
        if let Some((hash, height)) = finalized {
            rebuilt.chain.restore_finalized(hash, height).expect(
                "rewind_path proved the retained tip descends from the finalized head",
            );
        }
        *self = rebuilt;
        Ok(kept)
    }
}

impl ChainStore for MemChainStore {
    fn put_block(&mut self, block: StoredBlock) -> Result<Hash32, InsertError> {
        let hash = self.chain.insert_header(block.header())?;
        self.blocks.insert(hash, block);
        Ok(hash)
    }
    fn genesis_block_hash(&self) -> Hash32 {
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
    fn set_finalized(&mut self, hash: Hash32) -> Result<(), FinalizeMarkError> {
        self.chain.set_finalized(hash)
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

#[cfg(test)]
mod tests {
    //! Issue #162 — the chain-store rewind, at the one layer where a side branch
    //! can actually exist.
    //!
    //! `MemChainStore` accepts side branches (`ChainState::insert_header` stores a
    //! non-adopted block and returns `Ok`), so this is where
    //! [`RewindError::NotAnAncestorOfTip`] is reachable. `MemNode`'s own store never
    //! holds one — the state machine applies a single linear chain — which is why
    //! the node-level tests pin the other refusals instead.

    use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;

    use super::*;

    fn block(parent: &BlockHeader, marker: u64) -> StoredBlock {
        let body = BlockBody::from_single_payee(vec![], 0, [marker; 4]);
        let header = BlockHeader::child_of(
            parent,
            parent.timestamp + 75,
            GENESIS_DIFFICULTY,
            body.commitment(),
        );
        StoredBlock::from_parts(&header, &body)
    }

    fn genesis() -> StoredBlock {
        crate::node::genesis_block(GENESIS_DIFFICULTY, 0)
    }

    /// A three-block chain plus a sibling of block 1 that fork choice did not
    /// adopt (equal work ⇒ the tie-break keeps the incumbent, then the main branch
    /// pulls ahead).
    fn store_with_a_side_branch() -> (MemChainStore, Vec<Hash32>, Hash32) {
        let g = genesis();
        let g_header = g.header();
        let mut store = MemChainStore::new(g);
        let b1 = block(&g_header, 0xA1);
        let b2 = block(&b1.header(), 0xA2);
        let b3 = block(&b2.header(), 0xA3);
        let side = block(&g_header, 0xB2);
        let mut main = vec![store.genesis_block_hash()];
        for b in [b1, b2, b3] {
            main.push(store.put_block(b).expect("main chain inserts"));
        }
        let side_hash = store.put_block(side).expect("a side branch is stored, not rejected");
        assert_eq!(store.tip_hash(), main[3], "and it is not the tip");
        (store, main, side_hash)
    }

    #[test]
    fn a_rewind_keeps_the_ancestor_path_and_drops_everything_else() {
        let (mut store, main, side_hash) = store_with_a_side_branch();
        let kept = store.rewind_to(main[1]).expect("rewind to height 1");

        assert_eq!(store.tip_hash(), main[1], "the tip is the target");
        assert_eq!(store.tip_height(), 1);
        assert_eq!(
            kept.iter().map(|b| b.header().header_hash()).collect::<Vec<_>>(),
            vec![main[0], main[1]],
            "genesis → target, ascending"
        );
        assert!(store.contains(&main[0]) && store.contains(&main[1]));
        assert!(!store.contains(&main[2]), "the abandoned suffix is gone");
        assert!(!store.contains(&main[3]));
        assert!(!store.contains(&side_hash), "and so is the side branch");
        assert_eq!(store.genesis_block_hash(), main[0], "genesis identity is unchanged");
    }

    /// The reason the abandoned branch is **dropped** rather than left in place:
    /// while it is present, re-inserting it answers `Duplicate` and the
    /// heaviest-chain tie-break keeps it as the tip. A rewind that only moved a
    /// pointer would leave the store unable to re-apply the winner.
    #[test]
    fn a_dropped_branch_can_be_re_applied_and_becomes_the_tip() {
        let (mut store, main, _) = store_with_a_side_branch();
        let b1 = store.block(&main[1]).expect("held").clone();
        store.rewind_to(main[0]).expect("rewind to genesis");
        let re = store.put_block(b1).expect("re-inserts after the drop");
        assert_eq!(re, main[1]);
        assert_eq!(store.tip_hash(), main[1], "and it is the tip again");
    }

    #[test]
    fn a_rewind_refuses_a_target_off_the_tips_own_ancestry() {
        let (mut store, main, side_hash) = store_with_a_side_branch();
        assert_eq!(
            store.rewind_path(&side_hash),
            Err(RewindError::NotAnAncestorOfTip),
            "a stored block that is not an ancestor of the tip is not a rewind target"
        );
        assert_eq!(store.rewind_to(side_hash), Err(RewindError::NotAnAncestorOfTip));
        assert_eq!(store.tip_hash(), main[3], "and the refusal changed nothing");
        assert!(store.contains(&side_hash));

        assert_eq!(store.rewind_path(&[0x99; 32]), Err(RewindError::UnknownTarget));
    }

    /// The finality line, at the store. Rewinding **to** the finalized head is
    /// legal; one block below it is not, and the refusal names both heights.
    #[test]
    fn a_rewind_refuses_to_cross_the_finalized_head() {
        let (mut store, main, _) = store_with_a_side_branch();
        assert_eq!(store.set_finalized(main[2]), Ok(()), "finalize height 2");

        assert_eq!(
            store.rewind_path(&main[1]),
            Err(RewindError::PastFinalized { target_height: 1, finalized_height: 2 })
        );
        assert_eq!(
            store.rewind_path(&main[0]),
            Err(RewindError::PastFinalized { target_height: 0, finalized_height: 2 })
        );
        assert_eq!(store.tip_hash(), main[3], "refusals changed nothing");

        // TO the finalized head is allowed, and the head survives the rebuild.
        store.rewind_to(main[2]).expect("rewinding to finality is not rewinding past it");
        assert_eq!(store.tip_hash(), main[2]);
        assert_eq!(store.finalized_hash(), Some(main[2]));
        assert_eq!(store.finalized_height(), Some(2));
    }

    /// 🔴 **Issue #241 — the trait hands back the store's own refusal, not a bool.**
    ///
    /// This is the seam the issue is about. `ChainStore::set_finalized` returned
    /// `bool`, and `MemChainStore` produced it with
    /// `self.chain.set_finalized(hash).is_ok()`, so the one caller that has to print
    /// *which* refusal happened had no choice but to reconstruct it by re-reading
    /// store state. All three variants are produced here by the real store, from the
    /// real conditions, so nothing downstream has to guess.
    #[test]
    fn the_chain_store_returns_its_typed_refusal_for_every_variant() {
        let (mut store, main, side_hash) = store_with_a_side_branch();

        // (1) Unknown — a hash this store has never held.
        assert_eq!(store.set_finalized([0x99; 32]), Err(FinalizeMarkError::Unknown));
        assert_eq!(store.finalized_hash(), None, "a refusal changes nothing");

        // Grow the un-adopted side branch past the height we are about to finalize,
        // so there is a KNOWN block above the finalized head that does not descend
        // from it — the only way to reach `NotDescendantOfFinalized`.
        let side1 = store.block(&side_hash).expect("the side branch is stored").clone();
        let side2 = block(&side1.header(), 0xB3);
        let side3 = block(&side2.header(), 0xB4);
        store.put_block(side2).expect("a side branch extends");
        let side3_hash = store.put_block(side3).expect("a side branch extends");

        assert_eq!(store.set_finalized(main[2]), Ok(()), "finalize height 2");

        // (2) NotAdvancing — known, on the main chain, but at or below the head.
        assert_eq!(store.set_finalized(main[1]), Err(FinalizeMarkError::NotAdvancing));
        assert_eq!(store.set_finalized(main[2]), Err(FinalizeMarkError::NotAdvancing));

        // (3) NotDescendantOfFinalized — known, ABOVE the head, wrong branch. This
        // is the no-reorg-past-finality refusal and it is the one an operator most
        // needs told apart from the other two.
        assert_eq!(
            store.set_finalized(side3_hash),
            Err(FinalizeMarkError::NotDescendantOfFinalized)
        );

        assert_eq!(store.finalized_hash(), Some(main[2]), "and none of them moved the head");
        assert_eq!(store.finalized_height(), Some(2));
    }

    /// 🔴 **Lab #521 — a v5 store's rewind rebuilds under v5 identities.**
    ///
    /// The rebuild inside [`MemChainStore::rewind_to`] used [`MemChainStore::new`]
    /// — hard-coded v4 — so on a v5 chain the fresh `ChainState` registered
    /// genesis under its v4 hash and the very first retained-path re-insert
    /// (whose `prev` is the v5 genesis hash) hit `UnknownParent` inside the
    /// `expect`: the T2 launch-day panic, a node unable to reopen a datadir it
    /// had itself written. This is that panic at the layer it lives in; the
    /// node-level lifecycle is pinned beside the other stage-4a tests.
    #[test]
    fn a_v5_store_rewinds_under_its_own_identities() {
        use qlab_devnet::forms::GenesisForm;

        fn block_v5(parent: &BlockHeader, marker: u64) -> StoredBlock {
            let body = BlockBody::from_single_payee(vec![], 0, [marker; 4]);
            let header = BlockHeader::child_of_for(
                GenesisForm::V5,
                parent,
                parent.timestamp + 75,
                GENESIS_DIFFICULTY,
                body.commitment_v5(),
            );
            StoredBlock::from_parts(&header, &body)
        }

        let g = crate::node::genesis_block_for(GenesisForm::V5, GENESIS_DIFFICULTY, 0);
        let g_header = g.header();
        let mut store = MemChainStore::new_for(GenesisForm::V5, g);
        let b1 = block_v5(&g_header, 0xA1);
        let b2 = block_v5(&b1.header(), 0xA2);
        let b2_again = b2.clone();
        let b1_hash = store.put_block(b1).expect("v5 chain inserts");
        store.put_block(b2).expect("v5 chain inserts");

        // Pre-fix this line panicked `UnknownParent` at the re-insert expect.
        store.rewind_to(b1_hash).expect("a v5 store rewinds its own retained path");
        assert_eq!(store.tip_hash(), b1_hash, "the tip is the target");
        assert_eq!(store.chain().form(), GenesisForm::V5, "the rebuilt store keeps its form");

        // And the rebuilt store still links by v5 identities: the dropped block
        // re-inserts (its `prev` is b1's v5 hash — under a mis-keyed rebuild this
        // would be `UnknownParent` again).
        store.put_block(b2_again).expect("re-application links under v5 identities");
    }
}
