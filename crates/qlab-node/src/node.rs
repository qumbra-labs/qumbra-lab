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
    /// Block-body validation failed (header/body commitment mismatch, anchor not
    /// final, wrong fee, in-block double-spend, or invalid proof).
    Body(BodyError),
    /// A [`StoredBlock`] reaching the state-mutation funnel does not match its own
    /// header's `tx_body_commitment` (issue #77).
    ///
    /// Deliberately **distinct** from `Body(BodyError::CommitmentMismatch)`: that
    /// one is an adversarial object rejected at an entry point, this one means a
    /// block was assembled internally without the binding, or a replayed log
    /// record was corrupted or tampered with on disk. Same invariant, different
    /// culprit — do not merge the two.
    BodyCommitmentMismatch { height: u64, expected: Hash32, got: Hash32 },
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
            NodeError::BodyCommitmentMismatch { height, expected, got } => write!(
                f,
                "block at height {height} does not match its header's body commitment: \
                 header says {}, body hashes to {}",
                hex8(expected),
                hex8(got)
            ),
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

/// The header/body binding re-checked at the **state-mutation funnel**
/// (issue #77 P3, Addendum A1/A2).
///
/// [`Node::apply_state`] is the single door into node state — `apply_block` and
/// disk-log replay both pass through it — so checking here covers what the
/// entry-point check in [`validate_body`] structurally cannot: a future caller
/// that assembles a [`StoredBlock`] by hand, and a replayed log record whose
/// bytes were corrupted or tampered with on disk (replay deserializes
/// `LogRecord::Block` straight into `apply_state`, never through
/// `StoredBlock::from_parts`).
///
/// This is a **different job** from the entry check, not a substitute for it:
/// entry points reject adversarial input first and cheapest (P1); this catches
/// internal construction errors and replay damage. Both are kept.
///
/// Cost on replay is one Keccak pass over each block's bytes — bytes replay has
/// already paid to read off disk and deserialize, which costs strictly more.
///
/// **Genesis (height 0) is the single, deliberate exemption.** The devnet genesis
/// header pins `tx_body_commitment = ZERO_HASH` (`header.rs:107`) while an empty
/// body commits to `keccak256(coinbase_le)`, so genesis has never satisfied the
/// invariant; its hash is the frozen, operator-supplied network identity
/// (`4a75b3b8…c2c3`) and it is never sourced from the network. Changing it would
/// mean a new network, which is out of this fix's scope — see issue #77 finding
/// F1 and `qlab_devnet::body::tests::genesis_header_does_not_bind_its_empty_body`.
fn check_stored_binding(block: &StoredBlock) -> Result<(), NodeError> {
    if block.header.height == 0 {
        return Ok(()); // genesis — the documented exemption above
    }
    let got = block.body().commitment();
    if block.header.tx_body_commitment != got {
        return Err(NodeError::BodyCommitmentMismatch {
            height: block.header.height,
            expected: block.header.tx_body_commitment,
            got,
        });
    }
    Ok(())
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
                    // The binding is still checked (issue #77): this path skips
                    // `apply_state`, so it would otherwise be the one way a
                    // corrupted log record enters the node unchallenged.
                    check_stored_binding(b)?;
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
        // Read-only body validation (anchor closure borrows self immutably). The
        // header goes in too (issue #77): the body must be the one this header
        // committed to, checked before any other body work.
        {
            let anchor_ok = |root: &Hash32| self.is_valid_anchor(root);
            validate_body(&header, &body, verifier, anchor_ok).map_err(NodeError::Body)?;
        }
        let block = StoredBlock::from_parts(&header, &body);
        let hash = self.apply_state(&block)?;
        if let Some(dir) = &self.dir {
            persist::append_record(dir, &LogRecord::Block(block)).map_err(NodeError::Io)?;
        }
        Ok(hash)
    }

    /// The ancestor at exactly `height` of the block whose parent hash is `from`,
    /// found by walking `prev` through the chain store. `None` if the walk leaves
    /// the store or `height` is above `from`'s own height.
    ///
    /// Walking rather than indexing by height is deliberate: it answers "the
    /// ancestor **of this block**", which is what makes the maturity append
    /// schedule follow reorgs for free (see [`Self::apply_state`]). The cost is
    /// `depth` map lookups — 144 per block application at the maturity delay,
    /// against blocks the store holds anyway.
    fn ancestor_at(&self, from: &Hash32, height: u64) -> Option<&StoredBlock> {
        let mut cur = self.chain.block(from)?;
        while cur.header.height > height {
            cur = self.chain.block(&cur.header.prev)?;
        }
        (cur.header.height == height).then_some(cur)
    }

    /// The pure state transition (no proof verification, no log write): reject
    /// cross-block/in-block double-spends, store the block, append the coinbase
    /// leaf it matures plus its own output commitments, insert its nullifiers, and
    /// record the resulting root at this height. Used by both
    /// [`Self::apply_block`] and replay.
    fn apply_state(&mut self, block: &StoredBlock) -> Result<Hash32, NodeError> {
        // The funnel guard (issue #77): every state mutation — fresh application
        // and disk-log replay alike — passes through here, so the header/body
        // binding is re-established before anything is folded into state.
        check_stored_binding(block)?;
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
        // The coinbase leaf this block MATURES goes in first (issue #102) — the
        // one minted 144 blocks back, not this block's own. Computed before any
        // mutation, and before `put_block`, so it is a pure read of the ancestry
        // this block already commits to via `prev`.
        //
        // *Why the leaf moved.* Maturity used to be a mempool policy check
        // against a declaration the submitter supplied, which is a gate that only
        // fires when the spender chooses to let it — and, worse, a gate whose
        // honest use publishes "this tx spends that coinbase", collapsing the
        // anonymity set on a chain with no transparent tier. Appending the leaf
        // late instead means an immature spend has **no witness against any anchor
        // this chain accepts**: the leaf is in no root the node ever computed. Nothing
        // is declared, so nothing can be lied about, and the rule holds identically on
        // the P2P path and on a node that has just restarted.
        //
        // Not "unprovable" — an attacker can prove membership in a tree of their own;
        // what fails is the anchor, at `validate_body`. See `crate::coinbase`.
        //
        // *Why it is derived and not queued.* A leaf owed at `h + 144` is the
        // obvious candidate for a pending-insert map, and that would be a bug.
        // `Node::open`'s snapshot fast path applies `put_block` but deliberately
        // **skips `apply_state`** for every block at or below `applied_height`,
        // so any in-memory queue filled by `apply_state` would be missing exactly
        // the leaves owed across the snapshot boundary — `open` would build a
        // different tree than `replay`, which is a node forking from itself. So
        // the owed leaf is re-derived from the chain store, which both paths
        // populate for every block. Nothing is persisted and `Snapshot` is
        // unchanged.
        //
        // *Why it is reorg-safe.* The lookup walks `prev` from this block, so it
        // resolves against this block's own ancestry rather than a height index.
        // A block that leaves the main chain takes its unmatured coinbase with it:
        // whatever chain wins, the leaves appended are that chain's.
        //
        // *That it goes in first* is unchanged from issue #101 — an arbitrary but
        // fixed choice, and this is still the single funnel both fresh
        // application and log replay pass through, so `open == replay` holds by
        // construction.
        let matured = crate::coinbase::matured_coinbase_leaf(block.header.height, |minted_at| {
            self.ancestor_at(&block.header.prev, minted_at).map(|b| b.body())
        });
        let hash = self
            .chain
            .put_block(block.clone())
            .map_err(NodeError::Chain)?;
        if let Some(cb) = matured {
            self.commitments.append(cb);
            self.commitments_ordered.push(cb);
        }
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

    /// Whether the coinbase note minted at `minted_height` has entered the
    /// commitment tree yet, and if not, when it will (issue #102).
    ///
    /// This is the answer to "my coinbase note has no membership witness — is it
    /// immature, or does it not exist?", a question option (b) creates by making
    /// the two look identical. Reading it discloses nothing: both inputs are
    /// public chain facts, and unlike the `spends_coinbase` declaration it
    /// replaces, it says nothing about a spend. See
    /// [`crate::coinbase::CoinbaseMaturity`].
    pub fn coinbase_maturity(&self, minted_height: u64) -> crate::coinbase::CoinbaseMaturity {
        crate::coinbase::coinbase_maturity(minted_height, self.chain.tip_height())
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

#[cfg(test)]
mod tests {
    //! Issue #77 — the header/body binding at this crate's two seams: the
    //! `apply_block` entry point and the `apply_state` state-mutation funnel
    //! (which disk-log replay also passes through).

    use std::sync::atomic::{AtomicU64, Ordering};

    use qlab_devnet::body::{BodyError, TxEntry, TxPublic};
    use qlab_devnet::fees::{posted_fee, ArityBucket};
    use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;

    use super::*;
    use crate::store::StoredHeader;

    /// A proof is "valid" iff its bytes are `b"ok"` (the node is prover-free).
    struct MockVerifier;
    impl TxVerifier for MockVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        p.push(format!("qlab-node-i77-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn tx(anchor: Hash32, nf: u8) -> TxEntry {
        TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor,
                nullifiers: vec![[nf; 32]],
                commitments: vec![[nf.wrapping_add(80); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        }
    }

    /// A node whose genesis root is finalized, so an ordinary tx anchored to it
    /// passes the anchor gate and only the binding can reject it.
    fn node_with_finalized_genesis() -> (MemNode, BlockHeader, Hash32) {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::in_memory(genesis);
        assert!(node.finalize(g_header.header_hash()).unwrap());
        let root = node.commitment_root();
        (node, g_header, root)
    }

    fn child_committing_to(parent: &BlockHeader, body: &BlockBody) -> BlockHeader {
        BlockHeader::child_of(parent, parent.timestamp + 75, GENESIS_DIFFICULTY, body.commitment())
    }

    #[test]
    fn apply_block_rejects_a_body_the_header_did_not_commit_to() {
        let (mut node, g, root) = node_with_finalized_genesis();
        let honest = BlockBody { txs: vec![tx(root, 1)], coinbase: 0, coinbase_rkm: [0; 4] };
        let header = child_committing_to(&g, &honest);
        let swapped = BlockBody { txs: vec![tx(root, 2)], coinbase: 0, coinbase_rkm: [0; 4] };
        let err = node.apply_block(header, swapped.clone(), &MockVerifier).unwrap_err();
        assert!(
            matches!(
                err,
                NodeError::Body(BodyError::CommitmentMismatch { expected, got })
                    if expected == honest.commitment() && got == swapped.commitment()
            ),
            "got {err}"
        );
        assert_eq!(node.tip_height(), 0, "state untouched");
        assert_eq!(node.commitment_count(), 0);
    }

    /// The cheapest exploit at the state machine: an honest header, an empty body.
    #[test]
    fn apply_block_rejects_an_honest_header_with_an_empty_body() {
        let (mut node, g, root) = node_with_finalized_genesis();
        let honest = BlockBody { txs: vec![tx(root, 3)], coinbase: 0, coinbase_rkm: [0; 4] };
        let header = child_committing_to(&g, &honest);
        let err = node.apply_block(header, BlockBody::default(), &MockVerifier).unwrap_err();
        assert!(
            matches!(err, NodeError::Body(BodyError::CommitmentMismatch { .. })),
            "got {err}"
        );
        assert_eq!(node.tip_height(), 0, "no empty body was applied under an honest header");
    }

    /// The funnel guard: a log record whose body no longer matches its header —
    /// on-disk corruption, or a tampered log — is refused by replay. The entry
    /// check structurally cannot see this: replay deserializes `LogRecord::Block`
    /// straight into `apply_state`, never through `StoredBlock::from_parts`.
    #[test]
    fn replay_rejects_a_log_record_whose_body_no_longer_matches_its_header() {
        let dir = temp_dir("replay-tamper");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();

        // A block whose header honestly commits to `honest`…
        let honest = BlockBody { txs: vec![tx([9u8; 32], 4)], coinbase: 0, coinbase_rkm: [0; 4] };
        let header = child_committing_to(&g_header, &honest);
        // …but whose persisted body is not that body.
        let tampered = StoredBlock {
            header: StoredHeader::from(&header),
            txs: Vec::new(),
            coinbase: 0,
            coinbase_rkm: [0; 4],
        };
        persist::append_record(&dir, &LogRecord::Block(tampered)).unwrap();

        let err = match MemNode::replay(&dir, genesis.clone()) {
            Err(e) => e,
            Ok(_) => panic!("replay must refuse a tampered log record"),
        };
        assert!(
            matches!(err, NodeError::BodyCommitmentMismatch { height: 1, .. }),
            "got {err}"
        );
        // `open` (no snapshot ⇒ same path) refuses it too.
        assert!(matches!(
            MemNode::open(&dir, genesis),
            Err(NodeError::BodyCommitmentMismatch { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The snapshot fast path in `open` skips `apply_state` for log-prefix blocks
    /// (it only rebuilds the chain store) — so it carries the guard explicitly.
    #[test]
    fn open_snapshot_fast_path_also_rejects_a_tampered_record() {
        let dir = temp_dir("fastpath-tamper");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        node.finalize(g_header.header_hash()).unwrap();
        let root = node.commitment_root();

        // One honest block, then a snapshot covering it.
        let body = BlockBody { txs: vec![tx(root, 5)], coinbase: 0, coinbase_rkm: [0; 4] };
        let header = child_committing_to(&g_header, &body);
        node.apply_block(header, body, &MockVerifier).unwrap();
        node.save_snapshot().unwrap();
        assert_eq!(node.tip_height(), 1);
        drop(node);

        // Append a tampered record at the same height: `open` restores the
        // snapshot (applied_height = 1) and takes the fast path for it.
        let honest2 = BlockBody { txs: vec![tx(root, 6)], coinbase: 0, coinbase_rkm: [0; 4] };
        let h2 = child_committing_to(&g_header, &honest2);
        let tampered =
            StoredBlock {
                header: StoredHeader::from(&h2),
                txs: Vec::new(),
                coinbase: 0,
                coinbase_rkm: [0; 4],
            };
        persist::append_record(&dir, &LogRecord::Block(tampered)).unwrap();

        assert!(matches!(
            MemNode::open(&dir, genesis),
            Err(NodeError::BodyCommitmentMismatch { height: 1, .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Genesis is the one exemption, and it is exercised on every single startup:
    /// its header pins `ZERO_HASH` while an empty body hashes to
    /// `keccak256(coinbase_le)`. Locked so the exemption cannot be deleted without
    /// this failing loudly.
    #[test]
    fn genesis_is_exempt_from_the_binding_guard() {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        assert_ne!(
            genesis.header.tx_body_commitment,
            genesis.body().commitment(),
            "genesis really does not satisfy the invariant"
        );
        assert!(check_stored_binding(&genesis).is_ok(), "…and is exempt by height");
        // Nothing above height 0 inherits the exemption.
        let mut not_genesis = genesis.clone();
        not_genesis.header.height = 1;
        assert!(check_stored_binding(&not_genesis).is_err());
    }
}
