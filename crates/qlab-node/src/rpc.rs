//! Node RPC for wallets + embedded compact-block serving over **live node state**
//! (M9-N6, issue #53).
//!
//! This is the wallet-facing surface of a Qumbra full node. It composes two
//! things that already exist, adding no new consensus logic and **no forked
//! codec**:
//!
//! - The node's own consensus state ([`crate::Node`] via the [`crate::NodeState`]
//!   read view) — status, valid anchors, and transaction admission.
//! - `qlab-cbserver`'s ratified note-discovery serving ([`qlab_cbserver::codec`]
//!   + [`qlab_cbserver::tree`]) — `/v1/compact`, `/v1/…/full`, and
//!   `/v1/tree/frontier`. The bytes are produced by cbserver's **exact**,
//!   golden-locked encoders (reused, never re-implemented — the golden digest is
//!   re-asserted in the tests), so a wallet cannot tell a node's compact stream
//!   from the reference server's.
//!
//! # Wallet API (in-process)
//!
//! - [`NodeRpc::submit_tx`] — admit a transaction: the cheap public checks
//!   against **live** node state (anchor valid *now* per §4/§7, posted fee per
//!   §4, no already-spent or in-tx-repeated nullifier), the discovery-artifact ↔
//!   `cm` consistency check, then the injected [`TxVerifier`] proof check. On
//!   success the tx joins a light pending pool and its note-discovery artifacts
//!   are recorded for later serving. *(The pending pool is N6's own thin holding
//!   area — the real mempool with weight/block-assembly policy is N4 (#51); N7
//!   (#54) rewires this `submit_tx` onto it. It is kept deliberately minimal.)*
//! - [`NodeRpc::status`] / [`NodeRpc::anchors`] — the read views wallets poll.
//!
//! # Serving against live node state
//!
//! `/v1/compact` and `/v1/…/full` are **gated by the node's accepted chain**: a
//! height is only served if the node has it (≤ tip), and each served group is
//! assembled from the block's real transactions joined to the recorded discovery
//! artifacts by transaction id. `/v1/tree/frontier` is served straight from the
//! node's **live** depth-32 commitment tree ([`crate::CommitmentStore::tree`]) —
//! the very tree the M3 bucket proves membership against — at the leaf count the
//! node reached by the requested height. The frontier bytes follow protocol-spec
//! §3 exactly (`version ‖ depth ‖ n_leaves ‖ leaf ‖ per-level present+node`,
//! `present` == bit *i* of `n_leaves−1`); a served frontier reconstructs the same
//! root the node reports (asserted end-to-end).
//!
//! # New wires (status / anchors)
//!
//! `/v1/status` and `/v1/anchors` are new N6 surfaces (no prior golden). They
//! follow the repo's versioning discipline — a [`RPC_VERSION`] lead byte,
//! unknown-version and trailing-byte rejection — and are round-trip +
//! golden-digest locked here. The compact/full/frontier wires are **not** touched
//! and stay at [`qlab_cbserver::WIRE_VERSION`]; issue #117 moved `RPC_VERSION` to
//! `0x02` and see its doc for why the two constants are no longer the same one.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use qlab_cbserver::codec::{
    encode_compact_response, encode_full_response, read_varint, write_varint, CodecError,
    CompactBlock, CompactGroup,
};
use qlab_cbserver::tree::Frontier;
use qlab_devnet::body::{TxEntry, TxPublic, TxVerifier};
use qlab_devnet::params_devnet::{DEGRADED_MODE_LAG_BLOCKS, MAX_ANCHOR_AGE_BLOCKS};
use qlab_note::hash::{digest_bytes, keccak256};
use qlab_note::wire::RecipientBundle;

use std::collections::HashMap;

use crate::mempool::{Mempool, MempoolError};
use crate::node::{Node, NodeState};
use crate::store::{ChainStore, CommitmentStore, Hash32, NullifierStore, StoredBlock, StoredTx};
use crate::telemetry::{LocalCommitment, Telemetry};

/// The RPC wire-format version byte for the node's **own** surfaces —
/// `/v1/status`, `/v1/anchors` and `/v1/telemetry`.
///
/// **`0x02` since issue #117.** It was `0x01`, defined as `= qlab_cbserver::
/// WIRE_VERSION` and documented as deliberately equal "so a client speaks one
/// version to the whole node". Adding the finalized-checkpoint identity to
/// [`Telemetry`] is a payload change on a reject-unknown-version wire, so the
/// bump is the ratified mechanism (#117) — and it necessarily severs that tie:
///
/// - The ratified **compact-block** family (`/v1/compact`, `/v1/…/full`,
///   `/v1/tree/frontier`) stays at [`qlab_cbserver::WIRE_VERSION`] = `0x01`. It
///   is golden-digest locked and its lead byte is asserted on the P2P compact
///   relay path (`qlab_p2p::compact`), so bumping it would be a wire-codepoint
///   change. Untouched here, on purpose.
/// - `/v1/status` and `/v1/anchors` share this constant and therefore bump too,
///   although their payloads did not change. That is accepted rather than giving
///   `Telemetry` a private version byte: the node's own surfaces move as one, and
///   an old reader failing loudly against a new node is the reject-unknown
///   feature working, not a regression.
///
/// So a client now speaks `0x02` to the node's own wires and `0x01` to the
/// compact-block wires it shares with the `qlab-cbserver` reference server.
pub const RPC_VERSION: u8 = 0x02;

// ---------------------------------------------------------------------------
// Transaction identity + note-discovery artifacts
// ---------------------------------------------------------------------------

/// Deterministic transaction id: Keccak-256 over the canonical public surface
/// (anchor ‖ nullifiers ‖ commitments ‖ logical-actions ‖ fee, all in order).
/// Proof bytes are intentionally excluded — the id names the *statement*, so the
/// same tx maps to its discovery artifacts whether it is still pending or already
/// embedded in an accepted block (whose [`StoredTx`] carries the same surface).
pub fn tx_id(anchor: &Hash32, nullifiers: &[Hash32], commitments: &[Hash32], actions: u32, fee: u64) -> Hash32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(anchor);
    for nf in nullifiers {
        buf.extend_from_slice(nf);
    }
    for cm in commitments {
        buf.extend_from_slice(cm);
    }
    buf.extend_from_slice(&actions.to_le_bytes());
    buf.extend_from_slice(&fee.to_le_bytes());
    keccak256(&buf)
}

fn tx_id_of_public(p: &TxPublic) -> Hash32 {
    tx_id(&p.anchor, &p.nullifiers, &p.commitments, p.bucket.logical_actions(), p.fee)
}

fn tx_id_of_stored(t: &StoredTx) -> Hash32 {
    tx_id(&t.anchor, &t.nullifiers, &t.commitments, t.bucket_actions, t.fee)
}

/// One recipient's note-discovery artifacts: the compact bundle a light client
/// pre-filters over ([`RecipientBundle`] = shared ML-KEM ct + per-output
/// `cm ‖ tag`) plus the AEAD payloads a wallet pulls only on a tag match.
#[derive(Clone)]
pub struct RecipientDiscovery {
    pub bundle: RecipientBundle,
    pub payloads: Vec<Vec<u8>>,
}

/// A transaction's full note-discovery artifacts (per recipient), submitted
/// alongside the consensus tx so the node can serve them to light clients.
#[derive(Clone, Default)]
pub struct TxDiscovery {
    pub recipients: Vec<RecipientDiscovery>,
}

impl TxDiscovery {
    /// The output commitments the discovery artifacts describe, in serving order
    /// (recipient-major, then per-output) — must equal the consensus tx's
    /// `commitments` for the discovery to bind to the statement.
    fn commitments(&self) -> Vec<Hash32> {
        self.recipients
            .iter()
            .flat_map(|r| r.bundle.entries.iter().map(|e| e.cm))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Submit outcome
// ---------------------------------------------------------------------------

/// The result of [`NodeRpc::submit_tx`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Admitted to the pending pool; carries the transaction id.
    Accepted(Hash32),
    /// Already pending (same id); no state change.
    Duplicate,
    /// Rejected by a live-state check; the reason is stable and machine-usable.
    Rejected(RejectReason),
}

/// Why a submitted transaction was rejected. All checks read **live** node state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The anchor is not a valid anchor now (not finalized, or aged out — §4/§7).
    AnchorNotValid,
    /// The fee does not equal the posted price for the bucket (§4).
    WrongFee { expected: u64, got: u64 },
    /// A nullifier is already in the permanent spent set (cross-block double-spend).
    NullifierSpent,
    /// A nullifier is repeated within this transaction.
    NullifierRepeatedInTx,
    /// A nullifier collides with one already reserved by a pending transaction.
    NullifierPending,
    /// The discovery artifacts' commitments do not match the tx's commitments.
    DiscoveryMismatch,
    /// The tx spends a coinbase note that has not matured (frozen §2: 144 blocks).
    ImmatureCoinbase,
    /// The proof failed to verify under the injected verifier.
    ProofInvalid,
}

// ---------------------------------------------------------------------------
// NodeRpc
// ---------------------------------------------------------------------------

/// The wallet-facing node RPC: owns a [`Node`], a light pending pool, and the
/// note-discovery store, and serves reads over live node state.
pub struct NodeRpc<C: ChainStore, N: NullifierStore, T: CommitmentStore> {
    node: Node<C, N, T>,
    /// The real N4 pending pool (M9-N7 rewire): admission runs the same
    /// posted-fee / anchor / maturity / double-spend / injected-proof gates a
    /// block assembler enforces, and holds txs by their body-commitment id.
    mempool: Mempool,
    /// Note-discovery artifacts by **statement** tx id ([`tx_id_of_public`]) — the
    /// source `/v1/compact` and `/v1/…/full` join accepted-block transactions
    /// against. Keyed by the statement id, NOT the mempool's body-commitment id:
    /// the two encodings are deliberately distinct (see the module docs).
    discovery: HashMap<Hash32, TxDiscovery>,
    /// Network-layer facts the node itself cannot observe (peer count, committee
    /// epoch): the N1 traits do not carry them, so the P2P glue stamps them in via
    /// [`Self::set_net_facts`] for `/v1/telemetry`. Zero on a standalone node.
    net: NetFacts,
    /// Checkpoint-identity facts the node itself cannot observe (issue #117): they
    /// live in the committee finality tracker and the never-double-sign ledgers.
    /// Stamped in by the same glue via [`Self::set_checkpoint_facts`]; **absent**
    /// on a standalone node, which is the truth about it.
    checkpoint: CheckpointFacts,
}

/// The network-layer half of [`Telemetry`], injected by the P2P layer (M10-T0-2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetFacts {
    /// Connected peer count.
    pub peer_count: u64,
    /// Current committee epoch.
    pub epoch: u64,
}

/// The checkpoint-identity half of [`Telemetry`], injected the same way
/// [`NetFacts`] is (issue #117). Default = both absent, i.e. "this composition
/// cannot see the identity" — never a zero standing in for one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointFacts {
    /// `fid` — the identity of the finalized checkpoint.
    pub finalized_id: Option<u64>,
    /// `sslot`/`sid` — what this node's own committee keys are committed to.
    pub signed: Option<LocalCommitment>,
}

/// The default all-in-memory RPC composition.
pub type MemNodeRpc = NodeRpc<
    crate::store::MemChainStore,
    crate::store::MemNullifierStore,
    crate::store::MemCommitmentStore,
>;

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> NodeRpc<C, N, T> {
    /// Wrap a node in the RPC surface.
    pub fn new(node: Node<C, N, T>) -> Self {
        Self {
            node,
            mempool: Mempool::default(),
            discovery: HashMap::new(),
            net: NetFacts::default(),
            checkpoint: CheckpointFacts::default(),
        }
    }

    /// Borrow the underlying node (read views / block application in tests + N7).
    pub fn node(&self) -> &Node<C, N, T> {
        &self.node
    }

    /// Mutably borrow the underlying node — the block pipeline (N4/N7) applies
    /// blocks here; the discovery already recorded at submit then becomes
    /// serveable once a block embeds the tx.
    pub fn node_mut(&mut self) -> &mut Node<C, N, T> {
        &mut self.node
    }

    /// Number of pending (submitted, not-yet-embedded) transactions.
    pub fn pending_len(&self) -> usize {
        self.mempool.len()
    }

    /// The pending transactions (submitted, awaiting inclusion) — what a block
    /// assembler (N4) / the N7 wiring draws from.
    pub fn pending_txs(&self) -> Vec<TxEntry> {
        self.mempool.entries()
    }

    /// The underlying pending pool (read-only) — block assembly / N7 harness.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Record note-discovery artifacts for a tx id directly (composition entry
    /// point for a driver that embeds blocks without routing them through
    /// [`Self::submit_tx`] — e.g. genesis import or N7 wiring).
    pub fn record_discovery(&mut self, txid: Hash32, discovery: TxDiscovery) {
        self.discovery.insert(txid, discovery);
    }

    /// Admit a transaction for a wallet. Cheap public checks against live node
    /// state run first (anchor validity, posted fee, nullifier gates, discovery
    /// binding); the injected proof verify runs last. On success the tx is pended
    /// and its discovery artifacts recorded for serving.
    pub fn submit_tx<V: TxVerifier>(
        &mut self,
        tx: TxEntry,
        discovery: TxDiscovery,
        verifier: &V,
    ) -> SubmitOutcome {
        let p = &tx.public;
        // The wallet-facing (statement) id — what discovery is keyed by and what a
        // caller gets back. Distinct from the mempool's body-commitment id.
        let txid = tx_id_of_public(p);

        // Two rpc-layer pre-checks the mempool contract does not cover:
        // (1) a nullifier repeated within this single tx, and
        let mut in_tx = std::collections::HashSet::new();
        for nf in &p.nullifiers {
            if !in_tx.insert(*nf) {
                return SubmitOutcome::Rejected(RejectReason::NullifierRepeatedInTx);
            }
        }
        // (2) the note-discovery artifacts must describe exactly this tx's outputs.
        if discovery.commitments() != p.commitments {
            return SubmitOutcome::Rejected(RejectReason::DiscoveryMismatch);
        }

        // The N4 mempool runs the real admission gates (posted fee → valid anchor →
        // coinbase maturity → consensus double-spend → duplicate → in-pool nullifier
        // conflict → injected proof) against live node state and holds the tx.
        match self.mempool.admit(tx, vec![], &self.node, verifier) {
            Ok(_body_id) => {
                self.discovery.insert(txid, discovery);
                SubmitOutcome::Accepted(txid)
            }
            Err(MempoolError::DuplicateTx) => SubmitOutcome::Duplicate,
            Err(MempoolError::WrongFee { expected, got }) => {
                SubmitOutcome::Rejected(RejectReason::WrongFee { expected, got })
            }
            Err(MempoolError::AnchorNotValid) => {
                SubmitOutcome::Rejected(RejectReason::AnchorNotValid)
            }
            Err(MempoolError::AlreadySpent { .. }) => {
                SubmitOutcome::Rejected(RejectReason::NullifierSpent)
            }
            Err(MempoolError::NullifierConflictInPool { .. }) => {
                SubmitOutcome::Rejected(RejectReason::NullifierPending)
            }
            Err(MempoolError::ImmatureCoinbase { .. }) => {
                SubmitOutcome::Rejected(RejectReason::ImmatureCoinbase)
            }
            Err(MempoolError::ProofInvalid) => SubmitOutcome::Rejected(RejectReason::ProofInvalid),
        }
    }

    // ---- live read views ---------------------------------------------------

    /// Current node status (live).
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            tip_height: self.node.tip_height(),
            tip_hash: self.node.tip_hash(),
            finalized_height: self.node.finalized_height(),
            commitment_root: self.node.commitment_root(),
            commitment_count: self.node.commitment_count(),
            nullifier_count: self.node.nullifier_count() as u64,
            pending_count: self.mempool.len() as u64,
        }
    }

    /// The set of commitment roots that are valid anchors right now (finalized +
    /// within the age window), newest first, plus the window context a wallet
    /// needs. Enumerated over the main chain using only the public node API.
    pub fn anchors(&self) -> AnchorSet {
        let mut roots = Vec::new();
        let mut seen = std::collections::HashSet::new();
        // Walk main chain tip→genesis, accumulating leaf counts, and test each
        // height's root for anchor validity.
        for (_, root) in self.main_chain_roots().into_iter().rev() {
            if self.node.is_valid_anchor(&root) && seen.insert(root) {
                roots.push(root);
            }
        }
        AnchorSet {
            tip_height: self.node.tip_height(),
            finalized_height: self.node.finalized_height(),
            max_age_blocks: MAX_ANCHOR_AGE_BLOCKS,
            roots,
        }
    }

    /// Stamp in the network-layer facts the node cannot observe itself (peer
    /// count, committee epoch). The P2P glue calls this so `/v1/telemetry` reports
    /// the full picture; a standalone node leaves them at zero.
    pub fn set_net_facts(&mut self, peer_count: u64, epoch: u64) {
        self.net = NetFacts { peer_count, epoch };
    }

    /// Stamp in the checkpoint-identity facts the node cannot observe itself
    /// (issue #117): what it finalized (`fid`) and what its own committee keys are
    /// committed to (`sslot`/`sid`). The P2P/committee glue calls this; a
    /// composition that does not leaves them absent, and `/v1/telemetry` then says
    /// so rather than reporting a checkpoint identity it never had.
    pub fn set_checkpoint_facts(&mut self, facts: CheckpointFacts) {
        self.checkpoint = facts;
    }

    /// A live finality-health snapshot (`/v1/telemetry`, M10-T0-2). The node-owned
    /// half (regime, stall depth, last-finalized age, heights, mempool) is derived
    /// from live state; peer count and epoch come from the injected [`NetFacts`].
    ///
    /// `last_finalized_age_secs` is chain-time (block timestamps), not wall clock,
    /// so telemetry is deterministic given the chain: the gap between the tip
    /// block's timestamp and the finalized block's (or genesis, if nothing is
    /// finalized).
    pub fn telemetry(&self) -> Telemetry {
        let tip_height = self.node.tip_height();
        let finalized_height = self.node.finalized_height();
        let age = self.last_finalized_age_secs();
        Telemetry::assemble(
            tip_height,
            finalized_height,
            age,
            self.mempool.len() as u64,
            self.net.peer_count,
            self.net.epoch,
            DEGRADED_MODE_LAG_BLOCKS,
        )
        .with_checkpoint(self.checkpoint.finalized_id, self.checkpoint.signed)
        // Unlike the identity half, this one IS node state: the tip header is in
        // the chain store, so it is read rather than injected (issue #117).
        .with_tip_difficulty(
            self.node.chain().block(&self.node.tip_hash()).map(|b| b.header.difficulty),
        )
    }

    /// Chain-time seconds between the tip block and the finalized block. Reports
    /// **0 when nothing is finalized** (M10-T0-5 / S8): the T0-2 runbook keys its
    /// stall alarm on this field, and a genesis fallback made "no finality yet" read
    /// as a huge absolute age (Phase B-lite logged `age_s=1784917791`). Uses only the
    /// public chain store.
    fn last_finalized_age_secs(&self) -> u64 {
        if self.node.finalized_height().is_none() {
            return 0; // nothing finalized ⇒ there is no finalized-age to report
        }
        let chain = self.node.chain();
        let tip_ts = chain
            .block(&chain.tip_hash())
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
        let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_hash());
        let base_ts = chain.block(&base_hash).map(|b| b.header.timestamp).unwrap_or(0);
        tip_ts.saturating_sub(base_ts)
    }

    // ---- main-chain helpers (public API only) ------------------------------

    /// The main chain, genesis-first, as stored blocks (walks tip→genesis via
    /// `header.prev`, then reverses).
    fn main_chain(&self) -> Vec<StoredBlock> {
        let chain = self.node.chain();
        let mut out = Vec::new();
        let mut hash = chain.tip_hash();
        loop {
            let Some(block) = chain.block(&hash) else { break };
            let block = block.clone();
            let prev = block.header.prev;
            let height = block.header.height;
            out.push(block);
            if height == 0 {
                break;
            }
            hash = prev;
        }
        out.reverse();
        out
    }

    /// `(height, commitment-count-after-this-block)` for each main-chain height.
    ///
    /// Must count exactly what `Node::apply_state` appends, in the same order, or
    /// every root this module reconstructs is wrong. Since issue #101 that is the
    /// block's **coinbase-note leaf first** (one, when the block mints), then its
    /// transaction commitments. Miscounting here would not fail loudly: it would
    /// publish anchors nobody can build a witness against.
    fn main_chain_counts(&self) -> Vec<(u64, u64)> {
        let mut count = 0u64;
        self.main_chain()
            .iter()
            .map(|b| {
                if crate::coinbase::coinbase_note_leaf(b.header.height, &b.body()).is_some() {
                    count += 1;
                }
                count += b.txs.iter().map(|t| t.commitments.len() as u64).sum::<u64>();
                (b.header.height, count)
            })
            .collect()
    }

    /// `(height, root-after-this-block)` for each main-chain height, recomputed
    /// from the live tree prefix — reproduces the node's per-height anchor roots
    /// without touching private state.
    fn main_chain_roots(&self) -> Vec<(u64, Hash32)> {
        let tree = self.node.commitments().tree();
        self.main_chain_counts()
            .into_iter()
            .map(|(h, c)| (h, digest_bytes(&tree.root_at(c))))
            .collect()
    }

    /// Leaf count of the commitment tree at the end of `height` (clamped to the
    /// live tree). Heights beyond the tip clamp to the full tree.
    fn leaves_at(&self, height: u64) -> u64 {
        let mut count = 0;
        for (h, c) in self.main_chain_counts() {
            if h <= height {
                count = c;
            } else {
                break;
            }
        }
        count
    }

    // ---- compact-block serving (byte-identical, live-gated) -----------------

    /// The `/v1/compact` blocks for `[from, to]` (inclusive), gated by the
    /// node's accepted chain: heights the node does not have are skipped. Each
    /// group is the block's transaction joined to its recorded discovery
    /// artifacts (an empty group if none were recorded).
    fn compact_range(&self, from: u64, to: u64) -> Vec<CompactBlock> {
        let by_height: HashMap<u64, StoredBlock> =
            self.main_chain().into_iter().map(|b| (b.header.height, b)).collect();
        let mut out = Vec::new();
        for height in from..=to {
            let Some(block) = by_height.get(&height) else { continue };
            let groups = block
                .txs
                .iter()
                .enumerate()
                .map(|(tx_index, tx)| {
                    let recipients = self
                        .discovery
                        .get(&tx_id_of_stored(tx))
                        .map(|d| d.recipients.iter().map(|r| r.bundle.clone()).collect())
                        .unwrap_or_default();
                    CompactGroup { tx_index: tx_index as u64, recipients }
                })
                .collect();
            out.push(CompactBlock { height, groups });
        }
        out
    }

    /// The `/v1/…/full` per-recipient payload lists for one accepted `(height,
    /// tx_index)`. `None` if the node has no such block/tx.
    fn full_payloads(&self, height: u64, tx_index: u64) -> Option<Vec<Vec<Vec<u8>>>> {
        let block = self.main_chain().into_iter().find(|b| b.header.height == height)?;
        let tx = block.txs.get(tx_index as usize)?;
        let disc = self.discovery.get(&tx_id_of_stored(tx))?;
        Some(disc.recipients.iter().map(|r| r.payloads.clone()).collect())
    }

    /// The frontier of the **live** node commitment tree at the leaf count the
    /// node reached by `height` (protocol-spec §3).
    fn frontier_at(&self, height: u64) -> Frontier {
        let count = self.leaves_at(height);
        self.node.commitments().tree().frontier_at(count)
    }

    // ---- pure request router (no socket) -----------------------------------

    /// Route a GET request URL to its response bytes — the socket-free serving
    /// core (mirrors [`qlab_cbserver::server::route`]). Mutations (submit) are
    /// the in-process [`Self::submit_tx`] API, not a URL.
    pub fn route(&self, url: &str) -> RouteResult {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
        match segs.as_slice() {
            ["v1", "status"] => Ok(self.status().to_bytes()),
            ["v1", "anchors"] => Ok(self.anchors().to_bytes()),
            ["v1", "telemetry"] => Ok(self.telemetry().to_bytes()),
            ["v1", "compact"] => {
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
                if to < from {
                    return Err((400, "'to' < 'from'"));
                }
                Ok(encode_compact_response(&self.compact_range(from, to)))
            }
            ["v1", "block", h, "tx", i, "full"] => {
                let height = h.parse::<u64>().map_err(|_| (400, "invalid height"))?;
                let index = i.parse::<u64>().map_err(|_| (400, "invalid tx index"))?;
                let payloads = self.full_payloads(height, index).ok_or((404, "no such (height, tx)"))?;
                Ok(encode_full_response(&payloads))
            }
            ["v1", "tree", "frontier"] => {
                let at = query_u64(query, "at").ok_or((400, "missing/invalid 'at'"))?;
                Ok(self.frontier_at(at).to_bytes())
            }
            _ => Err((404, "unknown endpoint")),
        }
    }
}

/// The pure router result: response bytes, or an `(http status, message)` error.
pub type RouteResult = Result<Vec<u8>, (u16, &'static str)>;

fn query_u64(query: &str, key: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return v.parse::<u64>().ok();
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Status / anchors wire (new N6 surfaces — versioned, round-trip locked)
// ---------------------------------------------------------------------------

/// Live node status a wallet polls (`/v1/status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub tip_height: u64,
    pub tip_hash: Hash32,
    pub finalized_height: Option<u64>,
    pub commitment_root: Hash32,
    pub commitment_count: u64,
    pub nullifier_count: u64,
    pub pending_count: u64,
}

impl NodeStatus {
    /// `version(0x01) ‖ tip_height(8 LE) ‖ tip_hash(32) ‖ has_final(u8) ‖
    /// [final_height(8 LE) if has] ‖ root(32) ‖ commitment_count(8 LE) ‖
    /// nullifier_count(8 LE) ‖ pending_count(8 LE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        out.extend_from_slice(&self.tip_hash);
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.commitment_root);
        out.extend_from_slice(&self.commitment_count.to_le_bytes());
        out.extend_from_slice(&self.nullifier_count.to_le_bytes());
        out.extend_from_slice(&self.pending_count.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<NodeStatus, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let tip_height = r.u64()?;
        let tip_hash = r.hash32()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let commitment_root = r.hash32()?;
        let commitment_count = r.u64()?;
        let nullifier_count = r.u64()?;
        let pending_count = r.u64()?;
        r.finish()?;
        Ok(NodeStatus {
            tip_height,
            tip_hash,
            finalized_height,
            commitment_root,
            commitment_count,
            nullifier_count,
            pending_count,
        })
    }
}

/// The valid-anchor set + window context (`/v1/anchors`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSet {
    pub tip_height: u64,
    pub finalized_height: Option<u64>,
    pub max_age_blocks: u64,
    /// Valid anchor roots, newest first.
    pub roots: Vec<Hash32>,
}

impl AnchorSet {
    /// `version(0x01) ‖ tip_height(8) ‖ has_final(u8) ‖ [final_height(8) if has]
    /// ‖ max_age_blocks(8) ‖ n_roots(varint) ‖ [root(32) × n]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.max_age_blocks.to_le_bytes());
        write_varint(&mut out, self.roots.len() as u64);
        for r in &self.roots {
            out.extend_from_slice(r);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<AnchorSet, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let tip_height = r.u64()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let max_age_blocks = r.u64()?;
        let n = r.varint()?;
        let mut roots = Vec::with_capacity(n as usize);
        for _ in 0..n {
            roots.push(r.hash32()?);
        }
        r.finish()?;
        Ok(AnchorSet { tip_height, finalized_height, max_age_blocks, roots })
    }
}

/// A tiny cursor reusing cbserver's `CodecError` vocabulary + varint, so the N6
/// wires reject exactly like the ratified ones (unknown version, truncation,
/// trailing bytes).
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub(crate) fn version(&mut self) -> Result<(), CodecError> {
        let v = *self.b.get(self.pos).ok_or(CodecError::Truncated { what: "version" })?;
        self.pos += 1;
        if v != RPC_VERSION {
            return Err(CodecError::BadVersion { got: v });
        }
        Ok(())
    }
    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        let v = *self.b.get(self.pos).ok_or(CodecError::Truncated { what: "u8" })?;
        self.pos += 1;
        Ok(v)
    }
    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        let end = self.pos + 8;
        let slice = self.b.get(self.pos..end).ok_or(CodecError::Truncated { what: "u64" })?;
        self.pos = end;
        Ok(u64::from_le_bytes(slice.try_into().unwrap()))
    }
    pub(crate) fn hash32(&mut self) -> Result<Hash32, CodecError> {
        let end = self.pos + 32;
        let slice = self.b.get(self.pos..end).ok_or(CodecError::Truncated { what: "hash32" })?;
        self.pos = end;
        Ok(slice.try_into().unwrap())
    }
    #[allow(dead_code)]
    pub(crate) fn varint(&mut self) -> Result<u64, CodecError> {
        read_varint(self.b, &mut self.pos)
    }
    pub(crate) fn finish(&self) -> Result<(), CodecError> {
        if self.pos != self.b.len() {
            return Err(CodecError::TrailingBytes { remaining: self.b.len() - self.pos });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Localhost HTTP serving (GET reads only — submit is the in-process API)
// ---------------------------------------------------------------------------

/// A running node-RPC HTTP server: bound address + worker thread. Read-only over
/// the wire (GET); the state is shared behind a mutex so an owner can keep
/// submitting / applying blocks while it serves. Mirrors
/// [`qlab_cbserver::server`], localhost only.
pub struct RpcServerHandle {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl RpcServerHandle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Serve `rpc`'s GET endpoints on `127.0.0.1:0`. The shared `Arc<Mutex<..>>`
/// lets the caller keep mutating node state (submit / apply) between requests.
pub fn serve<C, N, T>(rpc: Arc<Mutex<NodeRpc<C, N, T>>>) -> RpcServerHandle
where
    C: ChainStore + Send + 'static,
    N: NullifierStore + Send + 'static,
    T: CommitmentStore + Send + 'static,
{
    use tiny_http::{Method, Response, Server};
    let server = Arc::new(Server::http("127.0.0.1:0").expect("bind localhost ephemeral port"));
    let addr = server.server_addr().to_ip().expect("tcp listener has an ip address");
    let served = Arc::new(AtomicU64::new(0));

    let worker_server = Arc::clone(&server);
    let worker_served = Arc::clone(&served);
    let thread = std::thread::spawn(move || {
        for request in worker_server.incoming_requests() {
            worker_served.fetch_add(1, Ordering::Relaxed);
            if *request.method() != Method::Get {
                let _ = request.respond(Response::from_string("method not allowed").with_status_code(405));
                continue;
            }
            let url = request.url().to_string();
            let response = rpc.lock().expect("rpc mutex poisoned").route(&url);
            let _ = match response {
                Ok(bytes) => request.respond(Response::from_data(bytes)),
                Err((code, msg)) => request.respond(Response::from_string(msg).with_status_code(code)),
            };
        }
    });

    RpcServerHandle { addr, server, thread: Some(thread), served }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::fees::posted_fee;
    use crate::node::{genesis_block, MemNode};
    use qlab_cbserver::codec::decode_compact_response;
    use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::header::BlockHeader;
    use qlab_note::wire::{ClueSlot, CompactEntry};

    // A verifier that accepts iff the proof bytes are exactly b"ok".
    struct OkVerifier;
    impl TxVerifier for OkVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    fn cm_bytes(seed: u8) -> Hash32 {
        [seed; 32]
    }

    fn recip(ct_base: u8, cms: &[u8]) -> RecipientDiscovery {
        let ct: [u8; qlab_note::kem::CT_LEN] =
            core::array::from_fn(|i| ct_base.wrapping_add((i % 251) as u8));
        let entries = cms
            .iter()
            .map(|&c| CompactEntry { cm: cm_bytes(c), tag: [c ^ 0xa5; 8], clue: ClueSlot::Empty })
            .collect();
        RecipientDiscovery {
            bundle: RecipientBundle { ct, entries },
            payloads: cms.iter().map(|&c| vec![c; 120]).collect(),
        }
    }

    fn tx_with(anchor: Hash32, nfs: &[u8], cms: &[u8], fee: u64) -> TxEntry {
        TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor,
                nullifiers: nfs.iter().map(|&n| [n; 32]).collect(),
                commitments: cms.iter().map(|&c| cm_bytes(c)).collect(),
                bucket: ArityBucket::TwoByTwo,
                fee,
            },
        }
    }

    // A node with genesis finalized so anchors become valid, plus one applied
    // block, returned wrapped in NodeRpc. Returns (rpc, genesis_root, anchor).
    fn rpc_with_finalized_genesis() -> (MemNodeRpc, Hash32) {
        let genesis = genesis_block(1_000, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let ghash = node.chain().genesis_hash();
        assert!(node.finalize(ghash).unwrap());
        let anchor = node.commitment_root(); // empty-tree root, finalized at height 0
        assert!(node.is_valid_anchor(&anchor), "genesis root is a valid anchor once finalized");
        (NodeRpc::new(node), anchor)
    }

    /// S8: with nothing finalized, the finalized-age telemetry field is 0, NOT the
    /// tip−genesis fallback (which read as a huge absolute value in Phase B-lite).
    #[test]
    fn telemetry_age_is_zero_when_nothing_finalized() {
        let node = MemNode::in_memory(genesis_block(1_000, 0));
        let rpc = NodeRpc::new(node);
        let t = rpc.telemetry();
        assert_eq!(t.finalized_height, None, "fresh node has no finalized head");
        assert_eq!(t.last_finalized_age_secs, 0, "age is 0 when nothing is finalized");
    }

    #[test]
    fn submit_accepts_valid_tx_and_records_discovery() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        let disc = TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] };
        let out = rpc.submit_tx(tx.clone(), disc, &OkVerifier);
        assert!(matches!(out, SubmitOutcome::Accepted(_)));
        assert_eq!(rpc.pending_len(), 1);
        // Duplicate submit is a no-op.
        let disc2 = TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] };
        assert_eq!(rpc.submit_tx(tx, disc2, &OkVerifier), SubmitOutcome::Duplicate);
    }

    #[test]
    fn submit_rejects_each_bad_condition() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);

        // Bad anchor.
        let bad_anchor = tx_with([0xEE; 32], &[1], &[10], fee);
        let d = TxDiscovery { recipients: vec![recip(1, &[10])] };
        assert_eq!(
            rpc.submit_tx(bad_anchor, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::AnchorNotValid)
        );

        // Wrong fee.
        let wrong_fee = tx_with(anchor, &[1], &[10], fee + 1);
        let d = TxDiscovery { recipients: vec![recip(1, &[10])] };
        assert_eq!(
            rpc.submit_tx(wrong_fee, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::WrongFee { expected: fee, got: fee + 1 })
        );

        // Repeated nullifier in-tx.
        let dup_nf = tx_with(anchor, &[5, 5], &[10, 11], fee);
        let d = TxDiscovery { recipients: vec![recip(1, &[10, 11])] };
        assert_eq!(
            rpc.submit_tx(dup_nf, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::NullifierRepeatedInTx)
        );

        // Discovery/commitment mismatch (discovery lists a different cm).
        let mismatch = tx_with(anchor, &[1], &[10], fee);
        let d = TxDiscovery { recipients: vec![recip(1, &[99])] };
        assert_eq!(
            rpc.submit_tx(mismatch, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::DiscoveryMismatch)
        );

        // Bad proof (verifier rejects).
        let mut bad_proof = tx_with(anchor, &[1], &[10], fee);
        bad_proof.proof = b"nope".to_vec();
        let d = TxDiscovery { recipients: vec![recip(1, &[10])] };
        assert_eq!(
            rpc.submit_tx(bad_proof, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::ProofInvalid)
        );

        assert_eq!(rpc.pending_len(), 0, "no rejected tx is pended");
    }

    #[test]
    fn submit_rejects_pending_and_spent_nullifiers() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let a = tx_with(anchor, &[7], &[10], fee);
        assert!(matches!(
            rpc.submit_tx(a, TxDiscovery { recipients: vec![recip(1, &[10])] }, &OkVerifier),
            SubmitOutcome::Accepted(_)
        ));
        // A second tx reusing nullifier 7 conflicts with the pending reservation.
        let b = tx_with(anchor, &[7], &[11], fee);
        assert_eq!(
            rpc.submit_tx(b, TxDiscovery { recipients: vec![recip(2, &[11])] }, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::NullifierPending)
        );
    }

    #[test]
    fn status_and_anchors_roundtrip_and_reflect_state() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        rpc.submit_tx(tx, TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] }, &OkVerifier);

        let s = rpc.status();
        assert_eq!(s.tip_height, 0);
        assert_eq!(s.pending_count, 1);
        assert_eq!(NodeStatus::from_bytes(&s.to_bytes()).unwrap(), s, "status round-trips");

        let a = rpc.anchors();
        assert!(a.roots.contains(&anchor), "finalized genesis root is a valid anchor");
        assert_eq!(a.max_age_blocks, MAX_ANCHOR_AGE_BLOCKS);
        assert_eq!(AnchorSet::from_bytes(&a.to_bytes()).unwrap(), a, "anchors round-trip");
    }

    #[test]
    fn telemetry_endpoint_reflects_state_and_injected_net_facts() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        // Inject the network half (peers, epoch) the node cannot observe itself.
        rpc.set_net_facts(4, 2);
        // …and the checkpoint-identity half (issue #117), which lives in the
        // committee finality tracker and the never-double-sign ledgers.
        assert_eq!(rpc.telemetry().finalized_id, None, "absent until injected");
        rpc.set_checkpoint_facts(CheckpointFacts {
            finalized_id: Some(0x3f1a_9c2b_0d41),
            signed: Some(LocalCommitment { slot: 0, id: Some(0x3f1a_9c2b_0d41) }),
        });
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        rpc.submit_tx(tx, TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] }, &OkVerifier);

        let t = rpc.telemetry();
        // Genesis finalized at height 0, tip 0 ⇒ Final, no stall.
        assert_eq!(t.finality_status, qlab_devnet::ebbflow::FinalityStatus::Final);
        assert_eq!(t.tip_height, 0);
        assert_eq!(t.finalized_height, Some(0));
        assert_eq!(t.stall_depth, 0);
        assert_eq!(t.peer_count, 4, "injected peer count surfaces");
        assert_eq!(t.epoch, 2, "injected epoch surfaces");
        assert_eq!(t.mempool_size, 1, "one pending tx");
        assert_eq!(t.fid_field(), "3f1a9c2b0d41", "injected checkpoint identity surfaces");
        assert_eq!(t.sslot_field(), "0");
        assert_eq!(t.sid_field(), "3f1a9c2b0d41");
        assert_eq!(Telemetry::from_bytes(&t.to_bytes()).unwrap(), t, "telemetry round-trips");

        // The `/v1/telemetry` route serves exactly those bytes.
        let served = rpc.route("/v1/telemetry").unwrap();
        assert_eq!(served, t.to_bytes());
        assert_eq!(Telemetry::from_bytes(&served).unwrap(), t);
    }

    #[test]
    fn wires_reject_bad_version_and_trailing() {
        let (rpc, _) = rpc_with_finalized_genesis();
        let mut sb = rpc.status().to_bytes();
        let good = sb.clone();
        assert_eq!(good[0], RPC_VERSION);
        sb[0] = 0x09;
        assert!(matches!(NodeStatus::from_bytes(&sb), Err(CodecError::BadVersion { got: 9 })));
        let mut extra = good.clone();
        extra.push(0xff);
        assert!(matches!(NodeStatus::from_bytes(&extra), Err(CodecError::TrailingBytes { .. })));
        assert!(NodeStatus::from_bytes(&good[..good.len() - 1]).is_err());

        let mut ab = rpc.anchors().to_bytes();
        let good_a = ab.clone();
        ab[0] = 0x09;
        assert!(matches!(AnchorSet::from_bytes(&ab), Err(CodecError::BadVersion { got: 9 })));
        let mut extra_a = good_a.clone();
        extra_a.push(0);
        assert!(matches!(AnchorSet::from_bytes(&extra_a), Err(CodecError::TrailingBytes { .. })));
    }

    /// Issue #117's **collateral, made explicit**: `/v1/status` and `/v1/anchors`
    /// share `RPC_VERSION` with `/v1/telemetry`, so bumping it for the checkpoint
    /// identity moves them to `0x02` too even though their payloads are byte-for-
    /// byte what they were. A `0x01` reader now fails loudly against them.
    ///
    /// That is the accepted trade (see [`RPC_VERSION`]'s doc), and it is locked
    /// here so nobody later "fixes" it back into a silent accept-both.
    #[test]
    fn status_and_anchors_moved_to_0x02_with_telemetry_and_reject_0x01() {
        let (rpc, _) = rpc_with_finalized_genesis();
        assert_eq!(RPC_VERSION, 0x02);

        for mut payload in [rpc.status().to_bytes(), rpc.anchors().to_bytes(), rpc.telemetry().to_bytes()] {
            assert_eq!(payload[0], 0x02, "the node's own surfaces move as one");
            payload[0] = 0x01;
            let as_status = NodeStatus::from_bytes(&payload);
            let as_anchors = AnchorSet::from_bytes(&payload);
            let as_telemetry = Telemetry::from_bytes(&payload);
            assert!(matches!(as_status, Err(CodecError::BadVersion { got: 1 })));
            assert!(matches!(as_anchors, Err(CodecError::BadVersion { got: 1 })));
            assert!(matches!(as_telemetry, Err(CodecError::BadVersion { got: 1 })));
        }

        // …while the ratified compact-block family is untouched at 0x01. Bumping it
        // would be a wire-codepoint change (it is asserted on the p2p relay path).
        assert_eq!(qlab_cbserver::WIRE_VERSION, 0x01);
        assert_eq!(rpc.route("/v1/compact?from=0&to=0").unwrap()[0], qlab_cbserver::WIRE_VERSION);
        assert_eq!(rpc.route("/v1/tree/frontier?at=0").unwrap()[0], qlab_cbserver::WIRE_VERSION);
    }

    // Apply one real block carrying `tx` to the node (so it becomes serveable).
    fn apply_block_with(node: &mut MemNode, txs: Vec<TxEntry>) {
        let tip_hash = node.tip_hash();
        let parent = node.chain().block(&tip_hash).expect("tip block stored").header();
        let height = parent.height + 1;
        // A minting body needs a payee (issue #101).
        let body =
            BlockBody { txs, coinbase: height, coinbase_rkm: [height, 2, 3, 4] };
        // child_of's 2nd arg is the timestamp; height is derived from the parent.
        let header = BlockHeader::child_of(&parent, height, 1_000, body.commitment());
        node.apply_block(header, body, &OkVerifier).expect("block applies");
    }

    #[test]
    fn compact_and_full_serve_accepted_blocks_only() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        let disc = TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] };
        assert!(matches!(rpc.submit_tx(tx.clone(), disc, &OkVerifier), SubmitOutcome::Accepted(_)));

        // Before the tx is in a block, nothing is served for height 1.
        let empty = rpc.route("/v1/compact?from=1&to=1").unwrap();
        assert_eq!(decode_compact_response(&empty).unwrap().len(), 0, "no accepted block yet");

        // Embed the tx in a block and apply it.
        apply_block_with(rpc.node_mut(), vec![tx]);

        let bytes = rpc.route("/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 1);
        assert_eq!(blocks[0].groups.len(), 1);
        assert_eq!(blocks[0].groups[0].recipients[0].entries.len(), 2, "2 outputs served");

        // Full-fetch payloads for that (height, tx).
        let full = rpc.route("/v1/block/1/tx/0/full").unwrap();
        let per_recipient = qlab_cbserver::codec::decode_full_response(&full).unwrap();
        assert_eq!(per_recipient.len(), 1);
        assert_eq!(per_recipient[0].len(), 2, "two AEAD payloads");

        // A height the node does not have serves nothing / errors as cbserver does.
        assert!(matches!(rpc.route("/v1/block/9/tx/0/full"), Err((404, _))));
    }

    #[test]
    fn e2e_over_localhost_socket() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        rpc.submit_tx(tx.clone(), TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] }, &OkVerifier);
        apply_block_with(rpc.node_mut(), vec![tx]);

        let shared = Arc::new(Mutex::new(rpc));
        let handle = serve(Arc::clone(&shared));
        let base = handle.base_url();
        assert!(base.starts_with("http://127.0.0.1:"));
        let bytes = qlab_cbserver::client::http_get(&base, "/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        let sb = qlab_cbserver::client::http_get(&base, "/v1/status").unwrap();
        let status = NodeStatus::from_bytes(&sb).unwrap();
        assert_eq!(status.tip_height, 1);
        assert!(handle.requests_served() >= 2);
        handle.shutdown();
    }

    #[test]
    fn frontier_served_from_live_tree_reconstructs_node_root() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        rpc.submit_tx(tx.clone(), TxDiscovery { recipients: vec![recip(0x10, &[10, 11])] }, &OkVerifier);
        apply_block_with(rpc.node_mut(), vec![tx]);

        let bytes = rpc.route("/v1/tree/frontier?at=1").unwrap();
        let f = Frontier::from_bytes(&bytes).unwrap();
        let root = digest_bytes(&f.root());
        assert_eq!(root, rpc.node().commitment_root(), "served frontier reconstructs the LIVE node root");
        // Frontier at height 0 is the empty tree.
        let f0 = Frontier::from_bytes(&rpc.route("/v1/tree/frontier?at=0").unwrap()).unwrap();
        assert_eq!(f0.n_leaves, 0);
    }

    /// The embedded compact encoder is byte-identical to cbserver's golden
    /// framing — reused, not forked. Reproduce cbserver's golden vector through
    /// the exact encoder this module calls and assert the on-record digest.
    #[test]
    fn compact_encoder_matches_golden_framing() {
        let ct: [u8; qlab_note::kem::CT_LEN] = core::array::from_fn(|i| (i % 256) as u8);
        let e0 = CompactEntry { cm: [0xAA; 32], tag: [0xBB; 8], clue: ClueSlot::Empty };
        let e1 = CompactEntry { cm: [0xCC; 32], tag: [0xDD; 8], clue: ClueSlot::Empty };
        let group = CompactGroup {
            tx_index: 2,
            recipients: vec![RecipientBundle { ct, entries: vec![e0, e1] }],
        };
        let block = CompactBlock { height: 7, groups: vec![group] };
        let bytes = encode_compact_response(&[block]);
        assert_eq!(bytes.len(), 1177, "golden total length");
        let digest = keccak256(&bytes);
        let hex: String = digest.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(
            hex, "3ee2a5e66192bdba4d86e3f6283edbf8ed842f2ef854b724e60b071c9cf54017",
            "compact framing must stay byte-identical to cbserver's golden vector"
        );
    }
}
