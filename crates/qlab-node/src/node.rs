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

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};

use qlab_devnet::forms::{BodySections, GenesisForm};
use qlab_devnet::body::{validate_body_with_names, BlockBody, BodyError, TxVerifier};
use qlab_devnet::chain::{FinalizeMarkError, InsertError, RestoreFinalizedError};
use qlab_devnet::committee::Checkpoint;
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS;

use crate::persist::{self, LogRecord, Snapshot, FORMAT_VERSION};
use crate::replay_progress::ReplayProgress;
use crate::store::{
    ChainStore, CommitmentStore, Hash32, MemChainStore, MemCommitmentStore, MemNullifierStore,
    NullifierStore, RewindError, StoredBlock,
};

/// The default all-in-memory node composition (with optional disk durability).
pub type MemNode = Node<MemChainStore, MemNullifierStore, MemCommitmentStore>;

/// **How many rewound blocks stay retrievable** (issue #198).
///
/// `8 × CHECKPOINT_CADENCE_BLOCKS`, the same figure and the same reasoning as
/// `qlab_p2p::adapter::MAX_REWIND_DEPTH` — it cannot be *imported* from there
/// (`qlab-p2p` depends on this crate, not the other way round), so it is restated
/// with its derivation rather than aliased. A block more than a few cadences below
/// the tip is finalized on a healthy net and [`Node::rewind_to`] refuses to cross
/// the finalized head, so material below that depth can never be re-applied; ×8 is
/// headroom for a stalled committee, the one regime in which a divergence can
/// legitimately run deep.
///
/// **This is a serving budget, not a correctness bound.** Overflowing it costs a
/// body some peer may have wanted; it cannot make this node wrong.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_RETAINED_BODIES: usize =
    (8 * qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS) as usize;

/// The byte budget for the same archive, matched to `qlab_p2p`'s
/// `MAX_PENDING_BODY_BYTES` so the two body queues a node carries cannot be sized
/// against different assumptions. Weight is the same crude sum the P2P side meters
/// with (proof bytes + 32 per nullifier/commitment + per-tx overhead), not a
/// serialization — this runs on a rewind and must not cost one.
/// 64 MiB since lab #785 F5-5a, with `MAX_PENDING_BODY_BYTES` (asserted on the
/// qlab-p2p side, which can see both).
pub const MAX_RETAINED_BODY_BYTES: usize = 64 * 1024 * 1024;

/// **Blocks this node has APPLIED AT SOME POINT and still holds, whether or not
/// they are in the applied chain right now** (issue #198).
///
/// `#182` gave the serving path one question — *have I applied this?* — and that
/// was a faithful proxy for *do I have this?* on the day it landed. `#178` broke
/// the equivalence four hours later: [`Node::rewind_to`] rebuilds the node from
/// genesis over the retained ancestor path, so the undone suffix leaves the block
/// store entirely. On 2026-08-01 the live net closed the loop that opens up
/// (`#197`), and the answer taken is that **possession outlives application**.
///
/// This is where the possession lives. It is deliberately NOT the applied store:
/// `ChainStore::contains` means *applied* to four separate callers — the duty
/// gate's lag arithmetic, `missing_body_hashes`, `is_body_worth_holding`, and
/// `on_block_announce`'s "we already have this" early return — and widening it
/// would have a node that rewound past a block treat the re-announced body as
/// redundant and drop it, which is the same deadlock one seam over.
///
/// Eviction is lowest-height-first, by a linear scan: `MAX_RETAINED_BODIES` is 64
/// and an eviction happens only on a rewind, so an index would cost more to
/// maintain than the scan costs to run.
#[derive(Clone, Debug, Default)]
struct RetainedBodies {
    by_hash: HashMap<Hash32, StoredBlock>,
    bytes: usize,
    /// The genesis form retained-block identities are computed under (lab
    /// #470 stage 4a). Defaults to v4; set at node construction.
    form: GenesisForm,
}

impl RetainedBodies {
    fn get(&self, hash: &Hash32) -> Option<&StoredBlock> {
        self.by_hash.get(hash)
    }

    fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// A block is back in the applied chain — the archive copy is now dead weight.
    fn forget(&mut self, hash: &Hash32) {
        if let Some(b) = self.by_hash.remove(hash) {
            self.bytes = self.bytes.saturating_sub(block_weight(&b));
        }
    }

    fn insert(&mut self, block: StoredBlock) {
        let hash = block.header().header_hash_for(self.form);
        let weight = block_weight(&block);
        if let Some(old) = self.by_hash.insert(hash, block) {
            self.bytes = self.bytes.saturating_sub(block_weight(&old));
        }
        self.bytes += weight;
        self.evict();
    }

    /// Drop anything more than [`MAX_RETAINED_BODIES`] below `tip` — past that
    /// depth `rewind_to` will refuse to go, so no peer can put the block back into
    /// an applied chain and the bytes serve nobody.
    fn prune_below(&mut self, tip: u64) {
        let floor = tip.saturating_sub(MAX_RETAINED_BODIES as u64);
        self.by_hash.retain(|_, b| {
            let keep = b.header.height > floor;
            if !keep {
                self.bytes = self.bytes.saturating_sub(block_weight(b));
            }
            keep
        });
    }

    fn evict(&mut self) {
        while self.by_hash.len() > MAX_RETAINED_BODIES
            || (self.bytes > MAX_RETAINED_BODY_BYTES && self.by_hash.len() > 1)
        {
            let victim = self
                .by_hash
                .iter()
                .min_by_key(|(hash, b)| (b.header.height, **hash))
                .map(|(hash, _)| *hash);
            let Some(victim) = victim else { break };
            self.forget(&victim);
        }
    }
}

/// The metered weight of a block, matched to `qlab_p2p::n1::txs_weight` plus the
/// coinbase fields — a budget unit, not a byte count.
fn block_weight(block: &StoredBlock) -> usize {
    block
        .txs
        .iter()
        .map(|tx| tx.proof.len() + 32 * (1 + tx.nullifiers.len() + tx.commitments.len()) + 16)
        .sum::<usize>()
        + 40
}

/// **Why a snapshot that was present and decodable was not honoured** (issue
/// #225) — the discarded half of a fall-through to the full replay.
///
/// The fall-through itself is always correct: the block log is the source of
/// truth and a from-genesis replay of it is this crate's standing correctness
/// anchor. That is exactly why the *reason* has to survive. A datadir whose
/// snapshot cannot be honoured has just told the operator something about
/// itself, and a node that recovers without saying so turns a finding into a
/// startup that is merely slower than usual — which is how this defect would
/// come back wearing a different hat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotRejection {
    /// The reconstructed log prefix did not end on the tip the snapshot claims,
    /// so the snapshot's derived state is for a branch this log abandoned
    /// (issue #162). Pre-#225 this was already a silent `Ok(None)`.
    TipDisagreement { applied_height: u64, snapshot_tip: Hash32, prefix_tip: Hash32 },
    /// A rewind the log implies could not be honoured against the chain store
    /// the snapshot path reconstructed (issue #225).
    ///
    /// `above_snapshot` says which of the two reconstruction loops refused.
    /// `true` is the shape that stranded a T0 host: fork choice moved the applied
    /// tip back onto a same-height sibling, so the prefix reconstruction dropped
    /// the orphan's parent, and the one logged block above `applied_height`
    /// then asked to rewind onto it.
    RewindRefused {
        applied_height: u64,
        /// Height of the log record whose `prev` asked for the rewind.
        at_height: u64,
        /// The rewind target — the record's `prev`.
        target: Hash32,
        error: RewindError,
        above_snapshot: bool,
    },
    /// The `names.bin` sidecar (lab #367) cannot be honoured beside this
    /// snapshot: it exists but does not decode, carries an unknown version, or
    /// records a different `applied_height` than the snapshot (the crash
    /// window between the two writes — they rename atomically one at a time).
    /// The full replay rebuilds the registry from the log and needs neither
    /// file, so this is a fall-through, not a refusal. An ABSENT sidecar is
    /// not this case: absence means the snapshot writer predates #367, whose
    /// registry state is exactly empty.
    NamesSidecarDisagreement { reason: String },
    /// `snapshot.bin` is present but could not even be loaded — undecodable
    /// bytes or a [`persist::FORMAT_VERSION`] mismatch (lab #408). Before #408
    /// this was `load_snapshot`'s silent `Ok(None)`, indistinguishable from a
    /// data dir that never had a snapshot.
    NotLoadable { reject: persist::SnapshotLoadReject },
    /// The snapshot decodes but hangs from a different genesis block than the
    /// one this node was handed — a snapshot from another net (or another
    /// mint). Also a silent fall-through before lab #408: the same
    /// present-but-unusable class as the load rejections above, discarded by a
    /// `filter()` with no record that a snapshot was ever there.
    GenesisMismatch { snapshot_genesis: Hash32, our_genesis: Hash32 },
}

impl std::fmt::Display for SnapshotRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotRejection::TipDisagreement { applied_height, snapshot_tip, prefix_tip } => {
                write!(
                    f,
                    "the log prefix at or below height {applied_height} ends on {}, but the \
                     snapshot claims tip {} — its derived state is for a branch this log abandoned",
                    hex8(prefix_tip),
                    hex8(snapshot_tip)
                )
            }
            SnapshotRejection::RewindRefused {
                applied_height,
                at_height,
                target,
                error,
                above_snapshot,
            } => {
                let where_ = if *above_snapshot {
                    "above the snapshot"
                } else {
                    "inside the snapshot prefix"
                };
                write!(
                    f,
                    "the log record at height {at_height} ({where_}, applied_height \
                     {applied_height}) implies a rewind to {} that this reconstruction cannot \
                     honour: {error}",
                    hex8(target)
                )
            }
            SnapshotRejection::NamesSidecarDisagreement { reason } => {
                write!(
                    f,
                    "the names.bin sidecar cannot be honoured beside this snapshot ({reason}); \
                     replaying from genesis rebuilds the registry from the log"
                )
            }
            SnapshotRejection::NotLoadable { reject } => write!(f, "{reject}"),
            SnapshotRejection::GenesisMismatch { snapshot_genesis, our_genesis } => write!(
                f,
                "the snapshot hangs from genesis block {} but this node's genesis block is {} — \
                 it belongs to a different net",
                hex8(snapshot_genesis),
                hex8(our_genesis)
            ),
        }
    }
}

/// What [`MemNode::open`] recovered from disk.
///
/// `replayed_records` counts log records that advanced state beyond the snapshot:
/// blocks above its applied height plus finalizations that advanced beyond its
/// restored finalized head. With no snapshot, every decoded record is replayed.
///
/// `snapshot_rejected` is `Some` when a snapshot **was** on disk but could not
/// be honoured — see [`SnapshotRejection`]. `snapshot_height` is usually `None`
/// in that case (no snapshot was used and the resume was a full replay), which
/// is exactly why the two fields are separate: before issue #225 "no snapshot
/// was used" and "the snapshot was unusable" were the same report.
///
/// **Both `Some` = the lab #408 near-tip degrade**: the snapshot was rejected,
/// but the log itself proves its tip is on the finalized main chain, so its
/// derived state was honoured anyway and only the tail was replayed. The
/// rejection is still reported — a rejected snapshot is an operator event —
/// but it no longer costs a from-genesis fold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub snapshot_height: Option<u64>,
    pub replayed_records: usize,
    pub resumed_tip: u64,
    pub snapshot_rejected: Option<SnapshotRejection>,
}

impl std::fmt::Display for RecoveryReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The rejected case is checked first and worded loudly: it is the one
        // startup where the operator has something to do afterwards.
        if let Some(why) = &self.snapshot_rejected {
            // Lab #408: rejected + a snapshot height = the near-tip degrade.
            // The rejection stays in the line — it is still an event — but the
            // resume it describes is the fast one, not the genesis fold.
            if let Some(height) = self.snapshot_height {
                return write!(
                    f,
                    "RECOVERY snapshot REJECTED ({why}) but its tip is on the finalized main \
                     chain — near-tip resume from height {height}, replayed {} records, resumed \
                     at tip {}",
                    self.replayed_records, self.resumed_tip
                );
            }
            return write!(
                f,
                "RECOVERY snapshot DISCARDED ({why}), full replay from genesis, replayed {} \
                 records, resumed at tip {}",
                self.replayed_records, self.resumed_tip
            );
        }
        match self.snapshot_height {
            Some(height) => write!(
                f,
                "RECOVERY restored snapshot at height {height}, replayed {} records, resumed at tip {}",
                self.replayed_records, self.resumed_tip
            ),
            None => write!(
                f,
                "RECOVERY no snapshot, replayed {} records, resumed at tip {}",
                self.replayed_records, self.resumed_tip
            ),
        }
    }
}

/// What a [`MemNode::rewind_to`] undid (issue #162).
///
/// Carries both ends rather than a depth, because "how far back" and "back onto
/// what" are different operator questions and the second one is the one that
/// distinguishes a rejoin from a repeat: `to_hash` is the block the state machine
/// will now re-apply forward from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewindReport {
    pub from_height: u64,
    pub from_hash: Hash32,
    pub to_height: u64,
    pub to_hash: Hash32,
}

impl RewindReport {
    /// How many applied blocks were dropped. The abandoned branch is linear from
    /// `to_hash` to `from_hash` (the target is an ancestor of the old tip — the
    /// rewind refuses otherwise), so the height difference is the block count.
    pub fn blocks_undone(&self) -> u64 {
        self.from_height.saturating_sub(self.to_height)
    }

    /// Whether anything was actually undone. A rewind to the current tip is a
    /// permitted no-op, and a no-op must not be reported as a recovery event.
    pub fn is_noop(&self) -> bool {
        self.from_hash == self.to_hash
    }
}

impl std::fmt::Display for RewindReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "REWIND applied tip {} at height {} → {} at height {} ({} block(s) undone)",
            hex8(&self.from_hash),
            self.from_height,
            hex8(&self.to_hash),
            self.to_height,
            self.blocks_undone()
        )
    }
}

/// What [`Node::finalize`] did with a finalize request (issue #241).
///
/// **A two-state enum and not a `bool`, because the refusal has to carry its own
/// reason to the operator's journal line.** Before #241 this was `Ok(bool)`, and the
/// one caller that renders `FINALIZE refused … why=` had to re-derive the reason by
/// re-reading store state — a second implementation of
/// [`ChainStore::set_finalized`]'s decision, able to disagree with the first. Issue
/// #205 removed exactly this discard one layer up (`let _ = set_finalized(…)`);
/// keeping a `bool` here preserved it one layer down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// The finalized head advanced, and (for a disk-backed node) the `Finalize`
    /// record is on the log.
    Recorded,
    /// The chain store refused, in its own terms. **Never a placeholder** — this is
    /// the value [`ChainState::set_finalized`] returned, not a reconstruction of it.
    ///
    /// [`ChainState::set_finalized`]: qlab_devnet::chain::ChainState::set_finalized
    Refused(FinalizeMarkError),
}

impl FinalizeOutcome {
    /// Whether the head advanced. A convenience for call sites that genuinely do not
    /// care *why* a refusal happened (replay, tests) — the reason is still in the
    /// value, not thrown away by the type.
    pub fn is_recorded(&self) -> bool {
        matches!(self, FinalizeOutcome::Recorded)
    }

    /// The store's refusal, if it refused.
    pub fn refusal(&self) -> Option<&FinalizeMarkError> {
        match self {
            FinalizeOutcome::Recorded => None,
            FinalizeOutcome::Refused(e) => Some(e),
        }
    }
}

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
    /// A decoded snapshot named a finalized point that cannot be proven against
    /// the reconstructed main chain. Refuse rather than silently starting clean.
    SnapshotFinality(RestoreFinalizedError),
    /// The snapshot claims finality that the authoritative append-only log cannot
    /// reproduce. Accepting it would make `open` disagree with `replay`.
    SnapshotFinalityNotLogged { hash: Hash32, height: u64 },
    /// Lab #785 F5-4b: re-deriving the wrapper surface on a snapshot path
    /// met a block above genesis that the chain store does not hold — the
    /// walk cannot say which bundle is latest, so it refuses rather than
    /// fall back to the genesis surface.
    WrapperWalkBroken { missing: Hash32 },
    /// A rewind of the applied chain was refused (issue #162). See
    /// [`RewindError`] — every variant leaves node state untouched.
    Rewind(RewindError),
    /// A persistence error.
    Io(io::Error),
    /// This node was handed a chain form it does not serve yet (lab #706):
    /// an Annulet block reaching the L1 node's state funnel. `owner` names the
    /// milestone that lands the Annulet node path (sequencer B2, state B3).
    FormNotServed { form: GenesisForm, owner: &'static str },
    /// An Annulet block reached the unsealed entry point (`apply_block`): on a
    /// sequencer net a block is applied only with its seal
    /// ([`Node::apply_sealed_block`], lab #708).
    UnsealedOnAnnulet,
    /// Final-on-acceptance (lab #708 Q4) was refused by the chain store for a
    /// block this node had just applied — an internal invariant, named.
    AnnuletFinality(FinalizeMarkError),
    /// A block-log record is of the other chain family than this node's form
    /// (lab #708): an Annulet record under an L1 genesis or the reverse — a
    /// foreign datadir, refused before any record is hashed.
    LogFormMismatch { form: GenesisForm, height: u64 },
    /// An Annulet header's `registry_root` is not the root of the registry
    /// this node holds after the block (lab #710, #728) — at genesis load
    /// (`height` 0) or on a block. A block without a registry write carries
    /// its parent's root; a block with one carries the root after the write.
    RegistryRootMismatch { height: u64, header: Hash32, store: Hash32 },
    /// A block's registry write (shape R, lab #728) was proven against a
    /// registry root that is not this node's root before the block — a write
    /// on another registry history.
    RegistryWriteNotOnParent { height: u64, surface: Hash32, store: Hash32 },
    /// Writing the R surface's leaf into this node's registry does not reach
    /// the root the surface declares (lab #728): the leaf and the declared
    /// root disagree about the tree they describe.
    RegistryWriteRootMismatch { height: u64, surface: Hash32, rebuilt: Hash32 },
    /// A block's registry write is refused by the registry itself (lab #728):
    /// asset 0's pinned slot, or a slot out of range.
    RegistryWrite { height: u64, err: crate::registry_store::RegistryError },
    /// The Annulet genesis notes do not state their issuance (lab #728 Q7):
    /// a note whose payload is not a genesis plaintext, or does not open its
    /// commitment. Genesis supply seeds the outstanding figure, so a genesis
    /// that cannot state it is refused by name.
    GenesisIssuance(String),
    /// The genesis registry does not build (a duplicate or out-of-range
    /// asset) — a malformed genesis, refused by name.
    RegistryGenesis(crate::registry_store::RegistryError),
    /// A block would take an asset's outstanding public supply below zero
    /// (lab #712): a redeem exceeding what was ever minted. Issuance is public
    /// arithmetic, and it cannot be negative.
    SupplyUnderflow { height: u64, asset: u16, outstanding: i128, delta: i128 },
}

/// What a V6 node carries beyond a V5 one (lab #785): committee₀ (the
/// roster finality records are judged by) and the wrapper chain's rule and
/// origin — installed before any record is replayed, carried across every
/// rebuild. `wrapper: None` refuses every bundle (ruling condition (b)).
#[derive(Clone)]
pub struct V6Setup {
    pub committee0: qlab_devnet::committee::Committee,
    pub wrapper: Option<qlab_devnet::body::WrapperSetup>,
}

/// What an Annulet node carries beyond an L1 node (lab #708/#710): the
/// genesis fee table and the genesis registry, already bound to the genesis
/// header's `registry_root`.
#[derive(Clone)]
pub(crate) struct AnnuletSetup {
    fees: qlab_devnet::annulet::L2FeeTable,
    /// The GENESIS registry — never a later one: a rebuild from genesis
    /// re-applies every block's write over it (lab #728).
    registry: crate::registry_store::MemRegistryStore,
    /// The genesis notes' commitments, in genesis order (lab #710, B1 P13):
    /// the fee unit's Phase-0 supply, applied at height 0.
    genesis_cms: Vec<Hash32>,
    /// The genesis notes' per-asset issuance (lab #728 Q7), recomputed from
    /// their public plaintexts with each commitment checked.
    genesis_supply: BTreeMap<u16, i128>,
}

impl AnnuletSetup {
    /// Build the registry and bind it to the genesis header (lab #710 Q6:
    /// on genesis load too), refusing a mismatch by name.
    fn bound_to(
        genesis_header: &BlockHeader,
        genesis_notes: &[qlab_devnet::annulet::GenesisNote],
        fees: qlab_devnet::annulet::L2FeeTable,
        leaves: &[crate::registry_store::RegistryLeaf],
    ) -> Result<Self, NodeError> {
        use crate::registry_store::RegistryStore as _;
        let registry = crate::registry_store::MemRegistryStore::from_genesis(leaves).map_err(NodeError::RegistryGenesis)?;
        let header_root = annulet_registry_root(genesis_header);
        if header_root != registry.root_bytes() {
            return Err(NodeError::RegistryRootMismatch { height: 0, header: header_root, store: registry.root_bytes() });
        }
        let genesis_supply = crate::asset_supply::genesis_issuance(genesis_notes)
            .map_err(NodeError::GenesisIssuance)?
            .into_iter()
            .map(|(asset, v)| {
                let v = i128::try_from(v).map_err(|_| NodeError::GenesisIssuance(format!("asset {asset}: issuance beyond i128")))?;
                Ok((asset, v))
            })
            .collect::<Result<_, NodeError>>()?;
        Ok(Self { fees, registry, genesis_cms: genesis_notes.iter().map(|n| n.cm).collect(), genesis_supply })
    }
}

/// The `registry_root` an Annulet header carries (zeros for an L1 header,
/// which no Annulet path hands in).
fn annulet_registry_root(h: &BlockHeader) -> Hash32 {
    match h.ext {
        qlab_devnet::annulet::HeaderExt::Annulet(ext) => ext.registry_root,
        _ => [0; 32],
    }
}

impl NodeError {
    /// The [`crate::metrics::BODY_REFUSAL_REASONS`] token this failure is counted
    /// under when a body is refused at the application funnel (issue #130 (b)).
    ///
    /// **The match is exhaustive on purpose.** #130's whole complaint is a refusal
    /// that reached no instrument, so a variant added later must not be able to
    /// arrive here and be silently folded into a catch-all: with no `_ =>` arm,
    /// adding one to [`NodeError`] fails to compile until somebody decides which
    /// class it belongs in. That decision is cheap to make and impossible to
    /// remember to make later.
    ///
    /// It lives beside the enum rather than at the counting site for the same
    /// reason: the enum and its classification are one thing to keep in step, and
    /// the compiler only enforces that if they are in the same file.
    pub fn refusal_reason(&self) -> &'static str {
        match self {
            NodeError::NotExtendingTip { .. } => "not_extending_tip",
            NodeError::Body(_) => "bad_body",
            NodeError::NullifierSpent { .. } => "nullifier_spent",
            NodeError::Io(_) => "persist_io",
            // Each of these means an invariant this node believes cannot fire has
            // fired, so they share one bucket — but they are enumerated, not
            // wildcarded. `BodyCommitmentMismatch` is the funnel guard (#77) and is
            // deliberately NOT `bad_body`: that one is an adversarial object refused
            // at an entry point, this one is an internally-assembled or on-disk
            // corrupted block, and the enum's own doc comment says not to merge them.
            NodeError::BodyCommitmentMismatch { .. }
            | NodeError::Chain(_)
            | NodeError::SnapshotFinality(_)
            | NodeError::SnapshotFinalityNotLogged { .. }
            | NodeError::WrapperWalkBroken { .. }
            | NodeError::Rewind(_)
            // A form this node cannot serve reaching its funnel is an internal
            // wiring error (`run` refuses an Annulet genesis before a node
            // exists), not a peer fault — the same bucket, enumerated.
            | NodeError::FormNotServed { .. }
            | NodeError::UnsealedOnAnnulet
            | NodeError::AnnuletFinality(_)
            | NodeError::LogFormMismatch { .. }
            | NodeError::RegistryGenesis(_)
            | NodeError::GenesisIssuance(_) => "internal",
            // A block whose header or registry write names another registry
            // than this node's state: refused like a bad body.
            NodeError::RegistryRootMismatch { .. }
            | NodeError::RegistryWriteNotOnParent { .. }
            | NodeError::RegistryWriteRootMismatch { .. }
            | NodeError::RegistryWrite { .. }
            | NodeError::SupplyUnderflow { .. } => "bad_body",
        }
    }
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
            NodeError::SnapshotFinality(e) => {
                write!(f, "snapshot finalized head is inconsistent with the block log: {e:?}")
            }
            NodeError::SnapshotFinalityNotLogged { hash, height } => write!(
                f,
                "snapshot finalized head {} at height {height} has no matching finalization in the block log",
                hex8(hash)
            ),
            NodeError::WrapperWalkBroken { missing } => write!(
                f,
                "re-deriving the wrapper surface: block {} is not held, so the latest bundle is unknown",
                hex8(missing)
            ),
            NodeError::Rewind(e) => write!(f, "rewind refused: {e}"),
            NodeError::Io(e) => write!(f, "persistence error: {e}"),
            NodeError::UnsealedOnAnnulet => write!(
                f,
                "an Annulet block is applied only with its sequencer seal (lab #708)"
            ),
            NodeError::AnnuletFinality(e) => {
                write!(f, "Annulet final-on-acceptance refused by the chain store: {e:?} (lab #708)")
            }
            NodeError::RegistryRootMismatch { height, header, store } => write!(
                f,
                "header registry_root {} at height {height} is not this node's registry root {} (lab #710)",
                hex8(header),
                hex8(store)
            ),
            NodeError::RegistryGenesis(e) => write!(f, "the genesis registry does not build: {e:?} (lab #710)"),
            NodeError::RegistryWriteNotOnParent { height, surface, store } => write!(
                f,
                "block {height}'s registry write is proven against root {} but this node's registry root is {} (lab #728)",
                hex8(surface),
                hex8(store)
            ),
            NodeError::RegistryWriteRootMismatch { height, surface, rebuilt } => write!(
                f,
                "block {height}'s registry write declares root {} but writing its leaf yields {} (lab #728)",
                hex8(surface),
                hex8(rebuilt)
            ),
            NodeError::RegistryWrite { height, err } => {
                write!(f, "block {height}'s registry write is refused by the registry: {err:?} (lab #728)")
            }
            NodeError::GenesisIssuance(e) => write!(f, "the Annulet genesis does not state its issuance: {e} (lab #728)"),
            NodeError::SupplyUnderflow { height, asset, outstanding, delta } => write!(
                f,
                "block {height} takes asset {asset}'s outstanding supply from {outstanding} by {delta} below zero (lab #712)"
            ),
            NodeError::LogFormMismatch { form, height } => write!(
                f,
                "the block log holds a record at height {height} of the other chain family than this \
                 {form:?} node — a foreign datadir; re-sync it, do not start against it (lab #708)"
            ),
            NodeError::FormNotServed { form, owner } => write!(
                f,
                "chain form {form:?} is not served by this node yet (lands with {owner}, lab #706)"
            ),
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
/// **There is no height-0 exemption any more (issue #115).** Genesis used to be
/// the single, deliberate exception: [`BlockHeader::genesis`] pinned
/// `tx_body_commitment = ZERO_HASH` while the genesis body committed to
/// `keccak256(coinbase_le ‖ rkm_le)`, so genesis structurally could not satisfy
/// the invariant and this function returned `Ok` for it unconditionally. That
/// exemption existed because genesis *predated* the binding (issue #77 F1), and
/// while it stood, "this genesis block is not the body it claims to be" was not
/// a property anything could express — a hand-assembled or disk-corrupted
/// genesis record entered node state unchallenged, and the only thing standing
/// between a node and a foreign genesis body was the `expected_genesis_hash`
/// config pin, which covers the *file* and not a `StoredBlock` reconstructed
/// past it. The 2026-07-31 mint set the genesis header's commitment to its real
/// body commitment, so the exemption is deleted rather than special-cased and
/// genesis is checked exactly like every other block — see
/// `qlab_devnet::body::tests::genesis_header_binds_its_empty_body`.
///
/// # Height-keyed since lab #367 (PR #464's finding, fixed by QUM-129)
///
/// The recompute is [`qlab_devnet::body::BlockBody::commitment_at`] **at the
/// block's own height**, not the bare `commitment()` — the "v2 regardless of
/// height" form whose own doc comment reserves it for pre-boundary blocks,
/// tests and the compat golden. While this seam was height-blind an ARMED node
/// (`NAME_RULE_BOUNDARY_HEIGHT = Some(19_008)`) refused **every** block above
/// the boundary, its own production included: the entry rule
/// (`validate_body_with_names` → `check_body_binding`) demanded the v3
/// commitment and this funnel demanded v2, so no block of any shape satisfied
/// both. It cost nothing below the boundary and everything above it, which is
/// how it survived the arming review.
///
/// The height is `block.header.height` — the same field the error below
/// reports, and the same one `check_body_binding` reads on the entry side, so
/// both layers now compute the identical expectation for the identical block.
/// That agreement is asserted end-to-end by
/// `qumbra-node/tests/name_boundary_drill.rs`.
///
/// **On replay this is what makes a v3-era datadir readable**: a logged block
/// carries its own height, so a v3 block recomputes v3 and every pre-boundary
/// block recomputes v2 byte-identically to before. A log written by an INERT
/// binary above the boundary (v2 bytes at a v3 height) is refused here —
/// loudly, naming the height — rather than silently starting fresh.
fn check_stored_binding(block: &StoredBlock) -> Result<(), NodeError> {
    check_stored_binding_for(GenesisForm::V4, BodySections::None, block)
}

/// [`check_stored_binding`] under an explicit genesis form (lab #470 4a): the
/// v4 arm is the height-keyed v2/v3 rule exactly as before; the v5 arm binds
/// under the height-keyed cap assertion in `commitment_v5_at` (the bytes stay
/// the same across that boundary).
///
/// The section axis (lab #785): on a V6 net every block binds under
/// `commitment_v6`, and on any other net a block carrying sections is refused
/// here — the V4/V5 commitments do not cover them.
fn check_stored_binding_for(
    form: GenesisForm,
    sections: BodySections,
    block: &StoredBlock,
) -> Result<(), NodeError> {
    let bundle = block.bundle_ref().map(|r| r.bytes()).transpose().map_err(NodeError::Io)?;
    check_stored_binding_with(form, sections, block, bundle.as_deref())
}

/// [`check_stored_binding_for`] over a bundle the caller has already read
/// (lab #785 F5-5c, pre-review Y4): `apply_state` reads a bundle once and
/// hands the same bytes to this check and to the fold.
fn check_stored_binding_with(
    form: GenesisForm,
    sections: BodySections,
    block: &StoredBlock,
    bundle: Option<&[u8]>,
) -> Result<(), NodeError> {
    if sections == BodySections::None && block.sections.is_some() {
        return Err(NodeError::Body(qlab_devnet::body::BodyError::SectionOnForm { section: "finality/bundle" }));
    }
    // Lab #785 F5-5c: the bundle is the caller's bytes (read back through
    // its reference once); the rest is the stored block's.
    let mut body = block.coinbase_view();
    if let Some(s) = &block.sections {
        body.finality = s.finality.clone();
        body.bundle = bundle.map(<[u8]>::to_vec).unwrap_or_default();
    }
    let got = match (form, sections) {
        (GenesisForm::V5, BodySections::V6) => body.commitment_v6(),
        (_, BodySections::V6) => unreachable!("BodySections::V6 exists only beside GenesisForm::V5 (forms.rs)"),
        (GenesisForm::V4, _) => body.commitment_at(block.header.height),
        (GenesisForm::V5, _) => body.commitment_v5_at(block.header.height),
        // Lab #708: the Annulet body commitment (B1). Genesis never passes this
        // funnel (it is bound at construction, over its genesis notes).
        (GenesisForm::Annulet, _) => qlab_devnet::annulet::body_commitment_annulet(&body),
    };
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
    /// The genesis-format-keyed consensus form set this node runs (lab #470
    /// stage 4a). Defaults to v4 so every stub keeps today's forms; the real
    /// node overrides it from its installed form — the assembler reads this,
    /// so a v5 node's templates mint the exact schedule and derive v5 leaves.
    fn genesis_form(&self) -> GenesisForm {
        GenesisForm::V4
    }
    /// The L2 fee table (lab #708) — `Some` exactly on an Annulet node; the
    /// mempool's Annulet arm prices admission with it.
    fn annulet_fee_table(&self) -> Option<qlab_devnet::annulet::L2FeeTable> {
        None
    }
    /// The registry root the next block's transactions must name (lab #712):
    /// the tip header's, `Some` exactly on an Annulet node.
    fn annulet_registry_root(&self) -> Option<Hash32> {
        None
    }
    /// The running outstanding public supply of `asset` (lab #712): Σ of
    /// every applied block's `vPublic` delta. 0 on L1 and for untouched
    /// assets.
    fn outstanding_supply(&self, _asset: u16) -> i128 {
        0
    }
    /// The root writing `leaf_lanes` into this node's registry reaches, or
    /// the registry's refusal (lab #728) — what the mempool checks a
    /// registry write against, so a write the block rule would refuse never
    /// pools. `None` on L1.
    fn annulet_registry_write_root(
        &self,
        _leaf_lanes: &[u64; 15],
    ) -> Option<Result<Hash32, crate::registry_store::RegistryError>> {
        None
    }
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

/// The installed bundle rule behind [`Node`]'s one-slot validated-outcome
/// cache (lab #785 F5-5b): `verify_bundle` for `key` returns the cached
/// outcome once and otherwise verifies and caches; folding and the stated
/// surface pass straight through.
struct CachedRule<'a> {
    inner: &'a dyn qlab_devnet::body::BundleVerifier,
    cache: &'a std::sync::Mutex<Option<(Hash32, Hash32, qlab_devnet::body::BundleOutcome)>>,
    key: (Hash32, Hash32),
}

impl qlab_devnet::body::BundleVerifier for CachedRule<'_> {
    fn verify_bundle(
        &self,
        header: &BlockHeader,
        bundle: &[u8],
        ctx: &qlab_devnet::body::BundleContext<'_>,
    ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
        // The lock is held only to read or write the slot, never across the
        // verification (F5-5b pre-review X7), and a poisoned lock is recovered
        // rather than propagated: the slot is a cache, so the worst a panic
        // mid-write leaves behind is a miss.
        let held = self.cache.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some((b, p, outcome)) = held {
            if (b, p) == self.key {
                return Ok(outcome);
            }
        }
        let outcome = self.inner.verify_bundle(header, bundle, ctx)?;
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((self.key.0, self.key.1, outcome.clone()));
        Ok(outcome)
    }
    fn fold_bundle(
        &self,
        surface: &[u8],
        bundle: &[u8],
    ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
        self.inner.fold_bundle(surface, bundle)
    }
    fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, qlab_devnet::body::BundleRefusal> {
        self.inner.bundle_surface(bundle)
    }
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
    /// The same anchor set indexed in the direction validation asks it:
    /// `commitment root → ascending heights at which that root existed`.
    ///
    /// Lab #402's settled-history gate used to scan up to the whole 1,152-block
    /// anchor window for every transaction in every replayed block. This derived
    /// index makes the membership query two tree/binary searches instead. It is
    /// rebuilt from `roots_by_height` on snapshot restore, so it changes neither
    /// snapshot bytes nor the consensus source of truth.
    anchor_heights_by_root: BTreeMap<Hash32, Vec<u64>>,
    /// Every appended commitment / spent nullifier, in application order — the
    /// deterministic material a snapshot serializes (a replay reproduces the
    /// exact order, so the on-disk form is stable).
    commitments_ordered: Vec<Hash32>,
    nullifiers_ordered: Vec<Hash32>,
    /// **Bodies this node still POSSESSES but has not applied** — the suffix undone
    /// by a rewind (issue #198). Bounded; see [`RetainedBodies`].
    retained: RetainedBodies,
    /// Directory backing the block log + snapshot; `None` = in-memory only.
    dir: Option<PathBuf>,
    /// Whether this process has cut a torn log tail yet (lab #804): done
    /// once, before the first append — [`Self::append_log`].
    log_tail_cut: bool,
    /// Recovery provenance for the startup banner. In-memory nodes carry the
    /// all-zero fresh report; disk-backed `open` replaces it before returning.
    recovery: RecoveryReport,
    /// The name registry (lab #367) — derived state, mutated only in
    /// `apply_state` (so rewinds rebuild it) and persisted as the `names.bin`
    /// sidecar (so snapshots restore it). See `crate::name_registry`.
    names: crate::name_registry::NameRegistry,
    /// The genesis form (lab #470 stage 4a): every block identity this node
    /// computes — replay, snapshot resume, retained bodies, the stored-binding
    /// check — is the header hash under this form. Set at construction
    /// (`open_for` / `in_memory_for`), BEFORE any record is replayed; there is
    /// no later setter (the install-before-run invariant, extended here).
    form: GenesisForm,
    /// The body-section axis (lab #785 F5-3b): [`BodySections::V6`] exactly on
    /// a V6 net (always beside [`GenesisForm::V5`]). Set at construction with
    /// `form`, before any record is replayed, and never re-keyed.
    sections: BodySections,
    /// Genesis committee₀ (lab #785 ruling Q1): the roster a V6 finality
    /// record's signatures are checked against. `Some` exactly on a V6 node;
    /// installed by [`MemNode::in_memory_v6`] / [`MemNode::open_v6`] before the
    /// first live block and carried across rewinds.
    committee0: Option<qlab_devnet::committee::Committee>,
    /// **Recorded finality** (lab #785 Q-L5): `block height → record height`
    /// for every applied main-chain block carrying a finality record. Derived
    /// state, folded in `apply_state` (so every replay and rewind rebuilds it)
    /// and re-derived from the held chain on the snapshot paths, which skip
    /// `apply_state` for the prefix. `CR(tip)` is its last value.
    recorded: BTreeMap<u64, u64>,
    /// The wrapper chain's rule and origin (lab #785 F5-4b) — `Some` on a V6
    /// node built with `WrapperParams`; installed with committee₀.
    wrapper: Option<qlab_devnet::body::WrapperSetup>,
    /// **The validated-outcome cache** (lab #785 F5-5b, plan item 7): one slot,
    /// `(block hash, parent hash) → BundleOutcome`, filled when the tip-path
    /// [`Node::validate_block_v6`] verifies a bundle and taken by the next
    /// verification of the same block on the same parent — the ingest check
    /// and `apply_block_gated`'s re-check — so a tip block's proofs verify once.
    /// Sound because the V6 funnel reads only the block's own ancestry: the
    /// same block on the same parent has the same verdict. Cleared on rewind;
    /// replay folds and never verifies, so it never reads this.
    bundle_cache: std::sync::Mutex<Option<(Hash32, Hash32, qlab_devnet::body::BundleOutcome)>>,
    /// The wrapper chain's surface after the applied tip, canonical bytes
    /// (opaque: only the rule decodes them). The genesis surface until the
    /// first bundle; empty on a node with no wrapper. Derived state, folded
    /// in `apply_state` and re-derived on the snapshot paths.
    surface: Vec<u8>,
    /// The height of the latest applied bundle-carrying block (spacing).
    last_bundle_height: Option<u64>,
    /// The L2 fee table (lab #708) — `Some` exactly on an Annulet node.
    annulet_fees: Option<qlab_devnet::annulet::L2FeeTable>,
    /// The asset registry (lab #710): `Some` exactly on an Annulet node,
    /// bound to every header's `registry_root`. Moved only by a block's
    /// registry write (shape R, lab #728), in `apply_state` — so it is chain
    /// state like the tree, rebuilt from the held main chain wherever a path
    /// skips `apply_state` ([`Self::recompute_annulet_state`]).
    registry: Option<crate::registry_store::MemRegistryStore>,
    /// The genesis registry (lab #728): what a rebuild from genesis starts
    /// from. `registry` is no longer it once a write has applied.
    registry_genesis: Option<crate::registry_store::MemRegistryStore>,
    /// The genesis notes' per-asset issuance (lab #728 Q7): the outstanding
    /// figure's starting point. Empty on L1.
    genesis_supply: BTreeMap<u16, i128>,
    /// The Annulet genesis notes' commitments (empty on L1), kept so a
    /// rebuild from genesis re-applies them.
    annulet_genesis_cms: Vec<Hash32>,
    /// The running per-asset outstanding public supply (lab #712): the
    /// genesis issuance (lab #728 Q7) plus Σ of every
    /// applied block's `annulet_supply_delta`. Chain state, **recomputed**
    /// (never persisted): folded in `apply_state` — which every replay and
    /// rewind runs — and rebuilt from the held main chain at `open_annulet`
    /// (the snapshot-prefix path skips `apply_state`). Never negative: a
    /// block that would take an asset below zero is refused by name.
    outstanding: BTreeMap<u16, i128>,
    /// Each applied block's non-empty supply delta, by height — recorded for
    /// D1's supply surface.
    supply_deltas: BTreeMap<u64, BTreeMap<u16, i128>>,
}

/// The outcome of [`MemNode::resume_from_snapshot`] — a node, or the reason this
/// snapshot could not be honoured against this log.
///
/// It replaces an `Option<MemNode>` (issue #225): the `None` carried no reason,
/// and the reason is the half of this fall-through an operator needs.
enum SnapshotResume {
    Resumed(MemNode),
    Rejected(SnapshotRejection),
}

impl MemNode {
    /// An in-memory node from a genesis block, with no disk durability.
    /// **v4 identities** — a v5 net starts via [`MemNode::in_memory_for`].
    pub fn in_memory(genesis: StoredBlock) -> Self {
        Self::from_genesis(GenesisForm::V4, BodySections::None, genesis, None)
    }

    /// [`MemNode::in_memory`] under an explicit genesis form (lab #470 4a).
    pub fn in_memory_for(form: GenesisForm, genesis: StoredBlock) -> Self {
        Self::from_genesis(form, BodySections::None, genesis, None)
    }

    /// An in-memory **V6** node (lab #785 F5-3b): `GenesisForm::V5` with the
    /// V6 body sections, record signatures checked against `committee0`.
    pub fn in_memory_v6(genesis: StoredBlock, v6: V6Setup) -> Self {
        let mut node = Self::from_genesis(GenesisForm::V5, BodySections::V6, genesis, None);
        node.install_v6(Some(v6));
        node
    }

    /// Open (or create) a disk-backed **V6** node — [`Self::open_for`]'s
    /// resume machinery unchanged, keyed `(V5, V6)` before any record is read.
    pub fn open_v6(
        dir: impl AsRef<Path>,
        genesis: StoredBlock,
        v6: V6Setup,
    ) -> Result<Self, NodeError> {
        // Installed before the log is read: replay folds bundles (F5-4b).
        Self::open_inner(GenesisForm::V5, BodySections::V6, dir.as_ref(), genesis, None, Some(v6))
    }

    /// Open (or create) a disk-backed node at `dir`, resuming restart-safely:
    /// load the atomic snapshot if present, then replay any block-log records
    /// past it. A missing/torn/version-mismatched snapshot falls back to a full
    /// genesis replay of the log. `genesis` must match the log's genesis.
    pub fn open(dir: impl AsRef<Path>, genesis: StoredBlock) -> Result<Self, NodeError> {
        Self::open_for(GenesisForm::V4, dir, genesis)
    }

    /// [`MemNode::open`] under an explicit genesis form (lab #470 stage 4a).
    /// The form arrives BEFORE the log is replayed — replay identities, the
    /// stored-binding form and the snapshot-resume walk all key off it.
    pub fn open_for(
        form: GenesisForm,
        dir: impl AsRef<Path>,
        genesis: StoredBlock,
    ) -> Result<Self, NodeError> {
        match form {
            GenesisForm::V4 | GenesisForm::V5 => Self::open_inner(form, BodySections::None, dir.as_ref(), genesis, None, None),
            // Lab #708: an Annulet genesis binds its notes and carries a fee
            // table, neither of which this signature has.
            GenesisForm::Annulet => Err(NodeError::FormNotServed { form, owner: "MemNode::open_annulet" }),
        }
    }

    /// **Open (or create) a disk-backed Annulet node** (lab #708): the
    /// genesis header must bind `genesis_notes` (checked here, before the log
    /// is read), and the fee table is the genesis's. Resume is
    /// [`Self::open_for`]'s machinery unchanged — snapshot, near-tip degrade,
    /// full replay — over the Annulet log record (`persist` variant 3).
    pub fn open_annulet(
        dir: impl AsRef<Path>,
        genesis_header: BlockHeader,
        genesis_notes: &[qlab_devnet::annulet::GenesisNote],
        fees: qlab_devnet::annulet::L2FeeTable,
        registry: &[crate::registry_store::RegistryLeaf],
    ) -> Result<Self, NodeError> {
        assert_eq!(
            genesis_header.tx_body_commitment,
            qlab_devnet::annulet::genesis_body_commitment_annulet(genesis_notes),
            "the Annulet genesis must bind its genesis notes (lab #706)"
        );
        let setup = AnnuletSetup::bound_to(&genesis_header, genesis_notes, fees, registry)?;
        let genesis = StoredBlock::annulet_genesis(&genesis_header);
        let dir = dir.as_ref();
        let node = Self::open_inner(GenesisForm::Annulet, BodySections::None, dir, genesis, Some(setup), None)?;
        // Lab #710, #728: the registry is chain state — every resume path
        // derives it from the log (replay through `apply_state`, a snapshot
        // through `recompute_annulet_state`). The sidecar is checked against
        // that derivation; one that disagrees, or cannot be read, is
        // replaced — said aloud, never trusted.
        match crate::registry_store::load_registry_at(dir) {
            Ok(Some((held, _))) if Some(&held) == node.registry.as_ref() => {}
            Ok(None) => {}
            Ok(Some((held, at))) => qlab_devnet::jprintln!(
                "REGISTRY sidecar at height {at} disagrees with the chain-derived registry (root {} vs {}); \
                 rewritten from the chain (lab #728)",
                hex8(&crate::registry_store::RegistryStore::root_bytes(&held)),
                hex8(&node.registry_root_bytes().unwrap_or_default())
            ),
            Err(e) => qlab_devnet::jprintln!("REGISTRY sidecar unusable ({e}); rewritten from the chain (lab #728)"),
        }
        if let Some(reg) = &node.registry {
            crate::registry_store::save_registry(dir, reg, node.chain.tip_height()).map_err(NodeError::Io)?;
        }
        Ok(node)
    }

    fn open_inner(
        form: GenesisForm,
        sections: BodySections,
        dir: &Path,
        genesis: StoredBlock,
        annulet: Option<AnnuletSetup>,
        v6: Option<V6Setup>,
    ) -> Result<Self, NodeError> {
        let dir = dir.to_path_buf();
        std::fs::create_dir_all(&dir).map_err(NodeError::Io)?;

        let records = persist::read_records(&dir).map_err(NodeError::Io)?;
        // Lab #708: every block record must be of this net's form — an L1
        // record on an Annulet net or the reverse is a foreign datadir,
        // refused by name before any record is hashed under the wrong form.
        for rec in &records {
            if let LogRecord::Block(b) = rec {
                let annulet_record = b.annulet.is_some();
                let ok = match form {
                    GenesisForm::V4 | GenesisForm::V5 => !annulet_record,
                    GenesisForm::Annulet => annulet_record,
                };
                if !ok {
                    return Err(NodeError::LogFormMismatch { form, height: b.header.height });
                }
            }
        }
        let genesis_block_hash = genesis.header().header_hash_for(form);
        // Lab #408: `Ok(None)`-style flattening is gone. A present-but-unusable
        // snapshot is a typed rejection that reaches the RECOVERY line exactly
        // like the #225 resume-time rejections below — a rejected snapshot is
        // an operator event, never a silent fallthrough to the genesis fold.
        let mut snapshot_rejected = None;
        let snapshot = match persist::load_snapshot(&dir).map_err(NodeError::Io)? {
            persist::SnapshotLoad::Absent => None,
            persist::SnapshotLoad::Rejected(reject) => {
                snapshot_rejected = Some(SnapshotRejection::NotLoadable { reject });
                None
            }
            persist::SnapshotLoad::Loaded(snap)
                if snap.genesis_block_hash != genesis_block_hash =>
            {
                snapshot_rejected = Some(SnapshotRejection::GenesisMismatch {
                    snapshot_genesis: snap.genesis_block_hash,
                    our_genesis: genesis_block_hash,
                });
                None
            }
            persist::SnapshotLoad::Loaded(snap) => Some(snap),
        };

        // Fast path: restore derived state (tree/nullifiers/roots) from the
        // snapshot, so log-prefix blocks only need to rebuild the chain store
        // (cheap header inserts), not re-fold the tree. Blocks past the snapshot,
        // and every finalization, are fully replayed — keeping the result
        // identical to a from-genesis `replay`.
        //
        // A snapshot that the log does not corroborate is a REJECTION, not an
        // error: the full replay below is always correct, and that fall-through is
        // the discipline `persist` already documents for a torn or
        // version-mismatched snapshot. Issue #162 gave it a second way to happen,
        // and issue #225 a third — see [`Self::resume_from_snapshot`]. The reason
        // is carried into the [`RecoveryReport`] rather than dropped.
        if let Some(snap) = snapshot.as_ref() {
            match Self::resume_from_snapshot(form, sections, &dir, &genesis, annulet.clone(), v6.clone(), snap, &records)? {
                SnapshotResume::Resumed(node) => return Ok(node),
                SnapshotResume::Rejected(why) => {
                    // Lab #408: before conceding the genesis fold, try the
                    // near-tip degrade — honour the rejected snapshot anyway
                    // when the log itself proves its tip is on the finalized
                    // main chain. Any failure inside the attempt falls back to
                    // the full replay, which stays the correctness anchor.
                    if let Some(node) = Self::resume_near_tip(form, sections, &dir, &genesis, annulet.clone(), v6.clone(), snap, &records, &why)
                    {
                        return Ok(node);
                    }
                    snapshot_rejected = Some(why);
                }
            }
        }
        Self::resume_by_replay(form, sections, &dir, genesis, annulet, v6, &records, snapshot_rejected)
    }

    /// The snapshot-assisted resume. `Rejected` = this snapshot cannot be
    /// honoured against this log and the caller must replay from genesis.
    ///
    /// # Which failures are a fall-through, and which are still a refusal
    ///
    /// **A fall-through is only ever "this SNAPSHOT cannot be honoured against
    /// this LOG".** Two things can say that, and both are recoverable because the
    /// log is the source of truth and the full replay does not consult the
    /// snapshot at all:
    ///
    /// - the reconstructed prefix does not end on `snap.tip` (issue #162), and
    /// - **a rewind refusal in either reconstruction loop** (issue #225). The
    ///   prefix loop rebuilds only records at or below `applied_height`, so a
    ///   rewind target that the *full* log holds can be missing here; and
    ///   `MemChainStore::rewind_to` drops the losing sibling, so a block logged
    ///   above `applied_height` whose parent lost fork choice asks to rewind onto
    ///   a block the prefix no longer stores. Neither says anything about the log.
    ///
    /// **Everything else still refuses, loudly**: a tampered or corrupt record
    /// ([`check_stored_binding`], and every [`Self::apply_state`] failure inside
    /// [`Self::apply_logged_block`]), a chain-store insert refusal, and the two
    /// snapshot-finality refusals. Those are properties of the datadir, not of
    /// the snapshot, so a full replay would refuse them too — swallowing them
    /// here would trade a loud refusal for a silent one.
    ///
    /// **The fall-through cannot hide a genuinely broken log**, and that is the
    /// argument for drawing the line at the rewind rather than at some narrower
    /// subset of [`RewindError`]: whatever the log really is, the from-genesis
    /// replay is what decides, and if the log is the problem the replay refuses
    /// with its own reason.
    fn resume_from_snapshot(
        form: GenesisForm,
        sections: BodySections,
        dir: &Path,
        genesis: &StoredBlock,
        annulet: Option<AnnuletSetup>,
        v6: Option<V6Setup>,
        snap: &Snapshot,
        records: &[LogRecord],
    ) -> Result<SnapshotResume, NodeError> {
        let mut node = Self::from_genesis_with(form, sections, genesis.clone(), Some(dir.to_path_buf()), annulet);
        node.install_v6(v6);
        node.restore_from_snapshot(snap);
        // Lab #367: the registry sidecar rides the snapshot. Any problem with
        // a PRESENT sidecar is a fall-through to the full replay (which
        // rebuilds the registry from the log and consults no sidecar);
        // absence is the exact empty registry (see the variant's doc).
        match crate::name_registry::load_names_at(dir) {
            Ok(None) => {}
            Ok(Some((names, at_height))) => {
                if at_height != snap.applied_height {
                    return Ok(SnapshotResume::Rejected(
                        SnapshotRejection::NamesSidecarDisagreement {
                            reason: format!(
                                "sidecar applied_height {at_height} != snapshot applied_height {}",
                                snap.applied_height
                            ),
                        },
                    ));
                }
                node.names = names;
            }
            Err(e) => {
                return Ok(SnapshotResume::Rejected(
                    SnapshotRejection::NamesSidecarDisagreement { reason: e.to_string() },
                ));
            }
        }

        // First reconstruct the snapshot prefix's block store. Finality is
        // restored only after every prefix block exists, so the persisted
        // `(hash, height)` can be proved against the actual main chain.
        for rec in records {
            if let LogRecord::Block(b) = rec {
                if b.header.height <= snap.applied_height {
                    // Derived state already restored — just rebuild the chain
                    // store. The binding is still checked (issue #77): this
                    // path skips `apply_state`, so it would otherwise be the
                    // one way a corrupted log record enters unchecked. It stays
                    // FIRST: a tampered record is refused outright, and must not
                    // be mistaken for the rewind below.
                    check_stored_binding_for(node.form, node.sections, b)?;
                    // Issue #162: the log is append-only but the applied chain is
                    // no longer append-only, so a prefix record whose parent is not
                    // the running tip is the live node's rewind, replayed here at
                    // the chain-store layer only (derived state came from the
                    // snapshot). See [`Self::apply_logged_block`] for the rule.
                    if b.header.height > 0 && b.header.prev != node.chain.tip_hash() {
                        // Issue #198: the prefix rewind happens at the chain-store
                        // layer, which `Node::rewind_to`'s retention does not cover —
                        // so the suffix is archived here too. Without this, `open`
                        // and `replay` would resume with different possession from
                        // the same log, and possession is what the serving path now
                        // keys on.
                        let mut cursor = node.chain.tip_hash();
                        while cursor != b.header.prev {
                            let Some(undone) = node.chain.block(&cursor).cloned() else { break };
                            cursor = undone.header.prev;
                            node.retained.insert(undone);
                        }
                        // Issue #225: a refusal here is "this snapshot cannot be
                        // honoured against this log", not "this log is broken" —
                        // the prefix loop has only the records at or below
                        // `applied_height`, so a target the whole log holds can be
                        // absent from it. Fall through to the full replay, which
                        // has every record and is always correct.
                        if let Err(error) = node.chain.rewind_to(b.header.prev) {
                            return Ok(SnapshotResume::Rejected(
                                SnapshotRejection::RewindRefused {
                                    applied_height: snap.applied_height,
                                    at_height: b.header.height,
                                    target: b.header.prev,
                                    error,
                                    above_snapshot: false,
                                },
                            ));
                        }
                    }
                    node.chain.put_block(b.clone()).map_err(NodeError::Chain)?;
                    node.retained.forget(&b.header().header_hash_for(node.form));
                }
            }
        }

        node.retained.prune_below(node.chain.tip_height());

        // **The snapshot has to describe the state this log actually reaches.**
        // Before issue #162 that held by construction: the log was append-only and
        // so was the applied chain, so reconstructing every record at or below
        // `applied_height` could only land on `snap.tip`. A rewind breaks the
        // second half of that — a snapshot taken at height H on the branch that
        // subsequently lost carries derived state for a tip the log no longer ends
        // that prefix on. Its tree and nullifier set are for the wrong branch, and
        // nothing downstream would notice. So the agreement is checked rather than
        // assumed, and a disagreement costs a full replay instead of a fork.
        if node.chain.tip_hash() != snap.tip {
            return Ok(SnapshotResume::Rejected(SnapshotRejection::TipDisagreement {
                applied_height: snap.applied_height,
                snapshot_tip: snap.tip,
                prefix_tip: node.chain.tip_hash(),
            }));
        }

        if let Some((hash, height)) = snap.finalized {
            node.chain
                .restore_finalized(hash, height)
                .map_err(NodeError::SnapshotFinality)?;
            if !records
                .iter()
                .any(|rec| matches!(rec, LogRecord::Finalize(logged) if *logged == hash))
            {
                return Err(NodeError::SnapshotFinalityNotLogged { hash, height });
            }
        }

        // Replay only state beyond the snapshot. Every finalization record is
        // offered to the live advance rule: prefix records are harmlessly
        // rejected as non-advancing, while a finalization written after the
        // snapshot still advances even when it names a prefix block.
        //
        // Lab #287: progress tracks the expensive work — block records above the
        // snapshot. That count is a free pre-scan of the already-loaded vec (not
        // a second disk read, not a 2× apply). Prefix no-ops and non-advancing
        // finalizations are not the silent-hang hazard; a tip-aligned restart
        // (replayed 0) stays quiet. Finalizations that *do* advance are counted
        // in the final RECOVERY line but are not a separate progress total —
        // fabricating a finalize-advance denominator would require replaying
        // them, which is the stop-point this baton refuses.
        let tail_blocks = records
            .iter()
            .filter(|r| matches!(r, LogRecord::Block(b) if b.header.height > snap.applied_height))
            .count();
        // Lab #712, #728: the prefix went in by `put_block` alone, so the
        // Annulet chain state the tail's `apply_state` reads is re-derived
        // here, before the first tail block needs it.
        node.recompute_annulet_state()?;
        node.recompute_recorded()?;
        node.recompute_wrapper()?;
        let mut progress = ReplayProgress::start(
            tail_blocks,
            &format!("past snapshot at height {}", snap.applied_height),
        );
        let mut replayed_records = 0usize;
        for rec in records {
            match rec {
                LogRecord::Block(b) if b.header.height <= snap.applied_height => {}
                LogRecord::Block(b) => {
                    if let Err(e) = node.apply_logged_block(b) {
                        // Issue #225 — THE line this issue is about, and the
                        // boundary it draws. A rewind refusal means the prefix
                        // reconstruction dropped a block the full log still holds
                        // (fork choice moved the applied tip back onto a
                        // same-height sibling, so the orphan's parent left the
                        // store); anything else — a tampered body, a chain-store
                        // refusal, IO — is a property of the datadir that the
                        // full replay would hit too, so it is re-raised.
                        let NodeError::Rewind(error) = e else { return Err(e) };
                        return Ok(SnapshotResume::Rejected(SnapshotRejection::RewindRefused {
                            applied_height: snap.applied_height,
                            at_height: b.header.height,
                            target: b.header.prev,
                            error,
                            above_snapshot: true,
                        }));
                    }
                    replayed_records += 1;
                    progress.tick();
                }
                LogRecord::Finalize(hash) => {
                    if node.chain.set_finalized(*hash).is_ok() {
                        replayed_records += 1;
                    }
                }
            }
        }
        node.recovery = RecoveryReport {
            snapshot_height: Some(snap.applied_height),
            replayed_records,
            resumed_tip: node.chain.tip_height(),
            snapshot_rejected: None,
        };
        Ok(SnapshotResume::Resumed(node))
    }

    /// **The lab #408 near-tip degrade**: honour a REJECTED snapshot anyway,
    /// when the log itself proves the snapshot's tip is the finalized main
    /// chain's block at its height — so the rejection costs a tail replay, not
    /// a from-genesis fold (~8 min on the live fleet post-#386, hours before).
    ///
    /// # Why a rejected snapshot can ever be trusted
    ///
    /// The #225 rejections are statements about the *reconstruction*, not
    /// necessarily about the snapshot: the prefix loop sees only records at or
    /// below `applied_height`, so an orphan the tail's fork choice later
    /// abandoned can make an honest snapshot unreconstructable from the prefix
    /// alone (`RewindRefused`), and a prefix that ends on a losing sibling
    /// makes an honest snapshot look tip-disagreeing. What separates "honest
    /// but unreconstructable" from "state of a branch this log abandoned" is
    /// **finality**: if the log's own finalizations prove `snap.tip` is the
    /// main-chain block at `applied_height`, then the canonical state at that
    /// height is unique, deterministic, and exactly what the live node held
    /// when it wrote the snapshot — the same trust an honoured snapshot gets.
    /// A snapshot whose tip finality does NOT corroborate keeps today's full
    /// replay: for a genuinely lost branch the fold is not waste, it is the
    /// only correct answer.
    ///
    /// # The failure discipline
    ///
    /// `None` = "this attempt buys nothing safe" and the caller proceeds to
    /// [`Self::resume_by_replay`] with the original rejection — including on
    /// internal errors, because whatever the log's real problem is, the full
    /// replay either survives it or refuses with its own, better reason. This
    /// path can therefore never turn a loud refusal into a silent success: it
    /// only ever *succeeds* on state identical to what the replay reaches
    /// (open == replay stays the acceptance anchor, test-locked), or steps
    /// aside entirely.
    ///
    /// [`SnapshotRejection::NamesSidecarDisagreement`] is excluded by
    /// construction: the registry at `applied_height` is derived state this
    /// path cannot re-derive without the very fold it exists to skip.
    #[allow(clippy::too_many_arguments)]
    fn resume_near_tip(
        form: GenesisForm,
        sections: BodySections,
        dir: &Path,
        genesis: &StoredBlock,
        annulet: Option<AnnuletSetup>,
        v6: Option<V6Setup>,
        snap: &Snapshot,
        records: &[LogRecord],
        why: &SnapshotRejection,
    ) -> Option<Self> {
        match why {
            SnapshotRejection::TipDisagreement { .. } | SnapshotRejection::RewindRefused { .. } => {}
            _ => return None,
        }
        // A height-0 snapshot IS the genesis state; the "degrade" would be the
        // full replay wearing a different name.
        if snap.applied_height == 0 {
            return None;
        }

        // (1) Prove `snap.tip` is the finalized main chain's block at
        // `applied_height`, from headers and finalizations alone — no state
        // fold. Finalizations are monotone along one chain (no-reorg-past-
        // finality, enforced at every live `set_finalized`), so the LAST
        // logged finalization's ancestry at `applied_height` is the proof.
        let mut by_hash: HashMap<Hash32, &StoredBlock> = HashMap::new();
        for rec in records {
            if let LogRecord::Block(b) = rec {
                by_hash.insert(b.header().header_hash_for(form), b);
            }
        }
        let fin_hash = records.iter().rev().find_map(|rec| match rec {
            LogRecord::Finalize(h) if by_hash.contains_key(h) => Some(*h),
            _ => None,
        })?;
        if by_hash[&fin_hash].header.height < snap.applied_height {
            return None; // finality never reached the snapshot's height: no proof
        }
        let mut cursor = fin_hash;
        while by_hash.get(&cursor)?.header.height > snap.applied_height {
            cursor = by_hash[&cursor].header.prev;
        }
        if cursor != snap.tip || by_hash[&cursor].header.height != snap.applied_height {
            return None; // the finalized main chain passes through a different block here
        }

        // (2) Derived state from the snapshot; the registry sidecar under the
        // same rule the honoured path applies (absent = pre-#367 = empty).
        let mut node = Self::from_genesis_with(form, sections, genesis.clone(), Some(dir.to_path_buf()), annulet);
        node.install_v6(v6);
        node.restore_from_snapshot(snap);
        match crate::name_registry::load_names_at(dir) {
            Ok(None) => {}
            Ok(Some((names, at_height))) if at_height == snap.applied_height => node.names = names,
            _ => return None,
        }

        // (3) The chain store, rebuilt along the proven ancestor path only —
        // cheap `put_block` inserts in ascending order, no rewind inference
        // needed because the path is linear by construction.
        let genesis_block_hash = genesis.header().header_hash_for(node.form);
        let mut path: Vec<&StoredBlock> = Vec::with_capacity(snap.applied_height as usize);
        let mut cursor = snap.tip;
        while cursor != genesis_block_hash {
            // The cap is defensive: heights strictly descend on an honest
            // chain, so a longer walk means a malformed log — the replay's
            // problem to refuse, not this path's to interpret.
            if path.len() > snap.applied_height as usize {
                return None;
            }
            let block = by_hash.get(&cursor)?;
            path.push(block);
            cursor = block.header.prev;
        }
        path.reverse();
        for block in path {
            // The binding is still checked (issue #77): this path skips
            // `apply_state`, so it would otherwise be the one door a corrupted
            // log record enters by.
            if let Err(e) = check_stored_binding_for(node.form, node.sections, block) {
                // Named here (F5-5c pre-review Y6): the fall-through to a full
                // replay would otherwise hide the cause until it refuses.
                qlab_devnet::jprintln!("SNAPSHOT resume: block {} does not bind ({e}); falling back", block.header.height);
                return None;
            }
            node.chain.put_block((*block).clone()).ok()?;
        }
        if node.chain.tip_hash() != snap.tip {
            return None;
        }

        // (4) The snapshot's own finalized head, under the honoured path's
        // exact discipline: provable against the store, and present in the
        // log. A snapshot that fails either check steps aside — the replay
        // decides what the datadir really is.
        if let Some((hash, height)) = snap.finalized {
            node.chain.restore_finalized(hash, height).ok()?;
            if !records
                .iter()
                .any(|rec| matches!(rec, LogRecord::Finalize(logged) if *logged == hash))
            {
                return None;
            }
        }

        // (5) The tail — the beyond-the-snapshot loop, with one new rule: a
        // tail block whose rewind is refused forks below a point finality has
        // sealed (its parent is not in the applied store, and the applied
        // store holds the finalized chain through `snap.tip`), so it can never
        // re-enter the applied chain. It is retained as a body — exactly what
        // the full replay ends up doing with it (applied, undone by the
        // winner's rewind, retained) — and skipped as state.
        let tail_blocks = records
            .iter()
            .filter(|r| matches!(r, LogRecord::Block(b) if b.header.height > snap.applied_height))
            .count();
        // Lab #712, #728: as on the honoured path — the prefix skipped
        // `apply_state`, so the Annulet chain state is re-derived first.
        node.recompute_annulet_state().ok()?;
        node.recompute_recorded().ok()?;
        node.recompute_wrapper().ok()?;
        let mut progress = ReplayProgress::start(
            tail_blocks,
            &format!("near-tip catch-up past rejected snapshot at height {}", snap.applied_height),
        );
        let mut replayed_records = 0usize;
        for rec in records {
            match rec {
                LogRecord::Block(b) if b.header.height <= snap.applied_height => {
                    // Prefix blocks off the proven path were applied and later
                    // undone by the live node — retained-body parity with the
                    // full replay (issue #198).
                    if !node.chain.contains(&b.header().header_hash()) {
                        node.retained.insert(b.clone());
                    }
                }
                LogRecord::Block(b) => {
                    match node.apply_logged_block(b) {
                        Ok(()) => replayed_records += 1,
                        Err(NodeError::Rewind(_)) => node.retained.insert(b.clone()),
                        Err(_) => return None,
                    }
                    progress.tick();
                }
                LogRecord::Finalize(hash) => {
                    if node.chain.set_finalized(*hash).is_ok() {
                        replayed_records += 1;
                    }
                }
            }
        }

        node.retained.prune_below(node.chain.tip_height());
        node.recovery = RecoveryReport {
            snapshot_height: Some(snap.applied_height),
            replayed_records,
            resumed_tip: node.chain.tip_height(),
            snapshot_rejected: Some(why.clone()),
        };
        Some(node)
    }

    /// The from-genesis resume: every record replayed, no snapshot consulted.
    ///
    /// `snapshot_rejected` is carried in rather than recomputed: by the time this
    /// runs the snapshot has already been discarded, and "there was no snapshot"
    /// and "the snapshot was unusable" are different things to tell an operator.
    fn resume_by_replay(
        form: GenesisForm,
        sections: BodySections,
        dir: &Path,
        genesis: StoredBlock,
        annulet: Option<AnnuletSetup>,
        v6: Option<V6Setup>,
        records: &[LogRecord],
        snapshot_rejected: Option<SnapshotRejection>,
    ) -> Result<Self, NodeError> {
        let mut node = Self::from_genesis_with(form, sections, genesis, Some(dir.to_path_buf()), annulet);
        node.install_v6(v6);
        // Lab #287: every record is applied, so walk total == final replayed_records.
        // `records` is already in memory from `open`; the total is free.
        let mut progress = ReplayProgress::start(records.len(), "from genesis");
        let mut replayed_records = 0usize;
        for rec in records {
            match rec {
                LogRecord::Block(b) => {
                    node.apply_logged_block(b)?;
                }
                LogRecord::Finalize(hash) => {
                    let _ = node.chain.set_finalized(*hash);
                }
            }
            replayed_records += 1;
            progress.tick();
        }
        node.recovery = RecoveryReport {
            snapshot_height: None,
            replayed_records,
            resumed_tip: node.chain.tip_height(),
            snapshot_rejected,
        };
        Ok(node)
    }

    /// Rebuild the node purely from the log at `dir`, ignoring any snapshot — the
    /// from-scratch correctness anchor `open` is checked against. Applies every
    /// block and replays every finalization.
    pub fn replay(dir: impl AsRef<Path>, genesis: StoredBlock) -> Result<Self, NodeError> {
        Self::replay_for(GenesisForm::V4, dir, genesis)
    }

    /// [`MemNode::replay`] under an explicit genesis form (lab #470 4a).
    pub fn replay_for(
        form: GenesisForm,
        dir: impl AsRef<Path>,
        genesis: StoredBlock,
    ) -> Result<Self, NodeError> {
        let dir = dir.as_ref().to_path_buf();
        let mut node = Self::from_genesis(form, BodySections::None, genesis, Some(dir.clone()));
        for rec in persist::read_records(&dir).map_err(NodeError::Io)? {
            match rec {
                LogRecord::Block(b) => {
                    node.apply_logged_block(&b)?;
                }
                LogRecord::Finalize(h) => {
                    let _ = node.chain.set_finalized(h);
                }
            }
        }
        Ok(node)
    }

    /// Apply one block read back from the durable log, **following the same
    /// rewind the live node performed** (issue #162).
    ///
    /// The block log is append-only and stays that way — no new record type, no
    /// format bump, no rewrite. What changed is that the *applied chain* is no
    /// longer append-only, and the log already carries that faithfully: a record
    /// is written by [`Node::apply_block`], which applies at the tip only, so in
    /// log order every block's `prev` **is** the tip at the moment it was applied.
    /// A record whose `prev` is not the running tip therefore says exactly one
    /// thing — the live node rewound to `prev` before applying it — and replaying
    /// that inference reproduces the live sequence exactly.
    ///
    /// Inferring it beats recording it. A `LogRecord::Rewind` would have to be read
    /// by binaries that predate it, and a datadir written after this change could
    /// not be opened by one that came before; the inference costs one hash
    /// comparison per record and leaves every existing `blocks.log` byte-identical
    /// in meaning. It is also self-checking: `rewind_to` refuses a `prev` that is
    /// not an ancestor of the replayed tip, so a log that does *not* describe a
    /// rewind cannot be silently reinterpreted as one.
    fn apply_logged_block(&mut self, block: &StoredBlock) -> Result<(), NodeError> {
        if block.header.height > 0 && block.header.prev != self.chain.tip_hash() {
            self.rewind_to(block.header.prev)?;
        }
        let hash = self.apply_state(block)?;
        match self.form {
            GenesisForm::V4 | GenesisForm::V5 => {}
            // Lab #708 Q4: final on acceptance, derived at replay too, so a
            // crash between the block record and its `Finalize` record cannot
            // leave a replayed Annulet node with finality behind its tip.
            GenesisForm::Annulet => {
                self.chain.set_finalized(hash).map_err(NodeError::AnnuletFinality)?;
            }
        }
        Ok(())
    }

    /// **Rewind the applied state to `target`, an ancestor of the applied tip**
    /// (issue #162) — the operation whose absence made a state machine on a losing
    /// sibling absorbing.
    ///
    /// `apply_block` extends the tip and only the tip. Before this existed, a state
    /// machine that had applied a block which then lost fork choice had no move: the
    /// winning sibling did not extend its tip, no descendant of the winner ever
    /// would, and the node reported `mready=synced` while applying nothing, forever
    /// (measured on the 2026-07-31 T0 net at the full block rate for eleven hours).
    ///
    /// **What it does not do.** This is not fork choice and it is not a reorg
    /// primitive. It only *undoes*: it takes the state machine back to a block it
    /// has already applied, and re-application forward is the caller's, through the
    /// unchanged `apply_block` funnel. Nothing here decides which branch is right —
    /// `ChainState`'s heaviest-chain rule already did, and this is the state machine
    /// catching up with that answer.
    ///
    /// **Three refusals, and the state is untouched on every one of them**
    /// ([`RewindError`]): an unknown target, a target that is not an ancestor of the
    /// applied tip, and — the load-bearing one — a target that would cross the
    /// finalized head. The finality refusal is why `qlab_devnet::finality` and
    /// [`crate::recovery`] are untouched by this change: the no-reorg-past-finality
    /// rule is enforced at the new door, in front of the drop, rather than being
    /// repaired after the fact by the machinery that owns it.
    ///
    /// **Rebuilt, not un-applied.** The retained ancestor path is re-folded from
    /// genesis through `apply_state` — the same single funnel `replay` uses — so the
    /// rewound state is by construction the state a from-genesis replay of the
    /// retained chain produces, which is this crate's standing correctness anchor.
    /// Un-applying the suffix in place would mean a second, inverse transition
    /// function to keep in step with the forward one; the tree, the nullifier set,
    /// the anchor index and the derived coinbase-maturity leaf would each need their
    /// own undo, and only one of those four is a plain truncation. The cost is
    /// `O(retained height)` per rewind, paid on a rare event (fork choice moving off
    /// a branch this node had applied), against an in-memory re-fold with no proof
    /// verification and no disk write — see the PR body for the measured figure.
    ///
    /// **Nothing is written.** The log already holds every retained block; the
    /// abandoned blocks stay in it too, and [`Self::apply_logged_block`] is what
    /// makes replay reach the same place.
    ///
    /// **The undone suffix is RETAINED, not discarded** (issue #198). Before this,
    /// the rebuild dropped the suffix's bodies along with its state, which made the
    /// node unable to serve a block whose bytes it had written to `blocks.log`
    /// minutes earlier — see [`RetainedBodies`] and [`Self::held_block`]. The
    /// retention changes nothing about *state*: the applied chain after a rewind is
    /// byte-identical to what it was, and every consumer of "have I applied this"
    /// still reads the applied store.
    pub fn rewind_to(&mut self, target: Hash32) -> Result<RewindReport, NodeError> {
        // F5-5b: a verdict cached at the old tip is not one at the new tip.
        *self.bundle_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let from_height = self.chain.tip_height();
        let from_hash = self.chain.tip_hash();
        if from_hash == target {
            return Ok(RewindReport { from_height, from_hash, to_height: from_height, to_hash: target });
        }
        let kept = self.chain.rewind_path(&target).map_err(NodeError::Rewind)?;
        let finalized = self.chain.finalized_hash().zip(self.chain.finalized_height());

        // The suffix about to be undone, walked off the LIVE store before anything
        // is replaced. `rewind_path` has already proved `target` is an ancestor of
        // the applied tip, so this terminates at `target`.
        let mut undone: Vec<StoredBlock> = Vec::new();
        let mut cursor = from_hash;
        while cursor != target {
            let Some(block) = self.chain.block(&cursor) else { break };
            let prev = block.header.prev;
            undone.push(block.clone());
            cursor = prev;
        }

        // Built beside the live state and swapped in only on success, so a failure
        // anywhere in the re-fold leaves the node exactly as it was.
        let mut rebuilt = Self::from_genesis_with(self.form, self.sections, kept[0].clone(), self.dir.clone(), self.annulet_setup());
        rebuilt.install_v6(self.v6_setup());
        for block in &kept[1..] {
            rebuilt.apply_state(block)?;
        }
        if let Some((hash, height)) = finalized {
            rebuilt
                .chain
                .restore_finalized(hash, height)
                .expect("rewind_path proved the retained tip descends from the finalized head");
        }
        rebuilt.recovery = self.recovery.clone();
        // Possession carries across the swap: what this node already held plus what
        // it is about to stop having applied.
        rebuilt.retained = std::mem::take(&mut self.retained);
        for block in undone {
            rebuilt.retained.insert(block);
        }
        // An archived block that the re-fold put back into the applied chain needs
        // no second copy. (`apply_state` already forgets on the live node, so this
        // is belt-and-braces rather than the load-bearing path.)
        for block in &kept[1..] {
            rebuilt.retained.forget(&block.header().header_hash_for(rebuilt.form));
        }
        rebuilt.retained.prune_below(rebuilt.chain.tip_height());
        let report = RewindReport {
            from_height,
            from_hash,
            to_height: rebuilt.chain.tip_height(),
            to_hash: rebuilt.chain.tip_hash(),
        };
        *self = rebuilt;
        Ok(report)
    }

    fn from_genesis(form: GenesisForm, sections: BodySections, genesis: StoredBlock, dir: Option<PathBuf>) -> Self {
        assert_eq!(genesis.header.height, 0, "genesis height must be 0");
        // Issue #115: genesis is bound to its body like every other block, and
        // this is the one seam a genesis enters by without passing
        // `check_stored_binding` (it is put straight into the chain store).
        // Panicking matches the height assertion above — the genesis block is
        // locally built or operator-supplied, never network input.
        let expected_binding = match (form, sections) {
            (GenesisForm::V5, BodySections::V6) => genesis.body().commitment_v6(),
            (_, BodySections::V6) => panic!("BodySections::V6 exists only beside GenesisForm::V5"),
            (GenesisForm::V4, _) => genesis.body().commitment(),
            (GenesisForm::V5, _) => genesis.body().commitment_v5(),
            // Locally-built input, same class as the height assertion above:
            // an Annulet genesis binds its genesis notes, which this signature
            // does not carry.
            (GenesisForm::Annulet, _) => panic!(
                "an Annulet genesis is opened with MemNode::in_memory_annulet (lab #708)"
            ),
        };
        assert_eq!(
            genesis.header.tx_body_commitment, expected_binding,
            "genesis must bind its own body (under the net's form)"
        );
        Self::from_bound_genesis(form, sections, genesis, dir)
    }

    /// [`Self::from_genesis`] for every internal (re)build: on Annulet the
    /// genesis binding was checked by the public constructor that first
    /// received it (`open_annulet` / `in_memory_annulet`, over its notes), the
    /// fee table is carried, and genesis is final on acceptance (Q4).
    fn from_genesis_with(
        form: GenesisForm,
        sections: BodySections,
        genesis: StoredBlock,
        dir: Option<PathBuf>,
        annulet: Option<AnnuletSetup>,
    ) -> Self {
        match (form, annulet) {
            (GenesisForm::V4 | GenesisForm::V5, None) => Self::from_genesis(form, sections, genesis, dir),
            (GenesisForm::Annulet, Some(setup)) => {
                let mut node = Self::from_bound_genesis(form, sections, genesis, dir);
                node.annulet_fees = Some(setup.fees);
                node.registry_genesis = Some(setup.registry.clone());
                node.registry = Some(setup.registry);
                // Lab #728 Q7: the genesis notes' issuance is outstanding from
                // height 0 — a redeem of genesis supply is not an underflow.
                node.outstanding = setup.genesis_supply.clone();
                node.genesis_supply = setup.genesis_supply;
                // Lab #710 (B1 P13): the genesis notes enter the commitment
                // tree at height 0, in genesis order, through the append every
                // block's outputs take — so the genesis anchor is the tree over
                // them and block 1 anchors on it. They spend nothing (no
                // nullifiers); their payloads are served by projection of the
                // genesis file on /v1/genesis/notes (lab #714).
                node.roots_by_height.clear();
                node.anchor_heights_by_root.clear();
                for cm in &setup.genesis_cms {
                    node.append_commitment(*cm);
                }
                node.record_root_at(0);
                node.annulet_genesis_cms = setup.genesis_cms;
                let g = node.chain.genesis_block_hash();
                node.chain.set_finalized(g).expect("genesis is final on acceptance (lab #708 Q4)");
                node
            }
            (GenesisForm::V4 | GenesisForm::V5 | GenesisForm::Annulet, _) => {
                panic!("a {form:?} node carries an L2 fee table iff it is an Annulet node (lab #708)")
            }
        }
    }

    /// [`Self::from_genesis`] after the genesis binding has been checked by
    /// the caller (the L1 arms above; the Annulet constructor over its notes).
    fn from_bound_genesis(form: GenesisForm, sections: BodySections, genesis: StoredBlock, dir: Option<PathBuf>) -> Self {
        let commitments = MemCommitmentStore::default();
        let chain = MemChainStore::new_for(form, genesis);
        let mut roots_by_height = BTreeMap::new();
        let mut anchor_heights_by_root = BTreeMap::new();
        // Genesis carries no outputs, so the tree is empty: record its root at
        // height 0 (the empty-tree root) as the base anchor entry.
        let genesis_root = commitments.root_bytes();
        roots_by_height.insert(0, genesis_root);
        anchor_heights_by_root.insert(genesis_root, vec![0]);
        Self {
            chain,
            nullifiers: MemNullifierStore::default(),
            commitments,
            roots_by_height,
            anchor_heights_by_root,
            commitments_ordered: Vec::new(),
            nullifiers_ordered: Vec::new(),
            retained: RetainedBodies { form, ..RetainedBodies::default() },
            dir,
            log_tail_cut: false,
            recovery: RecoveryReport::default(),
            names: crate::name_registry::NameRegistry::default(),
            form,
            sections,
            committee0: None,
            recorded: BTreeMap::new(),
            wrapper: None,
            bundle_cache: std::sync::Mutex::new(None),
            surface: Vec::new(),
            last_bundle_height: None,
            annulet_fees: None,
            registry: None,
            registry_genesis: None,
            genesis_supply: BTreeMap::new(),
            annulet_genesis_cms: Vec::new(),
            outstanding: BTreeMap::new(),
            supply_deltas: BTreeMap::new(),
        }
    }

    /// **An Annulet node** (lab #708), in memory: the genesis header must bind
    /// `genesis_notes` under B1's genesis body commitment (checked here, the
    /// constructor's panic class), the L2 fee table comes from the genesis
    /// params, and **genesis is final on acceptance** (Q4), so the genesis
    /// root is a valid anchor for block 1.
    ///
    /// The genesis notes are bound **and applied** to the commitment tree at
    /// height 0 (lab #710, B1 P13 — B3's). A data dir is B2b's (the
    /// Annulet log record); this constructor has none.
    pub fn in_memory_annulet(
        genesis_header: BlockHeader,
        genesis_notes: &[qlab_devnet::annulet::GenesisNote],
        fees: qlab_devnet::annulet::L2FeeTable,
        registry: &[crate::registry_store::RegistryLeaf],
    ) -> MemNode {
        assert_eq!(
            genesis_header.tx_body_commitment,
            qlab_devnet::annulet::genesis_body_commitment_annulet(genesis_notes),
            "the Annulet genesis must bind its genesis notes (lab #706)"
        );
        let setup = AnnuletSetup::bound_to(&genesis_header, genesis_notes, fees, registry)
            .unwrap_or_else(|e| panic!("the Annulet genesis must bind its registry (lab #710): {e}"));
        let genesis = StoredBlock::annulet_genesis(&genesis_header);
        MemNode::from_genesis_with(GenesisForm::Annulet, BodySections::None, genesis, None, Some(setup))
    }

    /// The genesis form this node's identities are keyed under (lab #470).
    pub fn form(&self) -> GenesisForm {
        self.form
    }

    /// Re-key a **fresh** node (genesis only, nothing applied, nothing
    /// retained, no datadir records) to `form` — the one legal moment is
    /// between construction and first use, mirroring
    /// `ChainState::rekey_genesis`. Anything else panics: replayed state
    /// cannot be re-keyed, it must be OPENED under its form (`open_for`).
    pub fn rekey_genesis(&mut self, form: GenesisForm) {
        if form == self.form {
            return;
        }
        assert!(
            self.chain.tip_height() == 0
                && self.retained.is_empty()
                && self.commitments_ordered.is_empty()
                && self.nullifiers_ordered.is_empty(),
            "rekey_genesis is only legal on a fresh node — open_for is the seam for replayed state"
        );
        let genesis = self
            .chain
            .block(&self.chain.genesis_block_hash())
            .expect("a fresh node holds its genesis")
            .clone();
        // The genesis header BINDS its body under the old form; a re-keyed net
        // needs it re-bound, so the standard empty-body genesis is REBUILT
        // under the new form from its two real inputs. A custom genesis (a
        // fixture with a hand-set commitment) cannot be re-bound blindly and
        // refuses instead.
        assert!(
            genesis.txs.is_empty() && genesis.coinbase == 0,
            "rekey_genesis only re-binds the standard empty-body genesis"
        );
        let rebuilt =
            genesis_block_for(form, genesis.header.difficulty, genesis.header.timestamp);
        let v6 = self.v6_setup();
        *self = Self::from_genesis(form, self.sections, rebuilt, self.dir.clone());
        self.install_v6(v6);
    }

    fn restore_from_snapshot(&mut self, snap: &Snapshot) {
        // Lab #710: an Annulet genesis has already appended its notes (the
        // node was built from genesis before the snapshot is laid over it),
        // and the snapshot's commitments begin with those same notes — the
        // genesis hash matched, and the header binds them. Append only what
        // follows; an L1 genesis holds none, so there it is every entry.
        let held = self.commitments_ordered.len();
        assert!(
            snap.commitments.starts_with(&self.commitments_ordered),
            "a snapshot of this genesis begins with the genesis commitments (lab #710)"
        );
        for cm in &snap.commitments[held..] {
            self.commitments.append(*cm);
        }
        self.commitments_ordered = snap.commitments.clone();
        for nf in &snap.nullifiers {
            self.nullifiers.insert(*nf);
        }
        self.nullifiers_ordered = snap.nullifiers.clone();
        self.roots_by_height = snap.roots_by_height.iter().copied().collect();
        self.anchor_heights_by_root.clear();
        for (&height, &root) in &self.roots_by_height {
            self.anchor_heights_by_root.entry(root).or_default().push(height);
        }
    }

    /// The checkpoint represented by the durable state-machine finalized head.
    ///
    /// The current devnet checkpoint root is the documented block-hash stand-in,
    /// so `(height, hash)` reconstructs the exact signed checkpoint identity. This
    /// does not finalize anything; the P2P adapter uses it only to restore its
    /// otherwise-ephemeral [`qlab_devnet::finality::FinalityTracker`].
    pub fn restored_checkpoint(&self) -> Option<Checkpoint> {
        self.chain
            .finalized_hash()
            .zip(self.chain.finalized_height())
            .map(|(hash, height)| Checkpoint::new(height, hash, hash))
    }
}

/// How [`Node::apply_block_gated`] evaluates the anchor-finality gate (lab #402).
///
/// The anchor rule has two inputs that are *temporal*: which roots were
/// finalized, and how old the anchor is. [`NodeState::is_valid_anchor`] reads
/// both from the node's **live** position (its own finalized head and applied
/// tip) — correct at the tip, and wrong for a block being replayed from settled
/// history, where the node's finality structurally lags its application (the
/// #402 joiner deadlock: block 4913's anchor was finalized when 4913 was mined,
/// and no syncing joiner can ever have it finalized *locally* before applying
/// 4913).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorGate {
    /// Today's rule, byte-identical: the anchor's height is at or below **this
    /// node's** finalized head and within [`MAX_ANCHOR_AGE_BLOCKS`] of **this
    /// node's** applied tip. The default — every live application, and the only
    /// gate `apply_block` itself ever uses.
    Live,
    /// The block is **settled history** and the anchor rule is evaluated as of
    /// the block's own height: the anchor root must be one this node's own
    /// replay computed for an ancestor height `h < H`, with `H − h ≤`
    /// [`MAX_ANCHOR_AGE_BLOCKS`] (see [`Node::is_valid_anchor_as_of`]).
    ///
    /// **Caller contract (security-load-bearing, lab #402):** pass this only
    /// for a block that is the main-chain block at its own height **at or
    /// below a quorum-verified finalized checkpoint** — i.e. an ancestor of a
    /// checkpoint whose vote set passed the unchanged
    /// `FinalityTracker::try_finalize`. That containment is what carries the
    /// "was finalized as of H" component of the rule: a block whose anchor had
    /// not been finalized when it was current would have been refused by every
    /// honest node then, and so cannot be an ancestor of an honestly finalized
    /// checkpoint. The structural components (the root is genuinely this
    /// chain's, the age window, `h < H`) are still enforced here, from state
    /// this node computed itself.
    SettledHistory,
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> Node<C, N, T> {
    /// Validate and apply a block at the tip, persisting it to the log if the
    /// node is disk-backed. Validation: it extends the tip; the body passes
    /// (anchor finalized-and-in-window, posted fee, no in-block double-spend, and
    /// every proof verifies via `verifier`); and no nullifier is already spent.
    /// On success the commitment tree and nullifier set advance and the block
    /// hash is returned.
    ///
    /// The anchor gate is [`AnchorGate::Live`] — this is the live-path entry
    /// point and its behaviour is unchanged by lab #402. A caller replaying
    /// settled history under a verified finalized checkpoint uses
    /// [`Self::apply_block_gated`].
    pub fn apply_block<V: TxVerifier>(
        &mut self,
        header: BlockHeader,
        body: BlockBody,
        verifier: &V,
    ) -> Result<Hash32, NodeError> {
        self.apply_block_gated(header, body, verifier, AnchorGate::Live)
    }

    /// [`Self::apply_block`], with the anchor-finality gate chosen by the caller
    /// (lab #402). Everything else — the tip-extension check, the full body
    /// validation including proofs, the state funnel, the log append — is
    /// identical for both gates; the *only* difference is which temporal view
    /// the anchor rule is evaluated against. See [`AnchorGate::SettledHistory`]
    /// for the caller contract.
    pub fn apply_block_gated<V: TxVerifier>(
        &mut self,
        header: BlockHeader,
        body: BlockBody,
        verifier: &V,
        gate: AnchorGate,
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
        //
        // Lab #785 F5-3b: on a V6 net the gate is not consulted at all. The V6
        // funnel reads only the block's own ancestry (`V6View`), so live
        // application and settled-history replay are the same function by
        // construction — the #402 split, and #786's race, do not exist here.
        if self.sections == BodySections::V6 {
            let _ = gate;
            self.validate_block_v6(&header, &body, verifier).map_err(NodeError::Body)?;
            let block = StoredBlock::from_parts(&header, &body);
            let hash = self.apply_state(&block)?;
            let rec = LogRecord::Block(block);
            let at = self.append_log(&rec)?;
            // Lab #785 F5-5c: the bundle is on disk now — the chain store's
            // copy (a clone of this ref) drops its resident bytes too.
            if let (Some(offset), Some(dir), LogRecord::Block(b)) = (at, &self.dir, &rec) {
                if let Some(r) = b.bundle_ref() {
                    r.spill_to_log(persist::log_path(dir), offset);
                }
            }
            return Ok(hash);
        }
        match gate {
            AnchorGate::Live => {
                let anchor_ok = |root: &Hash32| self.is_valid_anchor(root);
                // Lab #367: the registry is the NameView. While the boundary is
                // unset this is behaviourally identical to plain validate_body;
                // once armed, rider rules read real state with no plumbing left
                // to do. Lab #470 stage 4a: the funnel is selected by this
                // node's installed form — the registry-armed twin of the
                // adapter's relay-level selection.
                match self.form {
                    GenesisForm::V4 => {
                        validate_body_with_names(&header, &body, verifier, anchor_ok, &self.names)
                            .map_err(NodeError::Body)?
                    }
                    GenesisForm::V5 => qlab_devnet::body::validate_body_v5(
                        &header, &body, verifier, anchor_ok, &self.names,
                    )
                    .map_err(NodeError::Body)?,
                    // Lab #708: an Annulet block is applied only with its seal.
                    GenesisForm::Annulet => return Err(NodeError::UnsealedOnAnnulet),
                }
            }
            AnchorGate::SettledHistory => {
                let anchor_ok = |root: &Hash32| self.is_valid_anchor_as_of(root, header.height);
                match self.form {
                    GenesisForm::V4 => {
                        validate_body_with_names(&header, &body, verifier, anchor_ok, &self.names)
                            .map_err(NodeError::Body)?
                    }
                    GenesisForm::V5 => qlab_devnet::body::validate_body_v5(
                        &header, &body, verifier, anchor_ok, &self.names,
                    )
                    .map_err(NodeError::Body)?,
                    // Lab #708: an Annulet block is applied only with its seal.
                    GenesisForm::Annulet => return Err(NodeError::UnsealedOnAnnulet),
                }
            }
        }
        let block = StoredBlock::from_parts(&header, &body);
        let hash = self.apply_state(&block)?;
        self.append_log(&LogRecord::Block(block))?;
        Ok(hash)
    }

    /// The **V6 body verdict** for a block extending this node's applied tip
    /// (lab #785): the full `validate_body_v6` over the tip's ancestry. The
    /// relay path asks this before accepting a body at the tip; application
    /// asks it again inside [`Self::apply_block_gated`]. Only meaningful when
    /// `header.prev` is the tip — the view IS the tip's ancestry — so any
    /// other position panics: a verdict there would be read off the wrong
    /// ancestry.
    pub fn validate_block_v6<V: TxVerifier>(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
        verifier: &V,
    ) -> Result<(), BodyError> {
        assert_eq!(self.sections, BodySections::V6, "validate_block_v6 on a non-V6 node");
        assert_eq!(header.prev, self.chain.tip_hash(), "a V6 verdict is defined only at the tip");
        let view = V6View { node: self, block_height: header.height };
        // Condition (b): with no wrapper rule every bundle is refused.
        let inner: &dyn qlab_devnet::body::BundleVerifier = match &self.wrapper {
            Some(w) => &*w.rule,
            None => &qlab_devnet::body::RefuseAllBundles,
        };
        let cached = CachedRule {
            inner,
            cache: &self.bundle_cache,
            key: (header.header_hash_for(self.form), header.prev),
        };
        qlab_devnet::body::validate_body_v6(header, body, verifier, &view, &cached, &self.names)
    }

    /// **Verify a bundle as if carried by the next block on the applied tip**
    /// (lab #785 F5-5b — the producer's slot admission and its re-check at a
    /// new tip): the installed rule (never the cache), the tip's wrapper
    /// surface and last bundle height, spacing at `tip + 1`, and V7 under the
    /// tip's recorded finality — conservative, since the next block's own
    /// record can only widen it; the block that carries it is judged in full
    /// when applied. With no wrapper rule every bundle is refused.
    pub fn verify_bundle_at_tip(
        &self,
        bundle: &[u8],
    ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
        self.judge_bundle_at_tip(bundle, |rule, header, bundle, ctx| rule.verify_bundle(header, bundle, ctx))
    }

    /// [`Self::verify_bundle_at_tip`]'s re-check form (F5-5b pre-review X5):
    /// the same context, through [`qlab_devnet::body::BundleVerifier::recheck_bundle`]
    /// — for a bundle already verified at an earlier tip, only the checks a
    /// new tip can change.
    pub fn recheck_bundle_at_tip(&self, bundle: &[u8]) -> Result<(), qlab_devnet::body::BundleRefusal> {
        self.judge_bundle_at_tip(bundle, |rule, header, bundle, ctx| rule.recheck_bundle(header, bundle, ctx))
    }

    fn judge_bundle_at_tip<R>(
        &self,
        bundle: &[u8],
        judge: impl FnOnce(
            &dyn qlab_devnet::body::BundleVerifier,
            &BlockHeader,
            &[u8],
            &qlab_devnet::body::BundleContext<'_>,
        ) -> Result<R, qlab_devnet::body::BundleRefusal>,
    ) -> Result<R, qlab_devnet::body::BundleRefusal> {
        use qlab_devnet::body::V6ChainView as _;
        assert_eq!(self.sections, BodySections::V6, "verify_bundle_at_tip on a non-V6 node");
        let rule: &dyn qlab_devnet::body::BundleVerifier = match &self.wrapper {
            Some(w) => &*w.rule,
            None => &qlab_devnet::body::RefuseAllBundles,
        };
        let parent = self.chain.block(&self.chain.tip_hash()).expect("the tip is held").header();
        let header = BlockHeader::child_of_for(self.form, &parent, parent.timestamp, parent.difficulty, [0; 32]);
        let view = V6View { node: self, block_height: header.height };
        let recorded = view.recorded_finality();
        let anchor_ok =
            |root: &Hash32| qlab_devnet::body::v6_anchor_ok(view.root_heights(root), header.height, recorded);
        let ctx = qlab_devnet::body::BundleContext {
            surface: view.wrapper_surface(),
            last_bundle_height: view.last_bundle_height(),
            anchor_ok: &anchor_ok,
        };
        judge(rule, &header, bundle, &ctx)
    }

    /// Would `record` pass the V6 record rule in the **next** block on this
    /// node's applied tip (lab #785 ruling Q3)? The miner's self-check: a
    /// record that fails it is omitted, never included. Same view, same
    /// function the body rule runs, so the answer cannot drift from the rule.
    pub fn record_passes_at_tip(
        &self,
        record: &qlab_devnet::finality_record::FinalityRecord,
    ) -> Result<(), qlab_devnet::finality_record::RecordError> {
        use qlab_devnet::body::V6ChainView as _;
        assert_eq!(self.sections, BodySections::V6, "record_passes_at_tip on a non-V6 node");
        let view = V6View { node: self, block_height: self.chain.tip_height() + 1 };
        record.check(view.recorded_finality(), |h| view.ancestor_at(h), view.committee0())
    }

    /// Would a tx anchored at `root` pass V6's anchor rule in the next block
    /// on this node's applied tip, given that block's recorded finality
    /// `recorded` (its own record counted)? The assembler's filter — the
    /// mempool admits against local finality, which V6 anchors never read.
    pub fn v6_anchor_ok_at_tip(&self, root: &Hash32, recorded: Option<u64>) -> bool {
        let heights = self.anchor_heights_by_root.get(root).map_or(&[][..], Vec::as_slice);
        qlab_devnet::body::v6_anchor_ok(heights, self.chain.tip_height() + 1, recorded)
    }

    /// **Apply a sealed Annulet block** (lab #708): the seal was validated by
    /// the caller against the chain (`validate_sealed_header_annulet` — the
    /// adapter's ingest does it before this); here the block must extend the
    /// tip, the body passes B1's Annulet rule with this node's L2 fee table,
    /// the state funnel runs, and the block is **final on acceptance**.
    ///
    /// **Finality here is operator governance** (l2-architecture §6.10,
    /// §6.3's single sequencer), not BFT: with one signer and equivocation
    /// refused at ingest there is no competing branch, so there is nothing
    /// for a later finality to decide. Sequencer data withholding stays a
    /// liveness failure only; nothing here upgrades it to safety.
    pub fn apply_sealed_block<V: TxVerifier>(
        &mut self,
        sealed: &qlab_devnet::annulet::SealedHeader,
        body: BlockBody,
        verifier: &V,
    ) -> Result<Hash32, NodeError> {
        let fees = match (self.form, self.annulet_fees) {
            (GenesisForm::Annulet, Some(fees)) => fees,
            (GenesisForm::V4 | GenesisForm::V5 | GenesisForm::Annulet, _) => {
                return Err(NodeError::FormNotServed { form: self.form, owner: "an Annulet node (in_memory_annulet)" });
            }
        };
        let header = sealed.header;
        if header.prev != self.chain.tip_hash() {
            return Err(NodeError::NotExtendingTip { expected: self.chain.tip_hash(), got: header.prev });
        }
        self.check_registry_parent(&header, &body)?;
        let anchor_ok = |root: &Hash32| self.is_valid_anchor(root);
        qlab_devnet::annulet::validate_body_annulet(&header, &body, verifier, anchor_ok, &fees)
            .map_err(NodeError::Body)?;
        let block = StoredBlock::from_sealed_parts(sealed, &body);
        let hash = self.apply_state(&block)?;
        self.chain.set_finalized(hash).map_err(NodeError::AnnuletFinality)?;
        // The block (persist variant 3), then its finalization — the L1
        // `Finalize` record, so the snapshot's "finality was logged" check
        // and every resume path hold unchanged.
        self.append_log(&LogRecord::Block(block))?;
        self.append_log(&LogRecord::Finalize(hash))?;
        Ok(hash)
    }

    /// The L2 fee table an Annulet node applies (`None` on an L1 node).
    pub fn annulet_fee_table(&self) -> Option<qlab_devnet::annulet::L2FeeTable> {
        self.annulet_fees
    }

    /// The asset registry an Annulet node holds (lab #710; `None` on L1).
    pub fn registry(&self) -> Option<&crate::registry_store::MemRegistryStore> {
        self.registry.as_ref()
    }

    /// The registry root as header bytes (`None` on L1).
    pub fn registry_root_bytes(&self) -> Option<Hash32> {
        use crate::registry_store::RegistryStore as _;
        self.registry.as_ref().map(|r| r.root_bytes())
    }

    /// The running per-asset outstanding public supply (lab #712).
    pub fn outstanding_supplies(&self) -> &BTreeMap<u16, i128> {
        &self.outstanding
    }

    /// The non-empty per-block supply deltas, by height (lab #712; D1 serves).
    pub fn supply_deltas(&self) -> &BTreeMap<u64, BTreeMap<u16, i128>> {
        &self.supply_deltas
    }

    /// Rebuild the outstanding supply and the per-block deltas from the held
    /// main chain (lab #712) — the one pass that also covers a snapshot resume,
    /// whose prefix blocks never ran `apply_state`.
    fn recompute_supply(&mut self) {
        self.outstanding = self.genesis_supply.clone();
        self.supply_deltas.clear();
        // The main chain, walked back from the applied tip through `prev`.
        let mut cursor = self.chain.tip_hash();
        while let Some(block) = self.chain.block(&cursor) {
            let delta = qlab_devnet::annulet::annulet_supply_delta(&block.body());
            if !delta.is_empty() {
                for (&asset, &d) in &delta {
                    *self.outstanding.entry(asset).or_insert(0) += d;
                }
                self.supply_deltas.insert(block.header.height, delta);
            }
            if block.header.height == 0 {
                break;
            }
            cursor = block.header.prev;
        }
    }

    fn annulet_setup(&self) -> Option<AnnuletSetup> {
        Some(AnnuletSetup {
            fees: self.annulet_fees?,
            registry: self.registry_genesis.clone()?,
            genesis_cms: self.annulet_genesis_cms.clone(),
            genesis_supply: self.genesis_supply.clone(),
        })
    }

    /// Lab #710 Q6, #728: the registry binding a block is checked against
    /// before its proofs are — cheap, no tree rebuilt. A block that writes
    /// nothing carries this node's root; a block that writes proves its write
    /// against this node's root. What the write reaches is [`Self::registry_after`]'s.
    fn check_registry_parent(&self, header: &BlockHeader, body: &BlockBody) -> Result<(), NodeError> {
        use crate::registry_store::RegistryStore as _;
        let Some(store) = &self.registry else { return Ok(()) };
        let pre = store.root_bytes();
        match qlab_devnet::annulet::annulet_registry_write(body).map_err(NodeError::Body)? {
            None => {
                let got = annulet_registry_root(header);
                if got != pre {
                    return Err(NodeError::RegistryRootMismatch { height: header.height, header: got, store: pre });
                }
            }
            Some((_, old_root, _)) => {
                if old_root != pre {
                    return Err(NodeError::RegistryWriteNotOnParent { height: header.height, surface: old_root, store: pre });
                }
            }
        }
        Ok(())
    }

    /// **The registry after `block`** (lab #728), computed before any
    /// mutation: `None` when the block writes nothing. The write must be
    /// proven against this node's root before the block, writing its leaf
    /// must reach the root it declares, and the header must carry the root
    /// after the block — every one refused by name, state untouched.
    fn registry_after(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<Option<crate::registry_store::MemRegistryStore>, NodeError> {
        use crate::registry_store::RegistryStore as _;
        self.check_registry_parent(header, body)?;
        let Some(store) = &self.registry else { return Ok(None) };
        let Some((_, _, w)) = qlab_devnet::annulet::annulet_registry_write(body).map_err(NodeError::Body)? else {
            return Ok(None);
        };
        let height = header.height;
        let mut next = store.clone();
        next.apply_write(&w.leaf_lanes).map_err(|err| NodeError::RegistryWrite { height, err })?;
        let rebuilt = next.root_bytes();
        if rebuilt != w.new_root {
            return Err(NodeError::RegistryWriteRootMismatch { height, surface: w.new_root, rebuilt });
        }
        let got = annulet_registry_root(header);
        if got != rebuilt {
            return Err(NodeError::RegistryRootMismatch { height, header: got, store: rebuilt });
        }
        Ok(Some(next))
    }

    /// **Rebuild the Annulet chain state a path that skips `apply_state`
    /// leaves stale** (lab #712, #728) — a snapshot resume installs its prefix
    /// blocks with `put_block` alone. The registry is re-derived from the
    /// genesis registry through every held main-chain block's write, each
    /// header's root checked on the way; the outstanding supply from the
    /// genesis issuance through every block's delta. A no-op on L1.
    fn recompute_annulet_state(&mut self) -> Result<(), NodeError> {
        use crate::registry_store::RegistryStore as _;
        let Some(mut reg) = self.registry_genesis.clone() else { return Ok(()) };
        let mut path = Vec::new();
        let mut cursor = self.chain.tip_hash();
        while let Some(block) = self.chain.block(&cursor) {
            if block.header.height == 0 {
                break;
            }
            path.push(cursor);
            cursor = block.header.prev;
        }
        for hash in path.iter().rev() {
            let block = self.chain.block(hash).expect("walked above");
            let height = block.header.height;
            if let Some((_, _, w)) =
                qlab_devnet::annulet::annulet_registry_write(&block.body()).map_err(NodeError::Body)?
            {
                reg.apply_write(&w.leaf_lanes).map_err(|err| NodeError::RegistryWrite { height, err })?;
            }
            let got = annulet_registry_root(&block.header());
            if got != reg.root_bytes() {
                return Err(NodeError::RegistryRootMismatch { height, header: got, store: reg.root_bytes() });
            }
        }
        self.registry = Some(reg);
        self.recompute_supply();
        Ok(())
    }

    /// The finality-record height a block carries, or `None` (no record, or
    /// not a V6 net — where `check_stored_binding_for` has already refused a
    /// section).
    fn record_height_of(&self, block: &StoredBlock) -> Result<Option<u64>, NodeError> {
        let Some(sections) = &block.sections else { return Ok(None) };
        if sections.finality.is_empty() {
            return Ok(None);
        }
        qlab_devnet::finality_record::FinalityRecord::decode(&sections.finality)
            .map(|r| Some(r.cp.height))
            .map_err(|err| NodeError::Body(BodyError::FinalityRecord { err }))
    }

    /// Re-derive [`Self::recorded`] from the held main chain — the snapshot
    /// paths put the prefix in by `put_block` alone (the
    /// [`Self::recompute_annulet_state`] pattern). A no-op off V6.
    fn recompute_recorded(&mut self) -> Result<(), NodeError> {
        self.recorded.clear();
        if self.sections != BodySections::V6 {
            return Ok(());
        }
        let mut found = Vec::new();
        let mut cursor = self.chain.tip_hash();
        while let Some(block) = self.chain.block(&cursor) {
            if block.header.height == 0 {
                break;
            }
            if let Some(h) = self.record_height_of(block)? {
                found.push((block.header.height, h));
            }
            cursor = block.header.prev;
        }
        self.recorded.extend(found);
        Ok(())
    }

    /// `CR(tip)`: the latest recorded finality height on the applied main
    /// chain (lab #785 Q-L5). `None` off V6, or before the first record.
    pub fn recorded_finality(&self) -> Option<u64> {
        self.recorded.values().next_back().copied()
    }

    /// Install a V6 node's setup (lab #785): committee₀, and the wrapper
    /// chain at its genesis surface. Every constructor and rebuild calls it
    /// before any block is applied, so replay folds bundles with the rule.
    fn install_v6(&mut self, v6: Option<V6Setup>) {
        let Some(v6) = v6 else { return };
        self.committee0 = Some(v6.committee0);
        self.surface = v6.wrapper.as_ref().map(|w| w.genesis_surface.clone()).unwrap_or_default();
        self.last_bundle_height = None;
        self.wrapper = v6.wrapper;
    }

    /// This node's V6 setup, for a rebuild; `None` off V6.
    fn v6_setup(&self) -> Option<V6Setup> {
        self.committee0.clone().map(|committee0| V6Setup { committee0, wrapper: self.wrapper.clone() })
    }

    /// Re-derive the wrapper surface and the last bundle height from the held
    /// main chain (lab #785 F5-4b) — the snapshot paths put the prefix in by
    /// `put_block` alone. Walks back from the tip to the latest bundle block
    /// (the [`Self::recompute_recorded`] pattern; the log is already in
    /// memory) and takes that bundle's stated surface, which is the surface
    /// its fold moved the chain to. No bundle held: the genesis surface.
    fn recompute_wrapper(&mut self) -> Result<(), NodeError> {
        self.surface = self.wrapper.as_ref().map(|w| w.genesis_surface.clone()).unwrap_or_default();
        self.last_bundle_height = None;
        if self.sections != BodySections::V6 {
            return Ok(());
        }
        let mut cursor = self.chain.tip_hash();
        loop {
            // Pre-review Q5: a hole in the held chain is named, never read as
            // "no bundle" (which would silently restore the genesis surface).
            let block = self.chain.block(&cursor).ok_or(NodeError::WrapperWalkBroken { missing: cursor })?;
            if block.header.height == 0 {
                break;
            }
            if let Some(bundle) = block.bundle_ref() {
                let bundle_err = |refusal| NodeError::Body(BodyError::Bundle { refusal });
                let rule = &self.wrapper.as_ref().ok_or(bundle_err(qlab_devnet::body::BundleRefusal::NoRule))?.rule;
                // Lab #785 F5-5c: the one bundle a snapshot path reads back.
                let bytes = bundle.bytes().map_err(NodeError::Io)?;
                self.surface = rule.bundle_surface(&bytes).map_err(bundle_err)?;
                self.last_bundle_height = Some(block.header.height);
                break;
            }
            cursor = block.header.prev;
        }
        Ok(())
    }

    /// **The exits a stored block carries** (lab #785 F5-5d), `(rkm, v)` in
    /// the order the fold made them exit notes: empty for a block with no
    /// bundle; otherwise the installed rule's `bundle_exits` over the bundle
    /// read back through its reference. Proof-free and chain-free, so it
    /// answers for a block loaded by a snapshot resume, where no fold ran.
    /// A bundle that cannot be read back, or that the rule cannot read exits
    /// from, is an error naming why — never an empty list in its place.
    pub fn exits_of(&self, block: &StoredBlock) -> Result<Vec<(Hash32, u64)>, String> {
        let Some(r) = block.bundle_ref() else { return Ok(Vec::new()) };
        let bytes = r.bytes().map_err(|e| e.to_string())?;
        let rule: &dyn qlab_devnet::body::BundleVerifier = match &self.wrapper {
            Some(w) => &*w.rule,
            None => &qlab_devnet::body::RefuseAllBundles,
        };
        rule.bundle_exits(&bytes).map_err(|e| format!("{e:?}"))
    }

    /// The wrapper chain's surface after the applied tip, canonical bytes
    /// (lab #785 F5-4b); empty on a node with no wrapper.
    pub fn wrapper_surface(&self) -> &[u8] {
        &self.surface
    }

    /// The latest applied bundle's height (lab #785 F5-4b).
    pub fn last_bundle_height(&self) -> Option<u64> {
        self.last_bundle_height
    }

    /// The body-section axis this node runs (lab #785).
    pub fn sections(&self) -> BodySections {
        self.sections
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
    /// Append one output commitment — the one append every output takes: a
    /// block's matured coinbase leaf and its transactions' outputs, and an
    /// Annulet genesis's notes (lab #710).
    fn append_commitment(&mut self, cm: Hash32) {
        self.commitments.append(cm);
        self.commitments_ordered.push(cm);
    }

    /// Record the commitment root after the outputs at `height` — the anchor
    /// index every block (and an Annulet genesis) enters.
    fn record_root_at(&mut self, height: u64) {
        let root = self.commitments.root_bytes();
        self.roots_by_height.insert(height, root);
        let heights = self.anchor_heights_by_root.entry(root).or_default();
        debug_assert!(heights.last().is_none_or(|h| *h < height));
        heights.push(height);
    }

    fn apply_state(&mut self, block: &StoredBlock) -> Result<Hash32, NodeError> {
        // The funnel guard (issue #77): every state mutation — fresh application
        // and disk-log replay alike — passes through here, so the header/body
        // binding is re-established before anything is folded into state.
        // Lab #785 F5-5c (pre-review Y4): a bundle is read once — resident
        // bytes as they are, log bytes re-hashed — for this check and the fold
        // below; one that cannot be read back is a persistence error by name.
        let bundle_bytes = block.bundle_ref().map(|r| r.bytes()).transpose().map_err(NodeError::Io)?;
        check_stored_binding_with(self.form, self.sections, block, bundle_bytes.as_deref())?;
        // Lab #785: a V6 block's record height, decoded before any mutation. A
        // live block was validated in full before reaching here; a logged one
        // that no longer decodes is a corrupt log, named rather than skipped.
        let record_height = self.record_height_of(block)?;
        // Lab #785 F5-4b: a V6 block's bundle, folded before any mutation — the
        // proof-free half of the rule, over the surface the parent left. A live
        // block passed the whole rule first; a logged bundle that no longer
        // folds (or a node with no rule) stops here by name, never a skip.
        let bundle_outcome = match &bundle_bytes {
            None => None,
            Some(bytes) => {
                let bundle_err = |refusal| NodeError::Body(BodyError::Bundle { refusal });
                let rule = &self.wrapper.as_ref().ok_or(bundle_err(qlab_devnet::body::BundleRefusal::NoRule))?.rule;
                Some(rule.fold_bundle(&self.surface, bytes).map_err(bundle_err)?)
            }
        };
        // Lab #785 F5-4c: the exit notes' leaves, derived before any mutation.
        // The exit index is a u8 in the note derivation; an outcome with more
        // exits than that (a rule is a trait object — never trusted to cap) is
        // refused by name, not a panic.
        let exit_leaves: Vec<Hash32> = match &bundle_outcome {
            None => Vec::new(),
            Some(outcome) => outcome
                .exits
                .iter()
                .enumerate()
                .map(|(i, (rkm, v))| {
                    let index = u8::try_from(i).map_err(|_| {
                        NodeError::Body(BodyError::Bundle {
                            refusal: qlab_devnet::body::BundleRefusal::TooManyExits {
                                n: outcome.exits.len(),
                                k_exit: usize::from(u8::MAX) + 1,
                            },
                        })
                    })?;
                    let rkm = qlab_note::hash::digest_from_bytes(rkm);
                    Ok(crate::coinbase::exit_note_leaf(block.header.height, index, rkm, *v))
                })
                .collect::<Result<_, NodeError>>()?,
        };
        // Lab #712: the outstanding-supply rule, checked before any mutation.
        let supply_delta = match self.form {
            GenesisForm::V4 | GenesisForm::V5 => BTreeMap::new(),
            GenesisForm::Annulet => {
                let delta = qlab_devnet::annulet::annulet_supply_delta(&block.body());
                for (&asset, &d) in &delta {
                    let outstanding = self.outstanding.get(&asset).copied().unwrap_or(0);
                    if outstanding + d < 0 {
                        return Err(NodeError::SupplyUnderflow { height: block.header.height, asset, outstanding, delta: d });
                    }
                }
                delta
            }
        };
        // Lab #728: the registry after this block, also before any mutation.
        let registry_after = match self.form {
            GenesisForm::V4 | GenesisForm::V5 => None,
            GenesisForm::Annulet => self.registry_after(&block.header(), &block.body())?,
        };
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
        let matured =
            crate::coinbase::matured_coinbase_leaf_for(self.form, block.header.height, |minted_at| {
                self.ancestor_at(&block.header.prev, minted_at).map(|b| b.coinbase_view())
            });
        let hash = self
            .chain
            .put_block(block.clone())
            .map_err(NodeError::Chain)?;
        if let Some(cb) = matured {
            self.append_commitment(cb);
        }
        for tx in &block.txs {
            for cm in &tx.commitments {
                self.append_commitment(*cm);
            }
            for nf in &tx.nullifiers {
                self.nullifiers.insert(*nf);
                self.nullifiers_ordered.push(*nf);
            }
        }
        // Lab #785 F5-4c: the bundle's exit notes, after the block's own
        // outputs and in exit-list order, before the height's root is
        // recorded — so the root at this height covers them, and rewind,
        // replay and the snapshot's leaf list follow through the one append.
        for leaf in exit_leaves {
            self.append_commitment(leaf);
        }
        // Lab #367: fold the block's riders into the name registry — the same
        // funnel as everything above, so `open == replay` and rewind-refold
        // both hold for names with nothing extra to maintain. A rider that
        // fails to decode HERE means the block was never validated (or the
        // log is corrupt): named, not ignored.
        self.names
            .apply_block_riders(block.header.height, block.txs.iter().map(|t| t.rider.as_slice()))
            .map_err(|(index, err)| NodeError::Body(BodyError::RiderMalformed { index, err }))?;
        self.record_root_at(block.header.height);
        if let Some(h) = record_height {
            self.recorded.insert(block.header.height, h);
        }
        if let Some(outcome) = bundle_outcome {
            self.surface = outcome.surface;
            self.last_bundle_height = Some(block.header.height);
        }
        if let Some(next) = registry_after {
            self.registry = Some(next);
        }
        if !supply_delta.is_empty() {
            for (&asset, &d) in &supply_delta {
                *self.outstanding.entry(asset).or_insert(0) += d;
            }
            self.supply_deltas.insert(block.header.height, supply_delta);
        }
        // Issue #198: a block back in the applied chain is servable from the applied
        // store again, so the archive copy is dropped — and the archive is pruned to
        // the depth a rewind could still reach from the new tip. Guarded on
        // non-empty so the ordinary application path (the archive is empty on every
        // node that has never rewound) pays one boolean.
        if !self.retained.is_empty() {
            self.retained.forget(&hash);
            self.retained.prune_below(block.header.height);
        }
        Ok(hash)
    }

    /// **A block this node HOLDS, applied or not** (issue #198) — the possession
    /// predicate the serving path keys on.
    ///
    /// The applied store first, then the rewind archive. The distinction from
    /// `ChainStore::block` is the whole of #198: whether *this* node has folded a
    /// block into its own state says nothing about whether a *requester* can use it,
    /// because the requester validates the body against the header's
    /// `tx_body_commitment` either way. Refusing to hand over a body you have is
    /// withholding data for no safety reason — and on 2026-08-01 it halted the net.
    pub fn held_block(&self, hash: &Hash32) -> Option<&StoredBlock> {
        self.chain.block(hash).or_else(|| self.retained.get(hash))
    }

    /// How many rewound-but-still-held blocks this node is carrying. Zero on any
    /// node that has never rewound, which is almost every node almost always.
    pub fn retained_bodies(&self) -> usize {
        self.retained.len()
    }

    /// Mark `hash` finalized (delegates the no-reorg-past-finality rule to the
    /// chain store) and log it, so a restart/replay reconstructs the finalized
    /// head. Finalization is what makes a commitment root a *valid anchor* (§4).
    ///
    /// `Ok(`[`FinalizeOutcome::Refused`]`)` = the chain store said no, **carrying the
    /// store's own [`FinalizeMarkError`]**; `Err` = a persistence failure.
    ///
    /// This returned `Ok(bool)` until issue #241. The caller that journals the
    /// `FINALIZE refused why=` line then had to reconstruct the reason from store
    /// state, because `Ok(false)` did not carry it — the same discard issue #205
    /// removed one layer up, surviving one layer down.
    pub fn finalize(&mut self, hash: Hash32) -> Result<FinalizeOutcome, NodeError> {
        if let Err(refusal) = self.chain.set_finalized(hash) {
            return Ok(FinalizeOutcome::Refused(refusal));
        }
        self.append_log(&LogRecord::Finalize(hash))?;
        Ok(FinalizeOutcome::Recorded)
    }

    /// **The node's one log writer**: append `rec` when disk-backed (a no-op
    /// in memory), returning where a V6 bundle landed. The first call in a
    /// process cuts a torn tail first (lab #804, `persist::truncate_torn_tail`)
    /// — here, not at open, because only the process that writes may: an
    /// audit opening a live node's data dir would see that node's append in
    /// progress as a torn tail.
    fn append_log(&mut self, rec: &LogRecord) -> Result<Option<u64>, NodeError> {
        let Some(dir) = &self.dir else { return Ok(None) };
        if !self.log_tail_cut {
            if let Some(cut) = persist::truncate_torn_tail(dir).map_err(NodeError::Io)? {
                qlab_devnet::jprintln!(
                    "STARTUP blocks.log: cut a torn tail of {cut} B (a crash mid-append) before the first append (lab #804)"
                );
            }
            self.log_tail_cut = true;
        }
        persist::append_record(dir, rec).map_err(NodeError::Io)
    }

    /// Persist the current derived state as an atomic snapshot (no-op for an
    /// in-memory node). After this, [`Self::open`] resumes from here.
    pub fn save_snapshot(&self) -> Result<(), NodeError> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let snap = Snapshot {
            format_version: FORMAT_VERSION,
            genesis_block_hash: self.chain.genesis_block_hash(),
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
        persist::save_snapshot(dir, &snap).map_err(NodeError::Io)?;
        // Lab #367: the registry sidecar rides every snapshot write (its
        // format note explains why it is not a Snapshot field).
        crate::name_registry::save_names(dir, &self.names, self.chain.tip_height())
            .map_err(NodeError::Io)?;
        // Lab #710: the registry sidecar rides the snapshot too (Annulet).
        if let Some(reg) = &self.registry {
            crate::registry_store::save_registry(dir, reg, self.chain.tip_height()).map_err(NodeError::Io)?;
        }
        Ok(())
    }

    /// Borrow the name registry (lab #367) — the local-resolve surface and
    /// the `NameView` behind block validation.
    pub fn names(&self) -> &crate::name_registry::NameRegistry {
        &self.names
    }

    /// Borrow the chain store.
    pub fn chain(&self) -> &C {
        &self.chain
    }
    /// Borrow the commitment store.
    pub fn commitments(&self) -> &T {
        &self.commitments
    }
    /// Every commitment-tree leaf in **authoritative append order** — the order
    /// [`Self::apply_state`] appended (the coinbase leaf a block matures first,
    /// then that block's transaction commitments, issue #102), which is the
    /// order the tree's positions mean.
    ///
    /// This is the projection `/v1/tree/leaves` serves (issue #275): a wallet
    /// replays it into a local tree and computes membership witnesses itself.
    /// It was already maintained for the snapshot (a replay reproduces the exact
    /// order), so serving it adds no second ledger — a rewind rebuilds it with
    /// the rest of derived state, so a reorged suffix leaves it exactly as a
    /// re-application would.
    pub fn commitments_ordered(&self) -> &[Hash32] {
        &self.commitments_ordered
    }
    /// Borrow the nullifier store.
    pub fn nullifiers(&self) -> &N {
        &self.nullifiers
    }

    /// Recovery provenance from the last disk-backed [`MemNode::open`].
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery
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

    /// The anchor rule evaluated **as of `block_height`** — the settled-history
    /// form of [`NodeState::is_valid_anchor`] (lab #402), used only under
    /// [`AnchorGate::SettledHistory`].
    ///
    /// `root` is valid iff this node's **own replay** recorded it as the
    /// commitment root after some ancestor height `h` with `h < block_height`
    /// and `block_height − h ≤ MAX_ANCHOR_AGE_BLOCKS` — the same
    /// [`Self::apply_state`]-maintained index the live rule reads, so a forged
    /// root, or a root that exists only on a sibling branch, is refused here
    /// exactly as it is live: it is in no entry of `roots_by_height`, which is
    /// computed from the blocks this node folded into its own state and never
    /// taken from a peer.
    ///
    /// What this deliberately does **not** re-check is the temporal half of the
    /// live rule — "`h` was at or below the finalized head when the block was
    /// mined". That fact was never recorded anywhere (finalization timing is
    /// per-node; headers carry none of it; `LogRecord::Finalize` is a bare hash)
    /// and is irrecoverable for existing history. Its security content is
    /// carried instead by the caller's contract: the block is an ancestor of a
    /// quorum-verified finalized checkpoint, and a block that violated the live
    /// rule while current would have been refused by every honest node then and
    /// so could never have entered an honestly finalized prefix. See
    /// [`AnchorGate::SettledHistory`] and lab #402.
    pub fn is_valid_anchor_as_of(&self, root: &Hash32, block_height: u64) -> bool {
        let floor = block_height.saturating_sub(MAX_ANCHOR_AGE_BLOCKS);
        let Some(heights) = self.anchor_heights_by_root.get(root) else {
            return false;
        };
        let first_in_window = heights.partition_point(|height| *height < floor);
        heights.get(first_in_window).is_some_and(|height| *height < block_height)
    }

    /// **Every distinct valid anchor root, newest first** — what `/v1/anchors`
    /// serves, read off the [`Self::apply_state`]-maintained index instead of
    /// recomputed from the chain (lab #673).
    ///
    /// ## Why this is a method here and not a walk in `rpc.rs`
    ///
    /// [`crate::anchor_set`] used to derive this by walking the whole main
    /// chain — `main_chain_of` (clone every `StoredBlock`, proofs included),
    /// `main_chain_counts_of`, then `CommitmentTree::root_at` **once per
    /// height**. `root_at` is deliberately the O(n) prefix walk (issue #386
    /// kept it that way as the ground truth `root()` is pinned against), and
    /// its own doc says historical anchors are "off the hot path". They are
    /// not: the node's run loop calls this once per applied block, so the walk
    /// was `O(heights x leaves)` Merkle node hashes on the loop that also
    /// serves the network — lab #673's 13 s, and quadratic in the chain.
    ///
    /// Nothing needed recomputing. `roots_by_height` IS `height -> root after
    /// that height`, maintained by the single `apply_state` funnel and rebuilt
    /// from genesis by `rewind_to`, so it carries exactly the main chain and
    /// exactly the quantity the walk was recomputing.
    ///
    /// ## The answer is bounded, so the derivation is too
    ///
    /// A valid anchor is a root at a height that is finalized **and** within
    /// `MAX_ANCHOR_AGE_BLOCKS` of the tip. That is at most one age window of
    /// heights whatever the chain's height, which is why the old shape was
    /// paying `O(chain)` to produce an `O(window)` answer.
    ///
    /// ## Order, and why the key is the highest occurrence
    ///
    /// The walk this replaces went tip -> genesis and emitted each root the
    /// first time it saw it, testing validity as a property of the ROOT rather
    /// than of the height it was standing on ([`NodeState::is_valid_anchor`]
    /// quantifies over all heights). Blocks that append no leaf repeat their
    /// parent's root, so a root genuinely can occur at several heights — and
    /// one that is valid via an in-window occurrence could first be REACHED at
    /// a later, out-of-window height. The ordering key is therefore the
    /// highest height at which the root occurs anywhere on the chain, which is
    /// `anchor_heights_by_root`'s last entry (ascending, asserted by
    /// `historical_anchor_index_matches_the_height_scan_after_snapshot_restore`).
    /// Heights are unique per root under that key, so the order is total and
    /// the tie-break the walk never needed is still not needed.
    ///
    /// This is QUM-111's rule applied one level up: the reverse index is a
    /// derived acceleration structure, so every indexed answer must remain
    /// identical to the scan it accelerates —
    /// `anchor_set_matches_the_full_chain_recomputation` is the mutation lock.
    pub fn valid_anchor_roots(&self) -> Vec<Hash32> {
        let Some(finalized) = self.chain.finalized_height() else {
            return Vec::new(); // nothing finalized => no valid anchors yet
        };
        let tip = self.chain.tip_height();
        let floor = tip.saturating_sub(MAX_ANCHOR_AGE_BLOCKS);
        if floor > finalized {
            // The whole age window is ahead of the finalized head: a real state
            // on a net whose finality has stalled for a day, and `range` would
            // panic on the inverted bounds rather than answer it.
            return Vec::new();
        }
        let mut seen = std::collections::HashSet::new();
        let mut keyed: Vec<(u64, Hash32)> = Vec::new();
        for (_, root) in self.roots_by_height.range(floor..=finalized) {
            if !seen.insert(*root) {
                continue;
            }
            let highest = self
                .anchor_heights_by_root
                .get(root)
                .and_then(|heights| heights.last().copied())
                .expect("a root read out of roots_by_height is indexed by root in the same funnel");
            keyed.push((highest, *root));
        }
        keyed.sort_unstable_by_key(|(height, _)| std::cmp::Reverse(*height));
        keyed.into_iter().map(|(_, root)| root).collect()
    }
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> NodeState for Node<C, N, T> {
    fn genesis_form(&self) -> GenesisForm {
        self.form
    }

    fn annulet_fee_table(&self) -> Option<qlab_devnet::annulet::L2FeeTable> {
        self.annulet_fees
    }
    fn annulet_registry_root(&self) -> Option<Hash32> {
        self.registry_root_bytes()
    }
    fn annulet_registry_write_root(
        &self,
        leaf_lanes: &[u64; 15],
    ) -> Option<Result<Hash32, crate::registry_store::RegistryError>> {
        use crate::registry_store::RegistryStore as _;
        let mut next = self.registry.clone()?;
        Some(next.apply_write(leaf_lanes).map(|()| next.root_bytes()))
    }
    fn outstanding_supply(&self, asset: u16) -> i128 {
        self.outstanding.get(&asset).copied().unwrap_or(0)
    }

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

/// What the V6 funnel reads (lab #785 F5-3b): the node's applied main chain,
/// which is exactly the ancestry of a block extending its tip. Every answer is
/// taken as of that block — `CR(parent)` is `CR(tip)`, ancestors are walked
/// from the tip, anchor heights are the tip's index — never the node's local
/// finality.
struct V6View<'a, C: ChainStore, N: NullifierStore, T: CommitmentStore> {
    node: &'a Node<C, N, T>,
    block_height: u64,
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> qlab_devnet::body::V6ChainView for V6View<'_, C, N, T> {
    fn recorded_finality(&self) -> Option<u64> {
        self.node.recorded_finality()
    }

    fn ancestor_at(&self, height: u64) -> Option<Hash32> {
        if height >= self.block_height {
            return None;
        }
        let tip = self.node.chain.tip_hash();
        self.node
            .ancestor_at(&tip, height)
            .map(|b| b.header().header_hash_for(self.node.form))
    }

    fn committee0(&self) -> &qlab_devnet::committee::Committee {
        self.node
            .committee0
            .as_ref()
            .expect("a V6 node is constructed with committee0 (in_memory_v6 / open_v6)")
    }

    fn root_heights(&self, root: &Hash32) -> &[u64] {
        self.node.anchor_heights_by_root.get(root).map_or(&[], Vec::as_slice)
    }

    fn wrapper_surface(&self) -> &[u8] {
        &self.node.surface
    }

    fn last_bundle_height(&self) -> Option<u64> {
        self.node.last_bundle_height
    }
}

/// The **V6** genesis block (lab #785 F5-3b): the v5 genesis header over the
/// empty body, bound under `commitment_v6` (`0e32092e…ad1d`).
pub fn genesis_block_v6(difficulty: u64, timestamp: u64) -> StoredBlock {
    let mut header = BlockHeader::genesis_for(GenesisForm::V5, difficulty, timestamp);
    header.tx_body_commitment = BlockBody::default().commitment_v6();
    StoredBlock::from_parts(&header, &BlockBody::default())
}

/// Build the genesis [`StoredBlock`] (empty body) at the given difficulty and
/// timestamp — the base every node starts from.
pub fn genesis_block(difficulty: u64, timestamp: u64) -> StoredBlock {
    genesis_block_for(GenesisForm::V4, difficulty, timestamp)
}

/// [`genesis_block`] under an explicit genesis form (lab #470 stage 4a): the
/// v5 genesis header binds the empty body's `commitment_v5` — the stage-3
/// pre-registered golden `82c2707b…7ea5`.
pub fn genesis_block_for(form: GenesisForm, difficulty: u64, timestamp: u64) -> StoredBlock {
    StoredBlock::from_parts(
        &BlockHeader::genesis_for(form, difficulty, timestamp),
        &BlockBody::default(),
    )
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
        TxEntry::with_placeholder_discovery(b"ok".to_vec(), TxPublic {
            anchor,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(80); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
            })
    }

    /// A node whose genesis root is finalized, so an ordinary tx anchored to it
    /// passes the anchor gate and only the binding can reject it.
    fn node_with_finalized_genesis() -> (MemNode, BlockHeader, Hash32) {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::in_memory(genesis);
        assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
        let root = node.commitment_root();
        (node, g_header, root)
    }

    fn child_committing_to(parent: &BlockHeader, body: &BlockBody) -> BlockHeader {
        BlockHeader::child_of(parent, parent.timestamp + 75, GENESIS_DIFFICULTY, body.commitment())
    }

    /// QUM-111 performance regression: the reverse anchor index is a derived
    /// acceleration structure, so every indexed answer must remain identical to
    /// the original height-range scan — including repeated roots across empty
    /// blocks and after the snapshot fast path rebuilds the index.
    #[test]
    fn historical_anchor_index_matches_the_height_scan_after_snapshot_restore() {
        let dir = temp_dir("historical-anchor-index");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());

        let mut parent = g_header;
        for height in 1..=24u64 {
            let body = if height % 6 == 1 {
                BlockBody::from_single_payee(vec![tx(node.commitment_root(), height as u8)], 0, [0; 4])
            } else {
                BlockBody::default()
            };
            let header = child_committing_to(&parent, &body);
            node.apply_block_gated(header, body, &MockVerifier, AnchorGate::SettledHistory)
                .unwrap();
            parent = header;
        }
        node.save_snapshot().unwrap();
        drop(node);

        let node = MemNode::open(&dir, genesis).unwrap();
        let mut candidates: Vec<Hash32> = node.roots_by_height.values().copied().collect();
        candidates.push([0xEE; 32]);
        candidates.sort_unstable();
        candidates.dedup();

        for block_height in 0..=node.tip_height() + 2 {
            let floor = block_height.saturating_sub(MAX_ANCHOR_AGE_BLOCKS);
            for root in &candidates {
                let scanned = node
                    .roots_by_height
                    .range(floor..block_height)
                    .any(|(_, candidate)| candidate == root);
                assert_eq!(
                    node.is_valid_anchor_as_of(root, block_height),
                    scanned,
                    "root {root:?} at H={block_height}"
                );
            }
        }

        for (root, heights) in &node.anchor_heights_by_root {
            assert!(heights.windows(2).all(|pair| pair[0] < pair[1]));
            let scanned: Vec<u64> = node
                .roots_by_height
                .iter()
                .filter_map(|(height, candidate)| (candidate == root).then_some(*height))
                .collect();
            assert_eq!(heights, &scanned, "derived index for {root:?}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_block_rejects_a_body_the_header_did_not_commit_to() {
        let (mut node, g, root) = node_with_finalized_genesis();
        let honest = BlockBody::from_single_payee(vec![tx(root, 1)], 0, [0; 4]);
        let header = child_committing_to(&g, &honest);
        let swapped = BlockBody::from_single_payee(vec![tx(root, 2)], 0, [0; 4]);
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
        let honest = BlockBody::from_single_payee(vec![tx(root, 3)], 0, [0; 4]);
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
        let honest = BlockBody::from_single_payee(vec![tx([9u8; 32], 4)], 0, [0; 4]);
        let header = child_committing_to(&g_header, &honest);
        // …but whose persisted body is not that body.
        let tampered = StoredBlock { annulet: None, sections: None,
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

    #[test]
    fn snapshot_finality_without_its_authoritative_log_record_refuses_to_open() {
        let dir = temp_dir("snapshot-finality-not-logged");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let genesis_block_hash = genesis.header().header_hash();
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();

        // Construct the inconsistency directly: the snapshot carries a proven
        // point, but no live `finalize` call appended its source-of-truth record.
        node.chain.restore_finalized(genesis_block_hash, 0).unwrap();
        node.save_snapshot().unwrap();
        drop(node);

        assert!(matches!(
            MemNode::open(&dir, genesis),
            Err(NodeError::SnapshotFinalityNotLogged { hash, height: 0 })
                if hash == genesis_block_hash
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
        let body = BlockBody::from_single_payee(vec![tx(root, 5)], 0, [0; 4]);
        let header = child_committing_to(&g_header, &body);
        node.apply_block(header, body, &MockVerifier).unwrap();
        node.save_snapshot().unwrap();
        assert_eq!(node.tip_height(), 1);
        drop(node);

        // Append a tampered record at the same height: `open` restores the
        // snapshot (applied_height = 1) and takes the fast path for it.
        let honest2 = BlockBody::from_single_payee(vec![tx(root, 6)], 0, [0; 4]);
        let h2 = child_committing_to(&g_header, &honest2);
        let tampered =
            StoredBlock { annulet: None, sections: None,
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

    /// **The negative for issue #225: the fall-through must not become a
    /// swallow.** A tampered record ABOVE `applied_height` goes through
    /// `apply_logged_block` — the same call whose rewind refusal is now a
    /// fall-through — and must still refuse, with the height it refused at.
    ///
    /// The existing test above covers a tampered record *at* `applied_height`,
    /// which `check_stored_binding` catches in the prefix loop; this covers the
    /// other side of the boundary, where the widening would actually have
    /// happened. `#225` is specific that a torn or undecodable log still refuses
    /// loudly and only a rewind refusal falls through, and this is that line.
    #[test]
    fn a_tampered_record_above_the_snapshot_still_refuses_rather_than_falling_through() {
        let dir = temp_dir("i225-tamper-above-snapshot");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        node.finalize(g_header.header_hash()).unwrap();
        let root = node.commitment_root();

        let body = BlockBody::from_single_payee(vec![tx(root, 7)], 0, [0; 4]);
        let h1 = child_committing_to(&g_header, &body);
        node.apply_block(h1, body, &MockVerifier).unwrap();
        node.save_snapshot().unwrap();
        assert_eq!(node.tip_height(), 1, "snapshot applied_height = 1");
        drop(node);

        // A record at height 2 — strictly above the snapshot, so the beyond loop
        // takes it — whose stored body is not the body its header commits to.
        let honest2 = BlockBody::from_single_payee(vec![tx(root, 8)], 0, [0; 4]);
        let h2 = child_committing_to(&h1, &honest2);
        let tampered = StoredBlock { annulet: None, sections: None,
            header: StoredHeader::from(&h2),
            txs: Vec::new(),
            coinbase: 0,
            coinbase_rkm: [0; 4],
        };
        persist::append_record(&dir, &LogRecord::Block(tampered)).unwrap();

        let err = match MemNode::open(&dir, genesis.clone()) {
            Err(e) => e,
            Ok(n) => panic!(
                "a corrupt record must not be recovered from: opened at tip {} ({:?})",
                n.tip_height(),
                n.recovery_report()
            ),
        };
        assert!(
            matches!(err, NodeError::BodyCommitmentMismatch { height: 2, .. }),
            "and it says which record and why, got {err}"
        );
        // The full replay refuses it identically — which is the argument for the
        // fall-through: it hands the decision to a path that is not more tolerant.
        assert!(matches!(
            MemNode::replay(&dir, genesis),
            Err(NodeError::BodyCommitmentMismatch { height: 2, .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **The REPLAY half of the height-keyed funnel** (lab #367 / QUM-129) — the
    /// implication PR #464 flagged as "the first thing I would test and the first
    /// thing I would expect to surprise someone", and could not check.
    ///
    /// `check_stored_binding` runs on the disk-log replay path as well as on
    /// fresh application, so height-keying it changes what an existing datadir
    /// means. Two legs, one shared 19,008-block prefix:
    ///
    /// **(a) a datadir written by a FIXED armed binary above the boundary replays
    /// correctly.** The record carries its own header height, so a v3-era block
    /// recomputes v3 — `replay` and `open` both reproduce the live node's tip
    /// hash and commitment root exactly.
    ///
    /// **(b) a datadir written by an INERT binary above the boundary, opened by a
    /// fixed armed binary, is REFUSED at the first above-boundary block** —
    /// loudly, naming the height, from `replay` and from `open` alike. It is NOT
    /// the silent-fresh-start shape this repo has paid for before: the error is
    /// `BodyCommitmentMismatch { height, expected, got }`, whose `Display` reads
    /// `block at height 19009 does not match its header's body commitment: header
    /// says …, body hashes to …`, and neither entry point returns a node.
    ///
    /// It also asserts the two layers **agree** on that block: the entry rule
    /// (`qlab_devnet::body::check_body_binding`, which the p2p relay path and
    /// `apply_block` both run) and this funnel produce the same
    /// `expected`/`got` pair, v2 against v3. Before the fix they produced
    /// opposite pairs, which is precisely what deadlocked the armed node.
    ///
    /// # Why it is `#[ignore]`d
    ///
    /// `persist::append_record` fsyncs every record, so writing the 19,008-block
    /// prefix costs **67.6 s** (measured: `Instant::now()` around the build loop,
    /// release, 1 sample, coordinator laptop under `scripts/rig`, ~3.5 ms/record)
    /// against **0.21 s** for the identical chain in memory. That is a bench, not
    /// a test, and the suite must not pay it for a property whose cheap half is
    /// already covered — the in-memory crossing is
    /// `qumbra-node/tests/name_boundary_drill.rs::the_live_v2_to_v3_crossing_applies_through_the_real_node`,
    /// and the "replay refuses loudly with the height" shape is covered at low
    /// heights by the two tamper tests above. What is only reachable here is the
    /// v2/v3 *form* on the replay path, which needs a real above-boundary height.
    ///
    /// Run it deliberately:
    /// `cargo test --release -p qlab-node --lib -- --ignored --nocapture name_boundary`
    #[test]
    #[ignore = "~70 s: 19k fsync'd log records. Run explicitly with --ignored (lab #367 replay legs)"]
    fn a_v3_era_datadir_replays_and_an_inert_written_one_is_refused_at_the_boundary() {
        use qlab_devnet::emission_exact::{coinbase_exact, RULE_BOUNDARY_HEIGHT};
        use qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT;

        const DRILL_RKM: [u64; 4] = [0xA1, 0xA2, 0xA3, 0xA4];
        /// Empty body — no rider, no anchor, no fee, no proof — minting exactly
        /// the schedule above the emission boundary so only the name format can
        /// refuse it.
        fn empty_body_at(height: u64) -> BlockBody {
            if height > RULE_BOUNDARY_HEIGHT {
                BlockBody::from_single_payee(vec![], coinbase_exact(height), DRILL_RKM)
            } else {
                BlockBody::from_single_payee(vec![], 0, [0; 4])
            }
        }
        /// The header an ARMED producer emits: committed at its own height.
        fn honest_child(parent: &BlockHeader, body: &BlockBody) -> BlockHeader {
            let h = BlockHeader::child_of(parent, parent.timestamp + 75, GENESIS_DIFFICULTY, [0; 32]);
            BlockHeader { tx_body_commitment: body.commitment_at(h.height), ..h }
        }

        let b = NAME_RULE_BOUNDARY_HEIGHT
            .expect("the boundary is stamped (lab #367 arming step 0, PR #455); with `None` this test proves nothing");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let dir = temp_dir("name-boundary-replay-armed");

        // ── the shared prefix: an ordinary v2 chain up to and including `b` ──
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        for h in 1..=b {
            let body = empty_body_at(h);
            let parent = node.chain.block(&node.tip_hash()).expect("tip is stored").header();
            let header = honest_child(&parent, &body);
            node.apply_block(header, body, &MockVerifier)
                .unwrap_or_else(|e| panic!("honest block {h} at/below the boundary must apply: {e}"));
        }
        let tip_at_b = node.chain.block(&node.tip_hash()).expect("tip is stored").header();

        // The INERT binary's datadir is the SAME chain up to here — it diverges
        // only in what it writes above the boundary, so copy the log now.
        let inert_dir = temp_dir("name-boundary-replay-inert");
        std::fs::copy(dir.join(persist::BLOCK_LOG), inert_dir.join(persist::BLOCK_LOG)).unwrap();

        // ── (a) the fixed armed binary crosses, and reads its own datadir back ──
        let body = empty_body_at(b + 1);
        let v3_header = honest_child(&tip_at_b, &body);
        assert_ne!(v3_header.tx_body_commitment, body.commitment(), "b+1 commits v3");
        node.apply_block(v3_header, body.clone(), &MockVerifier)
            .expect("the crossing block applies on a fixed armed binary");
        let (live_tip, live_hash, live_root, live_leaves) =
            (node.tip_height(), node.tip_hash(), node.commitment_root(), node.commitment_count());
        drop(node);

        let replayed = MemNode::replay(&dir, genesis.clone())
            .unwrap_or_else(|e| panic!("a v3-era datadir must replay on a fixed armed binary: {e}"));
        assert_eq!(replayed.tip_height(), live_tip, "replay reached the crossing block");
        assert_eq!(replayed.tip_hash(), live_hash, "…the same tip");
        assert_eq!(replayed.commitment_root(), live_root, "…and the same state");
        assert_eq!(replayed.commitment_count(), live_leaves);
        let opened = MemNode::open(&dir, genesis.clone())
            .unwrap_or_else(|e| panic!("`open` (no snapshot ⇒ same path) must agree: {e}"));
        assert_eq!(opened.tip_hash(), live_hash);

        // ── (b) the INERT binary's datadir, opened by a fixed armed binary ──
        // What an inert build writes above the boundary: the v2 form at a v3
        // height. It is a block its own binary applied happily.
        let inert_header = BlockHeader {
            tx_body_commitment: body.commitment(),
            ..BlockHeader::child_of(&tip_at_b, tip_at_b.timestamp + 75, GENESIS_DIFFICULTY, [0; 32])
        };
        assert_eq!(inert_header.height, b + 1, "the first block above the boundary");
        persist::append_record(
            &inert_dir,
            &LogRecord::Block(StoredBlock::from_parts(&inert_header, &body)),
        )
        .unwrap();

        let err = match MemNode::replay(&inert_dir, genesis.clone()) {
            Err(e) => e,
            Ok(n) => panic!(
                "an inert-written datadir must not be silently accepted: replay returned a node at tip {}",
                n.tip_height()
            ),
        };
        match &err {
            NodeError::BodyCommitmentMismatch { height, expected, got } => {
                assert_eq!(*height, b + 1, "refused at the FIRST above-boundary block");
                assert_eq!(*expected, body.commitment(), "what the inert binary committed: v2");
                assert_eq!(*got, body.commitment_at(b + 1), "what the armed rule requires: v3");
                // Loud, and it names the height (this is the whole of 4(b)).
                let msg = err.to_string();
                assert!(
                    msg.contains(&format!("height {}", b + 1)),
                    "the refusal must name the height it refused at, got: {msg}"
                );
            }
            other => panic!("expected the funnel's binding refusal, got {other}"),
        }
        // `open` refuses identically — no snapshot-shaped path recovers from it,
        // and neither returns an empty node that would look like a fresh start.
        assert!(matches!(
            MemNode::open(&inert_dir, genesis),
            Err(NodeError::BodyCommitmentMismatch { height, .. }) if height == b + 1
        ));

        // BOTH LAYERS AGREE on that block: the entry rule computes the same
        // expected/got pair the funnel just reported (v2 committed, v3 required).
        match qlab_devnet::body::check_body_binding(&inert_header, &body) {
            Err(BodyError::CommitmentMismatch { expected, got }) => {
                assert_eq!(expected, body.commitment(), "entry: same `expected` as the funnel");
                assert_eq!(got, body.commitment_at(b + 1), "entry: same `got` as the funnel");
            }
            other => panic!("the entry rule must refuse the inert block too, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&inert_dir).ok();
    }

    /// **A log that no path can honour still refuses, whichever loop notices
    /// first** — the load-bearing property of the #225 fall-through.
    ///
    /// The fall-through hands the decision to the from-genesis replay rather than
    /// making it. So the way to check it cannot hide anything is to hand it a log
    /// the replay itself refuses: `open` must still come back with a refusal and
    /// a reason, not a node.
    ///
    /// The log here is **fabricated** — a live node cannot write it, because
    /// `apply_block` applies at the tip only and `P` is out of the store by the
    /// time `R` is appended. That is deliberate: it is the only way I could reach
    /// the PREFIX loop's rewind refusal at all (verified by mutation: this test
    /// is the only one that enters that branch). See the note on
    /// [`MemNode::resume_from_snapshot`] and the PR body — I could not construct
    /// a prefix-loop refusal that a full replay then survives, so that half of
    /// the fall-through is not behaviourally distinguishable from the `?` it
    /// replaced.
    #[test]
    fn a_log_the_replay_also_refuses_is_still_a_refusal_not_a_recovery() {
        let dir = temp_dir("i225-prefix-rewind-refusal");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();

        // Three records: P and Q are siblings at height 1 (so Q's arrival is a
        // rewind to genesis that drops P), then R at height 2 claims P as parent.
        let mk = |parent: &BlockHeader, nf: u8| {
            let body = BlockBody::from_single_payee(vec![tx([9u8; 32], nf)], 0, [0; 4]);
            let header = child_committing_to(parent, &body);
            let stored = StoredBlock { annulet: None, sections: None,
                header: StoredHeader::from(&header),
                txs: body.txs.iter().map(|t| t.into()).collect(),
                coinbase: 0,
                coinbase_rkm: [0; 4],
            };
            (header, stored)
        };
        let (p_header, p) = mk(&g_header, 21);
        let (_q_header, q) = mk(&g_header, 22);
        let (_r_header, r) = mk(&p_header, 23);
        assert_eq!(r.header.height, 2);
        for rec in [&p, &q, &r] {
            persist::append_record(&dir, &LogRecord::Block(rec.clone())).unwrap();
        }

        // A snapshot covering both heights, so the PREFIX loop sees all three.
        persist::save_snapshot(&dir, &Snapshot {
            format_version: FORMAT_VERSION,
            genesis_block_hash: g_header.header_hash(),
            applied_height: 2,
            tip: r.header().header_hash(),
            finalized: None,
            commitments: Vec::new(),
            nullifiers: Vec::new(),
            roots_by_height: vec![(0, MemNode::in_memory(genesis.clone()).commitment_root())],
        })
        .unwrap();

        // Both paths refuse, and `open` reports the replay's refusal rather than
        // starting on a state neither path could reach.
        assert!(
            matches!(
                MemNode::replay(&dir, genesis.clone()),
                Err(NodeError::Rewind(RewindError::UnknownTarget))
            ),
            "the log itself is not replayable"
        );
        let err = match MemNode::open(&dir, genesis) {
            Err(e) => e,
            Ok(n) => panic!("open must not recover from it: tip {}", n.tip_height()),
        };
        assert!(matches!(err, NodeError::Rewind(RewindError::UnknownTarget)), "got {err}");
        assert_eq!(err.to_string(), "rewind refused: rewind target is not a known block");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A genuinely corrupt log still refuses to start, with a reason** (issue
    /// #225's negative, upstream half).
    ///
    /// A record that does not decode with bytes still after it is not a torn
    /// tail, and `read_records` refuses it before the snapshot is even consulted
    /// — so the #225 fall-through structurally cannot reach it. Pinned here
    /// anyway, because "the fix did not turn a refusal into a silent replay" is
    /// the claim, and it is worth an assertion rather than an argument.
    #[test]
    fn a_block_log_that_does_not_decode_still_refuses_to_start_with_a_reason() {
        use std::io::Write as _;

        let dir = temp_dir("i225-corrupt-log");
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

        // Two length-framed records of bytes that are not a `LogRecord`. The
        // second is what makes the first a corruption rather than a crash
        // mid-append: a torn record is by construction the LAST thing in the file.
        let junk = [0xffu8; 24];
        let mut f = std::fs::File::create(dir.join(persist::BLOCK_LOG)).unwrap();
        for _ in 0..2 {
            f.write_all(&(junk.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&junk).unwrap();
        }
        f.sync_all().unwrap();
        drop(f);

        let err = match MemNode::open(&dir, genesis) {
            Err(e) => e,
            Ok(n) => panic!("a corrupt log must not start: opened at tip {}", n.tip_height()),
        };
        let NodeError::Io(io) = &err else { panic!("expected an IO refusal, got {err}") };
        assert_eq!(io.kind(), std::io::ErrorKind::InvalidData);
        let text = err.to_string();
        assert!(text.contains("does not decode"), "the reason is in it: {text}");
        assert!(text.contains("Re-sync this datadir"), "and what to do about it: {text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **Issue #115 — the property the height-0 exemption made inexpressible.**
    ///
    /// A genesis whose body is not the body its header commits to is rejected, at
    /// height 0, by the same guard every other block passes. Two mismatches are
    /// exercised because they fail differently in the wild: (a) the *pre-#115
    /// genesis itself* — an honest empty body under a header pinning `ZERO_HASH`,
    /// which is what a node built before this change writes into its log; and
    /// (b) an honest genesis header carrying a foreign body, which is what a
    /// hand-assembled `StoredBlock` or a corrupted log record looks like.
    ///
    /// While the exemption stood, both returned `Ok`.
    #[test]
    fn a_genesis_that_is_not_its_own_body_is_rejected() {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

        // The correct genesis binds its own body and passes the guard.
        assert_eq!(
            genesis.header.tx_body_commitment,
            genesis.body().commitment(),
            "genesis satisfies the invariant since #115"
        );
        assert!(check_stored_binding(&genesis).is_ok());

        // (a) the pre-#115 genesis header: ZERO_HASH over the same empty body.
        let mut pre_115 = genesis.clone();
        pre_115.header.tx_body_commitment = qlab_devnet::header::ZERO_HASH;
        assert!(
            matches!(
                check_stored_binding(&pre_115),
                Err(NodeError::BodyCommitmentMismatch { height: 0, .. })
            ),
            "the pre-#115 genesis must not enter node state"
        );

        // (b) the honest genesis header over a foreign body.
        let mut foreign_body = genesis.clone();
        foreign_body.coinbase = 1; // any body edit moves the commitment
        assert!(matches!(
            check_stored_binding(&foreign_body),
            Err(NodeError::BodyCommitmentMismatch { height: 0, .. })
        ));

        // The guard no longer reads the height at all: the same mismatched pair
        // is rejected identically at height 1, and the *correct* pair is accepted
        // at height 0. Before #115 the first of these passed and the second was
        // waved through unchecked.
        let mut mismatch_at_1 = pre_115.clone();
        mismatch_at_1.header.height = 1;
        assert!(matches!(
            check_stored_binding(&mismatch_at_1),
            Err(NodeError::BodyCommitmentMismatch { height: 1, .. })
        ));
    }

    /// A mismatched genesis is refused at **construction**, not only at the
    /// state-mutation funnel — the seam a node actually starts from. Matches the
    /// pre-existing `genesis height must be 0` assertion in the same function:
    /// the genesis block is locally constructed or operator-supplied, never
    /// network input, so a mismatch is a build/operator error and panicking is
    /// the loudest available refusal at a seam whose callers do not return
    /// `Result` ([`MemNode::in_memory`]).
    #[test]
    #[should_panic(expected = "genesis must bind its own body")]
    fn a_node_refuses_to_start_from_a_mismatched_genesis() {
        let mut bad = genesis_block(GENESIS_DIFFICULTY, 0);
        bad.header.tx_body_commitment = qlab_devnet::header::ZERO_HASH;
        let _ = MemNode::in_memory(bad);
    }

    /// A correct genesis still constructs, verifies and applies a child — the
    /// positive half of #115's acceptance, so "reject everything" cannot pass.
    #[test]
    fn a_correct_genesis_constructs_and_extends() {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut node = MemNode::in_memory(genesis);
        node.finalize(g_header.header_hash()).unwrap();
        let root = node.commitment_root();

        let body = BlockBody::from_single_payee(vec![tx(root, 21)], 0, [0; 4]);
        let header = child_committing_to(&g_header, &body);
        node.apply_block(header, body, &MockVerifier).expect("child applies over genesis");
        assert_eq!(node.tip_height(), 1);
    }

    /// **Issue #130 (b): every way `apply_block` can fail has a name on the
    /// instrument**, and the two that a real `NotExtendingTip` would produce are
    /// reached from real errors rather than asserted about in prose.
    ///
    /// The `not_extending_tip` arm is the one that matters and it is the one that
    /// cannot be produced through the adapter, so it is produced here directly: this
    /// is what keeps the token from being dead code that nobody would notice had
    /// stopped classifying anything.
    #[test]
    fn every_apply_failure_classifies_to_a_declared_refusal_reason() {
        use crate::metrics::BODY_REFUSAL_REASONS;
        let (mut node, g, root) = node_with_finalized_genesis();

        // The variant #130 was filed against — produced for real, by handing
        // `apply_block` a block whose parent is not the tip.
        let body = BlockBody::from_single_payee(Vec::new(), 0, [0; 4]);
        let orphan = BlockHeader {
            prev: [0x9c; 32],
            ..BlockHeader::child_of(&g, g.timestamp + 150, GENESIS_DIFFICULTY, body.commitment())
        };
        let err = node.apply_block(orphan, body, &MockVerifier).unwrap_err();
        assert!(matches!(err, NodeError::NotExtendingTip { .. }), "got {err}");
        assert_eq!(err.refusal_reason(), "not_extending_tip");

        // A body failure, likewise produced rather than constructed.
        let honest = BlockBody::from_single_payee(vec![tx(root, 1)], 0, [0; 4]);
        let header = child_committing_to(&g, &honest);
        let swapped = BlockBody::from_single_payee(vec![tx(root, 2)], 0, [0; 4]);
        let err = node.apply_block(header, swapped, &MockVerifier).unwrap_err();
        assert_eq!(err.refusal_reason(), "bad_body");

        // The remaining classes, so no arm of the exhaustive match is unexercised.
        for (err, want) in [
            (NodeError::NullifierSpent { tx: 0 }, "nullifier_spent"),
            (
                NodeError::Io(io::Error::new(io::ErrorKind::StorageFull, "log append failed")),
                "persist_io",
            ),
            (
                NodeError::BodyCommitmentMismatch {
                    height: 1,
                    expected: [0; 32],
                    got: [1; 32],
                },
                "internal",
            ),
            (NodeError::Rewind(RewindError::UnknownTarget), "internal"),
        ] {
            assert_eq!(err.refusal_reason(), want, "for {err}");
        }

        // And every token a classification can return is a series `/metrics` already
        // declares — a reason that reached the registry under a name it does not know
        // would be silently dropped by `observe_body_refusal`, which is exactly the
        // "counted nowhere" failure this issue is about.
        for reason in [
            "not_extending_tip",
            "bad_body",
            "nullifier_spent",
            "persist_io",
            "internal",
        ] {
            assert!(BODY_REFUSAL_REASONS.contains(&reason), "{reason} is not declared");
        }
    }
    // ── lab #470 stage 4a: the v5 identity plumbing, proven end to end ──────

    /// A v5 node boots, applies, persists, and RESUMES under v5 identities —
    /// the whole stage-4a plumbing in one lifecycle: `open_for(V5)` on a fresh
    /// dir (genesis binding under `commitment_v5`), a block applied through
    /// the real path, then a restart replay that must agree with itself.
    #[test]
    fn v5_node_boots_applies_and_resumes() {
        let dir = std::env::temp_dir().join(format!("qmb-i470-v5-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let genesis = genesis_block_for(GenesisForm::V5, 8, 0);
        let tip = {
            let mut node = MemNode::open_for(GenesisForm::V5, &dir, genesis.clone()).unwrap();
            assert_eq!(node.form(), GenesisForm::V5);
            let parent = genesis.header();
            // The v5 funnel enforces the exact schedule NATIVELY from height 1
            // (this test's first draft paid coinbase=100 and was refused with
            // WrongScheduledCoinbase{expected: 4_999_995_882} — the stage-3
            // contrast rule biting on the very first v5 block, as designed).
            let body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(1), [1, 2, 3, 4]);
            let header = BlockHeader::child_of_for(
                GenesisForm::V5,
                &parent,
                75,
                8,
                body.commitment_v5(),
            );
            node.apply_block(header, body, &MockVerifier).expect("v5 block applies");
            node.tip_hash()
        };
        let node = MemNode::open_for(GenesisForm::V5, &dir, genesis).expect("v5 replay resumes");
        assert_eq!(node.tip_hash(), tip, "the replayed v5 identity equals the live one");
        assert_eq!(node.tip_height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cross-form open refuses: the same datadir under the WRONG form is a
    /// named error (the stored-binding check under the wrong form), never a
    /// silent mis-keyed resume.
    #[test]
    fn a_v5_datadir_refuses_a_v4_open() {
        let dir = std::env::temp_dir().join(format!("qmb-i470-xform-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let genesis5 = genesis_block_for(GenesisForm::V5, 8, 0);
        {
            let mut node = MemNode::open_for(GenesisForm::V5, &dir, genesis5.clone()).unwrap();
            let body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(1), [1, 2, 3, 4]);
            let header = BlockHeader::child_of_for(
                GenesisForm::V5,
                &genesis5.header(),
                75,
                8,
                body.commitment_v5(),
            );
            node.apply_block(header, body, &MockVerifier).unwrap();
        }
        let genesis4 = genesis_block(8, 0);
        assert!(
            MemNode::open_for(GenesisForm::V4, &dir, genesis4).is_err(),
            "a v5 log under a v4 open must refuse, not mis-key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The install-before-run invariant, extended to the state node (the
    /// stage-1 ruling's condition): re-keying is legal only while fresh.
    #[test]
    #[should_panic(expected = "only legal on a fresh node")]
    fn rekey_genesis_refuses_a_node_with_applied_state() {
        let mut node = MemNode::in_memory(genesis_block(8, 0));
        let body = BlockBody::from_single_payee(vec![], 100, [1, 2, 3, 4]);
        let header =
            BlockHeader::child_of(&genesis_block(8, 0).header(), 75, 8, body.commitment_at(1));
        node.apply_block(header, body, &MockVerifier).unwrap();
        node.rekey_genesis(GenesisForm::V5);
    }

    /// 🔴 **Lab #521 — the T2 launch-day reopen panic, end to end.**
    ///
    /// The preserved svc0 datadir's exact lifecycle: a v5 node applies a chain,
    /// loses a same-height miner race (live rewind + sibling re-application —
    /// the fork-choice sequence the 14:16 h=13 race wrote into the log), keeps
    /// running, snapshots ABOVE the rewind, and is then reopened. The
    /// snapshot-prefix loop replays the rewind through
    /// `MemChainStore::rewind_to`, whose rebuild was keyed v4 regardless of the
    /// store's own form — on a v5 chain the first retained re-insert panicked
    /// `UnknownParent` at store.rs:446 and the node could not reopen a store it
    /// had itself written. The full replay of the same log (snapshot absent)
    /// always succeeded, which is how the datadir proves the log was never the
    /// problem.
    #[test]
    fn a_v5_node_reopens_a_snapshot_whose_prefix_carries_a_live_rewind() {
        let dir = std::env::temp_dir().join(format!("qmb-i521-v5-rewind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let genesis = genesis_block_for(GenesisForm::V5, 8, 0);

        let v5_block = |parent: &BlockHeader, height: u64, ts: u64, marker: u64| {
            let body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(height), [marker; 4]);
            let header =
                BlockHeader::child_of_for(GenesisForm::V5, parent, ts, 8, body.commitment_v5());
            (header, body)
        };

        let live_tip = {
            let mut node = MemNode::open_for(GenesisForm::V5, &dir, genesis.clone()).unwrap();
            let (h1, b1) = v5_block(&genesis.header(), 1, 75, 0xA1);
            node.apply_block(h1.clone(), b1, &MockVerifier).expect("b1 applies");
            let b1_hash = node.tip_hash();

            // The miner race: apply one h=2, then fork choice moves to its
            // sibling — undo through the real rewind and re-apply, exactly
            // what the live node logged.
            let (h2a, b2a) = v5_block(&h1, 2, 150, 0xA2);
            node.apply_block(h2a, b2a, &MockVerifier).expect("the losing sibling applies");
            node.rewind_to(b1_hash).expect("the live rewind succeeds");
            let (h2b, b2b) = v5_block(&h1, 2, 160, 0xB2);
            node.apply_block(h2b.clone(), b2b, &MockVerifier).expect("the winner applies");
            let (h3, b3) = v5_block(&h2b, 3, 235, 0xA3);
            node.apply_block(h3, b3, &MockVerifier).expect("the chain extends on the winner");

            node.save_snapshot().expect("snapshot written above the rewind");
            node.tip_hash()
        };
        assert_eq!(
            persist::snapshot_on_disk(&dir).unwrap(),
            persist::SnapshotOnDisk::At { applied_height: 3 },
            "the reopen below must take the snapshot-resume path, not the full replay"
        );

        // Pre-fix this open panicked `UnknownParent` at store.rs:446.
        let node = MemNode::open_for(GenesisForm::V5, &dir, genesis)
            .expect("a node reopens the store it wrote");
        assert_eq!(node.tip_hash(), live_tip, "the resumed identity equals the live one");
        assert_eq!(node.tip_height(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }


    // --- lab #785 F5-3b: the V6 apply path ------------------------------------

    /// Twenty-one rehearsal committee₀ keys (built once) — ML-DSA, ms-class.
    fn v6_validators() -> &'static (qlab_devnet::committee::Committee, Vec<qlab_devnet::committee::Validator>) {
        use qlab_devnet::committee::{Committee, Validator};
        static F: std::sync::OnceLock<(Committee, Vec<Validator>)> = std::sync::OnceLock::new();
        F.get_or_init(|| {
            let vs: Vec<Validator> = (0..21)
                .map(|i| {
                    let mut seed = [0u8; 32];
                    seed[..8].copy_from_slice(b"f5-3b-nd");
                    seed[8] = i as u8;
                    Validator::from_seed(i, seed)
                })
                .collect();
            (Committee::from_keys(vs.iter().map(Validator::verifying_key).collect()), vs)
        })
    }

    fn v6_block(parent: &BlockHeader, txs: Vec<TxEntry>, finality: Vec<u8>) -> (BlockHeader, BlockBody) {
        let height = parent.height + 1;
        let mut body =
            BlockBody::from_single_payee(txs, qlab_devnet::emission_exact::coinbase_exact(height), [height; 4]);
        body.finality = finality;
        let header =
            BlockHeader::child_of_for(GenesisForm::V5, parent, parent.timestamp + 75, 8, body.commitment_v6());
        (header, body)
    }

    /// The V6 script both gates and both disk paths replay: blocks 1–8 empty;
    /// a tx anchored at the empty-tree root at 9 **without** a record (refused:
    /// no recorded finality, no anchor); block 9 carrying the quorum record
    /// for checkpoint 8; block 10 spending against the root now under it.
    fn v6_script(node: &mut MemNode, gate: AnchorGate) -> Vec<Result<Hash32, String>> {
        let (_, vs) = v6_validators();
        let mut out = Vec::new();
        let root = node.commitment_root();
        let mut parent = node.chain.block(&node.tip_hash()).unwrap().header();
        for _ in 1..=8 {
            let (h, b) = v6_block(&parent, vec![], vec![]);
            out.push(node.apply_block_gated(h, b, &MockVerifier, gate).map_err(|e| format!("{e:?}")));
            parent = h;
        }
        let (h9_bad, b9_bad) = v6_block(&parent, vec![tx(root, 0x51)], vec![]);
        out.push(node.apply_block_gated(h9_bad, b9_bad, &MockVerifier, gate).map_err(|e| format!("{e:?}")));
        let cp8 = qlab_devnet::committee::Checkpoint::new(8, node.tip_hash(), node.tip_hash());
        let record = qlab_devnet::finality_record::FinalityRecord {
            cp: cp8,
            votes: (0..15).map(|i| vs[i].sign_checkpoint(&cp8)).collect(),
        }
        .encode();
        let (h9, b9) = v6_block(&parent, vec![], record);
        out.push(node.apply_block_gated(h9, b9, &MockVerifier, gate).map_err(|e| format!("{e:?}")));
        let (h10, b10) = v6_block(&h9, vec![tx(root, 0x52)], vec![]);
        out.push(node.apply_block_gated(h10, b10, &MockVerifier, gate).map_err(|e| format!("{e:?}")));
        out
    }

    /// 🔒 **F5-3b merge condition — replay equals live.** On a V6 net the
    /// anchor verdict reads only the block's ancestry, so the Live and
    /// SettledHistory gates return the same verdict for every block —
    /// including the refusal — and a reopened node (full replay, then the
    /// snapshot path) re-derives the same recorded finality and tip.
    #[test]
    fn v6_live_and_settled_history_agree_and_replay_rederives_the_record() {
        let (c0, _) = v6_validators();
        let genesis = genesis_block_v6(8, 0);
        let mut live = MemNode::in_memory_v6(genesis.clone(), V6Setup { committee0: c0.clone(), wrapper: None });
        let mut settled = MemNode::in_memory_v6(genesis.clone(), V6Setup { committee0: c0.clone(), wrapper: None });
        let a = v6_script(&mut live, AnchorGate::Live);
        let b = v6_script(&mut settled, AnchorGate::SettledHistory);
        assert_eq!(a, b, "one verdict per block whichever gate the caller names");
        assert!(a[..8].iter().all(Result::is_ok));
        assert!(a[8].as_ref().unwrap_err().contains("AnchorOutsideRecord"), "{:?}", a[8]);
        assert!(a[9].is_ok() && a[10].is_ok(), "{a:?}");
        assert_eq!(live.recorded_finality(), Some(8));
        assert_eq!(live.tip_hash(), settled.tip_hash());

        let dir = temp_dir("v6-replay");
        let tip = {
            let mut disk = MemNode::open_v6(&dir, genesis.clone(), V6Setup { committee0: c0.clone(), wrapper: None }).unwrap();
            assert_eq!(v6_script(&mut disk, AnchorGate::Live), a);
            disk.tip_hash()
        };
        let replayed = MemNode::open_v6(&dir, genesis.clone(), V6Setup { committee0: c0.clone(), wrapper: None }).expect("full replay");
        assert_eq!((replayed.tip_hash(), replayed.recorded_finality()), (tip, Some(8)));
        assert_eq!(replayed.recovery_report().snapshot_height, None, "no snapshot yet: a full replay");
        replayed.save_snapshot().unwrap();
        let mut resumed = MemNode::open_v6(&dir, genesis.clone(), V6Setup { committee0: c0.clone(), wrapper: None }).expect("snapshot resume");
        assert_eq!(
            persist::snapshot_on_disk(&dir).unwrap(),
            persist::SnapshotOnDisk::At { applied_height: 10 }
        );
        // The snapshot path was actually taken (review M2): nothing replayed,
        // so the record came from `recompute_recorded`, not from apply_state.
        assert_eq!(resumed.recovery_report().snapshot_height, Some(10));
        assert_eq!(resumed.recovery_report().replayed_records, 0);
        assert_eq!((resumed.tip_hash(), resumed.recorded_finality()), (tip, Some(8)));
        // …and the re-derived record is load-bearing: a post-resume block
        // spending against the empty root (valid only under the record) applies.
        let empty_root = MemNode::in_memory_v6(genesis, V6Setup { committee0: c0.clone(), wrapper: None }).commitment_root();
        let parent = resumed.chain.block(&tip).unwrap().header();
        let (h11, b11) = v6_block(&parent, vec![tx(empty_root, 0x54)], vec![]);
        resumed.apply_block(h11, b11, &MockVerifier).expect("anchored under the resumed record");
        assert_eq!(resumed.tip_height(), 11);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rewind below the carrying block drops the recorded finality with it,
    /// and re-applying restores it (the derived state follows the fold).
    #[test]
    fn v6_recorded_finality_follows_a_rewind() {
        let (c0, _) = v6_validators();
        let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), V6Setup { committee0: c0.clone(), wrapper: None });
        let r = v6_script(&mut node, AnchorGate::Live);
        assert!(r[9].is_ok());
        let at8 = node.ancestor_at(&node.tip_hash(), 8).unwrap().header().header_hash_for(GenesisForm::V5);
        let block9 = node.ancestor_at(&node.tip_hash(), 9).unwrap().clone();
        assert!(block9.sections.is_some(), "block 9 carries the record");
        node.rewind_to(at8).unwrap();
        assert_eq!(node.recorded_finality(), None);
        assert_eq!(node.sections(), BodySections::V6);
        // Re-applying the carrying block restores it (review M3).
        node.apply_block(block9.header(), block9.body(), &MockVerifier).expect("block 9 re-applies");
        assert_eq!(node.recorded_finality(), Some(8));
    }

    /// Review M3: the stored-binding funnel refuses a sectioned block on a
    /// net without sections, by name, before any hashing under the wrong form.
    #[test]
    fn the_stored_binding_refuses_sections_on_a_sectionless_net() {
        let genesis5 = genesis_block_for(GenesisForm::V5, 8, 0);
        let body = {
            let mut b = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(1), [1; 4]);
            b.finality = vec![1, 2, 3];
            b
        };
        let header =
            BlockHeader::child_of_for(GenesisForm::V5, &genesis5.header(), 75, 8, body.commitment_v6());
        let block = StoredBlock::from_parts(&header, &body);
        assert!(matches!(
            check_stored_binding_for(GenesisForm::V5, BodySections::None, &block),
            Err(NodeError::Body(BodyError::SectionOnForm { .. }))
        ));
        assert!(check_stored_binding_for(GenesisForm::V5, BodySections::V6, &block).is_ok());
    }

    /// A V6 genesis binds `commitment_v6`, and a V5 node refuses a V6
    /// datadir record through the stored binding (sections on a V5 net).
    #[test]
    fn v6_sections_are_refused_on_a_v5_node() {
        let (c0, vs) = v6_validators();
        let _ = c0;
        let genesis5 = genesis_block_for(GenesisForm::V5, 8, 0);
        let mut node = MemNode::in_memory_for(GenesisForm::V5, genesis5.clone());
        let cp = qlab_devnet::committee::Checkpoint::new(8, [1; 32], [1; 32]);
        let mut body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(1), [1; 4]);
        body.finality = qlab_devnet::finality_record::FinalityRecord {
            cp,
            votes: (0..15).map(|i| vs[i].sign_checkpoint(&cp)).collect(),
        }
        .encode();
        let header =
            BlockHeader::child_of_for(GenesisForm::V5, &genesis5.header(), 75, 8, body.commitment_v5());
        let err = node.apply_block(header, body, &MockVerifier).unwrap_err();
        assert!(format!("{err:?}").contains("SectionOnForm"), "{err:?}");
        assert_ne!(genesis_block_v6(8, 0).header.tx_body_commitment, genesis5.header.tx_body_commitment);
    }

    // --- lab #785 F5-4b: the bundle state on the funnel -------------------------

    /// A test-only bundle rule (ruling condition (b): no accepting stub outside
    /// tests). The surface is an 8-byte counter; a bundle states its successor
    /// counter, which must be above the predecessor's (the "threading");
    /// spacing is 3. It exercises the node's state, not `verify_wrapper`.
    struct CounterRule;
    const COUNTER_SPACING: u64 = 3;
    fn counter(b: &[u8]) -> Option<u64> {
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
    impl qlab_devnet::body::BundleVerifier for CounterRule {
        fn verify_bundle(
            &self,
            header: &BlockHeader,
            bundle: &[u8],
            ctx: &qlab_devnet::body::BundleContext<'_>,
        ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            if let Some(last) = ctx.last_bundle_height {
                let since = header.height - last;
                if since < COUNTER_SPACING {
                    return Err(qlab_devnet::body::BundleRefusal::Spacing { since, need: COUNTER_SPACING });
                }
            }
            self.fold_bundle(ctx.surface, bundle)
        }
        fn fold_bundle(
            &self,
            surface: &[u8],
            bundle: &[u8],
        ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            use qlab_devnet::body::BundleRefusal;
            let prev = counter(surface).ok_or(BundleRefusal::SurfaceState)?;
            let next = counter(bundle).ok_or(BundleRefusal::Codec("not 8 bytes".into()))?;
            if next <= prev {
                return Err(BundleRefusal::Wrapper("Thread".into()));
            }
            Ok(qlab_devnet::body::BundleOutcome { surface: bundle.to_vec(), exits: vec![], d_batch: 0, e_batch: 0 })
        }
        fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, qlab_devnet::body::BundleRefusal> {
            counter(bundle).map(|_| bundle.to_vec()).ok_or(qlab_devnet::body::BundleRefusal::Codec("not 8 bytes".into()))
        }
    }

    fn counter_setup() -> V6Setup {
        let wrapper = qlab_devnet::body::WrapperSetup {
            rule: std::sync::Arc::new(CounterRule),
            genesis_surface: 0u64.to_le_bytes().to_vec(),
        };
        V6Setup { committee0: v6_validators().0.clone(), wrapper: Some(wrapper) }
    }

/// [`CounterRule`] counting its `verify_bundle` calls (lab #785 F5-5b).
    struct CountingRule(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl qlab_devnet::body::BundleVerifier for CountingRule {
        fn verify_bundle(
            &self,
            header: &BlockHeader,
            bundle: &[u8],
            ctx: &qlab_devnet::body::BundleContext<'_>,
        ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            CounterRule.verify_bundle(header, bundle, ctx)
        }
        fn fold_bundle(&self, surface: &[u8], bundle: &[u8]) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            CounterRule.fold_bundle(surface, bundle)
        }
        fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, qlab_devnet::body::BundleRefusal> {
            CounterRule.bundle_surface(bundle)
        }
    }

    /// Lab #785 F5-5c: on a disk-backed V6 node an applied bundle is held as
    /// a reference into `blocks.log` (its resident bytes dropped on append),
    /// reads back byte-exact, and both reopen paths — full replay and snapshot
    /// resume — hold references and reach the same surface and last bundle
    /// height. An in-memory node keeps the bytes, behind the same API.
    #[test]
    fn an_applied_bundle_lives_in_the_log_and_reopens_both_ways() {
        let dir = std::env::temp_dir().join(format!("qlab-f5-5c-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let g = genesis_block_v6(8, 0);
        let (h1, b1) = bundle_block(&g.header(), Some(5));
        let (h2, b2) = bundle_block(&h1, None);
        let live = {
            let mut node = MemNode::open_v6(&dir, g.clone(), counter_setup()).unwrap();
            node.apply_block(h1, b1.clone(), &MockVerifier).unwrap();
            node.apply_block(h2, b2, &MockVerifier).unwrap();
            let stored = node.chain.block(&h1.header_hash_for(GenesisForm::V5)).unwrap();
            let r = stored.bundle_ref().expect("block 1 carries the bundle");
            assert!(!r.is_resident(), "spilled to the log once appended");
            let at = r.log_offset().unwrap() as usize;
            let log = std::fs::read(dir.join(persist::BLOCK_LOG)).unwrap();
            assert_eq!(&log[at..at + b1.bundle.len()], &b1.bundle[..], "the reference is the bytes' place");
            assert_eq!(stored.body().preimage_v6(), b1.preimage_v6(), "body() reads it back");
            (node.tip_hash(), node.wrapper_surface().to_vec(), node.last_bundle_height())
        };
        assert_eq!(live.2, Some(1));
        let held = |n: &MemNode| n.chain.block(&h1.header_hash_for(GenesisForm::V5)).unwrap().bundle_ref().unwrap().is_resident();

        let replayed = MemNode::open_v6(&dir, g.clone(), counter_setup()).expect("full replay");
        assert_eq!(replayed.recovery_report().snapshot_height, None);
        assert_eq!((replayed.tip_hash(), replayed.wrapper_surface().to_vec(), replayed.last_bundle_height()), live);
        assert!(!held(&replayed), "opened from the log: a reference");
        replayed.save_snapshot().unwrap();
        let resumed = MemNode::open_v6(&dir, g.clone(), counter_setup()).expect("snapshot resume");
        assert_eq!(resumed.recovery_report().snapshot_height, Some(2));
        assert_eq!((resumed.tip_hash(), resumed.wrapper_surface().to_vec(), resumed.last_bundle_height()), live);
        assert!(!held(&resumed));

        let mut mem = MemNode::in_memory_v6(g, counter_setup());
        mem.apply_block(h1, b1.clone(), &MockVerifier).unwrap();
        assert!(held(&mem), "the in-memory store keeps the bytes");
        assert_eq!(
            mem.chain.block(&h1.header_hash_for(GenesisForm::V5)).unwrap().body().preimage_v6(),
            resumed.chain.block(&h1.header_hash_for(GenesisForm::V5)).unwrap().body().preimage_v6(),
            "one API, one body"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lab #785 F5-5c, conditions 2–3: bytes that moved under a live
    /// reference refuse by name on the serving path (`try_body`) and on the
    /// walk-back; a reopen over them refuses by name too (the moved bytes no
    /// longer bind to the header); a log cut short of the reference refuses
    /// the same way. Nothing panics.
    #[test]
    fn a_bundle_whose_log_moved_refuses_by_name() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("qlab-f5-5c-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let g = genesis_block_v6(8, 0);
        let (h1, b1) = bundle_block(&g.header(), Some(5));
        let mut node = MemNode::open_v6(&dir, g.clone(), counter_setup()).unwrap();
        node.apply_block(h1, b1, &MockVerifier).unwrap();
        let hash = h1.header_hash_for(GenesisForm::V5);
        let at = node.chain.block(&hash).unwrap().bundle_ref().unwrap().log_offset().unwrap();

        // Test-only write: production code never rewrites the log.
        let mut f = std::fs::OpenOptions::new().write(true).open(dir.join(persist::BLOCK_LOG)).unwrap();
        f.seek(SeekFrom::Start(at)).unwrap();
        f.write_all(&[0xEE]).unwrap();
        drop(f);
        let e = node.chain.block(&hash).unwrap().try_body().err().expect("serving refuses");
        assert!(e.to_string().contains("not this bundle"), "{e}");
        let e = node.recompute_wrapper().expect_err("the walk-back refuses");
        assert!(matches!(&e, NodeError::Io(io) if io.to_string().contains("not this bundle")), "{e}");
        let e = MemNode::open_v6(&dir, g, counter_setup()).err().expect("a reopen refuses");
        assert!(matches!(e, NodeError::BodyCommitmentMismatch { height: 1, .. }), "{e}");

        std::fs::OpenOptions::new().write(true).open(dir.join(persist::BLOCK_LOG)).unwrap().set_len(at + 3).unwrap();
        let e = node.chain.block(&hash).unwrap().try_body().err().expect("a short log refuses");
        assert!(e.to_string().contains("ends short"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lab #804 through the node: a crash tears the last record (a bundle
    /// block's); opening reads up to it and leaves the file as it is (a
    /// reader never cuts); the node's first append cuts the tail and lands at
    /// the last complete record's end, so a reopen sees every block — and the
    /// re-applied bundle's reference reads back.
    #[test]
    fn the_first_append_after_a_torn_tail_cuts_it() {
        let dir = std::env::temp_dir().join(format!("qlab-i804-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let g = genesis_block_v6(8, 0);
        let (h1, b1) = bundle_block(&g.header(), Some(5));
        let (h2, b2) = bundle_block(&h1, None);
        let (h3, b3) = bundle_block(&h2, None);
        let (h4, b4) = bundle_block(&h3, Some(9));
        let log = dir.join(persist::BLOCK_LOG);
        {
            let mut node = MemNode::open_v6(&dir, g.clone(), counter_setup()).unwrap();
            for (h, b) in [(h1, b1), (h2, b2), (h3, b3), (h4, b4.clone())] {
                node.apply_block(h, b, &MockVerifier).unwrap();
            }
        }
        let full = std::fs::metadata(&log).unwrap().len();
        std::fs::OpenOptions::new().write(true).open(&log).unwrap().set_len(full - 5).unwrap();

        let mut node = MemNode::open_v6(&dir, g.clone(), counter_setup()).expect("opens up to the torn record");
        assert_eq!(node.tip_height(), 3);
        assert_eq!(std::fs::metadata(&log).unwrap().len(), full - 5, "opening never cuts");
        node.apply_block(h4, b4.clone(), &MockVerifier).expect("re-applied");
        let at = node.chain.block(&h4.header_hash_for(GenesisForm::V5)).unwrap().bundle_ref().unwrap().log_offset().unwrap();
        assert_eq!(std::fs::metadata(&log).unwrap().len(), full, "the torn bytes were cut, the record re-written in their place");
        assert_eq!(node.chain.block(&h4.header_hash_for(GenesisForm::V5)).unwrap().bundle_ref().unwrap().read().unwrap(), b4.bundle);
        drop(node);

        let reopened = MemNode::open_v6(&dir, g, counter_setup()).expect("reopens whole");
        assert_eq!(reopened.tip_height(), 4);
        let r = reopened.chain.block(&h4.header_hash_for(GenesisForm::V5)).unwrap().bundle_ref().unwrap().clone();
        assert_eq!((r.log_offset(), r.read().unwrap()), (Some(at), b4.bundle));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lab #785 F5-5b (item 7): a tip block's proofs verify once — the
    /// ingest-time check and the apply-time re-check of the same block on the
    /// same parent share one `verify_bundle`; a cached verdict for another
    /// block, or a rewind, is not reused.
    #[test]
    fn a_tip_bundle_block_is_verified_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let setup = V6Setup {
            committee0: v6_validators().0.clone(),
            wrapper: Some(qlab_devnet::body::WrapperSetup {
                rule: std::sync::Arc::new(CountingRule(calls.clone())),
                genesis_surface: 0u64.to_le_bytes().to_vec(),
            }),
        };
        let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), setup);
        let n = || calls.load(Ordering::SeqCst);
        // Validated at ingest, then applied: one verification.
        let g = node.chain.block(&node.tip_hash()).unwrap().header();
        let (h1, b1) = bundle_block(&g, Some(5));
        node.validate_block_v6(&h1, &b1, &MockVerifier).unwrap();
        node.apply_block(h1, b1, &MockVerifier).unwrap();
        assert_eq!(n(), 1, "the apply re-check took the cached verdict");
        // Applied with no prior check: one verification.
        let mut parent = h1;
        for _ in 0..2 {
            let (h, b) = bundle_block(&parent, None);
            node.apply_block(h, b, &MockVerifier).unwrap();
            parent = h;
        }
        let (h4, b4) = bundle_block(&parent, Some(9));
        node.apply_block(h4, b4, &MockVerifier).unwrap();
        assert_eq!(n(), 2);
        // Two candidates checked at one tip; applying the first misses (the
        // slot holds the second) and verifies again.
        let mut parent = h4;
        for _ in 0..2 {
            let (h, b) = bundle_block(&parent, None);
            node.apply_block(h, b, &MockVerifier).unwrap();
            parent = h;
        }
        let (hx, bx) = bundle_block(&parent, Some(12));
        let (hy, by) = bundle_block(&parent, Some(13));
        node.validate_block_v6(&hx, &bx, &MockVerifier).unwrap();
        node.validate_block_v6(&hy, &by, &MockVerifier).unwrap();
        assert_eq!(n(), 4);
        node.apply_block(hx, bx, &MockVerifier).unwrap();
        assert_eq!(n(), 5, "a cached verdict for another block is not reused");
        // A rewind clears it: re-checking a block validated before the rewind
        // verifies again.
        let tip = node.tip_hash();
        let (hz, bz) = {
            let mut p = node.chain.block(&tip).unwrap().header();
            for _ in 0..2 {
                let (h, b) = bundle_block(&p, None);
                node.apply_block(h, b, &MockVerifier).unwrap();
                p = h;
            }
            bundle_block(&p, Some(20))
        };
        node.validate_block_v6(&hz, &bz, &MockVerifier).unwrap();
        assert_eq!(n(), 6);
        node.rewind_to(hz.prev).unwrap(); // a no-op target: still clears
        node.validate_block_v6(&hz, &bz, &MockVerifier).unwrap();
        assert_eq!(n(), 7, "the rewind cleared the slot");
    }

    fn bundle_block(parent: &BlockHeader, bundle: Option<u64>) -> (BlockHeader, BlockBody) {
        let height = parent.height + 1;
        let mut body =
            BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(height), [height; 4]);
        body.bundle = bundle.map(|c| c.to_le_bytes().to_vec()).unwrap_or_default();
        let header =
            BlockHeader::child_of_for(GenesisForm::V5, parent, parent.timestamp + 75, 8, body.commitment_v6());
        (header, body)
    }

    /// Blocks 1–5: a bundle at 1 (counter 5), one at 2 refused on spacing,
    /// empty 2 and 3, a bundle at 4 (counter 9), empty 5. The verdicts, then
    /// the node's `(surface counter, last bundle height)`.
    /// The script's verdicts and the node's `(surface counter, last bundle height)`.
    type BundleRun = (Vec<Result<Hash32, String>>, (Option<u64>, Option<u64>));

    fn bundle_script(node: &mut MemNode) -> BundleRun {
        let mut out = Vec::new();
        let mut parent = node.chain.block(&node.tip_hash()).unwrap().header();
        for (i, b) in [Some(5), None, None, Some(9), None].into_iter().enumerate() {
            if i == 1 {
                let (h, bd) = bundle_block(&parent, Some(6));
                out.push(node.apply_block(h, bd, &MockVerifier).map_err(|e| format!("{e:?}")));
            }
            let (h, bd) = bundle_block(&parent, b);
            out.push(node.apply_block(h, bd, &MockVerifier).map_err(|e| format!("{e:?}")));
            parent = h;
        }
        (out, (counter(node.wrapper_surface()), node.last_bundle_height()))
    }

    /// Lab #785 F5-4b: the surface and last bundle height fold in
    /// `apply_state`; the rule sees them as its context (a second bundle one
    /// block later is refused on spacing, by name); a rewind below a bundle
    /// restores the previous surface and re-applying restores both.
    #[test]
    fn v6_bundle_state_folds_and_follows_a_rewind() {
        let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), counter_setup());
        assert_eq!((counter(node.wrapper_surface()), node.last_bundle_height()), (Some(0), None), "the genesis surface");
        let (verdicts, state) = bundle_script(&mut node);
        assert!(verdicts[0].is_ok(), "{verdicts:?}");
        assert!(verdicts[1].as_ref().unwrap_err().contains("Spacing { since: 1, need: 3 }"), "{:?}", verdicts[1]);
        assert!(verdicts[2..].iter().all(Result::is_ok), "{verdicts:?}");
        assert_eq!(state, (Some(9), Some(4)));

        let at3 = node.ancestor_at(&node.tip_hash(), 3).unwrap().header().header_hash_for(GenesisForm::V5);
        let block4 = node.ancestor_at(&node.tip_hash(), 4).unwrap().clone();
        node.rewind_to(at3).unwrap();
        assert_eq!((counter(node.wrapper_surface()), node.last_bundle_height()), (Some(5), Some(1)), "back to bundle 1's surface");
        node.apply_block(block4.header(), block4.body(), &MockVerifier).expect("block 4 re-applies");
        assert_eq!((counter(node.wrapper_surface()), node.last_bundle_height()), (Some(9), Some(4)));

        // A bundle whose counter does not advance fails the fold, by name —
        // at height 7, spacing (3) after bundle 4, so the fold is what refuses.
        let mut parent = node.chain.block(&node.tip_hash()).unwrap().header();
        for _ in 0..2 {
            let (h, b) = bundle_block(&parent, None);
            node.apply_block(h, b, &MockVerifier).expect("an empty block");
            parent = h;
        }
        let (h, b) = bundle_block(&parent, Some(9));
        let err = node.apply_block(h, b, &MockVerifier).unwrap_err();
        assert!(format!("{err:?}").contains("Wrapper(\"Thread\")"), "{err:?}");
    }

    /// Lab #785 F5-4b (the 4b ruling's (2)): replay and both snapshot paths
    /// re-derive the surface and the last bundle height — the snapshot path
    /// by walking back to the latest held bundle, with nothing replayed — and
    /// the re-derived spacing is load-bearing after resume.
    #[test]
    fn v6_bundle_state_snapshot_resume_equals_replay() {
        let genesis = genesis_block_v6(8, 0);
        let dir = temp_dir("v6-bundle-resume");
        let (live_tip, live_state) = {
            let mut disk = MemNode::open_v6(&dir, genesis.clone(), counter_setup()).unwrap();
            let (_, state) = bundle_script(&mut disk);
            (disk.tip_hash(), state)
        };
        assert_eq!(live_state, (Some(9), Some(4)));
        let replayed = MemNode::open_v6(&dir, genesis.clone(), counter_setup()).expect("full replay");
        assert_eq!(replayed.recovery_report().snapshot_height, None);
        assert_eq!((replayed.tip_hash(), counter(replayed.wrapper_surface()), replayed.last_bundle_height()), (live_tip, Some(9), Some(4)));
        replayed.save_snapshot().unwrap();
        let mut resumed = MemNode::open_v6(&dir, genesis.clone(), counter_setup()).expect("snapshot resume");
        assert_eq!(resumed.recovery_report().snapshot_height, Some(5));
        assert_eq!(resumed.recovery_report().replayed_records, 0, "the snapshot path, nothing folded");
        assert_eq!((resumed.tip_hash(), counter(resumed.wrapper_surface()), resumed.last_bundle_height()), (live_tip, Some(9), Some(4)));
        // Spacing from the re-derived height: a bundle at 6 is 2 after 4.
        let parent = resumed.chain.block(&live_tip).unwrap().header();
        let (h6, b6) = bundle_block(&parent, Some(11));
        let err = resumed.apply_block(h6, b6, &MockVerifier).unwrap_err();
        assert!(format!("{err:?}").contains("Spacing { since: 2, need: 3 }"), "{err:?}");
        let (h6, b6) = bundle_block(&parent, None);
        resumed.apply_block(h6, b6, &MockVerifier).unwrap();
        let (h7, b7) = bundle_block(&h6, Some(11));
        resumed.apply_block(h7, b7, &MockVerifier).expect("3 after 4");
        assert_eq!((counter(resumed.wrapper_surface()), resumed.last_bundle_height()), (Some(11), Some(7)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ruling condition (b), node side: with no rule a V6 node refuses a bundle
    /// on validation, and a datadir holding one does not open — refused by
    /// name on both the replay and the snapshot path, never skipped.
    #[test]
    fn v6_a_node_with_no_rule_refuses_bundles_live_and_logged() {
        use qlab_devnet::body::BundleRefusal;
        let genesis = genesis_block_v6(8, 0);
        let no_rule = || V6Setup { committee0: v6_validators().0.clone(), wrapper: None };
        let mut bare = MemNode::in_memory_v6(genesis.clone(), no_rule());
        let (h, b) = bundle_block(&genesis.header(), Some(1));
        assert!(matches!(
            bare.apply_block(h, b, &MockVerifier),
            Err(NodeError::Body(BodyError::Bundle { refusal: BundleRefusal::NoRule }))
        ));
        assert_eq!(bare.wrapper_surface(), &[] as &[u8]);

        let dir = temp_dir("v6-bundle-norule");
        {
            let mut disk = MemNode::open_v6(&dir, genesis.clone(), counter_setup()).unwrap();
            bundle_script(&mut disk);
        }
        let err = MemNode::open_v6(&dir, genesis.clone(), no_rule()).err().expect("replay refuses");
        assert!(matches!(err, NodeError::Body(BodyError::Bundle { refusal: BundleRefusal::NoRule })), "{err:?}");
        MemNode::open_v6(&dir, genesis.clone(), counter_setup()).unwrap().save_snapshot().unwrap();
        let err = MemNode::open_v6(&dir, genesis, no_rule()).err().expect("the snapshot path refuses too");
        assert!(matches!(err, NodeError::Body(BodyError::Bundle { refusal: BundleRefusal::NoRule })), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- lab #785 F5-4c: exit notes ---------------------------------------------

    /// A test-only rule whose bundle is `counter (8 B) ‖ n × (rkm 32 ‖ v 8)`:
    /// the fold carries the exits, so the node's append path is exercised
    /// without a proven P member (the exit-bearing proven bundle is F5-6's).
    struct ExitRule;
    fn exit_bundle(next: u64, exits: &[([u64; 4], u64)]) -> Vec<u8> {
        let mut b = next.to_le_bytes().to_vec();
        for (rkm, v) in exits {
            b.extend_from_slice(&qlab_note::hash::digest_bytes(rkm));
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    }
    impl qlab_devnet::body::BundleVerifier for ExitRule {
        fn verify_bundle(
            &self,
            _: &BlockHeader,
            bundle: &[u8],
            ctx: &qlab_devnet::body::BundleContext<'_>,
        ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            self.fold_bundle(ctx.surface, bundle)
        }
        fn fold_bundle(
            &self,
            surface: &[u8],
            bundle: &[u8],
        ) -> Result<qlab_devnet::body::BundleOutcome, qlab_devnet::body::BundleRefusal> {
            use qlab_devnet::body::BundleRefusal;
            let prev = counter(surface).ok_or(BundleRefusal::SurfaceState)?;
            let (head, rest) = bundle.split_at_checked(8).ok_or(BundleRefusal::Codec("short".into()))?;
            let next = counter(head).ok_or(BundleRefusal::Codec("short".into()))?;
            if next <= prev || rest.len() % 40 != 0 {
                return Err(BundleRefusal::Wrapper("Thread".into()));
            }
            let exits: Vec<(Hash32, u64)> = rest
                .chunks_exact(40)
                .map(|c| (c[..32].try_into().unwrap(), u64::from_le_bytes(c[32..].try_into().unwrap())))
                .collect();
            let e_batch = exits.iter().map(|e| e.1).sum();
            Ok(qlab_devnet::body::BundleOutcome { surface: head.to_vec(), exits, d_batch: 0, e_batch })
        }
        fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, qlab_devnet::body::BundleRefusal> {
            bundle.get(..8).map(<[u8]>::to_vec).ok_or(qlab_devnet::body::BundleRefusal::Codec("short".into()))
        }
        fn bundle_exits(&self, bundle: &[u8]) -> Result<Vec<(Hash32, u64)>, qlab_devnet::body::BundleRefusal> {
            let rest = bundle.get(8..).ok_or(qlab_devnet::body::BundleRefusal::Codec("short".into()))?;
            if rest.len() % 40 != 0 {
                return Err(qlab_devnet::body::BundleRefusal::Codec("exit list".into()));
            }
            Ok(rest
                .chunks_exact(40)
                .map(|c| (c[..32].try_into().unwrap(), u64::from_le_bytes(c[32..].try_into().unwrap())))
                .collect())
        }
    }

    fn exit_setup() -> V6Setup {
        let wrapper = qlab_devnet::body::WrapperSetup {
            rule: std::sync::Arc::new(ExitRule),
            genesis_surface: 0u64.to_le_bytes().to_vec(),
        };
        V6Setup { committee0: v6_validators().0.clone(), wrapper: Some(wrapper) }
    }

    fn raw_bundle_block(parent: &BlockHeader, bundle: Vec<u8>) -> (BlockHeader, BlockBody) {
        let height = parent.height + 1;
        let mut body =
            BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(height), [height; 4]);
        body.bundle = bundle;
        let header =
            BlockHeader::child_of_for(GenesisForm::V5, parent, parent.timestamp + 75, 8, body.commitment_v6());
        (header, body)
    }

    const EXIT_A: [u64; 4] = [0xa1, 2, 3, 4];
    const EXIT_B: [u64; 4] = [0xb1, 6, 7, 8];

    /// Blocks 1 (empty) and 2 (a bundle with exits A:40, B:2), then 3 (empty).
    fn exit_script(node: &mut MemNode) {
        let mut parent = node.chain.block(&node.tip_hash()).unwrap().header();
        for bundle in [vec![], exit_bundle(5, &[(EXIT_A, 40), (EXIT_B, 2)]), vec![]] {
            let (h, b) = raw_bundle_block(&parent, bundle);
            node.apply_block(h, b, &MockVerifier).unwrap();
            parent = h;
        }
    }

    /// Lab #785 F5-5d: `exits_of` reads a stored block's exits through the
    /// rule from its bundle — empty for a block without one — in the order
    /// the fold appended them; a rule that cannot read exits refuses (never an
    /// empty list), and so does a bundle that no longer reads back.
    #[test]
    fn exits_of_reads_a_stored_blocks_exits_through_the_rule() {
        let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), exit_setup());
        exit_script(&mut node);
        let at = |h: u64| node.ancestor_at(&node.tip_hash(), h).unwrap().clone();
        assert_eq!(node.exits_of(&at(1)), Ok(vec![]));
        let want = vec![(qlab_note::hash::digest_bytes(&EXIT_A), 40), (qlab_note::hash::digest_bytes(&EXIT_B), 2)];
        assert_eq!(node.exits_of(&at(2)), Ok(want));
        assert_eq!(node.exits_of(&at(3)), Ok(vec![]));
        // A rule without `bundle_exits` refuses for a bundle block.
        let mut counted = MemNode::in_memory_v6(genesis_block_v6(8, 0), counter_setup());
        let g = counted.chain.block(&counted.tip_hash()).unwrap().header();
        let (h1, b1) = bundle_block(&g, Some(5));
        counted.apply_block(h1, b1, &MockVerifier).unwrap();
        let b = counted.chain.block(&counted.tip_hash()).unwrap().clone();
        assert!(counted.exits_of(&b).unwrap_err().contains("NoRule"));
    }

    /// Lab #785 F5-4c: a bundle's exits become notes — after the block's
    /// outputs, in list order, under [`crate::coinbase::exit_note`] — the
    /// height's recorded root covers them; a rewind below the block removes
    /// them and re-applying restores them; replay and snapshot resume reach
    /// the same tree.
    #[test]
    fn v6_exit_notes_append_in_order_and_follow_rewind_and_resume() {
        let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), exit_setup());
        exit_script(&mut node);
        assert_eq!(node.commitments.count(), 2, "two exits, no matured coinbase yet");
        let leaf = |i: u64| qlab_note::hash::digest_bytes(&node.commitments.tree().leaf(i));
        assert_eq!(leaf(0), crate::coinbase::exit_note_leaf(2, 0, EXIT_A, 40));
        assert_eq!(leaf(1), crate::coinbase::exit_note_leaf(2, 1, EXIT_B, 2));
        assert_eq!(node.roots_by_height[&2], node.commitments.root_bytes(), "the root at 2 covers the exits");
        assert_ne!(node.roots_by_height[&1], node.roots_by_height[&2]);
        let live_root = node.commitments.root_bytes();

        let at1 = node.ancestor_at(&node.tip_hash(), 1).unwrap().header().header_hash_for(GenesisForm::V5);
        let kept: Vec<StoredBlock> = [2, 3].iter().map(|h| node.ancestor_at(&node.tip_hash(), *h).unwrap().clone()).collect();
        node.rewind_to(at1).unwrap();
        assert_eq!(node.commitments.count(), 0, "the exits left with their block");
        for b in &kept {
            node.apply_block(b.header(), b.body(), &MockVerifier).unwrap();
        }
        assert_eq!(node.commitments.root_bytes(), live_root, "re-applying restores them");

        let dir = temp_dir("v6-exit-notes");
        {
            let mut disk = MemNode::open_v6(&dir, genesis_block_v6(8, 0), exit_setup()).unwrap();
            exit_script(&mut disk);
        }
        let replayed = MemNode::open_v6(&dir, genesis_block_v6(8, 0), exit_setup()).unwrap();
        assert_eq!(replayed.commitments.root_bytes(), live_root);
        replayed.save_snapshot().unwrap();
        let resumed = MemNode::open_v6(&dir, genesis_block_v6(8, 0), exit_setup()).unwrap();
        assert_eq!(resumed.recovery_report().replayed_records, 0);
        assert_eq!((resumed.commitments.root_bytes(), resumed.commitments.count()), (live_root, 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The 4c ruling's condition: a 4b-era chain — bundles, none with exits —
    /// reaches the same tree under 4c: no exit, no append.
    #[test]
    fn a_bundle_without_exits_leaves_the_tree_as_before() {
        let mut with = MemNode::in_memory_v6(genesis_block_v6(8, 0), exit_setup());
        let mut without = MemNode::in_memory_v6(genesis_block_v6(8, 0), exit_setup());
        let (mut pw, mut po) = (
            with.chain.block(&with.tip_hash()).unwrap().header(),
            without.chain.block(&without.tip_hash()).unwrap().header(),
        );
        for n in 1..=4u64 {
            let (h, b) = raw_bundle_block(&pw, if n % 2 == 0 { exit_bundle(n, &[]) } else { vec![] });
            with.apply_block(h, b, &MockVerifier).unwrap();
            pw = h;
            let (h, b) = raw_bundle_block(&po, vec![]);
            without.apply_block(h, b, &MockVerifier).unwrap();
            po = h;
        }
        assert_eq!(with.last_bundle_height(), Some(4));
        assert_eq!(with.roots_by_height, without.roots_by_height, "every height's root is the no-bundle chain's");
    }

    /// 🔒 The exit-note golden (lab #785 F5-4c-1): ρ, rseed and the leaf at
    /// two fixed inputs, copied from the named `qlab-bench exitnote` run's
    /// output (`logs/f5-4c1-runs/exitnote.log`).
    #[test]
    fn the_exit_note_derivation_is_pinned() {
        use crate::coinbase::{exit_note, exit_note_leaf};
        let hex = |b: &Hash32| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let a = exit_note(100, 0, [1, 2, 3, 4], 40);
        assert_eq!(a.rho, [13712170880088095291, 4199033222445404976, 15972117310625030030, 15041945620642184602]);
        assert_eq!(a.rseed, [9743797210762047376, 5384718611270703694, 1562314213152760210, 4897966456472967529]);
        assert_eq!(hex(&exit_note_leaf(100, 0, [1, 2, 3, 4], 40)), "ad09e649d6cb186cca8aada010203ad9a273a3f051abc9dce6e49c98ed9e3bc6");
        let b = exit_note(100, 1, [5, 6, 7, 8], 2);
        assert_eq!(b.rho, [3022201620843842787, 16721148094731447576, 14861027003635416433, 6589176296354670576]);
        assert_eq!(b.rseed, [15747039078141673426, 5666021685480660654, 8548220196773582315, 18023207007031546542]);
        assert_eq!(hex(&exit_note_leaf(100, 1, [5, 6, 7, 8], 2)), "7e067871141533fc2c1f75691bf5831f9bd094f6bd3a1f7ff2f04e0ad8be457c");
    }

    /// The exit-note derivation: ρ and rseed separate by index, height and
    /// rkm, and from the coinbase domain.
    #[test]
    fn exit_note_derivation_separates_index_height_and_domain() {
        use crate::coinbase::{coinbase_rho_v5, exit_note};
        let n = exit_note(10, 0, EXIT_A, 40);
        assert_eq!((n.value, n.rkm), (40, EXIT_A));
        assert_ne!(n.rho, exit_note(10, 1, EXIT_A, 40).rho, "index");
        assert_ne!(n.rho, exit_note(11, 0, EXIT_A, 40).rho, "height");
        assert_ne!(n.rho, exit_note(10, 0, EXIT_B, 40).rho, "rkm");
        assert_ne!(n.rho, coinbase_rho_v5(10, 0, &EXIT_A), "not a coinbase ρ");
        assert_ne!(n.rho, n.rseed);
        assert_eq!(n.rho, exit_note(10, 0, EXIT_A, 999).rho, "value is not in ρ");
    }
}
