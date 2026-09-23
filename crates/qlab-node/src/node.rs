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

use qlab_devnet::forms::GenesisForm;
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
pub const MAX_RETAINED_BODY_BYTES: usize = 32 * 1024 * 1024;

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
            | NodeError::Rewind(_)
            // A form this node cannot serve reaching its funnel is an internal
            // wiring error (`run` refuses an Annulet genesis before a node
            // exists), not a peer fault — the same bucket, enumerated.
            | NodeError::FormNotServed { .. }
            | NodeError::UnsealedOnAnnulet
            | NodeError::AnnuletFinality(_) => "internal",
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
            NodeError::Rewind(e) => write!(f, "rewind refused: {e}"),
            NodeError::Io(e) => write!(f, "persistence error: {e}"),
            NodeError::UnsealedOnAnnulet => write!(
                f,
                "an Annulet block is applied only with its sequencer seal (lab #708)"
            ),
            NodeError::AnnuletFinality(e) => {
                write!(f, "Annulet final-on-acceptance refused by the chain store: {e:?} (lab #708)")
            }
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
    check_stored_binding_for(GenesisForm::V4, block)
}

/// [`check_stored_binding`] under an explicit genesis form (lab #470 4a): the
/// v4 arm is the height-keyed v2/v3 rule exactly as before; the v5 arm binds
/// under the height-keyed cap assertion in `commitment_v5_at` (the bytes stay
/// the same across that boundary).
fn check_stored_binding_for(form: GenesisForm, block: &StoredBlock) -> Result<(), NodeError> {
    let got = match form {
        GenesisForm::V4 => block.body().commitment_at(block.header.height),
        GenesisForm::V5 => block.body().commitment_v5_at(block.header.height),
        // Lab #708: the Annulet body commitment (B1). Genesis never passes this
        // funnel (it is bound at construction, over its genesis notes).
        GenesisForm::Annulet => qlab_devnet::annulet::body_commitment_annulet(&block.body()),
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
    /// The L2 fee table (lab #708) — `Some` exactly on an Annulet node.
    annulet_fees: Option<qlab_devnet::annulet::L2FeeTable>,
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
        Self::from_genesis(GenesisForm::V4, genesis, None)
    }

    /// [`MemNode::in_memory`] under an explicit genesis form (lab #470 4a).
    pub fn in_memory_for(form: GenesisForm, genesis: StoredBlock) -> Self {
        Self::from_genesis(form, genesis, None)
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
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(NodeError::Io)?;

        let records = persist::read_records(&dir).map_err(NodeError::Io)?;
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
            match Self::resume_from_snapshot(form, &dir, &genesis, snap, &records)? {
                SnapshotResume::Resumed(node) => return Ok(node),
                SnapshotResume::Rejected(why) => {
                    // Lab #408: before conceding the genesis fold, try the
                    // near-tip degrade — honour the rejected snapshot anyway
                    // when the log itself proves its tip is on the finalized
                    // main chain. Any failure inside the attempt falls back to
                    // the full replay, which stays the correctness anchor.
                    if let Some(node) = Self::resume_near_tip(form, &dir, &genesis, snap, &records, &why)
                    {
                        return Ok(node);
                    }
                    snapshot_rejected = Some(why);
                }
            }
        }
        Self::resume_by_replay(form, &dir, genesis, &records, snapshot_rejected)
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
        dir: &Path,
        genesis: &StoredBlock,
        snap: &Snapshot,
        records: &[LogRecord],
    ) -> Result<SnapshotResume, NodeError> {
        let mut node = Self::from_genesis(form, genesis.clone(), Some(dir.to_path_buf()));
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
                    check_stored_binding_for(node.form, b)?;
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
    fn resume_near_tip(
        form: GenesisForm,
        dir: &Path,
        genesis: &StoredBlock,
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
        let mut node = Self::from_genesis(form, genesis.clone(), Some(dir.to_path_buf()));
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
            check_stored_binding_for(node.form, block).ok()?;
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
        dir: &Path,
        genesis: StoredBlock,
        records: &[LogRecord],
        snapshot_rejected: Option<SnapshotRejection>,
    ) -> Result<Self, NodeError> {
        let mut node = Self::from_genesis(form, genesis, Some(dir.to_path_buf()));
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
        let mut node = Self::from_genesis(form, genesis, Some(dir.clone()));
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
        self.apply_state(block)?;
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
        let mut rebuilt = Self::from_genesis(self.form, kept[0].clone(), self.dir.clone());
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

    fn from_genesis(form: GenesisForm, genesis: StoredBlock, dir: Option<PathBuf>) -> Self {
        assert_eq!(genesis.header.height, 0, "genesis height must be 0");
        // Issue #115: genesis is bound to its body like every other block, and
        // this is the one seam a genesis enters by without passing
        // `check_stored_binding` (it is put straight into the chain store).
        // Panicking matches the height assertion above — the genesis block is
        // locally built or operator-supplied, never network input.
        let expected_binding = match form {
            GenesisForm::V4 => genesis.body().commitment(),
            GenesisForm::V5 => genesis.body().commitment_v5(),
            // Locally-built input, same class as the height assertion above:
            // an Annulet genesis binds its genesis notes, which this signature
            // does not carry.
            GenesisForm::Annulet => panic!(
                "an Annulet genesis is opened with MemNode::in_memory_annulet (lab #708)"
            ),
        };
        assert_eq!(
            genesis.header.tx_body_commitment, expected_binding,
            "genesis must bind its own body (under the net's form)"
        );
        Self::from_bound_genesis(form, genesis, dir)
    }

    /// [`Self::from_genesis`] after the genesis binding has been checked by
    /// the caller (the L1 arms above; the Annulet constructor over its notes).
    fn from_bound_genesis(form: GenesisForm, genesis: StoredBlock, dir: Option<PathBuf>) -> Self {
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
            recovery: RecoveryReport::default(),
            names: crate::name_registry::NameRegistry::default(),
            form,
            annulet_fees: None,
        }
    }

    /// **An Annulet node** (lab #708), in memory: the genesis header must bind
    /// `genesis_notes` under B1's genesis body commitment (checked here, the
    /// constructor's panic class), the L2 fee table comes from the genesis
    /// params, and **genesis is final on acceptance** (Q4), so the genesis
    /// root is a valid anchor for block 1.
    ///
    /// The genesis notes are bound, not applied — applying them to the
    /// commitment tree is B3's (lab #706 P13). A data dir is B2b's (the
    /// Annulet log record); this constructor has none.
    pub fn in_memory_annulet(
        genesis_header: BlockHeader,
        genesis_notes: &[qlab_devnet::annulet::GenesisNote],
        fees: qlab_devnet::annulet::L2FeeTable,
    ) -> MemNode {
        assert_eq!(
            genesis_header.tx_body_commitment,
            qlab_devnet::annulet::genesis_body_commitment_annulet(genesis_notes),
            "the Annulet genesis must bind its genesis notes (lab #706)"
        );
        let genesis = StoredBlock::annulet_genesis(&genesis_header);
        let mut node = MemNode::from_bound_genesis(GenesisForm::Annulet, genesis, None);
        node.annulet_fees = Some(fees);
        let g = node.chain.genesis_block_hash();
        node.chain.set_finalized(g).expect("genesis is final on acceptance (lab #708 Q4)");
        node
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
        *self = Self::from_genesis(form, rebuilt, self.dir.clone());
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
        if let Some(dir) = &self.dir {
            persist::append_record(dir, &LogRecord::Block(block)).map_err(NodeError::Io)?;
        }
        Ok(hash)
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
        if self.dir.is_some() {
            // Refused before any mutation: the Annulet log record is B2b's.
            return Err(NodeError::FormNotServed { form: self.form, owner: "B2b (the Annulet log record)" });
        }
        let header = sealed.header;
        if header.prev != self.chain.tip_hash() {
            return Err(NodeError::NotExtendingTip { expected: self.chain.tip_hash(), got: header.prev });
        }
        let anchor_ok = |root: &Hash32| self.is_valid_anchor(root);
        qlab_devnet::annulet::validate_body_annulet(&header, &body, verifier, anchor_ok, &fees)
            .map_err(NodeError::Body)?;
        let block = StoredBlock::from_sealed_parts(sealed, &body);
        let hash = self.apply_state(&block)?;
        self.chain.set_finalized(hash).map_err(NodeError::AnnuletFinality)?;
        Ok(hash)
    }

    /// The L2 fee table an Annulet node applies (`None` on an L1 node).
    pub fn annulet_fee_table(&self) -> Option<qlab_devnet::annulet::L2FeeTable> {
        self.annulet_fees
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
        check_stored_binding_for(self.form, block)?;
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
        // Lab #367: fold the block's riders into the name registry — the same
        // funnel as everything above, so `open == replay` and rewind-refold
        // both hold for names with nothing extra to maintain. A rider that
        // fails to decode HERE means the block was never validated (or the
        // log is corrupt): named, not ignored.
        self.names
            .apply_block_riders(block.header.height, block.txs.iter().map(|t| t.rider.as_slice()))
            .map_err(|(index, err)| NodeError::Body(BodyError::RiderMalformed { index, err }))?;
        let root = self.commitments.root_bytes();
        self.roots_by_height.insert(block.header.height, root);
        let heights = self.anchor_heights_by_root.entry(root).or_default();
        debug_assert!(heights.last().is_none_or(|height| *height < block.header.height));
        heights.push(block.header.height);
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
        if let Some(dir) = &self.dir {
            persist::append_record(dir, &LogRecord::Finalize(hash)).map_err(NodeError::Io)?;
        }
        Ok(FinalizeOutcome::Recorded)
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
            .map_err(NodeError::Io)
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
        let tampered = StoredBlock { annulet: None,
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
            StoredBlock { annulet: None,
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
        let tampered = StoredBlock { annulet: None,
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
            let stored = StoredBlock { annulet: None,
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

}
