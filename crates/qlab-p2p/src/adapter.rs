//! `NodeAdapter` — the **real** N1 node-state (M9-N7).
//!
//! Where [`crate::n1::StubNode`] is an in-memory reference that skips PoW and
//! proof verification, `NodeAdapter` wires the same five N1 traits onto the real
//! components the earlier waves built:
//!
//! - **header chain + PoW + fork-choice**: a devnet [`ChainState`] validated on
//!   ingest with real PoW + LWMA-120 difficulty + key-block seed
//!   ([`validate_header_under`] / [`expected_difficulty`] / [`pow_seed`], N3);
//! - **real state machine**: a [`qlab_node::MemNode`] (depth-32 commitment tree +
//!   permanent nullifier set + anchor set + restart-safe snapshots, N1);
//! - **pending pool**: the N4 [`Mempool`] — admission runs the injected M3
//!   verifier, so a tx (or a block body) carrying an invalid proof is *rejected*;
//! - **committee over the network**: the N5 [`EpochCommittee`] / [`FinalityTracker`]
//!   / [`SigningWindow`] / equivocation machinery (ported from `StubNode`, which
//!   already exercises exactly this logic).
//!
//! Because `P2pNode<T, N: NodeState>` is generic over the node, swapping
//! `StubNode` for `NodeAdapter` needs no change to the gossip/sync/relay layer.
//!
//! ## Two/three tx-id encodings — never conflated
//! The P2P layer keys mempool/inv by [`crate::codec::tx_id`] (keccak of the
//! varint tx wire, proof included). The N4 mempool keys internally by
//! [`qlab_node::txid`] (the body-commitment encoding). This adapter keeps a
//! `wire_id → mempool_txid` index so `has_tx`/`get_tx` answer in the P2P id-space
//! while the pool stays keyed by its own id.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use qlab_devnet::body::{
    check_scheduled_coinbase_payees, coinbase_payee_cap_v5, validate_body_with_names, BlockBody,
    BodyError, CoinbasePayee, TxEntry,
};
use qlab_devnet::chain::{ChainState, FinalizeMarkError, InsertError};
use qlab_devnet::committee::{Checkpoint, CommitteeState, MemberStatus, Validator, Vote};
use qlab_devnet::ebbflow::{
    equivocation_slash, finality_status, verify_equivocation, EquivocationEvidence, FinalityStatus,
    SigningWindow,
};
use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
use qlab_devnet::finality::{FinalityTracker, FinalizeError};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::tally::VoteTally;
use qlab_pow::keyblock::KeyBlockSchedule;
use qlab_devnet::mining::{grind_slice, mine_under, GrindOutcome, SliceBudget};
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{
    DEGRADED_MODE_LAG_BLOCKS, DOWNTIME_JAIL_THRESHOLD_PCT, DOWNTIME_JAIL_WINDOW,
    EPOCH_LENGTH_BLOCKS, JAIL_BLOCKS,
};
use qlab_devnet::pow::PowEngine;
use qlab_devnet::forms::{ChainRules, GenesisForm};
use qlab_devnet::halt::{regime as halt_regime, RuleSchedule};
use qlab_devnet::validation::{
    expected_difficulty, pow_seed, validate_header_under, ValidationError,
};

use qlab_node::mempool::TxId;
use qlab_node::metrics::Metrics;
use qlab_node::recovery::Finalizer;
use qlab_node::round::{ObsClock, RoundLedger, SlotContext, VoteRejects};
use qlab_node::telemetry::{AppliedTip, StateLag};
use qlab_node::{genesis_block_for, genesis_block, FinalizeOutcome, MemNode, Mempool, MempoolError, NodeError, NodeState as _,
    RecoveryReport, RewindReport,};
use qlab_devnet::body::TxVerifier;

use crate::bodywait::{AskSetObservation, MineDuty, RejoinGate};
use crate::codec::{checkpoint_id, tx_id as wire_tx_id};
use crate::node::body_window_for;
use crate::n1::{
    BlockIngest, ChainView, CheckpointIngest, CommitteeControl, IngestOutcome, TxPool, VotesOutcome,
};
use crate::punish::{self, PunishmentRestore};

/// The effective §6 median a soak-node assembles against: large enough that the
/// penalty-free zone accepts every pending tx (no gigantism at prototype scale).
const SOAK_EFFECTIVE_MEDIAN: u64 = 4_000_000;

/// How a mined block's header timestamp is chosen at the **mining-clock seam**
/// ([`NodeAdapter::mine_block`]).
///
/// The two modes are the whole of M10-T0-3 precondition item 0. In-process sims
/// and tests use [`MiningClock::Deterministic`] so runs stay reproducible and LWMA
/// sees a constant on-target solvetime; the `qumbra-node` binary switches to
/// [`MiningClock::WallClock`] so LWMA sees real, variable solvetimes at the frozen
/// 75 s cadence (T0's item-4 difficulty-trace measurement needs a non-constant
/// solvetime signal — a constant mining clock holds difficulty at the genesis
/// value forever).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MiningClock {
    /// A deterministic monotone counter: each mined block's timestamp is the
    /// parent's timestamp + the target block time. Reproducible; the default, so
    /// every in-process sim/test path is unchanged. LWMA sees a constant solvetime.
    #[default]
    Deterministic,
    /// Real wall-clock seconds (`SystemTime::now`), clamped non-decreasing against
    /// the parent so header validation's monotonic rule ([`validate_header_under`]) always
    /// holds. The binary path. Difficulty then retargets to real block-production
    /// pace; the jitter is exactly what LWMA's 6T / out-of-sequence clamps tolerate.
    WallClock,
}

/// An unground candidate: the node's own `mine_on_parent` assembly without
/// `mine_under`. Lab #511 serves this on `GET /v1/mine/template`.
#[derive(Clone)]
pub struct AssembledCandidate {
    /// The genesis form the header was assembled under.
    pub form: GenesisForm,
    /// Header with `nonce = 0` — the miner (or pool extra-nonce) owns the grind.
    pub header: BlockHeader,
    /// Body the header's `tx_body_commitment` binds. POST `/v1/mine/block`
    /// must submit this body with the completed header.
    pub body: BlockBody,
    /// RandomX key-block hash at `seed_height(header.height)`.
    pub seed_hash: Hash32,
    /// Next key-block hash, when this branch already holds that seed block.
    pub next_seed_hash: Option<Hash32>,
}

/// A self-mining grind parked between loop iterations (lab #651): the
/// snapshotted template plus the nonce cursor.
///
/// It lives on the adapter — not the node loop — because the adapter owns the
/// tip: the abandonment trigger is [`NodeAdapter::mining_parent_hash`]
/// answering differently than it did when the template was assembled, and
/// only here is that question answered atomically with the resume itself (the
/// loop would have to read the tip through an API and race its own phase).
struct GrindState {
    /// The parent this template extends — the staleness check's key. The tip
    /// moving off this hash is what makes the parked work worthless (its
    /// block would be an orphan); a clock cannot see that event.
    parent_hash: Hash32,
    /// The template exactly as assembled — header (nonce 0), body, seed. A
    /// resumed grind hashes this snapshot, so the header it finds is
    /// byte-identical to what an unsliced grind would have found.
    candidate: AssembledCandidate,
    /// First nonce the next slice tries; `[0, next_nonce)` are spent.
    next_nonce: u64,
}

/// One [`NodeAdapter::mine_step`] verdict (lab #651).
pub enum MineStep {
    /// A block was found — the caller announces it, exactly as it would a
    /// [`NodeAdapter::mine_block`] result.
    Mined(BlockHeader, BlockBody),
    /// The slice is done with no hit; the grind is parked for the next phase.
    Yielded,
    /// The template's nonce budget is spent — the grind is dropped. The next
    /// permitted phase assembles a fresh template (fresh timestamp, fresh
    /// mempool snapshot) and starts at nonce 0.
    Exhausted,
    /// Nothing was ground: no grind in flight and starting was not permitted
    /// (`may_start` false), or the mining parent is unavailable (halt / lag
    /// refusal / unknown), or assembly failed.
    Idle,
}

/// Real wall-clock time in whole seconds since the Unix epoch (the
/// [`MiningClock::WallClock`] source). A clock reading before the epoch (never on a
/// sane host) reads as 0 — the parent-clamp in [`NodeAdapter::next_timestamp`] then
/// keeps the header non-decreasing regardless.
fn wall_clock_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Unit-test caliper for the legacy tip-to-height main-chain walk. Dispatch-hot
// readers must use `main_chain_hash_at`; any fallback to the walk is observable
// without putting counters or branches in a production build.
#[cfg(test)]
std::thread_local! {
    static MAIN_CHAIN_ANCESTOR_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

/// A real full-node node-state: consensus header chain + PoW, the qlab-node state
/// machine, the N4 mempool, and the N5 committee machinery. Generic over the PoW
/// engine `P` (KeccakPow for fast deterministic soaks, RandomXPow for the real-PoW
/// composition) and the injected tx verifier `V`.
pub struct NodeAdapter<P: PowEngine, V: TxVerifier + Clone> {
    /// Header chain + heaviest-chain fork-choice (finality-marked).
    chain: ChainState,
    /// The PoW engine (N3).
    pow: P,
    /// The real state machine — commitment tree, nullifier set, anchors, snapshots.
    state: MemNode,
    /// The N4 pending pool.
    mempool: Mempool,
    /// The committee across epochs (N5).
    committee: EpochCommittee,
    /// Committee-checkpoint finality tracker (the finalized-height source of truth).
    finality: FinalityTracker,
    /// Trailing-window signer participation, for downtime jail.
    signing: SigningWindow,
    /// (height, signer) → first checkpoint+vote seen, for equivocation detection.
    votes_seen: HashMap<(u64, usize), (Checkpoint, Vote)>,
    /// Cross-message vote accumulator: distinct verified active votes per checkpoint
    /// variant, until a quorum can be handed to `try_finalize` (M10-T0-5).
    tally: VoteTally,
    /// Checkpoints already finalized (dedup).
    seen_checkpoints: HashSet<Hash32>,
    /// The injected M3 verifier.
    verifier: V,
    /// P2P wire id ([`crate::codec::tx_id`]) → mempool body-commitment id.
    wire_ids: HashMap<Hash32, TxId>,
    /// RandomX key-block schedule (N3).
    schedule: KeyBlockSchedule,
    /// Target block time (drives LWMA + timestamps).
    block_time: u64,
    /// Mining nonce budget per block — since lab #651 this bounds one
    /// TEMPLATE's nonce space (exhaustion ⇒ re-assemble fresh), not one
    /// blocking call; see [`Self::mine_step`].
    nonce_budget: u64,
    /// The parked self-mining grind, if one is in flight (lab #651). Only
    /// [`Self::mine_step`] reads or writes it; [`Self::mine_block`] (the
    /// simulator/test path) grinds to completion and never parks.
    grind: Option<GrindState>,
    /// Monotone mining clock (sim seconds) — used only by [`MiningClock::Deterministic`].
    clock: u64,
    /// How a mined block's header timestamp is chosen (item 0). Defaults to
    /// [`MiningClock::Deterministic`]; the binary opts into [`MiningClock::WallClock`].
    mining_clock: MiningClock,
    /// The running chain rules: the genesis-keyed form set + the release's
    /// halt/rule schedule (issue #74; form-keyed since lab #470). Defaults to
    /// [`ChainRules::V1_0`] — v4 forms, no halt, no post-halt rule domain — so
    /// every in-process sim, soak and test behaves exactly as before. The binary
    /// installs the value once at startup via [`Self::set_chain_rules`] (the one
    /// selection point); there is no config/CLI/env path to it (H1).
    rules: ChainRules,
    /// Counters that attribute ingest refusals to a layer (issue #74 drill
    /// evidence). Surfaced in the binary's telemetry line so the docker drill can
    /// answer "which layer rejected the old branch?" from the logs rather than from
    /// a narrative.
    ingest_counters: IngestCounters,
    /// Per-round committee diagnostics (issue #87): one record per checkpoint slot,
    /// **whether or not it finalizes**. Observation only — no method on it can
    /// change what finalizes, and every quorum/roster value it holds is *read* from
    /// the committee state rather than re-derived.
    rounds: RoundLedger,
    /// Source-side counters + histograms (issue #87). Fed at the event, so a
    /// distribution is never reconstructed from printed gauges.
    metrics: Metrics,
    /// Where this node's mined coinbase notes are paid (issue #101) — the raw
    /// `rkm` written into `BlockBody::coinbase_rkm`. Defaults to
    /// [`UNCONFIGURED_MINER_RKM`]; the binary installs the operator's key via
    /// [`Self::set_miner_rkm`].
    miner_rkm: [u64; 4],
    /// **Bodies held for headers this node already has, awaiting the state tip**
    /// (issue #130 (a)), keyed `(height, header hash)` so the map iterates in
    /// ascending height and two branches at one height can both be held.
    ///
    /// This is an **out-of-order window, not a sync mechanism**: a body reaches it
    /// only by arriving live, and the gap it closes is the one header-first sync
    /// opens when a `Headers` batch runs ahead of a body announce. Obtaining a body
    /// nobody offered needs a wire message that does not exist — #130 (c).
    ///
    /// Relationship to `P2pNode::blocks` (issue #135), stated because the two must
    /// not be confused: that map is a **serving** cache, keyed by hash with no
    /// ordering, holding bodies to answer `GetBlockTxn` with; it lives above the
    /// `NodeState` trait boundary and a body enters it only when the header was new.
    /// This map is an **application** queue: ordered by height, bounded, and emptied
    /// by the state machine advancing. They are two lifetimes for two jobs, so this
    /// is a second buffer on purpose rather than a reuse — and nothing here grows,
    /// prunes or reads that map. Bounding it is #135's, and is not done here.
    pending_bodies: BTreeMap<(u64, Hash32), (BlockHeader, BlockBody)>,
    /// Running weight of [`Self::pending_bodies`] in bytes, so the byte budget is a
    /// subtraction rather than a walk of the map on every insert.
    pending_bytes: usize,
    /// The node's data dir, when disk-backed — the durability seam for the committee
    /// punishment ledger (issue #133). `None` for an in-memory adapter, which keeps
    /// every in-process sim, soak and test writing nothing.
    ///
    /// Held here rather than reached for through `MemNode` because the punishment
    /// ledger is *this* layer's state: the committee lives here, and `qlab-node`
    /// deliberately knows nothing about ML-DSA signatures.
    dir: Option<PathBuf>,
    /// Every equivocation this node has adjudicated, in the order it applied them —
    /// the in-memory mirror of `punishments.dat` (issue #133). Bounded by the roster
    /// (a member is tombstoned once).
    punishments: Vec<EquivocationEvidence>,
    /// What the last `open` found in the ledger and did with it. Reported at startup
    /// so "restored nothing" and "had nothing to restore" are distinguishable.
    punish_restore: PunishmentRestore,
    /// Rewind reports awaiting the journal (issue #162), newest-wins and bounded by
    /// [`MAX_JOURNALLED_REWINDS`]. See [`NodeAdapter::drain_rewinds`].
    rewinds: Vec<RewindReport>,
    /// Finalize records refused and not yet journalled (issue #204). Bounded by
    /// [`MAX_JOURNALLED_FINALIZE_REFUSALS`], oldest dropped.
    finalize_refusals: Vec<FinalizeRefusal>,
    /// Lossless count of refusal **transitions** since process start — the number
    /// behind `fdrop=`. A transition, not an attempt: `sync_state_finality` retries
    /// on every drain (issue #130 (a)), so counting attempts would report the retry
    /// rate rather than the divergence, and an operator would have no way to tell
    /// one stuck head from a thousand.
    finalize_refused_total: u64,
    /// The refusal currently latched — `(head, height)`. Set on a new refusal,
    /// cleared the moment that head records a finalize. Exists so the retry loop
    /// neither re-counts nor re-journals a divergence that has not changed.
    finalize_refused_live: Option<(&'static str, u64)>,
    /// Issue #200: monotonic-ms when this node first entered the continuous
    /// *lagging + outstanding unserved body ask* state, or `None` when that
    /// condition is not holding. Progress (a requested body arrived) or leaving
    /// the condition clears it.
    unserved_since_ms: Option<u64>,
    /// Issue #200: the unobtainable-body exemption is armed. Once set, stays set
    /// until the applied tip is back on the main chain at zero lag — so a sibling
    /// mined under the exemption can be extended until fork choice adopts it
    /// (equal-work keeps the incumbent tip, so one sibling alone is not enough).
    state_tip_mine_ready: bool,
    /// Issue #229: the applied tip height as of the last [`Self::observe_body_fetch`]
    /// call — the previous sample of the one quantity a stranding freezes.
    stip_observed: u64,
    /// Issue #229: monotonic-ms when the applied tip last **changed**, or `None`
    /// before the first observation. See [`Self::ask_set_observation`] for why any
    /// change — including a rewind, which lowers it — resets this.
    stip_moved_ms: Option<u64>,
    /// Issue #229: monotonic-ms of the most recent observation, so the stall
    /// duration is measured against the same clock the re-ask ladder uses.
    stall_now_ms: u64,
    /// Issue #229: outstanding body asks as of the last observation. Kept because
    /// the arming predicate needs it and nothing else on the adapter can see it —
    /// the in-flight map lives in `P2pNode`.
    breq_observed: usize,
}

/// **A finalize record this node refused to write, and why** (issue #204, from the
/// coordinator's 2026-08-02 correction to #203).
///
/// There are three finalized heads on a running node and only one of them survives
/// a restart:
///
/// | # | head | written by | durable |
/// |---|---|---|---|
/// | 1 | [`FinalityTracker`] | `try_finalize`, on quorum | rehydrated from #3 at `open` |
/// | 2 | the adapter's fork-choice [`ChainState`] | `set_finalized` | no |
/// | 3 | the state machine's chain store | `Node::finalize` → snapshot + `Finalize` log | **yes** |
///
/// `final=` and `fid=` on the telemetry line read **#1**. `Snapshot.finalized` is
/// written from **#3**. Both writes to #2 and #3 used to be spelled `let _ =`, so a
/// refusal was **not logged, not counted, not on telemetry, and indistinguishable
/// from success** — which is how node1 could run for hours with an operator-facing
/// head of 1056 and a durable head of 1048 and no instrument able to say so.
///
/// `Ok(false)` from `Node::finalize` means head #1 and head #3 have diverged **at
/// that instant, on this node, at a known height, for a known reason**. It is the
/// cheapest and earliest detection point this class will ever have.
/// The first four bytes of a hash, rendered like every other short id on the
/// journal lines (`REWIND`, `ROUND`'s `cpid`, `TELEMETRY`'s `fid`).
fn finalize_hex8(h: &Hash32) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// **Why a head refused a finalize record — the store's own verdict, typed** (issue
/// #241).
///
/// This was a `&'static str` chosen by an `if / else if / else` over re-read store
/// state. Two things were wrong with that and only one of them was visible on
/// `t0-wan-9`:
///
/// 1. the chain of `else if`s ended in an **unconditional `else`**, so a
///    [`FinalizeMarkError`] variant nobody had thought about would have rendered as
///    `off-finality` — a confident, wrong attribution, and no compiler complaint;
/// 2. it was a *second implementation* of [`ChainState::set_finalized`]'s decision
///    and could disagree with the first (it tested the checkpoint's claimed height
///    where the store tests the stored header's, and asked the block map where the
///    store asks the header map).
///
/// Both are closed by construction here: the only way in from the store's refusal is
/// [`From<FinalizeMarkError>`], which is an exhaustive `match`, and the only way out
/// to the journal line is [`Self::as_str`], which is another. **A new
/// `FinalizeMarkError` variant is a compile error in two places and cannot render as
/// a placeholder.**
///
/// [`ChainState::set_finalized`]: qlab_devnet::chain::ChainState::set_finalized
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizeRefusalReason {
    /// **This head does not hold the block the checkpoint names.** The `t0-wan-9`
    /// refusal, and the `#229` shape: fork choice is at the tip, the state machine's
    /// bodies are short, a quorum arrives for a block the durable head has never
    /// applied.
    NotHeld,
    /// The block's height does not strictly advance this head's finalized point.
    NotAdvancing,
    /// The block is known, but does not descend from this head's finalized point —
    /// finalizing it would be a reorg past finality.
    OffFinality,
    /// The append to the durable log failed. Not a store verdict at all: the store
    /// said yes and the disk said no.
    Persist,
}

impl FinalizeRefusalReason {
    /// The `why=` token as it reaches the journal line and the container log.
    ///
    /// 🔴 **`NotHeld` renders `not-held`, and it rendered `unknown` before #241.**
    /// The rename is the whole operator-facing half of that issue. `unknown` is the
    /// same word this codebase uses for *"we could not determine"* on the line
    /// immediately above it (`mready=unknown`, `MineGate::Unknown`), so on one
    /// `grep unknown` over a container log the two meanings are indistinguishable —
    /// and on `#229` the session holding the host read it the wrong way and
    /// explicitly declined to interpret the line. The other three tokens were never
    /// ambiguous and are byte-identical to what they were.
    pub fn as_str(&self) -> &'static str {
        match self {
            FinalizeRefusalReason::NotHeld => "not-held",
            FinalizeRefusalReason::NotAdvancing => "not-advancing",
            FinalizeRefusalReason::OffFinality => "off-finality",
            FinalizeRefusalReason::Persist => "persist",
        }
    }
}

impl From<FinalizeMarkError> for FinalizeRefusalReason {
    /// The one door from the store's typed refusal into the journal's typed reason.
    /// **Exhaustive on purpose** — this is the compile-time guarantee acceptance item
    /// 2 of issue #241 asks for, and it only holds while there is no `_ =>` arm here.
    fn from(e: FinalizeMarkError) -> Self {
        match e {
            FinalizeMarkError::Unknown => FinalizeRefusalReason::NotHeld,
            FinalizeMarkError::NotAdvancing => FinalizeRefusalReason::NotAdvancing,
            FinalizeMarkError::NotDescendantOfFinalized => FinalizeRefusalReason::OffFinality,
        }
    }
}

impl std::fmt::Display for FinalizeRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeRefusal {
    /// Which head refused: `"chain"` (#2, fork choice) or `"state"` (#3, durable).
    pub head: &'static str,
    /// The checkpoint height the refused record was for.
    pub height: u64,
    /// The block the checkpoint names.
    pub hash: Hash32,
    /// Why, in the store's own terms. Typed since issue #241 — see
    /// [`FinalizeRefusalReason`].
    pub why: FinalizeRefusalReason,
}

impl std::fmt::Display for FinalizeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FINALIZE refused head={} h={} cp={} why={}",
            self.head,
            self.height,
            finalize_hex8(&self.hash),
            self.why.as_str()
        )
    }
}

/// How many [`FinalizeRefusal`]s are held for the journal before the oldest is
/// dropped. Same rule and same reason as [`MAX_JOURNALLED_REWINDS`]: the newest
/// event is the one an operator is looking at, and the counter is the lossless
/// record so a drop is visible as the count exceeding what was journalled.
pub const MAX_JOURNALLED_FINALIZE_REFUSALS: usize = 32;

/// How many [`RewindReport`]s are held for the journal before the oldest is dropped
/// (issue #162). Small on purpose: this is a detail buffer for a rare event, and
/// `qumbra_state_rewinds_total` is the lossless record.
pub const MAX_JOURNALLED_REWINDS: usize = 16;

/// How far above the state machine's applied tip a body is worth holding
/// (issue #130 (a)). Bitcoin's in-flight download window, reused as the shape rather
/// than the number: past this, a body cannot become applicable without material this
/// node has no way to request.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_PENDING_BODY_HEIGHTS: u64 = 1024;

/// **How far below its applied tip this node will hold material to rewind onto**
/// (issue #162) — the depth of divergence it is prepared to recover from without a
/// re-sync.
///
/// It is the counterpart to [`MAX_PENDING_BODY_HEIGHTS`] on the other side of the
/// applied tip, and it exists because #162's fix requires holding bodies at and
/// below that tip: without a floor, "hold the sibling" would mean "hold every fork
/// anyone ever offered", and the entry cap would be spent on ancient branches
/// instead of on the gap.
///
/// **8 × the checkpoint cadence (`CHECKPOINT_CADENCE_BLOCKS` = 8).** The cadence is
/// the natural unit: a block more than a few cadences below the tip is finalized on
/// a healthy net, and [`qlab_node::MemNode::rewind_to`] refuses to cross the
/// finalized head, so material below that is unusable by construction. The ×8 is
/// headroom for a *stalled* committee — the one regime in which nothing finalizes
/// and a divergence can legitimately run deep — and it is not derived from any
/// measurement of a real reorg, because this net has not produced one to measure.
/// The observed T0 wedge had a fork depth of 1.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_REWIND_DEPTH: u64 = 8 * qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// **How many checkpoint cadences of continuous lagging-with-unserved-asks before
/// a node may mine on its verified state tip** (issue #200).
///
/// The duty gate (#130 (a)) refuses to mine while the applied view is stale —
/// Ethereum's *"an optimistic validator MUST NOT produce a block"*. That rule is
/// right. On 2026-08-01 it composed with a body that **no host ever applied**
/// (#197 / #198's archive check) into a permanent halt: every node held a header
/// whose body exists nowhere, every node asked (`breq>0`), nobody could serve, and
/// nobody would mine the sibling that would break the deadlock.
///
/// This constant is the **exhaustion**, not the impatience, half of the exemption
/// that re-opens that loop:
///
/// | too small | a node merely slow to be served forks the chain for nothing |
/// | too large | the net stays halted longer than it must |
///
/// **N = 2**, not tuned to today's multi-hour incident:
///
/// - **1 cadence** (one 10-min bucket at the 75 s target) is one long partition or
///   one overloaded peer away from a needless fork. A single body-request cycle is
///   15 s (`BODY_REQUEST_TIMEOUT_MS`); one cadence is ~40 re-asks across the mesh —
///   enough to try every peer many times, but not enough margin for a WAN blip that
///   is still progress-bound.
/// - **2 cadences** is two full cadence windows of *continuous non-service* with an
///   outstanding ask. Any body that actually arrives resets the clock (progress is
///   "a requested body was satisfied", not "lag moved for any reason"), so a node
///   that is lagging **and being served** never reaches the threshold — that is the
///   half `the_duty_gate_still_refuses_to_mine_while_lagging_and_receiving` locks.
/// - **Not wall-clock seconds as a bare constant**: the threshold is
///   `N × CHECKPOINT_CADENCE_BLOCKS × block_time_secs` of monotonic time. Cadence is
///   the unit because the checkpoint grid is this net's natural progress quantum
///   (same precedent as [`MAX_REWIND_DEPTH`]); block time is the conversion because
///   while the chain is halted no height advances, and a loop-count threshold would
///   be wrong by the #107 factor (30 s vs 131 s loop period) between images.
///
/// At the live 75 s target this is **20 minutes**. At the in-process sim's 2 s
/// target it is 32 s of sim time. Either way it is network-parameter-relative, not
/// incident-tuned.
///
/// `[devnet-placeholder]`, testnet-tunable, **NOT frozen**.
pub const UNOBTAINABLE_BODY_CADENCES: u64 = 2;

/// Hard entry cap on the pending-body window (issue #130 (a)).
pub const MAX_PENDING_BODIES: usize = 512;

/// Byte budget for the pending-body window (issue #130 (a)).
///
/// **Two caps, because either alone is wrong**, and #135 is the reason it is stated
/// rather than assumed: a coinbase-only body is tens of bytes, so a byte budget alone
/// would admit millions of entries; a proof-carrying body is ~145 kB (#135's
/// measurement), so an entry cap alone would admit ~74 MB per 512 entries on hosts
/// sized for a coinbase-only chain. The binding cap is whichever bites first.
pub const MAX_PENDING_BODY_BYTES: usize = 32 * 1024 * 1024;

/// What a duty refused for state lag says (issue #130 (a)). Named because it is a
/// node declaring its own view stale, which is a different statement from any
/// judgement about the object or its sender.
pub const STATE_LAG_REASON: &str = "state lag: this node's applied state is behind its chain";

/// What a body refusal says when this node **could not judge** the anchor rule
/// (issue #134). Named for the same reason [`STATE_LAG_REASON`] is: it is a node
/// declaring its own view unable to answer, which is a different statement from
/// any judgement about the body or its sender — and the difference is exactly what
/// [`IngestOutcome::is_peer_fault`] reads.
pub const UNJUDGED_ANCHOR_REASON: &str =
    "unjudged anchor: this node cannot evaluate anchor finality at this position";

/// Whether a [`BodyError`] is a statement about the **body** or a statement about
/// **this node's chain position** (issue #134).
///
/// This is the boundary the issue asked to have named rather than patched a third
/// time, and it is the one distinction the old `Err(_) => Rejected("bad body")`
/// wildcard erased:
///
/// - [`Self::Intrinsic`] — the verdict is a function of `(header, body)` alone. Every
///   node, at every height, from any position, computes the same answer. A peer that
///   sends one is at fault, always, and nothing about the receiver's state can excuse
///   it. The binding, the coinbase payee, the posted fee, the in-block nullifier
///   uniqueness and the proof are all of this kind.
/// - [`Self::Positional`] — the verdict is computed **against the receiver's own
///   applied state**, so two honest nodes at different positions answer differently
///   for the same body. `AnchorNotFinal` is the only one today:
///   [`qlab_node::NodeState::is_valid_anchor`] reads the receiver's root index, its
///   finalized head and its applied tip, and a joiner has none of the three at the
///   height it is being served. Charging for it bans honest peers for serving correct
///   history — the whole of #134.
///
/// The match on it is **exhaustive on purpose** (no wildcard arm): a new `BodyError`
/// variant must declare which kind it is, and cannot inherit "peer fault" by silence
/// the way `AnchorNotFinal` did.
enum BodyFault {
    /// Same verdict on every node ⇒ always the sender's fault. Carries the reject
    /// reason string.
    Intrinsic(&'static str),
    /// Verdict depends on the receiver's position ⇒ the sender's fault only when this
    /// node occupies the position the rule is defined at
    /// ([`NodeAdapter::anchor_verdict_is_authoritative`]). Carries the reject reason
    /// used when it *is* chargeable.
    Positional(&'static str),
}

/// The retained body-surface weight shared with the #135 serving cache, so the
/// two byte budgets stay comparable. Fixed container/map overhead is bounded by
/// the separate entry caps; the peer-controlled proof and payee data is metered.
fn body_weight(body: &BlockBody) -> usize {
    crate::n1::txs_weight(&body.txs)
        + crate::n1::coinbase_payees_weight(&body.coinbase_payees)
}

/// The payout key a node mines to when no wallet has been configured (issue #101).
///
/// It is deliberately **non-zero**, because `[0; 4]` is rejected outright
/// (`BodyError::MissingCoinbasePayee`) and every in-process sim, soak and docker
/// rehearsal in this repo mines without a wallet; a zero default would make them
/// all produce invalid blocks. It is equally deliberately **unspendable in
/// practice**: it is a fixed constant, not derived from any `(sk, d)`, so nobody
/// holds a spend key for it and coins mined to it are burned.
///
/// That is the honest state of affairs for a node that was never told where to
/// pay itself, and it is loud rather than silent: [`Self::set_miner_rkm`] is what
/// a real miner calls, and `qumbra-node` warns at startup when it has nothing to
/// call it with.
pub const UNCONFIGURED_MINER_RKM: [u64; 4] =
    [0x1101_1101_1101_1101, 0x1101_1101_1101_1101, 0x1101_1101_1101_1101, 0x1101_1101_1101_1101];

/// Layer-attributed ingest refusal counts (issue #74; extended by #134).
///
/// They are deliberately separate because they are different claims about the
/// upgrade. `halt_ignored` is the **release** layer: this node has stopped, so it
/// will not act on the block (and does not blame the sender). `pow_rejected` is the
/// **header-validation** layer: under the post-halt rule domain the block's PoW does
/// not meet the target, so it is invalid, not merely unwanted. `unjudged_anchor` is
/// the **receiver** layer: nothing is wrong with the block or the sender, this node
/// simply cannot evaluate the rule from where it stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestCounters {
    /// Headers/blocks not acted on because this release is halted (release layer).
    pub halt_ignored: u64,
    /// Headers rejected because the PoW value did not meet the target
    /// (header-validation layer).
    pub pow_rejected: u64,
    /// Bodies neither applied nor charged because this node could not evaluate anchor
    /// finality at its own position (receiver layer, issue #134).
    ///
    /// **This is the joiner's instrument.** A number that climbs while `slag=` stays
    /// pinned is a node that is being served history it cannot judge — the state #134
    /// describes, which before this counter was indistinguishable from "nobody would
    /// talk to me" because the only visible symptom was an outbound set going quiet.
    pub unjudged_anchor: u64,
}

impl<P: PowEngine, V: TxVerifier + Clone> NodeAdapter<P, V> {
    /// New adapter from a genesis committee (wrapped at the frozen epoch length —
    /// behaves as the M6 static set for sub-epoch sims) plus the PoW engine and
    /// injected verifier. Genesis is derived from `sim.genesis_difficulty` so
    /// every node in a mesh shares one genesis.
    pub fn new(committee: CommitteeState, pow: P, verifier: V, sim: SimConfig) -> Self {
        let ec = EpochCommittee::genesis(EpochSchedule::new(EPOCH_LENGTH_BLOCKS), committee);
        Self::with_epoch(ec, pow, verifier, sim)
    }

    /// New (in-memory) adapter from an explicit [`EpochCommittee`] (membership/epoch
    /// tests use a small epoch length to cross boundaries).
    pub fn with_epoch(committee: EpochCommittee, pow: P, verifier: V, sim: SimConfig) -> Self {
        let state = MemNode::in_memory(genesis_block(sim.genesis_difficulty, 0));
        Self::assemble(GenesisForm::V4, committee, pow, verifier, sim, state)
    }

    /// New **disk-backed** adapter (M10-T0-1, `qumbra-node` binary): the state
    /// machine is opened at `dir` and resumes restart-safely (atomic snapshot +
    /// block-log tail), so accepted blocks and finalizations persist across
    /// restarts. Wraps `committee` at the frozen epoch length (like [`Self::new`]).
    /// [`Self::save_snapshot`] flushes the derived state on graceful shutdown.
    ///
    /// **Committee punishments are restored here too (issue #133).** The `committee`
    /// argument is always a fresh all-Active genesis roster — that is what the binary
    /// can build from the genesis file, and it is the whole defect: a member proven to
    /// have equivocated came back Active with a full bond on every restart. The
    /// punishment ledger in `dir` is replayed onto that roster **before** the epoch
    /// machinery advances, so the forced exits at each boundary drop exactly the
    /// members a node that never restarted had already dropped. A ledger this binary
    /// cannot honour is an error, never an empty start — see [`crate::punish`].
    pub fn open(
        dir: impl AsRef<std::path::Path>,
        committee: CommitteeState,
        pow: P,
        verifier: V,
        sim: SimConfig,
    ) -> Result<Self, NodeError> {
        Self::open_for(GenesisForm::V4, dir, committee, pow, verifier, sim)
    }

    /// [`Self::open`] under an explicit genesis form (lab #470 stage 4a) — the
    /// binary's seam: the form comes off the loaded genesis file BEFORE the
    /// datadir is replayed, so every replay identity, the stored-binding form
    /// and this adapter's chain/rules are keyed consistently from one value.
    pub fn open_for(
        form: GenesisForm,
        dir: impl AsRef<std::path::Path>,
        committee: CommitteeState,
        pow: P,
        verifier: V,
        sim: SimConfig,
    ) -> Result<Self, NodeError> {
        let dir = dir.as_ref().to_path_buf();
        let ec = EpochCommittee::genesis(EpochSchedule::new(EPOCH_LENGTH_BLOCKS), committee);
        let state = MemNode::open_for(form, &dir, genesis_block_for(form, sim.genesis_difficulty, 0))?;
        let mut me = Self::assemble(form, ec, pow, verifier, sim, state);
        me.dir = Some(dir.clone());
        // Restart-resume the in-memory fork-choice header chain from the persisted
        // block log: the state machine is the durable source of truth, so on open
        // the adapter adopts its restored ChainState (headers + finalized head),
        // trusting the log exactly as `MemNode::replay` does (no PoW re-run).
        // Otherwise a restarted node would start with an empty header view and have
        // to re-sync everything it already had on disk.
        let resumed = me.state.chain().chain().clone();
        me.chain = resumed;
        // The state-machine chain already restored and proved this durable point.
        // Rehydrate the committee tracker through its named recovery constructor:
        // startup is not a fresh quorum event and must never be routed through
        // `try_finalize`. Without this, the chain/anchor head survives but the
        // operator-facing `final=` / `fid=` pair resets to absent on every restart.
        if let Some(checkpoint) = me.state.restored_checkpoint() {
            me.finality = FinalityTracker::from_restored_checkpoint(checkpoint);
        }
        // Punishments BEFORE the epoch advance: a tombstone's effect at a boundary is
        // to shrink the roster and reindex it, and applying it afterwards would punish
        // whichever member had shifted into that index.
        me.restore_punishments(&dir)?;
        me.advance_epoch();
        Ok(me)
    }

    /// Replay `dir`'s punishment ledger onto the genesis committee this adapter was
    /// opened with (issue #133).
    ///
    /// Refuses — returns `Err` — for any ledger that exists and cannot be honoured.
    /// A ledger that is merely **absent** is reported, not refused, and this is a
    /// judgement call worth naming: an absent ledger on a data dir that already holds
    /// chain history is a pre-#133 data dir whose punishment history is *unknowable*,
    /// and refusing there would brick every existing data dir on upgrade. So it is
    /// recorded in [`PunishmentRestore`] and printed loudly by the binary instead —
    /// the "or reports" half of the rule, not a silent fall-through.
    fn restore_punishments(&mut self, dir: &std::path::Path) -> Result<(), NodeError> {
        let loaded = punish::load(dir).map_err(NodeError::Io)?;
        let absent = loaded.is_none();
        let mut records = loaded.unwrap_or_default();
        punish::sort_records(&mut records);
        let tip = self.chain.tip_height();
        let tombstoned = punish::replay(&mut self.committee, &records, tip)
            .map_err(|e| NodeError::Io(e.to_io()))?;
        self.punish_restore = PunishmentRestore {
            records: records.len(),
            tombstoned,
            ledger_absent_on_populated_datadir: absent && tip > 0,
        };
        self.punishments = records;
        // Write the ledger out when this data dir had none, so a *later* restart can
        // tell "this node has recorded no punishments" from "nobody ever asked".
        if absent {
            punish::save(dir, &self.punishments).map_err(NodeError::Io)?;
        }
        Ok(())
    }

    /// What the last [`Self::open`] found in the punishment ledger and did with it.
    /// Empty and all-zero for an in-memory adapter.
    pub fn punishment_restore(&self) -> &PunishmentRestore {
        &self.punish_restore
    }

    /// What the durable state-machine open recovered from disk.
    pub fn recovery_report(&self) -> &RecoveryReport {
        self.state.recovery_report()
    }

    /// Every equivocation this node has adjudicated — the in-memory mirror of the
    /// durable ledger. One record per tombstoned member.
    pub fn punishments(&self) -> &[EquivocationEvidence] {
        &self.punishments
    }

    /// Flush the state machine's derived state to an atomic on-disk snapshot
    /// (no-op for an in-memory adapter). Called on graceful shutdown = snapshot
    /// flush (issue #62 item 1).
    pub fn save_snapshot(&self) -> Result<(), NodeError> {
        self.state.save_snapshot()
    }

    /// Assemble the adapter around an already-built state machine (shared by the
    /// in-memory and disk-backed constructors).
    fn assemble(
        form: GenesisForm,
        committee: EpochCommittee,
        pow: P,
        verifier: V,
        sim: SimConfig,
        state: MemNode,
    ) -> Self {
        let genesis = BlockHeader::genesis_for(form, sim.genesis_difficulty, 0);
        NodeAdapter {
            chain: ChainState::new_for(form, genesis),
            pow,
            state,
            mempool: Mempool::default(),
            committee,
            finality: FinalityTracker::new(),
            signing: SigningWindow::new(DOWNTIME_JAIL_WINDOW, DOWNTIME_JAIL_THRESHOLD_PCT),
            votes_seen: HashMap::new(),
            tally: VoteTally::new(),
            seen_checkpoints: HashSet::new(),
            verifier,
            wire_ids: HashMap::new(),
            schedule: KeyBlockSchedule::new(sim.key_epoch_blocks, sim.key_epoch_lag),
            block_time: sim.block_time_secs,
            nonce_budget: sim.mine_nonce_budget,
            grind: None,
            clock: 0,
            mining_clock: MiningClock::default(),
            rules: ChainRules { form, halt: qlab_devnet::halt::RuleSchedule::V1_0 },
            ingest_counters: IngestCounters::default(),
            rounds: RoundLedger::default(),
            metrics: Metrics::new(),
            miner_rkm: UNCONFIGURED_MINER_RKM,
            pending_bodies: BTreeMap::new(),
            pending_bytes: 0,
            dir: None,
            punishments: Vec::new(),
            punish_restore: PunishmentRestore::default(),
            rewinds: Vec::new(),
            finalize_refusals: Vec::new(),
            finalize_refused_total: 0,
            finalize_refused_live: None,
            unserved_since_ms: None,
            state_tip_mine_ready: false,
            stip_observed: 0,
            stip_moved_ms: None,
            stall_now_ms: 0,
            breq_observed: 0,
        }
    }

    /// Set where this node's mined coinbase notes are paid (issue #101): the raw
    /// `rkm` of a miner-controlled address, as `qlab_wallet::Wallet::rkm(d)`
    /// computes it. Until this is called the node mines to
    /// [`UNCONFIGURED_MINER_RKM`], which nobody can spend.
    pub fn set_miner_rkm(&mut self, rkm: [u64; 4]) {
        self.miner_rkm = rkm;
    }

    /// The payout key this node currently mines to.
    pub fn miner_rkm(&self) -> [u64; 4] {
        self.miner_rkm
    }

    /// Select the header-timestamp [`MiningClock`]. The binary (`qumbra-node`)
    /// calls this with [`MiningClock::WallClock`] after `open`; sims/tests leave
    /// the deterministic default.
    pub fn set_mining_clock(&mut self, clock: MiningClock) {
        self.mining_clock = clock;
    }

    /// Select the round-diagnostics clock (issue #87). Same seam and same default
    /// as [`Self::set_mining_clock`]: sims/tests keep [`ObsClock::Deterministic`],
    /// so round records carry counts and rosters but no fabricated timings and the
    /// N7 soak stays reproducible; the binary opts into [`ObsClock::WallClock`],
    /// which is the only basis on which "were votes still arriving?" can be asked.
    pub fn set_obs_clock(&mut self, clock: ObsClock) {
        self.rounds = RoundLedger::new(clock);
        self.metrics.declare_roster(self.committee.state().size());
    }

    /// The per-round diagnostics ledger (issue #87).
    pub fn rounds(&self) -> &RoundLedger {
        &self.rounds
    }

    /// Mutable ledger — the run loop drains closed records from it, and the
    /// proposer path notes the slots this node proposed.
    pub fn rounds_mut(&mut self) -> &mut RoundLedger {
        &mut self.rounds
    }

    /// The source-side metric registry (issue #87).
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Mutable registry — the run loop accumulates regime residency into it.
    pub fn metrics_mut(&mut self) -> &mut Metrics {
        &mut self.metrics
    }

    /// Drain the rounds that have closed since the last call: each is folded into
    /// the metric aggregates **once** and then handed back for the journal.
    ///
    /// One drain point on purpose. Two consumers of the same queue is how a record
    /// gets counted twice or emitted zero times, and a diagnostics surface that
    /// miscounts is worse than none.
    pub fn drain_rounds(&mut self) -> Vec<qlab_node::round::RoundRecord> {
        let closed = self.rounds.take_emitted();
        for r in &closed {
            self.metrics.observe_round(r);
        }
        closed
    }

    /// Record a finality advance: how far it jumped in height, how far in chain
    /// time, and the stall depth it was carrying when it cleared.
    ///
    /// Chain time is observed only when **both** checkpoint blocks are known
    /// locally — a node that finalized against a block it has not downloaded yet has
    /// no basis for the interval, and a fabricated one would poison the histogram.
    fn observe_finality_advance(&mut self, cp: &Checkpoint, prev: Option<Checkpoint>, tip: u64) {
        // Finalizing genesis is the bootstrap act, not an advance: it would record a
        // zero-block jump and a stall depth equal to the tip, in a histogram whose
        // whole job is to show how far finality fell behind. Same rule, and the same
        // reason, as `RoundLedger::tracked` refusing to journal height 0 as a round.
        if cp.height == 0 {
            return;
        }
        let prev_height = prev.map(|p| p.height);
        let blocks = cp.height.saturating_sub(prev_height.unwrap_or(0));
        let secs = match (prev, self.chain.header(&cp.block_hash)) {
            (Some(p), Some(now_hdr)) => self
                .chain
                .header(&p.block_hash)
                .map(|prev_hdr| now_hdr.timestamp.saturating_sub(prev_hdr.timestamp)),
            _ => None,
        };
        let stall = match prev_height {
            Some(h) => tip.saturating_sub(h),
            None => tip,
        };
        self.metrics.observe_finality_advance(blocks, secs, stall);
    }

    /// The roster context for a checkpoint slot, **read** from the committee state
    /// for that height (never re-derived here): roster size, active members, and the
    /// quorum threshold in force. This is what makes a round record answerable —
    /// `have=11 need=15 active=21` is a diagnosis, `have=11` alone is not.
    ///
    /// Carries this node's own tip height too (issue #105): the ledger decides
    /// whether a slot is a live round or history this node walked through from the
    /// slot's distance to that tip, and reading it here — beside the roster, from
    /// the same local state, at the same instant — is what keeps that judgement a
    /// measurement rather than a mode the node believes itself to be in.
    pub fn slot_context(&self, height: u64) -> SlotContext {
        let cstate = self.committee.state_for_height(height);
        SlotContext {
            height,
            epoch: self.committee.schedule().epoch_of(height),
            roster: cstate.size(),
            active: cstate.active_count(height),
            need: cstate.quorum_threshold(),
            tip: self.chain.tip_height(),
        }
    }

    /// Override the downtime signing window (tests use a small window so it fills).
    pub fn set_signing_window(&mut self, window: usize, threshold_pct: u64) {
        self.signing = SigningWindow::new(window, threshold_pct);
    }

    /// Install the running release's halt/rule schedule (issue #74).
    ///
    /// Called once, at startup, with the value derived from the binary's
    /// compile-time `RELEASE` constant. This is plumbing, not a knob: nothing in
    /// the config file, the CLI, or the environment can reach it (H1), and the
    /// default is [`RuleSchedule::V1_0`].
    pub fn set_rule_schedule(&mut self, rules: RuleSchedule) {
        self.rules.halt = rules;
    }

    /// Install the complete chain rules — the genesis-keyed form set plus the
    /// halt schedule — in one act (lab #470: the one selection point's
    /// installation; `qumbra-node` composes the value from the loaded genesis
    /// file's `format_version` and the compile-time `RELEASE` + halt marker).
    pub fn set_chain_rules(&mut self, rules: ChainRules) {
        self.rules = rules;
        // Block identities are the header hash under the net's form. The
        // binary's path arrives here with the form already installed at
        // construction (`open_for`), so these are no-ops there; for an
        // in-memory adapter built form-less, the one legal moment to re-key is
        // before anything was inserted/applied — both re-keys panic otherwise,
        // making install-before-run a checked invariant across BOTH identity
        // holders (lab #470 stage 4a: the invariant extended to the state
        // node, per the stage-1 ruling's condition).
        self.state.rekey_genesis(rules.form);
        // The fork-choice chain is re-adopted FROM the re-keyed state node —
        // one source for the genesis identity and its re-bound header, exactly
        // like `open`'s restart-resume does.
        self.chain = self.state.chain().chain().clone();
    }

    /// The installed rule schedule (the halt half of [`Self::chain_rules`]).
    pub fn rules(&self) -> &RuleSchedule {
        &self.rules.halt
    }

    /// The installed chain rules (form + halt).
    pub fn chain_rules(&self) -> &ChainRules {
        &self.rules
    }

    /// Layer-attributed ingest refusal counts (issue #74 drill evidence).
    pub fn ingest_counters(&self) -> IngestCounters {
        self.ingest_counters
    }

    /// The height this node halts at, if its release carries one.
    pub fn halt_at(&self) -> Option<u64> {
        self.rules.halt.halt_at()
    }

    /// Whether this node is at or past its halt height — i.e. whether the halt has
    /// actually engaged, as opposed to merely being scheduled. The run loop uses
    /// this to write the durable halt marker.
    pub fn is_halted_at_tip(&self) -> bool {
        self.rules.halt.halt_at().is_some_and(|h| self.chain.tip_height() >= h)
    }

    // --- read-only accessors (harness / assertions) ---
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }
    pub fn state(&self) -> &MemNode {
        &self.state
    }
    pub fn state_mut(&mut self) -> &mut MemNode {
        &mut self.state
    }
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }
    pub fn committee(&self) -> &EpochCommittee {
        &self.committee
    }
    pub fn finality(&self) -> &FinalityTracker {
        &self.finality
    }

    // --- issue #130 (a): the two chain views, and the duties that need them ----

    /// **The gap between this node's two chain views** — the state machine's applied
    /// tip against fork choice's header tip (issue #130).
    ///
    /// One definition, shared with the telemetry surface and with
    /// [`qlab_node::telemetry::SupplyCoverage`], so a duty cannot be refused on one
    /// reading of "am I behind" while a figure is published on another.
    pub fn state_lag(&self) -> StateLag {
        StateLag::new(self.state.tip_height(), self.chain.tip_height())
    }

    /// **The identity of the applied tip, and whether it is on the chain this node
    /// is following** (issue #162 finding 6) — the other half of the same question
    /// [`Self::state_lag`] answers by height.
    ///
    /// `state_lag()` cannot separate a node three blocks behind from a node whose
    /// state machine is stranded on a losing sibling and will never catch up
    /// (`buffer_body` drops the one body that could rebuild it, and
    /// `qlab_node::Node` cannot rewind). Both print a nonzero `slag=`. Only the
    /// comparison here distinguishes them, and it is one lookup:
    /// `state.tip_hash() != chain.main_chain_hash_at(state.tip_height())`.
    ///
    /// The main-chain lookup goes through [`ChainView::main_chain_hash_at`] rather
    /// than reaching into `self.chain` — one definition of "what is on the main
    /// chain at height h", shared with sync.
    pub fn applied_tip(&self) -> AppliedTip {
        let height = self.state.tip_height();
        AppliedTip::new(height, self.state.tip_hash(), self.main_chain_hash_at(height))
    }

    /// Bodies currently held awaiting the state tip, and their weight in bytes.
    /// Operator-visible so buffer occupancy is a measurement, not an inference.
    pub fn pending_bodies(&self) -> (usize, usize) {
        (self.pending_bodies.len(), self.pending_bytes)
    }

    /// How many times a duty was refused because the state machine was lagging —
    /// read from the one metric registry, never from a second ledger.
    pub fn lag_refusals(&self, duty: &str) -> u64 {
        self.metrics.lag_refusals(duty)
    }

    /// **Issue #200 — is the unobtainable-body exemption armed?**
    ///
    /// When true, [`Self::mine_block`] will produce a child of the **state tip**
    /// rather than refuse (or rather than extend a fork-choice tip this node cannot
    /// verify). Operator-visible as `uex=` on `TELEMETRY`: an operator seeing a
    /// node mine while `slag>0` needs to know it was this exemption and not a bug.
    pub fn state_tip_mine_ready(&self) -> bool {
        self.state_tip_mine_ready
    }

    /// How many blocks this node has mined under the #200 exemption.
    pub fn state_tip_mines(&self) -> u64 {
        self.metrics.state_tip_mines()
    }

    /// Duration of continuous unserved lag (ms) required before the exemption
    /// arms — `UNOBTAINABLE_BODY_CADENCES × CHECKPOINT_CADENCE_BLOCKS × block_time`
    /// in milliseconds. Exposed so tests can drive the clock to the threshold
    /// without hard-coding the arithmetic.
    pub fn unobtainable_threshold_ms(&self) -> u64 {
        UNOBTAINABLE_BODY_CADENCES
            .saturating_mul(qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS)
            .saturating_mul(self.block_time)
            .saturating_mul(1_000)
    }

    /// **Issue #200 — feed the duty-gate exemption the body-fetch facts it keys on.**
    ///
    /// Called once per `P2pNode::tick` after body requests have been (re)issued, so
    /// `outstanding_breqs` already reflects this tick's ask set.
    ///
    /// - `body_progress`: a historical body **we asked for** was satisfied this
    ///   tick. That is the "being served" half of the distinction; lag moving for
    ///   any other reason (including our own exemption-mined sibling applying)
    ///   is deliberately not progress.
    /// - Leaving lag, or stopping asking, clears the unserved window. The armed
    ///   exemption itself only clears when the applied tip is back on the main
    ///   chain at zero lag — see [`Self::state_tip_mine_ready`].
    pub fn observe_body_fetch(
        &mut self,
        now_ms: u64,
        outstanding_breqs: usize,
        body_progress: bool,
    ) {
        // ── Issue #229, observation only. ────────────────────────────────────
        // Kept in its own block, ahead of every early return below, and writing
        // only to its own fields: #200's latch (`unserved_since_ms`,
        // `state_tip_mine_ready`) is byte-identical after this change, which is
        // the property that keeps this baton on the instrumentation side of the
        // fence.
        //
        // It rides in this call rather than in one of its own because the arming
        // predicate needs `outstanding_breqs`, and this is the only per-tick hook
        // that has it — the in-flight map lives in `P2pNode`.
        self.observe_state_stall(now_ms, outstanding_breqs);

        let lagging = self.state_lag().is_lagging();
        let on_main_caught_up =
            !lagging && !self.applied_tip().is_off_main_chain();

        if on_main_caught_up {
            // Healthy: applied tip is the main-chain tip. Disarm everything.
            self.unserved_since_ms = None;
            self.state_tip_mine_ready = false;
            return;
        }

        if body_progress {
            // A requested body arrived — we are being served. Reset the unserved
            // window; if the exemption had armed on a false start, drop it too so
            // a lagging-and-receiving node falls back under the duty gate.
            self.unserved_since_ms = None;
            self.state_tip_mine_ready = false;
            // If still lagging and still asking, the window restarts from now so a
            // later stall can still arm.
            if lagging && outstanding_breqs > 0 {
                self.unserved_since_ms = Some(now_ms);
            }
            return;
        }

        if !lagging {
            // Heights match but we may be off-main (exemption-mined sibling that
            // has not yet taken fork choice). Keep the armed flag so we continue
            // mining on the state tip until the branch wins; do not start a new
            // unserved window (there is nothing outstanding to be unserved for).
            self.unserved_since_ms = None;
            return;
        }

        // Lagging.
        if outstanding_breqs == 0 {
            // Not asking — cannot conclude unobtainable. Do not arm; if already
            // armed (e.g. peers dropped mid-recovery), leave the flag alone so a
            // recovery already in flight can finish on the state tip.
            self.unserved_since_ms = None;
            return;
        }

        // Lagging + asking + no progress this tick.
        let since = *self.unserved_since_ms.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= self.unobtainable_threshold_ms() {
            self.state_tip_mine_ready = true;
        }
    }

    /// Record a refused duty (issue #130 (a) part 3).
    fn refuse_for_lag(&mut self, duty: &'static str) {
        self.metrics.observe_lag_refusal(duty);
    }

    // ---- issue #229: making the ask set observable ---------------------------

    /// **Sample the applied tip against the clock** — the stall latch behind the
    /// `BODYWAIT` line. Writes nothing any decision reads.
    ///
    /// **Any change to `stip` resets it, including a decrease.** The trigger is
    /// *frozen*, not *behind*, and the two are different populations separated by
    /// two orders of magnitude: node3's own journal shows six rewinds in fifteen
    /// minutes with `stip` advancing throughout — every one of them healthy — and
    /// then `stip` pinned at 2693 for forty minutes and counting. A rewind lowers
    /// `stip`, and it is the state machine *moving*; a latch that armed on it
    /// would fire on exactly the six events the negative acceptance criterion
    /// names.
    ///
    /// `slag` is deliberately **not** the trigger: a node applying blocks more
    /// slowly than the chain produces them has a rising `slag` and is fine, and
    /// an off-main node with `slag=0` is #200's legitimate equal-work sibling case
    /// ("keep extending the verified branch until it is heavier"), which resolves
    /// by fork choice and must not be reported as a strand.
    fn observe_state_stall(&mut self, now_ms: u64, outstanding_breqs: usize) {
        let stip = self.state.tip_height();
        self.stall_now_ms = now_ms;
        self.breq_observed = outstanding_breqs;
        if self.stip_moved_ms.is_none() || stip != self.stip_observed {
            self.stip_observed = stip;
            self.stip_moved_ms = Some(now_ms);
        }
    }

    /// **[`Self::state_fork_point`]'s answer, published** (issue #229): the
    /// highest applied block that is also on the fork-choice main chain.
    ///
    /// It reaches the private function rather than recomputing the walk, so the
    /// number an operator reads and the base the requester walks from cannot
    /// drift. `None` is the reading that says layer (a) outright — the walk fell
    /// off the state machine's own block store and `missing_body_hashes` silently
    /// fell back to the applied tip, asking for blocks *above* the strand instead
    /// of the one block the rejoin gate needs.
    pub fn state_fork_point_observed(&self) -> Option<(u64, Hash32)> {
        self.state_fork_point()
    }

    /// **[`Self::rejoin_main_chain`]'s gate, evaluated without taking it** (issue
    /// #229) — the discriminator for layer (c).
    ///
    /// Recomputed from the same three inputs the gate reads, in the same order,
    /// and it mutates nothing. A node whose bodies are arriving and whose
    /// `pend=` is climbing while this stays `Missing` is the (c) reading: the
    /// material is on the node and the rewind still will not be taken.
    pub fn rejoin_gate_observed(&self) -> RejoinGate {
        let Some((fork_height, _)) = self.state_fork_point() else {
            return RejoinGate::NoForkPoint;
        };
        if fork_height == self.state.tip_height() {
            return RejoinGate::OnMain;
        }
        let next = fork_height + 1;
        let Some(next_hash) = self.main_chain_ancestor(next) else {
            return RejoinGate::NoMainBlock;
        };
        if self.pending_bodies.contains_key(&(next, next_hash)) {
            RejoinGate::Held(next)
        } else {
            RejoinGate::Missing(next)
        }
    }

    /// **The whole derived half of the `BODYWAIT` line** (issue #229), in one pass.
    ///
    /// `in_flight` is `P2pNode`'s number (`breq=`) and is passed in because the
    /// in-flight map is not the adapter's; everything else is read here so the two
    /// views of the ask set cannot disagree.
    ///
    /// ## The arming predicate, stated because it is the thing that keeps the line
    /// from becoming noise
    ///
    /// **`stip` frozen for [`UNOBTAINABLE_BODY_CADENCES`] cadences, AND (off-main
    /// OR something outstanding to ask for).**
    ///
    /// - **The clock is `#201`'s, unchanged** — `UNOBTAINABLE_BODY_CADENCES ×
    ///   CHECKPOINT_CADENCE_BLOCKS × block_time`, 20 minutes at the live 75 s
    ///   target and 32 s in the in-process sim. Its argument transfers without
    ///   amendment (cadence is the unit because the checkpoint grid is this net's
    ///   progress quantum; block time is the conversion because while the chain is
    ///   halted no height advances, and a loop-count threshold would be wrong by
    ///   #107's 30 s-vs-131 s factor between images). Reusing it rather than adding
    ///   a second constant also buys a **controlled comparison for free**: #222
    ///   established that #201's exemption never armed across 817 production
    ///   samples, and this latch runs the same clock behind a different predicate,
    ///   so which of the two fires on a live stranding is evidence about #222
    ///   obtained without building anything for it.
    /// - **Twenty minutes is ~4× the measured p99 inter-block gap** (320 s over
    ///   1,707 Phase B-WAN intervals against an 86 s mean) — outside legitimate
    ///   jitter, and far inside the 2 h 13 m – 2 h 23 m the observed strandings ran.
    /// - **The second clause is what makes an empty ask set reportable.** Layer
    ///   (a)'s worst reading is a node stranded with *nothing* outstanding, so a
    ///   predicate keyed on `breq > 0` alone would be silent in exactly the case it
    ///   exists to catch. `off_main` covers it. Conversely a caught-up node on a
    ///   halted net — `stip` frozen, on-main, nothing to ask — trips neither clause
    ///   and stays quiet, which is right: it is not stranded, the chain is.
    pub fn ask_set_observation(&self, in_flight: usize, mining: bool) -> AskSetObservation {
        let applied = self.applied_tip();
        let lag = self.state_lag();
        let off_main = applied.is_off_main_chain();
        let stuck_ms = self
            .stip_moved_ms
            .map_or(0, |t| self.stall_now_ms.saturating_sub(t));
        let armed = self.stip_moved_ms.is_some()
            && stuck_ms >= self.unobtainable_threshold_ms()
            && (off_main || self.breq_observed > 0);
        let mine = if !mining {
            MineDuty::Off
        } else if !lag.is_lagging() {
            MineDuty::Ok
        } else if self.state_tip_mine_ready {
            MineDuty::Exempt
        } else {
            MineDuty::RefusedLag
        };
        AskSetObservation {
            armed,
            stuck_ms,
            state_tip: applied.height,
            state_tip_id: applied.id_field(),
            lag: lag.blocks(),
            off_main,
            fork_point: self.state_fork_point().map(|(h, _)| h),
            // The window the requester would actually use this tick (QUM-115), not
            // a fixed 16: reporting the steady width while a catch-up asks 128
            // would make `ask_set` say the pipeline was full when it was not.
            ask_set: self.missing_body_hashes(body_window_for(lag.blocks())).len(),
            in_flight,
            pending: self.pending_bodies.len(),
            gate: self.rejoin_gate_observed(),
            mine,
            mine_refusals: self.metrics.lag_refusals("mine"),
        }
    }

    /// **Bodies this node's state machine refused at the application funnel, and the
    /// height of the most recent one** (issue #130 (b)) — the pair `bdrop=` prints.
    ///
    /// Read from the one metric registry, never from a second ledger.
    ///
    /// **Why a pair and not a total.** A cumulative count answers *how many* and
    /// cannot answer *are they still arriving*, and those want opposite operator
    /// responses: a burst while a joiner caught up is over, the same total still
    /// climbing is a node that is not converging. `/metrics` answers that with
    /// `rate()`; a single telemetry line has no previous sample to difference
    /// against. Height is the monotone quantity that IS on that line — `tip=` and
    /// `stip=` — so the last refusal's height read against `stip=` is the same
    /// answer, computed by eye, from one sample.
    ///
    /// **Height and not a timestamp**, deliberately: #106 recorded that genesis is
    /// stamped `timestamp = 0` for a reproducible genesis hash, so chain time has no
    /// wall-clock anchor, and a process-relative age would reset on the restarts this
    /// project counts.
    pub fn body_refusals(&self) -> (u64, Option<u64>) {
        (self.metrics.body_refusals_total(), self.metrics.body_refusal_last_height())
    }

    /// Bodies refused for one [`qlab_node::metrics::BODY_REFUSAL_REASONS`] class.
    pub fn body_refusals_by_reason(&self, reason: &str) -> u64 {
        self.metrics.body_refusals(reason)
    }

    /// How many times this node's state machine has rewound onto the main chain,
    /// and how many applied blocks that cost in total (issue #162).
    ///
    /// **Why a counter and not only `slag`.** After this fix the wedge's symptom
    /// disappears, and a detector that has gone quiet because the defect is gone
    /// looks exactly like one that has gone quiet because it broke. `slag` falling
    /// is the *absence* of a symptom; this is the presence of the cure — the event
    /// that says the state machine noticed it was on a losing branch and left it.
    pub fn state_rewinds(&self) -> (u64, u64) {
        (self.metrics.state_rewinds(), self.metrics.state_rewind_blocks())
    }

    /// Record that a head refused a finalize record (issue #204).
    ///
    /// Deduplicated on `(head, height)` so a retry loop reports once, not once per
    /// tick. Every distinct divergence is counted **and** journalled.
    fn note_finalize_refused(
        &mut self,
        head: &'static str,
        height: u64,
        hash: Hash32,
        why: FinalizeRefusalReason,
    ) {
        if self.finalize_refused_live == Some((head, height)) {
            return;
        }
        self.finalize_refused_live = Some((head, height));
        self.finalize_refused_total += 1;
        if self.finalize_refusals.len() >= MAX_JOURNALLED_FINALIZE_REFUSALS {
            self.finalize_refusals.remove(0);
        }
        self.finalize_refusals.push(FinalizeRefusal { head, height, hash, why });
    }

    /// `head` recorded a finalize — its latched divergence, if any, is over. Scoped
    /// to the head that succeeded, so a fork-choice advance cannot silently clear a
    /// **durable**-head divergence that is still live.
    fn note_finalize_recorded(&mut self, head: &'static str) {
        if self.finalize_refused_live.is_some_and(|(h, _)| h == head) {
            self.finalize_refused_live = None;
        }
    }

    /// Take the finalize refusals not yet journalled (issue #204). Drained and
    /// printed on the message-pump cadence beside `REWIND`, because a refusal is an
    /// **event** and the telemetry line carries only levels.
    pub fn drain_finalize_refusals(&mut self) -> Vec<FinalizeRefusal> {
        std::mem::take(&mut self.finalize_refusals)
    }

    /// Distinct finalize-record refusals since process start — `fdrop=`. Zero on
    /// every healthy node, always.
    pub fn finalize_refused_total(&self) -> u64 {
        self.finalize_refused_total
    }

    /// The **durable** finalized head (head #3) — what a restart of this node would
    /// read, and the head `Snapshot.finalized` is written from.
    ///
    /// `final=` reads head #1. Until issue #204 nothing anywhere compared the two,
    /// which is why a node whose durable head had never advanced past 1048 printed
    /// `final=1056` on every sample for hours.
    ///
    /// Derived from [`Self::durable_finalized_head`] rather than read separately, so
    /// the height on the telemetry line and the height on the wire cannot come from
    /// two reads of the store.
    pub fn durable_finalized_height(&self) -> Option<u64> {
        self.durable_finalized_head().map(|(height, _)| height)
    }

    /// **Head #3's height AND the block it names** (issue #212) — the pair
    /// `/v1/telemetry` publishes as `dfin`/`dfinbh`.
    ///
    /// Both halves come from **one borrow** of the store, so the pair is always a
    /// single observation of a single head. Reading the height and the hash through
    /// two accessors would let a caller pair a height with a hash from a different
    /// moment, which on this surface is the one mistake that would be invisible: the
    /// value would still render as a plausible identity.
    ///
    /// A half-present pair — a height with no hash, or the reverse — is not
    /// representable in the store (`set_finalized`/`restore_finalized` move both or
    /// neither) and reads as absent here rather than as a fabricated half.
    pub fn durable_finalized_head(&self) -> Option<(u64, Hash32)> {
        use qlab_node::ChainStore as _;
        let store = self.state.chain();
        match (store.finalized_height(), store.finalized_hash()) {
            (Some(height), Some(hash)) => Some((height, hash)),
            _ => None,
        }
    }

    /// Take the rewind reports not yet journalled (issue #162).
    ///
    /// The counters above are the lossless record and the alertable one; this is the
    /// **detail**, and it goes to the container log for the same reason `ROUND` does:
    /// metrics answer "how often", and only the journal can answer "off which block,
    /// onto which, at what height" after the fact. `[`RewindReport`] renders itself.
    ///
    /// Bounded at [`MAX_JOURNALLED_REWINDS`] with the OLDEST dropped, which is the
    /// opposite of the pending-body window's rule and for the opposite reason: here
    /// the newest event is the one an operator is looking at. An undrained buffer
    /// therefore cannot grow, and nothing is silently lost — the counters still hold
    /// every event, so a drop is visible as the count exceeding what was journalled.
    pub fn drain_rewinds(&mut self) -> Vec<RewindReport> {
        std::mem::take(&mut self.rewinds)
    }

    /// The main-chain hash at `height`, walked back from the fork-choice tip.
    ///
    /// Kept for the narrow rejoin transition seams that ask for `fork + 1`.
    /// Dispatch-hot readers must use [`ChainView::main_chain_hash_at`], whose
    /// maintained height index answers the same question in O(1).
    fn main_chain_ancestor(&self, height: u64) -> Option<Hash32> {
        #[cfg(test)]
        MAIN_CHAIN_ANCESTOR_CALLS.with(|calls| calls.set(calls.get() + 1));
        let tip_height = self.chain.tip_height();
        if height > tip_height {
            return None;
        }
        self.chain.ancestor(&self.chain.tip_hash(), tip_height - height)
    }

    /// **The block the state machine must rewind to before it can follow fork
    /// choice** (issue #162): the highest block that is both an ancestor of the
    /// applied tip and on the fork-choice main chain.
    ///
    /// When the applied tip is *on* the main chain — every node, almost always —
    /// this is the applied tip itself and the walk exits on its first comparison,
    /// so the ordinary path pays one O(1) indexed lookup. When the state machine is
    /// stranded on a losing sibling it walks the abandoned branch down to the fork
    /// point, with one indexed lookup per divergent block: O(divergence depth), not
    /// O(header tip − applied tip).
    ///
    /// The walk reads the STATE machine's own block store, not fork choice's: the
    /// abandoned branch is what it has applied, and that is the only side of the
    /// fork this function needs to enumerate. Genesis is shared by construction, so
    /// the walk always terminates.
    fn state_fork_point(&self) -> Option<(u64, Hash32)> {
        use qlab_node::ChainStore as _;
        let mut hash = self.state.tip_hash();
        let mut height = self.state.tip_height();
        loop {
            if self.main_chain_hash_at(height) == Some(hash) {
                return Some((height, hash));
            }
            if height == 0 {
                return None;
            }
            hash = self.state.chain().block(&hash)?.header.prev;
            height -= 1;
        }
    }

    /// **Whether a body is worth holding** — the single rule [`Self::buffer_body`]
    /// admits against and [`Self::drain_pending_bodies`] retains against (issue
    /// #162; one rule, so a body cannot be accepted by one and re-dropped by the
    /// other on the same tick).
    ///
    /// The pre-#162 rule was `height > applied tip`, and its doc comment stated the
    /// premise it rested on: a body at or below the applied tip is "already folded
    /// in, or on a branch this state machine will never rewind to". The second
    /// half was true only because `rewind_to` did not exist — and it was
    /// load-bearing in the worst possible way. **A sibling body arrives at exactly
    /// the applied tip's own height, and it arrives before fork choice has moved**:
    /// at the moment the winner's block reaches a node that already applied the
    /// loser, both branches carry equal work and the tie-break keeps the incumbent,
    /// so the node still reads as on the main chain. Any rule phrased against
    /// *where fork choice is now* discards the one object that will be needed one
    /// block later, and re-announcement never brings it back (`GetData(Block)`
    /// answers header-only — the #153 finding, untouched here).
    ///
    /// So the question is not "is this above my tip" but "have I applied this":
    ///
    /// - **applied already** ⇒ no. Read from the state machine's own block store,
    ///   which after a rewind holds exactly the branch being applied — so this
    ///   sharpens rather than approximates the old height test.
    /// - **more than [`MAX_PENDING_BODY_HEIGHTS`] above the applied tip** ⇒ no.
    ///   Unchanged: past it, a body cannot become applicable without material this
    ///   node has no message to request (#130 (c)).
    /// - **more than [`MAX_REWIND_DEPTH`] below the applied tip** ⇒ no. New, and it
    ///   is what keeps "hold siblings" from meaning "hold every fork ever offered":
    ///   below that depth this node will not rewind, so the body has no use.
    /// - otherwise ⇒ yes.
    ///
    /// Genesis is excluded explicitly: it is applied at construction, never through
    /// this window, and a genesis body in the queue would be a body that can never
    /// drain.
    fn is_body_worth_holding(&self, header: &BlockHeader) -> bool {
        use qlab_node::ChainStore as _;
        if header.height == 0 {
            return false;
        }
        if self.state.chain().contains(&header.header_hash_for(self.rules.form)) {
            return false;
        }
        let state_tip = self.state.tip_height();
        header.height <= state_tip + MAX_PENDING_BODY_HEIGHTS
            && header.height + MAX_REWIND_DEPTH > state_tip
    }

    /// Hold a body whose header this node already has, for application when the
    /// state machine reaches its parent.
    ///
    /// Admission is [`Self::is_body_worth_holding`]. Over the entry or byte cap the
    /// **highest** held entry is dropped: the lowest heights are the ones that close
    /// the gap, so the entry furthest from applicable is the one worth least — and
    /// since #162 that ordering also protects the sibling bodies at and just below
    /// the applied tip, which are the ones a rewind needs.
    fn buffer_body(&mut self, header: BlockHeader, body: BlockBody) {
        if !self.is_body_worth_holding(&header) {
            return;
        }
        let key = (header.height, header.header_hash_for(self.rules.form));
        let weight = body_weight(&body);
        if let Some((_, old)) = self.pending_bodies.insert(key, (header, body)) {
            // Re-announce of a body we already hold: replace, and do not double-count.
            self.pending_bytes = self.pending_bytes.saturating_sub(body_weight(&old));
        }
        self.pending_bytes += weight;
        while self.pending_bodies.len() > MAX_PENDING_BODIES
            || (self.pending_bytes > MAX_PENDING_BODY_BYTES && self.pending_bodies.len() > 1)
        {
            let Some(highest) = self.pending_bodies.keys().next_back().copied() else { break };
            if let Some((_, dropped)) = self.pending_bodies.remove(&highest) {
                self.pending_bytes = self.pending_bytes.saturating_sub(body_weight(&dropped));
            }
        }
    }

    /// **Take the state machine off a losing branch and back onto the chain fork
    /// choice is following** (issue #162) — the fix, at the seam that owns both
    /// views.
    ///
    /// Fires only when the applied tip is *not* the main-chain block at its own
    /// height: `state_lag()` cannot see this condition (a stranded node and a node
    /// three blocks behind both print a nonzero `slag=`), and #168's
    /// `applied_tip().off_main_chain()` is the comparison that can. This is the same
    /// predicate, reached through [`Self::state_fork_point`] so the rewind target
    /// and the detector cannot drift apart.
    ///
    /// **Gated on the rewind being immediately useful, and that gate is a
    /// position.** A rewind is only taken when this node already holds the
    /// main-chain body at `fork + 1`, so every rewind is followed in the same
    /// `drain_pending_bodies` pass by at least one application. Rewinding
    /// unconditionally would be defensible — fork choice has moved and the state
    /// machine's job is to follow it — but it would trade a wedged node for a node
    /// that has thrown away applied state and still cannot move, and it would let a
    /// branch that flaps re-fold the retained chain on every flap. The refusal to
    /// rewind without a way forward keeps the cost proportional to the progress.
    ///
    /// **What this does NOT do is decide the fork.** `ChainState`'s heaviest-chain
    /// rule, gated by finality, has already chosen; the losing branch is losing
    /// before this function is called, and `Node::rewind_to` refuses outright to
    /// cross the finalized head. A rewind here can only discard blocks that fork
    /// choice has already stopped counting.
    ///
    /// A refused rewind is recorded, not swallowed: the node stays exactly where it
    /// was — wedged, with `schain=fork` still true and `slag=` still climbing, which
    /// is the honest reading — and the refusal is attributable through the same lag
    /// counter every other refused duty uses.
    fn rejoin_main_chain(&mut self) {
        let Some((fork_height, fork_hash)) = self.state_fork_point() else { return };
        if fork_height == self.state.tip_height() {
            return; // the applied tip is on the main chain — nothing to undo
        }
        // The rewind must be able to be followed by an application, or it is a
        // pure loss. `fork + 1` on the main chain is the only block that can be.
        let next = fork_height + 1;
        let Some(next_hash) = self.main_chain_ancestor(next) else { return };
        if !self.pending_bodies.contains_key(&(next, next_hash)) {
            return;
        }
        match self.state.rewind_to(fork_hash) {
            Ok(report) if !report.is_noop() => {
                self.metrics.observe_state_rewind(report.blocks_undone());
                if self.rewinds.len() >= MAX_JOURNALLED_REWINDS {
                    self.rewinds.remove(0);
                }
                self.rewinds.push(report);
            }
            Ok(_) => {}
            // Unreachable as the guards above stand (the target is an ancestor of
            // the applied tip, and it is on the main chain, which descends from
            // finality). Kept as a refusal rather than an `expect` because the one
            // way it could ever fire is the finality line, and a node that has
            // convinced itself it must cross that line should stop, not panic and
            // not proceed.
            Err(_) => self.refuse_for_lag("rewind"),
        }
    }

    /// Apply every held body that has become applicable, **in ascending height
    /// order**, until none extends the state tip.
    ///
    /// Ascending is the whole mechanism: the state machine applies at its tip only,
    /// so a held span empties from the bottom as the tip advances — which is why one
    /// arriving body can close a gap of many, and why the old "apply what this one
    /// announcement carried" shape could never catch up.
    fn drain_pending_bodies(&mut self) {
        // Issue #162: before asking what is applicable, make sure the tip the
        // question is asked against is on the chain this node is following.
        self.rejoin_main_chain();
        while let Some(key) = self.next_applicable_body() {
            let (header, body) = self.pending_bodies.remove(&key).expect("just located");
            self.pending_bytes = self.pending_bytes.saturating_sub(body_weight(&body));
            // `apply_block_gated` is the authoritative gate and it re-validates the
            // body against the tree it is actually being applied to — so nothing is
            // ever folded in on the strength of an anchor answer computed from a
            // stale tree. It also persists: the log append is inside it, which is
            // what makes a buffered-then-applied body durable (issue #104).
            //
            // The gate is chosen per block (lab #402): a block that is settled
            // history — the main-chain block at its height under the quorum-verified
            // finalized pointer — has its anchor rule evaluated as of its OWN
            // height, because this node's live finality structurally lags its
            // application while it replays (the #402 joiner deadlock). Everything
            // else, including every block at or near the live tip, runs the live
            // rule exactly as before.
            let gate = if self.block_is_settled_history(&header) {
                qlab_node::AnchorGate::SettledHistory
            } else {
                qlab_node::AnchorGate::Live
            };
            match self.state.apply_block_gated(header, body.clone(), &self.verifier, gate) {
                Ok(_) => {
                    // The registry read here is the post-apply one — `apply_block`
                    // has already folded this body's own riders in, which is what
                    // makes the name-eviction leg see the block that outraced a
                    // pooled reveal (lab #387).
                    //
                    // Admission and eviction ask the same rider question and must
                    // ask it under the same installed form (lab #612). Calling the
                    // v4 convenience here silently evicted every native v5 rider
                    // on the block after it was admitted.
                    self.mempool.on_block_connected_above(
                        self.rules.form.rider_admit_boundary(),
                        &body,
                        &self.state,
                        self.state.names(),
                    );
                }
                // A body that fails at the funnel has mutated nothing (`apply_state`
                // validates before it writes), and no peer is charged for it — the
                // sender was judged once, on arrival, and this path holds no sender
                // to charge a second time.
                //
                // 🔴 **Issue #130 (b): what it costs is visibility, and until this
                // line it did not have any.** The sentence this arm's predecessor
                // carried — that the drop was expected — was the whole of #130's
                // complaint: *"a comment asserting that a dropped block is normal is
                // what kept anyone from asking whether it was."* Naming the error
                // class and the height turns the assertion into a measurement, so the
                // next person asking gets an answer instead of a comment. The
                // classification is [`qlab_node::NodeError::refusal_reason`], beside
                // the enum, where the compiler enforces that it stays exhaustive.
                Err(e) => {
                    self.metrics.observe_body_refusal(e.refusal_reason(), header.height);
                }
            }
        }
        // The finalized head is part of the view that has to catch up, not a separate
        // concern — see `sync_state_finality`.
        self.sync_state_finality();
        // Anything no longer worth holding is dead weight — and it is the SAME rule
        // the entry gate admits against (issue #162). Two rules here would either
        // re-drop the sibling body on the tick it was accepted, or accumulate bodies
        // the entry gate would have refused.
        //
        // Evaluated against a snapshot of the rule's inputs rather than inside the
        // closure, because `retain` holds the map borrowed.
        let worth: Vec<(u64, Hash32)> = self
            .pending_bodies
            .iter()
            .filter(|(_, (header, _))| self.is_body_worth_holding(header))
            .map(|(key, _)| *key)
            .collect();
        let worth: std::collections::HashSet<(u64, Hash32)> = worth.into_iter().collect();
        self.pending_bodies.retain(|key, body| {
            let keep = worth.contains(key);
            if !keep {
                // `pending_bytes` is maintained here rather than recomputed, so the
                // two never drift.
                self.pending_bytes = self.pending_bytes.saturating_sub(body_weight(&body.1));
            }
            keep
        });
    }

    /// Advance the **state machine's** finalized head to the committee's, as far as
    /// the state machine can see it (issue #130 (a)).
    ///
    /// One place, called from both sites that can move it: a finalization arriving
    /// ([`Self::ingest_checkpoint_votes`]) and buffered bodies advancing the applied
    /// tip. The second call site is the fix. `Node::finalize` requires the block to be
    /// **known locally**, so a checkpoint that finalized while the state was lagging
    /// named a block the state machine did not have: it returned `Ok(false)`, no
    /// `Finalize` record was appended, and nothing ever came back for it (the second
    /// fact #104 could not place). It is not only a log gap —
    /// [`qlab_node::NodeState::is_valid_anchor`] reads *this* finalized head, so a node
    /// whose bodies caught up but whose finality did not answers "no anchor is valid"
    /// forever.
    ///
    /// GUARANTEED: whenever the state machine holds the committee's finalized block,
    /// its own finalized head is advanced to it. A persistence failure on the append
    /// is still swallowed here (issue #85, unchanged by this pass) — but it is now
    /// *retried* on the next drain rather than being a single lost attempt.
    fn sync_state_finality(&mut self) {
        let Some(cp) = self.finality.latest().copied() else { return };
        if self.state.finalized_height() == Some(cp.height) {
            return;
        }
        // Issue #204: this was `let _ =`, and it is the one that mattered — the
        // **durable** head declining to record what the operator-facing head already
        // reports. That is exactly the state node1 was in, and nothing on the node
        // could say so.
        //
        // 🔴 Issue #241: and until then the *reason* still did not survive the trip.
        // `Node::finalize` returned `Ok(false)`, so the three arms that used to live
        // here re-derived the reason by re-reading store state — a second
        // implementation of `ChainStore::set_finalized`'s own decision, which could
        // disagree with it (it tested `cp.height`, the checkpoint's *claimed* height,
        // where the store tests the stored header's; and it asked `contains`, the
        // block map, where the store asks its header map). Worse, its last arm was an
        // unconditional `else`, so a fourth refusal variant would have rendered
        // `off-finality` with no compile error. The store's verdict is now threaded
        // through and converted once, exhaustively, at
        // `FinalizeRefusalReason::from`.
        //
        // The retry itself is unchanged (#130 (a)): a refusal is re-attempted on the
        // next drain. What changed is that it is counted, journalled and on the
        // telemetry line while it lasts — and now that it says which refusal.
        match self.state.finalize(cp.block_hash) {
            Ok(FinalizeOutcome::Recorded) => self.note_finalize_recorded("state"),
            Ok(FinalizeOutcome::Refused(e)) => {
                self.note_finalize_refused("state", cp.height, cp.block_hash, e.into());
            }
            // Not a store verdict: the store said yes and the log append failed.
            Err(_) => self.note_finalize_refused(
                "state",
                cp.height,
                cp.block_hash,
                FinalizeRefusalReason::Persist,
            ),
        }
    }

    /// The lowest held body that extends the applied tip, if any.
    fn next_applicable_body(&self) -> Option<(u64, Hash32)> {
        let tip_hash = self.state.tip_hash();
        let next = self.state.tip_height() + 1;
        self.pending_bodies
            .range((next, [0u8; 32])..=(next, [0xffu8; 32]))
            .find(|(_, (header, _))| header.prev == tip_hash)
            .map(|(key, _)| *key)
    }

    /// Advance the epoch machinery to the current tip; reset the downtime window on
    /// an epoch change (indices reindex at a boundary — matches `StubNode`).
    fn advance_epoch(&mut self) {
        let before = self.committee.current_epoch();
        self.committee.advance_to(self.chain.tip_height());
        if self.committee.current_epoch() != before {
            self.signing.reset();
        }
    }

    /// Apply any downtime jails the signing window now warrants at `height`.
    fn apply_downtime_jails(&mut self, height: u64) {
        let n = self.committee.state().size();
        for idx in 0..n {
            if self.signing.jailable(idx) {
                self.committee.state_mut().jail(idx, height + JAIL_BLOCKS);
            }
        }
    }

    /// Insert a header whose validation gate has already succeeded, preserving the
    /// ordinary epoch and block-interval side effects.
    fn insert_validated_header(&mut self, header: BlockHeader) -> IngestOutcome {
        let header_hash = header.header_hash_for(self.rules.form);
        // Chain-time gap to the parent, captured BEFORE the insert while the parent
        // is unambiguous (issue #87). Observed only when this header becomes the tip,
        // so the histogram describes the adopted chain rather than every side fork.
        let parent_ts = self.chain.header(&header.prev).map(|p| p.timestamp);
        let header_ts = header.timestamp;
        match self.chain.insert_header(header) {
            Ok(_) => {
                self.advance_epoch();
                if self.chain.tip_hash() == header_hash {
                    let interval =
                        parent_ts.filter(|&t| t > 0).map(|pts| header_ts.saturating_sub(pts));
                    self.metrics.observe_block(interval);
                }
                IngestOutcome::Accepted
            }
            Err(InsertError::Duplicate) => IngestOutcome::Duplicate,
            Err(InsertError::UnknownParent) => IngestOutcome::Orphan,
            Err(InsertError::BadHeight) => IngestOutcome::Rejected("bad height"),
        }
    }

    /// Map a header-insert result to an [`IngestOutcome`], advancing the epoch on
    /// acceptance.
    fn submit_header(&mut self, header: BlockHeader) -> IngestOutcome {
        // HALT (issue #74, H2). An armed node applies block H and accepts nothing
        // above it. This is a property of the running RELEASE, not of the chain, so
        // it is enforced here rather than inside `validate_header` — and the peer is
        // NOT penalised: a node still on the old binary offering post-H blocks is on
        // a different release, not misbehaving (the S5 discipline from #70).
        if !self.rules.halt.accepts_height(header.height) {
            self.ingest_counters.halt_ignored += 1;
            return IngestOutcome::Ignored("above halt height");
        }
        // Lab #412: the validated header store is also the immutable PoW-verdict
        // cache. Header-first sync deliberately learns a header before fetching its
        // body, so the normal body path submits the exact same header again. The old
        // order ran `validate_header_under` first — including RandomX and the two
        // ancestor walks — and only then let `ChainState::insert_header` discover
        // the duplicate. On a from-genesis join every historical body therefore
        // re-ran memory-hard PoW in `pump.dispatch`.
        //
        // A hash present in `self.chain` got there through the validation below
        // (apart from locally-constructed genesis), and the hash commits to every
        // header field. Its verdict cannot change with later chain state. Check the
        // release-height gate first so a halted binary keeps ignoring above-H input
        // even if such a header was learned under a previous rule schedule.
        let header_hash = header.header_hash_for(self.rules.form);
        if self.chain.header(&header_hash).is_some() {
            return IngestOutcome::Duplicate;
        }
        // Real PoW + LWMA difficulty + key-seed validation (N3), under this
        // release's rules (the PoW VALUE is domain-separated above an upgrade
        // boundary; at and below it, byte-identical to the v1.0 rules).
        if let Err(e) = validate_header_under(
            &self.chain,
            &self.pow,
            &header,
            self.block_time,
            self.schedule,
            &self.rules,
        ) {
            // Unknown parent → orphan (drives header-first sync); anything else is
            // an invalid header. The reason string names the FAILING CHECK, not just
            // "invalid header": issue #74's drill has to be able to say which layer
            // rejected an old-binary block — the release layer (halt) or the
            // header-validation layer (the post-halt PoW domain) — and a single
            // catch-all string cannot answer that.
            if matches!(e, ValidationError::UnknownParent) && header.height > 0 {
                return IngestOutcome::Orphan;
            }
            if self.chain.header(&header.prev).is_none() && header.height > 0 {
                return IngestOutcome::Orphan;
            }
            if matches!(e, ValidationError::PowUnsatisfied) {
                self.ingest_counters.pow_rejected += 1;
            }
            return IngestOutcome::Rejected(Self::header_reject_reason(&e));
        }
        self.insert_validated_header(header)
    }

    /// Choose the header timestamp for a block mined over `parent`, per the
    /// configured [`MiningClock`] (the mining-clock seam, item 0). Deterministic
    /// advances the monotone counter by the target block time (reproducible,
    /// constant solvetime); WallClock reads real wall-clock seconds clamped
    /// non-decreasing against the parent (so [`validate_header`]'s monotonic rule
    /// holds, and LWMA sees the real, variable solvetime).
    fn next_timestamp(&mut self, parent: &BlockHeader) -> u64 {
        match self.mining_clock {
            MiningClock::Deterministic => {
                self.clock =
                    (self.clock + self.block_time).max(parent.timestamp + self.block_time);
                self.clock
            }
            MiningClock::WallClock => wall_clock_secs().max(parent.timestamp),
        }
    }

    /// The header+body a miner would grind, assembled by the same parent
    /// selection and mempool path as [`Self::mine_block`] but **without**
    /// `mine_under`. Lab #511: the template RPC must reuse this path
    /// verbatim — a second assembly is a consensus-adjacent fork.
    pub fn assemble_block(&mut self) -> Option<AssembledCandidate> {
        let parent_hash = self.mining_parent_hash()?;
        self.assemble_on_parent(parent_hash, self.miner_rkm, None)
    }

    /// Form and height of the candidate [`Self::assemble_block`] would build,
    /// without assembling a body or advancing the mining clock. The pool uses
    /// this once at startup so its first template request carries a real payee
    /// list; there is no payee-free compatibility request.
    pub fn mine_template_context(&mut self) -> Option<(GenesisForm, u64)> {
        let parent_hash = self.mining_parent_hash()?;
        let parent = self.chain.header(&parent_hash)?;
        Some((self.rules.form, parent.height + 1))
    }

    /// Assemble the same candidate as [`Self::assemble_block`], but pay the
    /// caller-provided coinbase list (lab #553). The list is chosen before the
    /// header is issued because the body commitment is in the hashing blob.
    pub fn assemble_block_for_payees(
        &mut self,
        payees: &[CoinbasePayee],
    ) -> Result<Option<AssembledCandidate>, String> {
        let Some(parent_hash) = self.mining_parent_hash() else {
            return Ok(None);
        };
        let parent = self.chain.header(&parent_hash).ok_or_else(|| "assemble-parent-unknown".to_string())?;
        let height = parent.height + 1;
        let cap = match self.rules.form {
            GenesisForm::V4 => 1,
            GenesisForm::V5 => coinbase_payee_cap_v5(height),
        };
        if payees.is_empty() || payees.len() > cap {
            return Err(format!(
                "coinbase-payee-count: got {}, want 1..={} at height {}",
                payees.len(), cap, height
            ));
        }
        if payees.iter().any(|payee| payee.rkm == [0; 4]) {
            return Err("coinbase-payee-zero-rkm".into());
        }
        match self.rules.form {
            GenesisForm::V5 => check_scheduled_coinbase_payees(height, payees)
                .map_err(|e| format!("coinbase-payees: {e:?}"))?,
            GenesisForm::V4 => {
                let expected = qlab_node::emission::coinbase_for(GenesisForm::V4, height);
                if payees[0].amount != expected {
                    return Err(format!("coinbase-payee-amount: height {height} expected {expected}, got {}", payees[0].amount));
                }
            }
        }
        Ok(self.assemble_on_parent(parent_hash, payees[0].rkm, Some(payees)))
    }

    /// Assemble + mine (but do NOT insert) the next block over the current tip.
    /// Returns `(mined_header, body)`; the caller ingests it via `announce_block`
    /// → `ingest_block`, which is the single insert/apply path. `None` if there is
    /// no known parent or the nonce budget is exhausted.
    ///
    /// # Parent selection (issue #130 (a) + issue #200)
    ///
    /// The parent comes from **fork choice** and the body is assembled from
    /// **state**. When those disagree, the block this would produce is a valid
    /// child of the fork-choice tip that the node's own state machine then
    /// refuses — coinbase notes with no commitment-tree leaf, silent loss.
    ///
    /// - **Default (healthy):** parent = fork-choice tip.
    /// - **Lagging, exemption not armed:** refuse. Ethereum's optimistic-sync
    ///   rule ("an optimistic validator MUST NOT produce a block").
    /// - **Exemption armed (issue #200):** parent = **state tip** — the height
    ///   this node has actually verified. Never the fork-choice tip it cannot
    ///   reach. Produces a sibling that fork choice can resolve once extended
    ///   past the unobtainable header's work.
    pub fn mine_block(&mut self) -> Option<(BlockHeader, BlockBody)> {
        let lagging = self.state_lag().is_lagging();
        let off_main = self.applied_tip().is_off_main_chain();
        let exempt = self.state_tip_mine_ready;

        let parent_hash = self.mining_parent_hash()?;
        let mined = self.mine_on_parent(parent_hash)?;
        if exempt && (lagging || off_main) {
            self.metrics.observe_state_tip_mine();
        }
        Some(mined)
    }

    /// Parent hash [`Self::mine_block`] / [`Self::assemble_block`] would extend.
    /// Shared so the two cannot drift on halt / lag / #200 exemption.
    fn mining_parent_hash(&mut self) -> Option<Hash32> {
        let lagging = self.state_lag().is_lagging();
        let off_main = self.applied_tip().is_off_main_chain();
        let exempt = self.state_tip_mine_ready;

        // Parent height for the halt gate: under the exemption we extend the
        // *state* tip, so the height that must clear H2 is state_tip+1, not the
        // fork-choice tip the node cannot verify.
        let next_height = if exempt && (lagging || off_main) {
            self.state.tip_height().saturating_add(1)
        } else {
            self.chain.tip_height().saturating_add(1)
        };
        // HALT (H2): an upgraded node stops mining above H. Un-upgraded miners will
        // not, and that is fine — §4's hybrid honesty note; the committee, not miner
        // unanimity, is what makes the upgrade clean.
        if !self.rules.halt.accepts_height(next_height) {
            return None;
        }

        if lagging {
            if !exempt {
                self.refuse_for_lag("mine");
                return None;
            }
            // #200: mine on the verified state tip.
            Some(self.state.tip_hash())
        } else if exempt && off_main {
            // Heights match but the applied tip is a sibling of the main-chain
            // block at that height (the equal-work incumbent still holds fork
            // choice). Keep extending the verified branch until it is heavier.
            Some(self.state.tip_hash())
        } else {
            Some(self.chain.tip_hash())
        }
    }

    /// Mine a child of `parent_hash` (must be a known header). Shared by the
    /// healthy fork-choice path and the #200 state-tip path so the two cannot
    /// drift on timestamp / difficulty / seed selection.
    ///
    /// # The body commitment is keyed to the CANDIDATE's height (lab #367)
    ///
    /// `BlockBody::commitment()` is the "v2 regardless of height" form; above
    /// `NAME_RULE_BOUNDARY_HEIGHT` an armed node's entry rule requires the v3
    /// form, so a producer committing v2 there emits a header its own network
    /// (and, since the funnel was height-keyed too, its own state machine)
    /// refuses. PR #464 measured that deadlock; this is the producer half of
    /// the fix. The height used is the candidate's — `parent.height + 1`, which
    /// is exactly what [`BlockHeader::child_of`] assigns and what every
    /// validator will read back off the mined header. It is asserted below
    /// rather than assumed, because a divergence here is silent (a valid PoW
    /// header nobody can apply) and free to check.
    ///
    /// Note the template's own `height` (`state.tip_height() + 1`) is NOT the
    /// key: under the #200 state-tip exemption the parent may be the state tip
    /// while fork choice is elsewhere, and the header's height is the only one
    /// consensus reads.
    fn mine_on_parent(&mut self, parent_hash: Hash32) -> Option<(BlockHeader, BlockBody)> {
        let assembled = self.assemble_on_parent(parent_hash, self.miner_rkm, None)?;
        let mined = mine_under(
            &self.pow,
            assembled.header,
            self.nonce_budget,
            &assembled.seed_hash,
            &self.rules,
        )?;
        Some((mined, assembled.body))
    }

    /// Resumable self-mining, one bounded slice per call (lab #651). The node
    /// loop's mine phase calls this every iteration; each call blocks for at
    /// most `slice` (deadline + one hash) instead of [`Self::mine_block`]'s
    /// whole nonce budget — the defect measured at 9.4 minutes on the Windows
    /// node, with a 67,108,864-hash worst case.
    ///
    /// # `may_start` gates STARTING a template, never RESUMING one
    ///
    /// The caller passes its `mine_interval` verdict as `may_start`, and it is
    /// consulted only when there is no grind in flight. Gating the resume on
    /// it would grind one slice per interval — with a 75 s interval and a
    /// ~25 ms slice that is a ~99.97 % hashrate loss, worse than the blocking
    /// defect this replaces.
    ///
    /// # Abandonment is the tip moving, not a clock
    ///
    /// A parked grind is resumed only while [`Self::mining_parent_hash`] still
    /// answers the parent it was assembled on. A new mining parent (a block
    /// arrived, a rewind, the #200 exemption switching tips) drops the parked
    /// work — it could only produce an orphan — and assembly starts fresh in
    /// the same call, so no phase is wasted. When no parent can be read at all
    /// (halt / lag refusal), the grind is kept parked, not dropped: whether it
    /// is still worth resuming is exactly the parent comparison's question,
    /// answered when a parent can be read again. The lag gate itself
    /// (`refuse_for_lag("mine")` inside [`Self::mining_parent_hash`]) is
    /// untouched — it is what pulls a deaf-and-behind node back into the
    /// chain, and slicing does not make it redundant (it still stops a
    /// lagging node from mining a doomed template at full speed).
    ///
    /// `Exhausted` means the template's whole `nonce_budget` was spent: the
    /// grind is dropped and the next permitted call re-assembles — picking up
    /// a fresh timestamp and mempool snapshot, which is what the budget now
    /// bounds (template staleness), not blocking time.
    pub fn mine_step(&mut self, may_start: bool, slice: SliceBudget) -> MineStep {
        if self.grind.is_none() && !may_start {
            return MineStep::Idle;
        }
        let Some(parent_hash) = self.mining_parent_hash() else {
            return MineStep::Idle;
        };
        if self.grind.as_ref().is_some_and(|g| g.parent_hash != parent_hash) {
            self.grind = None;
        }
        if self.grind.is_none() {
            if !may_start {
                return MineStep::Idle;
            }
            let Some(candidate) = self.assemble_on_parent(parent_hash, self.miner_rkm, None)
            else {
                return MineStep::Idle;
            };
            self.grind = Some(GrindState { parent_hash, candidate, next_nonce: 0 });
        }
        let g = self.grind.as_mut().expect("grind state was just ensured");
        match grind_slice(
            &self.pow,
            &g.candidate.header,
            &g.candidate.seed_hash,
            &self.rules,
            g.next_nonce,
            self.nonce_budget,
            slice,
        ) {
            GrindOutcome::Found(header) => {
                let state = self.grind.take().expect("grind state present on Found");
                // #200 metric parity with `mine_block`: a block produced under
                // the state-tip exemption is observed at production time.
                if self.state_tip_mine_ready
                    && (self.state_lag().is_lagging() || self.applied_tip().is_off_main_chain())
                {
                    self.metrics.observe_state_tip_mine();
                }
                MineStep::Mined(header, state.candidate.body)
            }
            GrindOutcome::Exhausted => {
                self.grind = None;
                MineStep::Exhausted
            }
            GrindOutcome::Yielded { next_nonce } => {
                g.next_nonce = next_nonce;
                MineStep::Yielded
            }
        }
    }

    /// The parked grind, if any: `(mining parent, next nonce)`. Read by the
    /// node loop (idle-sleep suppression while grinding) and by tests; writes
    /// nothing.
    pub fn grind_progress(&self) -> Option<(Hash32, u64)> {
        self.grind.as_ref().map(|g| (g.parent_hash, g.next_nonce))
    }

    /// The node's own `mine_on_parent` assembly, WITHOUT grinding. Lab #511
    /// STOP-POINT: this is the same mempool / timestamp / difficulty / seed
    /// path as a self-mined block. A fork here is a consensus-adjacent fork.
    fn assemble_on_parent(
        &mut self,
        parent_hash: Hash32,
        coinbase_rkm: [u64; 4],
        requested_payees: Option<&[CoinbasePayee]>,
    ) -> Option<AssembledCandidate> {
        let template = self.mempool.assemble(&self.state, SOAK_EFFECTIVE_MEDIAN, coinbase_rkm);
        let mut body = template.body;
        if let Some(payees) = requested_payees {
            body.coinbase_payees = payees.to_vec();
        }
        let parent = *self.chain.header(&parent_hash)?;
        let candidate_height = parent.height + 1;
        let bc = match self.rules.form {
            GenesisForm::V4 => body.commitment_at(candidate_height),
            GenesisForm::V5 => body.commitment_v5_at(candidate_height),
        };
        let difficulty = expected_difficulty(&self.chain, &parent_hash, self.block_time)?;
        let timestamp = self.next_timestamp(&parent);
        let candidate =
            BlockHeader::child_of_for(self.rules.form, &parent, timestamp, difficulty, bc);
        assert_eq!(
            candidate.height, candidate_height,
            "the mined header's height must be the height its body commitment was keyed to"
        );
        let seed = pow_seed(&self.chain, &parent_hash, candidate.height, self.schedule)?;
        let mut seed_hash = [0u8; 32];
        if seed.len() != 32 {
            return None;
        }
        seed_hash.copy_from_slice(&seed);
        let next_seed_hash = self.next_seed_hash_if_known(candidate.height, &parent_hash);
        Some(AssembledCandidate {
            form: self.rules.form,
            header: candidate,
            body,
            seed_hash,
            next_seed_hash,
        })
    }

    /// Next key-block hash when this branch already holds the seed block of
    /// the *next* rotation. Absent far from a rotation (the usual case) and
    /// absent when that height has not been mined yet.
    fn next_seed_hash_if_known(&self, height: u64, parent_hash: &Hash32) -> Option<Hash32> {
        let epoch = self.schedule.epoch;
        let lag = self.schedule.lag;
        if epoch == 0 {
            return None;
        }
        let first = epoch + lag + 1;
        let rot = if height < first {
            first
        } else {
            let current = self.schedule.seed_height(height);
            current + epoch + lag + 1
        };
        let next_seed_h = self.schedule.seed_height(rot);
        let parent = self.chain.header(parent_hash)?;
        let depth = parent.height.checked_sub(next_seed_h)?;
        self.chain.ancestor(parent_hash, depth)
    }

    /// Build a checkpoint for the main-chain block at `height` (devnet root
    /// stand-in = the block hash) and sign it with `validators`.
    pub fn make_checkpoint(
        &self,
        height: u64,
        validators: &[Validator],
    ) -> Option<(Checkpoint, Vec<Vote>)> {
        if !self.rules.halt.may_checkpoint(height) {
            return None; // H2 — see `make_checkpoint_guarded`
        }
        let block_hash = self.chain.main_chain_hash_at(height)?;
        let cp = Checkpoint::new(height, block_hash, block_hash);
        let votes = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        Some((cp, votes))
    }

    /// The **recovery-aware** proposer path (M10-T0-2): build the checkpoint for
    /// `height` and collect votes from `finalizers` under each finalizer's
    /// never-re-sign-a-conflicting-checkpoint guard ([`Finalizer`]). A finalizer
    /// that would equivocate against its own past vote for this slot simply
    /// contributes no vote — so a committee restarting after a stall can never emit
    /// the second half of an equivocation pair, no matter what it signed before the
    /// crash. Each finalizer's [`Finalizer::state`] should be persisted after this
    /// call (the caller owns durability). Callers that want the count of honest
    /// votes can inspect the returned `Vec` length against the quorum.
    pub fn make_checkpoint_guarded(
        &self,
        height: u64,
        finalizers: &mut [Finalizer],
    ) -> Option<(Checkpoint, Vec<Vote>)> {
        // HALT (issue #74, H2) — **the load-bearing act**. §4: "the finality
        // committee stops checkpointing at exactly that height." The gate sits here,
        // as close to the signature as it can be: a halted committee member does not
        // produce the vote at all, rather than producing one that is later filtered.
        // The checkpoint *at* H is deliberately still produced — it is what makes the
        // upgrade boundary a finalized boundary.
        if !self.rules.halt.may_checkpoint(height) {
            return None;
        }
        let block_hash = self.chain.main_chain_hash_at(height)?;
        let cp = Checkpoint::new(height, block_hash, block_hash);
        let votes = finalizers.iter_mut().filter_map(|f| f.sign(&cp).ok()).collect();
        Some((cp, votes))
    }

    /// Name the header check that failed, so a rejection is attributable to a
    /// layer rather than to "something was wrong" (issue #74 drill evidence).
    fn header_reject_reason(err: &ValidationError) -> &'static str {
        match err {
            ValidationError::UnknownParent => "invalid header: unknown parent",
            ValidationError::BadHeight => "invalid header: height",
            ValidationError::NonMonotonicTimestamp => "invalid header: timestamp",
            ValidationError::WrongDifficulty { .. } => "invalid header: difficulty",
            // Under a post-halt rule domain this is the domain separation biting:
            // a block mined for the pre-halt rules does not meet the target here.
            ValidationError::PowUnsatisfied => "invalid header: pow",
            ValidationError::UnknownSeed => "invalid header: seed",
        }
    }

    /// Classify a body failure as intrinsic to the body or positional to this node
    /// (issue #134). See [`BodyFault`] for why the distinction exists.
    ///
    /// The reason strings are **unchanged** from the wildcard this replaces
    /// (`CommitmentMismatch` → its own string, everything else → `"bad body"`), so
    /// no existing rejection changes its name; the only thing this adds is a
    /// compiler-enforced decision point for every present and future variant.
    fn body_fault_class(err: &BodyError) -> BodyFault {
        match err {
            // Unambiguous misbehaviour by whoever handed us the pair, not a merely
            // invalid transaction — and it is the reason a body that reaches the
            // anchor check is always the body its header committed to.
            BodyError::CommitmentMismatch { .. } => {
                BodyFault::Intrinsic("body does not match header commitment")
            }
            // All computed from `(header, body)` alone: a minting block with no payee
            // (#101), the posted-price fee (§8), in-block nullifier uniqueness, and
            // the STARK proof. No node's chain position changes any of these answers.
            BodyError::MissingCoinbasePayee
            // Lab #470 stage 2: the payee-list length is a fact of the body
            // alone (and the birth cap a compiled constant) — as intrinsic as
            // MissingCoinbasePayee, whose class it shares.
            | BodyError::TooManyCoinbasePayees { .. }
            // Lab #299. `coinbase_exact(header.height)` is a pure function of the
            // height, evaluated identically on every conforming platform (#303) —
            // which is exactly what makes this intrinsic rather than positional. A
            // node's chain position, libc and view of finality are all irrelevant to
            // the answer, so a peer that relayed such a block either mis-assembled
            // it or never checked it.
            | BodyError::WrongScheduledCoinbase { .. }
            | BodyError::WrongFee { .. }
            | BodyError::DoubleSpendInBlock { .. }
            | BodyError::ProofInvalid { .. }
            // Issue #188. Both discovery rules read only the transaction's own
            // bytes and its own declared commitments, so they are as intrinsic
            // as the fee check — this node's chain position cannot change the
            // answer, which is what keeps them out of #134's amnesty.
            | BodyError::DiscoveryMalformed { .. }
            | BodyError::DiscoveryNotCanonical { .. }
            | BodyError::DiscoveryDoesNotBind { .. } => BodyFault::Intrinsic("bad body"),
            // Lab #367, the shape half: rider bytes that do not decode, and a
            // rider on the wrong side of the boundary (a pure height compare),
            // read nothing but the pair itself — intrinsic, like discovery's.
            BodyError::RiderMalformed { .. } | BodyError::RiderBeforeBoundary { .. } => {
                BodyFault::Intrinsic("bad body")
            }
            // Lab #367, the rule half — split by what the verdict reads:
            BodyError::RiderRule { err, .. } => match err {
                // Grammar, record kind and record size read only the revealed
                // record's own bytes.
                qlab_devnet::names::NameRuleError::Grammar
                | qlab_devnet::names::NameRuleError::UnknownRecordKind { .. }
                | qlab_devnet::names::NameRuleError::WrongRecordSize { .. } => {
                    BodyFault::Intrinsic("bad body")
                }
                // Commit-window, uniqueness and renewal verdicts answer from
                // THIS node's registry replay — a node that is behind answers
                // "no" from its own position, exactly the #134 shape below.
                qlab_devnet::names::NameRuleError::CommitNotFound
                | qlab_devnet::names::NameRuleError::NameTaken { .. }
                | qlab_devnet::names::NameRuleError::UnknownForRenewal => {
                    BodyFault::Positional("bad body")
                }
            },
            // The one positional check (#134). `is_valid_anchor` answers from THIS
            // node's root index, finalized head and applied tip; a joiner replaying
            // history has none of the three at the height it is being served, so its
            // "no" is a fact about itself.
            BodyError::AnchorNotFinal { .. } => BodyFault::Positional("bad body"),
        }
    }

    /// Whether this node's answer to the anchor-finality rule for `header`'s body is
    /// the **network's** answer, or merely a fact about where this node happens to
    /// stand (issue #134).
    ///
    /// Both clauses are computed from this node's own two numbers. **Nothing the
    /// sender says enters**, which is the property that keeps the amnesty from being
    /// a hole: a peer cannot put us into the unjudged case by claiming anything, and
    /// "the sender told me I'm syncing" is not expressible here.
    ///
    /// 1. **Position.** [`qlab_node::Node::apply_block`] refuses anything that does
    ///    not extend the applied tip (`NotExtendingTip`), so the applied tip is the
    ///    *only* position at which this check is ever run for real. Judged anywhere
    ///    else, `is_valid_anchor` reads a root index that does not yet contain the
    ///    roots this block may legitimately name, and measures `MAX_ANCHOR_AGE_BLOCKS`
    ///    against the wrong tip.
    /// 2. **Finality currency.** Even standing at the right height, the rule's other
    ///    input is this node's finalized head, and a node whose finality has not kept
    ///    up with its own chain has no view of what the network had finalized. That is
    ///    exactly `FinalityStatus::Degraded` — the project's existing definition of
    ///    "my finality is not current" ([`DEGRADED_MODE_LAG_BLOCKS`]) — and a joiner,
    ///    which has finalized nothing at all, is permanently in it.
    ///
    /// Both are read off the **state machine's** pair (applied tip / applied finalized
    /// head), not fork choice's, because those are precisely the two inputs
    /// `is_valid_anchor` consumed to produce the verdict being classified.
    fn anchor_verdict_is_authoritative(&self, header: &BlockHeader) -> bool {
        if header.prev != self.state.tip_hash() {
            return false;
        }
        matches!(
            finality_status(
                self.state.tip_height(),
                self.state.finalized_height(),
                DEGRADED_MODE_LAG_BLOCKS,
            ),
            FinalityStatus::Final
        )
    }

    /// Whether `header` is **settled history** (lab #402): the main-chain block at
    /// its own height, at or below the fork-choice finalized pointer.
    ///
    /// This is the predicate that authorises [`qlab_node::AnchorGate::SettledHistory`],
    /// so both of its inputs are chosen for what they prove:
    ///
    /// - the finalized pointer read here is **`ChainState`'s** (head #2), not the
    ///   tracker's: it has exactly one writer, the vote-tally path *after* the
    ///   unchanged `FinalityTracker::try_finalize` verified a roster-checked quorum
    ///   (`Self::ingest_checkpoint_votes`), and `ChainState::set_finalized` refuses a
    ///   point that is not a known header descending from the previous one — so a
    ///   height at or below it is committee-finalized AND on the header main chain;
    /// - [`ChainState::main_chain_hash_at`] reads the pure derived fork-choice index
    ///   maintained when headers connect or a pre-finality reorg replaces a suffix.
    ///   No-reorg-past-finality makes every indexed entry at or below the finalized
    ///   pointer immutable.
    ///
    /// Nothing the sender says enters (the #134 property, kept): both inputs are this
    /// node's own. A joiner that has not yet learned any finalized checkpoint answers
    /// `false` for everything and stays on today's paths.
    fn block_is_settled_history(&self, header: &BlockHeader) -> bool {
        self.chain.finalized_height().is_some_and(|height| header.height <= height)
            && self.chain.main_chain_hash_at(header.height) == Some(header.header_hash_for(self.rules.form))
    }

    fn reject_reason(err: &MempoolError) -> &'static str {
        match err {
            MempoolError::WrongFee { .. } => "wrong fee",
            MempoolError::AnchorNotValid => "anchor not valid",
            MempoolError::AlreadySpent { .. } => "nullifier spent",
            MempoolError::NullifierRepeatedInTx { .. } => "nullifier repeated in tx",
            MempoolError::NullifierConflictInPool { .. } => "nullifier in-pool conflict",
            MempoolError::DuplicateTx => "duplicate",
            // Issue #278. All three §4 discovery refusals are intrinsic to the
            // tx's own bytes — the same verdict on every node, from every chain
            // position — so, like `body_fault_class`'s reading of the identical
            // errors one layer up, they are peer faults (`Rejected`), never the
            // state-lag `Ignored`. Named individually because *cannot parse*
            // and *parses but does not bind* are different peers doing
            // different things (the #134/#164/#181 lesson).
            MempoolError::DiscoveryInvalid(e) => match e {
                BodyError::DiscoveryMalformed { .. } => "discovery malformed",
                BodyError::DiscoveryNotCanonical { .. } => "discovery not canonical",
                _ => "discovery does not bind",
            },
            // Lab #367: the rider rules, named the way the discovery ones are —
            // malformed / before-boundary are intrinsic (peer fault), the
            // rule failures positional (a node behind on the registry). The
            // string mirrors `body_fault_class`'s reading one layer up.
            MempoolError::RiderInvalid(e) => match e {
                BodyError::RiderMalformed { .. } => "rider malformed",
                BodyError::RiderBeforeBoundary { .. } => "rider before boundary",
                _ => "rider rule",
            },
            MempoolError::ProofInvalid => "proof invalid",
        }
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> ChainView for NodeAdapter<P, V> {
    fn genesis_form(&self) -> GenesisForm {
        // The one installed source (lab #470): the P2P codec reads the form
        // from the same ChainRules consensus runs under.
        self.rules.form
    }

    fn genesis_block_hash(&self) -> Hash32 {
        self.chain.genesis_block_hash()
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
        self.chain.main_chain_hash_at(height)
    }
    fn has_header(&self, hash: &Hash32) -> bool {
        self.chain.header(hash).is_some()
    }
    fn finalized_height(&self) -> Option<u64> {
        // Committee checkpoints are the source of truth (as in `StubNode`).
        self.finality.finalized_height()
    }
    fn stored_body(&self, hash: &Hash32) -> Option<BlockBody> {
        // The state machine's block store (issue #135): written inside
        // `apply_block` — the same append that makes a body durable (#104) — so an
        // answer here is a body this node validated AND folded into state. A body
        // merely buffered in `pending_bodies` is deliberately not served from
        // here: it has not been applied, and it is still in the serving cache if
        // it arrived for a new header.
        use qlab_node::ChainStore as _;
        self.state.chain().block(hash).map(|b| b.body())
    }
    fn has_stored_body(&self, hash: &Hash32) -> bool {
        use qlab_node::ChainStore as _;
        self.state.chain().block(hash).is_some()
    }
    fn held_body(&self, hash: &Hash32) -> Option<BlockBody> {
        // POSSESSION (issue #198): the applied store, then the rewind archive —
        // bodies this node applied at some point and still holds. `MemNode` owns
        // that distinction because `rewind_to` is where it is created.
        self.state.held_block(hash).map(|b| b.body())
    }

    /// The main-chain blocks whose bodies this node still needs (issue #130 (c)).
    ///
    /// **Where the walk starts is the whole of the correctness here**, and it is not
    /// the applied tip. It is [`Self::state_fork_point`] — the highest applied block
    /// that is *also* on the fork-choice main chain — for the #162 case: a state
    /// machine stranded on a losing sibling has an applied tip that is on no chain
    /// anyone will extend, and asking for `applied_tip + 1` there would request a
    /// block that does not exist. Starting at the fork point instead asks for
    /// `fork + 1`, which is exactly the body [`Self::rejoin_main_chain`] requires
    /// before it will rewind — so the requester also unwedges a strand whose sibling
    /// body was never offered live, which is the case #162 could only handle when the
    /// body happened to arrive on its own.
    ///
    /// Two exclusions, both of which are what makes the ask set shrink monotonically:
    ///
    /// - **already applied** — read from the state machine's own block store, the same
    ///   authority [`Self::is_body_worth_holding`] uses;
    /// - **already held in the pending-body window** — it will drain on its own as the
    ///   tip advances, and re-fetching it would be pure duplicate traffic.
    ///
    /// **The scan finds the first `max` MISSING hashes, not the missing residue of
    /// the first `max` heights** (lab #427). The pre-#427 shape — a window of `max`
    /// heights above the fork point — anchored the whole fetch pipeline to the
    /// applied tip: once most of that span was buffered, the ask set collapsed to
    /// the unanswered residue (the live joiner's `bask=19@1135` against
    /// `slag=12611`), and no new fetching could start until the residue landed.
    /// Every unserved low ask therefore gated the pipeline for one or more full
    /// [`crate::node::BODY_REQUEST_TIMEOUT_MS`] cycles, which is where the measured
    /// ~1.3 blk/s came from: ~96 blocks per ~74 s of re-ask ladder, independent of
    /// CPU and RTT. Scanning to the first `max` missing lets the fetch run ahead
    /// while a residue waits, so a slow block costs itself, not the window.
    ///
    /// The scan stays bounded on two axes, both #135-shaped (never ask for a body
    /// this node would then drop):
    ///
    /// - **the admission horizon** — never past
    ///   [`MAX_PENDING_BODY_HEIGHTS`] above the applied tip, the exact bound
    ///   [`Self::is_body_worth_holding`] admits against;
    /// - **buffer backpressure** — the scan extends past the classic `base + max`
    ///   window only while `pending_bodies` has room for a whole in-flight window
    ///   ([`crate::node::MAX_BODIES_IN_FLIGHT_CATCHUP`] entries) and its bytes are
    ///   under half [`MAX_PENDING_BODY_BYTES`] (a full catch-up window of FROZEN
    ///   v1.0 single-tx answers is ~14 MB — the #418 arithmetic — so half the cap
    ///   plus one window still cannot trigger the evict-highest churn the old
    ///   window bound existed to prevent).
    ///
    /// Cost: one O(1) indexed lookup at `top` plus at most
    /// [`MAX_PENDING_BODY_HEIGHTS`] parent hops. The distance from the header tip
    /// down to the applied tip is not part of the cost.
    fn missing_body_hashes(&self, max: usize) -> Vec<Hash32> {
        use qlab_node::ChainStore as _;
        if max == 0 {
            return Vec::new();
        }
        let base = self
            .state_fork_point()
            .map(|(h, _)| h)
            .unwrap_or_else(|| self.state.tip_height());
        let tip = self.chain.tip_height();
        // Fetch-ahead is admission-bounded and backpressure-gated; with no room it
        // degrades to exactly the pre-#427 window, which #418's sizing proved safe.
        let admit_top = self.state.tip_height().saturating_add(MAX_PENDING_BODY_HEIGHTS);
        let room = self
            .pending_bodies
            .len()
            .saturating_add(crate::node::MAX_BODIES_IN_FLIGHT_CATCHUP)
            <= MAX_PENDING_BODIES
            && self.pending_bytes < MAX_PENDING_BODY_BYTES / 2;
        let top = if room {
            tip.min(admit_top)
        } else {
            tip.min(base.saturating_add(max as u64))
        };
        if top <= base {
            return Vec::new();
        }
        let Some(mut hash) = self.main_chain_hash_at(top) else {
            return Vec::new();
        };
        let mut height = top;
        let mut out = Vec::new();
        loop {
            let held = self.state.chain().contains(&hash)
                || self.pending_bodies.contains_key(&(height, hash));
            if !held {
                out.push(hash);
            }
            if height == base + 1 {
                break;
            }
            let Some(header) = self.chain.header(&hash) else { break };
            hash = header.prev;
            height -= 1;
        }
        out.reverse(); // ascending — the order the state machine can apply them in
        // The walk is top-down (parent hops), so the cut to `max` must happen after
        // the reverse: the requester wants the LOWEST `max` missing — those are the
        // ones that close the gap — not the highest.
        out.truncate(max);
        out
    }

    fn holds_body_buffered(&self, hash: &Hash32) -> bool {
        // The pending map is keyed `(height, hash)` for ascending drain order;
        // the height comes from the header, which the buffer's admission gate
        // guarantees this node holds.
        self.chain
            .header(hash)
            .is_some_and(|h| self.pending_bodies.contains_key(&(h.height, *hash)))
    }

    fn observe_body_fetch(
        &mut self,
        now_ms: u64,
        outstanding_breqs: usize,
        body_progress: bool,
    ) {
        NodeAdapter::observe_body_fetch(self, now_ms, outstanding_breqs, body_progress);
    }

    fn state_tip_mine_ready(&self) -> bool {
        NodeAdapter::state_tip_mine_ready(self)
    }

    fn state_lag_blocks(&self) -> u64 {
        self.state_lag().blocks()
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> BlockIngest for NodeAdapter<P, V> {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome {
        self.submit_header(header)
    }

    fn ingest_finalized_headers(&mut self, headers: &[BlockHeader]) -> IngestOutcome {
        // The tracker only advances through the roster/signature/quorum gate. Its
        // block may be ahead of our local chain on the explicit eager-fetch path;
        // this span is admitted only when its hash chain lands exactly on that
        // attested block.
        let Some(checkpoint) = self.finality.latest().copied() else {
            return IngestOutcome::Rejected("no verified finalized checkpoint");
        };
        let Some(first) = headers.first() else {
            return IngestOutcome::Rejected("empty checkpoint header span");
        };
        let Some(last) = headers.last() else {
            return IngestOutcome::Rejected("empty checkpoint header span");
        };
        if last.height != checkpoint.height || last.header_hash_for(self.rules.form) != checkpoint.block_hash {
            return IngestOutcome::Rejected("checkpoint header frontier mismatch");
        }
        if first.height == 0
            || self.chain.main_chain_hash_at(first.height - 1) != Some(first.prev)
        {
            return IngestOutcome::Orphan;
        }
        let Some(mut parent) = self.chain.header(&first.prev).copied() else {
            return IngestOutcome::Orphan;
        };
        for header in headers {
            if !self.rules.halt.accepts_height(header.height) {
                return IngestOutcome::Ignored("above halt height");
            }
            if self.chain.header(&header.header_hash_for(self.rules.form)).is_some() {
                return IngestOutcome::Duplicate;
            }
            if header.prev != parent.header_hash_for(self.rules.form) || header.height != parent.height + 1 {
                return IngestOutcome::Rejected("non-contiguous checkpoint header span");
            }
            if header.timestamp < parent.timestamp {
                return IngestOutcome::Rejected("non-monotonic checkpoint header timestamp");
            }
            parent = *header;
        }

        // Every fallible structural check ran above, before the validated chain was
        // touched. Difficulty and nonce are intentionally not re-derived: the exact
        // header bytes are transitively attested by the frontier hash and quorum.
        for header in headers {
            if !matches!(self.insert_validated_header(*header), IngestOutcome::Accepted) {
                return IngestOutcome::Rejected("checkpoint header insertion failed");
            }
        }
        if self.chain.set_finalized(checkpoint.block_hash).is_err() {
            return IngestOutcome::Rejected("checkpoint finality mark failed");
        }
        self.sync_state_finality();
        IngestOutcome::Accepted
    }

    fn ingest_block(&mut self, header: BlockHeader, body: BlockBody) -> IngestOutcome {
        // 1. Body validity is checked independently of tip-extension: a body that is
        //    not the one this header committed to (issue #77), or an invalid tx proof
        //    / fee / in-block double-spend, is adversarial and is rejected + penalized
        //    regardless of fork position. `validate_body` checks the header/body
        //    binding first — it is the cheapest rejection and, for the empty-body
        //    relay, the only one that fires.
        //
        //    Issue #134 splits that sentence, because it was never true of *every*
        //    body failure. A body can be **intrinsically** invalid — the same verdict
        //    on every node, from every position — or it can fail a check this node
        //    computes **against its own applied state**, where an honest peer serving
        //    correct history draws the same verdict as an attacker. The anchor rule is
        //    the second kind, and the old `Err(_)` wildcard charged both at
        //    `PENALTY_INVALID_OBJECT`: a joiner replaying a chain that has ever carried
        //    one transaction banned the peer serving it after five blocks and its whole
        //    outbound set after forty — for correct behaviour, with no malformed byte
        //    on the wire. See [`BodyFault`] for the boundary, and
        //    [`Self::anchor_verdict_is_authoritative`] for how a node decides which
        //    side of it it is standing on.
        let anchor_ok = |root: &Hash32| self.state.is_valid_anchor(root);
        // The rule funnel keyed by the installed form (lab #470 stage 3): the
        // v4 arm is the v2/v3 body rule; the v5 arm is the same loop under the
        // v5 forms. Both thread this node's applied registry — the armed-node
        // path lab #381 specified (`validate_body_with_names` /
        // `validate_body_v5` with a real NameView). EmptyNameView was the
        // inert-era / pre-boundary shortcut: `commit_included_in` is
        // unconditionally false, so a current node that assembled a reveal
        // from its own registry then refused the block it just built
        // (lab #624).
        //
        // A positional `CommitNotFound` is charged only when
        // `anchor_verdict_is_authoritative`, whose first clause is
        // `header.prev == state.tip_hash()`. The registry is applied state
        // (`apply_state` → `names.apply_block_riders`), so a registry that is
        // stale for this block means the applied tip is not the parent and
        // the node is never charged. That is the position clause alone.
        // `is_valid_anchor` also reads the finalized head (checkpoint path,
        // not `apply_state`), so the two do not go stale together; a lagging
        // finality only makes the authority predicate more conservative.
        let validate_result = match self.rules.form {
            GenesisForm::V4 => validate_body_with_names(
                &header,
                &body,
                &self.verifier,
                anchor_ok,
                self.state.names(),
            ),
            GenesisForm::V5 => qlab_devnet::body::validate_body_v5(
                &header,
                &body,
                &self.verifier,
                anchor_ok,
                self.state.names(),
            ),
        };
        match validate_result {
            Ok(()) => {}
            Err(e) => match Self::body_fault_class(&e) {
                BodyFault::Intrinsic(why) => return IngestOutcome::Rejected(why),
                // Positional, but the block is SETTLED HISTORY (lab #402): the
                // main-chain block at its own height under the quorum-verified
                // finalized pointer. Our positional "no" is then a fact about our
                // lagging replay, not about the block — the #402 deadlock was this
                // arm's predecessor refusing the same canonical body forever (81
                // served answers, applied tip pinned at 4912). Fall through to the
                // header-submit + buffer path below: the binding already passed
                // (it is checked before the anchor, so a buffered body is
                // bit-exact the one its mined main-chain header committed to), and
                // `drain_pending_bodies` re-validates EVERYTHING — proofs
                // included — inside `apply_block_gated` at exactly the position
                // the rule is defined at, under the as-of-height anchor gate.
                //
                // Checked BEFORE the authoritative arm on purpose: a node whose
                // own state briefly lags the finalized pointer could otherwise
                // stand at its tip, judge a canonical block by its stale live
                // view, and charge the honest peer that served it.
                BodyFault::Positional(_) if self.block_is_settled_history(&header) => {}
                // Positional. Charged where our verdict IS the network's — the live
                // path, where a bad anchor is a bad anchor and costs the sender
                // exactly what it costs today.
                BodyFault::Positional(why) if self.anchor_verdict_is_authoritative(&header) => {
                    return IngestOutcome::Rejected(why)
                }
                // Positional, and we cannot judge it. Judge the HEADER instead: PoW +
                // LWMA under this release's rules is a check with no positional
                // component, and it is what separates "a peer served me real history"
                // from "a peer sent me bytes".
                //
                // **This is the price of the amnesty, and it is what stops it being a
                // hole.** `validate_body` runs the header/body binding FIRST, so a body
                // that reached the anchor check is the body this header committed to;
                // an attacker who wants an uncharged refusal must therefore bring a
                // *mined* header committing to their bad body — a block of real work
                // per attempt, at the difficulty the chain is running at. Anything
                // cheaper lands in one of the arms below and is charged.
                BodyFault::Positional(_) => {
                    return match self.submit_header(header) {
                        // Real work, and the header is now ours — so this is
                        // header-first sync doing its job, and the announcement that
                        // carried it was not wasted. The BODY is still refused: not
                        // relayed, not applied, and not buffered (its proofs were never
                        // verified, so it must not enter the #130 (a) window). And —
                        // the load-bearing part — the sender is NOT scored.
                        //
                        // Not penalising is not accepting.
                        IngestOutcome::Accepted | IngestOutcome::Duplicate => {
                            self.ingest_counters.unjudged_anchor += 1;
                            IngestOutcome::Ignored(UNJUDGED_ANCHOR_REASON)
                        }
                        // Unknown parent → the same orphan sync-kick a header-only
                        // announce gets, rather than a fault. Invalid header → the
                        // fault is the header's and it is now NAMED as one
                        // ("invalid header: pow") instead of being folded into the
                        // undifferentiated "bad body" this arm used to return.
                        other => other,
                    };
                }
            },
        }
        // 2. Header into the consensus chain (PoW / fork-choice).
        let outcome = self.submit_header(header);
        // 3. Application is gated on **whether we hold this header**, never on
        //    whether the header was NEW (issue #130 (a)).
        //
        //    GUARANTEED: a body whose header is in this node's chain is applied as
        //    soon as the state tip reaches its parent, in ascending height order,
        //    and the state machine converges on its own chain with no restart.
        //
        //    `Duplicate` is the load-bearing half of that condition. Header-first
        //    sync means the header is normally already known by the time its body is
        //    announced, so the old `== Accepted` gate discarded exactly the body that
        //    closes the gap, one branch above the `NotExtendingTip` arm the issue was
        //    filed against. `Ignored` is deliberately excluded: a halted release must
        //    not apply above its halt height (#74 H2), and `Orphan`/`Rejected` mean
        //    the header is not in the chain to apply a body against.
        if matches!(outcome, IngestOutcome::Accepted | IngestOutcome::Duplicate) {
            self.buffer_body(header, body);
            self.drain_pending_bodies();
        }
        outcome
    }
}

/// Why a submitted transaction was refused, carried whole (issue #275).
///
/// [`NodeAdapter::submit_tx_typed`] returns this so the deployed `POST /v1/tx`
/// surface can answer with a **named** refusal — `TxPool::ingest_tx`'s
/// [`IngestOutcome`] flattens the same verdict to a relay decision plus a static
/// string, which is the right shape for the peer wire and boolean-blind for a
/// wallet (`WrongFee`'s expected/got, in particular, do not survive it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxSubmitRefusal {
    /// The node cannot judge (issue #130 (a)): its applied state is behind its
    /// chain, and a stale tree answers the anchor rule wrongly in both
    /// directions. Not the submitter's fault — retry once the node catches up.
    StateLagging,
    /// Refused by the pool's admission gates, reason carried whole.
    Pool(MempoolError),
}

impl<P: PowEngine, V: TxVerifier + Clone> NodeAdapter<P, V> {
    /// Typed submission — **the exact admission [`TxPool::ingest_tx`] applies**,
    /// with the refusal carried whole instead of flattened to a relay verdict
    /// (issue #275). `ingest_tx` is a mapping over this, so the deployed
    /// `POST /v1/tx` surface and the peer wire cannot run two different rules.
    ///
    /// STATE LAG (issue #130 (a), part 3 — refusals two and three, which are the
    /// same seam): `Mempool::admit` answers `is_valid_anchor` from the state
    /// machine's tree, and a stale tree answers a CONSENSUS rule (protocol-spec
    /// §4 / frozen §7) wrongly in both directions — it cannot see roots it has
    /// not applied, and its stale tip makes the `MAX_ANCHOR_AGE_BLOCKS` window
    /// read as more permissive than it is. This is also the wallet refusal —
    /// `submit_local_tx` (#123) and the `POST /v1/tx` surface both land here —
    /// so a wallet cannot cut a witness against the wrong prefix of the tree
    /// and have this node take it.
    ///
    /// Issue #102: there is no coinbase-maturity declaration to pass and no way
    /// for this path to skip the rule — an immature coinbase has no leaf in any
    /// valid anchor, so a spend of one has no witness, fails `verify_tx`, and is
    /// refused as `ProofInvalid` by the same check that refuses every other
    /// unprovable claim.
    pub fn submit_tx_typed(&mut self, tx: TxEntry) -> Result<TxId, TxSubmitRefusal> {
        if self.state_lag().is_lagging() {
            self.refuse_for_lag("admit_tx");
            return Err(TxSubmitRefusal::StateLagging);
        }
        let wid = wire_tx_id(&tx);
        // Admission is keyed by the installed form, the same way body validation
        // is (see the `validate_body` / `validate_body_v5` funnel below): a name
        // rider on a v5 net is native from height ≥ 1, so the mempool must use
        // the form's admit boundary (V5 → Some(0)), NOT `Mempool::admit`'s
        // hardcoded v4 `NAME_RULE_BOUNDARY_HEIGHT` — which refused every T2 name
        // op as `RiderBeforeBoundary` while v5 block-validation accepted it.
        let admit_boundary = self.rules.form.rider_admit_boundary();
        match self.mempool.admit_above(
            admit_boundary,
            tx,
            &self.state,
            &self.verifier,
            self.state.names(),
        ) {
            Ok(id) => {
                self.wire_ids.insert(wid, id);
                Ok(id)
            }
            Err(e) => Err(TxSubmitRefusal::Pool(e)),
        }
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> TxPool for NodeAdapter<P, V> {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
        // The admission itself lives in `submit_tx_typed` (issue #275) — this is
        // the peer wire's flattening of it and nothing more. `Ignored`, never
        // `Rejected`, for state lag: the transaction may be perfectly valid and
        // the sender is not at fault, and #134 is precisely the cost of confusing
        // "this is invalid" with "I cannot judge this". So it is not relayed, not
        // pooled, and NOT scored.
        match self.submit_tx_typed(tx) {
            Ok(_) => IngestOutcome::Accepted,
            Err(TxSubmitRefusal::StateLagging) => IngestOutcome::Ignored(STATE_LAG_REASON),
            Err(TxSubmitRefusal::Pool(MempoolError::DuplicateTx)) => IngestOutcome::Duplicate,
            Err(TxSubmitRefusal::Pool(e)) => IngestOutcome::Rejected(Self::reject_reason(&e)),
        }
    }
    fn get_tx(&self, id: &Hash32) -> Option<TxEntry> {
        self.wire_ids.get(id).and_then(|txid| self.mempool.get(txid).cloned())
    }
    fn has_tx(&self, id: &Hash32) -> bool {
        self.wire_ids.get(id).is_some_and(|txid| self.mempool.contains(txid))
    }
    fn all_txs(&self) -> Vec<TxEntry> {
        self.mempool.entries()
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> CheckpointIngest for NodeAdapter<P, V> {
    fn finalized_checkpoint(&self) -> Option<Checkpoint> {
        self.finality.latest().copied()
    }

    // #362: the real tally's stored variants — what the boundary re-push sends.
    fn checkpoint_variants_at(&self, height: u64) -> Vec<(Checkpoint, Vec<Vote>)> {
        self.tally.variants_at(height)
    }

    fn ingest_checkpoint_votes_from(
        &mut self,
        cp: &Checkpoint,
        votes: &[Vote],
        explicitly_requested: bool,
    ) -> VotesOutcome {
        let id = checkpoint_id(cp);
        if self.seen_checkpoints.contains(&id) {
            return VotesOutcome::Stale; // already finalized this variant
        }
        // HALT (issue #74, H2): a halted node must not FINALIZE above H either — it
        // would be finalizing a chain it refuses to accept. `Stale`, not `Invalid`:
        // the sender is on a different release, not misbehaving (S5).
        if !self.rules.halt.may_checkpoint(cp.height) {
            return VotesOutcome::Stale;
        }
        let finalized = self.finality.finalized_height();
        let tip = self.chain.tip_height();
        // The round's roster context, read once from the committee state for this
        // height (issue #87). Every diagnostic number below is relative to it.
        let ctx = self.slot_context(cp.height);

        // Verify + active-filter against THIS height's epoch roster (frozen §4:
        // tombstoned/jailed excluded BEFORE the count). Issue #164 splits the old
        // catch-all `Invalid` the way #134 split the body-path wildcard — but
        // **only** the out-of-range arm is positional (PR #166 rework):
        //
        // - index out of range for this roster → `Unjudged` (positional)
        // - index resolves, signature fails against that key → `Invalid` (forged)
        // - duplicate-signer padding → `Invalid`
        //
        // `committee` is cloned so the immutable borrow ends before the mutable ops.
        //
        // Issue #87: each refusal is *recorded before it returns*. The 42 h soak's
        // silence was not only about rounds that ended short — a round being fed
        // junk looks identical, in the old logs, to a round nobody spoke about.
        let (committee, quorum, active_kept, excluded_idx, rejects) = {
            let cstate = self.committee.state_for_height(cp.height);
            let committee = cstate.committee().clone();
            let mut seen_signer = HashSet::new();
            let mut active_kept: Vec<Vote> = Vec::new();
            let mut excluded_idx: Vec<usize> = Vec::new();
            let mut rejects = VoteRejects::default();
            for v in votes {
                if committee.member(v.signer).is_none() {
                    rejects.unknown_signer += 1;
                    self.rounds.note_rejected_message(&ctx, rejects);
                    self.metrics.observe_votes(0, rejects);
                    return VotesOutcome::Unjudged; // index does not resolve under my roster
                }
                if !seen_signer.insert(v.signer) {
                    rejects.duplicate += 1;
                    self.rounds.note_rejected_message(&ctx, rejects);
                    self.metrics.observe_votes(0, rejects);
                    return VotesOutcome::Invalid; // duplicate-signer padding
                }
                if !committee.verify_vote(cp, v) {
                    rejects.forged += 1;
                    self.rounds.note_rejected_message(&ctx, rejects);
                    self.metrics.observe_votes(0, rejects);
                    // Index resolved; signature fails against that key → forged.
                    // Do NOT re-check other roster slots: that arm was over-broad
                    // and classed the soak's forged-cp (member-1 sig as signer 0)
                    // as Unjudged (PR #166 rejection).
                    return VotesOutcome::Invalid;
                }
                if cstate.is_active(v.signer, cp.height) {
                    active_kept.push(v.clone());
                } else {
                    // Valid but jailed/tombstoned — excluded, NOT penalised. Recorded
                    // separately from `absent` so an operator never goes looking for a
                    // host that the rule itself removed.
                    excluded_idx.push(v.signer);
                    rejects.inactive += 1;
                }
            }
            (committee, cstate.quorum_threshold(), active_kept, excluded_idx, rejects)
        };

        let added = if explicitly_requested && active_kept.len() >= quorum {
            self.tally.add_requested_complete(cp, &active_kept, quorum, finalized, tip)
        } else {
            self.tally.add(cp, &active_kept, finalized, tip)
        };
        let variants = self.tally.variant_count(cp.height);
        if !added.grew {
            // Nothing new — still a message this round received, and the roster
            // context may have moved; record it without disturbing what is known.
            let new = self.rounds.note_votes(&ctx, &[], &excluded_idx, rejects, variants);
            self.metrics.observe_votes(new.newly as u64, rejects);
            return VotesOutcome::Stale;
        }

        // Re-filter by CURRENT active status, then let the AUTHORITATIVE try_finalize
        // gate decide — the tally never lowers the bar (S4).
        let active_now: Vec<Vote> = {
            let cstate = self.committee.state_for_height(cp.height);
            added.accumulated.iter().filter(|v| cstate.is_active(v.signer, cp.height)).cloned().collect()
        };
        // Issue #87 / #226: `counted` is this **variant's** full accumulated set
        // (what `try_finalize` is handed). The ledger unions it into `seen` and
        // tracks `have` = max over variants so `have` stays comparable to `need`.
        // Arrival offsets of newly-seen signers feed the histogram directly —
        // they cannot be recovered later from a printed count.
        {
            let counted: Vec<usize> = active_now.iter().map(|v| v.signer).collect();
            let new = self.rounds.note_votes(&ctx, &counted, &excluded_idx, rejects, variants);
            self.metrics.observe_votes(new.newly as u64, rejects);
            for offset in new.arrivals {
                self.metrics.observe_vote_arrival(offset);
            }
        }
        if active_now.len() >= quorum {
            // Captured before the finalize so the advance can be measured against the
            // head it actually replaced (issue #87).
            let prev_cp = self.finality.latest().copied();
            match self.finality.try_finalize(cp, &active_now, &committee) {
                Ok(()) => {
                    self.seen_checkpoints.insert(id);
                    self.observe_finality_advance(cp, prev_cp, tip);
                    // Advance the consensus finalized pointer (no reorg past finality).
                    //
                    // Issue #204: this was `let _ =`. `ChainState::set_finalized`
                    // returns a typed refusal and it was being thrown away, so a
                    // fork-choice head that declined to advance was byte-identical,
                    // on every surface, to one that did.
                    match self.chain.set_finalized(cp.block_hash) {
                        Ok(()) => {
                            self.note_finalize_recorded("chain");
                        }
                        Err(e) => {
                            // Issue #241: this head always held the typed refusal —
                            // it is the durable head that lost it. The rendering now
                            // goes through the same one-way door for both, so the
                            // two heads cannot drift apart on what a reason is
                            // called.
                            self.note_finalize_refused(
                                "chain",
                                cp.height,
                                cp.block_hash,
                                e.into(),
                            );
                        }
                    }
                    // …and the state machine's finalized head, through the single
                    // place that does it. It may not hold this block yet — but that is
                    // no longer where the attempt ends: the next drain retries it
                    // (issue #130 (a)).
                    self.sync_state_finality();
                    let signers: Vec<usize> = active_now.iter().map(|v| v.signer).collect();
                    self.signing.record_round(&signers);
                    self.apply_downtime_jails(cp.height);
                    self.tally.on_finalized(cp.height);
                    // Close this round, and every lower open round with it: a
                    // strictly-advancing finalize is exactly what makes those slots
                    // unfinalizable, so this is where a catch-up jump becomes one
                    // journal line per skipped slot instead of one silent gap.
                    self.rounds.note_finalized(cp.height);
                    return VotesOutcome::Learned { finalized: true, accumulated: added.accumulated };
                }
                Err(FinalizeError::NotAdvancing { .. }) => {
                    self.seen_checkpoints.insert(id);
                    return VotesOutcome::Stale;
                }
                Err(_) => return VotesOutcome::Invalid, // pre-verified; defensive
            }
        }
        VotesOutcome::Learned { finalized: false, accumulated: added.accumulated }
    }
    fn has_checkpoint(&self, id: &Hash32) -> bool {
        self.seen_checkpoints.contains(id)
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> CommitteeControl for NodeAdapter<P, V> {
    fn observe_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> Vec<EquivocationEvidence> {
        let mut evidence = Vec::new();
        for v in votes {
            {
                let committee = self.committee.state_for_height(cp.height).committee();
                if !committee.verify_vote(cp, v) {
                    continue; // a forged vote cannot seed fake evidence
                }
            }
            let key = (cp.height, v.signer);
            match self.votes_seen.get(&key) {
                Some((prev_cp, prev_vote)) if prev_cp != cp => {
                    let ev = EquivocationEvidence {
                        cp_a: *prev_cp,
                        vote_a: prev_vote.clone(),
                        cp_b: *cp,
                        vote_b: v.clone(),
                    };
                    let committee = self.committee.state_for_height(cp.height).committee();
                    if verify_equivocation(&ev, committee).is_ok() {
                        evidence.push(ev);
                    }
                }
                Some(_) => { /* duplicate vote, not a conflict */ }
                None => {
                    self.votes_seen.insert(key, (*cp, v.clone()));
                }
            }
        }
        evidence
    }

    fn apply_evidence(&mut self, ev: &EquivocationEvidence) -> Option<usize> {
        let verified =
            verify_equivocation(ev, self.committee.state_for_height(ev.cp_a.height).committee());
        match verified {
            Ok(signer) => {
                // Durability FIRST (issue #133). A tombstone is permanent under FROZEN
                // §4 and cannot be re-derived from anything on disk — evidence is not in
                // blocks and the gossip that carried it is push-once — so a process that
                // dies between applying a punishment and recording it has simply lost
                // it, and the member is Active with a full bond on the next start. The
                // record is written ahead of the effect for the same reason the finalizer
                // ledger is written ahead of its vote.
                let already = matches!(
                    self.committee.state().status(signer),
                    Some(MemberStatus::Tombstoned)
                );
                if !already {
                    self.punishments.push(ev.clone());
                    if let Some(dir) = self.dir.clone() {
                        if let Err(e) = punish::save(&dir, &self.punishments) {
                            // The exclusion is applied anyway, and loudly. Frozen §4's
                            // "tombstoned votes MUST NOT count toward quorum" is an
                            // immediate safety rule, and making it conditional on a disk
                            // write would trade a durability failure for a live one. What
                            // the operator needs to know is that it will not survive a
                            // restart.
                            qlab_devnet::jeprintln!(ERROR,
                                "⚠️  committee punishment for member {signer} APPLIED but NOT \
                                 PERSISTED ({e}): the tombstone is in force now and will be LOST \
                                 on restart. Fix the data dir before restarting this node."
                            );
                        }
                    }
                }
                // Equivocation slash = **10 % of the member's bond** + permanent
                // tombstone (consensus-parameters §4 FROZEN; issue #62 item 5
                // convergence — replaces the flat `EQUIVOCATION_SLASH_AMOUNT`
                // placeholder now that the bond is a genesis constant). Integer
                // floor; a ramped bond of 0 slashes 0 (still tombstones). Named in
                // `ebbflow` since #133, because the restart path re-derives it and two
                // copies of a frozen rule is how the two views drift apart.
                let bond = self.committee.state().bond(signer).unwrap_or(0);
                let slash = equivocation_slash(bond);
                self.committee.state_mut().tombstone(signer, slash);
                Some(signer)
            }
            Err(_) => None,
        }
    }

    fn finality_status(&self) -> FinalityStatus {
        // Halt-aware (issue #74): `Halting`/`Halted` when a halt governs, the
        // ordinary Ebb-and-Flow pair otherwise. Single derivation, in qlab-devnet.
        halt_regime(
            self.chain.tip_height(),
            self.finality.finalized_height(),
            DEGRADED_MODE_LAG_BLOCKS,
            self.rules.halt.halt_at(),
        )
    }

    fn is_tombstoned(&self, idx: usize) -> bool {
        matches!(self.committee.state().status(idx), Some(MemberStatus::Tombstoned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use qlab_devnet::committee::devnet_committee;
    use qlab_devnet::fees::{posted_fee, ArityBucket};
    use qlab_devnet::params_devnet::BOND_AMOUNT;
    use qlab_devnet::pow::KeccakPow;
    use qlab_node::round::{RoundClose, RoundDiagnosis};
    use qlab_node::ChainStore as _;
    use qlab_node::telemetry::Telemetry;

    /// Mock M3 verifier: a proof is valid iff its bytes are exactly `b"ok"`.
    #[derive(Clone)]
    struct MockVerifier;
    impl TxVerifier for MockVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    #[derive(Clone)]
    struct CountingPow {
        calls: Arc<AtomicUsize>,
    }

    impl PowEngine for CountingPow {
        fn name(&self) -> &'static str {
            "counting-keccak"
        }

        fn pow_hash(&self, form: GenesisForm, header: &BlockHeader, seed: &[u8]) -> Hash32 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            KeccakPow.pow_hash(form, header, seed)
        }
    }

    fn sim() -> SimConfig {
        SimConfig::default()
    }

    /// A 7-member committee (quorum 5) + its validators.
    fn committee7() -> (CommitteeState, Vec<Validator>) {
        let (committee, validators) = devnet_committee(7);
        (CommitteeState::new(committee, BOND_AMOUNT), validators)
    }

    /// An adapter whose genesis (empty-tree) root is a finalized, valid anchor —
    /// so an ordinary tx anchored to it can be admitted.
    fn adapter_with_finalized_genesis() -> (NodeAdapter<KeccakPow, MockVerifier>, Hash32) {
        let (cstate, _v) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let g = a.chain().genesis_block_hash();
        // Finalize genesis in the real state machine → its commitment root is a
        // valid anchor within the age window.
        a.state_mut().finalize(g).expect("finalize genesis");
        let anchor = a.state().commitment_root();
        (a, anchor)
    }

    /// The form-aware sibling of [`adapter_with_finalized_genesis`]. The form
    /// must be installed before genesis is finalized: `set_chain_rules` re-keys
    /// an untouched adapter, and the finalized anchor must belong to that
    /// re-keyed chain rather than to the default v4 one.
    fn adapter_for_form_with_finalized_genesis(
        form: GenesisForm,
    ) -> (NodeAdapter<KeccakPow, MockVerifier>, Hash32) {
        let (cstate, _v) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        a.set_chain_rules(ChainRules { form, halt: RuleSchedule::V1_0 });
        let g = a.chain().genesis_block_hash();
        a.state_mut().finalize(g).expect("finalize the installed form's genesis");
        let anchor = a.state().commitment_root();
        (a, anchor)
    }

    fn tx_with(anchor: Hash32, nf: u8, proof: &[u8]) -> TxEntry {
        TxEntry::with_placeholder_discovery(proof.to_vec(), qlab_devnet::body::TxPublic {
            anchor,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(50); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
            })
    }

    #[test]
    fn txpool_rejects_invalid_proof_and_admits_valid() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        let good = tx_with(anchor, 1, b"ok");
        assert_eq!(a.ingest_tx(good.clone()), IngestOutcome::Accepted);
        assert!(a.has_tx(&wire_tx_id(&good)));
        assert_eq!(a.get_tx(&wire_tx_id(&good)).map(|t| t.public.anchor), Some(anchor));
        // A tx with a proof the injected verifier rejects → Rejected, not pooled.
        let bad = tx_with(anchor, 2, b"nope");
        assert!(matches!(a.ingest_tx(bad.clone()), IngestOutcome::Rejected(_)));
        assert!(!a.has_tx(&wire_tx_id(&bad)));
        assert_eq!(a.mempool().len(), 1);
        // Re-submitting the good tx is a duplicate.
        assert_eq!(a.ingest_tx(good), IngestOutcome::Duplicate);
    }

    /// **Issue #278's acceptance bar: a poisoned transaction must not wedge
    /// mining.** Both flavours block validation refuses — a discovery group
    /// that does not bind the declared commitments, and a nullifier repeated
    /// within one transaction — arrive over the peer wire and the node must
    /// still produce blocks.
    ///
    /// Pre-#278 this was a standing, peer-deliverable mining wedge: `admit` ran
    /// neither §4 lone-tx rule, `mine_on_parent` assembled the pool without
    /// re-validation, the miner's own `validate_body` then refused the mined
    /// block at the `announce_block` self-ingest seam (so `mine_block`'s PoW
    /// was burned and nothing was announced), and `Mempool::remove` fires only
    /// from a connected block — so the poison stayed pooled and every later
    /// template re-failed until restart. The assertions here are that wedge's
    /// negation at each link: the poison never pools, the sender is charged,
    /// and the node's next blocks pass its own validation.
    #[test]
    fn poisoned_tx_is_refused_at_admit_and_the_node_still_mines() {
        let (mut a, anchor) = adapter_with_finalized_genesis();

        // Flavour 1: a well-formed discovery group describing a DIFFERENT
        // commitment than the tx declares (`DiscoveryDoesNotBind` in a block).
        let mut unbound = tx_with(anchor, 1, b"ok");
        unbound.discovery = qlab_devnet::body::placeholder_discovery(&[[0xEE; 32]]);
        let out = a.ingest_tx(unbound.clone());
        assert_eq!(out, IngestOutcome::Rejected("discovery does not bind"));
        assert!(out.is_peer_fault(), "an unbound group is intrinsic misbehaviour");

        // Flavour 2: a self-double-spend (`DoubleSpendInBlock` once mined). Its
        // discovery binds its commitments, so only the nullifier rule refuses.
        let mut self_spend = tx_with(anchor, 2, b"ok");
        self_spend.public.nullifiers = vec![[2; 32], [2; 32]];
        let out = a.ingest_tx(self_spend.clone());
        assert_eq!(out, IngestOutcome::Rejected("nullifier repeated in tx"));
        assert!(out.is_peer_fault());

        // Neither reached the pool, so neither can reach a template.
        assert_eq!(a.mempool().len(), 0);
        assert!(!a.has_tx(&wire_tx_id(&unbound)));
        assert!(!a.has_tx(&wire_tx_id(&self_spend)));

        // THE NODE STILL MINES — the half a refusal-only test cannot see. An
        // honest tx is admitted, the template selects exactly it, and the mined
        // block passes the miner's own `validate_body` at the self-ingest seam
        // (pre-#278 this ingest was the `Rejected` that discarded the block).
        let honest = tx_with(anchor, 3, b"ok");
        assert_eq!(a.ingest_tx(honest), IngestOutcome::Accepted);
        let (h1, b1) = a.mine_block().expect("mine");
        assert_eq!(b1.txs.len(), 1, "the template carries exactly the honest tx");
        assert_eq!(a.ingest_block(h1, b1), IngestOutcome::Accepted);
        assert_eq!(a.chain().tip_height(), 1, "the chain advanced");

        // And keeps mining: the mined tx was evicted on connect, and the next
        // (empty) block is also self-acceptable — no standing wedge.
        assert_eq!(a.mempool().len(), 0, "the mined tx left the pool");
        let (h2, b2) = a.mine_block().expect("mine again");
        assert_eq!(a.ingest_block(h2, b2), IngestOutcome::Accepted);
        assert_eq!(a.chain().tip_height(), 2);
    }

    /// **The typed seam and the peer wire are one gate (issue #275).**
    /// `ingest_tx` is a mapping over [`NodeAdapter::submit_tx_typed`], so every
    /// verdict here is the verdict a peer submission gets — and the typed side
    /// carries what the flattening drops (`WrongFee`'s expected/got numbers, the
    /// exact `MempoolError` variant).
    #[test]
    fn submit_tx_typed_is_the_wire_gate_with_the_refusal_carried_whole() {
        let (mut a, anchor) = adapter_with_finalized_genesis();

        // Accepted: pooled under the returned id, wire id mapped as on the peer
        // path — and a resubmission is the typed duplicate.
        let good = tx_with(anchor, 1, b"ok");
        let id = a.submit_tx_typed(good.clone()).expect("admitted");
        assert!(a.mempool().contains(&id));
        assert!(a.has_tx(&wire_tx_id(&good)), "the wire id maps, exactly as ingest_tx would");
        assert_eq!(
            a.submit_tx_typed(good),
            Err(TxSubmitRefusal::Pool(MempoolError::DuplicateTx))
        );

        // WrongFee: the numbers a wallet needs survive, which the wire's static
        // string ("wrong fee") structurally cannot carry.
        let mut cheap = tx_with(anchor, 2, b"ok");
        cheap.public.fee = 1;
        assert_eq!(
            a.submit_tx_typed(cheap),
            Err(TxSubmitRefusal::Pool(MempoolError::WrongFee {
                expected: posted_fee(ArityBucket::TwoByTwo),
                got: 1,
            }))
        );

        // Anchor and proof refusals, named; nothing extra pooled by any of them.
        assert_eq!(
            a.submit_tx_typed(tx_with([0x5c; 32], 3, b"ok")),
            Err(TxSubmitRefusal::Pool(MempoolError::AnchorNotValid))
        );
        assert_eq!(
            a.submit_tx_typed(tx_with(anchor, 4, b"nope")),
            Err(TxSubmitRefusal::Pool(MempoolError::ProofInvalid))
        );
        assert_eq!(a.mempool().len(), 1, "only the accepted tx is pooled");

        // State lag: fork choice learns a header whose body has not applied — the
        // #130 (a) state where a stale tree would answer the anchor rule wrongly.
        // The typed path refuses by name; the wire path Ignores (not a fault),
        // and both are the same gate.
        let b = BlockBody::from_single_payee(vec![], 0, [0; 4]);
        let h = mine_body_over_tip(&mut a, &b);
        assert_eq!(a.ingest_header(h), IngestOutcome::Accepted);
        assert!(a.state_lag().is_lagging());
        assert_eq!(
            a.submit_tx_typed(tx_with(anchor, 5, b"ok")),
            Err(TxSubmitRefusal::StateLagging)
        );
        assert_eq!(
            a.ingest_tx(tx_with(anchor, 5, b"ok")),
            IngestOutcome::Ignored(STATE_LAG_REASON)
        );
    }

    /// 🔴 **The wire path can no longer admit an immature coinbase spend — issue
    /// #102's second seam, tested through `ingest_tx` rather than through the mempool
    /// API.**
    ///
    /// This is the line that used to read `admit(tx, vec![], …)`. The hardcoded empty
    /// declaration meant the frozen §2 maturity loop iterated **zero times for every
    /// transaction that ever arrived from a peer** — the rule had no enforcement at
    /// all on the only path carrying other people's transactions, and no test could
    /// have caught it by driving `Mempool::admit` directly, because the declaration
    /// production omitted was the very argument such a test supplies by hand.
    ///
    /// There is nothing to hardcode now, and that is what makes this testable here:
    /// the enforcement is that the immature coinbase's leaf is in no anchor, so a
    /// spend of it has no witness, so its proof cannot verify. What arrives from a
    /// peer is refused by the proof gate — the same gate that refuses every other
    /// unprovable claim, reached without anyone being asked to declare anything.
    ///
    /// `MockVerifier` here accepts `b"ok"` and rejects everything else, standing in
    /// for "a proof against an anchor containing the leaf" versus "any proof an
    /// immature spender could actually construct". The cryptographic half — that no
    /// such proof exists to bring — is `qumbra-node/tests/coinbase_spend.rs`
    /// (`an_immature_coinbase_spend_is_unprovable_not_refused`), against the real
    /// production verifier.
    #[test]
    fn the_wire_path_cannot_admit_an_immature_coinbase_spend() {
        let (mut a, anchor) = adapter_with_finalized_genesis();

        // A peer's transaction claiming to spend a coinbase note that has not matured.
        // It declares nothing about coinbase origin — there is no field for it — so
        // this is exactly the shape a hostile or careless submitter sends.
        let immature = tx_with(anchor, 7, b"unprovable");
        assert!(
            matches!(a.ingest_tx(immature.clone()), IngestOutcome::Rejected("proof invalid")),
            "an immature spend off the wire is refused as unprovable"
        );
        assert!(!a.has_tx(&wire_tx_id(&immature)), "and is not pooled");
        assert_eq!(a.mempool().len(), 0);

        // The refusal is the proof gate, not a maturity policy: `MempoolError` has no
        // maturity variant left to return, so `reject_reason` cannot name one.
        assert_eq!(
            NodeAdapter::<KeccakPow, MockVerifier>::reject_reason(&MempoolError::ProofInvalid),
            "proof invalid"
        );

        // And a provable spend on the same path is still admitted — the gate refuses
        // what cannot be proved, not everything.
        let provable = tx_with(anchor, 8, b"ok");
        assert_eq!(a.ingest_tx(provable.clone()), IngestOutcome::Accepted);
        assert!(a.has_tx(&wire_tx_id(&provable)));
    }

    #[test]
    fn mining_clock_default_is_deterministic_binary_uses_wall_clock() {
        use qlab_devnet::params_devnet::SIM_BLOCK_TIME_SECS;

        // Default (in-process sims/tests): the header timestamp is the deterministic
        // monotone counter — genesis(0) + one block ⇒ exactly the target block time.
        let (mut det, _a) = adapter_with_finalized_genesis();
        assert_eq!(det.mining_clock, MiningClock::Deterministic, "default is deterministic");
        let (h_det, _b) = det.mine_block().expect("mine (deterministic)");
        assert_eq!(
            h_det.timestamp, SIM_BLOCK_TIME_SECS,
            "deterministic clock ⇒ parent(0) + block_time, not wall-clock"
        );

        // Binary path: WallClock ⇒ the timestamp is real wall-clock seconds, bracketed
        // by now() around the call and far larger than the constant-clock value.
        let (mut wc, _a) = adapter_with_finalized_genesis();
        wc.set_mining_clock(MiningClock::WallClock);
        let before = wall_clock_secs();
        let (h_wc, _b) = wc.mine_block().expect("mine (wall-clock)");
        let after = wall_clock_secs();
        assert!(
            before <= h_wc.timestamp && h_wc.timestamp <= after,
            "wall-clock timestamp {} must fall in [{before}, {after}]",
            h_wc.timestamp
        );
        assert!(
            h_wc.timestamp > SIM_BLOCK_TIME_SECS,
            "wall-clock timestamp {} is real time, not the constant {SIM_BLOCK_TIME_SECS} s clock",
            h_wc.timestamp
        );
    }

    // ---- lab #651: the resumable mine phase --------------------------------

    use std::sync::atomic::AtomicBool;

    /// A PoW engine whose hashes can be made to never satisfy any real
    /// difficulty (all-0xFF ⇒ maximal work value on both forms), switchable at
    /// runtime so a test can let a real block validate mid-flight. It also
    /// counts hashes, so a slice's bound is asserted, not inferred.
    #[derive(Clone)]
    struct SwitchablePow {
        impossible: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl PowEngine for SwitchablePow {
        fn name(&self) -> &'static str {
            "switchable-keccak"
        }

        fn pow_hash(&self, form: GenesisForm, header: &BlockHeader, seed: &[u8]) -> Hash32 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.impossible.load(Ordering::Relaxed) {
                [0xFF; 32]
            } else {
                KeccakPow.pow_hash(form, header, seed)
            }
        }
    }

    fn slice(max_hashes: u64) -> SliceBudget {
        SliceBudget { max_hashes, deadline: None }
    }

    fn grinding_adapter() -> (
        NodeAdapter<SwitchablePow, MockVerifier>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let (cstate, _v) = committee7();
        let impossible = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let pow = SwitchablePow { impossible: impossible.clone(), calls: calls.clone() };
        (NodeAdapter::new(cstate, pow, MockVerifier, sim()), impossible, calls)
    }

    /// 🔴 Lab #651's regression test: a grind that cannot finish yields at its
    /// slice budget instead of blocking. On `main` the mine phase had no yield
    /// point — one call hashed the entire 2^26 nonce budget (measured at 566 s
    /// on the reporting Windows node), deaf to the network throughout. The
    /// phase must return after EXACTLY one slice of hashes, with the resume
    /// point parked — and the next phase must RESUME, not restart.
    #[test]
    fn a_grind_that_cannot_finish_yields_instead_of_blocking() {
        let (mut a, _impossible, calls) = grinding_adapter();
        let tip = a.chain().tip_hash();
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            512,
            "exactly one slice of hashes, not the nonce budget"
        );
        assert_eq!(a.grind_progress(), Some((tip, 512)), "the resume point is parked");
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert_eq!(calls.load(Ordering::Relaxed), 1024);
        assert_eq!(a.grind_progress(), Some((tip, 1024)), "progress accumulates across phases");
    }

    /// 🔴 Item (4) of the lab #651 design, adapter half: `may_start` gates
    /// STARTING a template, never RESUMING one. If a resume were gated, the
    /// node would grind one slice per `mine_interval` (75 s) — a ~99.97 %
    /// hashrate loss, worse than the blocking defect this replaced.
    #[test]
    fn starting_needs_permission_but_resuming_does_not() {
        let (mut a, _impossible, _calls) = grinding_adapter();
        // No grind in flight + no permission ⇒ nothing starts.
        assert!(matches!(a.mine_step(false, slice(512)), MineStep::Idle));
        assert!(a.grind_progress().is_none(), "no template starts before the interval permits");
        // Permission ⇒ a template is assembled and ground for one slice.
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        // 🔴 The resume proceeds WITHOUT start permission.
        assert!(matches!(a.mine_step(false, slice(512)), MineStep::Yielded));
        assert_eq!(
            a.grind_progress().map(|(_, nonce)| nonce),
            Some(1024),
            "the ungated resume made real progress"
        );
    }

    /// A moved tip abandons the parked grind. The abandonment trigger is the
    /// MINING PARENT CHANGING — the event that makes the work worthless (its
    /// block could only be an orphan) — not a clock, which cannot see it.
    #[test]
    fn a_moved_tip_abandons_the_parked_grind() {
        let (mut a, impossible, _calls) = grinding_adapter();
        let genesis_tip = a.chain().tip_hash();
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert_eq!(a.grind_progress(), Some((genesis_tip, 512)));

        // A block mined elsewhere arrives. The local engine must validate it
        // honestly, so the switchable engine drops its impossible mode for
        // exactly the ingest.
        let (cstate, _v) = committee7();
        let mut other = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let (header, body) = other.mine_block().expect("KeccakPow mines at sim difficulty");
        impossible.store(false, Ordering::Relaxed);
        assert_eq!(a.ingest_block(header, body), IngestOutcome::Accepted);
        impossible.store(true, Ordering::Relaxed);
        let new_tip = a.chain().tip_hash();
        assert_ne!(new_tip, genesis_tip, "the mining parent moved");

        // The next phase assembles FRESH on the new parent: cursor restarted
        // at one slice from zero, never resumed onto the stale parent.
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert_eq!(
            a.grind_progress(),
            Some((new_tip, 512)),
            "fresh template on the new parent, cursor restarted"
        );
    }

    /// `nonce_budget` is a per-TEMPLATE bound since lab #651: exhausting it
    /// drops the grind, and the next permitted phase assembles a fresh
    /// template (fresh timestamp + mempool snapshot) starting at nonce 0 —
    /// the pre-#651 retry-after-None behaviour, one slice at a time.
    #[test]
    fn an_exhausted_template_is_dropped_and_a_fresh_one_starts() {
        let (cstate, _v) = committee7();
        let impossible = Arc::new(AtomicBool::new(true));
        let pow = SwitchablePow { impossible, calls: Arc::new(AtomicUsize::new(0)) };
        let mut a = NodeAdapter::new(
            cstate,
            pow,
            MockVerifier,
            SimConfig { mine_nonce_budget: 1024, ..SimConfig::default() },
        );
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Exhausted));
        assert!(a.grind_progress().is_none(), "an exhausted template is dropped");
        assert!(matches!(a.mine_step(true, slice(512)), MineStep::Yielded));
        assert_eq!(
            a.grind_progress().map(|(_, nonce)| nonce),
            Some(512),
            "a fresh template started from nonce 0"
        );
    }

    #[test]
    fn ingest_block_applies_a_produced_block_and_rejects_a_bad_body() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        // Produce an (empty-body) block over genesis and ingest it.
        let (header, body) = a.mine_block().expect("mine");
        assert_eq!(a.ingest_block(header, body), IngestOutcome::Accepted);
        assert_eq!(a.chain().tip_height(), 1, "consensus tip advanced");
        assert_eq!(a.state().tip_height(), 1, "real state applied the body");

        // A block whose body carries a verifier-failing tx is rejected up front —
        // no crash, tip unchanged. Body validity is independent of *tip extension*,
        // but NOT of the header: the header must commit to the body being judged
        // (issue #77), so the bad body gets a header that honestly commits to it.
        // Before #77 this case paired a mined header with an unrelated body and
        // asserted "bad body" — a pairing no honest producer can emit.
        let bad_body = BlockBody::from_single_payee(vec![tx_with(anchor, 9, b"bad")], 0, [0; 4]);
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let h2 = BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, bad_body.commitment());
        assert_eq!(a.ingest_block(h2, bad_body), IngestOutcome::Rejected("bad body"));
        assert_eq!(a.chain().tip_height(), 1, "tip did not move on a bad block");
    }

    // --- issue #130 (a): the state machine catches up with its own chain -----

    /// Mine `n` blocks on `proposer`, returning the `(header, body)` pairs in
    /// ascending height order. The proposer applies each one itself.
    fn mine_chain(
        proposer: &mut NodeAdapter<KeccakPow, MockVerifier>,
        n: usize,
    ) -> Vec<(BlockHeader, BlockBody)> {
        (0..n)
            .map(|_| {
                let (h, body) = proposer.mine_block().expect("mine");
                assert_eq!(proposer.ingest_block(h, body.clone()), IngestOutcome::Accepted);
                (h, body)
            })
            .collect()
    }

    /// QUM-115's trust boundary in one caliper: only the span whose frontier is
    /// named by a locally verified quorum omits PoW. Above the checkpoint and on a
    /// sibling below it, the ordinary verifier still runs; without a verified
    /// quorum the special admission path is closed entirely.
    #[test]
    fn checkpoint_span_skips_only_attested_main_chain_pow() {
        let (cstate, validators) = committee7();
        let mut proposer =
            NodeAdapter::new(cstate.clone(), KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut proposer, 4);
        let checkpoint = Checkpoint::new(
            3,
            blocks[2].0.header_hash(),
            blocks[2].0.header_hash(),
        );
        let votes: Vec<Vote> = validators[..5]
            .iter()
            .map(|validator| validator.sign_checkpoint(&checkpoint))
            .collect();

        let calls = Arc::new(AtomicUsize::new(0));
        let mut joiner = NodeAdapter::new(
            cstate.clone(),
            CountingPow { calls: Arc::clone(&calls) },
            MockVerifier,
            easy_sim(),
        );
        assert!(matches!(
            joiner.ingest_requested_checkpoint_votes(&checkpoint, &votes),
            VotesOutcome::Learned { finalized: true, .. }
        ));
        assert_eq!(joiner.chain().finalized_height(), None, "the block is not held yet");
        assert_eq!(
            joiner.ingest_finalized_headers(&blocks[..3].iter().map(|b| b.0).collect::<Vec<_>>()),
            IngestOutcome::Accepted
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0, "PoW/LWMA/seed skipped below h_f");
        assert_eq!(joiner.chain().finalized_height(), Some(3));

        let mut wrong_body = blocks[0].1.clone();
        wrong_body.coinbase_payees[0].amount =
            wrong_body.coinbase_payees[0].amount.saturating_add(1);
        assert_eq!(
            joiner.ingest_block(blocks[0].0, wrong_body),
            IngestOutcome::Rejected("body does not match header commitment"),
            "checkpoint admission does not weaken header/body binding"
        );

        assert_eq!(joiner.ingest_header(blocks[3].0), IngestOutcome::Accepted);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "above h_f runs full PoW");

        let genesis = *joiner
            .chain()
            .header(&joiner.chain().genesis_block_hash())
            .expect("genesis");
        let mut sibling = BlockHeader::child_of(
            &genesis,
            genesis.timestamp + 2,
            genesis.difficulty,
            [0xA5; 32],
        );
        while qlab_devnet::pow::satisfies_target(
            &KeccakPow.pow_hash(GenesisForm::V4, &sibling, &joiner.chain().genesis_block_hash()),
            sibling.difficulty,
        ) {
            sibling.nonce = sibling.nonce.wrapping_add(1);
        }
        assert_eq!(
            joiner.ingest_header(sibling),
            IngestOutcome::Rejected("invalid header: pow"),
            "a below-finality sibling is not checkpoint-amnestied"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2, "the sibling ran full PoW");
        assert!(joiner.chain().header(&sibling.header_hash()).is_none());

        let unverified_calls = Arc::new(AtomicUsize::new(0));
        let mut unverified = NodeAdapter::new(
            cstate,
            CountingPow { calls: Arc::clone(&unverified_calls) },
            MockVerifier,
            easy_sim(),
        );
        let forged_checkpoint = Checkpoint::new(3, [0xEE; 32], [0xEE; 32]);
        let forged_votes: Vec<Vote> = validators[..5]
            .iter()
            .map(|validator| validator.sign_checkpoint(&forged_checkpoint))
            .collect();
        assert!(
            matches!(
                unverified.ingest_requested_checkpoint_votes(&checkpoint, &forged_votes),
                VotesOutcome::Invalid
            ),
            "quorum-many signatures over other bytes prove nothing"
        );
        assert_eq!(unverified.finalized_height(), None);
        assert_eq!(
            unverified.ingest_finalized_headers(&[blocks[0].0]),
            IngestOutcome::Rejected("no verified finalized checkpoint")
        );
        assert_eq!(unverified.ingest_header(blocks[0].0), IngestOutcome::Accepted);
        assert_eq!(
            unverified_calls.load(Ordering::Relaxed),
            1,
            "without a quorum-verified checkpoint every header runs PoW"
        );
    }

    /// A follower that has synced HEADERS for `blocks` and applied no body — the
    /// state of every node that joins a running net, and of every node whose
    /// header-first sync ran ahead of a body announce.
    fn follower_with_headers_only(
        blocks: &[(BlockHeader, BlockBody)],
    ) -> NodeAdapter<KeccakPow, MockVerifier> {
        let mut f = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        for (h, _) in blocks {
            assert_eq!(f.ingest_header(*h), IngestOutcome::Accepted);
        }
        assert_eq!(f.chain().tip_height(), blocks.len() as u64);
        assert_eq!(f.state().tip_height(), 0, "no body has been applied");
        f
    }

    /// QUM-113's second live bottleneck, at the exact adapter seams from the perf
    /// caller tree. A header-first joiner with an applied tip at genesis and a
    /// fork-choice tip well beyond the 16-body window must find both its fork point
    /// and its next ask set without falling back to a tip-to-height ancestor walk.
    ///
    /// The assertion is a deterministic call count, not a timing threshold: it
    /// remains sharp on a loaded CI runner and fails if either reader is changed
    /// back to `main_chain_ancestor`. The existing chain-index reorg test proves
    /// that the indexed answer is replaced synchronously when fork choice changes.
    #[test]
    fn far_ahead_body_dispatch_uses_no_tip_to_height_main_chain_walk() {
        const HEADER_TIP: usize = 128;
        const BODY_WINDOW: usize = 16;

        let mut proposer =
            NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut proposer, HEADER_TIP);
        let joiner = follower_with_headers_only(&blocks);

        MAIN_CHAIN_ANCESTOR_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            joiner.state_fork_point(),
            Some((0, joiner.chain().genesis_block_hash())),
            "an on-main applied genesis is the fork point"
        );
        let asks = joiner.missing_body_hashes(BODY_WINDOW);
        let expected: Vec<Hash32> = blocks[..BODY_WINDOW]
            .iter()
            .map(|(header, _)| header.header_hash())
            .collect();
        assert_eq!(
            asks, expected,
            "the indexed seed preserves the ascending ask window"
        );
        MAIN_CHAIN_ANCESTOR_CALLS.with(|calls| {
            assert_eq!(
                calls.get(),
                0,
                "dispatch readers must not walk header_tip - applied_tip parent links"
            );
        });

        // Semantic and edge equivalence with the retired walk: both readers name
        // the current fork-choice main-chain block, and both return None above tip.
        for height in [
            0,
            1,
            BODY_WINDOW as u64,
            HEADER_TIP as u64,
            HEADER_TIP as u64 + 1,
        ] {
            assert_eq!(
                joiner.main_chain_hash_at(height),
                joiner.main_chain_ancestor(height),
                "indexed and walked main-chain answers differ at height {height}"
            );
        }
    }

    /// **Acceptance 1 (#130 (a)): a node whose state tip trails its fork-choice tip
    /// applies the bodies it is holding, in ascending order, and converges — with no
    /// restart.**
    ///
    /// Before this, body application was gated on `submit_header` returning
    /// `Accepted`, i.e. on the header being *new*. Header-first sync guarantees the
    /// header is already known by the time the body arrives, so every body was
    /// dropped one branch above the `NotExtendingTip` arm everyone was looking at
    /// (QUM-18's F1). The bodies below arrive out of order and for headers this node
    /// already holds — both properties the old path could not survive.
    #[test]
    fn a_state_machine_behind_fork_choice_drains_buffered_bodies_in_ascending_order() {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 3);
        let mut f = follower_with_headers_only(&blocks);
        assert_eq!(f.state_lag().blocks(), 3, "the #130 gap, measured");

        // Bodies arrive newest-first. Each header is already held, so each ingest is
        // a `Duplicate` *header* — and each body is still applicable material.
        assert_eq!(f.ingest_block(blocks[2].0, blocks[2].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.state().tip_height(), 0, "block 3 must not be applied before 2");
        assert_eq!(f.ingest_block(blocks[1].0, blocks[1].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.state().tip_height(), 0, "…nor 2 before 1");

        // The body that closes the gap. Everything buffered drains behind it, in
        // ascending order, in this one call.
        assert_eq!(f.ingest_block(blocks[0].0, blocks[0].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.state().tip_height(), 3, "the state machine caught up to its own chain");
        assert_eq!(f.state_lag().blocks(), 0);
        assert!(!f.state_lag().is_lagging());
        assert_eq!(f.state().tip_hash(), f.chain().tip_hash(), "and to the same block");
    }

    /// Two adapters on one genesis, each mining to its own payout key — so their
    /// height-1 bodies differ and their height-1 headers are genuine siblings.
    /// This is the shape every `mine_chain`-based test lacks: a competing block at
    /// a height the state machine has already applied.
    fn two_racers() -> (NodeAdapter<KeccakPow, MockVerifier>, NodeAdapter<KeccakPow, MockVerifier>)
    {
        let mut a = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let mut b = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        a.set_miner_rkm([0xA1; 4]);
        b.set_miner_rkm([0xB2; 4]);
        (a, b)
    }

    /// **THE FIX (issue #162): a state machine that applied a block which then lost
    /// fork choice REJOINS the main chain — it does not merely buffer more.**
    ///
    /// This is `PR #163`'s reproduction with every assertion about the wedge
    /// inverted, deliberately kept as one test rather than added beside it: the two
    /// cannot both be true, and leaving the red one in the tree next to a green one
    /// would make the suite claim both. Its shape is the ingredient every
    /// `mine_chain`-based test lacks — a competing block at a height the state
    /// machine has already applied — and it fails on `main` today at the very first
    /// changed line (`main` holds zero of the winning sibling's body; here it holds
    /// one).
    ///
    /// The three things it pins, in order:
    ///
    /// 1. **The sibling body is HELD, at the moment it arrives, while both branches
    ///    still carry equal work and this node still reads as on the main chain.**
    ///    This is the load-bearing half. A rule phrased against where fork choice is
    ///    *now* discards it here, one block before it is needed, and nothing brings
    ///    it back (`GetData(Block)` answers header-only — #153's finding).
    /// 2. **The state machine rewinds and re-applies** once fork choice moves, in
    ///    the same ingest that moves it.
    /// 3. **It ends converged**: `slag` zero, applied tip == fork-choice tip, and
    ///    the duties it was refusing resume.
    #[test]
    fn i162_a_state_machine_on_a_losing_sibling_rejoins_the_main_chain() {
        let (mut winner, mut loser) = two_racers();

        // Both mine at height 1 before hearing the other — the four-way race a
        // fresh net's genesis difficulty makes near-certain.
        let (wh1, wb1) = winner.mine_block().expect("mine");
        assert_eq!(winner.ingest_block(wh1, wb1.clone()), IngestOutcome::Accepted);
        let (lh1, lb1) = loser.mine_block().expect("mine");
        assert_eq!(loser.ingest_block(lh1, lb1.clone()), IngestOutcome::Accepted);
        assert_ne!(wh1.header_hash(), lh1.header_hash(), "a genuine sibling race");
        assert_eq!(loser.state().tip_hash(), lh1.header_hash(), "it applied its own");

        // (1) The winner's height-1 block arrives after the loser applied its own.
        // Equal work, so the tie-break keeps the incumbent: fork choice has NOT
        // moved, `schain=` still reads main, and nothing yet says this node is on
        // the losing side. The body is held anyway — that is the fix.
        assert_eq!(loser.ingest_block(wh1, wb1.clone()), IngestOutcome::Accepted);
        assert_eq!(loser.chain().tip_hash(), lh1.header_hash(), "fork choice has not moved yet");
        assert!(!loser.applied_tip().is_off_main_chain(), "and nothing yet says otherwise");
        assert_eq!(
            loser.pending_bodies().0,
            1,
            "the winning sibling's body is held BEFORE it is known to be the winner"
        );
        assert_eq!(loser.state().tip_hash(), lh1.header_hash(), "and nothing was rewound for it");
        assert_eq!(loser.state_rewinds(), (0, 0), "a held body is not a rewind");

        // (2) The winner extends. Fork choice on the loser follows the taller
        // branch — and in the same ingest the state machine rewinds to the fork
        // point and re-applies both winning blocks.
        let (wh2, wb2) = winner.mine_block().expect("mine");
        assert_eq!(winner.ingest_block(wh2, wb2.clone()), IngestOutcome::Accepted);
        assert_eq!(loser.ingest_block(wh2, wb2.clone()), IngestOutcome::Accepted);
        assert_eq!(loser.chain().tip_hash(), wh2.header_hash(), "fork choice moved");
        assert_eq!(loser.state().tip_hash(), wh2.header_hash(), "and the state machine followed");
        assert_eq!(loser.state().tip_height(), 2);
        assert_eq!(
            loser.state_rewinds(),
            (1, 1),
            "one rewind, one applied block undone — the depth of a sibling race"
        );

        // The abandoned sibling is gone from the state machine's APPLIED store,
        // which is what let its own height be re-used. `stored_body` answers what
        // this node has applied (#135), and it has not.
        //
        // **It IS still served** — the sentence here used to end "and is not served
        // any more either", and that half was the defect. Serving keyed on
        // application, `rewind_to` (this very function) can un-apply a block the
        // node still holds, and on 2026-08-01 those two composed into a net-wide
        // mining deadlock (#197/#198). Since #198 the serving path asks `held_body`
        // and the applied predicate below is only half the answer.
        use qlab_node::ChainStore as _;
        assert!(!loser.state().chain().contains(&lh1.header_hash()), "the orphan was dropped");
        assert!(loser.stored_body(&lh1.header_hash()).is_none(), "not APPLIED");
        assert!(loser.held_body(&lh1.header_hash()).is_some(), "but still HELD, and served (#198)");
        assert!(loser.stored_body(&wh1.header_hash()).is_some(), "the winner's is applied");
        assert_eq!(
            lb1.coinbase_payees[0].rkm,
            [0xB2; 4],
            "the orphan really was the loser's own block"
        );

        // (3) Converged, and it stays converged as the winner keeps extending.
        for _ in 0..6 {
            let (h, b) = winner.mine_block().expect("mine");
            assert_eq!(winner.ingest_block(h, b.clone()), IngestOutcome::Accepted);
            assert_eq!(loser.ingest_block(h, b), IngestOutcome::Accepted);
        }
        assert_eq!(loser.chain().tip_height(), 8);
        assert_eq!(loser.state().tip_height(), 8, "the state machine is on the chain, not behind it");
        assert_eq!(loser.state_lag().blocks(), 0, "slag zero");
        assert!(!loser.state_lag().is_lagging());
        assert_eq!(loser.pending_bodies(), (0, 0), "nothing left held, and no bytes leaked");
        assert_eq!(loser.state_rewinds(), (1, 1), "and no further rewind was needed");
        assert_eq!(loser.ingest_counters().unjudged_anchor, 0, "#134's path never fired");
        assert_eq!(loser.lag_refusals("rewind"), 0, "no rewind was refused");
        // The duties resume, which is the point: a node that cannot mine and cannot
        // admit a transaction is the liveness stop this issue was filed for.
        assert!(loser.mine_block().is_some(), "a converged node mines again");
    }

    /// Mine a block over the current fork-choice tip carrying `body` **verbatim**.
    ///
    /// [`NodeAdapter::mine_block`] cannot be used for this: it assembles the body
    /// from the mempool, and the mempool refuses a cross-block double-spend by
    /// design — which is exactly the body the funnel-refusal test needs. This is
    /// `mine_block`'s own header arithmetic with the assembly step replaced, so the
    /// block it produces is indistinguishable on the wire from one a hostile miner
    /// with the same hash power would produce.
    fn mine_body_over_tip(
        a: &mut NodeAdapter<KeccakPow, MockVerifier>,
        body: &BlockBody,
    ) -> BlockHeader {
        let parent_hash = a.chain.tip_hash();
        let parent = *a.chain.header(&parent_hash).expect("the tip has a header");
        let difficulty =
            expected_difficulty(&a.chain, &parent_hash, a.block_time).expect("difficulty");
        let timestamp = a.next_timestamp(&parent);
        let candidate = BlockHeader::child_of(&parent, timestamp, difficulty, body.commitment());
        let seed = pow_seed(&a.chain, &parent_hash, candidate.height, a.schedule).expect("seed");
        mine_under(&a.pow, candidate, a.nonce_budget, &seed, &a.rules).expect("mine")
    }

    /// 🔴 **Issue #130 (b): a body the state machine refuses is counted, and the
    /// count says where — and a node that refuses nothing still reads zero.**
    ///
    /// This is the arm the issue was filed against. It used to be `Err(_) => {}`
    /// under a comment calling the drop expected, and #130's sharpest sentence is
    /// about that comment: *"a comment asserting that a dropped block is normal is
    /// what kept anyone from asking whether it was."* There was no counter and no
    /// telemetry field, so a node dropping every body it was handed printed exactly
    /// what a healthy node prints.
    ///
    /// The refusal driven here is **`nullifier_spent`, and that choice is the
    /// evidence, not a convenience**: it is the only class no earlier gate can
    /// pre-empt. `validate_body` checks in-block double-spends and knows nothing
    /// about the permanent nullifier set, so a two-block span whose second block
    /// re-spends the first's nullifier passes every arrival-time check on both
    /// blocks and can only fail at the state funnel — where, before this change,
    /// failing cost nothing and told nobody. Both headers carry real PoW.
    ///
    /// Both halves of the acceptance item are here in order: the counter is zero
    /// after a clean block is applied, and it moves — once, at the right height —
    /// when one is refused.
    #[test]
    fn a_body_refused_at_the_application_funnel_is_counted_and_located() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        assert_eq!(a.body_refusals(), (0, None), "a fresh node has refused nothing");

        // ── stays put: an ordinary block, applied ──
        let (h1, b1) = a.mine_block().expect("mine");
        assert_eq!(a.ingest_block(h1, b1), IngestOutcome::Accepted);
        assert_eq!(a.state().tip_height(), 1);
        assert_eq!(a.body_refusals(), (0, None), "applying a body is not refusing one");

        // ── moves: a two-block span whose second block re-spends the first's
        //    nullifier. Height 2 spends it; height 3 spends it again.
        let spend = tx_with(anchor, 1, b"ok");
        let b2 = BlockBody::from_single_payee(vec![spend.clone()], 0, [0; 4]);
        let h2 = mine_body_over_tip(&mut a, &b2);
        assert_eq!(a.ingest_header(h2), IngestOutcome::Accepted, "header-first sync");
        let b3 = BlockBody::from_single_payee(vec![spend], 0, [0; 4]);
        let h3 = mine_body_over_tip(&mut a, &b3);
        assert_eq!(h3.height, 3);

        // The bodies arrive out of order — the #130 (a) shape — so the second is
        // buffered and only reaches the funnel behind the first.
        assert_eq!(a.ingest_block(h3, b3), IngestOutcome::Accepted);
        assert_eq!(a.state().tip_height(), 1, "held: its parent is not applied yet");
        assert_eq!(a.body_refusals(), (0, None), "and holding is not refusing");

        assert_eq!(a.ingest_block(h2, b2), IngestOutcome::Duplicate);
        assert_eq!(a.state().tip_height(), 2, "the first spend applied");

        // The refusal, counted and located.
        assert_eq!(
            a.body_refusals(),
            (1, Some(3)),
            "one body refused, at the height it was refused at"
        );
        assert_eq!(a.body_refusals_by_reason("nullifier_spent"), 1, "and by the right name");
        assert_eq!(
            a.body_refusals_by_reason("not_extending_tip"),
            0,
            "the invariant tripwire did not fire"
        );
        // Nothing was mutated by the refusal and nothing was charged to a peer: the
        // state machine sits one block behind fork choice, which is now legible as a
        // refusal rather than only as a gap.
        assert_eq!(a.state().tip_height(), 2);
        assert_eq!(a.chain().tip_height(), 3);
        assert_eq!(a.state_lag().blocks(), 1);
        // The refused body leaves the window rather than being retried against an
        // unchanged state. It stays *re-requestable* — `missing_body_hashes` derives
        // its ask set from what has been applied, so the next tick asks for height 3
        // again, and each redelivery is counted here. That is the intended reading:
        // a body that can never apply makes `bdrop` climb with its height pinned,
        // which is the "still happening" signal this field exists to give.
        assert_eq!(a.pending_bodies().0, 0, "the refused body is not held");
    }

    /// 🔴 **Issue #130 (b), the reachability question: `NotExtendingTip` cannot be
    /// produced on any live path after `#178` and `#182` — and this is the test that
    /// fails if it becomes reachable again.**
    ///
    /// The argument is a chain of three facts, each mechanically checkable:
    ///
    /// 1. [`qlab_node::NodeError::NotExtendingTip`] has **one** construction site,
    ///    the first statement of [`qlab_node::Node::apply_block`].
    /// 2. `apply_block` has **one** production caller,
    ///    [`NodeAdapter::drain_pending_bodies`] (the others are a bench harness and
    ///    test modules). `#178`'s replay path reaches `apply_state` through
    ///    `apply_logged_block`, which rewinds first and never calls `apply_block`.
    /// 3. That caller selects what it applies with [`NodeAdapter::next_applicable_body`],
    ///    whose predicate — `header.prev == state.tip_hash()` — is the **exact
    ///    negation** of the error's trigger.
    ///
    /// Fact 3 is the one a future change can break silently, so it is the one under
    /// test, in **the one state where nothing else would stop it**. The selector has
    /// two clauses and only the second is the invariant here: the height range
    /// (`state tip + 1`) already excludes a sibling held at the applied tip's own
    /// height, so a test built on that shape passes even with the `prev` comparison
    /// deleted, and proves nothing. The state that isolates the `prev` clause is a
    /// held body **at `tip + 1` on a different branch** — the winner's second block
    /// arriving before its first — and that is what is built below. Delete the `prev`
    /// comparison and `apply_block` gets a block it must refuse, the counter moves,
    /// and this test goes red; that mutation was run, and it does.
    ///
    /// **An argument without a test decays into a comment, which is what this issue
    /// is about** — and the counter itself is the production half of the same
    /// tripwire: `qumbra_body_apply_refused_total{reason="not_extending_tip"}` is
    /// expected to be zero forever on every host, so a nonzero scrape is this
    /// argument failing in the field rather than in CI.
    #[test]
    fn i130b_a_held_body_that_does_not_extend_the_applied_tip_never_reaches_apply_block() {
        let (mut winner, mut loser) = two_racers();
        let (wh1, wb1) = winner.mine_block().expect("mine");
        assert_eq!(winner.ingest_block(wh1, wb1.clone()), IngestOutcome::Accepted);
        let (wh2, wb2) = winner.mine_block().expect("mine");
        assert_eq!(winner.ingest_block(wh2, wb2.clone()), IngestOutcome::Accepted);

        let (lh1, lb1) = loser.mine_block().expect("mine");
        assert_eq!(loser.ingest_block(lh1, lb1), IngestOutcome::Accepted);
        assert_ne!(wh1.header_hash(), lh1.header_hash(), "a genuine sibling race");

        // Header-first sync gives the loser the winner's branch as headers. Fork
        // choice moves to it — it is two blocks to the loser's one — while the state
        // machine is still on `lh1`, which is now off the main chain.
        assert_eq!(loser.ingest_header(wh1), IngestOutcome::Accepted);
        assert_eq!(loser.ingest_header(wh2), IngestOutcome::Accepted);
        assert_eq!(loser.chain().tip_hash(), wh2.header_hash(), "fork choice has moved");
        assert!(loser.applied_tip().is_off_main_chain(), "and the applied tip is stranded");

        // 🔴 THE STATE UNDER TEST. The winner's SECOND body arrives; its first has
        // not. It is held at `applied tip + 1` — inside the selector's height range,
        // so the range does not save us — and its parent is `wh1`, not the applied
        // tip `lh1`. It is the exact object `NotExtendingTip` exists to refuse, and
        // it is queued for application.
        assert_eq!(loser.ingest_block(wh2, wb2), IngestOutcome::Duplicate);
        // Asserted FIRST, because it is the claim: that ingest ran a full drain, and
        // if the selector had handed this body to `apply_block` the refusal would
        // already be on the counter.
        assert_eq!(
            loser.body_refusals(),
            (0, None),
            "\u{1f534} the drain this ingest ran refused nothing — nothing reached the funnel"
        );
        assert_eq!(loser.pending_bodies().0, 1, "held");
        assert_eq!(wh2.height, loser.state().tip_height() + 1, "at tip + 1");
        assert_ne!(wh2.prev, loser.state().tip_hash(), "and it does NOT extend that tip");
        // No rewind is available either: `rejoin_main_chain` needs the body at
        // `fork + 1` (= `wh1`) and the loser does not hold it, so nothing moves the
        // applied tip out from under the question.
        assert_eq!(loser.state_rewinds(), (0, 0));

        // The selector declines it — not by erroring, by not choosing it.
        assert!(
            loser.next_applicable_body().is_none(),
            "the held body does not extend the applied tip, so nothing is applicable"
        );
        loser.drain_pending_bodies();
        assert_eq!(loser.pending_bodies().0, 1, "still held, not consumed and not dropped");
        assert_eq!(loser.state().tip_hash(), lh1.header_hash(), "and nothing was applied");
        assert_eq!(
            loser.body_refusals(),
            (0, None),
            "🔴 nothing reached the funnel to be refused — this is the assertion that \
             fails if the selector and `apply_block`'s first check come apart"
        );

        // The missing body arrives and the whole `#178` path runs: rewind off the
        // losing sibling, then apply both winners ascending. The invariant holds
        // across the rewind too — `rewind_to` moves the applied tip to the parent
        // BEFORE anything is re-applied, so every `apply_block` still extends its tip.
        assert_eq!(loser.ingest_block(wh1, wb1), IngestOutcome::Duplicate);
        assert_eq!(loser.state().tip_hash(), wh2.header_hash(), "rejoined the main chain");
        assert_eq!(loser.state_rewinds(), (1, 1), "via exactly one rewind");
        assert_eq!(loser.state_lag().blocks(), 0);
        assert_eq!(
            loser.body_refusals_by_reason("not_extending_tip"),
            0,
            "🔴 NotExtendingTip stayed unreachable across the rewind as well"
        );
        assert_eq!(loser.body_refusals(), (0, None), "and nothing else was refused either");
    }

    /// **The slope, not the value (issue #162 acceptance item 2).**
    ///
    /// The production measurement that decided this issue was a *rate*: `slag`
    /// climbing at 0.78/min against a 0.80 blocks/min block rate, i.e. at the
    /// ceiling, for eleven hours. Nothing at ceiling slope recovers on its own, and
    /// the recovery criterion is the mirror image — after the fix, `slag` under the
    /// same load must climb **strictly slower than the block rate**, observable
    /// without waiting for it to reach zero.
    ///
    /// So this measures a slope in blocks rather than in minutes, which is the same
    /// quantity with the wall clock divided out: it drives the wedged node with N
    /// main-chain blocks and asks how much `slag` grew. On `main` the answer is N
    /// (slope 1.0, the ceiling). Here it is ≤ 0 — the fix does not merely slow the
    /// climb, it reverses it inside one block.
    #[test]
    fn i162_the_slag_slope_falls_below_the_block_rate_within_one_block() {
        let (mut winner, mut loser) = two_racers();
        let (wh1, wb1) = winner.mine_block().expect("mine");
        winner.ingest_block(wh1, wb1.clone());
        let (lh1, lb1) = loser.mine_block().expect("mine");
        loser.ingest_block(lh1, lb1);
        loser.ingest_block(wh1, wb1);

        // Drive the strand for one cadence of main-chain blocks, sampling `slag`
        // after each — the in-process equivalent of T-ops' 20-minute sampler.
        let mut slag = vec![loser.state_lag().blocks()];
        for _ in 0..qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS {
            let (h, b) = winner.mine_block().expect("mine");
            winner.ingest_block(h, b.clone());
            loser.ingest_block(h, b);
            slag.push(loser.state_lag().blocks());
        }
        let blocks = slag.len() as u64 - 1;
        let growth = slag.last().copied().expect("sampled") as i64 - slag[0] as i64;

        // The criterion, stated as the issue states it.
        assert!(
            (growth as f64) / (blocks as f64) < 1.0,
            "slag slope {growth}/{blocks} must be strictly below the block rate; \
             samples {slag:?}"
        );
        // And the stronger fact the criterion deliberately does not require: it is
        // not slower growth, it is no growth.
        assert_eq!(slag.last().copied(), Some(0), "converged, not merely slowed: {slag:?}");
        assert_eq!(
            loser.state_rewinds().0,
            1,
            "one rewind did it — the counter is the positive signal that the wedge \
             detector went quiet because the wedge went away"
        );
    }

    /// **Acceptance item 5: the `PR #168` wedge detector still separates lagging
    /// from stranded after the fix — and it goes quiet for the right reason.**
    ///
    /// A detector that stops firing because the defect is gone and one that stops
    /// firing because it broke look identical from the outside, so this exercises
    /// all three of its readings on the same tick:
    ///
    /// - a node whose state machine is genuinely behind on the SAME branch reads
    ///   `slag>0 schain=main` — the detector is still capable of a nonzero `slag`;
    /// - the node from the wedge reads `slag=0 schain=main` once it has rejoined —
    ///   quiet, and the rewind counter says why;
    /// - and `schain=fork` is still reachable, still off `slag` entirely, by
    ///   holding the sibling body back so no rewind can fire.
    #[test]
    fn i162_the_wedge_detector_still_separates_lagging_from_stranded() {
        // (a) Stranded, with the fix's material withheld: the detector fires.
        let (mut winner, mut loser) = two_racers();
        let (wh1, wb1) = winner.mine_block().expect("mine");
        winner.ingest_block(wh1, wb1.clone());
        let (lh1, lb1) = loser.mine_block().expect("mine");
        loser.ingest_block(lh1, lb1);
        // The HEADER only — this is the state a restarted node is in, since no peer
        // will re-serve a historical body (#153's open finding). The rewind gate is
        // "hold the body at fork+1", so withholding it withholds the recovery.
        assert_eq!(loser.ingest_header(wh1), IngestOutcome::Accepted);
        let (wh2, wb2) = winner.mine_block().expect("mine");
        winner.ingest_block(wh2, wb2.clone());
        loser.ingest_block(wh2, wb2);

        let stranded = loser.applied_tip();
        assert_eq!(stranded.chain_field(), qlab_node::APPLIED_TIP_OFF_MAIN, "schain=fork");
        assert!(loser.state_lag().blocks() > 0, "and slag is nonzero");
        assert_eq!(loser.state_rewinds(), (0, 0), "no rewind fired, so nothing is being claimed");
        let stranded_id = stranded.identity();

        // (b) Lagging on the SAME branch: nonzero slag, schain=main. Unchanged by
        // this fix, and the contrast that makes (a) mean something.
        let mut source = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let chain = mine_chain(&mut source, 3);
        let follower = follower_with_headers_only(&chain);
        assert!(follower.state_lag().blocks() > 0, "behind");
        assert_eq!(
            follower.applied_tip().chain_field(),
            qlab_node::APPLIED_TIP_ON_MAIN,
            "schain=main — behind is not stranded"
        );

        // (c) The same wedge, with the body in hand: quiet, and for the right
        // reason. `stipid` moved off the orphan, which is the identity half of the
        // detector doing its job rather than the detector going silent.
        let (mut winner2, mut loser2) = two_racers();
        let (w1, wb1b) = winner2.mine_block().expect("mine");
        winner2.ingest_block(w1, wb1b.clone());
        let (l1, lb1b) = loser2.mine_block().expect("mine");
        loser2.ingest_block(l1, lb1b);
        loser2.ingest_block(w1, wb1b);
        let (w2, wb2b) = winner2.mine_block().expect("mine");
        winner2.ingest_block(w2, wb2b.clone());
        loser2.ingest_block(w2, wb2b);

        let rejoined = loser2.applied_tip();
        assert_eq!(rejoined.chain_field(), qlab_node::APPLIED_TIP_ON_MAIN, "schain=main");
        assert_eq!(loser2.state_lag().blocks(), 0, "slag=0");
        assert_eq!(loser2.state_rewinds(), (1, 1), "quiet BECAUSE the wedge was undone");
        assert_ne!(
            rejoined.identity(),
            stranded_id,
            "stipid moved off the orphan — the detector's identity half still answers"
        );
    }

    /// **The rewind refuses to cross the finalized head — and that refusal is why
    /// `finality.rs` and `recovery.rs` are untouched.**
    ///
    /// The gate is checked at the state machine, on a node whose finalized head is
    /// its applied tip: no ancestor of that tip is a legal target, so every rewind
    /// that would cross it is refused with the state left exactly as it was. This
    /// is the one refusal that must never become an `expect`.
    #[test]
    fn i162_a_rewind_may_not_cross_the_finalized_head() {
        use qlab_node::RewindError;

        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, easy_sim());
        let chain = mine_chain(&mut a, qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS as usize);
        let height = a.chain().tip_height();
        let (cp, votes) = a.make_checkpoint(height, &validators).expect("checkpoint");
        assert!(
            matches!(
                a.ingest_checkpoint_votes(&cp, &votes),
                VotesOutcome::Learned { finalized: true, .. }
            ),
            "the quorum finalizes"
        );
        assert_eq!(a.state().finalized_height(), Some(height), "the state machine finalized it");

        let tip = a.state().tip_hash();
        let parent = chain[chain.len() - 2].0.header_hash();
        let root = a.chain().genesis_block_hash();

        // One block back, and all the way to genesis: both are below the finalized
        // head, and both are refused with the state untouched.
        for target in [parent, root] {
            let err = a.state_mut().rewind_to(target).expect_err("must refuse");
            assert!(
                matches!(
                    err,
                    qlab_node::NodeError::Rewind(RewindError::PastFinalized {
                        finalized_height, ..
                    }) if finalized_height == height
                ),
                "got {err}"
            );
            assert_eq!(a.state().tip_hash(), tip, "a refused rewind changes nothing");
            assert_eq!(a.state().finalized_height(), Some(height));
        }

        // The finalized block itself is a legal target (rewinding TO finality is
        // not rewinding PAST it) — the positive half, so "refuse everything" cannot
        // pass this test.
        let report = a.state_mut().rewind_to(tip).expect("rewinding to the tip is a no-op");
        assert!(report.is_noop());
        assert_eq!(a.state().tip_hash(), tip);
        // …and an unknown target is refused as unknown, not as a finality crossing.
        assert!(matches!(
            a.state_mut().rewind_to([0x5a; 32]),
            Err(qlab_node::NodeError::Rewind(RewindError::UnknownTarget))
        ));
    }

    /// **A rewind survives the restart** — the durability half, and the reason the
    /// block log needed no new record type.
    ///
    /// The log is append-only and stays so, but the applied chain is not any more.
    /// A logged block whose `prev` is not the running tip can only mean the live
    /// node rewound to that `prev` before applying it, and replay infers exactly
    /// that. This drives a real wedge-and-rejoin on a disk-backed adapter, then
    /// asserts the three durability facts that matter: `open` resumes on the
    /// winning branch, `open == replay`, and the orphan is gone from both.
    #[test]
    fn i162_a_rewound_state_machine_replays_from_disk_onto_the_winning_branch() {
        use qlab_node::ChainStore as _;

        let dir = temp_dir("i162-rewind-replay");
        let sim = easy_sim();
        let mut loser =
            NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, sim).expect("open");
        loser.set_miner_rkm([0xB2; 4]);
        let mut winner = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, sim);
        winner.set_miner_rkm([0xA1; 4]);

        let (wh1, wb1) = winner.mine_block().expect("mine");
        winner.ingest_block(wh1, wb1.clone());
        let (lh1, lb1) = loser.mine_block().expect("mine");
        loser.ingest_block(lh1, lb1);
        loser.ingest_block(wh1, wb1);
        let (wh2, wb2) = winner.mine_block().expect("mine");
        winner.ingest_block(wh2, wb2.clone());
        loser.ingest_block(wh2, wb2);
        assert_eq!(loser.state().tip_hash(), wh2.header_hash(), "rejoined live");
        assert_eq!(loser.state_rewinds(), (1, 1));
        let live_root = loser.state().commitment_root();
        let live_count = loser.state().commitment_count();
        loser.save_snapshot().expect("snapshot");
        drop(loser);

        // The log holds BOTH height-1 blocks — the orphan was never removed from it.
        let genesis = genesis_block(sim.genesis_difficulty, 0);
        for (what, node) in [
            ("open", MemNode::open(&dir, genesis.clone()).expect("open")),
            ("replay", MemNode::replay(&dir, genesis).expect("replay")),
        ] {
            assert_eq!(node.tip_hash(), wh2.header_hash(), "{what} resumed on the winner");
            assert_eq!(node.tip_height(), 2, "{what} height");
            assert_eq!(node.commitment_root(), live_root, "{what} tree root == live");
            assert_eq!(node.commitment_count(), live_count, "{what} leaf count == live");
            assert!(
                !node.chain().contains(&lh1.header_hash()),
                "{what} did not resurrect the orphan"
            );
            assert!(node.chain().contains(&wh1.header_hash()), "{what} holds the winner");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **#135's durable serving path**: `stored_body` answers exactly the bodies
    /// this node has APPLIED — with the exact body, since serving a different one
    /// would re-open #77 from the serving side — and declines a body that is
    /// merely buffered. The buffered body is deliberately not served from the
    /// store: it has not been validated against the tree it will be applied to,
    /// and while it awaits application it is still in the P2P serving cache if it
    /// arrived for a new header.
    #[test]
    fn stored_body_answers_applied_blocks_and_declines_merely_buffered_ones() {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 2);
        let h0 = blocks[0].0.header_hash();
        let h1 = blocks[1].0.header_hash();

        // The proposer applied both — the store answers, with the exact body.
        assert!(p.has_stored_body(&h0) && p.has_stored_body(&h1));
        let served = p.stored_body(&h0).expect("applied → servable");
        // "Exact" is #77's meaning of exact: the served body commits to the same
        // value the header committed to (which covers txs, coinbase AND payout key).
        assert_eq!(served.commitment(), blocks[0].1.commitment(), "the exact body");

        // A follower holding only headers serves nothing…
        let mut f = follower_with_headers_only(&blocks);
        assert!(!f.has_stored_body(&h0) && !f.has_stored_body(&h1));
        // …and a body buffered out-of-order (header already held → `Duplicate`)
        // is buffered, not applied, and therefore still not served.
        assert_eq!(f.ingest_block(blocks[1].0, blocks[1].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.pending_bodies().0, 1, "held for the state tip");
        assert!(!f.has_stored_body(&h1), "a buffered body is not an applied body");
        assert!(f.stored_body(&h1).is_none());

        // The gap closes → both apply → both become servable, durably.
        assert_eq!(f.ingest_block(blocks[0].0, blocks[0].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.state().tip_height(), 2);
        assert!(f.has_stored_body(&h0) && f.has_stored_body(&h1));
    }

    /// **Acceptance 2 (#130 (a)): the regression that produced this issue — a node
    /// mining on a fork-choice tip above its own state tip must not silently lose its
    /// coinbase.**
    ///
    /// `mine_block` takes its parent from **fork choice** (`chain.tip_hash()`) and
    /// assembles the body from **state**. So a lagging miner produced a valid child of
    /// the fork-choice tip, `submit_header` accepted it (it really did extend fork
    /// choice), and `apply_block` then refused it because `header.prev` was not the
    /// state tip: the coinbase note's leaf never entered the tree, the miner could
    /// never spend what it mined, and nothing anywhere reported an error.
    ///
    /// This gets its own test rather than riding along on the drain test above,
    /// because it is the sharpest of the four consequences and the one that reaches a
    /// miner's balance.
    #[test]
    fn a_miner_ahead_of_its_own_state_tip_does_not_silently_lose_its_coinbase() {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 2);
        let mut f = follower_with_headers_only(&blocks);

        // Lagging: it declines to produce a block it could not record.
        let leaves_before = f.state().commitment_count();
        assert!(
            f.mine_block().is_none(),
            "a node that cannot apply its own block must not mine one"
        );
        assert_eq!(f.lag_refusals("mine"), 1, "and the refusal is counted, not silent");
        assert_eq!(f.state().commitment_count(), leaves_before, "no leaf, and no lost leaf");

        // Caught up: it mines, and the coinbase leaf is in its own tree — which is
        // what "did not lose it" has to mean after #101 (a leaf is what makes a
        // mined coin spendable).
        for (header, body) in &blocks {
            assert_eq!(f.ingest_block(*header, body.clone()), IngestOutcome::Duplicate);
        }
        assert!(!f.state_lag().is_lagging(), "converged");
        let leaves = f.state().commitment_count();
        let (header, body) = f.mine_block().expect("mines once its state machine is its chain");
        assert_eq!(f.ingest_block(header, body), IngestOutcome::Accepted);
        assert_eq!(f.state().tip_height(), 3, "its own block is in its own state");

        // Issue #102 moved this test's observable, and the substitution is deliberate.
        // It asserted `leaves + 1` — the coinbase leaf appearing the moment the block
        // was applied, which was #101's semantics. The leaf now lands 144 blocks later,
        // so at height 3 there is nothing to count, and asserting `leaves + 0` would be
        // *vacuous*: it holds just as well if the block was never applied at all, which
        // is the silent-loss failure this test exists to catch.
        //
        // So "did not lose its coinbase" is checked as: the block is in this node's own
        // state, the note it minted is derivable from that stored body, and the leaf is
        // scheduled rather than missing. That a scheduled leaf really does land is
        // `qlab-node/tests/maturity_schedule.rs`, which spans the delay; here the point
        // is that the miner recorded its own block, which is what #130 (a) fixed.
        assert_eq!(f.state().commitment_count(), leaves, "not yet — it matures at 147");
        let stored = f
            .state()
            .chain()
            .block(&f.state().tip_hash())
            .expect("its own mined block is in its own chain store");
        assert!(
            qlab_node::coinbase_note_leaf(3, &stored.body()).is_some(),
            "the note it mined is derivable from the body it recorded — nothing is lost"
        );
        assert_eq!(qlab_node::coinbase_leaf_appears_at(3), 3 + qlab_node::COINBASE_MATURITY_BLOCKS);
    }

    /// **#134's boundary, checked rather than assumed: a body that is held, retried
    /// and possibly dropped is never a second peer fault.**
    ///
    /// #134 (a joiner banning honest peers because `AnchorNotFinal` is classified as a
    /// peer fault) is out of scope here, and the one thing (a) owes it is not to make
    /// it worse. Two properties do that, and both are asserted:
    ///
    /// 1. **Nothing is scored on the retry path.** Peer scoring keys on the
    ///    `IngestOutcome` that `ingest_block` returns to `P2pNode::complete_block`,
    ///    which is computed once, on arrival. `drain_pending_bodies` holds no
    ///    `PeerId` — it is not that the retry declines to penalise, it is that it has
    ///    nobody to penalise, which is a stronger guarantee than a policy.
    /// 2. **A held body's arrival verdict is not a fault to begin with.** It is
    ///    `Duplicate` (the header was already known) or `Accepted`.
    ///
    /// What this pass did NOT do is change the arrival-time classification — that was
    /// #134's to fix, and it has since: a body whose anchor this node cannot judge is
    /// now `Ignored(UNJUDGED_ANCHOR_REASON)` rather than `Rejected("bad body")`. Both
    /// properties above survive it unchanged, and neither depends on which of the two
    /// the arrival returns; they are about the RETRY path, which scores nothing at all.
    #[test]
    fn a_held_body_is_never_a_second_peer_fault_however_often_it_is_retried() {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 3);
        let mut f = follower_with_headers_only(&blocks);

        // Every arrival of a body for a header we hold — including repeats of the same
        // body, which is what a re-announce is — is a non-fault outcome.
        for round in 0..2 {
            for (header, body) in blocks.iter().skip(1) {
                let outcome = f.ingest_block(*header, body.clone());
                assert_eq!(outcome, IngestOutcome::Duplicate, "round {round}");
                assert!(!outcome.is_peer_fault(), "round {round}: a held body is not a fault");
            }
            assert_eq!(
                f.pending_bodies().0,
                2,
                "a re-announced body replaces its entry rather than adding one"
            );
        }

        // Draining does not produce an outcome at all: there is no return value for a
        // caller to score, and no sender attached to the retry.
        assert_eq!(f.ingest_block(blocks[0].0, blocks[0].1.clone()), IngestOutcome::Duplicate);
        assert_eq!(f.state().tip_height(), 3);
        assert_eq!(f.pending_bodies(), (0, 0), "and the window empties behind it");
    }

    // --- issue #134: an anchor this node cannot judge is not a peer fault -----

    /// A proposer that can put **real transactions** in the blocks it mines: its
    /// genesis root is finalized, so a tx anchored there is admissible and
    /// `mine_block` will assemble it into the body.
    ///
    /// This is the state every chain reaches the moment it carries one transaction —
    /// T1 by construction, since `t1-discovery-serving-decision.md` decided
    /// body-bound discovery. Every block below carries a tx, which is exactly what
    /// makes `validate_body`'s anchor loop execute at all; on a coinbase-only chain
    /// it iterates zero times and `AnchorNotFinal` is unreachable.
    fn transacting_proposer(n: usize) -> Vec<(BlockHeader, BlockBody)> {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let g = p.chain().genesis_block_hash();
        p.state_mut().finalize(g).expect("finalize genesis");
        let anchor = p.state().commitment_root();
        (0..n)
            .map(|i| {
                assert_eq!(
                    p.ingest_tx(tx_with(anchor, i as u8 + 1, b"ok")),
                    IngestOutcome::Accepted,
                    "the proposer admits its own tx"
                );
                let (h, body) = p.mine_block().expect("mine");
                assert_eq!(body.txs.len(), 1, "the block carries a transaction");
                assert_eq!(p.ingest_block(h, body.clone()), IngestOutcome::Accepted);
                (h, body)
            })
            .collect()
    }

    /// 🔴 **ACCEPTANCE 1 (#134), at the verdict seam: a joiner replaying history that
    /// contains transactions it cannot yet anchor never returns a peer fault — and
    /// still refuses to apply the bodies.**
    ///
    /// The joiner has header-synced (the state of every node that joins a running net)
    /// and has finalized nothing, so `is_valid_anchor` answers "no" to every anchor in
    /// every historical body — correctly, about itself. Under the old
    /// `Err(_) => Rejected("bad body")` wildcard each of these six blocks was a peer
    /// fault worth `PENALTY_INVALID_OBJECT` = 20 against `BAN_THRESHOLD` = −100: five
    /// blocks banned the peer serving them. The scoring half of that claim is
    /// `node.rs`'s `a_joiner_does_not_ban_the_peer_serving_it_correct_history`; this is
    /// the classification half.
    ///
    /// **Not penalising is not accepting**, and the second half of the test is the
    /// half that says so: the state machine applies nothing, the pending-body window
    /// stays empty (an unjudged body's proofs were never verified, so it must not be
    /// held), and the lag does not close.
    #[test]
    fn a_joiner_does_not_fault_a_peer_for_history_it_cannot_judge() {
        let blocks = transacting_proposer(6);
        let mut j = follower_with_headers_only(&blocks);
        assert_eq!(j.state().finalized_height(), None, "a joiner has finalized nothing");

        for (i, (header, body)) in blocks.iter().enumerate() {
            let outcome = j.ingest_block(*header, body.clone());
            assert_eq!(
                outcome,
                IngestOutcome::Ignored(UNJUDGED_ANCHOR_REASON),
                "block {} is unjudged, not invalid",
                i + 1
            );
            assert!(
                !outcome.is_peer_fault(),
                "block {}: the peer served correct history and is not at fault",
                i + 1
            );
        }
        assert!(blocks.len() >= 5, "≥5 blocks — enough to have banned the peer at −20 each");
        assert_eq!(
            j.ingest_counters().unjudged_anchor,
            6,
            "and every one of them is visible to an operator"
        );

        // Not penalising is not accepting.
        assert_eq!(j.state().tip_height(), 0, "the joiner applied none of the bodies");
        assert_eq!(j.pending_bodies(), (0, 0), "and held none of them either");
        assert_eq!(j.state_lag().blocks(), 6, "the sync gap is unchanged — this is not a sync fix");
    }

    /// 🔴 **ACCEPTANCE 2 (#134): the distinction is not a blanket amnesty.**
    ///
    /// Two ways a body is still the sender's fault, on the same node in the same test:
    ///
    /// 1. **An intrinsic failure, from any position.** A bad proof is a bad proof on
    ///    every node at every height; the joiner above would charge for it too.
    /// 2. **A positional failure where the verdict IS the network's.** A node standing
    ///    at the body's own parent, with a current finalized head, is running the rule
    ///    the network runs — so a genuinely non-final anchor costs the sender exactly
    ///    what it cost before this pass.
    ///
    /// (2) is the one that matters: it is the live path, and if it did not charge, the
    /// fix would have traded a joiner's problem for a validator's.
    #[test]
    fn a_genuinely_invalid_body_still_costs_the_sender() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        assert!(
            a.anchor_verdict_is_authoritative(
                &BlockHeader::child_of(
                    a.chain().header(&a.chain().tip_hash()).expect("tip"),
                    75,
                    1,
                    [0; 32]
                )
            ),
            "this node stands at the position the anchor rule is defined at"
        );

        // (1) Intrinsic: the proof does not verify. Same verdict on every node.
        let bad_proof = BlockBody::from_single_payee(vec![tx_with(anchor, 9, b"bad")], 0, [0; 4]);
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let h1 =
            BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, bad_proof.commitment());
        let out = a.ingest_block(h1, bad_proof);
        assert_eq!(out, IngestOutcome::Rejected("bad body"));
        assert!(out.is_peer_fault(), "an unverifiable proof is always the sender's fault");

        // (2) Positional, judged from the position that owns the verdict: an anchor
        // that is simply not a finalized root of this chain.
        let never_final = BlockBody::from_single_payee(vec![tx_with([0xEE; 32], 10, b"ok")], 0, [0; 4]);
        let h2 = BlockHeader::child_of(
            &tip,
            tip.timestamp + 75,
            tip.difficulty,
            never_final.commitment(),
        );
        let out = a.ingest_block(h2, never_final);
        assert_eq!(out, IngestOutcome::Rejected("bad body"));
        assert!(out.is_peer_fault(), "a bad anchor at the tip is still a bad anchor");
        assert_eq!(
            a.ingest_counters().unjudged_anchor,
            0,
            "nothing here was excused as unjudgeable"
        );
    }

    /// The **membership test** for the amnesty, stated so it cannot drift: both clauses
    /// of `anchor_verdict_is_authoritative` are computed from this node's own two
    /// numbers, and each one alone is enough to disqualify the verdict.
    ///
    /// This is the answer to "how does a node know it is in the 'cannot judge' case
    /// without that becoming a hole an attacker walks through" — it never asks, and
    /// there is no input here a sender can reach.
    #[test]
    fn the_unjudged_case_is_decided_by_this_nodes_own_two_numbers() {
        // Clause 2 alone: standing at the right position, but having finalized
        // nothing. This is the joiner, and it is also any node in a finality stall.
        let lagging = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let g = *lagging.chain().header(&lagging.chain().genesis_block_hash()).expect("genesis");
        let at_tip = BlockHeader::child_of(&g, 75, g.difficulty, [0; 32]);
        assert_eq!(at_tip.prev, lagging.state().tip_hash(), "clause 1 holds");
        assert!(
            !lagging.anchor_verdict_is_authoritative(&at_tip),
            "clause 2 fails: a node that has finalized nothing has no view of what was final"
        );

        // Clause 1 alone: finality is current, but the body is not at the position the
        // rule is defined at — `apply_block` would refuse it with `NotExtendingTip`,
        // and `is_valid_anchor` would be reading the wrong root index and the wrong tip.
        let (current, _anchor) = adapter_with_finalized_genesis();
        let cg = *current.chain().header(&current.chain().genesis_block_hash()).expect("genesis");
        let one = BlockHeader::child_of(&cg, 75, cg.difficulty, [0; 32]);
        let elsewhere = BlockHeader::child_of(&one, 150, cg.difficulty, [0; 32]);
        assert_ne!(elsewhere.prev, current.state().tip_hash());
        assert!(
            !current.anchor_verdict_is_authoritative(&elsewhere),
            "clause 1 fails: our verdict would be about our position, not about the body"
        );

        // Both: the live path. This is where a bad anchor is charged.
        assert_eq!(one.prev, current.state().tip_hash());
        assert!(current.anchor_verdict_is_authoritative(&one));
    }

    /// Every `BodyError` variant has a declared side of the boundary, and the strings
    /// are the ones this arm has always returned.
    ///
    /// The point of the exhaustive match is that a **future** variant cannot inherit
    /// "peer fault" by silence the way `AnchorNotFinal` did — this test is what makes
    /// the current assignment reviewable, the compiler is what makes the next one
    /// unavoidable.
    #[test]
    fn every_body_error_declares_whether_it_is_intrinsic_or_positional() {
        type A = NodeAdapter<KeccakPow, MockVerifier>;
        let intrinsic = |e: BodyError, want: &str| match A::body_fault_class(&e) {
            BodyFault::Intrinsic(why) => assert_eq!(why, want, "{e:?}"),
            BodyFault::Positional(_) => panic!("{e:?} is intrinsic"),
        };
        intrinsic(
            BodyError::CommitmentMismatch { expected: [0; 32], got: [1; 32] },
            "body does not match header commitment",
        );
        intrinsic(BodyError::MissingCoinbasePayee, "bad body");
        intrinsic(BodyError::WrongFee { index: 0, expected: 1, got: 2 }, "bad body");
        intrinsic(BodyError::DoubleSpendInBlock { index: 0 }, "bad body");
        intrinsic(BodyError::ProofInvalid { index: 0 }, "bad body");
        // The one positional check, and the whole of #134.
        assert!(matches!(
            A::body_fault_class(&BodyError::AnchorNotFinal { index: 0 }),
            BodyFault::Positional("bad body")
        ));
    }

    /// A body we could not judge does not become a body we *relay*. The header it
    /// carried is still learned — that is header-first sync, and it is why the next
    /// announcement in the sequence is not an orphan — but the block is not accepted,
    /// so `P2pNode::announce_block`'s "do not put on the wire what our own node
    /// refused" guard (#77) covers it.
    #[test]
    fn an_unjudged_body_is_not_applied_but_its_header_is_learned() {
        let blocks = transacting_proposer(3);
        // No header sync this time: the bodies arrive cold, as announcements.
        let mut j = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        for (i, (header, body)) in blocks.iter().enumerate() {
            assert_eq!(
                j.ingest_block(*header, body.clone()),
                IngestOutcome::Ignored(UNJUDGED_ANCHOR_REASON),
                "announcement {} is unjudged, not an orphan and not a fault",
                i + 1
            );
            assert_eq!(
                j.chain().tip_height(),
                i as u64 + 1,
                "the header IS learned, so announcement {} is not an orphan",
                i + 2
            );
        }
        assert_eq!(j.state().tip_height(), 0, "and not one body was applied");
    }

    // --- lab #402: settled history is applied under the as-of-height anchor gate ---

    /// 🔴 **ACCEPTANCE (lab #402): the joiner deadlock repro, and its resolution.**
    ///
    /// The live net's shape, at test scale: a chain whose every block carries a
    /// transaction (T1 by construction), a joiner that has header-synced but
    /// finalized nothing — and, the one new ingredient, the net's finalized
    /// checkpoint learned during sync (the #204 query / vote gossip path), with a
    /// real quorum over the real main-chain block, verified by the unchanged
    /// tracker.
    ///
    /// **The mutation lock is the test above this one**:
    /// `a_joiner_does_not_fault_a_peer_for_history_it_cannot_judge` runs the same
    /// bodies WITHOUT the checkpoint and pins the pre-#402 outcome — nothing
    /// applied, `Ignored(UNJUDGED_ANCHOR_REASON)` forever (the 81-asks wall,
    /// measured on box 44.223.26.80). This test is the same joiner WITH the
    /// checkpoint; together they pin that the settled-history gate activates on
    /// quorum-verified finality and on nothing else.
    #[test]
    fn a_joiner_applies_settled_history_whose_anchors_outrun_its_own_finality() {
        let blocks = transacting_proposer(6);
        let mut j = follower_with_headers_only(&blocks);
        assert_eq!(j.state().finalized_height(), None, "the joiner's own finality lags — the deadlock's premise");

        // The net's finalized checkpoint: height 6, the REAL main-chain block, a
        // real 5-of-7 quorum. `ingest_checkpoint` runs the unchanged verify path.
        let cp_hash = blocks[5].0.header_hash();
        let cp = Checkpoint::new(6, cp_hash, cp_hash);
        let (_, validators) = committee7();
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(j.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);

        // Every historical body now applies — no fault, no wall. Before the fix
        // this loop left the state tip at 0 with six unjudged refusals.
        for (i, (header, body)) in blocks.iter().enumerate() {
            let outcome = j.ingest_block(*header, body.clone());
            assert!(!outcome.is_peer_fault(), "block {}: honest history is never a fault", i + 1);
        }
        assert_eq!(j.state().tip_height(), 6, "the deadlock is gone: settled history applied");
        assert_eq!(j.state_lag().blocks(), 0, "the joiner caught its own chain up");
        assert_eq!(
            j.state().finalized_height(),
            Some(6),
            "and the durable head landed via sync_state_finality once the bodies did"
        );
        assert_eq!(
            j.ingest_counters().unjudged_anchor,
            0,
            "nothing was excused as unjudgeable — every body was judged, at its own height"
        );
    }

    /// QUM-111 performance acceptance: settled containment reads the derived
    /// fork-choice height index. Finality changes only the upper bound; it does not
    /// build or own another ancestry cache in the adapter.
    #[test]
    fn settled_history_lookup_uses_the_chain_height_index() {
        let blocks = transacting_proposer(6);
        let mut j = follower_with_headers_only(&blocks);
        let (_, validators) = committee7();

        let finalize = |j: &mut NodeAdapter<KeccakPow, MockVerifier>, height: usize| {
            let hash = blocks[height - 1].0.header_hash();
            let cp = Checkpoint::new(height as u64, hash, hash);
            let votes: Vec<Vote> =
                validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            assert_eq!(j.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        };

        finalize(&mut j, 3);
        assert!(j.block_is_settled_history(&blocks[2].0));
        assert!(!j.block_is_settled_history(&blocks[3].0));
        assert_eq!(j.chain().main_chain_hash_at(3), Some(blocks[2].0.header_hash()));

        finalize(&mut j, 6);
        assert!(j.block_is_settled_history(&blocks[5].0));
        for (height, (header, _)) in blocks.iter().enumerate() {
            assert_eq!(j.chain().main_chain_hash_at(height as u64 + 1), Some(header.header_hash()));
            assert!(j.block_is_settled_history(header));
        }
    }

    /// QUM-111 live-regression lock in the #402 shape: header sync is more than one
    /// complete anchor window ahead of the historical body. The settled decision
    /// still accepts it by its own height and performs only `finalized_height` plus
    /// one O(1) `main_chain_hash_at` read — no adapter prefix exists to walk.
    #[test]
    fn far_ahead_header_sync_applies_settled_body_without_a_per_body_chain_walk() {
        use qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS;

        let mut proposer = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let genesis = proposer.chain().genesis_block_hash();
        proposer.state_mut().finalize(genesis).expect("finalize genesis");
        let anchor = proposer.state().commitment_root();
        assert_eq!(proposer.ingest_tx(tx_with(anchor, 1, b"ok")), IngestOutcome::Accepted);

        let far_tip = MAX_ANCHOR_AGE_BLOCKS + 2;
        let blocks = mine_chain(&mut proposer, far_tip as usize);
        let historical = blocks[0].clone();
        assert!(far_tip.saturating_sub(0) > MAX_ANCHOR_AGE_BLOCKS);

        let mut j = follower_with_headers_only(&blocks);
        let (_, validators) = committee7();
        let cp_hash = blocks.last().expect("far tip").0.header_hash();
        let cp = Checkpoint::new(far_tip, cp_hash, cp_hash);
        let votes: Vec<Vote> =
            validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(j.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        assert_eq!(j.chain().tip_height(), far_tip);
        assert!(j.block_is_settled_history(&historical.0));
        let outcome = j.ingest_block(historical.0, historical.1);
        assert!(!outcome.is_peer_fault(), "header-known history is not a peer fault");
        assert_eq!(j.state().tip_height(), 1, "the far-ahead joiner crossed its first body");
    }

    /// **S1 (lab #402), at the adapter seam: the settled-history gate is a statement
    /// about ONE chain — the finalized one — and a sibling block at a settled height
    /// is not in it.**
    ///
    /// A sibling at height 1 (same parent, different body) sits at or below the
    /// finalized pointer by *height*, but it is not the main-chain block at its
    /// height, so `block_is_settled_history` refuses it and it stays on today's
    /// paths: header learned, body unjudged, nothing applied from it. The
    /// state-machine half of S1 — a root that is on NO chain this node applied is
    /// refused even under the settled gate — is
    /// `qlab-node/tests/historical_anchor.rs`.
    #[test]
    fn a_sibling_block_below_the_finalized_pointer_is_not_settled_history() {
        let blocks = transacting_proposer(3);
        let mut j = follower_with_headers_only(&blocks);

        // A sibling of block 1: same parent (genesis), different tx ⇒ different
        // header. Mined honestly on a fork this committee never finalized.
        let sibling = {
            let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
            let g = p.chain().genesis_block_hash();
            p.state_mut().finalize(g).expect("finalize genesis");
            let anchor = p.state().commitment_root();
            assert_eq!(p.ingest_tx(tx_with(anchor, 0x77, b"ok")), IngestOutcome::Accepted);
            let (h, b) = p.mine_block().expect("mine the sibling");
            (h, b)
        };
        assert_ne!(sibling.0.header_hash(), blocks[0].0.header_hash(), "a genuine sibling");

        // Finality lands on the MAIN chain's block 3.
        let cp_hash = blocks[2].0.header_hash();
        let cp = Checkpoint::new(3, cp_hash, cp_hash);
        let (_, validators) = committee7();
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(j.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);

        // The main-chain block at height 1 is settled history; its sibling is not,
        // by the ancestry clause — height alone does not admit it.
        assert!(j.block_is_settled_history(&blocks[0].0));
        assert!(!j.block_is_settled_history(&sibling.0));

        // Serve the sibling: unjudged (its anchor answers from our position, and it
        // is on no settled chain), never applied, and — #134 kept — not a fault.
        let out = j.ingest_block(sibling.0, sibling.1.clone());
        assert!(!out.is_peer_fault(), "an honest fork block is not a fault");
        assert_eq!(j.state().tip_height(), 0, "nothing from the sibling branch was applied");

        // And the settled main chain still applies around it.
        for (header, body) in blocks.iter() {
            let _ = j.ingest_block(*header, body.clone());
        }
        assert_eq!(j.state().tip_height(), 3);
        assert_eq!(j.state().tip_hash(), blocks[2].0.header_hash(), "the finalized chain won");
    }

    /// **The pending-body window is bounded on all three axes** (issue #130 (a)).
    ///
    /// #135 filed the unbounded twin of this map and made the argument this test
    /// exists to honour: a count cap alone does not behave when body size is variable
    /// by ~145 kB per transaction, and a byte budget alone does not behave when a
    /// coinbase-only body is tens of bytes. So there are two caps and a height window,
    /// and the eviction drops the entry **furthest** from applicable — the lowest
    /// heights are the ones that can close a gap.
    ///
    /// `buffer_body` is exercised directly: it is the admission decision, and it is
    /// deliberately reachable only for headers this node already holds, so a header
    /// 1,025 blocks above the applied tip (#106 resynced 3,597) cannot be built with
    /// real PoW inside a unit test.
    #[test]
    fn the_pending_body_window_is_bounded_by_height_count_and_bytes() {
        let (mut a, _anchor) = adapter_with_finalized_genesis();
        let genesis = *a.chain().header(&a.chain().genesis_block_hash()).expect("genesis header");
        let header_at = |height: u64| {
            let mut h = BlockHeader::child_of(&genesis, height * 75, genesis.difficulty, [0; 32]);
            h.height = height;
            h
        };
        let small = BlockBody::default();

        // At or below the applied tip: nothing to do with it.
        a.buffer_body(header_at(0), small.clone());
        assert_eq!(a.pending_bodies().0, 0, "height 0 is already applied");

        // Inside the window, held; one block past it, refused.
        a.buffer_body(header_at(1), small.clone());
        a.buffer_body(header_at(MAX_PENDING_BODY_HEIGHTS), small.clone());
        assert_eq!(a.pending_bodies().0, 2);
        a.buffer_body(header_at(MAX_PENDING_BODY_HEIGHTS + 1), small.clone());
        assert_eq!(
            a.pending_bodies().0,
            2,
            "beyond the window a body cannot become applicable without material this \
             node has no message to request (#130 (c))"
        );

        // The entry cap holds, and it is the highest heights that go.
        for height in 2..(MAX_PENDING_BODIES as u64 + 20) {
            a.buffer_body(header_at(height), small.clone());
        }
        assert_eq!(a.pending_bodies().0, MAX_PENDING_BODIES);
        assert_eq!(
            a.next_applicable_body().map(|(height, _)| height),
            Some(1),
            "the applicable pick is the LOWEST held height, whatever order they arrived in"
        );
        let heights: Vec<u64> = a.pending_bodies.keys().map(|(h, _)| *h).collect();
        assert_eq!(heights[0], 1, "the lowest held height survived eviction");
        assert!(
            *heights.last().expect("nonempty") < MAX_PENDING_BODIES as u64 + 19,
            "the furthest-from-applicable entries were the ones dropped"
        );

        // The byte budget bites first when bodies carry proofs.
        let (mut b, anchor) = adapter_with_finalized_genesis();
        let mut fat = BlockBody::from_single_payee(vec![tx_with(anchor, 1, b"ok")], 0, [0; 4]);
        fat.txs[0].proof = vec![0u8; 2 * 1024 * 1024];
        for height in 1..24u64 {
            b.buffer_body(header_at(height), fat.clone());
        }
        assert!(
            b.pending_bodies().1 <= MAX_PENDING_BODY_BYTES,
            "byte budget: {} bytes held",
            b.pending_bodies().1
        );
        assert!(
            b.pending_bodies().0 < 23 && b.pending_bodies().0 > 1,
            "the byte cap bound it, not the entry cap: {} entries",
            b.pending_bodies().0
        );
    }

    /// **Lab #427 — the ask set slides past a buffered span to the first `max`
    /// MISSING bodies.** The pre-#427 shape returned only the missing residue of
    /// the first `max` heights, so once most of that span was buffered the whole
    /// fetch pipeline idled behind the residue (the live joiner's `bask=19` against
    /// `slag=12611`), and catch-up throughput collapsed to
    /// ~window ÷ (re-ask rounds × 15 s) ≈ 1.3 blk/s.
    #[test]
    fn the_ask_set_slides_past_a_buffered_span_to_the_first_max_missing() {
        let (cstate, _v) = committee7();
        let mut proposer = NodeAdapter::new(cstate, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut proposer, 200);

        let mut joiner = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        for (h, _) in &blocks {
            assert_eq!(joiner.ingest_header(*h), IngestOutcome::Accepted);
        }
        // Bodies 2..=97 are held; 1 is missing — the exact live shape: the span is
        // nearly full and the residue holds the applied tip at 0.
        for (h, b) in &blocks[1..97] {
            joiner.buffer_body(*h, b.clone());
        }

        let missing = joiner.missing_body_hashes(96);
        assert_eq!(missing.len(), 96, "the ask set is a full window, not the residue");
        assert_eq!(missing[0], blocks[0].0.header_hash(), "the gap-closer is still first");
        assert_eq!(
            missing[1],
            blocks[97].0.header_hash(),
            "and the rest of the window is fetched AHEAD of the buffered span"
        );
        assert_eq!(missing[95], blocks[191].0.header_hash(), "ascending, first 96 missing");
    }

    /// **Lab #427, the bound the slide must keep (#135/#418's lesson): a
    /// backpressured pending buffer collapses the ask set back to the classic
    /// window.** Fetch-ahead must never ask for a body whose arrival would evict
    /// what the buffer already holds — fetch, drop, re-fetch is the exact loop the
    /// old window bound existed to prevent.
    #[test]
    fn a_backpressured_pending_buffer_collapses_the_ask_set_to_the_classic_window() {
        let (cstate, _v) = committee7();
        let mut proposer = NodeAdapter::new(cstate, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut proposer, 600);

        let mut joiner = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        for (h, _) in &blocks {
            assert_eq!(joiner.ingest_header(*h), IngestOutcome::Accepted);
        }
        // Fill pending past MAX_PENDING_BODIES − MAX_BODIES_IN_FLIGHT_CATCHUP
        // (512 − 96): heights 2..=450 = 449 entries. Height 1 stays missing.
        for (h, b) in &blocks[1..450] {
            joiner.buffer_body(*h, b.clone());
        }
        assert!(joiner.pending_bodies().0 + crate::node::MAX_BODIES_IN_FLIGHT_CATCHUP > MAX_PENDING_BODIES);

        let missing = joiner.missing_body_hashes(96);
        assert_eq!(
            missing,
            vec![blocks[0].0.header_hash()],
            "no room for a window of answers ⇒ only the classic window's residue is asked"
        );
    }

    /// **(#130 (a), and #104's second unplaced fact): the state machine's FINALIZED
    /// head catches up too, and its `Finalize` log records with it.**
    ///
    /// A checkpoint that finalizes while the state lags names a block the state
    /// machine does not have, so `Node::finalize` bails at `set_finalized` and returns
    /// `Ok(false)` — no error, no append, and nothing ever came back for it. That is
    /// why #104 saw a `blocks.log` that had not grown across ~450 finalizations.
    ///
    /// It matters beyond the log: `is_valid_anchor` requires a **finalized** height
    /// from the state machine's own store, so a state machine that catches up on
    /// bodies but not on finality answers "no valid anchors exist" forever — which
    /// would hand T1 a node that syncs and still cannot accept a transaction.
    #[test]
    fn the_state_machines_finalized_head_catches_up_after_the_bodies_do() {
        use qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS as CADENCE;

        let dir = temp_dir("finality-catchup");
        let (cstate, validators) = committee7();
        let mut p = NodeAdapter::new(cstate, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, CADENCE as usize);
        {
            let mut f =
                NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                    .expect("open disk-backed");
            for (header, _) in &blocks {
                assert_eq!(f.ingest_header(*header), IngestOutcome::Accepted);
            }
            // A quorum finalizes slot 8 while this node's state is still at genesis.
            let (cp, votes) = f.make_checkpoint(CADENCE, &validators).expect("checkpoint");
            assert!(matches!(
                f.ingest_checkpoint_votes(&cp, &votes[..5]),
                VotesOutcome::Learned { finalized: true, .. }
            ));
            assert_eq!(f.finalized_height(), Some(CADENCE), "the committee finalized");
            assert_eq!(
                f.state().finalized_height(),
                None,
                "…and the state machine could not, because it does not have that block"
            );

            // Bodies arrive. The applied tip catches up — and so must the finalized
            // head, which nothing was retrying.
            for (header, body) in &blocks {
                f.ingest_block(*header, body.clone());
            }
            assert_eq!(f.state().tip_height(), CADENCE);
            assert_eq!(
                f.state().finalized_height(),
                Some(CADENCE),
                "the state machine's finalized head caught up with the committee's"
            );
            assert!(
                f.state().is_valid_anchor(&f.state().commitment_root()),
                "and a finalized root is a valid anchor again"
            );
        }
        // The `Finalize` record reached the log: a restart replays the finalized head
        // rather than starting over with none.
        let reopened = MemNode::open(&dir, genesis_block(easy_sim().genesis_difficulty, 0))
            .expect("reopen");
        assert_eq!(reopened.finalized_height(), Some(CADENCE));
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- issue #133: committee punishments survive a restart -------------------

    /// Conflicting evidence at `slot` from `signer`, signed by the real key.
    fn conflicting(
        validators: &[Validator],
        signer: usize,
        slot: u64,
    ) -> EquivocationEvidence {
        let cp_a = Checkpoint::new(slot, [0xA0 + signer as u8; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(slot, [0xB0 + signer as u8; 32], [0xBB; 32]);
        EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&cp_a),
            cp_a,
            vote_b: validators[signer].sign_checkpoint(&cp_b),
            cp_b,
        }
    }

    /// **Issue #133 D3 — the two-node same-height finality divergence, executed.**
    ///
    /// The Multica baton asked for the case the single-node restart test cannot
    /// show: *a node that observed the evidence and one that did not disagree about
    /// whether an equivocator's vote counts toward quorum*, and at a round that
    /// reaches quorum **only** with that vote, one finalizes a checkpoint the other
    /// refuses. That is a same-height finality split — the R2 stop condition — and
    /// it is the class problem D1 (evidence in blocks) is for: local `punishments.dat`
    /// (PR #159) makes the witness durable, but it cannot teach a non-witness.
    ///
    /// Numbers (committee7, quorum 5): tombstone signer 3 on the witness only. Feed
    /// both nodes the same five votes from signers `{0,1,2,3,4}`:
    /// - witness excludes 3 → 4 active < 5 → does **not** finalize
    /// - non-witness counts all five → finalizes
    ///
    /// Then the witness restarts from its own data dir. After PR #159 it still
    /// refuses; the non-witness still finalizes. The divergence **survives** the
    /// restart rather than flipping — the resurrection the original issue predicted
    /// does **not** reproduce on a node that holds the ledger. What remains open is
    /// the non-witness forever, which is D1, not a missing local file.
    #[test]
    fn a_non_witness_finalizes_a_checkpoint_the_restarted_witness_refuses() {
        let dir = temp_dir("i133-two-node");
        let (_c, validators) = committee7();
        let ev = conflicting(&validators, 3, 8);
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        // Five votes including the equivocator: quorum-marginal for a full roster,
        // below-quorum once signer 3 is excluded.
        let votes: Vec<Vote> = [0usize, 1, 2, 3, 4]
            .iter()
            .map(|&i| validators[i].sign_checkpoint(&cp))
            .collect();

        {
            let mut witness =
                NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                    .expect("open witness");
            assert_eq!(witness.apply_evidence(&ev), Some(3));
            assert!(witness.is_tombstoned(3));
            match witness.ingest_checkpoint_votes(&cp, &votes) {
                VotesOutcome::Learned { finalized, accumulated } => {
                    assert!(
                        !finalized,
                        "witness must refuse: 5 votes minus tombstoned signer 3 is 4 < quorum 5"
                    );
                    assert_eq!(accumulated.len(), 4);
                }
                VotesOutcome::Stale => panic!("witness expected Learned(not finalized), got Stale"),
                VotesOutcome::Invalid => {
                    panic!("witness expected Learned(not finalized), got Invalid")
                }
                VotesOutcome::Unjudged => {
                    panic!("witness expected Learned(not finalized), got Unjudged")
                }
            }
            assert_eq!(witness.finalized_height(), None);
        }

        // Non-witness: never saw the evidence, same five votes, finalizes.
        let mut non_witness =
            NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        assert!(!non_witness.is_tombstoned(3));
        assert_eq!(
            non_witness.ingest_checkpoint(cp, votes.clone()),
            IngestOutcome::Accepted,
            "non-witness counts the equivocator toward quorum and finalizes"
        );
        assert_eq!(non_witness.finalized_height(), Some(2));

        // --- witness restarts from its own data dir ---

        let mut restarted =
            NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                .expect("reopen witness");
        // Control: the constructor still hands open a fresh all-Active roster; the
        // ledger is what keeps signer 3 tombstoned (PR #159). Without it this assert
        // would fail and the defect would have reproduced.
        assert_eq!(committee7().0.status(3), Some(MemberStatus::Active));
        assert!(
            restarted.is_tombstoned(3),
            "resurrection across restart does NOT reproduce when the ledger is present"
        );
        assert_eq!(restarted.punishment_restore().telemetry_field(), "1/1");
        match restarted.ingest_checkpoint_votes(&cp, &votes) {
            VotesOutcome::Learned { finalized, accumulated } => {
                assert!(
                    !finalized,
                    "restarted witness still refuses the checkpoint its non-witness peer finalized"
                );
                assert_eq!(accumulated.len(), 4);
            }
            VotesOutcome::Stale => {
                panic!("restarted witness expected Learned(not finalized), got Stale")
            }
            VotesOutcome::Invalid => {
                panic!("restarted witness expected Learned(not finalized), got Invalid")
            }
            VotesOutcome::Unjudged => {
                panic!("restarted witness expected Learned(not finalized), got Unjudged")
            }
        }
        assert_eq!(
            restarted.finalized_height(),
            None,
            "same height, different finality: non-witness final=2, restarted witness final=none"
        );
        assert_eq!(non_witness.finalized_height(), Some(2));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **THE acceptance property (issue #133), stated as the defect it repairs: a
    /// tombstoned member stays tombstoned across a restart.**
    ///
    /// `qumbra-node` rebuilds its committee from the genesis file on every start, so
    /// the reopen below is given a *fresh all-Active* `CommitteeState` — exactly what
    /// the binary hands `NodeAdapter::open`. Before this change that was the whole
    /// bug: the reopened node answered `is_active` = true for a signer every
    /// non-restarted node on the net had permanently removed, and counted its votes
    /// toward quorum. The control assertion is the one that matters — the fresh
    /// committee really does start Active, so the restored state is not an artifact
    /// of the test handing the node a pre-punished roster.
    #[test]
    fn a_tombstoned_member_stays_tombstoned_across_a_restart() {
        let dir = temp_dir("i133-tombstone");
        let (_c, validators) = committee7();
        let ev = conflicting(&validators, 3, 8);

        {
            let mut a = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                .expect("open");
            assert_eq!(a.committee().state().status(3), Some(MemberStatus::Active));
            assert_eq!(a.apply_evidence(&ev), Some(3));
            assert!(a.is_tombstoned(3));
            assert_eq!(a.punishments().len(), 1, "the evidence was recorded");
        }

        // The ledger is on disk under its own name, not folded into the snapshot or
        // the block log (both of which are allowed to be rebuilt or ignored).
        assert!(dir.join(crate::punish::PUNISHMENT_FILE).exists());

        // --- process dies; the datadir is all that survived ---

        // The control: a genesis committee, untouched, really is all-Active.
        assert_eq!(committee7().0.status(3), Some(MemberStatus::Active));

        let b = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
            .expect("reopen");
        assert!(b.is_tombstoned(3), "the tombstone must survive the restart");
        assert_eq!(b.committee().state().status(3), Some(MemberStatus::Tombstoned));
        assert!(
            !b.committee().state().is_active(3, u64::MAX),
            "and it is never active again, at any height"
        );
        assert_eq!(
            b.committee().state().active_count(0),
            6,
            "roster 7 minus one tombstone — the number a peer that never restarted has"
        );
        assert_eq!(b.punishment_restore().records, 1);
        assert_eq!(b.punishment_restore().tombstoned, vec![3]);
        assert!(!b.punishment_restore().ledger_absent_on_populated_datadir);

        // And its votes no longer reach quorum: 7 signers, 6 countable, quorum 5 —
        // still enough. So check the load-bearing half directly: the tombstoned
        // signer is excluded from the tally.
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let mut b = b;
        let votes: Vec<Vote> = [3usize, 0, 1, 2, 4]
            .iter()
            .map(|&i| validators[i].sign_checkpoint(&cp))
            .collect();
        match b.ingest_checkpoint_votes(&cp, &votes) {
            VotesOutcome::Learned { finalized, accumulated } => {
                assert!(!finalized, "5 votes minus the tombstoned signer is 4 < quorum 5");
                assert_eq!(accumulated.len(), 4, "the tombstoned signer's vote is excluded");
            }
            _ => panic!("expected a below-quorum Learned outcome"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **The second acceptance item, and the reason it is its own test: the BOND and
    /// the SLASHED amount survive too.**
    ///
    /// #133's own words are that the member comes back *"Active with a full bond"* —
    /// two facts, not one. A fix that restored `status` while leaving `bond` at its
    /// genesis value would pass a status-only test and still hand the node a ledger
    /// saying the slash never happened. Both are asserted here against the exact
    /// frozen arithmetic (10 % of bond, integer floor), not against "something less
    /// than before".
    #[test]
    fn the_bond_and_the_slash_survive_the_restart_not_just_the_status_flag() {
        let dir = temp_dir("i133-bond");
        let (_c, validators) = committee7();
        let ev = conflicting(&validators, 5, 16);
        let expect_slash = BOND_AMOUNT / 10;

        {
            let mut a = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                .expect("open");
            assert_eq!(a.apply_evidence(&ev), Some(5));
            assert_eq!(a.committee().state().slashed(5), Some(expect_slash));
            assert_eq!(a.committee().state().bond(5), Some(BOND_AMOUNT - expect_slash));
        }

        // The control: a fresh genesis committee has a FULL bond and a zero slash, so
        // the numbers below cannot have leaked in from the constructor.
        assert_eq!(committee7().0.bond(5), Some(BOND_AMOUNT));
        assert_eq!(committee7().0.slashed(5), Some(0));

        let b = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
            .expect("reopen");
        assert_eq!(b.committee().state().slashed(5), Some(expect_slash), "slash survives");
        assert_eq!(
            b.committee().state().bond(5),
            Some(BOND_AMOUNT - expect_slash),
            "and the bond is still short by exactly the slash"
        );
        // Nobody else was touched.
        for i in 0..7 {
            if i != 5 {
                assert_eq!(b.committee().state().bond(i), Some(BOND_AMOUNT), "member {i}");
                assert_eq!(b.committee().state().slashed(i), Some(0), "member {i}");
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **The third acceptance item, and the whole defect class: a ledger this binary
    /// cannot understand makes the node REFUSE, not start fresh.**
    ///
    /// `PR #140` found `Node::open`'s genesis guard falling through to a replay rather
    /// than refusing, and #133 is filed as *"a fallback that restores a proven
    /// misbehaver to good standing"*. A punishment ledger that fell back to empty
    /// would be a second instance of the same shape inside the fix for the first —
    /// which is why the assertion is on the *refusal*, and why the error names the
    /// file and tells the operator to re-sync rather than to bump a constant.
    #[test]
    fn a_punishment_ledger_this_binary_cannot_read_refuses_to_open() {
        let (_c, validators) = committee7();

        // (a) An unknown format version.
        let dir = temp_dir("i133-badversion");
        let mut bytes = crate::punish::encode(&[conflicting(&validators, 1, 8)]);
        bytes[0] = crate::punish::PUNISHMENT_FORMAT_VERSION + 1;
        std::fs::write(crate::punish::path(&dir), &bytes).unwrap();
        let err = refuses_to_open(&dir, "an unknown ledger version");
        let msg = format!("{err:?}");
        assert!(msg.contains(crate::punish::PUNISHMENT_FILE), "names the file: {msg}");
        assert!(msg.contains("Re-sync this data dir"), "tells the operator what to do: {msg}");
        std::fs::remove_dir_all(&dir).ok();

        // (b) A well-formed ledger whose evidence is not signed by a member of THIS
        //     node's committee — a datadir carried across a committee change. The
        //     seed differs at the same index, because `devnet_committee` derives key
        //     `i` from the index alone and two committee SIZES share their keys.
        let dir = temp_dir("i133-foreign");
        let foreign = Validator::from_seed(1, [0x77; 32]);
        let cp_a = Checkpoint::new(8, [0xA1; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(8, [0xB1; 32], [0xBB; 32]);
        let ev = EquivocationEvidence {
            vote_a: foreign.sign_checkpoint(&cp_a),
            cp_a,
            vote_b: foreign.sign_checkpoint(&cp_b),
            cp_b,
        };
        std::fs::write(crate::punish::path(&dir), crate::punish::encode(&[ev])).unwrap();
        let err = refuses_to_open(&dir, "unverifiable evidence");
        assert!(format!("{err:?}").contains("not a verified equivocation"), "{err:?}");
        std::fs::remove_dir_all(&dir).ok();

        // (c) Trailing garbage.
        let dir = temp_dir("i133-trailing");
        let mut bytes = crate::punish::encode(&[conflicting(&validators, 1, 8)]);
        bytes.push(0xEE);
        std::fs::write(crate::punish::path(&dir), &bytes).unwrap();
        refuses_to_open(&dir, "trailing bytes");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `NodeAdapter` has no `Debug`, so `expect_err` cannot be used: open, require the
    /// refusal, and hand back the error.
    fn refuses_to_open(dir: &std::path::Path, what: &str) -> NodeError {
        match NodeAdapter::open(dir, committee7().0, KeccakPow, MockVerifier, easy_sim()) {
            Err(e) => e,
            Ok(_) => panic!("{what} must refuse to open, but the node started"),
        }
    }

    /// A data dir that already holds chain history but carries **no** ledger is a
    /// pre-#133 data dir: whether a punishment was ever applied against it is
    /// unknowable, so it is *reported* rather than passed off as clean. This is the
    /// "or reports" half of the rule, and it is deliberately not a refusal — refusing
    /// would brick every existing data dir on upgrade.
    ///
    /// The reopen is the other half of the property: once an empty ledger has been
    /// written, "this node has recorded no punishments" is a statement on disk, and
    /// the flag goes quiet.
    #[test]
    fn a_populated_datadir_with_no_ledger_reports_rather_than_passing_as_clean() {
        let dir = temp_dir("i133-preexisting");
        // Build a datadir with real chain history and no ledger, the way a pre-#133
        // binary would have left it.
        {
            let mut a = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                .expect("open");
            mine_chain(&mut a, 3);
            assert_eq!(a.state().tip_height(), 3);
        }
        std::fs::remove_file(crate::punish::path(&dir)).expect("simulate a pre-#133 datadir");

        let a = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
            .expect("must still start — refusing would brick every existing datadir");
        assert!(
            a.punishment_restore().ledger_absent_on_populated_datadir,
            "a populated datadir with no ledger must be reported, not assumed clean"
        );
        assert_eq!(a.punishment_restore().records, 0);
        drop(a);

        // An empty ledger was written, so the next start is unambiguous.
        assert!(crate::punish::path(&dir).exists());
        let b = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
            .expect("reopen");
        assert!(
            !b.punishment_restore().ledger_absent_on_populated_datadir,
            "an explicitly empty ledger is a statement, not an absence"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A fresh data dir is not the reported case: no chain history means no history to
    /// have lost a punishment from, so the flag is quiet and the counter is a plain
    /// zero. Stated as a test because "reports on every cold start" would be a
    /// warning nobody reads, which is the same failure as no warning at all.
    #[test]
    fn a_fresh_datadir_restores_zero_punishments_quietly() {
        let dir = temp_dir("i133-fresh");
        let a = NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
            .expect("open");
        assert_eq!(a.punishment_restore(), &crate::punish::PunishmentRestore::default());
        assert!(a.punishment_restore().summary_line().contains("0 record(s) on disk"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An in-memory adapter writes nothing and restores nothing — every in-process
    /// sim, soak and test keeps its previous behaviour byte for byte.
    #[test]
    fn an_in_memory_adapter_persists_no_punishments() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        assert_eq!(a.apply_evidence(&conflicting(&validators, 4, 8)), Some(4));
        assert!(a.is_tombstoned(4), "the punishment still applies in memory");
        assert_eq!(a.punishments().len(), 1);
        assert_eq!(a.punishment_restore(), &crate::punish::PunishmentRestore::default());
    }

    /// A private temp dir for a disk-backed adapter.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        p.push(format!("qlab-p2p-i130a-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    /// **Acceptance (#104 — this defect's first observation, from production, three
    /// days before #130 was filed): a body that was buffered and then applied is
    /// PERSISTED.**
    ///
    /// #104 recorded `blocks.log` frozen on all four T0 hosts, four different sizes,
    /// four different stop times, all inside the first 27 minutes of a 73-hour run,
    /// and could not place two of its facts. Both are this: `apply_block` returns
    /// `NotExtendingTip` **before** `persist::append_record`, so the append was never
    /// attempted — a fix that replayed a buffer into memory without reaching the log
    /// would leave #104's exact symptom alive after its cause was gone. The append is
    /// inside `apply_block`, so applying through it is what makes it durable, and this
    /// test is what proves it rather than asserting it.
    #[test]
    fn buffered_bodies_reach_the_block_log_so_a_restart_replays_from_disk() {
        use qlab_node::BLOCK_LOG;

        let dir = temp_dir("persist");
        let log = dir.join(BLOCK_LOG);
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 3);

        let before = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
        {
            let mut f =
                NodeAdapter::open(&dir, committee7().0, KeccakPow, MockVerifier, easy_sim())
                    .expect("open disk-backed");
            for (header, _) in &blocks {
                assert_eq!(f.ingest_header(*header), IngestOutcome::Accepted);
            }
            assert_eq!(f.state().tip_height(), 0, "headers only");
            // Newest-first, so every one of them is buffered before any is applied.
            for (header, body) in blocks.iter().rev() {
                f.ingest_block(*header, body.clone());
            }
            assert_eq!(f.state().tip_height(), 3, "drained");
        }
        let after = std::fs::metadata(&log).expect("the block log exists").len();
        assert!(
            after > before,
            "the block log must grow when buffered bodies apply ({before} → {after})"
        );

        // The #104 acceptance shape: a restart replays its own chain from disk instead
        // of resyncing from peers. `open` (snapshot-assisted) and `replay`
        // (from-genesis) must agree — this repo's own correctness anchor.
        let genesis = genesis_block(easy_sim().genesis_difficulty, 0);
        let reopened = MemNode::open(&dir, genesis.clone()).expect("reopen");
        let replayed = MemNode::replay(&dir, genesis).expect("replay");
        assert_eq!(reopened.tip_height(), 3, "restart replays three applied bodies");
        assert_eq!(replayed.tip_height(), 3);
        assert_eq!(reopened.tip_hash(), replayed.tip_hash());
        assert_eq!(reopened.commitment_root(), replayed.commitment_root());
        // Issue #102 moved this assertion's observable too, and for the same reason as
        // in `a_miner_ahead_of_its_own_state_tip_does_not_silently_lose_its_coinbase`.
        // It counted three coinbase leaves as proof the bodies "really were folded in,
        // not just logged"; three blocks now append no leaves, and `== 0` would be true
        // of a header-only log as well, which is precisely the distinction this line
        // exists to draw.
        //
        // The replacement is strictly stronger: every height's *body* came back off
        // disk, byte-identical to what was mined. A log that recorded only headers
        // cannot produce that, and neither can one whose bodies were buffered and
        // dropped.
        for (height, (_, mined)) in (1..=3u64).zip(blocks.iter()) {
            let hash = reopened.chain().chain().main_chain()[height as usize];
            let stored = reopened.chain().block(&hash).expect("the body replayed from disk");
            assert_eq!(
                stored.body().commitment(),
                mined.commitment(),
                "height {height}: the body itself replayed, not just its header"
            );
            assert!(
                qlab_node::coinbase_note_leaf(height, &stored.body()).is_some(),
                "height {height}: and it is a minting body, so a leaf is owed for it"
            );
        }
        assert_eq!(
            reopened.commitment_count(),
            0,
            "and none of the three has matured yet — the first lands at 145"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **Acceptance 3 (#130 (a) part 3): every duty that needs a current view is
    /// refused while the lag is nonzero, and refused NO LONGER once it converges.**
    ///
    /// The second half is the load-bearing one: a refusal that never lifts is a
    /// permanently degraded node wearing a fix's clothes. Ethereum's optimistic-sync
    /// rule is the precedent — an optimistic validator MUST NOT produce a block or
    /// attest, *while it is optimistic*.
    #[test]
    fn duties_are_refused_while_the_state_lags_and_resume_once_it_converges() {
        let mut p = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let blocks = mine_chain(&mut p, 2);
        let mut f = follower_with_headers_only(&blocks);
        // Finalized genesis ⇒ the empty-tree root is a valid anchor, so only the lag
        // can be the reason the transaction below is refused.
        let genesis = f.chain().genesis_block_hash();
        f.state_mut().finalize(genesis).expect("finalize genesis");
        let anchor = f.state().commitment_root();
        let tx = tx_with(anchor, 7, b"ok");

        // 1. Mining — it would build on a tip whose body it has not applied.
        assert!(f.mine_block().is_none());
        // 2. Admitting a transaction — `Mempool::admit` answers `is_valid_anchor`
        //    from the state machine's tree, and that tree is stale.
        let refused = f.ingest_tx(tx.clone());
        assert!(
            matches!(refused, IngestOutcome::Ignored(_)),
            "a refusal to judge is `Ignored`, got {refused:?}"
        );
        assert!(
            !refused.is_peer_fault(),
            "the sender did nothing wrong — this node is the one that cannot judge (#134's boundary)"
        );
        assert_eq!(f.mempool().len(), 0);
        assert_eq!(f.lag_refusals("mine"), 1);
        assert_eq!(f.lag_refusals("admit_tx"), 1);

        // Converge.
        for (header, body) in &blocks {
            assert_eq!(f.ingest_block(*header, body.clone()), IngestOutcome::Duplicate);
        }
        assert!(!f.state_lag().is_lagging());

        // 3. Both duties resume, and the counters stop climbing.
        assert!(f.mine_block().is_some(), "mining resumes");
        assert_eq!(f.ingest_tx(tx), IngestOutcome::Accepted, "admission resumes");
        assert_eq!(f.mempool().len(), 1);
        assert_eq!(f.lag_refusals("mine"), 1, "no further refusal after convergence");
        assert_eq!(f.lag_refusals("admit_tx"), 1);
    }

    // --- issue #77: the p2p ingest seam ------------------------------------

    /// The p2p seam rejects a body that is not the one the header committed to,
    /// with its own reason (it is misbehaviour, not merely an invalid tx).
    #[test]
    fn ingest_block_rejects_a_body_that_is_not_the_headers_body() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        // An honest header over the tip, committing to a real one-tx body.
        let honest_body = BlockBody::from_single_payee(vec![tx_with(anchor, 3, b"ok")], 0, [0; 4]);
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let header =
            BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, honest_body.commitment());
        // …handed a different, also-internally-valid body.
        let swapped = BlockBody::from_single_payee(vec![tx_with(anchor, 4, b"ok")], 0, [0; 4]);
        assert_eq!(
            a.ingest_block(header, swapped),
            IngestOutcome::Rejected("body does not match header commitment")
        );
        assert_eq!(a.chain().tip_height(), 0, "nothing was accepted");
    }

    /// **The cheapest exploit (issue #77): the honest header relayed with an EMPTY
    /// body.** Nothing else rejects it — an empty body has no bad anchor, no wrong
    /// fee, no repeated nullifier and no invalid proof — so before this fix the
    /// header was accepted and empty state applied under it.
    #[test]
    fn ingest_block_rejects_an_honest_header_with_an_empty_body() {
        let (mut a, anchor) = adapter_with_finalized_genesis();
        let honest_body = BlockBody::from_single_payee(vec![tx_with(anchor, 5, b"ok")], 0, [0; 4]);
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let header =
            BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, honest_body.commitment());
        assert_eq!(
            a.ingest_block(header, BlockBody::default()),
            IngestOutcome::Rejected("body does not match header commitment")
        );
        assert_eq!(a.chain().tip_height(), 0, "the header was not accepted either");
        assert_eq!(a.state().tip_height(), 0, "no empty body was applied to state");
    }

    #[test]
    fn ingest_header_orphan_then_accept() {
        let (mut a, _anchor) = adapter_with_finalized_genesis();
        // Mine h1 (child of genesis) but hold it; a header built on h1 is an orphan
        // until h1 is known.
        let (h1, _b) = a.mine_block().unwrap();
        let h2 = BlockHeader::child_of(&h1, 150, h1.difficulty, [2; 32]);
        assert_eq!(a.ingest_header(h2), IngestOutcome::Orphan);
        assert_eq!(a.ingest_header(h1), IngestOutcome::Accepted);
    }

    #[test]
    fn checkpoint_quorum_gate_and_finalized_height() {
        let (cstate, validators) = committee7(); // quorum 5
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0xAA; 32], [0xAA; 32]);
        let votes4: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(a.ingest_checkpoint(cp, votes4), IngestOutcome::Rejected("insufficient quorum"));
        let votes5: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(a.ingest_checkpoint(cp, votes5.clone()), IngestOutcome::Accepted);
        assert_eq!(a.finalized_height(), Some(2));
        assert_eq!(a.ingest_checkpoint(cp, votes5), IngestOutcome::Duplicate);
    }

    #[test]
    fn equivocation_evidence_tombstones_and_drops_from_quorum() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        // Tombstone signers 0,1,2 via verified conflicting evidence.
        for s in [0usize, 1, 2] {
            let ca = Checkpoint::new(90 + s as u64, [0xA0 + s as u8; 32], [0xA0; 32]);
            let cb = Checkpoint::new(90 + s as u64, [0xB0 + s as u8; 32], [0xB0; 32]);
            let ev = EquivocationEvidence {
                vote_a: validators[s].sign_checkpoint(&ca),
                cp_a: ca,
                vote_b: validators[s].sign_checkpoint(&cb),
                cp_b: cb,
            };
            assert_eq!(a.apply_evidence(&ev), Some(s));
            assert!(a.is_tombstoned(s));
        }
        // 7 votes, only 4 non-tombstoned count < quorum 5 → not finalized.
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let votes: Vec<Vote> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(a.ingest_checkpoint(cp, votes), IngestOutcome::Rejected("insufficient quorum"));
        assert_eq!(a.finalized_height(), None);
    }

    /// M10-T0-1 item 5 convergence: the equivocation slash is 10 % of the
    /// member's bond (not the old flat placeholder). At the standard bond this is
    /// the same 100,000 the placeholder used, but it is now derived from the bond.
    #[test]
    fn equivocation_slash_is_ten_percent_of_bond() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let ca = Checkpoint::new(8, [0xA5; 32], [0xA0; 32]);
        let cb = Checkpoint::new(8, [0xB5; 32], [0xB0; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[2].sign_checkpoint(&ca),
            cp_a: ca,
            vote_b: validators[2].sign_checkpoint(&cb),
            cp_b: cb,
        };
        assert_eq!(a.apply_evidence(&ev), Some(2));
        assert!(a.is_tombstoned(2));
        assert_eq!(a.committee().state().slashed(2), Some(BOND_AMOUNT / 10), "slash = 10% of bond");
        assert_eq!(a.committee().state().bond(2), Some(BOND_AMOUNT - BOND_AMOUNT / 10));
    }

    #[test]
    fn observe_votes_detects_conflict_not_forgery() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp_a = Checkpoint::new(8, [0xAA; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(8, [0xBB; 32], [0xBB; 32]);
        assert!(a.observe_votes(&cp_a, &[validators[3].sign_checkpoint(&cp_a)]).is_empty());
        let ev = a.observe_votes(&cp_b, &[validators[3].sign_checkpoint(&cp_b)]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].vote_a.signer, 3);
        // Forged vote (valid sig, wrong signer index) does not seed evidence.
        let forged = Vote { signer: 5, signature: validators[3].sign_checkpoint(&cp_a).signature };
        assert!(a.observe_votes(&cp_a, &[forged]).is_empty());
    }

    // ---- M10-T0-2: finality-stall recovery e2e --------------------------------

    /// A fast-mining sim so the e2e can cross the degraded-mode lag threshold
    /// (`DEGRADED_MODE_LAG_BLOCKS` = 16) in a couple dozen cheap blocks.
    fn easy_sim() -> SimConfig {
        SimConfig {
            block_time_secs: 2,
            genesis_difficulty: 8,
            mine_nonce_budget: 5_000_000,
            ..SimConfig::default()
        }
    }

    /// Reproduce `devnet_committee`'s deterministic seed for validator `i`, so a
    /// simulated crash-restart can rebuild the same signing key from its keystore.
    fn devnet_seed(i: usize) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0x9c;
        s[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        s
    }

    /// Mine one block on `proposer` and relay it to `follower` — a two-node
    /// in-process mesh sharing one genesis. Both accept the same block.
    fn mine_and_relay(
        proposer: &mut NodeAdapter<KeccakPow, MockVerifier>,
        follower: &mut NodeAdapter<KeccakPow, MockVerifier>,
    ) {
        let (h, body) = proposer.mine_block().expect("mine");
        assert_eq!(proposer.ingest_block(h, body.clone()), IngestOutcome::Accepted);
        assert_eq!(follower.ingest_block(h, body), IngestOutcome::Accepted);
    }

    /// Assemble a telemetry snapshot from a live adapter + an injected peer count
    /// (age is chain-time from block timestamps — deterministic).
    ///
    /// Lab #633: the age comes from `qlab_node::telemetry::finalized_age_secs`, the
    /// one arithmetic every producer shares. This helper used to carry a **third**
    /// copy of the subtraction, and it indexed `main_chain()` by the finalized
    /// height — which panics outright on the very state #633 is about (a tracker
    /// head above this node's tip), so the harness could not have expressed the
    /// defect even deliberately.
    fn telemetry_of(a: &NodeAdapter<KeccakPow, MockVerifier>, peer_count: u64) -> Telemetry {
        let tip = a.chain().tip_height();
        let finalized = a.finalized_height();
        let age = qlab_node::telemetry::finalized_age_secs(
            finalized,
            a.chain().header(&a.chain().tip_hash()).map(|hd| hd.timestamp),
            a.chain().finalized_hash().and_then(|h| a.chain().header(&h)).map(|hd| hd.timestamp),
        );
        Telemetry::assemble(
            tip,
            finalized,
            age,
            a.mempool().len() as u64,
            peer_count,
            a.committee().current_epoch(),
            DEGRADED_MODE_LAG_BLOCKS,
        )
    }

    /// The full recovery arc over a two-node mesh: normal finality → committee
    /// goes dark → node flags Degraded (stall depth + age rise, committee earns
    /// nothing) → the committee process restarts from persisted finalizer state →
    /// catch-up finalization jumps past the stalled span → both nodes recover to
    /// Final. This is the half Crosslink left undesigned (design §4 status).
    #[test]
    fn finality_stall_degrade_committee_restart_recovery() {
        use qlab_node::recovery::{catch_up_slot, committee_accrual_finalized, FinalizerState};
        use qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS as CADENCE;

        // Two-node mesh, one committee (quorum 5), five finalizers hold the keys.
        let mut a = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let mut b = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        let mut finalizers: Vec<Finalizer> =
            (0..5).map(|i| Finalizer::new(Validator::from_seed(i, devnet_seed(i)))).collect();
        const PEERS: u64 = 1; // each node sees one peer in this mesh

        // --- 1. Normal operation: mine a cadence span and finalize slot 8. ---
        for _ in 0..CADENCE {
            mine_and_relay(&mut a, &mut b);
        }
        let (cp8, votes8) = a.make_checkpoint_guarded(CADENCE, &mut finalizers).unwrap();
        assert_eq!(votes8.len(), 5, "all five finalizers vote on a fresh slot");
        assert_eq!(a.ingest_checkpoint(cp8, votes8.clone()), IngestOutcome::Accepted);
        assert_eq!(b.ingest_checkpoint(cp8, votes8), IngestOutcome::Accepted);
        assert_eq!(a.finalized_height(), Some(CADENCE));
        assert_eq!(a.finality_status(), FinalityStatus::Final);
        assert_eq!(telemetry_of(&a, PEERS).finality_status, FinalityStatus::Final);
        let income_before = committee_accrual_finalized(a.finalized_height());
        assert!(income_before > 0);

        // --- 2. Committee goes dark: chain keeps producing, finality does not. ---
        // Mine past the degraded threshold (lag = tip − 8 > 16).
        for _ in 0..(DEGRADED_MODE_LAG_BLOCKS + 1) {
            mine_and_relay(&mut a, &mut b);
        }
        let stalled_tip = a.chain().tip_height();
        assert!(stalled_tip - CADENCE > DEGRADED_MODE_LAG_BLOCKS);
        assert_eq!(a.finality_status(), FinalityStatus::Degraded, "committee stall ⇒ Degraded");
        assert_eq!(b.finality_status(), FinalityStatus::Degraded);

        let t_stall = telemetry_of(&a, PEERS);
        assert_eq!(t_stall.finality_status, FinalityStatus::Degraded);
        assert_eq!(t_stall.stall_depth, stalled_tip - CADENCE, "stall depth = tip − finalized");
        assert!(
            t_stall.last_finalized_age_secs.is_some_and(|age| age > 0),
            "chain-time age of the stall is visible — and it is measured, not a fallback"
        );
        // The stalled span earns the committee nothing (finalized-only accrual):
        // income is unchanged from before the stall despite ~17 new blocks.
        assert_eq!(
            committee_accrual_finalized(a.finalized_height()),
            income_before,
            "no committee income accrues for the unfinalized span"
        );

        // --- 3. Committee restart: persist finalizer state, crash, rejoin. ---
        let saved: Vec<Vec<u8>> = finalizers.iter().map(|f| f.state().to_bytes()).collect();
        drop(finalizers); // the finalizer processes die
        let mut finalizers: Vec<Finalizer> = (0..5)
            .map(|i| {
                let st = FinalizerState::from_bytes(&saved[i]).expect("reload ledger");
                Finalizer::restore(Validator::from_seed(i, devnet_seed(i)), st)
            })
            .collect();
        // They resume knowing exactly where they left off — no operator surgery.
        assert!(finalizers.iter().all(|f| f.last_voted_slot() == Some(CADENCE)));

        // --- 4. Catch-up finalization: jump straight to the newest slot ≤ tip,
        //         skipping the stalled intermediate slots (strictly-advancing). ---
        let recover = catch_up_slot(stalled_tip, CADENCE).expect("a slot to catch up to");
        assert!(recover > CADENCE && recover <= stalled_tip);
        let (cpr, votesr) = a.make_checkpoint_guarded(recover, &mut finalizers).unwrap();
        assert_eq!(votesr.len(), 5, "restarted finalizers all vote on the fresh recovery slot");
        assert_eq!(a.ingest_checkpoint(cpr, votesr.clone()), IngestOutcome::Accepted);
        assert_eq!(b.ingest_checkpoint(cpr, votesr), IngestOutcome::Accepted);

        // --- 5. Both nodes recover to Final; finality jumped 8 → recover directly. ---
        assert_eq!(a.finalized_height(), Some(recover), "finality advanced past the stall");
        assert!(recover - CADENCE > 1, "the recovery skipped intermediate stalled slots");
        assert_eq!(a.finality_status(), FinalityStatus::Final, "node a recovered");
        assert_eq!(b.finality_status(), FinalityStatus::Final, "node b recovered (mesh converged)");
        let t_recovered = telemetry_of(&a, PEERS);
        assert_eq!(t_recovered.finality_status, FinalityStatus::Final);
        assert!(t_recovered.stall_depth < t_stall.stall_depth, "stall depth dropped on recovery");
        // Recovery accrues the newly-finalized span's committee income.
        assert!(
            committee_accrual_finalized(a.finalized_height()) > income_before,
            "the recovered span now accrues committee income"
        );

        // --- 6. The never-double-sign invariant held across the restart. ---
        // A restarted finalizer refuses to sign a CONFLICTING checkpoint for slot 8
        // (which it signed before the crash) — it can never emit the second half of
        // an equivocation pair.
        let conflicting_slot8 = Checkpoint::new(CADENCE, [0xEE; 32], [0xEE; 32]);
        assert!(
            finalizers[0].sign(&conflicting_slot8).is_err(),
            "restarted finalizer must not equivocate against its pre-crash slot-8 vote"
        );
    }

    // ---- M10-T0-5: cross-message vote accumulation ----------------------------

    /// A 21-key committee (quorum 15) where NO single message carries a quorum: a
    /// first partial set is Learned-but-not-finalized, a second partial completes the
    /// quorum across messages, and finality forms. (Acceptance #3, node level.)
    #[test]
    fn partial_then_completing_set_finalizes() {
        let (committee, validators) = devnet_committee(21); // quorum 15
        let mut a =
            NodeAdapter::new(CommitteeState::new(committee, BOND_AMOUNT), KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(8, [0x08; 32], [0x08; 32]);
        let sign = |idxs: &[usize]| -> Vec<Vote> {
            idxs.iter().map(|&i| validators[i].sign_checkpoint(&cp)).collect()
        };

        match a.ingest_checkpoint_votes(&cp, &sign(&[0, 1, 2, 3, 4, 5])) {
            VotesOutcome::Learned { finalized, accumulated } => {
                assert!(!finalized, "6 < quorum 15 does not finalize");
                assert_eq!(accumulated.len(), 6);
            }
            _ => panic!("a fresh partial set must be Learned"),
        }
        assert_eq!(a.finalized_height(), None, "no finality below quorum");

        // Nine more distinct signers → 15 total → quorum → finalize.
        match a.ingest_checkpoint_votes(&cp, &sign(&[6, 7, 8, 9, 10, 11, 12, 13, 14])) {
            VotesOutcome::Learned { finalized, accumulated } => {
                assert!(finalized, "15 distinct across messages reaches quorum");
                assert_eq!(accumulated.len(), 15);
            }
            _ => panic!("the completing set must finalize"),
        }
        assert_eq!(a.finalized_height(), Some(8), "distributed finality formed");
        // Re-delivery of the same variant is stale (already finalized).
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &sign(&[0])), VotesOutcome::Stale));
    }

    /// Frozen §4 / acceptance #5: a tombstoned signer's vote is excluded from the
    /// tally (never counted toward quorum), without penalising the well-formed set.
    #[test]
    fn tombstoned_vote_excluded_from_tally() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        // Tombstone signer 0 via verified conflicting evidence.
        let ca = Checkpoint::new(90, [0xA0; 32], [0xA0; 32]);
        let cb = Checkpoint::new(90, [0xB0; 32], [0xB0; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[0].sign_checkpoint(&ca),
            cp_a: ca,
            vote_b: validators[0].sign_checkpoint(&cb),
            cp_b: cb,
        };
        assert_eq!(a.apply_evidence(&ev), Some(0));

        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let set: Vec<Vote> = [0usize, 1, 2].iter().map(|&i| validators[i].sign_checkpoint(&cp)).collect();
        match a.ingest_checkpoint_votes(&cp, &set) {
            VotesOutcome::Learned { finalized, accumulated } => {
                assert!(!finalized);
                assert_eq!(accumulated.len(), 2, "tombstoned signer 0 excluded");
                assert!(accumulated.iter().all(|v| v.signer != 0), "signer 0 not tallied");
            }
            _ => panic!("a valid partial set (minus the tombstoned signer) is Learned"),
        }
    }

    /// Acceptance #4 (updated #164 rework): intrinsic rejects never grow the tally
    /// and are `Invalid` (→ the wire handler penalises). Unknown index is
    /// `Unjudged` (positional — not a peer fault). A signature under a
    /// **resolvable** index that fails against that key is `Invalid` — including
    /// the soak's forged-cp shape (valid member-1 sig claimed as signer 0).
    #[test]
    fn forged_unknown_dup_never_increase_tally() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        // Genuine forge: an outsider's signature attributed to an in-range index.
        let outsider = qlab_devnet::committee::Validator::from_seed(99, [0xEE; 32]);
        let forged = Vote {
            signer: 0,
            signature: outsider.sign_checkpoint(&cp).signature,
        };
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &[forged]), VotesOutcome::Invalid));
        assert!(VotesOutcome::Invalid.is_peer_fault());

        // Unknown signer index (outside the 7-member committee) ⇒ Unjudged (#164).
        assert!(matches!(
            a.ingest_checkpoint_votes(&cp, &[outsider.sign_checkpoint(&cp)]),
            VotesOutcome::Unjudged
        ));
        assert!(!VotesOutcome::Unjudged.is_peer_fault());

        // In-roster signature under the wrong claimed index ⇒ still Invalid
        // (index resolved; verify fails). This is n7soak S2's forged-cp shape.
        let misindexed =
            Vote { signer: 0, signature: validators[1].sign_checkpoint(&cp).signature };
        assert!(matches!(
            a.ingest_checkpoint_votes(&cp, &[misindexed]),
            VotesOutcome::Invalid
        ));

        // Duplicate-signer padding within one set ⇒ still Invalid.
        let dup = vec![validators[3].sign_checkpoint(&cp), validators[3].sign_checkpoint(&cp)];
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &dup), VotesOutcome::Invalid));

        assert_eq!(a.finalized_height(), None, "no invalid/unjudged set moved finality");
    }

    // ---- issue #87: round-level diagnostics on the real ingest path -----------

    /// **The headline acceptance.** The T0 shape — 21 keys split across four nodes,
    /// no message carrying a quorum — with a round that dies short and is caught up
    /// past. The record of the dead round names the number, the counts, the roster
    /// context and the members whose votes never arrived; before this, that round
    /// produced no output of any kind.
    #[test]
    fn a_stalled_round_names_its_number_its_counts_and_its_absentees() {
        let (committee, validators) = devnet_committee(21); // quorum 15
        let mut a =
            NodeAdapter::new(CommitteeState::new(committee, BOND_AMOUNT), KeccakPow, MockVerifier, sim());

        // Mine a real two-cadence span, so the checkpoints name real blocks and the
        // finality advance has a real chain-time interval to measure.
        for _ in 0..16 {
            let (h, body) = a.mine_block().expect("mine");
            assert_eq!(a.ingest_block(h, body), IngestOutcome::Accepted);
        }

        // Slot 8: the nodes holding 6 and 5 keys are heard from, then the net
        // partitions — 11 of 21, four short of quorum 15.
        let (cp8, all8) = a.make_checkpoint(8, &validators).expect("slot 8");
        a.ingest_checkpoint_votes(&cp8, &all8[0..6]);
        a.ingest_checkpoint_votes(&cp8, &all8[6..11]);
        assert_eq!(a.finalized_height(), None, "11 < 15: the round is short");
        assert_eq!(a.rounds().open_round(8).map(|r| r.have()), Some(11));

        // The partition heals and slot 16 finalizes, overtaking slot 8 — the exact
        // catch-up shape behind the soak's 61-of-165 multi-slot advances.
        let (cp16, all16) = a.make_checkpoint(16, &validators).expect("slot 16");
        a.ingest_checkpoint_votes(&cp16, &all16[0..15]);
        assert_eq!(a.finalized_height(), Some(16));

        let closed = a.drain_rounds();
        assert_eq!(closed.len(), 2, "the dead slot and the finalized slot both produce a record");

        let dead = closed.iter().find(|r| r.height == 8).expect("slot 8 has a record");
        assert_eq!(dead.close, Some(RoundClose::Superseded { by_height: 16 }));
        assert_eq!((dead.have(), dead.need, dead.active, dead.roster), (11, 15, 21, 21));
        assert_eq!(dead.absent(), (11..21).collect::<Vec<_>>(), "the ten who never reached us");
        assert_eq!(dead.msgs, 2, "both partial messages are accounted for");
        assert_eq!(dead.rejects.total(), 0, "nothing was thrown away — this was a shortage");
        // The journal line an operator would actually read.
        let line = dead.to_line();
        assert!(line.starts_with("ROUND slot=8 "), "{line}");
        assert!(line.contains("have=11 need=15 active=21"), "{line}");
        assert!(line.contains("absent=11,12,13,14,15,16,17,18,19,20"), "{line}");

        let ok = closed.iter().find(|r| r.height == 16).expect("slot 16 has a record");
        assert_eq!(ok.close, Some(RoundClose::Finalized));
        assert_eq!(ok.diagnose(), RoundDiagnosis::Finalized);

        // Aggregates: one finalized round, one that did not, and per-member
        // participation split the same way.
        assert_eq!(a.metrics().rounds_by_verdict(RoundDiagnosis::Finalized), 1);
        assert_eq!(a.metrics().votes_by_result("counted"), 11 + 15);
        let text = qlab_node::metrics::render(a.metrics(), &qlab_node::metrics::LiveGauges::default());
        assert!(text.contains("qumbra_committee_absent_rounds_total{signer=\"20\"} 2"), "absent in both");
        assert!(text.contains("qumbra_committee_signed_rounds_total{signer=\"0\"} 2"), "signed in both");
        // The catch-up jump is a real histogram observation, not a differenced gauge.
        assert!(text.contains("qumbra_finality_advance_blocks_bucket{le=\"16\"} 1"), "{text}");
    }

    /// A round being fed junk must not look like a round nobody spoke about. Forged,
    /// unknown-signer and duplicate sets are recorded against the slot with their
    /// reason — and still never touch what counts. (#164: unknown is Unjudged, not
    /// Invalid, but the diagnostic counters still name each refuse.)
    #[test]
    fn rejected_vote_sets_are_recorded_against_the_round_they_targeted() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        let outsider = qlab_devnet::committee::Validator::from_seed(99, [0xEE; 32]);
        let forged = Vote {
            signer: 0,
            signature: outsider.sign_checkpoint(&cp).signature,
        };
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &[forged]), VotesOutcome::Invalid));
        assert!(matches!(
            a.ingest_checkpoint_votes(&cp, &[outsider.sign_checkpoint(&cp)]),
            VotesOutcome::Unjudged
        ));
        let dup = vec![validators[3].sign_checkpoint(&cp), validators[3].sign_checkpoint(&cp)];
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &dup), VotesOutcome::Invalid));

        let r = a.rounds().open_round(2).expect("the targeted slot has a record");
        assert_eq!(r.have(), 0, "no rejected vote ever counted");
        assert_eq!((r.rejects.forged, r.rejects.unknown_signer, r.rejects.duplicate), (1, 1, 1));
        assert_eq!(r.msgs, 3);
        assert_eq!(a.finalized_height(), None);
        assert_eq!(a.metrics().votes_by_result("forged"), 1);
        assert_eq!(a.metrics().votes_by_result("counted"), 0);
    }

    /// A tombstoned member is `excluded`, never `absent` — the operator must not be
    /// sent to look at a host that the frozen §4 rule itself removed. And the round
    /// that this makes unwinnable is diagnosed as *quorum impossible*, not as a
    /// participation failure.
    #[test]
    fn tombstoned_members_are_excluded_not_reported_absent() {
        let (cstate, validators) = committee7(); // quorum 5
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        // Tombstone signers 0, 1 and 2 → 4 active < quorum 5.
        for i in 0..3usize {
            let ca = Checkpoint::new(90, [0xA0 + i as u8; 32], [0xA0; 32]);
            let cb = Checkpoint::new(90, [0xB0 + i as u8; 32], [0xB0; 32]);
            let ev = EquivocationEvidence {
                vote_a: validators[i].sign_checkpoint(&ca),
                cp_a: ca,
                vote_b: validators[i].sign_checkpoint(&cb),
                cp_b: cb,
            };
            assert_eq!(a.apply_evidence(&ev), Some(i));
        }

        let cp = Checkpoint::new(8, [0x08; 32], [0x08; 32]);
        let set: Vec<Vote> = [0usize, 1, 3, 4].iter().map(|&i| validators[i].sign_checkpoint(&cp)).collect();
        a.ingest_checkpoint_votes(&cp, &set);

        let r = a.rounds().open_round(8).expect("slot 8 recorded");
        assert_eq!(r.voted, vec![3, 4], "only active signers count");
        assert_eq!(r.excluded, vec![0, 1], "tombstoned voters are excluded, by name");
        assert_eq!(r.absent(), vec![2, 5, 6], "signer 2 is tombstoned but silent — still absent");
        assert_eq!(r.active, 4, "roster 7 minus three tombstones");
        assert!(
            r.active < r.need,
            "the roster could not have produced a quorum — the fields say so before any \
             verdict does, which is why the raw fields are always on the line"
        );
        // Still open, so it has no verdict yet — a round that has not ended has no
        // cause. The `active < need ⇒ quorum_impossible` step is exercised on a CLOSED
        // record in `qlab_node::round`'s classifier test.
        assert_eq!(r.diagnose(), RoundDiagnosis::Open);
    }

    /// **Caught on the lab net, not in a unit test.** Genesis carries a placeholder
    /// timestamp of 0 and is finalized as a bootstrap act, so two event observations
    /// had a wrong basis at the source: the genesis→block-1 gap entered the block
    /// interval histogram as ~1.78e9 seconds (the whole Unix epoch, wrecking the sum
    /// and the tail from one sample), and finalizing genesis entered the advance
    /// histograms as a 0-block jump carrying a stall depth equal to the tip.
    #[test]
    fn genesis_placeholders_never_enter_the_event_histograms() {
        let (committee, validators) = devnet_committee(21);
        let mut a =
            NodeAdapter::new(CommitteeState::new(committee, BOND_AMOUNT), KeccakPow, MockVerifier, sim());

        // Finalize genesis (height 0) exactly as the binary does at startup.
        let (cp0, votes0) = a.make_checkpoint(0, &validators).expect("genesis checkpoint");
        a.ingest_checkpoint_votes(&cp0, &votes0);
        assert_eq!(a.finalized_height(), Some(0));

        for _ in 0..8 {
            let (h, body) = a.mine_block().expect("mine");
            assert_eq!(a.ingest_block(h, body), IngestOutcome::Accepted);
        }
        let text = qlab_node::metrics::render(a.metrics(), &qlab_node::metrics::LiveGauges::default());

        // 8 blocks connected, but only 7 intervals — the genesis gap is not one.
        assert!(text.contains("qumbra_blocks_connected_total 8"), "{text}");
        assert!(text.contains("qumbra_block_interval_seconds_count 7"), "{text}");
        let sum: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("qumbra_block_interval_seconds_sum "))
            .and_then(|v| v.parse().ok())
            .expect("sum series present");
        assert!(sum < 10_000, "a placeholder timestamp leaked into the histogram: sum={sum}");

        // Finalizing genesis is not a finality advance.
        assert!(text.contains("qumbra_finality_advances_total 0"), "{text}");
        assert!(text.contains("qumbra_finality_advance_blocks_count 0"), "{text}");

        // …and a real finalize afterwards IS counted.
        let (cp8, votes8) = a.make_checkpoint(8, &validators).expect("slot 8");
        a.ingest_checkpoint_votes(&cp8, &votes8);
        assert_eq!(a.finalized_height(), Some(8));
        let after = qlab_node::metrics::render(a.metrics(), &qlab_node::metrics::LiveGauges::default());
        assert!(after.contains("qumbra_finality_advances_total 1"), "{after}");
        assert!(after.contains("qumbra_finality_advance_blocks_bucket{le=\"8\"} 1"), "{after}");
    }

    /// The observation surface must not change consensus. Same inputs, same
    /// finalized head, same outcomes — with the ledger fully wired.
    #[test]
    fn diagnostics_do_not_change_what_finalizes() {
        let (committee, validators) = devnet_committee(21);
        let mk = || {
            NodeAdapter::new(
                CommitteeState::new(committee.clone(), BOND_AMOUNT),
                KeccakPow,
                MockVerifier,
                sim(),
            )
        };
        let cp = Checkpoint::new(8, [0x08; 32], [0x08; 32]);
        let sign = |idxs: &[usize]| -> Vec<Vote> {
            idxs.iter().map(|&i| validators[i].sign_checkpoint(&cp)).collect()
        };

        // Fourteen distinct signers is one short and must not finalize; the
        // fifteenth must. The ledger observes both and changes neither.
        let mut a = mk();
        a.ingest_checkpoint_votes(&cp, &sign(&(0..14).collect::<Vec<_>>()));
        assert_eq!(a.finalized_height(), None, "14 < 15 stays short with diagnostics on");
        assert_eq!(a.rounds().open_round(8).map(|r| r.have()), Some(14));
        a.ingest_checkpoint_votes(&cp, &sign(&[14]));
        assert_eq!(a.finalized_height(), Some(8), "the fifteenth finalizes, as before");

        // The ledger is bounded: a spray of junk heights cannot grow it without end.
        let mut b = mk();
        for h in 1..200u64 {
            let junk = Checkpoint::new(h * 8, [h as u8; 32], [h as u8; 32]);
            let v = vec![validators[0].sign_checkpoint(&junk)];
            b.ingest_checkpoint_votes(&junk, &v);
        }
        assert!(
            b.rounds().open_len() <= qlab_node::round::MAX_OPEN_ROUNDS,
            "open-round cap holds under a height spray"
        );
        assert_eq!(b.finalized_height(), None, "nothing in the spray finalized");
    }

    // ---- issue #74: halt-height upgrade mechanism -----------------------------

    use qlab_devnet::halt::{HaltPlan, PostHaltRules};
    use qlab_devnet::validation::{validate_header_under, ValidationError};

    /// The drill's halt height, on the cadence grid.
    const DRILL_H: u64 = 16;
    /// The resuming revision's rule domain (stands in for `Revision::digest()`,
    /// which lives in the binary crate — this crate must not depend on it).
    const DRILL_DOMAIN: Hash32 = [0x74; 32];

    fn armed_at(h: u64) -> RuleSchedule {
        RuleSchedule { halt: HaltPlan::Armed { height: h }, post_halt: None }
    }
    fn resumed_past(h: u64) -> RuleSchedule {
        RuleSchedule {
            halt: HaltPlan::None,
            post_halt: Some(PostHaltRules { from_height: h, domain: DRILL_DOMAIN }),
        }
    }
    fn node_with(rules: RuleSchedule) -> NodeAdapter<KeccakPow, MockVerifier> {
        let mut n = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        n.set_rule_schedule(rules);
        n
    }
    fn finalizers5() -> Vec<Finalizer> {
        (0..5).map(|i| Finalizer::new(Validator::from_seed(i, devnet_seed(i)))).collect()
    }
    /// Mine one block on `proposer` and offer it to `to`, returning `to`'s verdict.
    fn mine_then_offer(
        proposer: &mut NodeAdapter<KeccakPow, MockVerifier>,
        to: &mut NodeAdapter<KeccakPow, MockVerifier>,
    ) -> (BlockHeader, IngestOutcome) {
        let (h, body) = proposer.mine_block().expect("proposer mines");
        assert_eq!(proposer.ingest_block(h, body.clone()), IngestOutcome::Accepted);
        (h, to.ingest_block(h, body))
    }

    /// A node with no halt scheduled behaves EXACTLY as it did before #74 — the
    /// default rule schedule changes nothing anywhere.
    #[test]
    fn halt_default_schedule_is_a_no_op() {
        let mut n = NodeAdapter::new(committee7().0, KeccakPow, MockVerifier, easy_sim());
        assert_eq!(*n.rules(), RuleSchedule::V1_0);
        assert_eq!(n.halt_at(), None);
        assert!(!n.is_halted_at_tip());
        for _ in 0..4 {
            let (h, body) = n.mine_block().expect("mines");
            assert_eq!(n.ingest_block(h, body), IngestOutcome::Accepted);
        }
        assert_eq!(n.tip_height(), 4);
        assert_eq!(n.finality_status(), FinalityStatus::Degraded, "nothing finalized yet");
    }

    /// H2, the three halt acts, on one armed node: it applies block H, then stops
    /// mining above it, rejects blocks above it, and — the load-bearing act — stops
    /// signing checkpoints above it. Plus the Halting → Halted regime walk.
    #[test]
    fn halt_stops_mining_accepting_and_signing_above_h() {
        let mut up = node_with(armed_at(DRILL_H));
        let mut old = node_with(RuleSchedule::V1_0);
        for _ in 0..DRILL_H {
            mine_and_relay(&mut old, &mut up);
        }
        assert_eq!(up.tip_height(), DRILL_H, "block H itself is applied");

        // (1) stops mining above H
        assert!(up.mine_block().is_none(), "an armed node does not mine above H");
        assert!(up.is_halted_at_tip());
        // (2) rejects blocks above H — and does NOT penalise the sender: the peer is
        //     on a different release, not misbehaving.
        let (_, verdict) = mine_then_offer(&mut old, &mut up);
        assert_eq!(
            verdict,
            IngestOutcome::Ignored("above halt height"),
            "Ignored, NOT Rejected — an old-binary peer is on a different release, not \
             misbehaving, and must not be scored as an invalid-object sender"
        );
        assert_eq!(up.ingest_counters().halt_ignored, 1, "attributed to the RELEASE layer");
        assert_eq!(up.ingest_counters().pow_rejected, 0, "…not to header validation");
        assert_eq!(up.tip_height(), DRILL_H, "tip pinned at the boundary");
        // (3) regime: Halting until H's checkpoint finalizes…
        assert_eq!(up.finality_status(), FinalityStatus::Halting);
        let mut fz = finalizers5();
        let (cp, votes) = up.make_checkpoint_guarded(DRILL_H, &mut fz).expect("checkpoint AT H");
        assert_eq!(votes.len(), 5, "the checkpoint AT H is exactly the one that must be signed");
        assert_eq!(up.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        // …then Halted. The upgrade boundary is a FINALIZED boundary.
        assert_eq!(up.finalized_height(), Some(DRILL_H));
        assert_eq!(up.finality_status(), FinalityStatus::Halted);
    }

    /// The committee-signing gate in isolation: an armed node refuses to sign any
    /// checkpoint above H even when it holds the block, and refuses to FINALIZE one
    /// offered by a peer (it must not finalize a chain it will not accept).
    #[test]
    fn halt_committee_refuses_to_sign_or_finalize_above_h() {
        // Build the chain first, THEN arm at a height below the tip — the only way
        // to hold a block above H on an armed node, and exactly the isolation the
        // assertion needs.
        let mut n = node_with(RuleSchedule::V1_0);
        for _ in 0..DRILL_H {
            let (h, body) = n.mine_block().unwrap();
            assert_eq!(n.ingest_block(h, body), IngestOutcome::Accepted);
        }
        let mut fz = finalizers5();
        // Un-armed, slot 16 signs fine.
        assert!(n.make_checkpoint_guarded(16, &mut fz).is_some());
        // Armed at 8: slot 8 still signs, slot 16 does not.
        let mut n2 = node_with(RuleSchedule::V1_0);
        for _ in 0..DRILL_H {
            let (h, body) = n2.mine_block().unwrap();
            assert_eq!(n2.ingest_block(h, body), IngestOutcome::Accepted);
        }
        n2.set_rule_schedule(armed_at(8));
        let mut fz2 = finalizers5();
        assert!(n2.make_checkpoint_guarded(8, &mut fz2).is_some(), "the checkpoint AT H is signed");
        assert!(
            n2.make_checkpoint_guarded(16, &mut fz2).is_none(),
            "the committee stops signing ABOVE H — the load-bearing act"
        );
        // And a quorum-carrying checkpoint above H offered by a peer does not
        // finalize on the halted node (Duplicate/Stale, not Invalid — no penalty).
        let (cp16, votes16) = n.make_checkpoint_guarded(16, &mut fz).unwrap();
        assert_eq!(n2.ingest_checkpoint(cp16, votes16), IngestOutcome::Duplicate);
        assert_eq!(n2.finalized_height(), None, "a halted node finalizes nothing above H");
    }

    /// **DRILL (a) — the hybrid honesty case (H3), in process.**
    ///
    /// committee-and-governance §4: old-binary PoW miners *can* keep producing
    /// blocks past the halt height; those blocks can never finalize, and the fork
    /// resolves to the checkpointed branch. This is the drill that proves the
    /// mechanism, so it asserts all four halves: the old branch GROWS, it never
    /// finalizes, the checkpointed branch wins, and nothing reorgs past a finalized
    /// checkpoint.
    ///
    /// (The binary swap is modelled here by installing the resumed rule schedule on
    /// the same node — same state, new release. The real process-restart path is
    /// what the docker drill covers.)
    #[test]
    fn drill_a_old_miner_grows_past_h_and_never_finalizes() {
        let mut up = node_with(armed_at(DRILL_H));
        let mut old = node_with(RuleSchedule::V1_0);
        for _ in 0..DRILL_H {
            mine_and_relay(&mut old, &mut up);
        }
        // The boundary is finalized before any swap (H2).
        let mut fz = finalizers5();
        let (cp, votes) = up.make_checkpoint_guarded(DRILL_H, &mut fz).unwrap();
        assert_eq!(up.ingest_checkpoint(cp, votes.clone()), IngestOutcome::Accepted);
        assert_eq!(old.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        assert_eq!(up.finality_status(), FinalityStatus::Halted);
        let boundary_hash = up.main_chain_hash_at(DRILL_H).unwrap();

        // --- 1. The old binary keeps mining past H. It GROWS. ---
        for _ in 0..5 {
            let (_, verdict) = mine_then_offer(&mut old, &mut up);
            assert_eq!(verdict, IngestOutcome::Ignored("above halt height"));
        }
        // WHILE HALTED the refusal is at the RELEASE layer: nothing was judged
        // invalid, we simply stopped. No penalty is owed to the old miner.
        assert_eq!(up.ingest_counters().halt_ignored, 5);
        assert_eq!(up.ingest_counters().pow_rejected, 0);
        assert_eq!(old.tip_height(), DRILL_H + 5, "the old branch grows — expected, not a defect");
        assert_eq!(up.tip_height(), DRILL_H, "the halted node stays at the boundary");

        // --- 2. The swap: the upgraded release resumes past H. ---
        up.set_rule_schedule(resumed_past(DRILL_H));
        assert_eq!(
            up.finality_status(),
            FinalityStatus::Final,
            "no longer a halt regime — tip == finalized == H, so the ordinary rule applies again"
        );

        // --- 3. The old branch is STILL rejected — now structurally, by the
        //        post-halt rules, not by the halt. This is what makes "those blocks
        //        can never finalize" a property rather than an accident. ---
        for h in (DRILL_H + 1)..=(DRILL_H + 5) {
            let hdr = *old.chain().header(&old.main_chain_hash_at(h).unwrap()).unwrap();
            let verdict = up.ingest_header(hdr);
            if h == DRILL_H + 1 {
                // The first old-rule block above the boundary attaches to a parent
                // the upgraded node HAS, so it is fully validated — and its PoW does
                // not meet the target under the post-halt rules.
                //
                // WHICH LAYER: this is the HEADER-VALIDATION layer, not the release
                // layer. After the swap the node has no halt at all; the block is
                // refused because the post-halt rule domain makes it invalid. The
                // exact failing check is asserted directly below, against
                // `validate_header_under`, so the claim is about `PowUnsatisfied`
                // and not about a coincidental difficulty/timestamp mismatch.
                assert_eq!(
                    verdict,
                    IngestOutcome::Rejected("invalid header: pow"),
                    "the first post-H block built under PRE-halt rules must fail PoW"
                );
                assert_eq!(
                    validate_header_under(
                        up.chain(),
                        &KeccakPow,
                        &hdr,
                        easy_sim().block_time_secs,
                        KeyBlockSchedule::new(easy_sim().key_epoch_blocks, easy_sim().key_epoch_lag),
                        up.chain_rules(),
                    ),
                    Err(ValidationError::PowUnsatisfied),
                    "the failing check is the PoW target under the post-halt domain — \
                     the rejection is attributable to the header-validation layer"
                );
            } else {
                // Everything above it hangs off a block the upgraded node refused,
                // so it is an orphan — never accepted, and never reachable.
                assert_eq!(verdict, IngestOutcome::Orphan, "old-branch block {h} is unreachable");
            }
            assert_ne!(up.tip_height(), h, "no old-rule block ever becomes the upgraded tip");
        }
        assert_eq!(up.tip_height(), DRILL_H, "the upgraded node is still at the boundary");
        // AFTER the swap the refusal moved layers: no further halt-ignores (this
        // release has no halt), and the PoW counter took the hit instead. That
        // difference is exactly what the run doc must report.
        assert_eq!(up.ingest_counters().halt_ignored, 5, "unchanged since the swap");
        assert_eq!(
            up.ingest_counters().pow_rejected,
            1,
            "post-swap refusal is at the header-validation layer (domain separation)"
        );

        // --- 4. …and the fork is bilateral: the upgraded branch does not verify
        //        under the old rules either. Neither side can silently absorb the
        //        other; only finality arbitrates. ---
        let (new_hdr, verdict) = mine_then_offer(&mut up, &mut old);
        assert_eq!(new_hdr.height, DRILL_H + 1, "the upgraded net resumes AT the boundary");
        assert_eq!(
            verdict,
            IngestOutcome::Rejected("invalid header: pow"),
            "…and the old binary rejects the NEW block at the same layer, for the same reason"
        );

        // --- 5. The checkpointed branch wins: the upgraded committee finalizes
        //        past H; the old branch's finality is frozen at H forever. ---
        while up.tip_height() < DRILL_H + 8 {
            let (h, body) = up.mine_block().expect("the resumed net mines");
            assert_eq!(up.ingest_block(h, body), IngestOutcome::Accepted);
        }
        let (cp2, votes2) = up.make_checkpoint_guarded(DRILL_H + 8, &mut fz).unwrap();
        assert_eq!(up.ingest_checkpoint(cp2, votes2), IngestOutcome::Accepted);
        assert_eq!(up.finalized_height(), Some(DRILL_H + 8), "finality resumed on the new rules");
        assert_eq!(
            old.finalized_height(),
            Some(DRILL_H),
            "the un-upgraded branch NEVER finalizes above H, however long it grows"
        );
        assert!(old.tip_height() > DRILL_H, "…while still growing");

        // --- 6. THE INVARIANT: no reorg past a finalized checkpoint, on either
        //        side, and both still agree on the finalized boundary block. ---
        assert_eq!(up.main_chain_hash_at(DRILL_H), Some(boundary_hash));
        assert_eq!(old.main_chain_hash_at(DRILL_H), Some(boundary_hash));
        assert!(up.finalized_height().unwrap() >= DRILL_H);
        assert!(old.finalized_height().unwrap() >= DRILL_H);
    }

    /// **DRILL (b) — the ⅔ gate (N2), in process.** With fewer than quorum keys on
    /// the upgraded binary, finality does NOT resume: the net stays where it was
    /// rather than limping forward on a minority committee.
    #[test]
    fn drill_b_finality_does_not_resume_below_quorum() {
        let mut up = node_with(armed_at(DRILL_H));
        for _ in 0..DRILL_H {
            let (h, body) = up.mine_block().unwrap();
            assert_eq!(up.ingest_block(h, body), IngestOutcome::Accepted);
        }
        let mut fz = finalizers5(); // quorum for committee7 is 5
        let (cp, votes) = up.make_checkpoint_guarded(DRILL_H, &mut fz).unwrap();
        assert_eq!(up.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        assert_eq!(up.finalized_height(), Some(DRILL_H));

        // Swap in the upgraded release, but only 4 of the 5 quorum keys come back.
        up.set_rule_schedule(resumed_past(DRILL_H));
        let mut minority: Vec<Finalizer> =
            (0..4).map(|i| Finalizer::new(Validator::from_seed(i, devnet_seed(i)))).collect();
        while up.tip_height() < DRILL_H + 8 {
            let (h, body) = up.mine_block().unwrap();
            assert_eq!(up.ingest_block(h, body), IngestOutcome::Accepted);
        }
        let (cp2, votes2) = up.make_checkpoint_guarded(DRILL_H + 8, &mut minority).unwrap();
        assert_eq!(votes2.len(), 4, "a minority of the committee is on the new binary");
        assert_eq!(
            up.ingest_checkpoint(cp2, votes2),
            IngestOutcome::Rejected("insufficient quorum"),
            "below ⅔ ⇒ no finalization"
        );
        assert_eq!(
            up.finalized_height(),
            Some(DRILL_H),
            "finality stays at the boundary — the net does not limp forward on a minority"
        );

        // The fifth key returns → quorum → finality resumes on the new rules.
        let mut fz5 = finalizers5();
        let (cp3, votes3) = up.make_checkpoint_guarded(DRILL_H + 8, &mut fz5).unwrap();
        assert_eq!(votes3.len(), 5);
        assert_eq!(up.ingest_checkpoint(cp3, votes3), IngestOutcome::Accepted);
        assert_eq!(up.finalized_height(), Some(DRILL_H + 8));
    }

    /// **DRILL (d) — the stand-down (N1), in process.** A cancelled upgrade does not
    /// halt at the cancelled height: the net mines and finalizes straight through it.
    #[test]
    fn drill_d_a_cancelled_upgrade_does_not_halt() {
        let cancelled = RuleSchedule {
            halt: HaltPlan::Cancelled { height: DRILL_H, reason: "review stood it down" },
            post_halt: None,
        };
        let mut n = node_with(cancelled);
        assert_eq!(n.halt_at(), None);
        while n.tip_height() < DRILL_H + 8 {
            let (h, body) = n.mine_block().expect("a cancelled upgrade never stops mining");
            assert_eq!(n.ingest_block(h, body), IngestOutcome::Accepted);
        }
        assert_eq!(n.tip_height(), DRILL_H + 8, "mined straight through the cancelled height");
        assert!(!n.is_halted_at_tip());
        // …and the committee keeps checkpointing across it.
        let mut fz = finalizers5();
        for slot in [DRILL_H, DRILL_H + 8] {
            let (cp, votes) = n.make_checkpoint_guarded(slot, &mut fz).expect("signs across it");
            assert_eq!(n.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        }
        assert_eq!(n.finalized_height(), Some(DRILL_H + 8), "finality never paused");
        assert_eq!(n.finality_status(), FinalityStatus::Final, "never reports a halt regime");
    }

    // --- issue #164: a roster mismatch is "I cannot judge this", not "you forged it" --

    /// Build two adapters that share a genesis committee under a short epoch so a
    /// unit test can cross a boundary without mining a day of blocks.
    fn pair_under_epoch(
        epoch_len: u64,
        n: usize,
    ) -> (NodeAdapter<KeccakPow, MockVerifier>, NodeAdapter<KeccakPow, MockVerifier>, Vec<Validator>) {
        let (committee, validators) = devnet_committee(n);
        let sched = EpochSchedule::new(epoch_len);
        let holds = NodeAdapter::with_epoch(
            EpochCommittee::genesis(sched, CommitteeState::new(committee.clone(), BOND_AMOUNT)),
            KeccakPow,
            MockVerifier,
            sim(),
        );
        let lost = NodeAdapter::with_epoch(
            EpochCommittee::genesis(sched, CommitteeState::new(committee, BOND_AMOUNT)),
            KeccakPow,
            MockVerifier,
            sim(),
        );
        (holds, lost, validators)
    }

    fn tombstone_mid(a: &mut NodeAdapter<KeccakPow, MockVerifier>, validators: &[Validator], idx: usize) {
        let ca = Checkpoint::new(90, [0xA0 + idx as u8; 32], [0xA0; 32]);
        let cb = Checkpoint::new(90, [0xB0 + idx as u8; 32], [0xB0; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[idx].sign_checkpoint(&ca),
            cp_a: ca,
            vote_b: validators[idx].sign_checkpoint(&cb),
            cp_b: cb,
        };
        assert_eq!(a.apply_evidence(&ev), Some(idx));
    }

    /// Mine `n` blocks onto `a` so the epoch machinery advances with the tip.
    fn mine_n(a: &mut NodeAdapter<KeccakPow, MockVerifier>, n: usize) {
        for _ in 0..n {
            let (h, body) = a.mine_block().expect("mine");
            assert_eq!(a.ingest_block(h, body), IngestOutcome::Accepted);
        }
    }

    /// 🔴 **ACCEPTANCE 1 (#164): two nodes that disagree about a tombstone still
    /// agree within the epoch** — quorum is over roster size N, not over active
    /// members, so a mid-epoch tombstone moves nothing about thresholds or indices.
    ///
    /// This is the correction to the coordinator's original claim on issue #133
    /// (that a divergent tombstone changes the quorum threshold). Pinned here so
    /// nobody re-derives the wrong mechanism.
    #[test]
    fn two_nodes_disagreeing_about_a_tombstone_still_agree_within_the_epoch() {
        let (mut holds, mut lost, validators) = pair_under_epoch(8, 7);
        // Mid-index tombstone — the case that *will* shift indices at the boundary.
        tombstone_mid(&mut holds, &validators, 2);

        assert!(holds.is_tombstoned(2));
        assert!(!lost.is_tombstoned(2));

        // Within the epoch the roster is fixed: both still N=7, quorum 5.
        assert_eq!(holds.committee().state().size(), 7, "tombstone does not shrink the roster mid-epoch");
        assert_eq!(lost.committee().state().size(), 7);
        assert_eq!(
            holds.committee().state().quorum_threshold(),
            lost.committee().state().quorum_threshold(),
            "quorum is over N, not over active — both compute the same threshold"
        );
        assert_eq!(holds.committee().state().quorum_threshold(), 5);

        // Indices are unshifted on both: signer 5 is still key_5 on both, so an
        // honest vote verifies under either roster.
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let vote5 = validators[5].sign_checkpoint(&cp);
        assert!(holds.committee().state().committee().verify_vote(&cp, &vote5));
        assert!(lost.committee().state().committee().verify_vote(&cp, &vote5));

        // And the vote is accepted into the tally on both (tombstoned signer 2 is
        // the only one excluded on `holds`; signer 5 is active everywhere).
        assert!(matches!(
            holds.ingest_checkpoint_votes(&cp, &[vote5.clone()]),
            VotesOutcome::Learned { finalized: false, .. }
        ));
        assert!(matches!(
            lost.ingest_checkpoint_votes(&cp, &[vote5]),
            VotesOutcome::Learned { finalized: false, .. }
        ));
    }

    /// 🔴 **ACCEPTANCE 2 (#164 rework): at the epoch boundary the rosters diverge,
    /// and an out-of-range index is Unjudged (not scored).**
    ///
    /// Only the **out-of-range** arm is positional. After seal, holds has N=6 and
    /// lost has N=7: lost's honest vote at signer 6 is unaddressable on holds and
    /// must not be a peer fault. Mid-index reseal (index in range, wrong key) is
    /// **not** amnestied — that residual is still Invalid; evidence-on-chain is
    /// the real agreement fix (STOP-POINT, not this baton).
    #[test]
    fn at_the_epoch_boundary_out_of_range_votes_are_unjudged() {
        const EPOCH: u64 = 8;
        let (mut holds, mut lost, validators) = pair_under_epoch(EPOCH, 7);
        // Tombstone a mid-index member so seal shifts every higher index down by one.
        tombstone_mid(&mut holds, &validators, 2);

        mine_n(&mut holds, EPOCH as usize);
        mine_n(&mut lost, EPOCH as usize);
        assert_eq!(holds.committee().current_epoch(), 1);
        assert_eq!(lost.committee().current_epoch(), 1);

        // Half 1 — the divergence still happens.
        assert_eq!(holds.committee().state().size(), 6, "seal drops the tombstoned member");
        assert_eq!(lost.committee().state().size(), 7, "a node that never saw the tombstone keeps N");
        assert_eq!(holds.committee().state().quorum_threshold(), 5); // ⌊2·6/3⌋+1 = 5
        assert_eq!(lost.committee().state().quorum_threshold(), 5); // ⌊2·7/3⌋+1 = 5
        // Key that was at 5 is at 4 on holds (shifted), still at 5 on lost.
        let key5 = validators[5].verifying_key().encode().to_vec();
        assert_eq!(
            holds.committee().state().committee().member(4).map(|k| k.encode().to_vec()),
            Some(key5.clone()),
            "holds: key_5 shifted to index 4"
        );
        assert_eq!(
            lost.committee().state().committee().member(5).map(|k| k.encode().to_vec()),
            Some(key5),
            "lost: key_5 still at index 5"
        );

        let tip = holds.chain().tip_hash();
        let cp = Checkpoint::new(EPOCH, tip, tip);

        // Positional half — lost's high index is out of range on holds.
        let lost_high = validators[6].sign_checkpoint(&cp);
        assert_eq!(lost_high.signer, 6);
        let from_high = holds.ingest_checkpoint_votes(&cp, &[lost_high]);
        assert!(
            matches!(from_high, VotesOutcome::Unjudged),
            "index 6 does not resolve on holds' N=6 roster"
        );
        assert!(!from_high.is_peer_fault(), "out-of-range is not a peer fault");

        // Residual half — mid-index reseal still looks like a forge under the
        // narrowed boundary (index resolves, key is wrong). Pinned so nobody
        // re-widens Unjudged to swallow this without naming the trade-off.
        let lost_mid = validators[5].sign_checkpoint(&cp);
        let from_mid = holds.ingest_checkpoint_votes(&cp, &[lost_mid]);
        assert!(
            matches!(from_mid, VotesOutcome::Invalid),
            "mid-index reseal: index resolves, verify fails → Invalid (not Unjudged)"
        );
        assert!(from_mid.is_peer_fault());
    }

    /// 🔴 **ACCEPTANCE 3 (#164 criterion 3): a forged vote with a resolvable index
    /// is still scored.**
    ///
    /// Shape matches `n7soak::tests::s2_adversarial_rejected`'s forged-cp: a valid
    /// signature by member 1 claimed under signer index 0. Index resolves; verify
    /// against key_0 fails → `Invalid` + `is_peer_fault()`. This must not become a
    /// blanket amnesty (issue #134 criterion 2, applied identically). Named so the
    /// next regression is caught by name, not by soak luck.
    #[test]
    fn a_forged_vote_with_a_resolvable_index_is_still_scored() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        // Soak shape: member-1 signature, claimed as signer 0.
        let soak_forged = Vote {
            signer: 0,
            signature: validators[1].sign_checkpoint(&cp).signature,
        };
        let out = a.ingest_checkpoint_votes(&cp, &[soak_forged]);
        assert!(
            matches!(out, VotesOutcome::Invalid),
            "resolvable index + bad sig is Invalid, not Unjudged"
        );
        assert!(out.is_peer_fault(), "and it is a peer fault");

        // Outsider signature under an in-range index is the same arm.
        let outsider = Validator::from_seed(99, [0xEE; 32]);
        let outsider_forged = Vote {
            signer: 0,
            signature: outsider.sign_checkpoint(&cp).signature,
        };
        let out2 = a.ingest_checkpoint_votes(&cp, &[outsider_forged]);
        assert!(matches!(out2, VotesOutcome::Invalid));
        assert!(out2.is_peer_fault());
        assert_eq!(a.finalized_height(), None);
    }

    /// Backward-compatible name for the outsider half of criterion 3 (kept so
    /// older references in the PR body / issue comments still resolve).
    #[test]
    fn a_genuinely_forged_vote_is_still_a_peer_fault() {
        let (cstate, _validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        let outsider = Validator::from_seed(99, [0xEE; 32]);
        let forged = Vote {
            signer: 0,
            signature: outsider.sign_checkpoint(&cp).signature,
        };
        let out = a.ingest_checkpoint_votes(&cp, &[forged]);
        assert!(matches!(out, VotesOutcome::Invalid), "genuine forge is Invalid");
        assert!(out.is_peer_fault(), "and it is a peer fault");
        assert_eq!(a.finalized_height(), None);
    }

    /// Classification boundary itself — every refuse path declares Intrinsic vs
    /// Positional, so a new arm cannot inherit "peer fault" by silence (#134's
    /// exhaustive-match discipline, applied to votes).
    #[test]
    fn every_vote_refuse_declares_whether_it_is_a_peer_fault() {
        assert!(VotesOutcome::Invalid.is_peer_fault());
        assert!(!VotesOutcome::Unjudged.is_peer_fault());
        assert!(!VotesOutcome::Stale.is_peer_fault());
        assert!(!VotesOutcome::Learned {
            finalized: false,
            accumulated: vec![]
        }
        .is_peer_fault());
    }

    // --- issue #241: the refusal reaches the journal WITH its typed reason -----
    //
    // One test per variant, and each one sources its `FinalizeMarkError` from a
    // **real store refusing for real** rather than from a hand-written literal —
    // otherwise these tests would pin the rendering against an assumption instead
    // of against the thing being rendered.
    //
    // Two of the three come out of `Node::finalize`, which is the seam the adapter
    // actually calls. The third cannot: `MemNode` applies one linear chain and so
    // never holds a side branch, which is the only way to reach
    // `NotDescendantOfFinalized`; it is sourced one layer down, at `ChainStore`,
    // where a side branch does exist. That asymmetry is real and is why this is
    // three tests and not one loop.

    /// The `t0-wan-9` checkpoint, so every rendering below is checked against the
    /// exact line shape `#229` recorded: `h=2984 cp=4f2932d6`.
    const T0_WAN_9_HEIGHT: u64 = 2984;
    fn t0_wan_9_block() -> Hash32 {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&[0x4f, 0x29, 0x32, 0xd6]);
        h
    }

    /// The whole journal line the operator sees for a refusal carrying `reason`.
    fn journalled_line(reason: FinalizeRefusalReason) -> String {
        let (mut a, _) = adapter_with_finalized_genesis();
        a.note_finalize_refused("state", T0_WAN_9_HEIGHT, t0_wan_9_block(), reason);
        let journal = a.drain_finalize_refusals();
        assert_eq!(journal.len(), 1, "one refusal, journalled once");
        assert_eq!(journal[0].why, reason, "the journal holds the typed reason");
        let line = journal[0].to_string();
        assert!(
            line.starts_with("FINALIZE refused head=state h=2984 cp=4f2932d6 why="),
            "the #229 line shape, unchanged apart from the token: {line}"
        );
        line
    }

    /// 🔴 **`FinalizeMarkError::Unknown` reaches the journal as `why=not-held`** —
    /// and this is the `t0-wan-9` line, rendered from the refusal those hosts hit.
    ///
    /// `FINALIZE refused head=state h=2984 cp=4f2932d6 why=unknown` was the only
    /// positive emission at the instant both hosts stranded. It said the durable
    /// head does not hold block `4f2932d6`; it was read as *"the reason is
    /// unknown"*, because that is what the same word means on the `mready=unknown`
    /// line. Same refusal, same instant, same cause — a token that says which.
    #[test]
    fn a_head_that_does_not_hold_the_block_journals_not_held() {
        let (mut a, _) = adapter_with_finalized_genesis();
        // The state machine refuses a block it has never seen, in its own terms.
        let refusal = a
            .state_mut()
            .finalize([0x4f; 32])
            .expect("no persistence on an in-memory node");
        assert_eq!(
            refusal,
            FinalizeOutcome::Refused(FinalizeMarkError::Unknown),
            "the store's own verdict, not a reconstruction of it"
        );

        let reason = FinalizeRefusalReason::from(FinalizeMarkError::Unknown);
        assert_eq!(reason, FinalizeRefusalReason::NotHeld);
        assert!(
            journalled_line(reason).ends_with(" why=not-held"),
            "{}",
            journalled_line(reason)
        );
    }

    /// `FinalizeMarkError::NotAdvancing` reaches the journal as `why=not-advancing`.
    ///
    /// Sourced from `Node::finalize` re-finalizing the head it already holds — the
    /// retry shape `sync_state_finality` runs on every drain.
    #[test]
    fn a_head_asked_to_finalize_what_it_already_holds_journals_not_advancing() {
        let (mut a, _) = adapter_with_finalized_genesis();
        let g = a.chain().genesis_block_hash();
        let refusal = a.state_mut().finalize(g).expect("no persistence on an in-memory node");
        assert_eq!(
            refusal,
            FinalizeOutcome::Refused(FinalizeMarkError::NotAdvancing),
            "genesis is already this head's finalized point"
        );

        let reason = FinalizeRefusalReason::from(FinalizeMarkError::NotAdvancing);
        assert_eq!(reason, FinalizeRefusalReason::NotAdvancing);
        assert!(
            journalled_line(reason).ends_with(" why=not-advancing"),
            "{}",
            journalled_line(reason)
        );
    }

    /// `FinalizeMarkError::NotDescendantOfFinalized` reaches the journal as
    /// `why=off-finality` — the no-reorg-past-finality refusal, and the one an
    /// operator most needs told apart from the other two.
    ///
    /// Sourced at `ChainStore` because `MemNode` cannot hold the side branch this
    /// refusal requires (see `qlab_node::store`'s test module, which says the same
    /// thing from the other side).
    #[test]
    fn a_known_block_off_the_finalized_branch_journals_off_finality() {
        use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
        use qlab_node::{ChainStore as _, MemChainStore, StoredBlock};

        let child = |parent: &BlockHeader, marker: u64| {
            let body = BlockBody::from_single_payee(vec![], 0, [marker; 4]);
            let header =
                BlockHeader::child_of(parent, parent.timestamp + 75, GENESIS_DIFFICULTY, body.commitment());
            StoredBlock::from_parts(&header, &body)
        };

        let g = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = g.header();
        let mut store = MemChainStore::new(g);
        // Main chain to height 2, plus a sibling branch that reaches height 3.
        let m1 = child(&g_header, 0xA1);
        let m2 = child(&m1.header(), 0xA2);
        let m1_header = m1.header();
        store.put_block(m1).expect("main inserts");
        let m2_hash = store.put_block(m2).expect("main inserts");
        let s1 = child(&g_header, 0xB1);
        let s1_header = s1.header();
        store.put_block(s1).expect("a side branch is stored, not rejected");
        let s2 = child(&s1_header, 0xB2);
        let s2_header = s2.header();
        store.put_block(s2).expect("a side branch extends");
        let s3_hash = store.put_block(child(&s2_header, 0xB3)).expect("a side branch extends");
        assert_eq!(m1_header.height, 1, "the branches diverge at height 1");

        store.set_finalized(m2_hash).expect("finalize height 2 on the main chain");
        let refusal = store.set_finalized(s3_hash);
        assert_eq!(
            refusal,
            Err(FinalizeMarkError::NotDescendantOfFinalized),
            "height 3, known, and on the wrong branch"
        );

        let reason = FinalizeRefusalReason::from(FinalizeMarkError::NotDescendantOfFinalized);
        assert_eq!(reason, FinalizeRefusalReason::OffFinality);
        assert!(
            journalled_line(reason).ends_with(" why=off-finality"),
            "{}",
            journalled_line(reason)
        );
    }

    /// `persist` is the fourth token and it is **not** a store verdict — the store
    /// said yes and the log append failed. It has no `FinalizeMarkError` to come
    /// from, which is exactly why it must not be reachable through
    /// `From<FinalizeMarkError>`.
    #[test]
    fn a_failed_log_append_journals_persist_and_no_store_verdict_maps_to_it() {
        assert!(journalled_line(FinalizeRefusalReason::Persist).ends_with(" why=persist"));
        for e in [
            FinalizeMarkError::Unknown,
            FinalizeMarkError::NotAdvancing,
            FinalizeMarkError::NotDescendantOfFinalized,
        ] {
            assert_ne!(
                FinalizeRefusalReason::from(e),
                FinalizeRefusalReason::Persist,
                "a store refusal must never be reported as a disk failure"
            );
        }
    }

    /// 🔴 **Acceptance item 2 of #241: a refusal cannot render as a placeholder.**
    ///
    /// The load-bearing half of that guarantee is structural and is not this test:
    /// `From<FinalizeMarkError>` and `as_str` are both exhaustive `match`es with no
    /// `_ =>` arm, so a fourth `FinalizeMarkError` variant is a **compile error** in
    /// two places rather than a silent `off-finality`. What a test *can* pin is the
    /// output side — that the four tokens are distinct, non-empty, and that none of
    /// them is the word this issue exists to retire.
    // --- lab #367 / QUM-129: the PRODUCER across the stamped name boundary ---

    /// 🟢 **Producer symmetry: what this node mines above the boundary, this
    /// node (and every armed peer) accepts** — asserted end-to-end, mine →
    /// validate → apply, not by construction.
    ///
    /// PR #464 reported `mine_on_parent`'s height-blind `body.commitment()` **by
    /// inspection** and said so plainly: "if you want the producer's behaviour
    /// itself pinned, it is not pinned." This pins it. A real
    /// [`NodeAdapter`] — the producer `qumbra-node` runs — is driven from
    /// genesis to the **stamped** `NAME_RULE_BOUNDARY_HEIGHT` and across it:
    ///
    /// - the block it mines at `b + 1` commits `commitment_at(b + 1)`, the **v3**
    ///   form, not the v2 form it emitted before the fix (both asserted, so a
    ///   regression cannot pass by the two forms coinciding);
    /// - `ingest_block` — the single insert/apply path, which runs the entry rule
    ///   (`validate_body`) *and* then the `apply_state` funnel — accepts it;
    /// - the consensus tip AND the state tip both reach `b + 1`, so neither layer
    ///   is the one that refused;
    /// - production continues above the boundary (`b + 2`, `b + 3`).
    ///
    /// **The committee/finality half** the QUM-128 dispatch wanted is here too,
    /// at the scale this scaffolding supports: a real 7-member devnet committee
    /// signs a checkpoint **below** the boundary and another **above** it, both
    /// verified through the unchanged `ingest_checkpoint` quorum path, and the
    /// node's finalized height advances *across* the format change. It is one
    /// node's view of a committee, not a TCP mesh — the live multi-host crossing
    /// is T-ops's roll, and `run.rs`'s D1/D2/D3 drills own the mesh side.
    ///
    /// Cheap enough for the suite because it is the **producer** that is
    /// expensive to fake, not the PoW: `genesis_difficulty: 1` makes each mine a
    /// single hash while leaving every consensus rule (emission exactness above
    /// 8,640, payee, binding, fork choice) fully in force.
    ///
    /// Mutation checks: revert `mine_on_parent` to `body.commitment()` → the
    /// `V3_FORM` assertion fails at `b + 1` (and, if it were removed, `ingest`
    /// then rejects "bad body"); key it to `template.height` instead of the
    /// candidate's height → identical here, which is why the code asserts the
    /// two agree rather than relying on it.
    #[test]
    fn the_fixed_producer_mines_across_the_stamped_boundary_and_its_own_node_applies_it() {
        use qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT;

        let b = NAME_RULE_BOUNDARY_HEIGHT
            .expect("the boundary is stamped (lab #367 arming step 0, PR #455); with `None` this test proves nothing");
        assert!(b <= 200_000, "stamped boundary {b} is past this test's in-suite ceiling");

        let (cstate, validators) = committee7();
        // Difficulty 1: the PoW is not what is under test, the commitment form is.
        let cfg = SimConfig { genesis_difficulty: 1, ..sim() };
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, cfg);
        a.set_miner_rkm([0xA1, 0xA2, 0xA3, 0xA4]);
        let g = a.chain().genesis_block_hash();
        a.state_mut().finalize(g).expect("finalize genesis");

        // ── mine an ordinary chain up to and including the boundary block ──
        for h in 1..=b {
            let (header, body) = a.mine_block().unwrap_or_else(|| panic!("mine at {h}"));
            assert_eq!(header.height, h);
            assert_eq!(
                header.tx_body_commitment,
                body.commitment(),
                "at/below the boundary the producer commits the v2 form — the live chain is untouched"
            );
            assert_eq!(a.ingest_block(header, body), IngestOutcome::Accepted, "block {h}");
        }
        assert_eq!(a.chain().tip_height(), b);
        assert_eq!(a.state().tip_height(), b, "the state machine kept up");

        // ── finality BELOW the boundary, through the real quorum path ──
        let cp_below = Checkpoint::new(b, a.chain().tip_hash(), a.chain().tip_hash());
        let votes_below: Vec<Vote> =
            validators[..5].iter().map(|v| v.sign_checkpoint(&cp_below)).collect();
        assert_eq!(a.ingest_checkpoint(cp_below, votes_below), IngestOutcome::Accepted);
        assert_eq!(a.state().finalized_height(), Some(b), "finalized at the boundary block");

        // ── the CROSSING, produced by this node ──
        let (header, body) = a.mine_block().expect("the producer must mine above the boundary");
        assert_eq!(header.height, b + 1);
        // V3_FORM — the assertion the pre-fix producer fails.
        assert_eq!(
            header.tx_body_commitment,
            body.commitment_at(b + 1),
            "the producer must commit the form the rule requires at the candidate's height"
        );
        assert_ne!(
            header.tx_body_commitment,
            body.commitment(),
            "…and above the boundary that form is NOT the v2 one — if these coincide \
             this test cannot tell a fixed producer from the broken one"
        );
        // Entry rule AND funnel, in the one call the live node uses.
        assert_eq!(
            a.ingest_block(header, body),
            IngestOutcome::Accepted,
            "the node this block was mined by must accept it"
        );
        assert_eq!(a.chain().tip_height(), b + 1, "consensus tip crossed");
        assert_eq!(a.state().tip_height(), b + 1, "…and so did the state machine");

        // ── production continues, and finality crosses the format change ──
        for h in (b + 2)..=(b + 3) {
            let (header, body) = a.mine_block().unwrap_or_else(|| panic!("mine at {h}"));
            assert_eq!(header.tx_body_commitment, body.commitment_at(h), "v3 above the boundary");
            assert_eq!(a.ingest_block(header, body), IngestOutcome::Accepted, "block {h}");
        }
        let cp_above = Checkpoint::new(b + 3, a.chain().tip_hash(), a.chain().tip_hash());
        let votes_above: Vec<Vote> =
            validators[..5].iter().map(|v| v.sign_checkpoint(&cp_above)).collect();
        assert_eq!(a.ingest_checkpoint(cp_above, votes_above), IngestOutcome::Accepted);
        assert_eq!(
            a.state().finalized_height(),
            Some(b + 3),
            "finality advanced ACROSS the v2→v3 boundary — no halt, no re-sync"
        );
    }

    #[test]
    fn no_refusal_token_is_a_placeholder_and_none_of_them_collide() {
        let all = [
            FinalizeRefusalReason::NotHeld,
            FinalizeRefusalReason::NotAdvancing,
            FinalizeRefusalReason::OffFinality,
            FinalizeRefusalReason::Persist,
        ];
        let tokens: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(tokens, ["not-held", "not-advancing", "off-finality", "persist"]);
        for (i, t) in tokens.iter().enumerate() {
            assert!(!t.is_empty(), "an empty token is a placeholder with extra steps");
            assert_ne!(
                *t, "unknown",
                "`unknown` is what `mready=`/`MineGate::Unknown` say when the answer \
                 is NOT known — a refusal that knows its reason must not share the word"
            );
            assert!(!t.contains(' '), "the journal line is space-delimited");
            for (j, u) in tokens.iter().enumerate() {
                assert!(i == j || t != u, "two reasons rendering the same token: {t}");
            }
            // `Display` and `as_str` are the same string, so a caller cannot pick a
            // different rendering by accident.
            assert_eq!(all[i].to_string(), *t);
        }
    }
    // ── lab #470 stage 4a: a v5 net, in memory, end to end ──────────────────

    /// Two v5 adapters: one mines, the other ingests — the whole threaded
    /// identity stack (v5 chain identities, v5 header PoW, v5 body binding,
    /// v5 template minting the exact schedule, v5 funnel validation) in one
    /// test. Also exercises the fresh-rekey seam (`set_chain_rules` on
    /// untouched adapters re-keys chain AND state, the extended invariant).
    #[test]
    fn a_v5_net_mines_and_relays_in_memory() {
        use qlab_devnet::forms::{ChainRules, GenesisForm};
        let v5 = ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 };
        let mk = || {
            let (cstate, _v) = committee7();
            let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
            a.set_chain_rules(v5);
            a.set_miner_rkm([7, 7, 7, 7]);
            a
        };
        let mut miner = mk();
        let mut peer = mk();
        assert_eq!(miner.chain_rules().form, GenesisForm::V5);
        assert_eq!(miner.state.form(), GenesisForm::V5, "the state node was re-keyed too");

        let (header, body) = miner.mine_block().expect("v5 mining succeeds");
        assert_eq!(
            body.coinbase_total(),
            qlab_devnet::emission_exact::coinbase_exact(1),
            "a v5 template mints the exact schedule natively"
        );
        assert_eq!(
            header.tx_body_commitment,
            body.commitment_v5(),
            "a v5 template binds the v5 body form"
        );
        let id = header.header_hash_for(GenesisForm::V5);
        assert!(matches!(
            miner.ingest_block(header, body.clone()),
            IngestOutcome::Accepted
        ));
        assert!(matches!(peer.ingest_block(header, body), IngestOutcome::Accepted));
        assert_eq!(peer.chain().tip_hash(), id, "the peer adopted the v5 identity");
        assert_eq!(peer.chain().tip_hash(), miner.chain().tip_hash());
        assert_eq!(peer.chain().tip_height(), 1);
    }

    /// Lab #624 / #629 fixture: a v5 node has applied a COMMIT and the aging
    /// blocks, admitted a burn-bearing REVEAL, and mined a candidate that
    /// includes it. The candidate has not been ingested.
    struct PooledRevealCandidate {
        node: NodeAdapter<KeccakPow, MockVerifier>,
        history: Vec<(BlockHeader, BlockBody)>,
        reveal_header: BlockHeader,
        reveal_body: BlockBody,
        reveal_id: TxId,
        reveal_wire_id: Hash32,
        name: Vec<u8>,
        name_fee: u64,
    }

    fn t2rollcheck_ops(anchor: Hash32) -> (TxEntry, TxEntry, Vec<u8>, u64) {
        use qlab_devnet::names::{
            commit_hash, name_fee_bessel, NameOp, NameRecord, L1_ADDRESS_LEN,
            RECORD_KIND_L1_ADDRESS,
        };

        // Eleven bytes matches the live `t2rollcheck` fee tier: 1 QMB burned,
        // or 100_000_000 bessel, on top of the 0.01 QMB relay fee.
        let name = b"t2rollcheck".to_vec();
        let salt = [0x62; 32];
        let record = NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: name.clone(),
            address: vec![0xA5; L1_ADDRESS_LEN],
        };
        let name_fee = name_fee_bessel(name.len());
        assert_eq!(name_fee, 100_000_000, "the fixture is the live reveal's burn tier");
        let commit = tx_with(anchor, 0x61, b"ok")
            .with_name_op(&NameOp::Commit { commit: commit_hash(&record, &salt) });
        let mut reveal = tx_with(anchor, 0x63, b"ok")
            .with_name_op(&NameOp::Reveal { record, salt });
        reveal.public.fee = posted_fee(ArityBucket::TwoByTwo) + name_fee;
        (commit, reveal, name, name_fee)
    }

    fn v5_pooled_burn_bearing_reveal() -> PooledRevealCandidate {
        use qlab_devnet::names::COMMIT_MIN_AGE;

        let (mut node, anchor) =
            adapter_for_form_with_finalized_genesis(GenesisForm::V5);
        node.set_miner_rkm([0x624, 2, 3, 4]);
        let (commit, reveal, name, name_fee) = t2rollcheck_ops(anchor);
        let reveal_wire_id = wire_tx_id(&reveal);

        node.submit_tx_typed(commit).expect("the v5 production path admits the commit");
        let (commit_header, commit_body) = node.mine_block().expect("mine the commit block");
        assert_eq!(commit_header.height, 1);
        assert_eq!(commit_body.txs.len(), 1, "the commit is on chain, not seeded by hand");
        assert_eq!(commit_body.total_name_burn(), 0, "a commit pays relay only");
        assert_eq!(
            node.ingest_block(commit_header, commit_body.clone()),
            IngestOutcome::Accepted
        );
        assert_eq!(node.state().tip_height(), 1, "the commit block applied");
        let mut history = vec![(commit_header, commit_body)];

        // Commit at height 1, reveal candidate at height 1 + COMMIT_MIN_AGE.
        // The seven intervening blocks are mined and applied through the same
        // path, so the registry and tip view admission reads are production state.
        for height in 2..=COMMIT_MIN_AGE {
            let (header, body) = node.mine_block().expect("mine the commit-aging block");
            assert_eq!(header.height, height);
            assert!(body.txs.is_empty());
            assert_eq!(node.ingest_block(header, body.clone()), IngestOutcome::Accepted);
            assert_eq!(node.state().tip_height(), height);
            history.push((header, body));
        }

        let reveal_id = node
            .submit_tx_typed(reveal)
            .expect("production admit_above(form.rider_admit_boundary(), ...) admits the reveal");
        assert!(node.mempool().contains(&reveal_id), "the reveal is pooled before mining");

        let (reveal_header, reveal_body) =
            node.mine_block().expect("the node's own mining path assembles");
        assert_eq!(reveal_header.height, 1 + COMMIT_MIN_AGE);
        assert_eq!(
            reveal_body.txs.len(),
            1,
            "the reveal is included, not silently omitted"
        );
        assert_eq!(
            wire_tx_id(&reveal_body.txs[0]),
            reveal_wire_id,
            "the included tx is the reveal"
        );
        assert_eq!(
            reveal_body.total_name_burn(),
            name_fee,
            "the included block carries the real burn"
        );
        assert_eq!(
            reveal_body.total_fees(),
            posted_fee(ArityBucket::TwoByTwo) + name_fee,
            "relay plus burn is the declared fee"
        );

        PooledRevealCandidate {
            node,
            history,
            reveal_header,
            reveal_body,
            reveal_id,
            reveal_wire_id,
            name,
            name_fee,
        }
    }

    fn v5_follower_with_headers_only(
        blocks: &[(BlockHeader, BlockBody)],
    ) -> NodeAdapter<KeccakPow, MockVerifier> {
        let (cstate, _v) = committee7();
        let mut f = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        f.set_chain_rules(ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 });
        for (h, _) in blocks {
            assert_eq!(f.ingest_header(*h), IngestOutcome::Accepted);
        }
        assert_eq!(f.chain().tip_height(), blocks.len() as u64);
        assert_eq!(f.state().tip_height(), 0, "no body has been applied");
        f
    }

    /// Lab #624: a v5 node holding a valid pending reveal assembles it and
    /// **ingests its own candidate**. On `main` at `3b778c5` this fails with
    /// `Rejected("bad body")` because ingest validated under `EmptyNameView`.
    ///
    /// Mutation: revert the v5 arm of `ingest_block` to `EmptyNameView` → the
    /// `Accepted` assertion fails with that same `Rejected("bad body")`.
    #[test]
    fn a_v5_burn_bearing_name_reveal_is_admitted_assembled_and_ingested() {
        use qlab_devnet::names::COMMIT_MIN_AGE;

        let mut fx = v5_pooled_burn_bearing_reveal();
        let header = fx.reveal_header;
        let body = fx.reveal_body.clone();

        // Pin the exact predicate EmptyNameView still produces, so a future
        // reader cannot mistake "ingest now succeeds" for "the empty view grew
        // a registry". The disagreement is the view, not the rider rule.
        let empty_view_refusal = qlab_devnet::body::validate_body_v5(
            &header,
            &body,
            &fx.node.verifier,
            |root| fx.node.state.is_valid_anchor(root),
            &qlab_devnet::names::EmptyNameView,
        );
        assert_eq!(
            empty_view_refusal,
            Err(qlab_devnet::body::BodyError::RiderRule {
                index: 0,
                err: qlab_devnet::names::NameRuleError::CommitNotFound,
            }),
            "EmptyNameView still cannot see the mined commit"
        );
        assert_eq!(
            qlab_devnet::body::validate_body_v5(
                &header,
                &body,
                &fx.node.verifier,
                |root| fx.node.state.is_valid_anchor(root),
                fx.node.state.names(),
            ),
            Ok(()),
            "the node's real registry makes the identical block valid"
        );

        // Burn remains a correlate, not the trigger: forcing the burn input
        // to zero raises the derived miner note by exactly the name fee.
        let burned_value = qlab_node::coinbase_note_value_parts(
            body.coinbase_total(),
            body.total_fees(),
            body.total_name_burn(),
        );
        let forced_zero_value =
            qlab_node::coinbase_note_value_parts(body.coinbase_total(), body.total_fees(), 0);
        assert_eq!(forced_zero_value - burned_value, fx.name_fee);

        // Second attempt before ingest: assemble is deterministic and a
        // refused (or uningested) candidate evicts nothing, so the next mine
        // reselects the same reveal — "no blocks, not empty blocks".
        let (retry_header, retry_body) = fx.node.mine_block().expect("second mine at the same height");
        assert_eq!(retry_header.height, header.height);
        assert_eq!(
            retry_body.txs.len(),
            1,
            "without ingest, assemble reselects the same reveal"
        );
        assert_eq!(wire_tx_id(&retry_body.txs[0]), fx.reveal_wire_id);

        assert_eq!(
            fx.node.ingest_block(header, body),
            IngestOutcome::Accepted,
            "self-ingest of the assembled reveal must succeed"
        );
        assert_eq!(fx.node.state().tip_height(), COMMIT_MIN_AGE + 1);
        assert!(
            fx.node.state().names().entry(&fx.name).is_some(),
            "the reveal applied; the name is registered"
        );
        assert!(
            !fx.node.mempool().contains(&fx.reveal_id),
            "a connected reveal is dropped from the pool"
        );

        let (next_header, next_body) = fx.node.mine_block().expect("the node keeps mining");
        assert_eq!(next_header.height, COMMIT_MIN_AGE + 2);
        assert!(
            next_body.txs.is_empty(),
            "the reveal was consumed; the next block is not a stuck retry of it"
        );
        assert_eq!(
            fx.node.ingest_block(next_header, next_body),
            IngestOutcome::Accepted
        );
    }

    /// Lab #624: a node whose applied state is behind still produces
    /// `Positional` for `CommitNotFound` and does not charge the sender —
    /// neither on the unjudged-anchor path nor on the settled-history amnesty.
    ///
    /// Mutation: classify `CommitNotFound` as intrinsic, or charge every
    /// positional rider verdict — both arms below fail `is_peer_fault`.
    /// Reverting ingest to `EmptyNameView` does **not** fail this test: the
    /// empty view also yields `CommitNotFound`. That is the amnesty invariant,
    /// not the inclusion fix.
    #[test]
    fn a_lagging_node_does_not_charge_commit_not_found() {
        type A = NodeAdapter<KeccakPow, MockVerifier>;
        assert!(
            matches!(
                A::body_fault_class(&BodyError::RiderRule {
                    index: 0,
                    err: qlab_devnet::names::NameRuleError::CommitNotFound,
                }),
                BodyFault::Positional("bad body")
            ),
            "CommitNotFound stays positional so a lagging registry is not a peer fault"
        );

        let fx = v5_pooled_burn_bearing_reveal();
        let mut announced = fx.history.clone();
        announced.push((fx.reveal_header, fx.reveal_body.clone()));

        // (1) Joiner: headers only, nothing finalized past genesis on this
        // node (it never finalized genesis). Unjudged positional path.
        let mut joiner = v5_follower_with_headers_only(&announced);
        assert_eq!(joiner.state().finalized_height(), None);
        assert!(!joiner.anchor_verdict_is_authoritative(&fx.reveal_header));
        assert!(!joiner.block_is_settled_history(&fx.reveal_header));
        let joiner_out = joiner.ingest_block(fx.reveal_header, fx.reveal_body.clone());
        assert_eq!(joiner_out, IngestOutcome::Ignored(UNJUDGED_ANCHOR_REASON));
        assert!(
            !joiner_out.is_peer_fault(),
            "a lagging joiner must not charge the sender of a reveal it cannot yet see"
        );
        assert_eq!(joiner.state().tip_height(), 0, "unjudged is not accepting");

        // (2) Settled-history amnesty: the same headers, but the reveal height
        // is committee-finalized on the joiner's fork-choice chain. The
        // positional `{}` arm must still not charge.
        let mut settled = v5_follower_with_headers_only(&announced);
        let (_cstate, validators) = committee7();
        let tip = settled.chain().tip_hash();
        let cp = Checkpoint::new(fx.reveal_header.height, tip, tip);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(settled.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        assert!(
            settled.block_is_settled_history(&fx.reveal_header),
            "the reveal header is settled history on this node"
        );
        let settled_out = settled.ingest_block(fx.reveal_header, fx.reveal_body);
        assert!(
            !settled_out.is_peer_fault(),
            "settled-history amnesty must still excuse CommitNotFound"
        );
        assert_ne!(settled_out, IngestOutcome::Rejected("bad body"));
        assert_eq!(
            settled.state().tip_height(),
            0,
            "amnesty is not applying a body whose parent is unapplied"
        );
    }

    /// Lab #624 v4 arm: T1 crossed `NAME_RULE_BOUNDARY_HEIGHT = 19_008` on
    /// 2026-08-21. The identical EmptyNameView exclusion is latent there.
    /// Cheap enough for the suite because `genesis_difficulty: 1` makes each
    /// mine a single hash (same ceiling as the producer-across-boundary test).
    ///
    /// Mutation: revert the v4 arm of `ingest_block` to `validate_body`
    /// (`EmptyNameView`) → `Accepted` fails with `Rejected("bad body")`.
    #[test]
    fn a_v4_burn_bearing_name_reveal_is_ingested_above_the_stamped_boundary() {
        use qlab_devnet::names::{COMMIT_MIN_AGE, NAME_RULE_BOUNDARY_HEIGHT};

        let b = NAME_RULE_BOUNDARY_HEIGHT
            .expect("the boundary is stamped; with None this test proves nothing");
        assert!(b <= 200_000, "stamped boundary {b} is past this test's in-suite ceiling");

        let (cstate, validators) = committee7();
        let cfg = SimConfig { genesis_difficulty: 1, ..sim() };
        let mut node = NodeAdapter::new(cstate, KeccakPow, MockVerifier, cfg);
        node.set_miner_rkm([0x624, 0x04, 0, 0]);
        let g = node.chain().genesis_block_hash();
        node.state_mut().finalize(g).expect("finalize genesis");

        for h in 1..=b {
            let (header, body) = node.mine_block().unwrap_or_else(|| panic!("mine at {h}"));
            assert_eq!(node.ingest_block(header, body), IngestOutcome::Accepted, "block {h}");
        }
        let cp = Checkpoint::new(b, node.chain().tip_hash(), node.chain().tip_hash());
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(node.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        assert_eq!(node.state().finalized_height(), Some(b));

        // Genesis is long outside MAX_ANCHOR_AGE_BLOCKS. Anchor the name txs
        // at the just-finalized boundary root.
        let anchor = node.state().commitment_root();
        let (commit, reveal, name, name_fee) = t2rollcheck_ops(anchor);
        let reveal_wire_id = wire_tx_id(&reveal);

        node.submit_tx_typed(commit).expect("v4 admits a commit above the boundary");
        let (commit_header, commit_body) = node.mine_block().expect("mine the v4 commit");
        assert_eq!(commit_header.height, b + 1);
        assert_eq!(commit_body.txs.len(), 1);
        assert_eq!(
            node.ingest_block(commit_header, commit_body),
            IngestOutcome::Accepted
        );

        for height in (b + 2)..=(b + COMMIT_MIN_AGE) {
            let (header, body) = node.mine_block().unwrap_or_else(|| panic!("mine at {height}"));
            assert!(body.txs.is_empty());
            assert_eq!(node.ingest_block(header, body), IngestOutcome::Accepted);
        }

        let reveal_id = node.submit_tx_typed(reveal).expect("v4 admits the reveal");
        let (header, body) = node.mine_block().expect("v4 assembles the reveal");
        assert_eq!(header.height, b + 1 + COMMIT_MIN_AGE);
        assert_eq!(body.txs.len(), 1, "the v4 assembler includes the reveal");
        assert_eq!(wire_tx_id(&body.txs[0]), reveal_wire_id);
        assert_eq!(body.total_name_burn(), name_fee);

        let empty_view_refusal = qlab_devnet::body::validate_body_with_names(
            &header,
            &body,
            &node.verifier,
            |root| node.state.is_valid_anchor(root),
            &qlab_devnet::names::EmptyNameView,
        );
        assert_eq!(
            empty_view_refusal,
            Err(qlab_devnet::body::BodyError::RiderRule {
                index: 0,
                err: qlab_devnet::names::NameRuleError::CommitNotFound,
            }),
            "v4 EmptyNameView still cannot see the mined commit"
        );
        assert_eq!(
            qlab_devnet::body::validate_body_with_names(
                &header,
                &body,
                &node.verifier,
                |root| node.state.is_valid_anchor(root),
                node.state.names(),
            ),
            Ok(())
        );

        let (retry_header, retry_body) = node.mine_block().expect("second v4 mine at the same height");
        assert_eq!(retry_header.height, header.height);
        assert_eq!(retry_body.txs.len(), 1, "without ingest, v4 reselects the same reveal");

        assert_eq!(
            node.ingest_block(header, body),
            IngestOutcome::Accepted,
            "v4 self-ingest of the assembled reveal must succeed"
        );
        assert!(node.state().names().entry(&name).is_some());
        assert!(!node.mempool().contains(&reveal_id));

        let (next_header, next_body) = node.mine_block().expect("v4 keeps mining");
        assert!(next_body.txs.is_empty());
        assert_eq!(node.ingest_block(next_header, next_body), IngestOutcome::Accepted);
    }

    /// Lab #612: admission and eviction must ask the rider question under the
    /// same installed form. A v5 name COMMIT is valid natively from height 1;
    /// connecting an unrelated empty v5 block must not make the pool re-ask it
    /// under v4's height-19,008 boundary and silently delete it.
    ///
    /// This is the production path in both halves: `submit_tx_typed` admits the
    /// transaction, then `ingest_block` applies the unrelated block and reaches
    /// the adapter's post-connect mempool reconciliation. On `96f04fe` the last
    /// assertion fails because that reconciliation calls the v4-hardcoded
    /// `Mempool::on_block_connected`.
    #[test]
    fn a_v5_name_rider_survives_an_unrelated_connected_block() {
        use qlab_devnet::names::NameOp;

        let (mut peer, anchor) =
            adapter_for_form_with_finalized_genesis(GenesisForm::V5);
        let (mut producer, _) =
            adapter_for_form_with_finalized_genesis(GenesisForm::V5);

        let commit = tx_with(anchor, 0x51, b"ok")
            .with_name_op(&NameOp::Commit { commit: [0xA6; 32] });
        let id = peer.submit_tx_typed(commit).expect("v5 admits its native name rider");
        assert!(peer.mempool().contains(&id));

        let (header, body) = producer.mine_block().expect("mine an unrelated v5 block");
        assert!(body.txs.is_empty(), "the connected block does not mine the pooled commit");
        assert_eq!(peer.ingest_block(header, body), IngestOutcome::Accepted);

        assert!(
            peer.mempool().contains(&id),
            "an unrelated v5 block must not evict a still-valid v5 name rider"
        );

        // The opposite mutation: a rider that somehow exists in a v4 pool below
        // height 19,008 MUST be evicted. Seed it through the explicit boundary
        // seam because ordinary v4 admission correctly refuses it. If the
        // production call above is hardcoded to v5's Some(0), this half fails.
        let (mut v4, v4_anchor) =
            adapter_for_form_with_finalized_genesis(GenesisForm::V4);
        let (mut v4_producer, _) =
            adapter_for_form_with_finalized_genesis(GenesisForm::V4);
        let v4_commit = tx_with(v4_anchor, 0x52, b"ok")
            .with_name_op(&NameOp::Commit { commit: [0xA7; 32] });
        let v4_id = v4
            .mempool
            .admit_above(
                GenesisForm::V5.rider_admit_boundary(),
                v4_commit,
                &v4.state,
                &v4.verifier,
                v4.state.names(),
            )
            .expect("explicit v5 boundary seeds the v4 mutation fixture");
        let (v4_header, v4_body) =
            v4_producer.mine_block().expect("mine an unrelated v4 block");
        assert!(v4_body.txs.is_empty());
        assert_eq!(v4.ingest_block(v4_header, v4_body), IngestOutcome::Accepted);
        assert!(
            !v4.mempool().contains(&v4_id),
            "v4 eviction must still enforce the v4 boundary"
        );
    }

    /// Lab #553 acceptance: parameterising the RPC assembly path must not move
    /// one byte of the node's own mining candidate.
    #[test]
    fn own_mining_candidate_is_byte_identical_to_its_parameterised_sibling() {
        use qlab_devnet::forms::{ChainRules, GenesisForm};
        let payout = [0xA1, 0xA2, 0xA3, 0xA4];
        let mk = || {
            let (cstate, _v) = committee7();
            let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
            a.set_chain_rules(ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 });
            a.set_miner_rkm(payout);
            a
        };
        let mut native_node = mk();
        let mut requested_node = mk();
        let native = native_node.assemble_block().expect("native candidate");
        let requested = requested_node
            .assemble_block_for_payees(&native.body.coinbase_payees)
            .expect("valid requested payee list")
            .expect("requested candidate");
        assert_eq!(requested.form, native.form);
        assert_eq!(requested.header, native.header);
        assert_eq!(requested.seed_hash, native.seed_hash);
        assert_eq!(requested.next_seed_hash, native.next_seed_hash);
        assert_eq!(requested.body.coinbase_payees, native.body.coinbase_payees);
        assert_eq!(requested.body.txs.len(), native.body.txs.len());
        assert_eq!(requested.body.commitment_v5(), native.body.commitment_v5());
    }

    /// The extended install-before-run invariant: re-keying an adapter whose
    /// chain already carries a block panics — replayed/advanced state must be
    /// OPENED under its form, never re-keyed.
    #[test]
    #[should_panic(expected = "rekey_genesis is only legal")]
    fn set_chain_rules_refuses_a_rekey_after_the_first_block() {
        use qlab_devnet::forms::{ChainRules, GenesisForm};
        let (cstate, _v) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        a.set_miner_rkm([7, 7, 7, 7]);
        let (header, body) = a.mine_block().expect("v4 mining succeeds");
        assert!(matches!(a.ingest_block(header, body), IngestOutcome::Accepted));
        a.set_chain_rules(ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 });
    }

}
