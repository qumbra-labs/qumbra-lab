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

use qlab_devnet::body::{validate_body, BlockBody, BodyError, TxEntry};
use qlab_devnet::chain::{ChainState, InsertError};
use qlab_devnet::committee::{Checkpoint, CommitteeState, MemberStatus, Validator, Vote};
use qlab_devnet::ebbflow::{
    finality_status, verify_equivocation, EquivocationEvidence, FinalityStatus, SigningWindow,
};
use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
use qlab_devnet::finality::{FinalityTracker, FinalizeError};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::tally::VoteTally;
use qlab_pow::keyblock::KeyBlockSchedule;
use qlab_devnet::mining::mine_under;
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{
    DEGRADED_MODE_LAG_BLOCKS, DOWNTIME_JAIL_THRESHOLD_PCT, DOWNTIME_JAIL_WINDOW,
    EPOCH_LENGTH_BLOCKS, JAIL_BLOCKS,
};
use qlab_devnet::pow::PowEngine;
use qlab_devnet::halt::{regime as halt_regime, RuleSchedule};
use qlab_devnet::validation::{
    expected_difficulty, pow_seed, validate_header_under, ValidationError,
};

use qlab_node::mempool::TxId;
use qlab_node::metrics::Metrics;
use qlab_node::recovery::Finalizer;
use qlab_node::round::{ObsClock, RoundLedger, SlotContext, VoteRejects};
use qlab_node::telemetry::StateLag;
use qlab_node::{genesis_block, MemNode, Mempool, MempoolError, NodeError, NodeState as _};
use qlab_devnet::body::TxVerifier;

use crate::codec::{checkpoint_id, tx_id as wire_tx_id};
use crate::n1::{
    BlockIngest, ChainView, CheckpointIngest, CommitteeControl, IngestOutcome, TxPool, VotesOutcome,
};

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
    /// Mining nonce budget per block.
    nonce_budget: u64,
    /// Monotone mining clock (sim seconds) — used only by [`MiningClock::Deterministic`].
    clock: u64,
    /// How a mined block's header timestamp is chosen (item 0). Defaults to
    /// [`MiningClock::Deterministic`]; the binary opts into [`MiningClock::WallClock`].
    mining_clock: MiningClock,
    /// The running release's halt/rule schedule (issue #74). Defaults to
    /// [`RuleSchedule::V1_0`] — no halt, no post-halt rule domain — so every
    /// in-process sim, soak and test behaves exactly as before. The binary installs
    /// its compile-time release schedule once at startup via
    /// [`Self::set_rule_schedule`]; there is no config/CLI/env path to it (H1).
    rules: RuleSchedule,
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
}

/// How far above the state machine's applied tip a body is worth holding
/// (issue #130 (a)). Bitcoin's in-flight download window, reused as the shape rather
/// than the number: past this, a body cannot become applicable without material this
/// node has no way to request.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_PENDING_BODY_HEIGHTS: u64 = 1024;

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

/// The memory a held body actually costs: the proof bytes (which dominate — one 2×2
/// proof is ~145 kB against a ~100-byte public surface) plus its declared surface.
fn body_weight(body: &BlockBody) -> usize {
    let txs: usize = body
        .txs
        .iter()
        .map(|tx| {
            tx.proof.len()
                + 32 * (1 + tx.public.nullifiers.len() + tx.public.commitments.len())
                + 16
        })
        .sum();
    txs + 40 // coinbase counter + payout key + map overhead
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
        Self::assemble(committee, pow, verifier, sim, state)
    }

    /// New **disk-backed** adapter (M10-T0-1, `qumbra-node` binary): the state
    /// machine is opened at `dir` and resumes restart-safely (atomic snapshot +
    /// block-log tail), so accepted blocks and finalizations persist across
    /// restarts. Wraps `committee` at the frozen epoch length (like [`Self::new`]).
    /// [`Self::save_snapshot`] flushes the derived state on graceful shutdown.
    pub fn open(
        dir: impl AsRef<std::path::Path>,
        committee: CommitteeState,
        pow: P,
        verifier: V,
        sim: SimConfig,
    ) -> Result<Self, NodeError> {
        let ec = EpochCommittee::genesis(EpochSchedule::new(EPOCH_LENGTH_BLOCKS), committee);
        let state = MemNode::open(dir, genesis_block(sim.genesis_difficulty, 0))?;
        let mut me = Self::assemble(ec, pow, verifier, sim, state);
        // Restart-resume the in-memory fork-choice header chain from the persisted
        // block log: the state machine is the durable source of truth, so on open
        // the adapter adopts its restored ChainState (headers + finalized head),
        // trusting the log exactly as `MemNode::replay` does (no PoW re-run).
        // Otherwise a restarted node would start with an empty header view and have
        // to re-sync everything it already had on disk.
        let resumed = me.state.chain().chain().clone();
        me.chain = resumed;
        me.advance_epoch();
        Ok(me)
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
        committee: EpochCommittee,
        pow: P,
        verifier: V,
        sim: SimConfig,
        state: MemNode,
    ) -> Self {
        let genesis = BlockHeader::genesis(sim.genesis_difficulty, 0);
        NodeAdapter {
            chain: ChainState::new(genesis),
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
            clock: 0,
            mining_clock: MiningClock::default(),
            rules: RuleSchedule::V1_0,
            ingest_counters: IngestCounters::default(),
            rounds: RoundLedger::default(),
            metrics: Metrics::new(),
            miner_rkm: UNCONFIGURED_MINER_RKM,
            pending_bodies: BTreeMap::new(),
            pending_bytes: 0,
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
        self.rules = rules;
    }

    /// The installed rule schedule.
    pub fn rules(&self) -> &RuleSchedule {
        &self.rules
    }

    /// Layer-attributed ingest refusal counts (issue #74 drill evidence).
    pub fn ingest_counters(&self) -> IngestCounters {
        self.ingest_counters
    }

    /// The height this node halts at, if its release carries one.
    pub fn halt_at(&self) -> Option<u64> {
        self.rules.halt_at()
    }

    /// Whether this node is at or past its halt height — i.e. whether the halt has
    /// actually engaged, as opposed to merely being scheduled. The run loop uses
    /// this to write the durable halt marker.
    pub fn is_halted_at_tip(&self) -> bool {
        self.rules.halt_at().is_some_and(|h| self.chain.tip_height() >= h)
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

    /// Record a refused duty (issue #130 (a) part 3).
    fn refuse_for_lag(&mut self, duty: &'static str) {
        self.metrics.observe_lag_refusal(duty);
    }

    /// Hold a body whose header this node already has, for application when the
    /// state tip reaches its parent.
    ///
    /// Refused, silently and correctly, for anything that cannot become applicable:
    /// a height at or below the applied tip (already folded in, or on a branch this
    /// state machine will never rewind to), and a height beyond
    /// [`MAX_PENDING_BODY_HEIGHTS`]. Over either cap, the **highest** held entry is
    /// dropped: the lowest heights are the ones that close the gap, so the entry
    /// furthest from applicable is the one worth least.
    fn buffer_body(&mut self, header: BlockHeader, body: BlockBody) {
        let state_tip = self.state.tip_height();
        if header.height <= state_tip || header.height > state_tip + MAX_PENDING_BODY_HEIGHTS {
            return;
        }
        let key = (header.height, header.header_hash());
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

    /// Apply every held body that has become applicable, **in ascending height
    /// order**, until none extends the state tip.
    ///
    /// Ascending is the whole mechanism: the state machine applies at its tip only,
    /// so a held span empties from the bottom as the tip advances — which is why one
    /// arriving body can close a gap of many, and why the old "apply what this one
    /// announcement carried" shape could never catch up.
    fn drain_pending_bodies(&mut self) {
        while let Some(key) = self.next_applicable_body() {
            let (header, body) = self.pending_bodies.remove(&key).expect("just located");
            self.pending_bytes = self.pending_bytes.saturating_sub(body_weight(&body));
            // `apply_block` is the authoritative gate and it re-validates the body
            // against the tree it is actually being applied to — so nothing is ever
            // folded in on the strength of an anchor answer computed from a stale
            // tree. It also persists: the log append is inside it, which is what
            // makes a buffered-then-applied body durable (issue #104).
            match self.state.apply_block(header, body.clone(), &self.verifier) {
                Ok(_) => {
                    self.mempool.on_block_connected(&body, &self.state);
                }
                // GUARANTEED HERE, and this is not the old "expected" annotation: a
                // body that fails at the funnel has mutated nothing (`apply_state`
                // validates before it writes), and no peer is charged for it — the
                // sender was judged once, on arrival, and this path holds no sender
                // to charge a second time. What such a failure costs is visibility,
                // and it has it: the body is dropped, the lag stays nonzero, and the
                // duty gate below keeps refusing until it is not.
                Err(_) => {}
            }
        }
        // The finalized head is part of the view that has to catch up, not a separate
        // concern — see `sync_state_finality`.
        self.sync_state_finality();
        // Anything no longer reachable from the applied tip is dead weight.
        let state_tip = self.state.tip_height();
        self.pending_bodies.retain(|(height, _), body| {
            let keep = *height > state_tip && *height <= state_tip + MAX_PENDING_BODY_HEIGHTS;
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
        let _ = self.state.finalize(cp.block_hash);
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

    /// Map a header-insert result to an [`IngestOutcome`], advancing the epoch on
    /// acceptance.
    fn submit_header(&mut self, header: BlockHeader) -> IngestOutcome {
        // HALT (issue #74, H2). An armed node applies block H and accepts nothing
        // above it. This is a property of the running RELEASE, not of the chain, so
        // it is enforced here rather than inside `validate_header` — and the peer is
        // NOT penalised: a node still on the old binary offering post-H blocks is on
        // a different release, not misbehaving (the S5 discipline from #70).
        if !self.rules.accepts_height(header.height) {
            self.ingest_counters.halt_ignored += 1;
            return IngestOutcome::Ignored("above halt height");
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
        // Chain-time gap to the parent, captured BEFORE the insert while the parent
        // is unambiguous (issue #87). Observed only when this header becomes the tip,
        // so the histogram describes the main chain the issue measured, not every
        // side branch that was ever offered.
        let parent_ts = self.chain.header(&header.prev).map(|p| p.timestamp);
        let header_hash = header.header_hash();
        let header_ts = header.timestamp;
        match self.chain.insert_header(header) {
            Ok(_) => {
                self.advance_epoch();
                if self.chain.tip_hash() == header_hash {
                    // A parent timestamp of 0 is the GENESIS PLACEHOLDER, not a time.
                    // Differencing against it yields the whole Unix epoch (~1.78e9 s)
                    // and poisons the histogram's sum and tail with one sample. The
                    // genesis→first-block gap is not an interval; it is skipped, and
                    // the guard is on the placeholder value rather than on the height
                    // so a genesis that ever carries a real timestamp contributes
                    // normally. (Same root cause as issue #73's `age_s`.)
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

    /// Assemble + mine (but do NOT insert) the next block over the current tip.
    /// Returns `(mined_header, body)`; the caller ingests it via `announce_block`
    /// → `ingest_block`, which is the single insert/apply path. `None` if there is
    /// no known parent or the nonce budget is exhausted.
    pub fn mine_block(&mut self) -> Option<(BlockHeader, BlockBody)> {
        // HALT (H2): an upgraded node stops mining above H. Un-upgraded miners will
        // not, and that is fine — §4's hybrid honesty note; the committee, not miner
        // unanimity, is what makes the upgrade clean.
        if !self.rules.accepts_height(self.chain.tip_height() + 1) {
            return None;
        }
        // STATE LAG (issue #130 (a), part 3 — the first of the three refusals).
        //
        // The parent comes from FORK CHOICE and the body is assembled from STATE. When
        // those disagree, the block this would produce is a valid child of the
        // fork-choice tip that the node's own state machine then refuses, so its
        // coinbase note never gets a commitment-tree leaf and the coins are gone with
        // no error raised anywhere. A node that cannot record its own block does not
        // mine one — Ethereum's optimistic-sync rule ("an optimistic validator MUST
        // NOT produce a block"), and the reason this is a refusal rather than a
        // best-effort attempt.
        if self.state_lag().is_lagging() {
            self.refuse_for_lag("mine");
            return None;
        }
        let template =
            self.mempool.assemble(&self.state, SOAK_EFFECTIVE_MEDIAN, self.miner_rkm);
        let body = template.body;
        let bc = body.commitment();
        let parent_hash = self.chain.tip_hash();
        let parent = *self.chain.header(&parent_hash)?;
        let difficulty = expected_difficulty(&self.chain, &parent_hash, self.block_time)?;
        let timestamp = self.next_timestamp(&parent);
        let candidate = BlockHeader::child_of(&parent, timestamp, difficulty, bc);
        let seed = pow_seed(&self.chain, &parent_hash, candidate.height, self.schedule)?;
        let mined =
            mine_under(&self.pow, candidate, self.nonce_budget, &seed, &self.rules)?;
        Some((mined, body))
    }

    /// Build a checkpoint for the main-chain block at `height` (devnet root
    /// stand-in = the block hash) and sign it with `validators`.
    pub fn make_checkpoint(
        &self,
        height: u64,
        validators: &[Validator],
    ) -> Option<(Checkpoint, Vec<Vote>)> {
        if !self.rules.may_checkpoint(height) {
            return None; // H2 — see `make_checkpoint_guarded`
        }
        let block_hash = *self.chain.main_chain().get(height as usize)?;
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
        if !self.rules.may_checkpoint(height) {
            return None;
        }
        let block_hash = *self.chain.main_chain().get(height as usize)?;
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
            | BodyError::WrongFee { .. }
            | BodyError::DoubleSpendInBlock { .. }
            | BodyError::ProofInvalid { .. } => BodyFault::Intrinsic("bad body"),
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

    fn reject_reason(err: &MempoolError) -> &'static str {
        match err {
            MempoolError::WrongFee { .. } => "wrong fee",
            MempoolError::AnchorNotValid => "anchor not valid",
            MempoolError::AlreadySpent { .. } => "nullifier spent",
            MempoolError::NullifierConflictInPool { .. } => "nullifier in-pool conflict",
            MempoolError::DuplicateTx => "duplicate",
            MempoolError::ProofInvalid => "proof invalid",
        }
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> ChainView for NodeAdapter<P, V> {
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
        // Committee checkpoints are the source of truth (as in `StubNode`).
        self.finality.finalized_height()
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> BlockIngest for NodeAdapter<P, V> {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome {
        self.submit_header(header)
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
        match validate_body(&header, &body, &self.verifier, anchor_ok) {
            Ok(()) => {}
            Err(e) => match Self::body_fault_class(&e) {
                BodyFault::Intrinsic(why) => return IngestOutcome::Rejected(why),
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

impl<P: PowEngine, V: TxVerifier + Clone> TxPool for NodeAdapter<P, V> {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
        // STATE LAG (issue #130 (a), part 3 — refusals two and three, which are the
        // same seam).
        //
        // `Mempool::admit` answers `is_valid_anchor` from the state machine's tree,
        // and a stale tree answers a CONSENSUS rule (protocol-spec §4 / frozen §7)
        // wrongly in both directions: it cannot see roots it has not applied, and its
        // stale tip makes the `MAX_ANCHOR_AGE_BLOCKS` window read as more permissive
        // than it is. This is also the wallet refusal — `submit_local_tx`, the only
        // write a co-resident wallet has (#123), lands here — so a wallet cannot cut
        // a witness against the wrong prefix of the tree and have this node take it.
        //
        // `Ignored`, never `Rejected`: the transaction may be perfectly valid and the
        // sender is not at fault, and #134 is precisely the cost of confusing "this is
        // invalid" with "I cannot judge this". So it is not relayed, not pooled, and
        // NOT scored.
        if self.state_lag().is_lagging() {
            self.refuse_for_lag("admit_tx");
            return IngestOutcome::Ignored(STATE_LAG_REASON);
        }
        let wid = wire_tx_id(&tx);
        // Issue #102: this line used to read `admit(tx, vec![], …)`. The hardcoded
        // empty declaration meant every transaction arriving from a peer claimed to
        // spend no coinbase note, so the frozen §2 maturity loop iterated zero times
        // on the *only* path that carries other people's transactions — the rule had
        // no enforcement here at all. There is no declaration to hardcode now: an
        // immature coinbase has no leaf in any valid anchor, so a spend of one has no
        // witness, fails `verify_tx`, and is refused as `proof invalid` — by the same
        // check that refuses every other unprovable claim.
        match self.mempool.admit(tx, &self.state, &self.verifier) {
            Ok(id) => {
                self.wire_ids.insert(wid, id);
                IngestOutcome::Accepted
            }
            Err(MempoolError::DuplicateTx) => IngestOutcome::Duplicate,
            Err(e) => IngestOutcome::Rejected(Self::reject_reason(&e)),
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
    fn ingest_checkpoint_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> VotesOutcome {
        let id = checkpoint_id(cp);
        if self.seen_checkpoints.contains(&id) {
            return VotesOutcome::Stale; // already finalized this variant
        }
        // HALT (issue #74, H2): a halted node must not FINALIZE above H either — it
        // would be finalizing a chain it refuses to accept. `Stale`, not `Invalid`:
        // the sender is on a different release, not misbehaving (S5).
        if !self.rules.may_checkpoint(cp.height) {
            return VotesOutcome::Stale;
        }
        let finalized = self.finality.finalized_height();
        let tip = self.chain.tip_height();
        // The round's roster context, read once from the committee state for this
        // height (issue #87). Every diagnostic number below is relative to it.
        let ctx = self.slot_context(cp.height);

        // Verify + active-filter against THIS height's epoch roster (frozen §4:
        // tombstoned/jailed excluded BEFORE the count; forged/unknown/dup penalised).
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
                    return VotesOutcome::Invalid; // unknown signer index
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
                    return VotesOutcome::Invalid; // forged signature
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

        let added = self.tally.add(cp, &active_kept, finalized, tip);
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
        // Issue #87: the accumulated set is the round's `have`, and the offsets of the
        // signers new in this message are real arrival observations — fed straight
        // into a histogram, because they cannot be recovered later from a printed count.
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
                    let _ = self.chain.set_finalized(cp.block_hash);
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
                // Equivocation slash = **10 % of the member's bond** + permanent
                // tombstone (consensus-parameters §4 FROZEN; issue #62 item 5
                // convergence — replaces the flat `EQUIVOCATION_SLASH_AMOUNT`
                // placeholder now that the bond is a genesis constant). Integer
                // floor; a ramped bond of 0 slashes 0 (still tombstones).
                let bond = self.committee.state().bond(signer).unwrap_or(0);
                let slash = bond / 10;
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
            self.rules.halt_at(),
        )
    }

    fn is_tombstoned(&self, idx: usize) -> bool {
        matches!(self.committee.state().status(idx), Some(MemberStatus::Tombstoned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let g = a.chain().genesis_hash();
        // Finalize genesis in the real state machine → its commitment root is a
        // valid anchor within the age window.
        a.state_mut().finalize(g).expect("finalize genesis");
        let anchor = a.state().commitment_root();
        (a, anchor)
    }

    fn tx_with(anchor: Hash32, nf: u8, proof: &[u8]) -> TxEntry {
        TxEntry {
            proof: proof.to_vec(),
            public: qlab_devnet::body::TxPublic {
                anchor,
                nullifiers: vec![[nf; 32]],
                commitments: vec![[nf.wrapping_add(50); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        }
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
        let bad_body = BlockBody { txs: vec![tx_with(anchor, 9, b"bad")], coinbase: 0, coinbase_rkm: [0; 4] };
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
        let g = p.chain().genesis_hash();
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
        let bad_proof = BlockBody {
            txs: vec![tx_with(anchor, 9, b"bad")],
            coinbase: 0,
            coinbase_rkm: [0; 4],
        };
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let h1 =
            BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, bad_proof.commitment());
        let out = a.ingest_block(h1, bad_proof);
        assert_eq!(out, IngestOutcome::Rejected("bad body"));
        assert!(out.is_peer_fault(), "an unverifiable proof is always the sender's fault");

        // (2) Positional, judged from the position that owns the verdict: an anchor
        // that is simply not a finalized root of this chain.
        let never_final = BlockBody {
            txs: vec![tx_with([0xEE; 32], 10, b"ok")],
            coinbase: 0,
            coinbase_rkm: [0; 4],
        };
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
        let g = *lagging.chain().header(&lagging.chain().genesis_hash()).expect("genesis");
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
        let cg = *current.chain().header(&current.chain().genesis_hash()).expect("genesis");
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
        let genesis = *a.chain().header(&a.chain().genesis_hash()).expect("genesis header");
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
        let mut fat = BlockBody { txs: vec![tx_with(anchor, 1, b"ok")], coinbase: 0, coinbase_rkm: [0; 4] };
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
        let genesis = f.chain().genesis_hash();
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
        let honest_body = BlockBody { txs: vec![tx_with(anchor, 3, b"ok")], coinbase: 0, coinbase_rkm: [0; 4] };
        let tip = *a.chain().header(&a.chain().tip_hash()).expect("tip header");
        let header =
            BlockHeader::child_of(&tip, tip.timestamp + 75, tip.difficulty, honest_body.commitment());
        // …handed a different, also-internally-valid body.
        let swapped = BlockBody { txs: vec![tx_with(anchor, 4, b"ok")], coinbase: 0, coinbase_rkm: [0; 4] };
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
        let honest_body = BlockBody { txs: vec![tx_with(anchor, 5, b"ok")], coinbase: 0, coinbase_rkm: [0; 4] };
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
    fn telemetry_of(a: &NodeAdapter<KeccakPow, MockVerifier>, peer_count: u64) -> Telemetry {
        let tip = a.chain().tip_height();
        let finalized = a.finalized_height();
        let main = a.chain().main_chain();
        let ts_at = |h: u64| a.chain().header(&main[h as usize]).map(|hd| hd.timestamp).unwrap_or(0);
        let age = ts_at(tip).saturating_sub(ts_at(finalized.unwrap_or(0)));
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
        assert!(t_stall.last_finalized_age_secs > 0, "chain-time age of the stall is visible");
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

    /// Acceptance #4: forged, unknown-signer, and duplicate-signer sets never grow the
    /// tally and are reported Invalid (→ the wire handler penalises).
    #[test]
    fn forged_unknown_dup_never_increase_tally() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        // Forged: a valid signature attributed to the wrong signer index.
        let forged = Vote { signer: 0, signature: validators[1].sign_checkpoint(&cp).signature };
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &[forged]), VotesOutcome::Invalid));

        // Unknown signer index (outside the 7-member committee).
        let outsider = qlab_devnet::committee::Validator::from_seed(99, [0xEE; 32]);
        assert!(matches!(
            a.ingest_checkpoint_votes(&cp, &[outsider.sign_checkpoint(&cp)]),
            VotesOutcome::Invalid
        ));

        // Duplicate-signer padding within one set.
        let dup = vec![validators[3].sign_checkpoint(&cp), validators[3].sign_checkpoint(&cp)];
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &dup), VotesOutcome::Invalid));

        assert_eq!(a.finalized_height(), None, "no invalid set moved finality");
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
    /// reason — and still never touch what counts.
    #[test]
    fn rejected_vote_sets_are_recorded_against_the_round_they_targeted() {
        let (cstate, validators) = committee7();
        let mut a = NodeAdapter::new(cstate, KeccakPow, MockVerifier, sim());
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);

        let forged = Vote { signer: 0, signature: validators[1].sign_checkpoint(&cp).signature };
        assert!(matches!(a.ingest_checkpoint_votes(&cp, &[forged]), VotesOutcome::Invalid));
        let outsider = qlab_devnet::committee::Validator::from_seed(99, [0xEE; 32]);
        assert!(matches!(
            a.ingest_checkpoint_votes(&cp, &[outsider.sign_checkpoint(&cp)]),
            VotesOutcome::Invalid
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
                        up.rules(),
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
}
