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

use std::collections::{HashMap, HashSet};

use qlab_devnet::body::{validate_body, BlockBody, TxEntry};
use qlab_devnet::chain::{ChainState, InsertError};
use qlab_devnet::committee::{Checkpoint, CommitteeState, MemberStatus, Validator, Vote};
use qlab_devnet::ebbflow::{
    verify_equivocation, EquivocationEvidence, FinalityStatus, SigningWindow,
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
use qlab_node::recovery::Finalizer;
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
}

/// Layer-attributed ingest refusal counts (issue #74).
///
/// The two are deliberately separate because they are different claims about the
/// upgrade. `halt_ignored` is the **release** layer: this node has stopped, so it
/// will not act on the block (and does not blame the sender). `pow_rejected` is the
/// **header-validation** layer: under the post-halt rule domain the block's PoW does
/// not meet the target, so it is invalid, not merely unwanted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestCounters {
    /// Headers/blocks not acted on because this release is halted (release layer).
    pub halt_ignored: u64,
    /// Headers rejected because the PoW value did not meet the target
    /// (header-validation layer).
    pub pow_rejected: u64,
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
        }
    }

    /// Select the header-timestamp [`MiningClock`]. The binary (`qumbra-node`)
    /// calls this with [`MiningClock::WallClock`] after `open`; sims/tests leave
    /// the deterministic default.
    pub fn set_mining_clock(&mut self, clock: MiningClock) {
        self.mining_clock = clock;
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
        match self.chain.insert_header(header) {
            Ok(_) => {
                self.advance_epoch();
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
        let template = self.mempool.assemble(&self.state, SOAK_EFFECTIVE_MEDIAN);
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

    fn reject_reason(err: &MempoolError) -> &'static str {
        match err {
            MempoolError::WrongFee { .. } => "wrong fee",
            MempoolError::AnchorNotValid => "anchor not valid",
            MempoolError::ImmatureCoinbase { .. } => "immature coinbase",
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
        // 1. Body validity is independent of tip-extension: an invalid tx proof /
        //    fee / in-block double-spend / non-final anchor is adversarial and must
        //    be rejected + penalized regardless of fork position.
        let anchor_ok = |root: &Hash32| self.state.is_valid_anchor(root);
        if validate_body(&body, &self.verifier, anchor_ok).is_err() {
            return IngestOutcome::Rejected("bad body");
        }
        // 2. Header into the consensus chain (PoW / fork-choice).
        let outcome = self.submit_header(header);
        // 3. On a fresh accept, fold the body into real state (best-effort: a
        //    non-tip block — benign reorg lag — is left for the canonical chain,
        //    since the state machine is tip-only by design).
        if outcome == IngestOutcome::Accepted {
            match self.state.apply_block(header, body.clone(), &self.verifier) {
                Ok(_) => {
                    self.mempool.on_block_connected(header.height, &body, &self.state);
                }
                Err(NodeError::NotExtendingTip { .. }) => { /* reorg lag — expected */ }
                Err(_) => { /* body already validated above; nothing else to do */ }
            }
        }
        outcome
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> TxPool for NodeAdapter<P, V> {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
        let wid = wire_tx_id(&tx);
        match self.mempool.admit(tx, vec![], &self.state, &self.verifier) {
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

        // Verify + active-filter against THIS height's epoch roster (frozen §4:
        // tombstoned/jailed excluded BEFORE the count; forged/unknown/dup penalised).
        // `committee` is cloned so the immutable borrow ends before the mutable ops.
        let (committee, quorum, active_kept) = {
            let cstate = self.committee.state_for_height(cp.height);
            let committee = cstate.committee().clone();
            let mut seen_signer = HashSet::new();
            let mut active_kept: Vec<Vote> = Vec::new();
            for v in votes {
                if committee.member(v.signer).is_none() {
                    return VotesOutcome::Invalid; // unknown signer index
                }
                if !seen_signer.insert(v.signer) {
                    return VotesOutcome::Invalid; // duplicate-signer padding
                }
                if !committee.verify_vote(cp, v) {
                    return VotesOutcome::Invalid; // forged signature
                }
                if cstate.is_active(v.signer, cp.height) {
                    active_kept.push(v.clone());
                }
                // else: valid but jailed/tombstoned — excluded, NOT penalised.
            }
            (committee, cstate.quorum_threshold(), active_kept)
        };

        let added = self.tally.add(cp, &active_kept, finalized, tip);
        if !added.grew {
            return VotesOutcome::Stale;
        }

        // Re-filter by CURRENT active status, then let the AUTHORITATIVE try_finalize
        // gate decide — the tally never lowers the bar (S4).
        let active_now: Vec<Vote> = {
            let cstate = self.committee.state_for_height(cp.height);
            added.accumulated.iter().filter(|v| cstate.is_active(v.signer, cp.height)).cloned().collect()
        };
        if active_now.len() >= quorum {
            match self.finality.try_finalize(cp, &active_now, &committee) {
                Ok(()) => {
                    self.seen_checkpoints.insert(id);
                    // Advance the consensus finalized pointer (no reorg past finality)
                    // and the state-machine finalized height — both best-effort: the
                    // block may not be known locally yet, which anchor queries tolerate.
                    let _ = self.chain.set_finalized(cp.block_hash);
                    let _ = self.state.finalize(cp.block_hash);
                    let signers: Vec<usize> = active_now.iter().map(|v| v.signer).collect();
                    self.signing.record_round(&signers);
                    self.apply_downtime_jails(cp.height);
                    self.tally.on_finalized(cp.height);
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
        // no crash, tip unchanged. (Body validity is independent of the header.)
        let (h2, _b2) = a.mine_block().expect("mine 2");
        let bad_body = BlockBody { txs: vec![tx_with(anchor, 9, b"bad")], coinbase: 0 };
        assert_eq!(a.ingest_block(h2, bad_body), IngestOutcome::Rejected("bad body"));
        assert_eq!(a.chain().tip_height(), 1, "tip did not move on a bad block");
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
