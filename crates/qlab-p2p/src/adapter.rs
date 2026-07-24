//! `NodeAdapter` — the **real** N1 node-state (M9-N7).
//!
//! Where [`crate::n1::StubNode`] is an in-memory reference that skips PoW and
//! proof verification, `NodeAdapter` wires the same five N1 traits onto the real
//! components the earlier waves built:
//!
//! - **header chain + PoW + fork-choice**: a devnet [`ChainState`] validated on
//!   ingest with real PoW + LWMA-120 difficulty + key-block seed
//!   ([`validate_header`] / [`expected_difficulty`] / [`pow_seed`], N3);
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
    finality_status, verify_equivocation, EquivocationEvidence, FinalityStatus, SigningWindow,
};
use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
use qlab_devnet::finality::{FinalityTracker, FinalizeError};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_pow::keyblock::KeyBlockSchedule;
use qlab_devnet::mining::mine;
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{
    DEGRADED_MODE_LAG_BLOCKS, DOWNTIME_JAIL_THRESHOLD_PCT, DOWNTIME_JAIL_WINDOW,
    EPOCH_LENGTH_BLOCKS, JAIL_BLOCKS,
};
use qlab_devnet::pow::PowEngine;
use qlab_devnet::validation::{expected_difficulty, pow_seed, validate_header};

use qlab_node::mempool::TxId;
use qlab_node::recovery::Finalizer;
use qlab_node::{genesis_block, MemNode, Mempool, MempoolError, NodeError, NodeState as _};
use qlab_devnet::body::TxVerifier;

use crate::codec::{checkpoint_id, tx_id as wire_tx_id};
use crate::n1::{BlockIngest, ChainView, CheckpointIngest, CommitteeControl, IngestOutcome, TxPool};

/// The effective §6 median a soak-node assembles against: large enough that the
/// penalty-free zone accepts every pending tx (no gigantism at prototype scale).
const SOAK_EFFECTIVE_MEDIAN: u64 = 4_000_000;

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
    /// Checkpoints already ingested (dedup).
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
    /// Monotone mining clock (sim seconds).
    clock: u64,
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
            seen_checkpoints: HashSet::new(),
            verifier,
            wire_ids: HashMap::new(),
            schedule: KeyBlockSchedule::new(sim.key_epoch_blocks, sim.key_epoch_lag),
            block_time: sim.block_time_secs,
            nonce_budget: sim.mine_nonce_budget,
            clock: 0,
        }
    }

    /// Override the downtime signing window (tests use a small window so it fills).
    pub fn set_signing_window(&mut self, window: usize, threshold_pct: u64) {
        self.signing = SigningWindow::new(window, threshold_pct);
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
        // Real PoW + LWMA difficulty + key-seed validation (N3).
        if validate_header(&self.chain, &self.pow, &header, self.block_time, self.schedule).is_err()
        {
            // Unknown parent → orphan (drives header-first sync); anything else is
            // an invalid header (bad PoW / difficulty / timestamp / height).
            return match self.chain.header(&header.prev) {
                None if header.height > 0 => IngestOutcome::Orphan,
                _ => IngestOutcome::Rejected("invalid header"),
            };
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

    /// Assemble + mine (but do NOT insert) the next block over the current tip.
    /// Returns `(mined_header, body)`; the caller ingests it via `announce_block`
    /// → `ingest_block`, which is the single insert/apply path. `None` if there is
    /// no known parent or the nonce budget is exhausted.
    pub fn mine_block(&mut self) -> Option<(BlockHeader, BlockBody)> {
        let template = self.mempool.assemble(&self.state, SOAK_EFFECTIVE_MEDIAN);
        let body = template.body;
        let bc = body.commitment();
        let parent_hash = self.chain.tip_hash();
        let parent = *self.chain.header(&parent_hash)?;
        let difficulty = expected_difficulty(&self.chain, &parent_hash, self.block_time)?;
        self.clock = (self.clock + self.block_time).max(parent.timestamp + self.block_time);
        let candidate = BlockHeader::child_of(&parent, self.clock, difficulty, bc);
        let seed = pow_seed(&self.chain, &parent_hash, candidate.height, self.schedule)?;
        let mined = mine(&self.pow, candidate, self.nonce_budget, &seed)?;
        Some((mined, body))
    }

    /// Build a checkpoint for the main-chain block at `height` (devnet root
    /// stand-in = the block hash) and sign it with `validators`.
    pub fn make_checkpoint(
        &self,
        height: u64,
        validators: &[Validator],
    ) -> Option<(Checkpoint, Vec<Vote>)> {
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
        let block_hash = *self.chain.main_chain().get(height as usize)?;
        let cp = Checkpoint::new(height, block_hash, block_hash);
        let votes = finalizers.iter_mut().filter_map(|f| f.sign(&cp).ok()).collect();
        Some((cp, votes))
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
    fn ingest_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) -> IngestOutcome {
        let id = checkpoint_id(&cp);
        if self.seen_checkpoints.contains(&id) {
            return IngestOutcome::Duplicate;
        }
        // Tombstoned/jailed signers are excluded from quorum BEFORE the count
        // (frozen §4). "Who may sign" is this checkpoint's epoch committee.
        let active_signers: Vec<usize> = {
            let cstate = self.committee.state_for_height(cp.height);
            votes.iter().filter(|v| cstate.is_active(v.signer, cp.height)).map(|v| v.signer).collect()
        };
        let active_votes: Vec<Vote> =
            votes.iter().filter(|v| active_signers.contains(&v.signer)).cloned().collect();

        let result = {
            let committee = self.committee.state_for_height(cp.height).committee();
            self.finality.try_finalize(&cp, &active_votes, committee)
        };
        match result {
            Ok(()) => {
                self.seen_checkpoints.insert(id);
                // Advance the consensus finalized pointer (no reorg past finality)
                // and the state-machine finalized height (marks commitment roots up
                // to this block as valid tx anchors) — both best-effort: the block
                // may not be known locally yet, which the anchor queries tolerate.
                let _ = self.chain.set_finalized(cp.block_hash);
                let _ = self.state.finalize(cp.block_hash);
                self.signing.record_round(&active_signers);
                self.apply_downtime_jails(cp.height);
                IngestOutcome::Accepted
            }
            Err(FinalizeError::NotAdvancing { .. }) => {
                self.seen_checkpoints.insert(id);
                IngestOutcome::Duplicate
            }
            Err(FinalizeError::InsufficientQuorum { .. }) => {
                IngestOutcome::Rejected("insufficient quorum")
            }
            Err(FinalizeError::InvalidVote { .. }) => IngestOutcome::Rejected("invalid vote"),
            Err(FinalizeError::UnknownSigner { .. }) => IngestOutcome::Rejected("unknown signer"),
            Err(FinalizeError::DuplicateSigner { .. }) => IngestOutcome::Rejected("duplicate signer"),
        }
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
        finality_status(self.chain.tip_height(), self.finality.finalized_height(), DEGRADED_MODE_LAG_BLOCKS)
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
}
