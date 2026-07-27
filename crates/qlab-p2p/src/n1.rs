//! N1 boundary — **stubbed** node-state interfaces this P2P layer consumes.
//!
//! Issue #48 (N1) owns the real node-state traits (chain store, commitment tree,
//! nullifier set, restart-safe snapshots) and will publish them from
//! qlab-consensus / qlab-node. Those have not landed, so this module defines the
//! **consumer-facing** slice the P2P layer needs — read the chain to serve sync,
//! ingest received headers / txs / checkpoints — as traits, with an in-memory
//! [`StubNode`] implementation for tests. Wiring these to the real node is N7
//! (#54); the trait names/shapes here are the contract N7 satisfies.
//!
//! Kept deliberately minimal: the P2P layer builds locators and answers
//! `GetHeaders` itself (see [`crate::sync`]) from a few primitive accessors, so
//! the node interface stays small and easy for N1 to implement over real state.

use std::collections::{HashMap, HashSet};

use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::chain::{ChainState, InsertError};
use qlab_devnet::committee::{Checkpoint, CommitteeState, Vote};
use qlab_devnet::ebbflow::{
    finality_status, verify_equivocation, EquivocationEvidence, FinalityStatus, SigningWindow,
};
use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
use qlab_devnet::finality::{FinalityTracker, FinalizeError};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::tally::VoteTally;
use qlab_devnet::params_devnet::{
    DEGRADED_MODE_LAG_BLOCKS, DOWNTIME_JAIL_THRESHOLD_PCT, DOWNTIME_JAIL_WINDOW,
    EPOCH_LENGTH_BLOCKS, EQUIVOCATION_SLASH_AMOUNT, JAIL_BLOCKS,
};

use crate::codec::{checkpoint_id, tx_id};

/// What happened when an object was handed to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New and accepted into node state.
    Accepted,
    /// Already known; no state change (do not re-relay).
    Duplicate,
    /// Well-formed but its parent/context is missing — caller should sync it.
    Orphan,
    /// Rejected as invalid; the peer that sent it may be penalized.
    Rejected(&'static str),
    /// Well-formed as far as this node can tell, but **this release will not act
    /// on it** (issue #74: the object is above our halt height). Not relayed, not
    /// synced toward, and — the load-bearing part — **the sender is not penalized**.
    ///
    /// Distinct from [`Self::Rejected`] on purpose. A peer still mining above a
    /// halt height is on a different release, not misbehaving; §4 says explicitly
    /// that old-binary miners *can* keep producing blocks past the halt height.
    /// Scoring them as invalid-object senders would ban honest peers during the
    /// upgrade window — partitioning the net at exactly the moment an operator
    /// needs it whole. This is the #70 S5 rule ("a well-formed thing we cannot use
    /// is not a misbehaving peer") applied to the halt.
    Ignored(&'static str),
}

impl IngestOutcome {
    /// Whether this object is worth relaying onward (only genuinely-new objects).
    pub fn should_relay(&self) -> bool {
        matches!(self, IngestOutcome::Accepted)
    }

    /// Whether the **sender** is at fault and should be penalized.
    ///
    /// Only [`Self::Rejected`]. In particular [`Self::Ignored`] is NOT a fault: a
    /// peer producing blocks above our halt height is on a different release, which
    /// `committee-and-governance.md` §4 says explicitly it may be. Penalizing it
    /// would ban honest peers during the upgrade window — partitioning the net at
    /// exactly the moment an operator needs it whole (issue #74; the #70 S5 rule
    /// applied to the halt).
    pub fn is_peer_fault(&self) -> bool {
        matches!(self, IngestOutcome::Rejected(_))
    }
}

/// The outcome of feeding a **partial** checkpoint-vote set into the accumulator
/// ([`CheckpointIngest::ingest_checkpoint_votes`], M10-T0-5). Distinct from
/// [`IngestOutcome`] because a well-formed below-quorum set is neither "accepted +
/// finalized" nor a penalisable reject — it is progress toward a quorum that must be
/// relayed but never scored against the sender (task-book S5).
#[derive(Clone)]
pub enum VotesOutcome {
    /// This message added ≥1 previously-unseen active vote. `finalized` = the
    /// accumulated distinct-active count reached quorum and the checkpoint finalized
    /// on this call. `accumulated` = the full active vote set for this variant, to be
    /// relayed onward (sender excluded).
    Learned { finalized: bool, accumulated: Vec<Vote> },
    /// No new information — already tallied, already finalized, or out of the tally
    /// window. Do NOT relay, do NOT penalise.
    Stale,
    /// The set carried a forged signature, an unknown signer index, or duplicate-
    /// signer padding — penalise the sender (task-book S5). A well-formed partial set
    /// (valid sigs, distinct in-committee signers, merely below quorum) is never this.
    Invalid,
}

/// Read-only view of the chain — the primitives sync/relay/serving need.
pub trait ChainView {
    fn genesis_hash(&self) -> Hash32;
    fn tip_hash(&self) -> Hash32;
    fn tip_height(&self) -> u64;
    /// A header by its hash, if known (on any fork).
    fn header(&self, hash: &Hash32) -> Option<BlockHeader>;
    /// The main-chain block hash at `height`, if the main chain reaches it.
    fn main_chain_hash_at(&self, height: u64) -> Option<Hash32>;
    /// Whether a header is known (on any fork).
    fn has_header(&self, hash: &Hash32) -> bool;
    /// The finalized height, if any checkpoint has finalized.
    fn finalized_height(&self) -> Option<u64>;
}

/// Ingest headers received from peers.
pub trait BlockIngest {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome;

    /// Ingest a full block (header + ordered body). Header-only node-states
    /// (sync/gossip only, e.g. [`StubNode`]) inherit the default, which drops the
    /// body and ingests just the header. A real full node (N7's `NodeAdapter`)
    /// overrides this to validate the body and fold it into consensus state — so
    /// a block whose body carries an invalid tx is rejected here, and restart
    /// state reflects applied bodies. The body arrives via BIP-152 relay
    /// (produced locally or reconstructed from the mempool).
    fn ingest_block(&mut self, header: BlockHeader, _body: BlockBody) -> IngestOutcome {
        self.ingest_header(header)
    }
}

/// The transaction mempool, from the P2P layer's point of view.
pub trait TxPool {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome;
    fn get_tx(&self, id: &Hash32) -> Option<TxEntry>;
    fn has_tx(&self, id: &Hash32) -> bool;
    /// All mempool transactions — used by compact-block reconstruction to build
    /// the short-id → tx index. (A real node would expose a short-id lookup;
    /// snapshotting the pool is fine at prototype scale.)
    fn all_txs(&self) -> Vec<TxEntry>;
}

/// Ingest checkpoint-vote gossip (checkpoint + committee votes).
pub trait CheckpointIngest {
    /// Accumulate a (possibly partial) vote set for `cp` across messages (M10-T0-5).
    /// Verifies each vote against `cp`'s epoch roster, excludes tombstoned/jailed
    /// signers, de-duplicates by signer into the bounded tally, and finalizes through
    /// the unchanged `try_finalize` the moment the distinct-active count reaches
    /// quorum. This is THE accumulation path — [`Self::ingest_checkpoint`] delegates to
    /// it. See [`VotesOutcome`].
    fn ingest_checkpoint_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> VotesOutcome;

    /// Ingest a full checkpoint object (the finalized-set serving path). Delegates to
    /// [`Self::ingest_checkpoint_votes`]: a full quorum set finalizes in one call, a
    /// partial set accumulates and reports `insufficient quorum` (without penalty at
    /// the caller). Kept for the `Checkpoint` (0x0022) object + re-serve path and its
    /// direct callers/tests.
    fn ingest_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) -> IngestOutcome {
        match self.ingest_checkpoint_votes(&cp, &votes) {
            VotesOutcome::Learned { finalized: true, .. } => IngestOutcome::Accepted,
            VotesOutcome::Learned { finalized: false, .. } => {
                IngestOutcome::Rejected("insufficient quorum")
            }
            VotesOutcome::Stale => IngestOutcome::Duplicate,
            VotesOutcome::Invalid => IngestOutcome::Rejected("invalid vote"),
        }
    }

    fn has_checkpoint(&self, id: &Hash32) -> bool;
}

/// The committee-over-network control surface (M9-N5): equivocation detection +
/// the automated-punishment path, and the Ebb-and-Flow regime. The P2P layer calls
/// these when it relays checkpoint votes and evidence; N7 satisfies the same
/// contract over the real node.
pub trait CommitteeControl {
    /// Record the votes carried by a gossiped checkpoint and return any **new**
    /// equivocation evidence they reveal — the same signer having signed two
    /// conflicting checkpoints at the same slot (committee-gov §3: "the pair of
    /// signatures *is* the proof"). Only votes that verify against the epoch's
    /// committee are recorded, so a peer cannot manufacture fake evidence.
    fn observe_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> Vec<EquivocationEvidence>;

    /// Apply verified equivocation evidence: permanent tombstone + bond slash, no
    /// human in the path. Idempotent (tombstone is terminal). Returns the punished
    /// signer index, or `None` if the evidence does not verify.
    fn apply_evidence(&mut self, ev: &EquivocationEvidence) -> Option<usize>;

    /// This node's finality regime (Final vs degraded probabilistic PoW) from the
    /// tip-vs-finalized lag — the Ebb-and-Flow split (consensus §4), observed over
    /// the network.
    fn finality_status(&self) -> FinalityStatus;

    /// Whether committee member `idx` is currently tombstoned (test/assert hook).
    fn is_tombstoned(&self, idx: usize) -> bool;
}

/// Convenience super-trait: a node the P2P layer can fully drive.
pub trait NodeState: ChainView + BlockIngest + TxPool + CheckpointIngest + CommitteeControl {}
impl<T: ChainView + BlockIngest + TxPool + CheckpointIngest + CommitteeControl> NodeState for T {}

/// An in-memory node-state stub for tests — a real (devnet) [`ChainState`] + an
/// [`EpochCommittee`] (membership + status across epochs) + a finality tracker + a
/// mempool + a seen-checkpoint set + a downtime [`SigningWindow`]. Structural only:
/// it does **not** re-run PoW / proof verification (that is N1/N4's job); it is
/// enough to exercise checkpoint gossip, committee finalization, epoch membership,
/// downtime jail, equivocation-evidence, and Ebb-and-Flow — all over the network.
pub struct StubNode {
    chain: ChainState,
    mempool: HashMap<Hash32, TxEntry>,
    /// The committee across epochs (M9-N5) — replaces the M6 static set.
    committee: EpochCommittee,
    finality: FinalityTracker,
    seen_checkpoints: HashSet<Hash32>,
    /// Trailing-window signer participation, for downtime-jail detection.
    signing: SigningWindow,
    /// Every (height, signer) → the checkpoint+vote first seen for it, so a second
    /// conflicting vote at the same slot is detectable as equivocation.
    votes_seen: HashMap<(u64, usize), (Checkpoint, Vote)>,
    /// Cross-message vote accumulator: distinct verified active votes per checkpoint
    /// variant, until a quorum can be handed to `try_finalize` (M10-T0-5).
    tally: VoteTally,
}

impl StubNode {
    /// New node from a shared genesis header and a **static genesis committee** —
    /// wrapped in a genesis [`EpochCommittee`] at the frozen epoch length, so a
    /// caller that does not exercise membership changes behaves exactly as the M6
    /// static set did (no boundary is crossed under the frozen 1,152-block epoch in
    /// these short sims). The downtime window is the frozen (100, 33 %).
    pub fn new(genesis: BlockHeader, committee: CommitteeState) -> Self {
        let ec = EpochCommittee::genesis(EpochSchedule::new(EPOCH_LENGTH_BLOCKS), committee);
        Self::with_epoch(genesis, ec)
    }

    /// New node from a shared genesis header and an explicit [`EpochCommittee`] —
    /// used by membership/epoch tests that want a small epoch length so a run
    /// crosses boundaries.
    pub fn with_epoch(genesis: BlockHeader, committee: EpochCommittee) -> Self {
        StubNode {
            chain: ChainState::new(genesis),
            mempool: HashMap::new(),
            committee,
            finality: FinalityTracker::new(),
            seen_checkpoints: HashSet::new(),
            signing: SigningWindow::new(DOWNTIME_JAIL_WINDOW, DOWNTIME_JAIL_THRESHOLD_PCT),
            votes_seen: HashMap::new(),
            tally: VoteTally::new(),
        }
    }

    /// Override the downtime signing window (tests use a small window so it fills).
    pub fn set_signing_window(&mut self, window: usize, threshold_pct: u64) {
        self.signing = SigningWindow::new(window, threshold_pct);
    }

    /// Read-only chain access (tests / assertions).
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }
    /// Current mempool size.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }
    /// The finality tracker (tests / assertions).
    pub fn finality(&self) -> &FinalityTracker {
        &self.finality
    }
    /// The epoch committee (tests / assertions).
    pub fn committee(&self) -> &EpochCommittee {
        &self.committee
    }

    /// Apply any downtime jails the signing window now warrants at `height`
    /// (jail-no-slash; auto-readmit after [`JAIL_BLOCKS`]). No-op on tombstoned.
    fn apply_downtime_jails(&mut self, height: u64) {
        let n = self.committee.state().size();
        for idx in 0..n {
            if self.signing.jailable(idx) {
                self.committee.state_mut().jail(idx, height + JAIL_BLOCKS);
            }
        }
    }
}

impl ChainView for StubNode {
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
        // The finality tracker (committee checkpoints) is the source of truth for
        // finalized height — the chain store only reflects it when the finalized
        // block is also locally known.
        self.finality.finalized_height()
    }
}

impl BlockIngest for StubNode {
    fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome {
        match self.chain.insert_header(header) {
            Ok(_) => {
                // Advance the epoch machinery to the new tip: membership changes
                // seal at any boundary crossed (committee-gov §2). Reset the
                // downtime window on an epoch change — indices are reassigned at a
                // boundary (prototype simplification, annotated in `epoch`).
                let before = self.committee.current_epoch();
                self.committee.advance_to(self.chain.tip_height());
                if self.committee.current_epoch() != before {
                    self.signing.reset();
                }
                IngestOutcome::Accepted
            }
            Err(InsertError::Duplicate) => IngestOutcome::Duplicate,
            Err(InsertError::UnknownParent) => IngestOutcome::Orphan,
            Err(InsertError::BadHeight) => IngestOutcome::Rejected("bad height"),
        }
    }
}

impl TxPool for StubNode {
    fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
        let id = tx_id(&tx);
        if self.mempool.contains_key(&id) {
            return IngestOutcome::Duplicate;
        }
        self.mempool.insert(id, tx);
        IngestOutcome::Accepted
    }
    fn get_tx(&self, id: &Hash32) -> Option<TxEntry> {
        self.mempool.get(id).cloned()
    }
    fn has_tx(&self, id: &Hash32) -> bool {
        self.mempool.contains_key(id)
    }
    fn all_txs(&self) -> Vec<TxEntry> {
        self.mempool.values().cloned().collect()
    }
}

impl CheckpointIngest for StubNode {
    fn ingest_checkpoint_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> VotesOutcome {
        let id = checkpoint_id(cp);
        if self.seen_checkpoints.contains(&id) {
            return VotesOutcome::Stale; // already finalized this variant
        }
        let finalized = self.finality.finalized_height();
        let tip = self.chain.tip_height();

        // Verify + active-filter against THIS height's epoch roster (frozen §4:
        // tombstoned/jailed excluded BEFORE the count; forged/unknown/dup penalised).
        // `committee` is cloned so the immutable borrow of `self.committee` ends before
        // the mutable finalization ops.
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

        // Re-filter the accumulated set by CURRENT active status (a since-jailed
        // signer's stale vote must not count), then let the AUTHORITATIVE try_finalize
        // gate decide — the tally never lowers the bar (S4).
        let active_now: Vec<Vote> = {
            let cstate = self.committee.state_for_height(cp.height);
            added.accumulated.iter().filter(|v| cstate.is_active(v.signer, cp.height)).cloned().collect()
        };
        if active_now.len() >= quorum {
            match self.finality.try_finalize(cp, &active_now, &committee) {
                Ok(()) => {
                    self.seen_checkpoints.insert(id);
                    let _ = self.chain.set_finalized(cp.block_hash);
                    let signers: Vec<usize> = active_now.iter().map(|v| v.signer).collect();
                    self.signing.record_round(&signers);
                    self.apply_downtime_jails(cp.height);
                    self.tally.on_finalized(cp.height);
                    return VotesOutcome::Learned { finalized: true, accumulated: added.accumulated };
                }
                Err(FinalizeError::NotAdvancing { .. }) => {
                    // A higher (or another variant already past this height) finalized
                    // first — record so we don't re-try, treat as no-progress.
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

impl CommitteeControl for StubNode {
    fn observe_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> Vec<EquivocationEvidence> {
        let mut evidence = Vec::new();
        for v in votes {
            // Only record votes that actually verify against this epoch's
            // committee — a forged vote cannot seed fake equivocation.
            {
                let committee = self.committee.state_for_height(cp.height).committee();
                if !committee.verify_vote(cp, v) {
                    continue;
                }
            }
            let key = (cp.height, v.signer);
            match self.votes_seen.get(&key) {
                Some((prev_cp, prev_vote)) if prev_cp != cp => {
                    // Two valid votes, same slot, different checkpoint = equivocation.
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
                Some(_) => { /* same checkpoint again — a duplicate vote, not a conflict */ }
                None => {
                    self.votes_seen.insert(key, (*cp, v.clone()));
                }
            }
        }
        evidence
    }

    fn apply_evidence(&mut self, ev: &EquivocationEvidence) -> Option<usize> {
        // Verify against the committee that owned the equivocated slot; the borrow
        // ends before we take the mutable one to tombstone.
        let verified =
            verify_equivocation(ev, self.committee.state_for_height(ev.cp_a.height).committee());
        match verified {
            Ok(signer) => {
                self.committee.state_mut().tombstone(signer, EQUIVOCATION_SLASH_AMOUNT);
                Some(signer)
            }
            Err(_) => None,
        }
    }

    fn finality_status(&self) -> FinalityStatus {
        finality_status(
            self.chain.tip_height(),
            self.finality.finalized_height(),
            DEGRADED_MODE_LAG_BLOCKS,
        )
    }

    fn is_tombstoned(&self, idx: usize) -> bool {
        matches!(
            self.committee.state().status(idx),
            Some(qlab_devnet::committee::MemberStatus::Tombstoned)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::{devnet_committee, Validator};
    use qlab_devnet::params_devnet::BOND_AMOUNT;

    fn genesis() -> BlockHeader {
        BlockHeader::genesis(1000, 0)
    }

    fn node() -> StubNode {
        let (committee, _v) = devnet_committee(7);
        StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT))
    }

    #[test]
    fn header_ingest_accept_dup_orphan() {
        let mut n = node();
        let g = genesis();
        let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
        assert_eq!(n.ingest_header(h1), IngestOutcome::Accepted);
        assert_eq!(n.ingest_header(h1), IngestOutcome::Duplicate);
        // A header whose parent we do not have → orphan.
        let unknown_parent = BlockHeader::child_of(&h1, 150, 1000, [2; 32]);
        let orphan_child = BlockHeader::child_of(&unknown_parent, 225, 1000, [3; 32]);
        assert_eq!(n.ingest_header(orphan_child), IngestOutcome::Orphan);
    }

    #[test]
    fn stubnode_ingest_block_defaults_to_header_only() {
        // A header-only node-state inherits the trait default: the body is
        // dropped, the header is ingested, the tip advances.
        let mut n = node();
        let g = genesis();
        let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
        let body = BlockBody { txs: vec![], coinbase: 0 };
        assert_eq!(n.ingest_block(h1, body), IngestOutcome::Accepted);
        assert_eq!(n.tip_height(), 1);
    }

    #[test]
    fn tx_ingest_dedups() {
        let mut n = node();
        let tx = TxEntry {
            proof: vec![1, 2, 3],
            public: qlab_devnet::body::TxPublic {
                anchor: [0; 32],
                nullifiers: vec![],
                commitments: vec![],
                bucket: qlab_devnet::fees::ArityBucket::TwoByTwo,
                fee: 0,
            },
        };
        assert_eq!(n.ingest_tx(tx.clone()), IngestOutcome::Accepted);
        assert_eq!(n.ingest_tx(tx.clone()), IngestOutcome::Duplicate);
        assert_eq!(n.mempool_len(), 1);
        assert!(n.has_tx(&tx_id(&tx)));
    }

    #[test]
    fn checkpoint_ingest_quorum_gate() {
        let (committee, validators) = devnet_committee(7); // quorum 5
        let mut n = StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT));
        let cp = Checkpoint::new(2, [0xAA; 32], [0xAA; 32]);

        let votes4: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(
            n.ingest_checkpoint(cp, votes4),
            IngestOutcome::Rejected("insufficient quorum")
        );

        let votes5: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(n.ingest_checkpoint(cp, votes5.clone()), IngestOutcome::Accepted);
        assert_eq!(n.finalized_height(), Some(2));
        // Re-delivery is a dup.
        assert_eq!(n.ingest_checkpoint(cp, votes5), IngestOutcome::Duplicate);
    }

    fn conflicting_evidence(validators: &[Validator], signer: usize, height: u64) -> EquivocationEvidence {
        let a = Checkpoint::new(height, [0xA0 + signer as u8; 32], [0xA0; 32]);
        let b = Checkpoint::new(height, [0xB0 + signer as u8; 32], [0xB0; 32]);
        EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[signer].sign_checkpoint(&b),
            cp_b: b,
        }
    }

    #[test]
    fn ingest_checkpoint_drops_tombstoned_votes_from_quorum() {
        // frozen §4: tombstoned votes MUST NOT count toward quorum.
        let (committee, validators) = devnet_committee(7); // quorum 5
        let mut n = StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT));
        // Tombstone signers 0,1,2 via verified equivocation evidence → 4 active.
        for s in [0usize, 1, 2] {
            assert_eq!(n.apply_evidence(&conflicting_evidence(&validators, s, 90 + s as u64)), Some(s));
            assert!(n.is_tombstoned(s));
        }
        // All 7 sign a fresh checkpoint, but only the 4 non-tombstoned count < 5.
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let votes: Vec<Vote> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        assert_eq!(n.ingest_checkpoint(cp, votes), IngestOutcome::Rejected("insufficient quorum"));
        assert_eq!(n.finalized_height(), None);
    }

    #[test]
    fn observe_votes_detects_conflict_but_not_duplicates_or_forgeries() {
        let (committee, validators) = devnet_committee(7);
        let mut n = StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT));
        let cp_a = Checkpoint::new(8, [0xAA; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(8, [0xBB; 32], [0xBB; 32]); // conflicting, same slot

        // First sighting: nothing to report.
        let v_a = vec![validators[3].sign_checkpoint(&cp_a)];
        assert!(n.observe_votes(&cp_a, &v_a).is_empty());
        // Same checkpoint again = a duplicate vote, not a conflict.
        assert!(n.observe_votes(&cp_a, &v_a).is_empty());
        // A conflicting checkpoint by the same signer = equivocation.
        let v_b = vec![validators[3].sign_checkpoint(&cp_b)];
        let ev = n.observe_votes(&cp_b, &v_b);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].vote_a.signer, 3);
        // A forged vote (valid signature but wrong signer index) is ignored — it
        // does not verify against the committee, so it can't seed fake evidence.
        let forged = Vote { signer: 5, signature: validators[3].sign_checkpoint(&cp_a).signature };
        assert!(n.observe_votes(&cp_a, &[forged]).is_empty());
    }

    #[test]
    fn downtime_jail_fires_over_the_ingest_path() {
        // A member that never signs across a full window is jailed (no slash).
        let (committee, validators) = devnet_committee(7); // quorum 5
        let mut n = StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT));
        n.set_signing_window(4, 33); // small window so it fills quickly
        // Four advancing checkpoints, each signed by 0..4 only (5,6 stay dark).
        for h in 1..=4u64 {
            let cp = Checkpoint::new(h, [h as u8; 32], [h as u8; 32]);
            let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            assert_eq!(n.ingest_checkpoint(cp, votes), IngestOutcome::Accepted);
        }
        // Signer 6 signed 0 of 4 (0 % < 33 %) → jailed; a full signer is not.
        assert!(matches!(
            n.committee().state().status(6),
            Some(qlab_devnet::committee::MemberStatus::Jailed { .. })
        ));
        assert_eq!(n.committee().state().status(0), Some(qlab_devnet::committee::MemberStatus::Active));
        assert_eq!(n.committee().state().slashed(6), Some(0), "downtime is jail, NOT slash");
    }

    /// #74 + #70 S5: exactly one outcome is the sender's fault. In particular a
    /// block above our halt height is NOT — penalizing it would ban honest peers
    /// still on the old release, during the upgrade window, which is the worst
    /// possible moment to shed peers.
    #[test]
    fn only_rejected_is_a_peer_fault() {
        assert!(IngestOutcome::Rejected("bad pow").is_peer_fault());
        assert!(!IngestOutcome::Ignored("above halt height").is_peer_fault());
        assert!(!IngestOutcome::Accepted.is_peer_fault());
        assert!(!IngestOutcome::Orphan.is_peer_fault());
        assert!(!IngestOutcome::Duplicate.is_peer_fault());
        // …and only a genuinely new object is relayed.
        assert!(IngestOutcome::Accepted.should_relay());
        assert!(!IngestOutcome::Ignored("above halt height").should_relay());
    }
}
