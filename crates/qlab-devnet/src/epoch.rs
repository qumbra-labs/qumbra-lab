//! Epoch-boundary committee membership machinery (committee-and-governance §2).
//!
//! This replaces the M6 **static genesis set**. committee-governance §2 decided:
//! *"Set changes happen in-protocol at epoch boundaries — never as fork events …
//! changing the set only at a boundary makes 'who may sign' a pure function of the
//! finalized state at the previous boundary."* This module realizes exactly that:
//!
//! - Membership *changes* (admit a new entity, voluntary/stale exit, forced
//!   removal of a tombstoned member) are **staged** and applied **only** when the
//!   chain crosses an epoch boundary. A staged change is invisible until then.
//! - Each sealed epoch's committee is retained, so a checkpoint at height `h` is
//!   always verified against the committee that owned `epoch_of(h)` — the previous
//!   boundary's set, never a mid-stream one.
//! - Per-member **status** (jail / tombstone, [`crate::committee::MemberStatus`])
//!   still applies **immediately** for quorum within the current epoch: tombstone
//!   is an immediate safety exclusion (frozen §4: *tombstoned votes MUST NOT count
//!   toward quorum*). The tombstoned entity is *formally* dropped from the roster
//!   at the next boundary (§2's "forced exit").
//!
//! Prototype boundary (annotated, not a design claim): the machinery advances with
//! the chain tip and status mutations (tombstone/jail) apply to the **current**
//! epoch's live committee — checkpoints finalize within the current epoch (cadence
//! 8 ≪ epoch length), so an equivocator is a current member. Cross-epoch
//! adjudication of a stale checkpoint against an already-resealed roster is a
//! full-M8 concern.

use std::collections::{HashMap, HashSet};

use crate::committee::{Committee, CommitteeState, MemberKey, MemberStatus};

/// Maps block heights to epochs. A **boundary** is any height that is an exact
/// multiple of `epoch_length`; epoch `e` spans `[e·len, (e+1)·len)`. The frozen
/// length is [`crate::params_devnet::EPOCH_LENGTH_BLOCKS`] (1,152); the sim uses a
/// small [`crate::params_devnet::SIM_EPOCH_LENGTH_BLOCKS`] so a run crosses several
/// boundaries — the boundary *rule* is identical, only the length differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochSchedule {
    epoch_length: u64,
}

impl EpochSchedule {
    /// Build a schedule with a non-zero epoch length.
    pub fn new(epoch_length: u64) -> Self {
        assert!(epoch_length > 0, "epoch length must be positive");
        Self { epoch_length }
    }

    /// The epoch length in blocks.
    pub fn epoch_length(&self) -> u64 {
        self.epoch_length
    }

    /// The epoch a height belongs to.
    pub fn epoch_of(&self, height: u64) -> u64 {
        height / self.epoch_length
    }

    /// The first height of `epoch`.
    pub fn epoch_start(&self, epoch: u64) -> u64 {
        epoch * self.epoch_length
    }

    /// Whether `height` is an epoch boundary (start of a new epoch).
    pub fn is_boundary(&self, height: u64) -> bool {
        height % self.epoch_length == 0
    }
}

/// A membership change staged for the next epoch boundary. committee-governance §2:
/// entry = admission (bond + candidate-net record + admission vote); exit is
/// voluntary / forced (tombstone) / stale — all effective at epoch+1, never
/// mid-stream. The *decision* to admit/remove is out of scope here (that is the
/// governance layer); this module just applies a decided change at the boundary.
#[derive(Clone)]
pub enum MembershipChange {
    /// Admit a new entity: its ML-DSA verifying key and entry self-bond.
    Admit { key: MemberKey, bond: u64 },
    /// Remove the member at `index` in the CURRENT epoch's roster (voluntary exit
    /// or stale drop; tombstoned members are removed automatically at the boundary
    /// even without an explicit change).
    Remove { index: usize },
}

/// The committee across epochs: the current epoch's [`CommitteeState`] plus staged
/// changes and the sealed history of prior epochs.
pub struct EpochCommittee {
    schedule: EpochSchedule,
    current_epoch: u64,
    current: CommitteeState,
    /// Changes to apply at the next boundary the chain crosses.
    pending: Vec<MembershipChange>,
    /// Sealed committees of past epochs, for verifying slightly-behind checkpoints.
    history: HashMap<u64, CommitteeState>,
}

impl EpochCommittee {
    /// Seed the genesis committee (epoch 0) under `schedule`.
    pub fn genesis(schedule: EpochSchedule, genesis: CommitteeState) -> Self {
        Self {
            schedule,
            current_epoch: 0,
            current: genesis,
            pending: Vec::new(),
            history: HashMap::new(),
        }
    }

    /// The epoch schedule.
    pub fn schedule(&self) -> EpochSchedule {
        self.schedule
    }

    /// The current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// The current epoch's committee state (live status; quorum is over this).
    pub fn state(&self) -> &CommitteeState {
        &self.current
    }

    /// Mutable access to the current committee (apply jail/tombstone penalties).
    pub fn state_mut(&mut self) -> &mut CommitteeState {
        &mut self.current
    }

    /// The committee state that owns `height`'s epoch — the current one for the
    /// current/future epoch, or the sealed one for a past epoch. This is the
    /// "who may sign at height h" function of §2: the set from the previous
    /// boundary, never a mid-stream one.
    pub fn state_for_height(&self, height: u64) -> &CommitteeState {
        let e = self.schedule.epoch_of(height);
        if e >= self.current_epoch {
            &self.current
        } else {
            self.history.get(&e).unwrap_or(&self.current)
        }
    }

    /// Number of staged changes awaiting the next boundary.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Stage a membership change for the next epoch boundary. It has **no effect**
    /// until [`Self::advance_to`] crosses a boundary — that is the §2 guarantee.
    pub fn stage(&mut self, change: MembershipChange) {
        self.pending.push(change);
    }

    /// Advance the machinery to `height`, sealing every epoch boundary crossed.
    /// Staged changes apply at the first boundary crossed; tombstoned members are
    /// dropped from the roster at every boundary. Idempotent for a height in the
    /// current epoch.
    pub fn advance_to(&mut self, height: u64) {
        let target = self.schedule.epoch_of(height);
        while self.current_epoch < target {
            self.seal();
        }
    }

    /// Seal the current epoch: snapshot it into history, then build the next
    /// epoch's roster (drop tombstoned + `Remove`d members, append `Admit`ted
    /// ones), carrying surviving members' status/bond/slash forward exactly.
    fn seal(&mut self) {
        let removing: HashSet<usize> = self
            .pending
            .iter()
            .filter_map(|c| match c {
                MembershipChange::Remove { index } => Some(*index),
                _ => None,
            })
            .collect();

        let cur = &self.current;
        let mut keys: Vec<MemberKey> = Vec::new();
        let mut status: Vec<MemberStatus> = Vec::new();
        let mut bond: Vec<u64> = Vec::new();
        let mut slashed: Vec<u64> = Vec::new();
        for i in 0..cur.size() {
            // Forced exit: a tombstoned member leaves the roster at the boundary
            // (it was already excluded from quorum immediately). Explicit removals
            // (voluntary/stale) leave here too.
            if removing.contains(&i) || matches!(cur.status(i), Some(MemberStatus::Tombstoned)) {
                continue;
            }
            keys.push(cur.committee().member(i).expect("in-range").clone());
            status.push(cur.status(i).expect("in-range"));
            bond.push(cur.bond(i).expect("in-range"));
            slashed.push(cur.slashed(i).expect("in-range"));
        }
        for change in self.pending.drain(..) {
            if let MembershipChange::Admit { key, bond: b } = change {
                keys.push(key);
                status.push(MemberStatus::Active);
                bond.push(b);
                slashed.push(0);
            }
        }

        let next = CommitteeState::from_parts(Committee::from_keys(keys), status, bond, slashed);
        let old = std::mem::replace(&mut self.current, next);
        self.history.insert(self.current_epoch, old);
        self.current_epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{devnet_committee, Checkpoint, MemberStatus, Vote};
    use crate::finality::{FinalityTracker, FinalizeError};
    use crate::params_devnet::{
        BOND_AMOUNT, EPOCH_LENGTH_BLOCKS, FROZEN_COMMITTEE_SIZE, FROZEN_QUORUM,
    };

    fn sched() -> EpochSchedule {
        EpochSchedule::new(8) // small epoch so tests cross boundaries cheaply
    }

    #[test]
    fn schedule_maps_heights_to_epochs_and_boundaries() {
        let s = EpochSchedule::new(EPOCH_LENGTH_BLOCKS);
        assert_eq!(s.epoch_of(0), 0);
        assert_eq!(s.epoch_of(1_151), 0);
        assert_eq!(s.epoch_of(1_152), 1);
        assert!(s.is_boundary(0) && s.is_boundary(1_152) && s.is_boundary(2_304));
        assert!(!s.is_boundary(1_151) && !s.is_boundary(1));
        assert_eq!(s.epoch_start(2), 2_304);
    }

    #[test]
    fn frozen_genesis_n_and_quorum_agree() {
        // The frozen genesis committee is N=21, quorum 15 (consensus-parameters §4).
        let (committee, _v) = devnet_committee(FROZEN_COMMITTEE_SIZE);
        assert_eq!(committee.size(), 21);
        assert_eq!(committee.quorum_threshold(), FROZEN_QUORUM);
        assert_eq!(FROZEN_QUORUM, 15);
    }

    #[test]
    fn staged_change_is_invisible_until_the_boundary() {
        let (committee, validators) = devnet_committee(4);
        let mut ec = EpochCommittee::genesis(sched(), CommitteeState::new(committee, BOND_AMOUNT));
        assert_eq!(ec.state().size(), 4);

        // Stage a removal — must NOT take effect mid-epoch.
        ec.stage(MembershipChange::Remove { index: 1 });
        ec.advance_to(5); // still epoch 0
        assert_eq!(ec.current_epoch(), 0);
        assert_eq!(ec.state().size(), 4, "staged change invisible before the boundary");

        // Cross into epoch 1 (height 8): the change applies exactly here.
        ec.advance_to(8);
        assert_eq!(ec.current_epoch(), 1);
        assert_eq!(ec.state().size(), 3, "removal applied at the boundary");
        // The surviving members are still the real validators (their keys verify).
        let cp = Checkpoint::new(8, [1; 32], [1; 32]);
        // former index 0 stays index 0; former index 2 shifts to index 1.
        let vote0 = validators[0].sign_checkpoint(&cp);
        assert!(ec.state().committee().verify_vote(&cp, &vote0));
    }

    #[test]
    fn admit_appends_at_boundary_and_new_member_can_finalize() {
        let (committee, validators) = devnet_committee(4); // genesis quorum 3
        let newcomer = crate::committee::Validator::from_seed(4, [0x4a; 32]);
        let mut ec = EpochCommittee::genesis(sched(), CommitteeState::new(committee, BOND_AMOUNT));

        ec.stage(MembershipChange::Admit { key: newcomer.verifying_key(), bond: BOND_AMOUNT });
        ec.advance_to(8); // boundary → epoch 1
        assert_eq!(ec.state().size(), 5, "admitted at the boundary");
        assert_eq!(ec.state().quorum_threshold(), 4); // ⌊2·5/3⌋+1

        // The newcomer is index 4 and its vote verifies + counts toward quorum.
        let cp = Checkpoint::new(8, [9; 32], [9; 32]);
        let mut votes: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        votes.push(newcomer.sign_checkpoint(&cp));
        let mut fin = FinalityTracker::new();
        assert!(fin.try_finalize(&cp, &votes, ec.state().committee()).is_ok());
    }

    #[test]
    fn tombstoned_member_is_dropped_at_the_next_boundary() {
        let (committee, _v) = devnet_committee(5);
        let mut ec = EpochCommittee::genesis(sched(), CommitteeState::new(committee, BOND_AMOUNT));
        // Tombstone member 2 mid-epoch (immediate quorum exclusion).
        assert!(ec.state_mut().tombstone(2, 100));
        assert_eq!(ec.state().status(2), Some(MemberStatus::Tombstoned));
        assert_eq!(ec.state().size(), 5, "roster unchanged mid-epoch");

        // At the boundary it is formally removed (forced exit, §2).
        ec.advance_to(8);
        assert_eq!(ec.state().size(), 4, "tombstoned member dropped at the boundary");
        // No surviving member is tombstoned (the roster is clean).
        for i in 0..ec.state().size() {
            assert_ne!(ec.state().status(i), Some(MemberStatus::Tombstoned));
        }
    }

    #[test]
    fn past_epoch_committee_is_retained_for_behind_checkpoints() {
        let (committee, validators) = devnet_committee(4);
        let mut ec = EpochCommittee::genesis(sched(), CommitteeState::new(committee, BOND_AMOUNT));
        // Remember an epoch-0 checkpoint's votes, then advance past the boundary.
        let cp0 = Checkpoint::new(3, [3; 32], [3; 32]); // epoch 0
        let votes0: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp0)).collect();
        ec.stage(MembershipChange::Remove { index: 0 });
        ec.advance_to(8); // now in epoch 1, roster shrank
        assert_eq!(ec.current_epoch(), 1);

        // A behind checkpoint at height 3 is still verified against epoch 0's set.
        let past = ec.state_for_height(3);
        assert_eq!(past.size(), 4, "epoch-0 committee retained intact");
        let mut fin = FinalityTracker::new();
        assert!(fin.try_finalize(&cp0, &votes0, past.committee()).is_ok());

        // ...while the current committee (height ≥ 8) is the shrunk one.
        assert_eq!(ec.state_for_height(8).size(), 3);
    }

    #[test]
    fn multiple_boundaries_apply_pending_once() {
        let (committee, _v) = devnet_committee(4);
        let mut ec = EpochCommittee::genesis(sched(), CommitteeState::new(committee, BOND_AMOUNT));
        ec.stage(MembershipChange::Remove { index: 0 });
        // Jump three epochs at once: pending applies at the first crossing only.
        ec.advance_to(24);
        assert_eq!(ec.current_epoch(), 3);
        assert_eq!(ec.state().size(), 3);
        assert_eq!(ec.pending_len(), 0);
        // A duplicate finalize attempt across the retained history is unaffected —
        // sanity that FinalizeError is still the devnet type (no shadowing).
        let _ = FinalizeError::NotAdvancing { finalized_height: 0, proposed_height: 0 };
    }
}
