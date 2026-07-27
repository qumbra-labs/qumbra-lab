//! Ebb-and-Flow semantics (consensus-and-network.md §4; committee-governance §3):
//! the availability/finality split, evidence-automated equivocation slashing, and
//! jail-without-slash downtime.
//!
//! - **Degraded mode.** If the committee stalls, the PoW chain keeps growing in
//!   degraded *probabilistic* mode rather than halting — "a privacy chain that
//!   stops producing blocks when k-of-N validators go dark would have traded the
//!   rental attack for a liveness hostage" (§4). [`finality_status`] reports which
//!   regime the node is in from the finality lag; finality resumes cleanly when a
//!   new checkpoint lands (demonstrated end-to-end in `node.rs`).
//! - **Equivocation → tombstone + slash, automated.** "Any node that observes two
//!   conflicting ML-DSA votes from the same validator for the same checkpoint slot
//!   can package them as an evidence transaction; the pair of signatures *is* the
//!   proof, verification is two signature checks, and the tombstone + slash
//!   executes in the state machine with no human vote anywhere in the path"
//!   (committee-gov §3). See [`verify_equivocation`] / [`punish_equivocation`].
//! - **Downtime → jail, no slash.** Modeled by [`crate::committee::CommitteeState::jail`];
//!   at N≈20 known entities an offline validator already forfeits income while
//!   jailed, so no monetary penalty is needed (committee-gov §3).

use std::collections::{HashSet, VecDeque};

use crate::committee::{Checkpoint, Committee, CommitteeState, Vote};

/// A rolling record of committee signing participation, for **downtime-jail**
/// detection (committee-governance §3; frozen §4: jail — no slash — a member that
/// signed *fewer than 33 % of the trailing 100* finalized checkpoints). Each
/// entry is the set of committee indices that signed one finalized checkpoint; the
/// window keeps the trailing `window` rounds. Detection fires only once the window
/// is full, so a fresh committee is never falsely jailed.
///
/// The comparison is exact integer arithmetic — `signed·100 < threshold_pct·rounds`
/// — so no float ever enters consensus. The window is index-based, so a membership
/// change (which reindexes the roster, [`crate::epoch`]) invalidates it; callers
/// [`Self::reset`] it at an epoch boundary.
#[derive(Clone, Debug)]
pub struct SigningWindow {
    window: usize,
    threshold_pct: u64,
    rounds: VecDeque<HashSet<usize>>,
}

impl SigningWindow {
    /// A window of `window` rounds with a `threshold_pct`% participation floor
    /// (frozen: 100, 33).
    pub fn new(window: usize, threshold_pct: u64) -> Self {
        Self { window: window.max(1), threshold_pct, rounds: VecDeque::new() }
    }

    /// Record one finalized checkpoint's signer set, evicting the oldest round
    /// past the window.
    pub fn record_round(&mut self, signers: &[usize]) {
        self.rounds.push_back(signers.iter().copied().collect());
        while self.rounds.len() > self.window {
            self.rounds.pop_front();
        }
    }

    /// Number of rounds currently held (≤ window).
    pub fn len(&self) -> usize {
        self.rounds.len()
    }

    /// Whether the trailing set is empty.
    pub fn is_empty(&self) -> bool {
        self.rounds.is_empty()
    }

    /// Whether the window is full (detection only fires when it is).
    pub fn is_full(&self) -> bool {
        self.rounds.len() >= self.window
    }

    /// How many of the held rounds `idx` signed.
    pub fn signed_count(&self, idx: usize) -> usize {
        self.rounds.iter().filter(|s| s.contains(&idx)).count()
    }

    /// Whether member `idx` is jailable for downtime: the window is full and it
    /// signed strictly fewer than `threshold_pct`% of the rounds.
    pub fn jailable(&self, idx: usize) -> bool {
        self.is_full()
            && (self.signed_count(idx) as u64) * 100 < self.threshold_pct * self.rounds.len() as u64
    }

    /// Clear the window (e.g. at an epoch boundary, where indices are reassigned).
    pub fn reset(&mut self) {
        self.rounds.clear();
    }
}

/// Which finality regime the node is in.
///
/// `Final`/`Degraded` are the Ebb-and-Flow pair. `Halting`/`Halted` are the
/// halt-height upgrade pair (issue #74, committee-and-governance §4) — they extend
/// this same surface deliberately, rather than forking a parallel status field, so
/// there is exactly one thing an operator (and the telemetry wire) has to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityStatus {
    /// Recent checkpoints are finalizing; the tip is within `max_lag` of finality.
    Final,
    /// The committee has stalled (or never finalized): the chain continues under
    /// probabilistic PoW confirmation until finality resumes.
    Degraded,
    /// The tip has reached the scheduled halt height H, but H's checkpoint has not
    /// finalized yet ([`crate::halt`]). The node is paused at the boundary and
    /// waiting for it to become final; a net stuck here has NOT completed its halt
    /// and must not be upgraded yet.
    Halting,
    /// H is finalized. The upgrade boundary is a finalized boundary — everything
    /// pre-halt is final by construction, and the binaries may now be swapped.
    Halted,
}

/// Assess the finality regime from the tip and finalized heights.
///
/// `Degraded` when nothing is finalized yet, or when the tip has outrun the
/// finalized head by more than `max_lag` blocks. Otherwise `Final`.
pub fn finality_status(tip_height: u64, finalized_height: Option<u64>, max_lag: u64) -> FinalityStatus {
    match finalized_height {
        Some(fh) if tip_height.saturating_sub(fh) <= max_lag => FinalityStatus::Final,
        _ => FinalityStatus::Degraded,
    }
}

/// Two conflicting signed votes from one validator for the same checkpoint slot —
/// the self-contained proof of equivocation (committee-gov §3).
pub struct EquivocationEvidence {
    /// First checkpoint and the validator's vote on it.
    pub cp_a: Checkpoint,
    pub vote_a: Vote,
    /// Second (conflicting) checkpoint at the SAME height and the same validator's
    /// vote on it.
    pub cp_b: Checkpoint,
    pub vote_b: Vote,
}

/// Why equivocation evidence was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// The two votes are from different signers.
    NotSameSigner,
    /// The two checkpoints are for different heights (not the same slot).
    NotSameSlot,
    /// The two checkpoints are identical — a duplicate vote, not a conflict.
    NotConflicting,
    /// At least one signature does not verify.
    InvalidSignature,
}

/// Verify equivocation evidence against the committee. On success returns the
/// offending signer's committee index. This is the entire adjudication — two
/// signature checks, no human judgement (committee-gov §3).
pub fn verify_equivocation(
    ev: &EquivocationEvidence,
    committee: &Committee,
) -> Result<usize, EvidenceError> {
    let signer = ev.vote_a.signer;
    if ev.vote_b.signer != signer {
        return Err(EvidenceError::NotSameSigner);
    }
    if ev.cp_a.height != ev.cp_b.height {
        return Err(EvidenceError::NotSameSlot);
    }
    if ev.cp_a == ev.cp_b {
        return Err(EvidenceError::NotConflicting);
    }
    if !committee.verify_vote(&ev.cp_a, &ev.vote_a) || !committee.verify_vote(&ev.cp_b, &ev.vote_b) {
        return Err(EvidenceError::InvalidSignature);
    }
    Ok(signer)
}

/// Verify equivocation evidence and, if valid, apply the automated penalty:
/// permanent tombstone + bond slash of `slash_amount` (committee-gov §3). Returns
/// the punished signer index.
pub fn punish_equivocation(
    state: &mut CommitteeState,
    ev: &EquivocationEvidence,
    slash_amount: u64,
) -> Result<usize, EvidenceError> {
    let signer = verify_equivocation(ev, state.committee())?;
    state.tombstone(signer, slash_amount);
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{devnet_committee, MemberStatus};
    use crate::params_devnet::{BOND_AMOUNT, EQUIVOCATION_SLASH_AMOUNT};

    #[test]
    fn equivocation_is_detected_and_punished() {
        // `devnet_committee` is deterministic, so this committee's keys match the
        // validators it returns — signatures verify against it.
        let (committee, validators) = devnet_committee(7);
        let signer = 3usize;
        let cp_a = Checkpoint::new(5, [0xAA; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(5, [0xBB; 32], [0xBB; 32]); // conflicting, same slot
        let ev = EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&cp_a),
            cp_a,
            vote_b: validators[signer].sign_checkpoint(&cp_b),
            cp_b,
        };
        assert_eq!(verify_equivocation(&ev, &committee), Ok(signer));

        let mut state = CommitteeState::new(committee, BOND_AMOUNT);
        assert_eq!(state.status(signer), Some(MemberStatus::Active));
        let punished = punish_equivocation(&mut state, &ev, EQUIVOCATION_SLASH_AMOUNT).unwrap();
        assert_eq!(punished, signer);
        // Tombstoned + slashed, and no longer active at any height.
        assert_eq!(state.status(signer), Some(MemberStatus::Tombstoned));
        assert_eq!(state.slashed(signer), Some(EQUIVOCATION_SLASH_AMOUNT));
        assert_eq!(state.bond(signer), Some(BOND_AMOUNT - EQUIVOCATION_SLASH_AMOUNT));
        assert!(!state.is_active(signer, u64::MAX));
    }

    #[test]
    fn evidence_negatives() {
        let (committee, validators) = devnet_committee(7);

        // Not the same slot (different heights).
        let a = Checkpoint::new(5, [0xAA; 32], [0xAA; 32]);
        let b = Checkpoint::new(6, [0xBB; 32], [0xBB; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[3].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[3].sign_checkpoint(&b),
            cp_b: b,
        };
        assert_eq!(verify_equivocation(&ev, &committee), Err(EvidenceError::NotSameSlot));

        // Not conflicting (identical checkpoint — just a duplicate vote).
        let c = Checkpoint::new(5, [0xAA; 32], [0xAA; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[3].sign_checkpoint(&c),
            cp_a: c,
            vote_b: validators[3].sign_checkpoint(&c),
            cp_b: c,
        };
        assert_eq!(verify_equivocation(&ev, &committee), Err(EvidenceError::NotConflicting));

        // Not the same signer.
        let a = Checkpoint::new(5, [0xAA; 32], [0xAA; 32]);
        let b = Checkpoint::new(5, [0xBB; 32], [0xBB; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[3].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[4].sign_checkpoint(&b),
            cp_b: b,
        };
        assert_eq!(verify_equivocation(&ev, &committee), Err(EvidenceError::NotSameSigner));

        // Invalid signature (tamper: claim signer 3 signed cp_b but supply a
        // signature over a THIRD checkpoint).
        let a = Checkpoint::new(5, [0xAA; 32], [0xAA; 32]);
        let b = Checkpoint::new(5, [0xBB; 32], [0xBB; 32]);
        let wrong = Checkpoint::new(5, [0xCC; 32], [0xCC; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[3].sign_checkpoint(&a),
            cp_a: a,
            vote_b: Vote { signer: 3, signature: validators[3].sign_checkpoint(&wrong).signature },
            cp_b: b,
        };
        assert_eq!(verify_equivocation(&ev, &committee), Err(EvidenceError::InvalidSignature));
    }

    #[test]
    fn jail_is_no_slash_and_auto_readmits() {
        let (committee, _) = devnet_committee(7);
        let mut state = CommitteeState::new(committee, BOND_AMOUNT);
        // Jail validator 2 for downtime until height 40 — no slash.
        assert!(state.jail(2, 40));
        assert_eq!(state.bond(2), Some(BOND_AMOUNT), "downtime must NOT slash");
        assert_eq!(state.slashed(2), Some(0));
        assert!(!state.is_active(2, 39), "still jailed before the term");
        assert!(state.is_active(2, 40), "auto-readmitted at the term height");
        // A tombstoned validator cannot be un-tombstoned by jailing.
        state.tombstone(5, EQUIVOCATION_SLASH_AMOUNT);
        assert!(!state.jail(5, 100));
        assert_eq!(state.status(5), Some(MemberStatus::Tombstoned));
    }

    #[test]
    fn signing_window_jails_a_dark_validator_only_when_full() {
        // Frozen shape at a small window: 33 % of a 10-round window (< 3.3 signed).
        let mut w = SigningWindow::new(10, 33);
        // Members 0,1 sign every round; member 2 signs nothing.
        for _ in 0..9 {
            w.record_round(&[0, 1]);
            // Not jailable before the window is full, even at 0 % participation.
            assert!(!w.jailable(2), "no false jail before the window fills");
        }
        w.record_round(&[0, 1]); // 10th round → full
        assert!(w.is_full());
        assert!(w.jailable(2), "0 % over a full window is jailable");
        assert!(!w.jailable(0), "100 % signer is safe");
        assert_eq!(w.signed_count(0), 10);
        assert_eq!(w.signed_count(2), 0);
    }

    #[test]
    fn signing_window_threshold_is_strict_and_integer() {
        // Exactly 33 % is NOT below 33 % (strict). 3 of 10 = 30 % < 33 % ⇒ jail;
        // 4 of 10 = 40 % ≥ 33 % ⇒ safe. (No float: 3·100 < 33·10 = 300 → 300<330.)
        let mut w = SigningWindow::new(10, 33);
        for i in 0..10 {
            let mut signers = vec![0u8 as usize];
            if i < 3 {
                signers.push(1); // member 1 signs 3 of 10
            }
            if i < 4 {
                signers.push(2); // member 2 signs 4 of 10
            }
            w.record_round(&signers);
        }
        assert!(w.jailable(1), "30 % < 33 % ⇒ jailable");
        assert!(!w.jailable(2), "40 % ≥ 33 % ⇒ safe");
        w.reset();
        assert!(w.is_empty());
        assert!(!w.jailable(1), "reset window never jails");
    }

    #[test]
    fn degraded_when_finality_lags_or_absent() {
        // Never finalized ⇒ degraded (probabilistic mode until the committee acts).
        assert_eq!(finality_status(10, None, 16), FinalityStatus::Degraded);
        // Within lag ⇒ final.
        assert_eq!(finality_status(20, Some(10), 16), FinalityStatus::Final);
        assert_eq!(finality_status(26, Some(10), 16), FinalityStatus::Final);
        // Lag exceeds threshold ⇒ degraded (committee stalled).
        assert_eq!(finality_status(27, Some(10), 16), FinalityStatus::Degraded);
    }
}
