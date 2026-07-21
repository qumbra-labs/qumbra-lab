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

use crate::committee::{Checkpoint, Committee, CommitteeState, Vote};

/// Which finality regime the node is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityStatus {
    /// Recent checkpoints are finalizing; the tip is within `max_lag` of finality.
    Final,
    /// The committee has stalled (or never finalized): the chain continues under
    /// probabilistic PoW confirmation until finality resumes.
    Degraded,
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
