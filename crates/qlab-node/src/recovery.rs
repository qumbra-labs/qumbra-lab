//! Finality-stall **recovery** (M10-T0-2, issue #63) — the half the Crosslink
//! feature-net left under-designed.
//!
//! Qumbra freezes the *degradation* half of Ebb-and-Flow (consensus-and-network
//! §4, [`qlab_devnet::ebbflow`]): if the committee stalls, the PoW chain keeps
//! growing in degraded probabilistic mode rather than halting. That is the
//! liveness-never-hostage property, and it is **frozen and read-only** here. What
//! this module adds is the *recovery* half — the part whose absence stalled the
//! Crosslink feature net's BFT finality from ~2026-05-12 onward with no clean way
//! back (design status update 2026-07-24): a finalizer that can crash and rejoin
//! without operator surgery, a hard guard against a restarting finalizer
//! equivocating against its own past votes, catch-up finalization after a stall,
//! and the degraded-mode reward-accounting rule.
//!
//! ## What is frozen vs what is built here
//!
//! FROZEN §4 (read-only, never touched here): quorum ([`Committee::quorum_threshold`]),
//! tombstone + slash on equivocation ([`qlab_devnet::ebbflow::punish_equivocation`]),
//! downtime jail, and the [`FinalityStatus`] degradation semantics. This module
//! only *reads* them. In particular the never-re-sign guard below is the honest
//! finalizer protecting **itself** from tripping the frozen equivocation penalty
//! — it changes nothing about how equivocation is adjudicated when it does occur.
//!
//! BUILT HERE (devnet-grade recovery): [`FinalizerState`] / [`Finalizer`] (the
//! persistent last-voted ledger + the never-re-sign-a-conflicting-checkpoint
//! invariant), catch-up scheduling ([`catch_up_slot`]), and the degraded-mode
//! committee-reward accrual rule ([`committee_accrual_finalized`]).

use std::collections::BTreeMap;

use qlab_cbserver::codec::{read_varint, write_varint, CodecError};
use qlab_devnet::committee::{Checkpoint, Validator, Vote};

use crate::emission::{coinbase, RewardSplit};
use crate::store::Hash32;

/// On-disk format version for [`FinalizerState`] persistence. Independent of the
/// RPC wire version — this is a node-local durability artifact. Reject-unknown on
/// load, matching the repo's §0 versioning discipline.
pub const FINALIZER_FORMAT_VERSION: u8 = 1;

/// Why a finalizer refused to sign a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignRefusal {
    /// This finalizer already signed a **different** checkpoint for this slot
    /// (checkpoint height). Signing `cp` would self-equivocate — exactly the
    /// conflicting-vote pair that the frozen §4 machinery tombstones and slashes
    /// ([`qlab_devnet::ebbflow::verify_equivocation`]). The guard refuses
    /// **without producing the signature**, so the conflicting vote never exists.
    WouldEquivocate {
        /// The checkpoint slot (height) already committed to.
        slot: u64,
        /// The checkpoint this finalizer already signed for that slot.
        already: Checkpoint,
    },
}

/// A committee member's **persistent** finalizer state: the minimum a finalizer
/// process must record durably so that crashing and coming back can never make it
/// equivocate, and so it can resume voting on the next cadence slot without
/// operator surgery.
///
/// The ledger is `slot (checkpoint height) → the checkpoint signed at that slot`.
/// It answers the one question the stateless [`Validator`] cannot: *have I already
/// committed to a checkpoint at this slot, and if so which one?* A real node bounds
/// this to the trailing few (un-pruned) slots; the devnet keeps them all.
///
/// **Operational invariant (see the recovery runbook):** the last-voted slot MUST
/// be persisted (`to_bytes` → fsync) *before* the corresponding vote is released to
/// the network. A crash after persisting but before broadcasting simply re-emits
/// the same vote on restart (idempotent); a crash after broadcasting but before
/// persisting is the window this guard cannot close on its own — write-ahead the
/// slot to shrink it to nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalizerState {
    signed: BTreeMap<u64, Checkpoint>,
}

impl FinalizerState {
    /// A fresh finalizer that has never voted.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest slot this finalizer has committed a vote to, if any — the
    /// "last-voted slot" a rejoining process reads to know where it left off.
    pub fn last_voted_slot(&self) -> Option<u64> {
        self.signed.keys().next_back().copied()
    }

    /// The checkpoint this finalizer signed at `slot`, if any.
    pub fn signed_at(&self, slot: u64) -> Option<&Checkpoint> {
        self.signed.get(&slot)
    }

    /// Number of slots on record.
    pub fn len(&self) -> usize {
        self.signed.len()
    }

    /// Whether nothing has been signed yet.
    pub fn is_empty(&self) -> bool {
        self.signed.is_empty()
    }

    /// Decide whether signing `cp` is permitted **and** record the intent.
    ///
    /// - `Ok(true)` — this is a fresh slot (or a re-affirmation of the exact same
    ///   checkpoint after a crash); the intent is now recorded. `true` means the
    ///   ledger changed (a new slot), `false` means it was an idempotent repeat.
    /// - `Err(WouldEquivocate)` — a **different** checkpoint is already committed
    ///   for this slot; the ledger is left unchanged.
    ///
    /// This is the pure state transition; [`Finalizer::sign`] wraps it with the
    /// actual signature so a refusal never yields a vote.
    pub fn authorize(&mut self, cp: &Checkpoint) -> Result<bool, SignRefusal> {
        match self.signed.get(&cp.height) {
            Some(prev) if prev != cp => Err(SignRefusal::WouldEquivocate {
                slot: cp.height,
                already: *prev,
            }),
            Some(_) => Ok(false), // idempotent: same checkpoint already committed
            None => {
                self.signed.insert(cp.height, *cp);
                Ok(true)
            }
        }
    }

    /// Serialize for durable storage. `version(1) ‖ n(varint) ‖ [slot(8 LE) ‖
    /// checkpoint(72)]×n`, slots ascending (BTree order → deterministic bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(FINALIZER_FORMAT_VERSION);
        write_varint(&mut out, self.signed.len() as u64);
        for (slot, cp) in &self.signed {
            out.extend_from_slice(&slot.to_le_bytes());
            write_checkpoint(&mut out, cp);
        }
        out
    }

    /// Reload persisted state, rejecting an unknown version and trailing bytes
    /// (the §0 reject-unknown discipline the whole stack follows).
    pub fn from_bytes(b: &[u8]) -> Result<Self, CodecError> {
        let mut pos = 0usize;
        let v = *b.get(pos).ok_or(CodecError::Truncated { what: "version" })?;
        pos += 1;
        if v != FINALIZER_FORMAT_VERSION {
            return Err(CodecError::BadVersion { got: v });
        }
        let n = read_varint(b, &mut pos)?;
        let mut signed = BTreeMap::new();
        for _ in 0..n {
            let slot = read_u64(b, &mut pos)?;
            let cp = read_checkpoint(b, &mut pos)?;
            signed.insert(slot, cp);
        }
        if pos != b.len() {
            return Err(CodecError::TrailingBytes { remaining: b.len() - pos });
        }
        Ok(Self { signed })
    }
}

/// A committee member's signing side under the never-double-sign guard: a stateless
/// [`Validator`] key paired with its persistent [`FinalizerState`]. This is the
/// unit that "goes down and comes back": persist [`Self::state`]`.to_bytes()`,
/// then [`Self::restore`] it after a restart to resume voting without equivocating.
pub struct Finalizer {
    validator: Validator,
    state: FinalizerState,
}

impl Finalizer {
    /// A fresh finalizer for `validator` with an empty ledger.
    pub fn new(validator: Validator) -> Self {
        Self { validator, state: FinalizerState::new() }
    }

    /// Rejoin: reconstruct a finalizer from its signing key and a previously
    /// persisted ledger. This is the crash-restart path — the resumed finalizer
    /// carries every past commitment, so the never-re-sign guard survives a reboot.
    pub fn restore(validator: Validator, state: FinalizerState) -> Self {
        Self { validator, state }
    }

    /// The committee index of the underlying validator.
    pub fn index(&self) -> usize {
        self.validator.index
    }

    /// The persistent ledger (persist this after every successful sign).
    pub fn state(&self) -> &FinalizerState {
        &self.state
    }

    /// The highest slot signed so far — where a rejoining finalizer resumes from.
    pub fn last_voted_slot(&self) -> Option<u64> {
        self.state.last_voted_slot()
    }

    /// Sign `cp` under the never-re-sign-a-conflicting-checkpoint invariant.
    ///
    /// On success the vote is returned and the intent recorded in [`Self::state`]
    /// (persist it before broadcasting). On a conflicting slot the signature is
    /// **never produced** — the guard is the point: an honest finalizer that
    /// restarted mid-round cannot be tricked into emitting the second half of an
    /// equivocation pair.
    pub fn sign(&mut self, cp: &Checkpoint) -> Result<Vote, SignRefusal> {
        self.state.authorize(cp)?;
        Ok(self.validator.sign_checkpoint(cp))
    }
}

/// The **catch-up** finalization slot after a stall: the highest cadence multiple
/// at or below `tip`, or `None` if `tip` is below the first slot. Steady-state
/// finalization walks successive slots
/// ([`qlab_devnet::finality::next_checkpoint_height`]); recovery after a long
/// stall instead jumps straight to the newest available slot, which the
/// strictly-advancing finalization rule already permits (skipping the stalled
/// intermediate slots — no per-slot back-fill, no retroactive canonical-block
/// designation à la Crosslink).
pub fn catch_up_slot(tip: u64, cadence: u64) -> Option<u64> {
    if cadence == 0 {
        return None;
    }
    let slot = (tip / cadence) * cadence;
    if slot == 0 {
        None
    } else {
        Some(slot)
    }
}

/// **Degraded-mode committee-reward accrual (devnet-grade, testnet-tunable — NOT
/// frozen; coordinator inline stamp 2026-07-24).**
///
/// Committee rewards accrue **only for finalized checkpoints**: the committee's
/// 15 % coinbase share ([`RewardSplit`], frozen §3) is earned for a block only
/// once that block is under the finalized head. A finality stall therefore means
/// **zero committee income for the stalled span** — there is no retroactive manual
/// canonical-block designation (the Crosslink anti-pattern the design §4 status
/// update calls out). The unfinalized span's committee share simply does not
/// accrue here; how the emission telescoping ultimately distributes it is a ledger
/// question M11+ revisits.
///
/// Returns the total committee reward accrued up to and including the finalized
/// head. `None` finalized ⇒ nothing has finalized ⇒ `0` (a stall from genesis
/// earns the committee nothing, by construction).
pub fn committee_accrual_finalized(finalized_height: Option<u64>) -> u64 {
    match finalized_height {
        None => 0,
        Some(fh) => (0..=fh).map(|h| RewardSplit::of(coinbase(h)).committee).sum(),
    }
}

/// The committee reward that accrues when the finalized head advances from
/// `prev_final` to `new_final` (exclusive → inclusive) — the incremental form of
/// [`committee_accrual_finalized`]. Blocks beyond `new_final` (the stalled/
/// unfinalized span) contribute nothing. If `new_final` does not advance past
/// `prev_final`, the accrual is `0`.
pub fn committee_accrual_for_span(prev_final: Option<u64>, new_final: u64) -> u64 {
    let start = prev_final.map_or(0, |h| h + 1);
    if new_final < start {
        return 0;
    }
    (start..=new_final).map(|h| RewardSplit::of(coinbase(h)).committee).sum()
}

// ---- Checkpoint (de)serialization for the finalizer ledger ------------------
// height(8 LE) ‖ block_hash(32) ‖ root(32) = 72 B. Hand-rolled LE, matching the
// consensus stack's zero-serde convention (devnet objects carry no serde).

fn write_checkpoint(out: &mut Vec<u8>, cp: &Checkpoint) {
    out.extend_from_slice(&cp.height.to_le_bytes());
    out.extend_from_slice(&cp.block_hash);
    out.extend_from_slice(&cp.root);
}

fn read_checkpoint(b: &[u8], pos: &mut usize) -> Result<Checkpoint, CodecError> {
    let height = read_u64(b, pos)?;
    let block_hash = read_hash32(b, pos)?;
    let root = read_hash32(b, pos)?;
    Ok(Checkpoint::new(height, block_hash, root))
}

fn read_u64(b: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    let end = *pos + 8;
    let slice = b.get(*pos..end).ok_or(CodecError::Truncated { what: "u64" })?;
    *pos = end;
    Ok(u64::from_le_bytes(slice.try_into().unwrap()))
}

fn read_hash32(b: &[u8], pos: &mut usize) -> Result<Hash32, CodecError> {
    let end = *pos + 32;
    let slice = b.get(*pos..end).ok_or(CodecError::Truncated { what: "hash32" })?;
    *pos = end;
    Ok(slice.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::devnet_committee;
    use qlab_devnet::finality::{next_checkpoint_height, FinalityTracker};
    use qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS as CADENCE;

    fn cp(height: u64, tag: u8) -> Checkpoint {
        Checkpoint::new(height, [tag; 32], [tag; 32])
    }

    /// THE hard invariant (test-locked): a finalizer will re-affirm the exact
    /// checkpoint it already signed for a slot, but will NEVER sign a *conflicting*
    /// checkpoint for that slot — and no signature is produced on refusal.
    #[test]
    fn never_re_signs_a_conflicting_checkpoint() {
        // A finalizer's signing key stands alone here — the guard is about this
        // finalizer's own votes, independent of committee verification.
        let mut f = Finalizer::new(Validator::from_seed(0, [7u8; 32]));

        let a = cp(8, 0xAA);
        let vote_a = f.sign(&a).expect("first sign at slot 8 is allowed");
        assert_eq!(vote_a.signer, 0);
        assert_eq!(f.last_voted_slot(), Some(8));

        // Idempotent: re-signing the SAME checkpoint (e.g. a retry after a crash
        // before the vote was broadcast) is allowed and yields the same vote.
        let vote_a2 = f.sign(&a).expect("re-affirming the same checkpoint is allowed");
        assert_eq!(vote_a2.signer, 0);

        // A DIFFERENT checkpoint at the same slot is refused — this is the guard.
        // (`Vote` implements neither `Debug` nor `PartialEq`, so we match the Err.)
        let b = cp(8, 0xBB);
        match f.sign(&b) {
            Err(SignRefusal::WouldEquivocate { slot, already }) => {
                assert_eq!(slot, 8);
                assert_eq!(already, a, "must refuse to equivocate against its slot-8 vote");
            }
            Ok(_) => panic!("guard breached: signed a conflicting slot-8 checkpoint"),
        }
        // The ledger is unchanged (still committed to `a`, not `b`).
        assert_eq!(f.state().signed_at(8), Some(&a));

        // A later slot is fine — the guard is per-slot, not a freeze.
        f.sign(&cp(16, 0xCC)).expect("a fresh higher slot is allowed");
        assert_eq!(f.last_voted_slot(), Some(16));
    }

    /// The guard MUST survive a crash-restart: persist the ledger, reload it into a
    /// fresh finalizer, and the conflicting checkpoint is still refused. Without
    /// persistence a rebooted finalizer would happily equivocate (exactly the
    /// Crosslink-class restart hazard).
    #[test]
    fn guard_survives_restart_via_persistence() {
        // The same 32-byte seed reconstructs the same signing key across a restart
        // (real validators reload their key from their keystore; here the seed is
        // that keystore stand-in).
        let seed = [0x5Au8; 32];

        let a = cp(8, 0x11);
        let bytes = {
            let mut f = Finalizer::new(Validator::from_seed(3, seed));
            f.sign(&a).unwrap();
            f.state().to_bytes()
        };

        // --- process dies here; only `bytes` survived on disk ---

        let restored = FinalizerState::from_bytes(&bytes).expect("ledger round-trips");
        assert_eq!(restored.last_voted_slot(), Some(8));
        let mut f = Finalizer::restore(Validator::from_seed(3, seed), restored);

        // Resumes cleanly: re-affirming `a` still works…
        f.sign(&a).expect("re-affirm after restart");
        // …but the conflicting checkpoint is STILL refused after the reboot.
        match f.sign(&cp(8, 0x22)) {
            Err(SignRefusal::WouldEquivocate { slot, already }) => {
                assert_eq!(slot, 8);
                assert_eq!(already, a);
            }
            Ok(_) => panic!("guard did not survive restart: signed a conflicting checkpoint"),
        }
    }

    #[test]
    fn finalizer_state_roundtrips_and_rejects_bad_version_and_trailing() {
        let mut s = FinalizerState::new();
        s.authorize(&cp(8, 1)).unwrap();
        s.authorize(&cp(16, 2)).unwrap();
        s.authorize(&cp(24, 3)).unwrap();
        let bytes = s.to_bytes();
        assert_eq!(FinalizerState::from_bytes(&bytes).unwrap(), s);

        // Unknown version rejected.
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert!(matches!(FinalizerState::from_bytes(&bad), Err(CodecError::BadVersion { got: 2 })));

        // Trailing byte rejected.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(
            FinalizerState::from_bytes(&extra),
            Err(CodecError::TrailingBytes { .. })
        ));

        // Truncation rejected.
        assert!(FinalizerState::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        // Empty ledger round-trips too.
        let empty = FinalizerState::new();
        assert_eq!(FinalizerState::from_bytes(&empty.to_bytes()).unwrap(), empty);
    }

    /// Catch-up after a stall: a rejoining finalizer resumes on the next cadence
    /// slot (successive scheduling), and the committee can finalize a LATER slot
    /// directly, skipping the stalled span — the strictly-advancing rule permits it.
    #[test]
    fn catch_up_resumes_and_finalizes_a_later_slot_directly() {
        // Steady-state scheduling returns successive slots…
        assert_eq!(next_checkpoint_height(Some(8), 40, CADENCE), Some(16));
        // …but catch-up jumps to the newest available slot at/below the tip.
        assert_eq!(catch_up_slot(40, CADENCE), Some(40)); // 40 = 5·8
        assert_eq!(catch_up_slot(41, CADENCE), Some(40)); // highest ≤ 41
        assert_eq!(catch_up_slot(7, CADENCE), None); // below the first slot

        // The finalization rule accepts a direct jump over the stalled span.
        let (committee, validators) = devnet_committee(4); // quorum = 3
        let mut fin = FinalityTracker::new();
        let c8 = cp(8, 8);
        let v8: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&c8)).collect();
        fin.try_finalize(&c8, &v8, &committee).unwrap();
        assert_eq!(fin.finalized_height(), Some(8));

        // Long stall: tip ran to 40, finality stuck at 8. Recover by finalizing
        // slot 40 DIRECTLY (skipping 16/24/32) — no back-fill.
        let recover = catch_up_slot(40, CADENCE).unwrap();
        let c40 = cp(recover, 40);
        let v40: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&c40)).collect();
        fin.try_finalize(&c40, &v40, &committee).unwrap();
        assert_eq!(fin.finalized_height(), Some(40), "finality jumped 8 → 40 on recovery");
    }

    /// Degraded-mode accounting: the committee earns nothing for the stalled span.
    #[test]
    fn committee_accrues_only_for_finalized_span() {
        // Nothing finalized ⇒ zero committee income (a stall from genesis).
        assert_eq!(committee_accrual_finalized(None), 0);

        // Finalized head at 8: committee earned the 15 % share of coinbase(0..=8).
        let up_to_8: u64 = (0..=8).map(|h| RewardSplit::of(coinbase(h)).committee).sum();
        assert_eq!(committee_accrual_finalized(Some(8)), up_to_8);
        assert!(up_to_8 > 0);

        // Tip ran to 40 but finality is stuck at 8: income is STILL only up-to-8.
        // The 9..=40 span produced blocks but, being unfinalized, earns the
        // committee nothing — the whole point of the rule.
        assert_eq!(
            committee_accrual_finalized(Some(8)),
            up_to_8,
            "the stalled 9..=40 span accrues no committee income"
        );

        // Incremental form: advancing 8 → 40 on recovery accrues the 9..=40 share.
        let span_9_40: u64 = (9..=40).map(|h| RewardSplit::of(coinbase(h)).committee).sum();
        assert_eq!(committee_accrual_for_span(Some(8), 40), span_9_40);
        assert!(span_9_40 > 0);
        // A non-advancing "recovery" (still stuck at 8) accrues nothing.
        assert_eq!(committee_accrual_for_span(Some(8), 8), 0);
        assert_eq!(committee_accrual_for_span(Some(8), 5), 0);
        // Full-chain identity: up-to-8 + span(9..=40) == up-to-40.
        assert_eq!(up_to_8 + span_9_40, committee_accrual_finalized(Some(40)));
    }
}
