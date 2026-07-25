//! Cross-message checkpoint-vote accumulation (M10-T0-5, issue #70).
//!
//! The finality committee is split across nodes (the T0 net runs 21 keys 6/5/5/5),
//! so **no single gossip message ever carries a quorum**. Before this module,
//! [`crate::finality::FinalityTracker::try_finalize`] counted only the votes handed
//! to one call, and an honest 6-vote announcement returned `InsufficientQuorum` and
//! was dropped — distributed finality never formed (Phase B-lite headline finding).
//!
//! [`VoteTally`] is the accumulator that closes that gap: it de-duplicates verified,
//! active votes by signer index across *any number* of messages, per checkpoint
//! variant, until the distinct-active count reaches quorum — at which point the
//! owning node hands the accumulated set to the **unchanged** `try_finalize` (the
//! single, authoritative quorum gate; the tally only *accumulates* evidence, it
//! never lowers the bar — task-book S4).
//!
//! ## What this module does NOT do
//! It performs **no crypto**. Callers pass votes that are already signature-verified
//! against the checkpoint height's epoch roster and already active-filtered
//! (tombstoned/jailed excluded — task-book S4). The tally is pure book-keeping; it
//! is deliberately dependency-light so it can live beside `finality`.
//!
//! ## Bounded state (task-book S6)
//! A hostile peer spraying vote sets for arbitrary heights/roots must not grow node
//! state without bound. Three named caps enforce this:
//!   - only heights in `(finalized, tip + TALLY_TIP_SLACK]` are tallied;
//!   - at most [`MAX_VARIANTS_PER_SLOT`] distinct checkpoint variants per height;
//!   - at most [`MAX_TALLIED_SLOTS`] distinct heights at once (newest kept — a long
//!     stall's catch-up finalizes the newest slot directly, so the newest slots are
//!     the load-bearing ones).
//! Entries are dropped on finalization or when they fall behind the finalized head.
//! The tally needs **no persistence** — it rebuilds from re-gossip, and finalized
//! checkpoints already survive via the finality tracker / block log (task-book S7).
//!
//! **Caps are devnet-grade, testnet-tunable — NOT frozen.**

use std::collections::BTreeMap;

use crate::committee::{Checkpoint, Vote};

/// Max distinct checkpoint **heights** the tally holds at once. An honest run has
/// ~1 live slot (cadence 8, finality keeps pace); a stall grows `tip − finalized`,
/// but only the newest slots matter for catch-up, so older ones are evicted.
pub const MAX_TALLIED_SLOTS: usize = 8;

/// Max distinct checkpoint **variants** (same height, different block_hash/root) the
/// tally holds per height. An honest committee produces one; a Byzantine minority
/// could produce a few. Small cap bounds the equivocation-spray surface.
pub const MAX_VARIANTS_PER_SLOT: usize = 4;

/// How far **above the local tip** a checkpoint height may still be tallied. A
/// follower slightly behind its peers can legitimately receive votes for a slot up
/// to one cadence ahead of its own tip; this slack (= one cadence) absorbs that
/// while the upper bound still blocks a junk-high-height eviction attack.
pub const TALLY_TIP_SLACK: u64 = crate::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// Whether `height` is inside the tally window `(finalized, tip + slack]`. A height
/// at or below the finalized head is stale; one beyond `tip + slack` is rejected so
/// junk-high heights cannot evict legitimate near-tip slots. When nothing is finalized
/// yet, even genesis (height 0) is a valid first checkpoint — the finality tracker
/// permits any height as the first finalize.
fn in_window(height: u64, finalized: Option<u64>, tip: u64) -> bool {
    let above_floor = match finalized {
        Some(f) => height > f,
        None => true,
    };
    above_floor && height <= tip.saturating_add(TALLY_TIP_SLACK)
}

/// One checkpoint variant's accumulated votes: the checkpoint itself plus the votes
/// seen for it, keyed by signer index (so a signer is counted at most once).
#[derive(Clone)]
struct Variant {
    cp: Checkpoint,
    votes: BTreeMap<usize, Vote>,
}

/// The result of feeding a vote set into the tally for one variant.
#[derive(Clone)]
pub struct AddOutcome {
    /// Whether this call added at least one previously-unseen signer to the variant.
    pub grew: bool,
    /// Distinct signers accumulated for this variant so far.
    pub total: usize,
    /// The full accumulated vote set for this variant (signer-ascending) — this is
    /// what the owning node relays onward and, on quorum, re-verifies + finalizes.
    pub accumulated: Vec<Vote>,
}

/// A bounded, per-variant checkpoint-vote accumulator. See the module docs.
#[derive(Clone, Default)]
pub struct VoteTally {
    /// height → the distinct checkpoint variants tallied at that height.
    slots: BTreeMap<u64, Vec<Variant>>,
}

impl VoteTally {
    /// A fresh, empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate `active_votes` (already signature-verified, active, in-committee)
    /// for `cp`. Prunes stale/ahead slots first, enforces the window and the slot /
    /// variant caps, then de-duplicates by signer. Returns whether the variant grew,
    /// its current distinct-signer total, and the full accumulated set.
    ///
    /// A call for an out-of-window height, or one that would exceed a cap without
    /// growing an existing entry, is a no-op (`grew = false, total = 0`).
    pub fn add(
        &mut self,
        cp: &Checkpoint,
        active_votes: &[Vote],
        finalized: Option<u64>,
        tip: u64,
    ) -> AddOutcome {
        self.prune(finalized, tip);
        if !in_window(cp.height, finalized, tip) {
            return AddOutcome { grew: false, total: 0, accumulated: Vec::new() };
        }

        // Find (or admit) the variant for this exact checkpoint at its height.
        let variants = self.slots.entry(cp.height).or_default();
        let idx = match variants.iter().position(|v| &v.cp == cp) {
            Some(i) => i,
            None => {
                if variants.len() >= MAX_VARIANTS_PER_SLOT {
                    // Variant cap hit — refuse the new variant (spray protection).
                    return AddOutcome { grew: false, total: 0, accumulated: Vec::new() };
                }
                variants.push(Variant { cp: *cp, votes: BTreeMap::new() });
                variants.len() - 1
            }
        };

        // If admitting this height newly exceeds the slot cap, keep the newest
        // heights and drop the lowest — unless THIS height is the lowest, in which
        // case it is the one refused (evict-nothing, undo the just-added variant).
        if self.slots.len() > MAX_TALLIED_SLOTS {
            let lowest = *self.slots.keys().next().expect("non-empty");
            if lowest == cp.height {
                // This new slot is the oldest — do not admit it over live newer ones.
                self.slots.remove(&cp.height);
                return AddOutcome { grew: false, total: 0, accumulated: Vec::new() };
            }
            self.slots.remove(&lowest);
        }

        let variant = &mut self.slots.get_mut(&cp.height).expect("slot present")[idx];
        let before = variant.votes.len();
        for v in active_votes {
            variant.votes.entry(v.signer).or_insert_with(|| v.clone());
        }
        let total = variant.votes.len();
        let accumulated: Vec<Vote> = variant.votes.values().cloned().collect();
        AddOutcome { grew: total > before, total, accumulated }
    }

    /// Drop the slot at `height` (called once its checkpoint is finalized).
    pub fn on_finalized(&mut self, height: u64) {
        self.slots.remove(&height);
    }

    /// Drop everything at or below the finalized head, and anything beyond
    /// `tip + slack` (heights that can no longer become the next finalized slot, or
    /// junk-ahead heights).
    pub fn prune(&mut self, finalized: Option<u64>, tip: u64) {
        let high = tip.saturating_add(TALLY_TIP_SLACK);
        self.slots.retain(|&h, _| {
            let above = match finalized {
                Some(f) => h > f,
                None => true,
            };
            above && h <= high
        });
    }

    /// Distinct variants tracked at `height` (test/observability hook).
    pub fn variant_count(&self, height: u64) -> usize {
        self.slots.get(&height).map_or(0, |v| v.len())
    }

    /// Distinct heights currently tracked (test/observability hook).
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Distinct accumulated signers for the exact checkpoint `cp` (test hook).
    pub fn total_for(&self, cp: &Checkpoint) -> usize {
        self.slots
            .get(&cp.height)
            .and_then(|vs| vs.iter().find(|v| &v.cp == cp))
            .map_or(0, |v| v.votes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{devnet_committee, Validator};

    fn cp(height: u64, tag: u8) -> Checkpoint {
        Checkpoint::new(height, [tag; 32], [tag; 32])
    }

    /// Sign `cp` with validators `idxs` (real ML-DSA votes; the tally does not
    /// verify but the votes must be well-formed `Vote`s).
    fn votes(vals: &[Validator], c: &Checkpoint, idxs: &[usize]) -> Vec<Vote> {
        idxs.iter().map(|&i| vals[i].sign_checkpoint(c)).collect()
    }

    /// The core blocker-3 regression: distinct signers accumulate across separate
    /// messages for the SAME checkpoint (announce {0..5}, later {6..10} ⇒ 11).
    #[test]
    fn accumulates_distinct_signers_across_calls() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        let c = cp(8, 0x08);

        let r1 = t.add(&c, &votes(&vals, &c, &[0, 1, 2, 3, 4, 5]), None, 8);
        assert!(r1.grew && r1.total == 6);

        let r2 = t.add(&c, &votes(&vals, &c, &[6, 7, 8, 9, 10]), None, 8);
        assert!(r2.grew && r2.total == 11, "late votes accumulate: {}", r2.total);
        assert_eq!(r2.accumulated.len(), 11);
        assert_eq!(t.total_for(&c), 11);
    }

    #[test]
    fn dedups_same_signer() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        let c = cp(8, 1);
        t.add(&c, &votes(&vals, &c, &[0, 1, 2]), None, 8);
        let r = t.add(&c, &votes(&vals, &c, &[2, 3]), None, 8); // signer 2 repeats
        assert_eq!(r.total, 4, "signer 2 counted once");
        assert!(r.grew, "signer 3 is new");
        let dup = t.add(&c, &votes(&vals, &c, &[0, 1]), None, 8); // all already seen
        assert!(!dup.grew);
    }

    #[test]
    fn ignores_stale_and_future_heights() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        // finalized 8, tip 16 → window (8, 24].
        let stale = cp(8, 8); // == finalized head, stale
        assert!(!t.add(&stale, &votes(&vals, &stale, &[0]), Some(8), 16).grew);
        let future = cp(25, 25); // 25 > 16 + 8
        assert!(!t.add(&future, &votes(&vals, &future, &[0]), Some(8), 16).grew);
        let ok = cp(16, 16);
        assert!(t.add(&ok, &votes(&vals, &ok, &[0]), Some(8), 16).grew);
    }

    #[test]
    fn genesis_height_zero_is_in_window_when_nothing_finalized() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        let g = cp(0, 0);
        // The binary finalizes genesis (height 0) as its first checkpoint.
        assert!(t.add(&g, &votes(&vals, &g, &[0]), None, 0).grew, "genesis is finalizable first");
        // Once height 0 is the finalized head, it is stale.
        assert!(!t.add(&g, &votes(&vals, &g, &[1]), Some(0), 8).grew);
    }

    #[test]
    fn variant_cap_bounds_per_height() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        // MAX_VARIANTS_PER_SLOT + 2 distinct variants at one height.
        for tag in 0..(MAX_VARIANTS_PER_SLOT as u8 + 2) {
            let c = cp(8, tag);
            t.add(&c, &votes(&vals, &c, &[0]), None, 8);
        }
        assert_eq!(t.variant_count(8), MAX_VARIANTS_PER_SLOT, "variant cap holds");
    }

    #[test]
    fn slot_cap_keeps_newest() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        // Spray many distinct in-window heights; tip high so all are in window.
        // Heights 8,16,…; MAX_TALLIED_SLOTS + 5 of them.
        let n = (MAX_TALLIED_SLOTS + 5) as u64;
        let tip = (n + 2) * 8;
        for k in 1..=n {
            let h = k * 8;
            let c = cp(h, h as u8);
            t.add(&c, &votes(&vals, &c, &[0]), None, tip);
        }
        assert_eq!(t.slot_count(), MAX_TALLIED_SLOTS, "slot cap holds under a height spray");
        // The newest MAX_TALLIED_SLOTS heights are the ones kept.
        let newest_low = (n - MAX_TALLIED_SLOTS as u64 + 1) * 8;
        assert_eq!(t.variant_count(newest_low), 1, "newest slots retained");
        assert_eq!(t.variant_count(8), 0, "oldest slot evicted");
    }

    #[test]
    fn on_finalized_and_prune_drop_slots() {
        let (_c, vals) = devnet_committee(21);
        let mut t = VoteTally::new();
        let c16 = cp(16, 16);
        let c24 = cp(24, 24);
        t.add(&c16, &votes(&vals, &c16, &[0]), None, 30);
        t.add(&c24, &votes(&vals, &c24, &[0]), None, 30);
        assert_eq!(t.slot_count(), 2);
        t.on_finalized(16);
        assert_eq!(t.variant_count(16), 0);
        assert_eq!(t.slot_count(), 1);
        // Prune drops the height-24 slot once finality passes it.
        t.prune(Some(24), 30);
        assert_eq!(t.slot_count(), 0);
    }
}
