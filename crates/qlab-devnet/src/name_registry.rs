//! The name registry — a replay of committed riders (lab #367 stage 3, moved
//! here from `qlab-node` by lab #660).
//!
//! Design walls: `name-service-decision.md` D1–D2 (the registry is chain
//! state, bulk-synced and resolved locally) and the brief's N4–N6 (write-once
//! records, permissionless renewal, expiry + grace). "Resolved locally" only
//! works if every resolver runs the SAME replay — the node folding blocks in
//! `apply_state`, a wallet paging `/v1/names`, an auditor re-deriving from the
//! log — and #586 is what a second implementation of one rider rule costs.
//! This module is that one replay; it lives in the crate every consumer
//! already depends on, and it takes **rider bytes**, not a node type, because
//! rider bytes are exactly what `/v1/names` serves (`BlockNames::riders`) and
//! exactly the one field the node's `StoredTx` contributed.
//!
//! What deliberately did NOT move: the `names.bin` sidecar I/O. That is the
//! node's datadir layout, not a shared rule — it stays in
//! `qlab-node::name_registry`, which re-exports these types.
//!
//! The `serde` derives are gated behind this crate's off-by-default `serde`
//! feature (the sidecar needs them; no other consumer does) — see the
//! feature's note in `Cargo.toml`.

use std::collections::BTreeMap;

use crate::header::Hash32;
use crate::names::{decode_rider, extended_expiry, NameOp, NameView, RiderError, COMMIT_MAX_AGE};

/// One registered name: the bound record and its clock. Write-once (N4) —
/// nothing here is ever mutated except `expiry`, and that only forward.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NameEntry {
    /// Record kind (`names::RECORD_KIND_L1_ADDRESS` at v1).
    pub kind: u8,
    /// The bound payment address, exactly as revealed.
    pub address: Vec<u8>,
    /// Height of the registering reveal.
    pub registered: u64,
    /// End-of-term height (grace excluded; `names::reopens_at` adds it).
    pub expiry: u64,
}

/// The registry: every in-window commit and every current registration.
///
/// `BTreeMap` on both sides for a deterministic serialized form — two nodes
/// at the same height must produce byte-identical sidecars.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NameRegistry {
    /// COMMIT rider hash → height it was included at. Pruned once older than
    /// `COMMIT_MAX_AGE` — a dead commit can never satisfy a reveal, and the
    /// prune is a deterministic function of height, so replay agrees.
    commits: BTreeMap<Hash32, u64>,
    /// name → its current (or expired-in-place) registration. Entries are
    /// kept past grace and overwritten by the next legal reveal — the map is
    /// the registry's whole history of *current* bindings, not an event log.
    names: BTreeMap<Vec<u8>, NameEntry>,
}

impl NameRegistry {
    /// Apply one block's riders at `height`, **one entry per transaction in
    /// block order, the absent `[0x00]` included** — the same shape the block
    /// body commits to and `/v1/names` serves, so the same-block tie rule
    /// (earliest wins by tx order) needs no second numbering scheme.
    ///
    /// Callers have already validated the block (`validate_body*` runs before
    /// any state fold, and a `/v1/names` page carries committed bodies); a
    /// rider that fails to decode here is therefore log corruption or a logic
    /// error, and is returned as the codec's own verdict — with the offending
    /// transaction's index — rather than ignored.
    pub fn apply_block_riders<'a>(
        &mut self,
        height: u64,
        riders: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), (usize, RiderError)> {
        // Deterministic prune: commits too old to satisfy any reveal at or
        // after this height. `height - MAX_AGE` is the oldest height a commit
        // included there could still be revealed from.
        let horizon = height.saturating_sub(COMMIT_MAX_AGE);
        self.commits.retain(|_, h| *h >= horizon);

        for (i, rider) in riders.into_iter().enumerate() {
            let op = decode_rider(rider).map_err(|e| (i, e))?;
            match op {
                None => {}
                Some(NameOp::Commit { commit }) => {
                    // First inclusion wins for window purposes; a re-commit of
                    // the same hash refreshes nothing (the earlier height is
                    // the one the window was entered at). `entry` keeps the
                    // earliest, deterministically.
                    self.commits.entry(commit).or_insert(height);
                }
                Some(NameOp::Reveal { record, .. }) => {
                    // Validation already enforced uniqueness/grammar/window;
                    // by construction this is a fresh registration or a
                    // legal past-grace re-registration (the N6 rebinding).
                    self.names.insert(
                        record.name.clone(),
                        NameEntry {
                            kind: record.kind,
                            address: record.address.clone(),
                            registered: height,
                            expiry: extended_expiry(None, height),
                        },
                    );
                }
                Some(NameOp::Renew { name }) => {
                    if let Some(entry) = self.names.get_mut(&name) {
                        entry.expiry = extended_expiry(Some(entry.expiry), height);
                    }
                    // A renewal of an unknown name was refused by validation;
                    // reaching here without an entry would mean replaying a
                    // block that never validated — nothing to do but nothing
                    // to corrupt either.
                }
            }
        }
        Ok(())
    }

    /// The entry for `name`, if any — expired entries included (the caller
    /// owns the expiry comparison; `names::reopens_at` is the horizon).
    pub fn entry(&self, name: &[u8]) -> Option<&NameEntry> {
        self.names.get(name)
    }

    /// Number of names with an entry (current or expired-in-place).
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the registry holds nothing at all.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.commits.is_empty()
    }

    /// Iterate registrations in name order (deterministic — serving and
    /// audit both lean on it).
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &NameEntry)> {
        self.names.iter()
    }
}

impl NameView for NameRegistry {
    fn commit_included_in(&self, commit: &Hash32, min_h: u64, max_h: u64) -> bool {
        self.commits.get(commit).is_some_and(|h| (min_h..=max_h).contains(h))
    }
    fn registration_expiry(&self, name: &[u8]) -> Option<u64> {
        self.names.get(name).map(|e| e.expiry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::{
        commit_hash, encode_rider, reopens_at, NameRecord, L1_ADDRESS_LEN, NAME_TERM_BLOCKS,
        RECORD_KIND_L1_ADDRESS,
    };

    /// One block's riders, the client shape: one byte-vector per transaction,
    /// `[0x00]` for a rider-free tx — what `BlockNames::riders` carries.
    fn riders(ops: &[Option<&NameOp>]) -> Vec<Vec<u8>> {
        ops.iter().map(|op| encode_rider(*op)).collect()
    }

    fn apply(reg: &mut NameRegistry, height: u64, ops: &[Option<&NameOp>]) {
        let r = riders(ops);
        reg.apply_block_riders(height, r.iter().map(Vec::as_slice)).unwrap();
    }

    fn record() -> NameRecord {
        NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: b"alice".to_vec(),
            address: vec![0xAB; L1_ADDRESS_LEN],
        }
    }

    #[test]
    fn the_lifecycle_commit_reveal_renew_expire_rebind() {
        let mut reg = NameRegistry::default();
        let r = record();
        let salt = [7u8; 32];
        let c = commit_hash(&r, &salt);

        // Commit at 9_000: visible to the view in-window.
        apply(&mut reg, 9_000, &[Some(&NameOp::Commit { commit: c })]);
        assert!(reg.commit_included_in(&c, 8_000, 9_500));
        assert!(!reg.commit_included_in(&c, 9_001, 9_500), "window edges are inclusive-exact");

        // Reveal at 9_100.
        apply(&mut reg, 9_100, &[Some(&NameOp::Reveal { record: r.clone(), salt })]);
        let e = reg.entry(b"alice").expect("registered");
        assert_eq!((e.registered, e.expiry), (9_100, 9_100 + NAME_TERM_BLOCKS));
        assert_eq!(e.address, r.address);
        assert_eq!(reg.registration_expiry(b"alice"), Some(9_100 + NAME_TERM_BLOCKS));

        // Renew while active: extends from expiry, not from now.
        apply(&mut reg, 10_000, &[Some(&NameOp::Renew { name: b"alice".to_vec() })]);
        assert_eq!(
            reg.entry(b"alice").unwrap().expiry,
            9_100 + 2 * NAME_TERM_BLOCKS,
            "renewal extends from max(now, expiry) = the old expiry"
        );

        // The N6 rebinding: a fresh reveal long past grace overwrites.
        let mut r2 = record();
        r2.address = vec![0xCD; L1_ADDRESS_LEN];
        let salt2 = [8u8; 32];
        let h2 = reopens_at(reg.entry(b"alice").unwrap().expiry) + 50;
        apply(&mut reg, h2 - 100, &[Some(&NameOp::Commit { commit: commit_hash(&r2, &salt2) })]);
        apply(&mut reg, h2, &[Some(&NameOp::Reveal { record: r2.clone(), salt: salt2 })]);
        let e = reg.entry(b"alice").unwrap();
        assert_eq!(e.address, vec![0xCD; L1_ADDRESS_LEN], "the rebinding is visible");
        assert_eq!(e.registered, h2);
    }

    #[test]
    fn commits_prune_deterministically_past_the_window() {
        let mut reg = NameRegistry::default();
        let c = [0x11u8; 32];
        apply(&mut reg, 9_000, &[Some(&NameOp::Commit { commit: c })]);
        // Applying a block far enough ahead prunes it.
        apply(&mut reg, 9_000 + COMMIT_MAX_AGE + 1, &[]);
        assert!(
            !reg.commit_included_in(&c, 0, u64::MAX),
            "a commit past MAX_AGE can satisfy no reveal and is gone"
        );
    }

    #[test]
    fn absent_riders_change_nothing_and_the_index_names_the_offender() {
        let mut reg = NameRegistry::default();
        apply(&mut reg, 9_000, &[None, None]);
        assert!(reg.is_empty());

        // A malformed rider is refused with ITS index — the tx the error
        // attributes, position 1 behind an absent rider at 0.
        let bad = [encode_rider(None), vec![0xFF, 0xFF]];
        let (i, _) = reg
            .apply_block_riders(9_001, bad.iter().map(Vec::as_slice))
            .expect_err("garbage cannot decode");
        assert_eq!(i, 1);
        assert!(reg.is_empty(), "nothing before the refusal had anything to apply");
    }

    /// Stage-7 drill: REORG ACROSS A REGISTRATION. The registry's reorg story
    /// is "ride `apply_state`, get the rewind re-fold for free" — which is a
    /// claim about determinism: folding a prefix and then a different suffix
    /// must equal folding the winning chain fresh. A registration that
    /// un-happens with its branch must leave no residue (the #325 SupplyLedger
    /// gap, asserted against the shape that replaced it).
    #[test]
    fn drill_reorg_refold_leaves_no_residue_of_the_losing_branch() {
        let r_alice = record();
        let mut r_bob = record();
        r_bob.name = b"bob".to_vec();
        let salt = [7u8; 32];

        // Branch A: alice reveals at 9_100 (this branch will LOSE).
        let mut on_a = NameRegistry::default();
        apply(&mut on_a, 9_000, &[Some(&NameOp::Commit { commit: commit_hash(&r_alice, &salt) })]);
        apply(&mut on_a, 9_100, &[Some(&NameOp::Reveal { record: r_alice.clone(), salt })]);
        assert!(on_a.entry(b"alice").is_some());

        // The reorg: rewind to the prefix, re-fold the winning branch, where
        // block 9_100 carries a DIFFERENT registration (bob's commit landed
        // in the prefix too — fixture simplicity, same window).
        let commit_alice = NameOp::Commit { commit: commit_hash(&r_alice, &salt) };
        let commit_bob = NameOp::Commit { commit: commit_hash(&r_bob, &salt) };
        let winning_prefix = [Some(&commit_alice), Some(&commit_bob)];
        let mut winning = NameRegistry::default();
        apply(&mut winning, 9_000, &winning_prefix);
        apply(&mut winning, 9_100, &[Some(&NameOp::Reveal { record: r_bob.clone(), salt })]);

        // The re-fold (what rewind_to does: fresh from genesis + winning blocks).
        let mut refolded = NameRegistry::default();
        apply(&mut refolded, 9_000, &winning_prefix);
        apply(&mut refolded, 9_100, &[Some(&NameOp::Reveal { record: r_bob.clone(), salt })]);

        assert_eq!(winning, refolded, "fold is deterministic");
        assert!(refolded.entry(b"alice").is_none(), "the losing branch's registration left no residue");
        assert!(refolded.entry(b"bob").is_some());
    }
}
