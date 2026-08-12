//! The name registry — a replay of committed riders (lab #367, stage 3).
//!
//! Design walls: `name-service-decision.md` D1–D2 (the registry is chain
//! state, bulk-synced and resolved locally) and the brief's N4–N6 (write-once
//! records, permissionless renewal, expiry + grace). This module is the
//! node-side state those rules read: [`crate::node::MemNode`] mutates it in
//! `apply_state` — the same funnel every other piece of derived state rides —
//! so a rewind's re-fold rebuilds it exactly as a re-application would, and
//! no separate reorg handling exists to get wrong (the `SupplyLedger` reorg
//! gap, PR #325, is the lesson; riding `apply_state` is the shape that
//! doesn't have it).
//!
//! # Persistence: a sidecar, not a `Snapshot` field
//!
//! `Snapshot` is positional `bincode` behind `FORMAT_VERSION`; a new field
//! there orphans every datadir in existence (see `persist.rs`'s #367 note).
//! The registry instead persists as **`names.bin`** beside the snapshot,
//! written by the same `save_snapshot` call, versioned reject-unknown. A
//! missing sidecar is **exact, not a guess**: a snapshot written by a
//! pre-#367 binary cannot have applied a rider-carrying block (it cannot even
//! decode that log record), so its registry state IS empty.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use qlab_devnet::names::{
    self, decode_rider, extended_expiry, NameOp, NameView, RiderError, COMMIT_MAX_AGE,
};

use crate::store::{Hash32, StoredTx};

/// The sidecar file name. Lives beside `snapshot.bin`, written atomically
/// through the same tmp-then-rename move.
pub const NAMES_FILE: &str = "names.bin";
const NAMES_TMP: &str = "names.bin.tmp";

/// Sidecar format version — the registry's own, deliberately independent of
/// `persist::FORMAT_VERSION` (which must not move for this feature).
pub const NAMES_FORMAT_VERSION: u32 = 1;

/// One registered name: the bound record and its clock. Write-once (N4) —
/// nothing here is ever mutated except `expiry`, and that only forward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Apply one block's riders at `height`. Callers have already validated
    /// the block (`validate_body*` runs before `apply_state`); a rider that
    /// fails to decode here is therefore log corruption or a logic error, and
    /// is returned as the codec's own verdict rather than ignored.
    pub fn apply_block_riders(
        &mut self,
        height: u64,
        txs: &[StoredTx],
    ) -> Result<(), (usize, RiderError)> {
        // Deterministic prune: commits too old to satisfy any reveal at or
        // after this height. `height - MAX_AGE` is the oldest height a commit
        // included there could still be revealed from.
        let horizon = height.saturating_sub(COMMIT_MAX_AGE);
        self.commits.retain(|_, h| *h >= horizon);

        for (i, tx) in txs.iter().enumerate() {
            let op = decode_rider(&tx.rider).map_err(|e| (i, e))?;
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

/// The sidecar's on-disk form: version first, reject-unknown. Carries the
/// `applied_height` it was captured at so `open` can prove it belongs beside
/// the snapshot it rides with — the two files rename atomically one at a
/// time, and the crash window between them must be detectable, not guessed
/// across.
#[derive(Serialize, Deserialize)]
struct NamesSidecar {
    format_version: u32,
    applied_height: u64,
    registry: NameRegistry,
}

/// Write the registry sidecar atomically (tmp + rename, the snapshot's move).
pub fn save_names(dir: &Path, registry: &NameRegistry, applied_height: u64) -> io::Result<()> {
    let sidecar = NamesSidecar {
        format_version: NAMES_FORMAT_VERSION,
        applied_height,
        registry: registry.clone(),
    };
    let bytes = bincode::serialize(&sidecar)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp: PathBuf = dir.join(NAMES_TMP);
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(NAMES_FILE))?;
    Ok(())
}

/// Load the registry sidecar with the height it was captured at. `Ok(None)`
/// when the file is absent — the exact empty-registry case (module docs) —
/// and an **error** when it exists but does not decode or carries an unknown
/// version. The caller (`resume_from_snapshot`) treats every error as a
/// fall-through to the full replay, which rebuilds the registry from the log
/// and consults no sidecar — recovery by the source of truth, not by guess.
pub fn load_names_at(dir: &Path) -> io::Result<Option<(NameRegistry, u64)>> {
    let path = dir.join(NAMES_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let sidecar: NamesSidecar = bincode::deserialize(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{NAMES_FILE}: does not decode ({e}). Written by an incompatible build — \
                 current sidecar version is {NAMES_FORMAT_VERSION}. Re-sync this datadir."
            ),
        )
    })?;
    if sidecar.format_version != NAMES_FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{NAMES_FILE}: sidecar version {} (this build reads {NAMES_FORMAT_VERSION}). \
                 Refusing rather than guessing.",
                sidecar.format_version
            ),
        ));
    }
    Ok(Some((sidecar.registry, sidecar.applied_height)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::names::{
        commit_hash, encode_rider, name_fee_bessel, reopens_at, NameRecord,
        L1_ADDRESS_LEN, NAME_TERM_BLOCKS, RECORD_KIND_L1_ADDRESS,
    };

    fn tx_with(op: Option<&NameOp>) -> StoredTx {
        StoredTx {
            anchor: [0x0F; 32],
            nullifiers: vec![],
            commitments: vec![],
            bucket_actions: 2,
            fee: 1_000_000 + op.map_or(0, names::name_fee_for),
            proof: vec![],
            discovery: vec![0x00],
            rider: encode_rider(op),
        }
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
        reg.apply_block_riders(9_000, &[tx_with(Some(&NameOp::Commit { commit: c }))]).unwrap();
        assert!(reg.commit_included_in(&c, 8_000, 9_500));
        assert!(!reg.commit_included_in(&c, 9_001, 9_500), "window edges are inclusive-exact");

        // Reveal at 9_100.
        reg.apply_block_riders(
            9_100,
            &[tx_with(Some(&NameOp::Reveal { record: r.clone(), salt }))],
        )
        .unwrap();
        let e = reg.entry(b"alice").expect("registered");
        assert_eq!((e.registered, e.expiry), (9_100, 9_100 + NAME_TERM_BLOCKS));
        assert_eq!(e.address, r.address);
        assert_eq!(reg.registration_expiry(b"alice"), Some(9_100 + NAME_TERM_BLOCKS));

        // Renew while active: extends from expiry, not from now.
        reg.apply_block_riders(10_000, &[tx_with(Some(&NameOp::Renew { name: b"alice".to_vec() }))])
            .unwrap();
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
        reg.apply_block_riders(
            h2 - 100,
            &[tx_with(Some(&NameOp::Commit { commit: commit_hash(&r2, &salt2) }))],
        )
        .unwrap();
        reg.apply_block_riders(h2, &[tx_with(Some(&NameOp::Reveal { record: r2.clone(), salt: salt2 }))])
            .unwrap();
        let e = reg.entry(b"alice").unwrap();
        assert_eq!(e.address, vec![0xCD; L1_ADDRESS_LEN], "the rebinding is visible");
        assert_eq!(e.registered, h2);
    }

    #[test]
    fn commits_prune_deterministically_past_the_window() {
        let mut reg = NameRegistry::default();
        let c = [0x11u8; 32];
        reg.apply_block_riders(9_000, &[tx_with(Some(&NameOp::Commit { commit: c }))]).unwrap();
        // Applying a block far enough ahead prunes it.
        reg.apply_block_riders(9_000 + COMMIT_MAX_AGE + 1, &[]).unwrap();
        assert!(
            !reg.commit_included_in(&c, 0, u64::MAX),
            "a commit past MAX_AGE can satisfy no reveal and is gone"
        );
    }

    #[test]
    fn absent_riders_change_nothing_and_fees_line_up() {
        let mut reg = NameRegistry::default();
        reg.apply_block_riders(9_000, &[tx_with(None), tx_with(None)]).unwrap();
        assert!(reg.is_empty());
        // Sanity on the fixture itself: reveal fee = relay + 5-char tier.
        let r = record();
        let t = tx_with(Some(&NameOp::Reveal { record: r, salt: [0; 32] }));
        assert_eq!(t.fee, 1_000_000 + name_fee_bessel(5));
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

        let prefix = |reg: &mut NameRegistry| {
            reg.apply_block_riders(
                9_000,
                &[tx_with(Some(&NameOp::Commit { commit: commit_hash(&r_alice, &salt) }))],
            )
            .unwrap();
        };

        // Branch A: alice reveals at 9_100 (this branch will LOSE).
        let mut on_a = NameRegistry::default();
        prefix(&mut on_a);
        on_a.apply_block_riders(
            9_100,
            &[tx_with(Some(&NameOp::Reveal { record: r_alice.clone(), salt }))],
        )
        .unwrap();
        assert!(on_a.entry(b"alice").is_some());

        // The reorg: rewind to the prefix, re-fold the winning branch, where
        // block 9_100 carries a DIFFERENT registration (bob's commit landed
        // in the prefix too — fixture simplicity, same window).
        let mut winning = NameRegistry::default();
        winning
            .apply_block_riders(
                9_000,
                &[
                    tx_with(Some(&NameOp::Commit { commit: commit_hash(&r_alice, &salt) })),
                    tx_with(Some(&NameOp::Commit { commit: commit_hash(&r_bob, &salt) })),
                ],
            )
            .unwrap();
        winning
            .apply_block_riders(
                9_100,
                &[tx_with(Some(&NameOp::Reveal { record: r_bob.clone(), salt }))],
            )
            .unwrap();

        // The re-fold (what rewind_to does: fresh from genesis + winning blocks).
        let mut refolded = NameRegistry::default();
        refolded
            .apply_block_riders(
                9_000,
                &[
                    tx_with(Some(&NameOp::Commit { commit: commit_hash(&r_alice, &salt) })),
                    tx_with(Some(&NameOp::Commit { commit: commit_hash(&r_bob, &salt) })),
                ],
            )
            .unwrap();
        refolded
            .apply_block_riders(
                9_100,
                &[tx_with(Some(&NameOp::Reveal { record: r_bob.clone(), salt }))],
            )
            .unwrap();

        assert_eq!(winning, refolded, "fold is deterministic");
        assert!(refolded.entry(b"alice").is_none(), "the losing branch's registration left no residue");
        assert!(refolded.entry(b"bob").is_some());
    }

    #[test]
    fn sidecar_round_trips_and_absence_is_the_empty_registry() {
        let dir = std::env::temp_dir().join(format!("qlab-names-i367-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert_eq!(load_names_at(&dir).unwrap(), None, "missing sidecar = None = exact empty");

        let mut reg = NameRegistry::default();
        let r = record();
        reg.apply_block_riders(9_100, &[tx_with(Some(&NameOp::Reveal { record: r, salt: [7; 32] }))])
            .unwrap();
        save_names(&dir, &reg, 9_100).unwrap();
        assert_eq!(load_names_at(&dir).unwrap(), Some((reg, 9_100)));

        // An unknown version refuses with a reason, never guesses.
        let bad = NamesSidecar {
            format_version: 99,
            applied_height: 0,
            registry: NameRegistry::default(),
        };
        fs::write(dir.join(NAMES_FILE), bincode::serialize(&bad).unwrap()).unwrap();
        let err = load_names_at(&dir).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");

        let _ = fs::remove_dir_all(&dir);
    }
}
