//! The name registry's **sidecar persistence** — the node-side half of what
//! used to be one module, after lab #660 moved the replay and query core to
//! [`qlab_devnet::name_registry`] (re-exported below, so every existing
//! `crate::name_registry::NameRegistry` path still means the same type).
//!
//! Why the split falls exactly here: the replay is a consensus-adjacent rule
//! every resolver must share (`name-service-decision.md` D1–D2 — "resolved
//! locally" — with #586 as the cost of a second implementation), while
//! `names.bin` is THIS node's datadir layout and nobody else's. The registry
//! rides [`crate::node::MemNode`]'s `apply_state` — the same funnel every
//! other piece of derived state rides — so a rewind's re-fold rebuilds it
//! exactly as a re-application would, and no separate reorg handling exists
//! to get wrong (the `SupplyLedger` reorg gap, PR #325, is the lesson).
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
//!
//! The moved types keep their exact field shapes and `BTreeMap` layout, and
//! `bincode` is structural, so a sidecar written before the move decodes
//! byte-for-byte after it — `NAMES_FORMAT_VERSION` deliberately does not bump.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use qlab_devnet::name_registry::{NameEntry, NameRegistry};

/// The sidecar file name. Lives beside `snapshot.bin`, written atomically
/// through the same tmp-then-rename move.
pub const NAMES_FILE: &str = "names.bin";
const NAMES_TMP: &str = "names.bin.tmp";

/// Sidecar format version — the registry's own, deliberately independent of
/// `persist::FORMAT_VERSION` (which must not move for this feature).
pub const NAMES_FORMAT_VERSION: u32 = 1;

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
        encode_rider, NameOp, NameRecord, L1_ADDRESS_LEN, RECORD_KIND_L1_ADDRESS,
    };

    #[test]
    fn sidecar_round_trips_and_absence_is_the_empty_registry() {
        let dir = std::env::temp_dir().join(format!("qlab-names-i367-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert_eq!(load_names_at(&dir).unwrap(), None, "missing sidecar = None = exact empty");

        let mut reg = NameRegistry::default();
        let reveal = encode_rider(Some(&NameOp::Reveal {
            record: NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xAB; L1_ADDRESS_LEN],
            },
            salt: [7; 32],
        }));
        reg.apply_block_riders(9_100, [reveal.as_slice()]).unwrap();
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
