//! **Registry state** (lab #710, L2-B3): the asset registry an Annulet node
//! holds, and its `registry.bin` sidecar.
//!
//! The tree is `qlab_cbserver::registry::RegistryTree` (depth 16, keyed by
//! asset id). Its root is in every Annulet header, and the node binds the two
//! at genesis load and on every applied block (`NodeError::RegistryRootMismatch`).
//!
//! **Immutable after genesis until A2** (shape R): the store has no mutating
//! method. At Phase 0 the genesis file is the whole registry history, so a
//! replay rebuilds it exactly; the sidecar exists so A2's updates have a home
//! and so a restart can be checked against what was held.
//!
//! The sidecar follows `names.bin` (lab #367): versioned bincode, written with
//! tmp + rename beside every snapshot, carrying the height it was captured at.
//! It is **not** part of the block log — `persist::FORMAT_VERSION` and the log
//! layout do not move for it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use qlab_cbserver::registry::{RegistryError, RegistryLeaf, RegistryTree, RegistryWitness};

use crate::store::Hash32;

/// The sidecar file name.
pub const REGISTRY_FILE: &str = "registry.bin";
const REGISTRY_TMP: &str = "registry.bin.tmp";

/// Sidecar format version — independent of `persist::FORMAT_VERSION`.
pub const REGISTRY_FORMAT_VERSION: u32 = 1;

/// The registry an Annulet node holds.
pub trait RegistryStore {
    /// The tree.
    fn tree(&self) -> &RegistryTree;

    /// The root as header bytes (lane-major little-endian).
    fn root_bytes(&self) -> Hash32 {
        qlab_note::hash::digest_bytes(&self.tree().root())
    }
}

/// The in-memory registry store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemRegistryStore {
    tree: RegistryTree,
}

impl MemRegistryStore {
    /// Build from the genesis leaves.
    pub fn from_genesis(leaves: &[RegistryLeaf]) -> Result<Self, RegistryError> {
        Ok(Self { tree: RegistryTree::from_leaves(leaves)? })
    }
}

impl RegistryStore for MemRegistryStore {
    fn tree(&self) -> &RegistryTree {
        &self.tree
    }
}

/// The sidecar's on-disk form. A leaf travels as its 15 lanes
/// (`RegistryLeaf::state()[0..15]`), the served wire's order.
#[derive(Serialize, Deserialize)]
struct RegistrySidecar {
    format_version: u32,
    applied_height: u64,
    leaves: Vec<[u64; 15]>,
}

fn lanes_of(l: &RegistryLeaf) -> [u64; 15] {
    l.state()[..15].try_into().expect("15 lanes")
}

fn leaf_of(x: &[u64; 15]) -> RegistryLeaf {
    RegistryLeaf {
        asset: x[0],
        issuer_key: [x[1], x[2], x[3], x[4]],
        mode: x[5],
        freeze_root: [x[6], x[7], x[8], x[9]],
        allow_root: [x[10], x[11], x[12], x[13]],
        flags: x[14],
    }
}

/// Write the sidecar atomically (tmp + rename).
pub fn save_registry(dir: &Path, store: &impl RegistryStore, applied_height: u64) -> io::Result<()> {
    let sidecar = RegistrySidecar {
        format_version: REGISTRY_FORMAT_VERSION,
        applied_height,
        leaves: store.tree().leaves().map(lanes_of).collect(),
    };
    let bytes = bincode::serialize(&sidecar).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp: PathBuf = dir.join(REGISTRY_TMP);
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(REGISTRY_FILE))?;
    Ok(())
}

/// Load the sidecar: `Ok(None)` when absent, an error when it does not
/// decode, carries an unknown version, or does not build a tree. The caller
/// treats every error as "rebuild from genesis" and says so.
pub fn load_registry_at(dir: &Path) -> io::Result<Option<(MemRegistryStore, u64)>> {
    let path = dir.join(REGISTRY_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let sidecar: RegistrySidecar = bincode::deserialize(&bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{REGISTRY_FILE}: does not decode ({e})"))
    })?;
    if sidecar.format_version != REGISTRY_FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{REGISTRY_FILE}: sidecar version {} (this build reads {REGISTRY_FORMAT_VERSION})",
                sidecar.format_version
            ),
        ));
    }
    let leaves: Vec<RegistryLeaf> = sidecar.leaves.iter().map(leaf_of).collect();
    let store = MemRegistryStore::from_genesis(&leaves).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{REGISTRY_FILE}: does not build a registry ({e:?})"))
    })?;
    Ok(Some((store, sidecar.applied_height)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_round_trips_and_refuses_what_it_cannot_read() {
        let dir = std::env::temp_dir().join(format!("qlab-registry-sidecar-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(load_registry_at(&dir).unwrap().is_none(), "absent is None");
        let leaves = [
            RegistryLeaf::cloaked(0),
            RegistryLeaf { mode: 2, issuer_key: [7; 4], ..RegistryLeaf::cloaked(7) },
        ];
        let s = MemRegistryStore::from_genesis(&leaves).unwrap();
        save_registry(&dir, &s, 12).unwrap();
        let (back, h) = load_registry_at(&dir).unwrap().unwrap();
        assert_eq!((back.tree().root(), h), (s.tree().root(), 12));
        assert_eq!(back.root_bytes(), s.root_bytes());
        fs::write(dir.join(REGISTRY_FILE), b"junk").unwrap();
        assert!(load_registry_at(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
