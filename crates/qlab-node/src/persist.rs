//! Restart-safe disk persistence: an append-only block log + an atomic snapshot.
//!
//! Durability has two layers with different jobs:
//!
//! - **`blocks.log`** — an append-only, length-prefixed `bincode` stream of
//!   [`LogRecord`]s: every accepted block AND every finalization, in order. This
//!   is the **source of truth**: replaying it from genesis reconstructs the exact
//!   node state ([`crate::node::Node::replay`]) — including the finalized head,
//!   which a block-only log could not — and is the correctness anchor a snapshot
//!   is checked against.
//! - **`snapshot.bin`** — the derived state (commitment leaves, nullifier set,
//!   chain pointers, finalized roots) at a given applied height, so a restart is
//!   O(blocks since the snapshot) instead of O(whole chain). It is written
//!   **atomically** (temp file + fsync + rename), so a crash mid-write can never
//!   leave a torn snapshot — the previous snapshot (or none) survives and the log
//!   catches the node back up. A snapshot that fails to decode is treated as
//!   absent, forcing a full, always-correct genesis replay.
//!
//! Both files are self-describing via [`FORMAT_VERSION`]; a snapshot from a
//! different format version is ignored (protocol-spec §0 versioning discipline).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::{Hash32, StoredBlock};

/// On-disk format version for both the block log and the snapshot. Bump on any
/// incompatible change to [`StoredBlock`] or [`Snapshot`].
pub const FORMAT_VERSION: u32 = 1;

/// The append-only log file name (source of truth: blocks + finalizations).
pub const BLOCK_LOG: &str = "blocks.log";
/// The snapshot file name (fast-restart derived state).
pub const SNAPSHOT: &str = "snapshot.bin";
/// The temp name a snapshot is written to before the atomic rename.
const SNAPSHOT_TMP: &str = "snapshot.bin.tmp";

/// One record in the append-only log. Finalizations are logged alongside blocks
/// so a from-genesis replay reconstructs the finalized head too (a block-only
/// log could not — finalization is committee-driven, not derivable from blocks).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogRecord {
    /// An accepted block.
    Block(StoredBlock),
    /// A finalization of the block with this hash.
    Finalize(Hash32),
}

/// The derived node state at a given applied height — everything needed to
/// resume without replaying the whole log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format_version: u32,
    pub genesis_hash: Hash32,
    /// Height of the highest block whose state transition is folded in here.
    pub applied_height: u64,
    pub tip: Hash32,
    /// The finalized head as `(hash, height)`, if any.
    pub finalized: Option<(Hash32, u64)>,
    /// Every commitment-tree leaf, in append order (protocol-spec §3).
    pub commitments: Vec<Hash32>,
    /// The spent-nullifier set (sorted, for a deterministic on-disk form).
    pub nullifiers: Vec<Hash32>,
    /// `(height, commitment root)` after applying each block — the anchor set
    /// (a finalized root within the age window is a valid anchor, §4).
    pub roots_by_height: Vec<(u64, Hash32)>,
}

/// Append a record to the log (source of truth). Each record is a 4-byte LE
/// length prefix followed by its `bincode`, flushed + fsync'd before returning.
pub fn append_record(dir: &Path, rec: &LogRecord) -> io::Result<()> {
    let bytes = bincode::serialize(rec).map_err(to_io)?;
    let mut f = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(BLOCK_LOG))?,
    );
    f.write_all(&(bytes.len() as u32).to_le_bytes())?;
    f.write_all(&bytes)?;
    f.flush()?;
    f.into_inner()?.sync_all()?;
    Ok(())
}

/// Read every record from the log in order. Missing log ⇒ empty vec. A truncated
/// or corrupt trailing record (e.g. a crash mid-append) is dropped, not an error
/// — the log stays usable up to the last complete record.
pub fn read_records(dir: &Path) -> io::Result<Vec<LogRecord>> {
    let path = dir.join(BLOCK_LOG);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if r.read_exact(&mut buf).is_err() {
            break; // torn trailing record from a crash mid-append
        }
        match bincode::deserialize::<LogRecord>(&buf) {
            Ok(rec) => out.push(rec),
            Err(_) => break, // corrupt trailing record — stop at the last good one
        }
    }
    Ok(out)
}

/// Atomically persist a snapshot: write to a temp file, fsync it, then rename
/// over the live snapshot (a rename is atomic on the same filesystem).
pub fn save_snapshot(dir: &Path, snap: &Snapshot) -> io::Result<()> {
    let bytes = bincode::serialize(snap).map_err(to_io)?;
    let tmp: PathBuf = dir.join(SNAPSHOT_TMP);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(SNAPSHOT))?;
    Ok(())
}

/// Load the snapshot if present, valid, and of the current [`FORMAT_VERSION`].
/// A missing, unreadable, undecodable, or version-mismatched snapshot returns
/// `Ok(None)` — the caller then rebuilds from the log (always correct).
pub fn load_snapshot(dir: &Path) -> io::Result<Option<Snapshot>> {
    let path = dir.join(SNAPSHOT);
    if !path.exists() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    match bincode::deserialize::<Snapshot>(&bytes) {
        Ok(s) if s.format_version == FORMAT_VERSION => Ok(Some(s)),
        _ => Ok(None),
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
