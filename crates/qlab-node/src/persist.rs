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
///
/// **2** since issue #101: [`StoredBlock`] gained `coinbase_rkm`, without which a
/// replay cannot re-derive the block's coinbase note and therefore cannot rebuild
/// the commitment tree. A version-1 snapshot is ignored (forcing a full replay),
/// but a version-1 *block log* cannot be replayed at all — its records decode
/// short. That is a data-directory break, not just a slow start: see the operator
/// note in the PR. Nothing in-tree carries a v1 datadir; the T0 hosts are not
/// being upgraded by this baton.
///
/// **3** since issue #188: [`StoredBlock`]'s transactions gained `discovery`,
/// without which a replayed body's `commitment()` no longer matches the
/// persisted header and every block carrying a transaction fails the #77
/// header/body binding on restart. A v2 datadir is a full break for the same
/// reason a v1 one was — and #188 changes the genesis hash anyway, so a v2
/// datadir belongs to a different network and must not be resumed.
pub const FORMAT_VERSION: u32 = 3;

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
    /// The **genesis block header** hash — `keccak256` over the height-0
    /// `BlockHeader`. It is the root this snapshot's chain hangs from, and
    /// [`crate::node::Node::open`] compares it against the genesis it was handed
    /// to decide whether this snapshot belongs to this chain at all.
    ///
    /// 🔴 **This is NOT the number an operator means by "the genesis hash", and
    /// comparing the two is meaningless** (issue #206). The operational genesis
    /// hash — the one `qumbra-node genesis init` prints, the one pinned as
    /// `expected_genesis_hash` in every node config, the one asserted at startup
    /// and quoted in `qumbra-deploy/OPERATOR.md` and every roll task book — is
    /// `qumbra_node::genesis::GenesisFile::hash()`: `keccak256` over the whole
    /// **genesis file's** canonical bincode (network name, FROZEN v1.0 params,
    /// all 21 committee keys, *and* the genesis block).
    ///
    /// The file contains the block, so the two values are **structurally
    /// guaranteed to differ**. A mismatch between this field and the runbook is
    /// the expected state, not evidence of a wrong net — which matters because
    /// the moment an operator decodes `snapshot.bin` is the moment a host has
    /// already come back wrong. To answer "does this data dir belong to this
    /// net", compare this field against the genesis block header hash the node
    /// computes from its own genesis file (`Node::open` does exactly that), and
    /// compare `expected_genesis_hash` against `genesis init` — never across.
    ///
    /// Renamed from `genesis_hash` by issue #206. Field names are not on disk:
    /// `bincode` 1.x serialises struct fields positionally, so the rename moved
    /// no byte (test-locked by
    /// `tests::the_genesis_block_hash_rename_moved_no_on_disk_byte`).
    pub genesis_block_hash: Hash32,
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
/// or corrupt **trailing** record (a crash mid-append) is dropped, not an error —
/// the log stays usable up to the last complete record.
///
/// # A record that fails to decode with bytes still after it is an ERROR
///
/// The tolerance above used to apply to *any* failing record, which was safe only
/// while the record type never changed. Issue #101 added `coinbase_rkm` to
/// [`StoredBlock`], so every record written by a pre-#101 binary now decodes
/// short — and under the old rule a whole populated block log would have been
/// read as "zero records" and the node would have resumed **silently from
/// genesis**, discarding its chain without a word. Silent data loss on a format
/// change is a worse failure than refusing to start.
///
/// So the tolerance is narrowed to what it was actually for: a torn record is by
/// construction the *last* thing in the file. If bytes follow a record that will
/// not decode, or if a non-empty log yields no records at all, this returns
/// [`io::ErrorKind::InvalidData`] and the caller refuses to open. Recovery is to
/// re-sync the datadir, not to bump a constant.
pub fn read_records(dir: &Path) -> io::Result<Vec<LogRecord>> {
    let path = dir.join(BLOCK_LOG);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file_len = fs::metadata(&path)?.len();
    let mut r = BufReader::new(File::open(&path)?);
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
            Err(e) => {
                // Tolerated only if nothing follows it (a crash mid-append).
                let mut probe = [0u8; 1];
                let has_more = r.read(&mut probe)? > 0;
                if has_more {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{BLOCK_LOG}: record {} does not decode and is not the last record \
                             ({e}). This block log was written by an incompatible build — the \
                             current on-disk format is version {FORMAT_VERSION}. Re-sync this \
                             datadir; do not start against it.",
                            out.len(),
                        ),
                    ));
                }
                break;
            }
        }
    }
    if out.is_empty() && file_len > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{BLOCK_LOG}: {file_len} bytes on disk but not one record decodes. This block \
                 log was written by an incompatible build — the current on-disk format is \
                 version {FORMAT_VERSION}. Re-sync this datadir; do not start against it."
            ),
        ));
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

/// **What a data dir's `snapshot.bin` says about itself** — issue #359 S3, the
/// answer to *"can this host restart in minutes, or does it replay from genesis?"*
/// without opening a node or replaying anything.
///
/// [`load_snapshot`] deliberately flattens three different situations into
/// `Ok(None)`, because for its own caller — resume — they are one situation: the
/// full replay is always correct. **For an operator they are not one situation**,
/// and that flattening is why the question in issue #104 ("no `snapshot.bin` on
/// any host despite SIGTERM") could only be answered by ssh + `ls`. A missing file
/// and an undecodable one both cost a from-genesis replay, but they have different
/// causes and different fixes: the first says a write never happened, the second
/// says one happened under a different [`FORMAT_VERSION`] (or was truncated by
/// something other than this writer — the write itself is atomic).
///
/// This reads and decodes the file. It is for the startup path and for one-shot
/// operator commands, **not** for a per-sample telemetry read: the decode is
/// O(state size). See `qumbra_node::run` for how the run loop caches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotOnDisk {
    /// No `snapshot.bin` in this data dir — node3's shape (issue #359). A restart
    /// here replays the whole block log from genesis.
    Absent,
    /// Present, decodable, and at the current [`FORMAT_VERSION`]: a restart
    /// resumes from this applied height and replays only the records past it.
    At { applied_height: u64 },
    /// Present but unusable — torn, or written at a different [`FORMAT_VERSION`].
    /// Costs the same full replay as [`Self::Absent`] and is reported apart from
    /// it because the cause is different.
    Unreadable,
}

impl SnapshotOnDisk {
    /// The applied height a restart would resume from, or `None` when this data
    /// dir has no usable snapshot.
    pub fn height(&self) -> Option<u64> {
        match self {
            Self::At { applied_height } => Some(*applied_height),
            Self::Absent | Self::Unreadable => None,
        }
    }

    /// The operator-facing token, shared by `TELEMETRY`'s `snap=` field and
    /// `halt-status` so one grep covers both surfaces (the `UNAVAILABLE`
    /// precedent from #136/#243): a height, `none`, or `bad`.
    pub fn field(&self) -> String {
        match self {
            Self::At { applied_height } => applied_height.to_string(),
            Self::Absent => "none".to_string(),
            Self::Unreadable => "bad".to_string(),
        }
    }
}

/// Read what `dir`'s snapshot says about itself — see [`SnapshotOnDisk`].
///
/// An I/O error opening a file that `exists()` reported is returned rather than
/// folded into [`SnapshotOnDisk::Unreadable`]: an unreadable *directory* is a
/// different fault from an unusable snapshot, and telling them apart is the whole
/// point of this function.
pub fn snapshot_on_disk(dir: &Path) -> io::Result<SnapshotOnDisk> {
    let path = dir.join(SNAPSHOT);
    if !path.exists() {
        return Ok(SnapshotOnDisk::Absent);
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    match bincode::deserialize::<Snapshot>(&bytes) {
        Ok(s) if s.format_version == FORMAT_VERSION => {
            Ok(SnapshotOnDisk::At { applied_height: s.applied_height })
        }
        _ => Ok(SnapshotOnDisk::Unreadable),
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 317 on-disk bytes of a fully-populated [`Snapshot`], captured from the
    /// tree **before** issue #206 renamed `Snapshot::genesis_hash` to
    /// `genesis_block_hash` (`main` `e8d2e95`, by serialising the struct built in
    /// [`golden_snapshot`] below and printing the hex).
    ///
    /// This is the vector that makes the #206 rename provable rather than merely
    /// asserted: `bincode` 1.x writes struct fields **positionally** and never
    /// writes a field name, so a rename must move exactly zero bytes. If a future
    /// change reorders, adds, retypes or removes a field, this literal stops
    /// matching and [`FORMAT_VERSION`] is owed a bump.
    const GOLDEN_SNAPSHOT_PRE_I206: &str = "\
03000000111111111111111111111111111111111111111111111111111111111111111107000000\
00000000222222222222222222222222222222222222222222222222222222222222222201333333\
33333333333333333333333333333333333333333333333333333333330400000000000000020000\
00000000004444444444444444444444444444444444444444444444444444444444444444555555\
55555555555555555555555555555555555555555555555555555555550100000000000000666666\
66666666666666666666666666666666666666666666666666666666660200000000000000000000\
00000000007777777777777777777777777777777777777777777777777777777777777777010000\
00000000008888888888888888888888888888888888888888888888888888888888888888";

    fn h(b: u8) -> Hash32 {
        [b; 32]
    }

    /// Every field populated and distinguishable, so a reorder is visible in the
    /// bytes rather than hidden behind two equal values.
    fn golden_snapshot() -> Snapshot {
        Snapshot {
            format_version: FORMAT_VERSION,
            genesis_block_hash: h(0x11),
            applied_height: 7,
            tip: h(0x22),
            finalized: Some((h(0x33), 4)),
            commitments: vec![h(0x44), h(0x55)],
            nullifiers: vec![h(0x66)],
            roots_by_height: vec![(0, h(0x77)), (1, h(0x88))],
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 🔴 Issue #206's format question, answered by the bytes and not by argument.
    ///
    /// A **rename** of a `bincode`-serialised field is byte-neutral, so
    /// [`FORMAT_VERSION`] does not move and every existing data dir keeps
    /// resuming. The alternative — a bump — would have refused every deployed
    /// snapshot for a naming fix, which is not a trade worth making; that is why
    /// this test exists rather than a comment saying it should be fine.
    #[test]
    fn the_genesis_block_hash_rename_moved_no_on_disk_byte() {
        let bytes = bincode::serialize(&golden_snapshot()).expect("serialize");
        assert_eq!(
            to_hex(&bytes),
            GOLDEN_SNAPSHOT_PRE_I206,
            "the on-disk snapshot bytes moved. `bincode` is positional and a field \
             *rename* cannot do this, so something else changed shape — bump \
             FORMAT_VERSION (currently {FORMAT_VERSION}) rather than re-pinning this vector"
        );
        assert_eq!(bytes.len(), GOLDEN_SNAPSHOT_PRE_I206.len() / 2);
    }

    /// The other direction: a snapshot file written by a **pre-#206 binary**
    /// decodes into the renamed struct with every field intact. Byte-equality
    /// above proves the writer did not move; this proves the reader did not
    /// either, which is the half an operator's data dir actually depends on.
    #[test]
    fn a_pre_i206_snapshot_file_still_decodes() {
        let bytes: Vec<u8> = (0..GOLDEN_SNAPSHOT_PRE_I206.len() / 2)
            .map(|i| u8::from_str_radix(&GOLDEN_SNAPSHOT_PRE_I206[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let snap: Snapshot = bincode::deserialize(&bytes).expect("a pre-#206 snapshot decodes");
        assert_eq!(snap, golden_snapshot());
        assert_eq!(
            snap.genesis_block_hash,
            h(0x11),
            "the field the rename touched reads back the same value it was written with"
        );
    }
}
