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
//!   catches the node back up. A snapshot that fails to decode is **rejected
//!   with its reason** ([`SnapshotLoadReject`], lab #408) and the caller falls
//!   back to a full, always-correct genesis replay — reported, not silent.
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
///
/// **Still 3 after lab #367 (name-service riders), and that is the point.**
/// The rider reaches disk as an **additive log variant** ([`WireRecord`]),
/// never as a field on the frozen v3 layouts — so every v3 datadir on the
/// live fleet stays readable with no migration and no version bump. The two
/// prior bumps each orphaned every datadir in existence; this one arrives on
/// a running chain through a halt boundary, where that price is not payable.
/// Forward-incompatibility is unchanged in kind: a pre-#367 binary reading a
/// rider-carrying record refuses loudly through the same
/// record-does-not-decode path as any other unknown future format.
pub const FORMAT_VERSION: u32 = 3;

/// The append-only log file name (source of truth: blocks + finalizations).
pub const BLOCK_LOG: &str = "blocks.log";
/// The snapshot file name (fast-restart derived state).
pub const SNAPSHOT: &str = "snapshot.bin";
/// The temp name a snapshot is written to before the atomic rename.
///
/// `pub` since lab #478, for one reason: a test that wants to make the snapshot
/// write *fail* has to be able to name the file the write goes to. The previous
/// way of failing it — marking the data dir read-only — is a unix-only concept
/// and does nothing on Windows, so the test that depended on it asserted against
/// a flush that had quietly succeeded. Blocking this exact path is portable, and
/// naming the constant rather than re-typing the string is what keeps the
/// injection from going vacuous if the file is ever renamed.
pub const SNAPSHOT_TMP: &str = "snapshot.bin.tmp";

/// One record in the append-only log. Finalizations are logged alongside blocks
/// so a from-genesis replay reconstructs the finalized head too (a block-only
/// log could not — finalization is committee-driven, not derivable from blocks).
///
/// **Deliberately NOT `Serialize`/`Deserialize` since lab #367**: the on-disk
/// encoding is [`WireRecord`]'s, and the only doors to it are
/// [`append_record`] and [`read_records`]. A direct `bincode::serialize` of
/// this enum would emit `StoredBlock`'s new positional layout under the old
/// variant index — a byte stream no build ever reads — so the derive is
/// removed rather than trusted to stay unused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogRecord {
    /// An accepted block.
    Block(StoredBlock),
    /// A finalization of the block with this hash.
    Finalize(Hash32),
}

// ---------------------------------------------------------------------------
// The on-disk encoding (lab #367)
// ---------------------------------------------------------------------------

/// Frozen positional layout of a v3-era stored transaction. `bincode` 1.x is
/// positional, so this struct **is** the byte layout of every record written
/// before lab #367 — and of every rider-free record written after it.
///
/// 🔴 **DO NOT add fields here.** `StoredTx`'s own history (#101, #188) is two
/// demonstrations of what a field added to a positional layout does to every
/// datadir in existence; this struct exists so the third field lands in a new
/// [`WireRecord`] variant instead.
#[derive(Serialize, Deserialize)]
struct LegacyStoredTx {
    anchor: Hash32,
    nullifiers: Vec<Hash32>,
    commitments: Vec<Hash32>,
    bucket_actions: u32,
    fee: u64,
    proof: Vec<u8>,
    discovery: Vec<u8>,
}

/// Frozen v3-era block layout. See [`LegacyStoredTx`].
#[derive(Serialize, Deserialize)]
struct LegacyStoredBlock {
    header: crate::store::StoredHeader,
    txs: Vec<LegacyStoredTx>,
    coinbase: u64,
    coinbase_rkm: [u64; 4],
}

/// What actually reaches disk. Variant indices are the compatibility contract:
/// 0 and 1 are the pre-#367 stream byte-for-byte; 2 is additive, appears only
/// for blocks carrying a non-absent rider (impossible below the name
/// boundary), and makes a pre-#367 binary refuse through the ordinary
/// record-does-not-decode path.
#[derive(Serialize, Deserialize)]
enum WireRecord {
    /// Variant 0 — a rider-free block in the frozen v3 layout.
    Block(LegacyStoredBlock),
    /// Variant 1 — a finalization.
    Finalize(Hash32),
    /// Variant 2 — a rider-carrying block (lab #367), current layouts.
    BlockV4(StoredBlock),
}

fn rider_free(b: &StoredBlock) -> bool {
    b.txs.iter().all(|t| t.rider == qlab_devnet::names::RIDER_ABSENT)
}

impl From<&LogRecord> for WireRecord {
    fn from(rec: &LogRecord) -> Self {
        match rec {
            LogRecord::Finalize(h) => WireRecord::Finalize(*h),
            LogRecord::Block(b) if rider_free(b) => WireRecord::Block(LegacyStoredBlock {
                header: b.header.clone(),
                txs: b
                    .txs
                    .iter()
                    .map(|t| LegacyStoredTx {
                        anchor: t.anchor,
                        nullifiers: t.nullifiers.clone(),
                        commitments: t.commitments.clone(),
                        bucket_actions: t.bucket_actions,
                        fee: t.fee,
                        proof: t.proof.clone(),
                        discovery: t.discovery.clone(),
                    })
                    .collect(),
                coinbase: b.coinbase,
                coinbase_rkm: b.coinbase_rkm,
            }),
            LogRecord::Block(b) => WireRecord::BlockV4(b.clone()),
        }
    }
}

impl From<WireRecord> for LogRecord {
    fn from(rec: WireRecord) -> Self {
        match rec {
            WireRecord::Finalize(h) => LogRecord::Finalize(h),
            WireRecord::BlockV4(b) => LogRecord::Block(b),
            WireRecord::Block(l) => LogRecord::Block(StoredBlock { annulet: None,
                header: l.header,
                txs: l
                    .txs
                    .into_iter()
                    .map(|t| crate::store::StoredTx { l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(),
                        anchor: t.anchor,
                        nullifiers: t.nullifiers,
                        commitments: t.commitments,
                        bucket_actions: t.bucket_actions,
                        fee: t.fee,
                        proof: t.proof,
                        discovery: t.discovery,
                        // A legacy record structurally predates riders, so
                        // absence is exact — a fact, not a migration guess.
                        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
                    })
                    .collect(),
                coinbase: l.coinbase,
                coinbase_rkm: l.coinbase_rkm,
            }),
        }
    }
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
    let bytes = bincode::serialize(&WireRecord::from(rec)).map_err(to_io)?;
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
/// Refuse a decoded record naming an unknown `bucket_actions` value (lab #470
/// stage 3). {2, 4, 8} is the complete set every writer in every era produces.
fn check_record_buckets(rec: &WireRecord, record_index: usize) -> io::Result<()> {
    match rec {
        WireRecord::Finalize(_) => Ok(()),
        WireRecord::Block(b) => {
            check_bucket_values(b.txs.iter().map(|t| t.bucket_actions), record_index)
        }
        WireRecord::BlockV4(b) => {
            check_bucket_values(b.txs.iter().map(|t| t.bucket_actions), record_index)
        }
    }
}

fn check_bucket_values(
    values: impl Iterator<Item = u32>,
    record_index: usize,
) -> io::Result<()> {
    for (i, v) in values.enumerate() {
        if !matches!(v, 2 | 4 | 8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{BLOCK_LOG}: record {record_index} tx {i} names bucket_actions {v}, which                      no writer of this format has ever produced (legitimate values: 2, 4, 8).                      This datadir is corrupt or foreign — re-sync it; do not start against it."
                ),
            ));
        }
    }
    Ok(())
}

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
        match bincode::deserialize::<WireRecord>(&buf) {
            Ok(rec) => {
                // Lab #470 stage 3: a record whose bucket_actions is not a
                // value any legitimate writer ever produced ({2,4,8} — see
                // store.rs::bucket_from_actions for the writer enumeration) is
                // corrupt or foreign data. It DECODES (any u32 is bincode-
                // valid), so the torn-tail tolerance below never applies to
                // it: refuse by name, unconditionally — the old behavior was
                // a silent coercion to TwoByTwo, i.e. a wrong body rebuilt
                // from disk with nothing pointing at it.
                check_record_buckets(&rec, out.len())?;
                out.push(LogRecord::from(rec));
            }
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

/// Why a **present** `snapshot.bin` could not be loaded (lab #408).
///
/// Before this existed, both cases were folded into the same `Ok(None)` as a
/// genuinely absent file — so a present-but-unusable snapshot silently cost a
/// full genesis replay with nothing on the startup line saying why. The two
/// reasons are kept apart because their fixes differ: undecodable bytes were
/// truncated or written by something other than this writer (the write itself
/// is atomic), a version mismatch is a binary rolled across a format bump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotLoadReject {
    /// The bytes do not decode as a [`Snapshot`] at all.
    Undecodable { detail: String },
    /// Decodes, but was written under a different [`FORMAT_VERSION`] than this
    /// binary honours.
    VersionMismatch { found: u32 },
}

impl std::fmt::Display for SnapshotLoadReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotLoadReject::Undecodable { detail } => {
                write!(f, "{SNAPSHOT} is present but does not decode ({detail})")
            }
            SnapshotLoadReject::VersionMismatch { found } => write!(
                f,
                "{SNAPSHOT} was written at on-disk format version {found}; this binary honours \
                 only {FORMAT_VERSION}"
            ),
        }
    }
}

/// What [`load_snapshot`] found on disk. `Absent` means **genuinely absent** —
/// no `snapshot.bin` in the data dir. A present-but-unusable file is
/// [`Self::Rejected`], never `Absent` (lab #408): the two used to share one
/// `Ok(None)`, which is exactly how a rejected snapshot's genesis replay
/// became indistinguishable from a first start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotLoad {
    /// No `snapshot.bin` in this data dir.
    Absent,
    /// Present, decodable, and at the current [`FORMAT_VERSION`].
    Loaded(Snapshot),
    /// Present but unusable, with the reason.
    Rejected(SnapshotLoadReject),
}

/// Load the snapshot. An I/O error reading a file that exists is still an
/// `Err` (an unreadable *directory* is a different fault from an unusable
/// snapshot); everything else is a [`SnapshotLoad`]. The caller decides what a
/// rejection costs — for resume that is a fall-through to the log, but since
/// lab #408 it is a *reported* fall-through, not a silent one.
pub fn load_snapshot(dir: &Path) -> io::Result<SnapshotLoad> {
    let path = dir.join(SNAPSHOT);
    if !path.exists() {
        return Ok(SnapshotLoad::Absent);
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    match bincode::deserialize::<Snapshot>(&bytes) {
        Ok(s) if s.format_version == FORMAT_VERSION => Ok(SnapshotLoad::Loaded(s)),
        Ok(s) => {
            Ok(SnapshotLoad::Rejected(SnapshotLoadReject::VersionMismatch {
                found: s.format_version,
            }))
        }
        Err(e) => {
            Ok(SnapshotLoad::Rejected(SnapshotLoadReject::Undecodable { detail: e.to_string() }))
        }
    }
}

/// **What a data dir's `snapshot.bin` says about itself** — issue #359 S3, the
/// answer to *"can this host restart in minutes, or does it replay from genesis?"*
/// without opening a node or replaying anything.
///
/// [`load_snapshot`] used to flatten three different situations into `Ok(None)`;
/// this enum was the operator-facing separation of them, and since lab #408 the
/// load path itself separates them too ([`SnapshotLoad`]) — this stays as the
/// cheap operator token over the same decoder. A missing file
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
    // One decoder, two readers (lab #408): this is [`load_snapshot`]'s verdict
    // mapped onto the operator token, so the two surfaces cannot drift.
    Ok(match load_snapshot(dir)? {
        SnapshotLoad::Absent => SnapshotOnDisk::Absent,
        SnapshotLoad::Loaded(s) => SnapshotOnDisk::At { applied_height: s.applied_height },
        SnapshotLoad::Rejected(_) => SnapshotOnDisk::Unreadable,
    })
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

    /// Issue #359: [`snapshot_on_disk`] separates the three situations
    /// [`load_snapshot`] flattens into `Ok(None)`, and the separation is the point
    /// — an operator asking "why does this host replay from genesis" needs to know
    /// whether a write never happened or happened under another format.
    ///
    /// The version-mismatch case is built by serialising a [`Snapshot`] with a
    /// deliberately wrong `format_version` rather than by writing junk, because
    /// those are different failures (undecodable vs decodable-and-refused) and
    /// both must land on `Unreadable`.
    #[test]
    fn snapshot_on_disk_separates_absent_from_unusable() {
        let dir = std::env::temp_dir().join(format!("qumbra-i359-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert_eq!(snapshot_on_disk(&dir).unwrap(), SnapshotOnDisk::Absent);
        assert_eq!(snapshot_on_disk(&dir).unwrap().height(), None);
        assert_eq!(snapshot_on_disk(&dir).unwrap().field(), "none");

        // A real snapshot: the height a restart resumes from.
        save_snapshot(&dir, &golden_snapshot()).unwrap();
        assert_eq!(snapshot_on_disk(&dir).unwrap(), SnapshotOnDisk::At { applied_height: 7 });
        assert_eq!(snapshot_on_disk(&dir).unwrap().field(), "7");
        // The same file `load_snapshot` honours — one file, two readers, one answer.
        assert_eq!(
            load_snapshot(&dir).unwrap(),
            SnapshotLoad::Loaded(golden_snapshot()),
            "load_snapshot honours what snapshot_on_disk reports a height for"
        );

        // Undecodable bytes.
        fs::write(dir.join(SNAPSHOT), b"not a snapshot at all").unwrap();
        assert_eq!(snapshot_on_disk(&dir).unwrap(), SnapshotOnDisk::Unreadable);
        assert_eq!(snapshot_on_disk(&dir).unwrap().field(), "bad");
        assert_eq!(snapshot_on_disk(&dir).unwrap().height(), None, "an unusable file has no height");
        assert!(
            matches!(
                load_snapshot(&dir).unwrap(),
                SnapshotLoad::Rejected(SnapshotLoadReject::Undecodable { .. })
            ),
            "and load_snapshot now says WHY it falls through (lab #408)"
        );

        // Decodable, but written by another on-disk format version.
        let mut wrong = golden_snapshot();
        wrong.format_version = FORMAT_VERSION + 1;
        fs::write(dir.join(SNAPSHOT), bincode::serialize(&wrong).unwrap()).unwrap();
        assert_eq!(
            snapshot_on_disk(&dir).unwrap(),
            SnapshotOnDisk::Unreadable,
            "a version this binary cannot honour is unusable, not a height"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Lab #408 items (a) and (c): `Ok(Absent)` means genuinely absent ONLY.
    /// A present-but-unusable `snapshot.bin` is a typed rejection carrying its
    /// reason — a version-mismatched file and an undecodable one are different
    /// failures with different fixes, and neither may read as "no snapshot".
    #[test]
    fn a_present_but_unusable_snapshot_is_rejected_with_its_reason_not_absent() {
        let dir = std::env::temp_dir().join(format!("qumbra-i408-load-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // (c) genuinely absent — no file — is still the quiet case.
        assert_eq!(load_snapshot(&dir).unwrap(), SnapshotLoad::Absent);

        // (a) a version-mismatched snapshot names the version it found.
        let mut wrong = golden_snapshot();
        wrong.format_version = FORMAT_VERSION + 1;
        fs::write(dir.join(SNAPSHOT), bincode::serialize(&wrong).unwrap()).unwrap();
        match load_snapshot(&dir).unwrap() {
            SnapshotLoad::Rejected(reject) => {
                assert_eq!(
                    reject,
                    SnapshotLoadReject::VersionMismatch { found: FORMAT_VERSION + 1 }
                );
                assert!(
                    reject.to_string().contains(&format!("version {}", FORMAT_VERSION + 1)),
                    "the reason an operator reads carries the found version: {reject}"
                );
            }
            other => panic!("a version-mismatched snapshot must be Rejected, got {other:?}"),
        }

        // Undecodable bytes are the other rejection, kept apart from the
        // version case (truncation-by-something-else vs a rolled binary).
        fs::write(dir.join(SNAPSHOT), b"junk").unwrap();
        assert!(matches!(
            load_snapshot(&dir).unwrap(),
            SnapshotLoad::Rejected(SnapshotLoadReject::Undecodable { .. })
        ));

        // And the healthy file still loads — the rejection is not a tightening
        // of what a usable snapshot is.
        save_snapshot(&dir, &golden_snapshot()).unwrap();
        assert_eq!(load_snapshot(&dir).unwrap(), SnapshotLoad::Loaded(golden_snapshot()));

        let _ = fs::remove_dir_all(&dir);
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

    // --- lab #367: the rider's on-disk story --------------------------------

    fn a_stored_block(rider: Vec<u8>) -> StoredBlock {
        StoredBlock { annulet: None,
            header: crate::store::StoredHeader {
                prev: h(0x11),
                height: 9_000,
                timestamp: 675_000,
                difficulty: 256,
                nonce: 7,
                tx_body_commitment: h(0x22),
            },
            txs: vec![crate::store::StoredTx { l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(),
                anchor: h(0x33),
                nullifiers: vec![h(0x44)],
                commitments: vec![h(0x55)],
                bucket_actions: 2,
                fee: 1_000_000,
                proof: vec![0xAB; 8],
                discovery: vec![0x00],
                rider,
            }],
            coinbase: 42,
            coinbase_rkm: [1, 2, 3, 4],
        }
    }

    /// A rider-free block reaches disk as **variant 0 in the frozen v3
    /// layout** — no rider byte anywhere in the record — and a rider-carrying
    /// block as the additive variant 2. `bincode` writes an enum's variant
    /// index as the first 4 LE bytes, so the claim is checkable on the raw
    /// stream rather than asserted about it.
    #[test]
    fn rider_free_blocks_keep_the_v3_layout_and_rider_carrying_ones_are_additive() {
        let free = LogRecord::Block(a_stored_block(qlab_devnet::names::RIDER_ABSENT.to_vec()));
        let free_bytes = bincode::serialize(&WireRecord::from(&free)).unwrap();
        assert_eq!(&free_bytes[..4], &[0, 0, 0, 0], "rider-free ⇒ legacy variant 0");
        // The frozen layout, independently: serialize the legacy struct alone
        // and expect it verbatim after the variant index.
        let LogRecord::Block(b) = &free else { unreachable!() };
        let legacy = LegacyStoredBlock {
            header: b.header.clone(),
            txs: vec![LegacyStoredTx {
                anchor: b.txs[0].anchor,
                nullifiers: b.txs[0].nullifiers.clone(),
                commitments: b.txs[0].commitments.clone(),
                bucket_actions: b.txs[0].bucket_actions,
                fee: b.txs[0].fee,
                proof: b.txs[0].proof.clone(),
                discovery: b.txs[0].discovery.clone(),
            }],
            coinbase: b.coinbase,
            coinbase_rkm: b.coinbase_rkm,
        };
        assert_eq!(&free_bytes[4..], &bincode::serialize(&legacy).unwrap()[..]);

        let carrying = LogRecord::Block(a_stored_block(qlab_devnet::names::encode_rider(Some(
            &qlab_devnet::names::NameOp::Commit { commit: [0x5A; 32] },
        ))));
        let carrying_bytes = bincode::serialize(&WireRecord::from(&carrying)).unwrap();
        assert_eq!(&carrying_bytes[..4], &[2, 0, 0, 0], "rider-carrying ⇒ additive variant 2");
    }

    /// 🔴 **The persisted-bytes gate of lab #706 (Q3), as a test.** A v4 block
    /// built from a *live* `BlockHeader` + `BlockBody` — so it passes through
    /// the `From` mirrors #706 touched (`ext`, `l2`) — is written through the
    /// real [`append_record`] and the raw `blocks.log` bytes are compared with
    /// a hex literal computed **outside Rust** (a Python bincode-fixint encoder
    /// of the frozen v3 legacy layout: `u32 len ‖ variant 0 ‖ header ‖ txs ‖
    /// coinbase ‖ rkm`). Adding `BlockHeader.ext` / `TxEntry.l2` moved no
    /// on-disk byte; if this fails, an L1 datadir format moved.
    #[test]
    fn a_v4_block_reaches_disk_byte_identically_to_the_frozen_layout() {
        use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
        use qlab_devnet::fees::ArityBucket;
        use qlab_devnet::header::BlockHeader;
        let mut header = BlockHeader::genesis(256, 1000);
        header.prev = [0x11; 32];
        header.height = 7;
        header.nonce = 99;
        header.tx_body_commitment = [0x22; 32];
        let tx = TxEntry {
            proof: vec![0xAB; 5],
            public: TxPublic {
                anchor: [0x0A; 32],
                nullifiers: vec![[0x0B; 32], [0x0C; 32]],
                commitments: vec![[0x0D; 32], [0x0E; 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
            discovery: vec![0x00],
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
            l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(),
        };
        let body = BlockBody::from_single_payee(vec![tx], 12_345, [1, 2, 3, 4]);
        let block = StoredBlock::from_parts(&header, &body);

        let dir = std::env::temp_dir().join(format!("qlab-persist-i706-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        append_record(&dir, &LogRecord::Block(block.clone())).unwrap();
        let on_disk = fs::read(dir.join(BLOCK_LOG)).unwrap();
        let _ = fs::remove_dir_all(&dir);

        const GOLDEN: &str = "660100000000000011111111111111111111111111111111111111111111111111111111111111110700000000000000\
         e80300000000000000010000000000006300000000000000222222222222222222222222222222222222222222222222\
         222222222222222201000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\
         02000000000000000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c\
         0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c02000000000000000d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\
         0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e\
         0200000040420f00000000000500000000000000ababababab0100000000000000003930000000000000010000000000\
         0000020000000000000003000000000000000400000000000000";
        let hex: String = on_disk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN, "an L1 on-disk block record moved (lab #706 Q3 gate)");
        assert_eq!(on_disk.len(), 362);
        // …and the mirror round-trip is lossless on L1 (ext NONE, l2 absent).
        assert_eq!(block.header(), header);
        assert_eq!(block.body().txs[0].l2, qlab_devnet::annulet::L2_SURFACE_ABSENT);
    }

    /// Both shapes round-trip through the real append/read path, and a legacy
    /// record reads back with the rider structurally absent — a fact of the
    /// format, not a migration guess.
    #[test]
    fn both_record_shapes_round_trip_through_the_log() {
        let dir = std::env::temp_dir().join(format!("qlab-persist-i367-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let free = LogRecord::Block(a_stored_block(qlab_devnet::names::RIDER_ABSENT.to_vec()));
        let carrying = LogRecord::Block(a_stored_block(qlab_devnet::names::encode_rider(Some(
            &qlab_devnet::names::NameOp::Commit { commit: [0x5A; 32] },
        ))));
        append_record(&dir, &free).unwrap();
        append_record(&dir, &carrying).unwrap();
        append_record(&dir, &LogRecord::Finalize(h(0x99))).unwrap();

        let back = read_records(&dir).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[0], free, "legacy round-trip: rider comes back absent");
        assert_eq!(back[1], carrying, "additive round-trip: rider comes back verbatim");
        assert_eq!(back[2], LogRecord::Finalize(h(0x99)));

        let _ = fs::remove_dir_all(&dir);
    }
    /// Lab #470 stage 3, the strictness rider's replay proof (coordinator
    /// condition): every value a legitimate writer produces — {2, 4, 8}, the
    /// range of `ArityBucket::logical_actions()` in every era including the
    /// dummy-latch one, which never changed it — replays green through the
    /// real writer (`append_record`) and the real reader (`read_records`).
    #[test]
    fn replay_accepts_every_writer_produced_bucket_value() {
        let dir = std::env::temp_dir().join(format!("qmb-i470-bucket-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for actions in [2u32, 4, 8] {
            let mut b = a_stored_block(qlab_devnet::names::RIDER_ABSENT.to_vec());
            b.txs[0].bucket_actions = actions;
            append_record(&dir, &LogRecord::Block(b)).unwrap();
        }
        let back = read_records(&dir).unwrap();
        assert_eq!(back.len(), 3);
        for (rec, want) in back.iter().zip([2u32, 4, 8]) {
            match rec {
                LogRecord::Block(b) => assert_eq!(b.txs[0].bucket_actions, want),
                _ => panic!("expected blocks"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rider itself: a record naming bucket_actions = 3 — which DECODES
    /// (any u32 is bincode-valid) and used to be silently coerced to TwoByTwo —
    /// is refused BY NAME at datadir open, even as the last record (it is not
    /// a torn tail; it is wrong data).
    #[test]
    fn replay_refuses_an_unknown_bucket_value_by_name() {
        let dir = std::env::temp_dir().join(format!("qmb-i470-bucket-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut b = a_stored_block(qlab_devnet::names::RIDER_ABSENT.to_vec());
        b.txs[0].bucket_actions = 3;
        append_record(&dir, &LogRecord::Block(b)).unwrap();
        let err = read_records(&dir).expect_err("bucket_actions 3 must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(msg.contains("bucket_actions 3"), "the refusal names the value: {msg}");
        assert!(msg.contains("record 0 tx 0"), "and the location: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

}
