//! **The landed-nullifier store** (lab #945; the design note and its ruling
//! on the issue): the format-34 nullifier follow, persisted beside the paid
//! ledger, so a restart resumes from the last whole height instead of paging
//! `/v1/nullifiers` from height 1.
//!
//! The file is `<paid ledger>.nullifiers`, created 0600 like the ledger. It
//! is append-only text:
//!
//! ```text
//! qumbra-prover nullifiers v1 genesis=<64 hex>
//! <height> <block id, 64 hex> <nullifier, 64 hex>*     one line per block, in height order
//! rollback <h>                                          every block line above h is void
//! ```
//!
//! A block that spends nothing still has its line (its id is what a later
//! poll compares). A poll's lines are appended and fsynced **before** the
//! set in memory advances, so the file never holds less than memory says.
//! A rollback is a line too, never a rewrite. There is no compaction in v1.
//!
//! Opening replays the file. Each outcome has a name:
//! - **a torn last line** (no newline: a crash mid-append) is cut away —
//!   unlike the paid ledger's, which is closed and kept, because the next poll
//!   re-fetches that height;
//! - **`genesis-mismatch`**: a file written for another genesis is logged,
//!   emptied to a fresh header, and the follow rebuilds from height 1;
//! - **`store-corrupt`**: a malformed line, a height out of order, or a
//!   rollback below the reorganisation window refuses the start-up, naming
//!   the line and the operator's move (move the file aside; the follow
//!   rebuilds from height 1) — a file that disagrees with itself is not
//!   silently rebuilt over;
//! - **`store-unwritable`**: a file that cannot be created, opened, read or
//!   appended refuses the start-up (an append that fails later is a failed
//!   poll: memory does not advance).

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::token::hex;

/// The store's path: the paid ledger's, with this appended.
pub const NULLIFIER_STORE_SUFFIX: &str = ".nullifiers";
/// The first line's prefix; the genesis hash (64 hex) follows.
pub const NULLIFIER_STORE_HEADER: &str = "qumbra-prover nullifiers v1 genesis=";
/// The deepest reorganisation a rollback follows (lab #945: D = 64, about
/// 10.7 min at a 10 s slot): the window keeps the last `D + 1` blocks, so the
/// common block of a reorganisation `D` deep is still in it. Deeper rebuilds
/// the set from height 1.
pub const REORG_WINDOW: usize = 64;

/// One followed block: its height, its id (the sealed header's
/// `SealedHeader::id`), and the nullifiers it published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FollowedBlock {
    pub height: u64,
    pub id: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
}

/// What a replay rebuilt: the landed set, the height it reaches, and the
/// last [`REORG_WINDOW`] + 1 blocks (oldest first).
#[derive(Debug, Default)]
pub struct Replayed {
    pub landed: HashSet<[u8; 32]>,
    pub height: u64,
    pub window: VecDeque<FollowedBlock>,
}

impl Replayed {
    /// Follow `block` (the next height): its nullifiers join the set, it
    /// joins the window, and the oldest leaves the window past
    /// [`REORG_WINDOW`] + 1.
    pub fn push(&mut self, block: FollowedBlock) {
        self.landed.extend(block.nullifiers.iter().copied());
        self.height = block.height;
        self.window.push_back(block);
        while self.window.len() > REORG_WINDOW + 1 {
            self.window.pop_front();
        }
    }

    /// Back to height `a`: every block above it leaves the set and the
    /// window. Exact, because the double-spend rule puts a nullifier in at
    /// most one block. `false` (nothing changed) when a height above `a` is
    /// no longer in the window.
    pub fn roll_back_to(&mut self, a: u64) -> bool {
        let lowest = self.window.front().map_or(self.height + 1, |b| b.height);
        if a > self.height || a + 1 < lowest {
            return false;
        }
        while self.window.back().is_some_and(|b| b.height > a) {
            let b = self.window.pop_back().expect("checked");
            for nf in &b.nullifiers {
                self.landed.remove(nf);
            }
        }
        self.height = a;
        true
    }
}

/// The store's open file (module doc).
pub struct NullifierStore {
    path: PathBuf,
    file: File,
    genesis: [u8; 32],
}

fn unwritable(path: &Path, what: &str) -> String {
    format!("store-unwritable: the nullifier store {} could not be {what}", path.display())
}

fn corrupt(path: &Path, line: usize, why: &str) -> String {
    format!(
        "store-corrupt: the nullifier store {} line {line}: {why}; move {} aside and the follow rebuilds from height 1",
        path.display(),
        path.display()
    )
}

fn header(genesis: &[u8; 32]) -> String {
    format!("{NULLIFIER_STORE_HEADER}{}\n", hex(genesis))
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

impl NullifierStore {
    /// The store for the ledger at `ledger`.
    pub fn path_for(ledger: &Path) -> PathBuf {
        let mut p = ledger.as_os_str().to_owned();
        p.push(NULLIFIER_STORE_SUFFIX);
        PathBuf::from(p)
    }

    /// Open the store at `path` for `genesis` (created 0600 when absent) and
    /// replay it, refusing by name (module doc).
    pub fn open(path: &Path, genesis: &[u8; 32]) -> Result<(Self, Replayed), String> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.append(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path).map_err(|_| unwritable(path, "created"))?;
                file.write_all(header(genesis).as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| unwritable(path, "written"))?;
                let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
                File::open(dir).and_then(|d| d.sync_all()).map_err(|_| unwritable(path, "synced into its directory"))?;
                Ok((Self { path: path.to_path_buf(), file, genesis: *genesis }, Replayed::default()))
            }
            Err(_) => Err(unwritable(path, "read")),
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(format!("store-unwritable: the nullifier store {} is not a regular file", path.display()));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return Err(format!(
                            "store-unwritable: the nullifier store {} must be readable and writable by its owner only (0600)",
                            path.display()
                        ));
                    }
                }
                let mut file = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(path)
                    .map_err(|_| unwritable(path, "opened for appending"))?;
                let mut raw = Vec::new();
                file.read_to_end(&mut raw).map_err(|_| unwritable(path, "read"))?;
                // A torn last line: cut back to the last newline.
                let whole = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                if whole < raw.len() {
                    file.set_len(whole as u64)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| unwritable(path, "cut back to its last whole line"))?;
                    eprintln!(
                        "qumbra-prover-service: the nullifier store {} ended in a torn line ({} bytes); it was cut away",
                        path.display(),
                        raw.len() - whole
                    );
                }
                let mut store = Self { path: path.to_path_buf(), file, genesis: *genesis };
                let text = std::str::from_utf8(&raw[..whole]).map_err(|_| corrupt(path, 1, "not text"))?;
                let mut lines = text.lines();
                let first = lines.next().unwrap_or_default();
                let written_for = first
                    .strip_prefix(NULLIFIER_STORE_HEADER)
                    .and_then(hex32)
                    .ok_or_else(|| corrupt(path, 1, "not a version-1 nullifier store header"))?;
                if written_for != *genesis {
                    eprintln!(
                        "qumbra-prover-service: genesis-mismatch: the nullifier store {} was written for genesis {}, not {}; \
                         it is emptied and the follow rebuilds from height 1",
                        path.display(),
                        hex(&written_for),
                        hex(genesis)
                    );
                    store.reset().map_err(|_| unwritable(path, "emptied"))?;
                    return Ok((store, Replayed::default()));
                }
                let mut replayed = Replayed::default();
                for (i, line) in lines.enumerate() {
                    let n = i + 2;
                    let mut words = line.split(' ');
                    let first = words.next().unwrap_or_default();
                    if first == "rollback" {
                        let a: u64 = words
                            .next()
                            .and_then(|w| w.parse().ok())
                            .filter(|_| words.next().is_none())
                            .ok_or_else(|| corrupt(path, n, "a malformed rollback line"))?;
                        if !replayed.roll_back_to(a) {
                            return Err(corrupt(path, n, &format!("a rollback to {a} outside the followed window")));
                        }
                        continue;
                    }
                    let height: u64 = first.parse().map_err(|_| corrupt(path, n, "not a block line"))?;
                    if height != replayed.height + 1 {
                        return Err(corrupt(
                            path,
                            n,
                            &format!("height {height} follows height {}", replayed.height),
                        ));
                    }
                    let id = words.next().and_then(hex32).ok_or_else(|| corrupt(path, n, "no block id"))?;
                    let nullifiers = words
                        .map(|w| hex32(w).ok_or_else(|| corrupt(path, n, "a malformed nullifier")))
                        .collect::<Result<Vec<_>, _>>()?;
                    replayed.push(FollowedBlock { height, id, nullifiers });
                }
                Ok((store, replayed))
            }
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append `lines` and fsync them; on failure the file is cut back to its
    /// length before the write (best effort).
    fn append(&mut self, lines: &str) -> std::io::Result<()> {
        let before = self.file.metadata()?.len();
        let written = self.file.write_all(lines.as_bytes()).and_then(|()| self.file.sync_data());
        if written.is_err() {
            let _ = self.file.set_len(before).and_then(|()| self.file.sync_data());
        }
        written
    }

    /// Append one poll's blocks, fsynced.
    pub fn append_blocks(&mut self, blocks: &[FollowedBlock]) -> std::io::Result<()> {
        let mut lines = String::new();
        for b in blocks {
            lines.push_str(&format!("{} {}", b.height, hex(&b.id)));
            for nf in &b.nullifiers {
                lines.push(' ');
                lines.push_str(&hex(nf));
            }
            lines.push('\n');
        }
        self.append(&lines)
    }

    /// Append `rollback a`, fsynced.
    pub fn rollback(&mut self, a: u64) -> std::io::Result<()> {
        self.append(&format!("rollback {a}\n"))
    }

    /// Empty the file to a fresh header (a reorganisation deeper than the
    /// window, or another genesis), fsynced.
    pub fn reset(&mut self) -> std::io::Result<()> {
        self.file.set_len(0)?;
        self.file.write_all(header(&self.genesis).as_bytes())?;
        self.file.sync_all()
    }
}
