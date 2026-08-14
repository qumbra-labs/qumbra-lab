//! Local commitment-tree sync over the leaf stream, and the anchor a spend is
//! actually built against — the wallet half of the stamped A1+B1 decision
//! (issue #276, `t1-wallet-send-seams-decision.md`).
//!
//! The wallet maintains its own [`CommitmentTree`] from `GET
//! /v1/tree/leaves?from=N` and computes `auth_path` locally, so the server
//! learns which IP syncs leaves and **nothing positional** — never which leaf a
//! spend is about (the brief's B2 rejection).
//!
//! ```text
//!   <dir>/tree-leaves.v1   [version byte ‖ n×32-byte leaf cms, append order]
//! ```
//!
//! The cache file IS the high-water mark: its leaf count is where the next sync
//! resumes (`from=len`), so a wallet never re-downloads what it holds. Leaves
//! are public chain data — the cache is neither secret nor precious; a corrupt
//! cache is refused by name and the safe recovery is deleting it (one full
//! re-download, no funds at stake). Each successful sync rewrites the file via
//! temp-file + rename, so a torn write can never masquerade as a shorter valid
//! cache.
//!
//! # Two steps, because the wire has two questions in it
//!
//! [`sync_tree`] replays the stream into the local tree. It cannot verify
//! anything by itself: the served framing is
//! `version ‖ from ‖ total ‖ n ‖ leaves` (`qlab_node::TreeLeaves`, golden-locked
//! by #275) and **carries no root** — `total` is the live leaf count at the
//! serving node's *applied tip*, which is not a claim anybody signed.
//!
//! [`select_anchor`] is where the verification and the selection happen, and
//! they are deliberately the same act. A valid anchor is a **finalized** root
//! (`Node::is_valid_anchor`: height ≤ finalized, within `MAX_ANCHOR_AGE_BLOCKS`
//! of tip), so the wallet walks its local leaf counts down from the top and
//! takes the largest count whose reconstructed root is one the node serves as
//! an anchor. That single step answers both questions at once:
//!
//! - **Did the stream tell the truth?** A doctored or reordered stream
//!   reconstructs to roots that are not in the served anchor set, so no count
//!   matches and [`SyncRefusal::NoVerifiedAnchor`] fires. A lying stream is
//!   censorship, not forgery (§3-B1): the server can withhold leaves, it cannot
//!   make this wallet build a witness against a tree the chain never had.
//! - **Which count may a witness be built at?** The matched count, and only it.
//!   Building at the local tip instead would declare an unfinalized root, which
//!   `POST /v1/tx` refuses as `anchor-not-valid` on every net whose finality
//!   runs on a cadence — see the issue #276 finding.
//!
//! What fetches the chunks is a [`LeafSource`] and what serves the anchors is
//! an [`AnchorSource`]; `crate::net` implements both over HTTP, and the logic
//! here is testable against in-memory ones.

use std::io;
use std::path::{Path, PathBuf};

use qlab_cbserver::tree::CommitmentTree;
use qlab_note::hash::digest_bytes;

/// The leaf-cache file inside the wallet dir. Versioned, reject-unknown — the
/// same persistence discipline as `wallet.seed` / `addresses.v1`.
pub const LEAVES_FILE: &str = "tree-leaves.v1";

/// The cache format this binary reads and writes. One byte, first in the file.
pub const LEAVES_FILE_VERSION: u8 = 1;

/// One bounded response from the leaf stream — the wallet-side shape of
/// `qlab_node::TreeLeaves`, field for field, so there is no second reading of
/// the golden framing.
#[derive(Clone, Debug)]
pub struct LeafChunk {
    /// Index of `leaves[0]` in the tree — the server's **echo** of the
    /// requested `from`. Checked, not trusted: the wire carries it precisely so
    /// a paging client cannot misattribute a response.
    pub from: u64,
    /// The serving tree's live leaf count when it answered. Both the loop
    /// condition and the honest answer to a `from` past the end (an empty page
    /// carrying `total`, never an error).
    pub total: u64,
    /// Leaf note commitments (on-wire 32-byte form), authoritative append
    /// order, starting exactly at `from`. At most `MAX_TREE_LEAVES`.
    pub leaves: Vec<[u8; 32]>,
}

/// Where leaves come from. The real implementation is
/// [`crate::net::HttpLeafSource`] over `GET /v1/tree/leaves?from=N`; tests
/// inject their own.
pub trait LeafSource {
    /// Fetch one bounded chunk starting at leaf index `from`. An `Err` is a
    /// transport/decode failure, verbatim — the sync turns it into the named
    /// endpoint refusal.
    fn fetch_from(&self, from: u64) -> Result<LeafChunk, String>;
}

/// The node's valid-anchor set — the wallet-side shape of
/// `qlab_node::AnchorSet`, carrying the window context a refusal needs to be
/// legible.
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    /// Fork-choice tip height.
    pub tip_height: u64,
    /// Finalized head height, if anything is finalized at all.
    pub finalized_height: Option<u64>,
    /// How far below tip an anchor may be before it ages out.
    pub max_age_blocks: u64,
    /// Roots that are valid anchors right now, newest first.
    pub roots: Vec<[u8; 32]>,
}

/// Where the valid-anchor set comes from. [`crate::net::HttpAnchorSource`]
/// serves it over `GET /v1/anchors`.
pub trait AnchorSource {
    fn anchors(&self) -> Result<Anchors, String>;
}

/// Every way a sync or an anchor selection refuses, each with its reason named
/// — no boolean blindness on this path (the same house style as the submit
/// endpoint's typed refusals).
#[derive(Debug)]
pub enum SyncRefusal {
    /// The endpoint could not be reached or its response could not be decoded.
    Endpoint { why: String },
    /// The response's `from` is not the one that was asked for. The wire echoes
    /// `from` so a paging client cannot misattribute a page to the wrong
    /// offset; this is that check, not a formality.
    FromMismatch { asked: u64, got: u64 },
    /// The endpoint serves fewer leaves than the local cache holds. An
    /// append-only tree never rewinds, so either the endpoint is behind (try
    /// again, or another node) or this cache was synced against a different
    /// net — and this code will not guess which.
    StreamBehindLocal { served: u64, local: u64 },
    /// The endpoint claims more leaves than it returned, repeatedly, without
    /// progress — refused rather than looped on forever.
    NoProgress { at: u64, claimed: u64 },
    /// The node serves no valid anchors at all: nothing is finalized yet, so
    /// there is nothing legal to build a witness against. Distinct from a
    /// mismatch — the chain is young, not lying.
    NoAnchorsYet { tip_height: u64 },
    /// **No leaf count in the local tree reproduces any root the node serves as
    /// an anchor.** Either the stream this tree was built from does not
    /// describe the chain the node is on, or every anchor is older than the
    /// wallet's oldest reconstructable state. Nothing was spent, nothing was
    /// proved: this is the detection working.
    NoVerifiedAnchor {
        local_count: u64,
        served_roots: usize,
        tip_height: u64,
        finalized_height: Option<u64>,
    },
    /// A cache file this binary does not understand. Never guessed at, never
    /// truncated to fit: the named fix is deleting it (leaves are public chain
    /// data; the cost is one full re-download, never funds).
    BadCache { path: PathBuf, why: String },
    /// The cache could not be read or written.
    Io(io::Error),
}

impl std::fmt::Display for SyncRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncRefusal::Endpoint { why } => {
                write!(f, "tree sync never completed: the leaf endpoint refused or was unreachable ({why})")
            }
            SyncRefusal::FromMismatch { asked, got } => write!(
                f,
                "tree sync refused: asked the leaf stream for offset {asked} and it answered for \
                 {got}. The wire echoes `from` so a page cannot be misattributed; refusing to \
                 append leaves at an offset nobody claimed"
            ),
            SyncRefusal::StreamBehindLocal { served, local } => write!(
                f,
                "tree sync refused: the endpoint serves {served} leaves but the local cache \
                 already holds {local}. An append-only tree never rewinds — either this endpoint \
                 is behind (retry, or use another node) or the cache was synced against a \
                 different net; refusing to guess which"
            ),
            SyncRefusal::NoProgress { at, claimed } => write!(
                f,
                "tree sync refused: the endpoint claims {claimed} leaves but returned none past \
                 {at} — refusing to poll it forever"
            ),
            SyncRefusal::NoAnchorsYet { tip_height } => write!(
                f,
                "no spend is possible yet: the node is at tip {tip_height} with nothing finalized, \
                 so it serves no valid anchors. A witness must be built against a FINALIZED root; \
                 wait for the first checkpoint"
            ),
            SyncRefusal::NoVerifiedAnchor {
                local_count,
                served_roots,
                tip_height,
                finalized_height,
            } => write!(
                f,
                "tree sync refused: no leaf count from 0..={local_count} reconstructs any of the \
                 {served_roots} anchor(s) this node serves (tip {tip_height}, finalized {}). The \
                 leaf stream and the node's own anchors disagree — a lying stream is censorship, \
                 not forgery: nothing was persisted as verified, no witness will be built against \
                 it, and no proof was spent. If the node is honest and merely far ahead, delete \
                 {LEAVES_FILE} and re-sync",
                match finalized_height {
                    Some(h) => h.to_string(),
                    None => "none".to_string(),
                }
            ),
            SyncRefusal::BadCache { path, why } => write!(
                f,
                "unreadable leaf cache {}: {why}. It caches PUBLIC chain data only — delete it \
                 and re-sync (a full re-download; no key material, no funds at stake)",
                path.display()
            ),
            SyncRefusal::Io(e) => write!(f, "leaf cache I/O: {e}"),
        }
    }
}

impl std::error::Error for SyncRefusal {}

impl From<io::Error> for SyncRefusal {
    fn from(e: io::Error) -> Self {
        SyncRefusal::Io(e)
    }
}

/// Lowercase hex of a 32-byte root — how an anchor is shown to a person (the
/// CLI prints the anchor it built against, so a refused submission can be
/// argued about against the node's own `/v1/anchors`).
pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The local tree as the stream left it. **Not yet verified against anything**
/// — that is [`select_anchor`]'s job, and the type deliberately does not carry
/// an anchor so a caller cannot mistake "downloaded" for "checked".
pub struct SyncedTree {
    pub tree: CommitmentTree,
    /// Leaves held locally after this sync (the local tip).
    pub count: u64,
    /// Leaves fetched by THIS sync (0 = the cache was already current).
    pub fetched: u64,
}

impl std::fmt::Debug for SyncedTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tree itself is leaf data; the two numbers say what a debugger needs.
        f.debug_struct("SyncedTree")
            .field("count", &self.count)
            .field("fetched", &self.fetched)
            .finish()
    }
}

/// A leaf count whose reconstructed root the node serves as a valid anchor.
/// This `(tree, count)` pair is exactly what [`crate::spend::select`] turns into
/// a witness bundle — the caller-owned correspondence, now actually established.
#[derive(Clone, Debug)]
pub struct VerifiedAnchor {
    /// The leaf count to build the witness at (`anchor_count`).
    pub count: u64,
    /// The root at that count — verified equal to one the node serves.
    pub root: [u8; 32],
    /// How far below the local tip this anchor sits, in leaves. 0 means the
    /// node's finalized state is caught up with what it served.
    pub leaves_behind_local: u64,
    /// The node's tip height when it answered.
    pub tip_height: u64,
    /// The node's finalized height when it answered.
    pub finalized_height: Option<u64>,
}

/// Sync the wallet dir's leaf cache against `source`: resume from the cached
/// count and append until caught up with the endpoint's claimed size.
///
/// Refusals are named ([`SyncRefusal`]) and leave the cache exactly as it was —
/// a refused sync costs nothing and can be retried.
pub fn sync_tree(dir: &Path, source: &impl LeafSource) -> Result<SyncedTree, SyncRefusal> {
    let path = dir.join(LEAVES_FILE);
    let mut catch = TreeCatchUp::new(load_cache(&path)?);
    while let Some(from) = catch.want_from() {
        let chunk = source.fetch_from(from).map_err(|why| SyncRefusal::Endpoint { why })?;
        catch.supply(chunk)?;
    }
    let synced = catch.finish();
    persist_cache(&path, &synced.tree)?;
    Ok(synced)
}

/// The chunk-accumulation half of [`sync_tree`], caller-pumped — **one copy of
/// the catch-up protocol** (lab #399), shared by the synchronous pump above and
/// the select driver. The endpoint's tree can grow between chunks; the catch-up
/// chases the LAST claim it saw, and every check the pump ever made lives HERE:
/// the wire's `from` echo, behind-local, overshoot, and no-progress.
pub struct TreeCatchUp {
    tree: CommitmentTree,
    start: u64,
    done: bool,
}

impl TreeCatchUp {
    /// `tree` is whatever the caller already holds — the dir cache for the CLI,
    /// storage-held leaves for a wasm host, or an empty tree on first sync.
    pub fn new(tree: CommitmentTree) -> TreeCatchUp {
        let start = tree.len();
        TreeCatchUp { tree, start, done: false }
    }

    /// The leaf index to ask the endpoint for next, or `None` once caught up.
    /// The first ask always happens: only the endpoint's own `total` claim can
    /// say the cache is current.
    pub fn want_from(&self) -> Option<u64> {
        (!self.done).then(|| self.tree.len())
    }

    /// Feed one chunk.
    pub fn supply(&mut self, chunk: LeafChunk) -> Result<(), SyncRefusal> {
        if self.done {
            return Err(SyncRefusal::Endpoint {
                why: "a chunk was supplied after the catch-up completed".into(),
            });
        }
        if chunk.from != self.tree.len() {
            return Err(SyncRefusal::FromMismatch { asked: self.tree.len(), got: chunk.from });
        }
        if chunk.total < self.tree.len() {
            return Err(SyncRefusal::StreamBehindLocal {
                served: chunk.total,
                local: self.tree.len(),
            });
        }
        if self.tree.len() + chunk.leaves.len() as u64 > chunk.total {
            // A chunk that overshoots its own `total` claim is malformed.
            return Err(SyncRefusal::Endpoint {
                why: format!(
                    "chunk of {} leaves from {} overshoots the endpoint's own claimed size {}",
                    chunk.leaves.len(),
                    self.tree.len(),
                    chunk.total
                ),
            });
        }
        let empty = chunk.leaves.is_empty();
        for cm in &chunk.leaves {
            self.tree.append_bytes(cm);
        }
        if chunk.total == self.tree.len() {
            self.done = true; // caught up with this claim
        } else if empty {
            return Err(SyncRefusal::NoProgress { at: self.tree.len(), claimed: chunk.total });
        }
        Ok(())
    }

    pub fn finish(self) -> SyncedTree {
        let count = self.tree.len();
        SyncedTree { tree: self.tree, count, fetched: count - self.start }
    }
}

/// Find the largest leaf count whose reconstructed root the node serves as a
/// valid anchor — the verification and the selection in one act (see the module
/// docs for why they are the same thing).
///
/// Walks down from the local tip. Worst case it computes `root_at` for every
/// count, which is the refusal path and is bounded by the tree the wallet
/// already holds; at devnet leaf counts that is cheap next to the ~3 s / ~12 GB
/// prove it guards. The brief's §4 overturn trigger (leaf-stream cost at real
/// chain length) owns the day this measures impractically large — the fix there
/// is a checkpointed variant, and it would land here.
pub fn select_anchor(synced: &SyncedTree, anchors: &Anchors) -> Result<VerifiedAnchor, SyncRefusal> {
    if anchors.roots.is_empty() {
        return Err(SyncRefusal::NoAnchorsYet { tip_height: anchors.tip_height });
    }
    let served: std::collections::HashSet<[u8; 32]> = anchors.roots.iter().copied().collect();
    for count in (0..=synced.count).rev() {
        let root = digest_bytes(&synced.tree.root_at(count));
        if served.contains(&root) {
            return Ok(VerifiedAnchor {
                count,
                root,
                leaves_behind_local: synced.count - count,
                tip_height: anchors.tip_height,
                finalized_height: anchors.finalized_height,
            });
        }
    }
    Err(SyncRefusal::NoVerifiedAnchor {
        local_count: synced.count,
        served_roots: anchors.roots.len(),
        tip_height: anchors.tip_height,
        finalized_height: anchors.finalized_height,
    })
}

/// Sync, then select — the whole witness-source story the CLI runs, in one
/// call, so a caller cannot accidentally build against an unverified tip.
pub fn sync_and_select(
    dir: &Path,
    leaves: &impl LeafSource,
    anchors: &impl AnchorSource,
) -> Result<(SyncedTree, VerifiedAnchor), SyncRefusal> {
    let synced = sync_tree(dir, leaves)?;
    let set = anchors.anchors().map_err(|why| SyncRefusal::Endpoint { why })?;
    let anchor = select_anchor(&synced, &set)?;
    Ok((synced, anchor))
}

/// Load the leaf cache, or an empty tree when none exists yet (first sync).
pub(crate) fn load_cache(path: &Path) -> Result<CommitmentTree, SyncRefusal> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(CommitmentTree::new()),
        Err(e) => return Err(e.into()),
    };
    let bad = |why: String| SyncRefusal::BadCache { path: path.to_path_buf(), why };
    let Some((&version, leaves)) = bytes.split_first() else {
        return Err(bad("empty file".into()));
    };
    if version != LEAVES_FILE_VERSION {
        return Err(bad(format!(
            "version {version}; this binary knows version {LEAVES_FILE_VERSION} only"
        )));
    }
    if leaves.len() % 32 != 0 {
        return Err(bad(format!(
            "{} leaf bytes is not a whole number of 32-byte commitments (torn write?)",
            leaves.len()
        )));
    }
    let mut tree = CommitmentTree::new();
    for cm in leaves.chunks_exact(32) {
        tree.append_bytes(cm.try_into().expect("chunks_exact(32)"));
    }
    Ok(tree)
}

/// Persist the whole cache atomically: temp file + rename, so a torn write can
/// never read back as a shorter-but-valid cache. Rewriting in full is a
/// deliberate simplicity trade at devnet scale (32 B/leaf); the brief's §4
/// overturn trigger owns the day this measures impractically large.
pub(crate) fn persist_cache(path: &Path, tree: &CommitmentTree) -> Result<(), SyncRefusal> {
    let mut out = Vec::with_capacity(1 + tree.len() as usize * 32);
    out.push(LEAVES_FILE_VERSION);
    for pos in 0..tree.len() {
        out.extend_from_slice(&digest_bytes(&tree.leaf(pos)));
    }
    let tmp = path.with_extension("v1.tmp");
    std::fs::write(&tmp, &out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_wallet_sync_{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cm(seed: u64) -> [u8; 32] {
        let lanes: [u64; 4] =
            core::array::from_fn(|i| seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(i as u64 + 1));
        digest_bytes(&lanes)
    }

    fn root_of(n: u64) -> [u8; 32] {
        let mut t = CommitmentTree::new();
        for i in 0..n {
            t.append_bytes(&cm(i));
        }
        digest_bytes(&t.root())
    }

    /// An honest in-memory endpoint over `n` leaves, serving bounded chunks and
    /// recording every `from` it was asked for — the shape `TreeLeaves::page`
    /// serves, echo included.
    struct Honest {
        leaves: Vec<[u8; 32]>,
        chunk: usize,
        asked: RefCell<Vec<u64>>,
    }

    impl Honest {
        fn new(n: u64, chunk: usize) -> Honest {
            Honest { leaves: (0..n).map(cm).collect(), chunk, asked: RefCell::new(Vec::new()) }
        }
    }

    impl LeafSource for Honest {
        fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
            self.asked.borrow_mut().push(from);
            let total = self.leaves.len() as u64;
            let start = (from.min(total)) as usize;
            let end = (start + self.chunk).min(self.leaves.len());
            Ok(LeafChunk { from, total, leaves: self.leaves[start..end].to_vec() })
        }
    }

    /// An anchor source serving the roots at the given counts.
    struct At(Vec<u64>, u64, Option<u64>);
    impl AnchorSource for At {
        fn anchors(&self) -> Result<Anchors, String> {
            Ok(Anchors {
                tip_height: self.1,
                finalized_height: self.2,
                max_age_blocks: 1152,
                roots: self.0.iter().map(|c| root_of(*c)).collect(),
            })
        }
    }

    #[test]
    fn a_fresh_sync_downloads_chunks_and_persists() {
        let d = tmp("fresh");
        let src = Honest::new(10, 3); // 4 chunks: 3+3+3+1
        let s = sync_tree(&d, &src).unwrap();
        assert_eq!(s.count, 10);
        assert_eq!(s.fetched, 10);
        assert_eq!(s.tree.len(), 10);
        assert_eq!(*src.asked.borrow(), vec![0, 3, 6, 9], "bounded chunks, client loops");
        // The cache file is version byte + 10 × 32 B.
        assert_eq!(std::fs::read(d.join(LEAVES_FILE)).unwrap().len(), 1 + 10 * 32);
    }

    #[test]
    fn a_second_sync_resumes_from_the_high_water_mark_never_redownloading() {
        let d = tmp("resume");
        sync_tree(&d, &Honest::new(6, 100)).unwrap();

        // The chain grew by 3; the wallet asks from 6 — never from 0.
        let grown = Honest::new(9, 100);
        let s = sync_tree(&d, &grown).unwrap();
        assert_eq!(s.count, 9);
        assert_eq!(s.fetched, 3, "only the new leaves travel");
        assert_eq!(*grown.asked.borrow(), vec![6], "resume point is the cached count");

        // Nothing new: fetched = 0.
        let same = Honest::new(9, 100);
        let s2 = sync_tree(&d, &same).unwrap();
        assert_eq!(s2.fetched, 0);
        assert_eq!(s2.count, 9);
    }

    /// The load-bearing property (issue #276's finding): the anchor selected is
    /// a FINALIZED one, which on a net with a finality cadence is BELOW the
    /// local tip. Building at the tip would declare an unfinalized root.
    #[test]
    fn the_selected_anchor_is_the_newest_finalized_one_not_the_local_tip() {
        let d = tmp("select");
        let synced = sync_tree(&d, &Honest::new(12, 100)).unwrap();
        assert_eq!(synced.count, 12, "the wallet holds the served tip");

        // The node has finalized only as far as 8 leaves; 10 is stale-but-valid.
        let anchor = select_anchor(&synced, &At(vec![8, 10], 40, Some(33)).anchors().unwrap())
            .expect("a finalized anchor is selectable");
        assert_eq!(anchor.count, 10, "the LARGEST valid anchor, not the local tip");
        assert_eq!(anchor.root, root_of(10));
        assert_eq!(anchor.leaves_behind_local, 2, "and it is honestly behind the tip");
        assert_eq!(anchor.finalized_height, Some(33));

        // The witness built at it folds to the anchor root — the correspondence
        // the witness-bundle builder relies on.
        let w = synced.tree.auth_path(3, anchor.count);
        assert_eq!(digest_bytes(&w.fold_root(&synced.tree.leaf(3))), anchor.root);
    }

    /// A doctored stream reconstructs to roots nobody anchors — the detection
    /// the whole B1 posture leans on, now expressed against the real wire
    /// (which carries no root of its own to compare).
    #[test]
    fn a_doctored_stream_matches_no_served_anchor_and_is_refused_by_name() {
        let d = tmp("doctored");
        struct Doctored;
        impl LeafSource for Doctored {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                // Same count as the honest tree, different leaves.
                Ok(LeafChunk {
                    from,
                    total: 6,
                    leaves: (from..6).map(|i| cm(i + 9_000)).collect(),
                })
            }
        }
        let synced = sync_tree(&d, &Doctored).unwrap();
        let e = match select_anchor(&synced, &At(vec![4, 6], 20, Some(18)).anchors().unwrap()) {
            Err(e) => e,
            Ok(a) => panic!("a doctored stream must not yield an anchor, got {a:?}"),
        };
        assert!(matches!(e, SyncRefusal::NoVerifiedAnchor { local_count: 6, served_roots: 2, .. }), "{e}");
        let msg = e.to_string();
        assert!(msg.contains("censorship, not forgery"), "{msg}");
        assert!(msg.contains("no proof was spent"), "{msg}");
    }

    /// Nothing finalized is a different state from a lying stream, and says so.
    #[test]
    fn a_chain_with_nothing_finalized_refuses_by_a_different_name() {
        let d = tmp("nofinal");
        let synced = sync_tree(&d, &Honest::new(5, 100)).unwrap();
        let e = select_anchor(&synced, &Anchors { tip_height: 7, ..Anchors::default() }).unwrap_err();
        assert!(matches!(e, SyncRefusal::NoAnchorsYet { tip_height: 7 }), "{e}");
        assert!(e.to_string().contains("wait for the first checkpoint"), "{e}");
    }

    /// The wire echoes `from` so a page cannot be misattributed. A server that
    /// answers for a different offset is refused before a leaf is appended.
    #[test]
    fn a_page_answering_the_wrong_offset_is_refused_before_it_is_appended() {
        let d = tmp("echo");
        struct WrongEcho;
        impl LeafSource for WrongEcho {
            fn fetch_from(&self, _from: u64) -> Result<LeafChunk, String> {
                Ok(LeafChunk { from: 7, total: 9, leaves: vec![cm(0), cm(1)] })
            }
        }
        let e = sync_tree(&d, &WrongEcho).unwrap_err();
        assert!(matches!(e, SyncRefusal::FromMismatch { asked: 0, got: 7 }), "{e}");
        assert!(!d.join(LEAVES_FILE).exists(), "nothing was persisted");
    }

    #[test]
    fn an_endpoint_behind_the_cache_is_refused_not_rewound() {
        let d = tmp("behind");
        sync_tree(&d, &Honest::new(8, 100)).unwrap();
        let e = match sync_tree(&d, &Honest::new(5, 100)) {
            Err(e) => e,
            Ok(_) => panic!("an endpoint behind the cache must refuse"),
        };
        assert!(matches!(e, SyncRefusal::StreamBehindLocal { served: 5, local: 8 }), "{e}");
        assert!(e.to_string().contains("never rewinds"), "{}", e);
    }

    #[test]
    fn an_unreachable_endpoint_is_a_named_refusal() {
        let d = tmp("unreachable");
        struct Down;
        impl LeafSource for Down {
            fn fetch_from(&self, _: u64) -> Result<LeafChunk, String> {
                Err("connection refused".into())
            }
        }
        let e = sync_tree(&d, &Down).unwrap_err();
        assert!(matches!(e, SyncRefusal::Endpoint { .. }));
        assert!(e.to_string().contains("connection refused"), "{e}");
    }

    #[test]
    fn a_stalling_endpoint_is_refused_not_polled_forever() {
        let d = tmp("stall");
        struct Stall;
        impl LeafSource for Stall {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                // Claims 5 leaves, serves none past 2.
                Ok(LeafChunk { from, total: 5, leaves: (from..2).map(cm).collect() })
            }
        }
        let e = sync_tree(&d, &Stall).unwrap_err();
        assert!(matches!(e, SyncRefusal::NoProgress { at: 2, claimed: 5 }), "{e}");
    }

    #[test]
    fn a_chunk_overshooting_its_own_size_claim_is_malformed() {
        let d = tmp("overshoot");
        struct Overshoot;
        impl LeafSource for Overshoot {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                Ok(LeafChunk { from, total: 3, leaves: (from..4).map(cm).collect() })
            }
        }
        let e = sync_tree(&d, &Overshoot).unwrap_err();
        assert!(matches!(e, SyncRefusal::Endpoint { .. }), "{e}");
        assert!(e.to_string().contains("overshoots"), "{e}");
    }

    #[test]
    fn a_corrupt_cache_is_refused_by_name_with_the_safe_fix() {
        let d = tmp("corrupt");
        // Unknown version byte.
        std::fs::write(d.join(LEAVES_FILE), [9u8]).unwrap();
        let e = sync_tree(&d, &Honest::new(1, 100)).unwrap_err();
        assert!(matches!(e, SyncRefusal::BadCache { .. }));
        let msg = e.to_string();
        assert!(msg.contains("version 9"), "{msg}");
        assert!(msg.contains("delete it"), "{msg}");
        assert!(msg.contains("no funds at stake"), "{msg}");

        // Torn write: not a whole number of leaves.
        let mut torn = vec![LEAVES_FILE_VERSION];
        torn.extend_from_slice(&[0u8; 33]);
        std::fs::write(d.join(LEAVES_FILE), torn).unwrap();
        let e = sync_tree(&d, &Honest::new(1, 100)).unwrap_err();
        assert!(e.to_string().contains("torn write"), "{e}");
    }

    /// The endpoint's tree grows while the wallet is mid-sync: the loop chases
    /// the newest claim.
    #[test]
    fn a_growing_endpoint_is_chased_to_its_latest_claim() {
        let d = tmp("growing");
        struct Growing;
        impl LeafSource for Growing {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                let total: u64 = if from < 4 { 4 } else { 6 };
                Ok(LeafChunk { from, total, leaves: (from..total).map(cm).collect() })
            }
        }
        let s = sync_tree(&d, &Growing).unwrap();
        assert_eq!(s.count, 4);
        let s2 = sync_tree(&d, &Growing).unwrap();
        assert_eq!(s2.count, 6);
        assert_eq!(s2.fetched, 2);
    }

    /// `sync_and_select` is the CLI's one call, and a refused selection still
    /// leaves the downloaded cache in place — leaves are public data and
    /// re-downloading them is the only thing a retry would otherwise repeat.
    #[test]
    fn sync_and_select_runs_both_steps_and_keeps_the_cache_on_a_refused_selection() {
        let d = tmp("both");
        let (synced, anchor) =
            sync_and_select(&d, &Honest::new(9, 4), &At(vec![9], 12, Some(12))).unwrap();
        assert_eq!(synced.count, 9);
        assert_eq!(anchor.count, 9);
        assert_eq!(anchor.leaves_behind_local, 0);

        // Same tree, an anchor set from a different chain: refused, cache kept.
        let before = std::fs::read(d.join(LEAVES_FILE)).unwrap();
        struct Foreign;
        impl AnchorSource for Foreign {
            fn anchors(&self) -> Result<Anchors, String> {
                Ok(Anchors {
                    tip_height: 12,
                    finalized_height: Some(12),
                    max_age_blocks: 1152,
                    roots: vec![[0x5A; 32]],
                })
            }
        }
        let e = sync_and_select(&d, &Honest::new(9, 4), &Foreign).unwrap_err();
        assert!(matches!(e, SyncRefusal::NoVerifiedAnchor { .. }), "{e}");
        assert_eq!(std::fs::read(d.join(LEAVES_FILE)).unwrap(), before);
    }

    /// An anchor source that cannot be reached is an endpoint refusal, named as
    /// such — not silently "no anchors".
    #[test]
    fn an_unreachable_anchor_endpoint_is_an_endpoint_refusal_not_an_empty_set() {
        let d = tmp("anchordown");
        struct Down;
        impl AnchorSource for Down {
            fn anchors(&self) -> Result<Anchors, String> {
                Err("connection refused".into())
            }
        }
        let e = sync_and_select(&d, &Honest::new(3, 100), &Down).unwrap_err();
        assert!(matches!(e, SyncRefusal::Endpoint { .. }), "{e}");
        assert!(e.to_string().contains("connection refused"), "{e}");
    }

}
