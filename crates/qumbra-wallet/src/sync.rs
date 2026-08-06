//! Local commitment-tree sync over the leaf stream — the wallet half of the
//! stamped A1+B1 decision (issue #276, `t1-wallet-send-seams-decision.md`).
//!
//! The wallet maintains its own [`CommitmentTree`] from `GET
//! /v1/tree/leaves?from=N` and computes `auth_path` locally, so the server
//! learns which IP syncs leaves and **nothing positional** — never which leaf a
//! spend is about (the brief's B2 rejection). The stream is self-verifying end
//! to end: after every sync the reconstructed root at the served count must
//! equal the anchor the endpoint's node serves, and a mismatch is a **named
//! refusal**, not a retry — a lying stream is censorship, not forgery (§3-B1
//! posture: the server can withhold, it cannot make this wallet spend against a
//! fake tree undetected, because the same wrong root would then fail the anchor
//! check at submission).
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
//! What fetches the chunks is a [`LeafSource`] — the HTTP client over the
//! server half's (#275) framing plugs in behind it, and the sync logic itself
//! is testable against an in-memory source.

use std::io;
use std::path::{Path, PathBuf};

use qlab_cbserver::tree::CommitmentTree;
use qlab_note::hash::digest_bytes;

/// The leaf-cache file inside the wallet dir. Versioned, reject-unknown — the
/// same persistence discipline as `wallet.seed` / `addresses.v1`.
pub const LEAVES_FILE: &str = "tree-leaves.v1";

/// The cache format this binary reads and writes. One byte, first in the file.
pub const LEAVES_FILE_VERSION: u8 = 1;

/// One bounded response from the leaf stream: the leaves from the requested
/// index, plus the server's claim of its tree at response time — total leaf
/// count and the root at that count (the anchor the sync verifies against).
#[derive(Clone, Debug)]
pub struct LeafChunk {
    /// Leaf note commitments (on-wire 32-byte form), authoritative append
    /// order, starting exactly at the requested `from`.
    pub leaves: Vec<[u8; 32]>,
    /// The serving node's total leaf count when it answered.
    pub tree_size: u64,
    /// The serving node's root over its first `tree_size` leaves — the anchor
    /// claim the reconstruction is checked against.
    pub root: [u8; 32],
}

/// Where leaves come from. The real implementation is an HTTP client over
/// `GET /v1/tree/leaves?from=N` (#275's framing); tests inject their own.
pub trait LeafSource {
    /// Fetch one bounded chunk starting at leaf index `from`. An `Err` is a
    /// transport/decode failure, verbatim — the sync turns it into the named
    /// endpoint refusal.
    fn fetch_from(&self, from: u64) -> Result<LeafChunk, String>;
}

/// Every way a sync refuses, each with its reason named — no boolean blindness
/// on this path (the same house style as the submit endpoint's typed refusals).
#[derive(Debug)]
pub enum SyncRefusal {
    /// The endpoint could not be reached or its response could not be decoded.
    Endpoint { why: String },
    /// The endpoint serves fewer leaves than the local cache holds. An
    /// append-only tree never rewinds, so either the endpoint is behind (try
    /// again, or another node) or this cache was synced against a different
    /// net — and this code will not guess which.
    StreamBehindLocal { served: u64, local: u64 },
    /// The reconstructed root at the served count does not match the anchor
    /// the endpoint serves. A lying stream is censorship, not forgery — the
    /// refusal is the detection working, and nothing was persisted.
    RootMismatch { count: u64, computed: [u8; 32], served: [u8; 32] },
    /// The endpoint claims more leaves than it returned, repeatedly, without
    /// progress — refused rather than looped on forever.
    NoProgress { at: u64, claimed: u64 },
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
            SyncRefusal::StreamBehindLocal { served, local } => write!(
                f,
                "tree sync refused: the endpoint serves {served} leaves but the local cache \
                 already holds {local}. An append-only tree never rewinds — either this endpoint \
                 is behind (retry, or use another node) or the cache was synced against a \
                 different net; refusing to guess which"
            ),
            SyncRefusal::RootMismatch { count, computed, served } => write!(
                f,
                "tree sync refused: the reconstructed root at {count} leaves is {} but the \
                 endpoint's anchor is {} — the stream and the anchor disagree. A lying stream is \
                 censorship, not forgery: nothing was persisted, and no witness will be built \
                 against it",
                hex32(computed),
                hex32(served)
            ),
            SyncRefusal::NoProgress { at, claimed } => write!(
                f,
                "tree sync refused: the endpoint claims {claimed} leaves but returned none past \
                 {at} — refusing to poll it forever"
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

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A tree the sync verified: `tree.root_at(count)` equals the anchor the
/// endpoint served at `count` leaves. This `(tree, count)` pair is exactly what
/// `send::build_send` takes — the caller-owned correspondence its docs name.
pub struct SyncedTree {
    pub tree: CommitmentTree,
    /// The leaf count the root was verified at.
    pub count: u64,
    /// Leaves fetched by THIS sync (0 = the cache was already current).
    pub fetched: u64,
}

impl std::fmt::Debug for SyncedTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tree itself is leaf data; the two numbers say what a debugger needs.
        f.debug_struct("SyncedTree").field("count", &self.count).field("fetched", &self.fetched).finish()
    }
}

/// Sync the wallet dir's leaf cache against `source`: resume from the cached
/// count, append until caught up with the endpoint's claimed size, verify the
/// reconstructed root against the served anchor, and only then persist.
///
/// Refusals are named ([`SyncRefusal`]) and leave the cache exactly as it was —
/// a refused sync costs nothing and can be retried.
pub fn sync_tree(dir: &Path, source: &impl LeafSource) -> Result<SyncedTree, SyncRefusal> {
    let path = dir.join(LEAVES_FILE);
    let mut tree = load_cache(&path)?;
    let start = tree.len();

    // Catch up. The endpoint's tree can grow between chunks; the loop chases
    // the LAST claim it saw, and the root check below is against that claim.
    let mut claim = source.fetch_from(tree.len()).map_err(|why| SyncRefusal::Endpoint { why })?;
    loop {
        if claim.tree_size < tree.len() {
            return Err(SyncRefusal::StreamBehindLocal { served: claim.tree_size, local: tree.len() });
        }
        if tree.len() + claim.leaves.len() as u64 > claim.tree_size {
            // A chunk that overshoots its own tree_size claim is malformed.
            return Err(SyncRefusal::Endpoint {
                why: format!(
                    "chunk of {} leaves from {} overshoots the endpoint's own claimed size {}",
                    claim.leaves.len(),
                    tree.len(),
                    claim.tree_size
                ),
            });
        }
        for cm in &claim.leaves {
            tree.append_bytes(cm);
        }
        if claim.tree_size == tree.len() {
            break; // caught up with this claim
        }
        if claim.leaves.is_empty() {
            return Err(SyncRefusal::NoProgress { at: tree.len(), claimed: claim.tree_size });
        }
        claim = source.fetch_from(tree.len()).map_err(|why| SyncRefusal::Endpoint { why })?;
    }

    // The verification the whole design leans on: reconstructed root at the
    // served count == the anchor the endpoint's node serves. On mismatch,
    // refuse by name and persist nothing.
    let count = claim.tree_size;
    let computed = digest_bytes(&tree.root_at(count));
    if computed != claim.root {
        return Err(SyncRefusal::RootMismatch { count, computed, served: claim.root });
    }

    persist_cache(&path, &tree)?;
    Ok(SyncedTree { tree, count, fetched: count - start })
}

/// Load the leaf cache, or an empty tree when none exists yet (first sync).
fn load_cache(path: &Path) -> Result<CommitmentTree, SyncRefusal> {
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
fn persist_cache(path: &Path, tree: &CommitmentTree) -> Result<(), SyncRefusal> {
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

    /// An honest in-memory endpoint over `n` leaves, serving bounded chunks and
    /// recording every `from` it was asked for.
    struct Honest {
        leaves: Vec<[u8; 32]>,
        chunk: usize,
        asked: RefCell<Vec<u64>>,
    }

    impl Honest {
        fn new(n: u64, chunk: usize) -> Honest {
            Honest {
                leaves: (0..n).map(cm).collect(),
                chunk,
                asked: RefCell::new(Vec::new()),
            }
        }

        fn root(&self) -> [u8; 32] {
            let mut t = CommitmentTree::new();
            for l in &self.leaves {
                t.append_bytes(l);
            }
            digest_bytes(&t.root())
        }
    }

    impl LeafSource for Honest {
        fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
            self.asked.borrow_mut().push(from);
            // Past the end: an honest empty answer with an honest claim — the
            // client's stream-behind refusal is the client's to make.
            let from = (from as usize).min(self.leaves.len());
            let to = (from + self.chunk).min(self.leaves.len());
            Ok(LeafChunk {
                leaves: self.leaves[from..to].to_vec(),
                tree_size: self.leaves.len() as u64,
                root: self.root(),
            })
        }
    }

    #[test]
    fn a_fresh_sync_downloads_chunks_verifies_and_persists() {
        let d = tmp("fresh");
        let src = Honest::new(10, 3); // 4 chunks: 3+3+3+1
        let s = sync_tree(&d, &src).unwrap();
        assert_eq!(s.count, 10);
        assert_eq!(s.fetched, 10);
        assert_eq!(s.tree.len(), 10);
        assert_eq!(digest_bytes(&s.tree.root_at(10)), src.root());
        assert_eq!(*src.asked.borrow(), vec![0, 3, 6, 9], "bounded chunks, client loops");
        // The cache file is version byte + 10 × 32 B.
        assert_eq!(std::fs::read(d.join(LEAVES_FILE)).unwrap().len(), 1 + 10 * 32);
    }

    #[test]
    fn a_second_sync_resumes_from_the_high_water_mark_never_redownloading() {
        let d = tmp("resume");
        let src = Honest::new(6, 100);
        sync_tree(&d, &src).unwrap();

        // The chain grew by 3; the wallet asks from 6 — never from 0.
        let grown = Honest::new(9, 100);
        let s = sync_tree(&d, &grown).unwrap();
        assert_eq!(s.count, 9);
        assert_eq!(s.fetched, 3, "only the new leaves travel");
        assert_eq!(*grown.asked.borrow(), vec![6], "resume point is the cached count");

        // Nothing new: fetched = 0, still verified.
        let same = Honest::new(9, 100);
        let s2 = sync_tree(&d, &same).unwrap();
        assert_eq!(s2.fetched, 0);
        assert_eq!(s2.count, 9);
    }

    #[test]
    fn a_lying_root_is_a_named_refusal_and_nothing_is_persisted() {
        let d = tmp("lying");
        // First, an honest sync at 4 leaves.
        sync_tree(&d, &Honest::new(4, 100)).unwrap();
        let cache_before = std::fs::read(d.join(LEAVES_FILE)).unwrap();

        // A liar serving 6 leaves whose anchor claim is garbage.
        struct Liar;
        impl LeafSource for Liar {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                Ok(LeafChunk {
                    leaves: (from..6).map(cm).collect(),
                    tree_size: 6,
                    root: [0xAB; 32],
                })
            }
        }
        let e = match sync_tree(&d, &Liar) {
            Err(e) => e,
            Ok(_) => panic!("a root/anchor mismatch must refuse"),
        };
        assert!(matches!(e, SyncRefusal::RootMismatch { count: 6, .. }), "{e}");
        let msg = e.to_string();
        assert!(msg.contains("censorship, not forgery"), "{msg}");
        assert!(msg.contains("nothing was persisted"), "{msg}");
        assert_eq!(
            std::fs::read(d.join(LEAVES_FILE)).unwrap(),
            cache_before,
            "a refused sync leaves the cache exactly as it was"
        );
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
                Ok(LeafChunk { leaves: (from..2).map(cm).collect(), tree_size: 5, root: [0; 32] })
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
                Ok(LeafChunk { leaves: (from..4).map(cm).collect(), tree_size: 3, root: [0; 32] })
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

    /// The synced tree is the witness source `build_send` consumes: an auth
    /// path over the verified (tree, count) pair folds to the verified root.
    #[test]
    fn the_synced_tree_witnesses_against_the_verified_root() {
        let d = tmp("witness");
        let src = Honest::new(7, 2);
        let s = sync_tree(&d, &src).unwrap();
        let w = s.tree.auth_path(3, s.count);
        assert_eq!(
            digest_bytes(&w.fold_root(&s.tree.leaf(3))),
            src.root(),
            "auth path folds to the anchor-verified root"
        );
    }

    /// The endpoint's tree grows while the wallet is mid-sync: the loop chases
    /// the newest claim and verifies against the LAST one.
    #[test]
    fn a_growing_endpoint_is_chased_to_its_latest_claim() {
        let d = tmp("growing");
        // Serves 4 leaves claiming 4, then on the next ask serves 2 more
        // claiming 6 — as if a block landed between chunks.
        struct Growing;
        impl LeafSource for Growing {
            fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
                let total: u64 = if from < 4 { 4 } else { 6 };
                let mut t = CommitmentTree::new();
                for i in 0..total {
                    t.append_bytes(&cm(i));
                }
                Ok(LeafChunk {
                    leaves: (from..total).map(cm).collect(),
                    tree_size: total,
                    root: digest_bytes(&t.root()),
                })
            }
        }
        // First sync stops at the first claim it catches up with (4).
        let s = sync_tree(&d, &Growing).unwrap();
        assert_eq!(s.count, 4);
        // The next sync picks up the growth.
        let s2 = sync_tree(&d, &Growing).unwrap();
        assert_eq!(s2.count, 6);
        assert_eq!(s2.fetched, 2);
    }
}
