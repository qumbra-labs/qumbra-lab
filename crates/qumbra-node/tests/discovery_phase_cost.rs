//! **Issue #673 — WHICH of the discovery phase's three refreshes costs the 13 s.**
//!
//! The fleet reading is a sum. `run.rs`'s discovery block runs
//! `refresh_discovery` → `refresh_leaves` → `refresh_anchors` behind one gate
//! and reports `phases.discovery` as their total, so "discovery blocks the loop
//! for 13.1 s and grows at ~4.5 ms/block" is a statement about three functions
//! at once. `crate::looptime::DiscoveryTimings` splits the live instrument;
//! this file is the split's deterministic half — the one that settles the
//! question in CI instead of waiting for a host to report back.
//!
//! ## Why allocation and not wall clock
//!
//! A timing assertion on a shared runner is a flake generator, and a timing
//! assertion is also not the claim. The claim is **cost shape**: which of the
//! three does an amount of work proportional to the chain, and which does not.
//! Bytes allocated is deterministic for a given code path and given chain, it
//! is exactly what a "copy the world" defect looks like, and a refresh that
//! stops copying the world cannot keep allocating like one.
//!
//! The counter is thread-local and const-initialised, so the allocator itself
//! allocates nothing and cannot recurse; the arming window is the measured call
//! and nothing else, on the measuring thread and nothing else.
//!
//! ## What "chain-proportional" is measured against
//!
//! Two chains, `SHORT` and `LONG = 2 × SHORT`, **both taller than
//! `MAX_ANCHOR_AGE_BLOCKS`**. That bound is what makes the test discriminating:
//! the anchor *answer* is capped at the age window, so above it a projection
//! whose cost tracks its answer is flat while one that walks the whole chain to
//! produce it doubles.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::{GENESIS_DIFFICULTY, MAX_ANCHOR_AGE_BLOCKS};
use qlab_node::{anchor_set, genesis_block, ChainStore, MemNode, NodeState};
use qumbra_node::discovery_server::{DiscoveryView, LeavesView};

// ── the instrument ──────────────────────────────────────────────────────────

thread_local! {
    /// Armed only inside [`measure`], and only on the thread that armed it.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// `Cell<u64>` / `Cell<bool>` are not `Drop` and are const-initialised, so these
// thread-locals are plain `#[thread_local]` statics: reading one allocates
// nothing, needs no lazy initialisation, and has no destructor phase in which
// `with` could panic. That is what makes counting inside the allocator sound.
#[inline]
fn note(size: usize) {
    if ARMED.with(Cell::get) {
        BYTES.with(|b| b.set(b.get() + size as u64));
        ALLOCS.with(|c| c.set(c.get() + 1));
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        note(new.saturating_sub(l.size()));
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Bytes and allocation count charged to one call.
#[derive(Clone, Copy, Debug)]
struct Cost {
    bytes: u64,
    allocs: u64,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    BYTES.with(|b| b.set(0));
    ALLOCS.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    let out = f();
    ARMED.with(|a| a.set(false));
    (out, Cost { bytes: BYTES.with(Cell::get), allocs: ALLOCS.with(Cell::get) })
}

/// How much a quantity grew between the two chains, as a ratio. `LONG` is twice
/// `SHORT`, so ~1.0 is flat and ~2.0 is chain-proportional.
fn growth(short: u64, long: u64) -> f64 {
    // The floor keeps a genuinely-zero measurement from dividing by zero; it
    // biases the ratio DOWN, i.e. towards "flat", which is the direction that
    // makes a false pass harder rather than easier.
    long as f64 / short.max(1) as f64
}

// ── the chains ──────────────────────────────────────────────────────────────

struct OkVerifier;
impl qlab_devnet::body::TxVerifier for OkVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

/// A coinbase-only chain `height` blocks tall, with its finalized head one
/// block below the tip.
///
/// Coinbase-only is the shape the T2 fleet actually runs (the #673 readings
/// come off a chain whose blocks are overwhelmingly coinbase), and above
/// `COINBASE_MATURITY_BLOCKS` every block appends the leaf it matures — so the
/// tree grows once per block and each height has its own root, which is what
/// makes the anchor projection non-degenerate.
fn chain(height: u64) -> MemNode {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut node = MemNode::in_memory(genesis);
    let mut last = node.tip_hash();
    let mut prev_last = last;
    for h in 1..=height {
        let parent = node.chain().block(&last).expect("tip stored").header();
        let body = BlockBody::from_single_payee(vec![], h, [h, 2, 3, 4]);
        let header = BlockHeader::child_of(&parent, h, GENESIS_DIFFICULTY, body.commitment());
        let hash = header.header_hash();
        node.apply_block(header, body, &OkVerifier).expect("block applies");
        prev_last = last;
        last = hash;
    }
    // Finality one block behind the tip: the real case, and the one where the
    // anchor set is not simply "every root".
    assert!(node.finalize(prev_last).expect("finalize").is_recorded());
    node
}

/// Comfortably above the age window, so the anchor ANSWER is capped and only a
/// chain-proportional derivation still grows. Kept as small as that allows —
/// these chains are built twice per test binary.
const SHORT: u64 = MAX_ANCHOR_AGE_BLOCKS + 200;
const LONG: u64 = SHORT * 2;

// ── the measurement ─────────────────────────────────────────────────────────

/// 🔴 **The #673 answer, and it is not either of the two candidates the issue
/// named.**
///
/// The issue's reading of the source put `refresh_leaves`'s
/// `commitments_ordered().to_vec()` first and `refresh_discovery`'s
/// clone-before-checking second. Measured, `refresh_anchors` is the one whose
/// cost tracks the chain — and it tracks it *above the age window*, where the
/// answer it produces has stopped growing.
///
/// The three numbers are printed as well as asserted: a ratio that moves is
/// news either way, and the next reader should not have to re-instrument to see
/// what it moved to.
#[test]
fn the_anchor_refresh_is_the_one_whose_cost_tracks_the_chain() {
    let short = chain(SHORT);
    let long = chain(LONG);

    // `refresh_leaves`: `commitments_ordered().to_vec()`.
    let (_, l_short) = measure(|| LeavesView { leaves: short.commitments_ordered().to_vec() });
    let (_, l_long) = measure(|| LeavesView { leaves: long.commitments_ordered().to_vec() });

    // `refresh_discovery`: the clone of the whole view, then the incremental
    // walk. Measured on a COLD view — the once-per-restart worst case — so the
    // comparison is against each refresh's own largest honest cost.
    let (_, d_short) = measure(|| {
        let mut v = DiscoveryView::default();
        v.refresh(short.chain());
        v
    });
    let (_, d_long) = measure(|| {
        let mut v = DiscoveryView::default();
        v.refresh(long.chain());
        v
    });

    // `refresh_anchors`: `anchor_set(state).to_bytes()`.
    let (a_short_set, a_short) = measure(|| anchor_set(&short).to_bytes());
    let (a_long_set, a_long) = measure(|| anchor_set(&long).to_bytes());

    println!(
        "#673 refresh cost, SHORT={SHORT} LONG={LONG} (MAX_ANCHOR_AGE_BLOCKS={MAX_ANCHOR_AGE_BLOCKS})\n\
         \x20 leaves   {:>12} -> {:>12} B  ({:>9} -> {:>9} allocs)  growth {:.2}\n\
         \x20 view     {:>12} -> {:>12} B  ({:>9} -> {:>9} allocs)  growth {:.2}\n\
         \x20 anchors  {:>12} -> {:>12} B  ({:>9} -> {:>9} allocs)  growth {:.2}",
        l_short.bytes, l_long.bytes, l_short.allocs, l_long.allocs,
        growth(l_short.bytes, l_long.bytes),
        d_short.bytes, d_long.bytes, d_short.allocs, d_long.allocs,
        growth(d_short.bytes, d_long.bytes),
        a_short.bytes, a_long.bytes, a_short.allocs, a_long.allocs,
        growth(a_short.bytes, a_long.bytes),
    );

    // The premise the whole comparison rests on: above the age window the
    // anchor ANSWER has stopped growing. If this ever fails, the ratios below
    // stop meaning what they are asserted to mean.
    assert_eq!(
        a_short_set.len(),
        a_long_set.len(),
        "the served anchor bytes are capped by MAX_ANCHOR_AGE_BLOCKS, so doubling \
         the chain must not change the answer's size"
    );

    // 🔴 The finding: the answer is flat and the work is not.
    assert!(
        growth(a_short.allocs, a_long.allocs) > 1.8,
        "refresh_anchors allocates proportionally to the chain even though its \
         answer is capped: {} -> {} allocations across a 2x chain",
        a_short.allocs,
        a_long.allocs
    );

    // And it dominates the two the issue suspected — by so much that no
    // plausible measurement error reorders them.
    assert!(
        a_short.bytes > 10 * (l_short.bytes + d_short.bytes),
        "refresh_anchors is the phase's cost: anchors {} B vs leaves {} B + view {} B",
        a_short.bytes,
        l_short.bytes,
        d_short.bytes
    );
}

/// `refresh_leaves` is the candidate the issue named first, and it is a single
/// contiguous copy: one allocation, 32 B per commitment. It grows with the
/// chain — but it is one memcpy, and this pins the shape so the PR's arithmetic
/// about it can be checked rather than believed.
#[test]
fn the_leaf_copy_is_one_allocation_of_32_bytes_per_commitment() {
    let node = chain(SHORT);
    let n = node.commitments_ordered().len() as u64;
    assert!(n > 0, "the chain must be past coinbase maturity for this to mean anything");
    let (view, cost) = measure(|| LeavesView { leaves: node.commitments_ordered().to_vec() });
    assert_eq!(view.leaves.len() as u64, n);
    assert_eq!(cost.allocs, 1, "one Vec, one allocation — a memcpy, not a walk");
    assert_eq!(cost.bytes, n * 32, "32 B per commitment and nothing else");
}
