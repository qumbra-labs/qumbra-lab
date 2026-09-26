//! `zkpeak --phases` (lab #742, A5 lever 4a's measure step): a phase-level
//! memory account of ONE hiding prove, with no stack unwinding.
//!
//! heaptrack on the aarch64 lane box attributed every allocation to `0x0 in ??`
//! twice (plain release, then line tables + frame pointers). This module asks
//! a smaller question that needs no symbols: **how many heap bytes are live at
//! each phase boundary of the prover, and what is the peak inside each phase.**
//!
//! Two parts, both compiled only with the `phasemem` cargo feature (a bench
//! build; nothing in any production crate links it):
//!
//! - [`Counting`] — a `#[global_allocator]` wrapper around `System` keeping
//!   `LIVE` (bytes currently allocated) and `PEAK` (the maximum `LIVE` since
//!   the last [`mark`]). Relaxed atomics; allocations on rayon workers count.
//! - [`PhaseLayer`] — a `tracing` layer. Plonky3 0.6.1 already opens a span at
//!   every prover phase (`prove`, `commit to trace data` ⊃ `randomize polys`,
//!   `quotient_values`, `commit to quotient poly chunks`, `open` ⊃
//!   `FRI prover` ⊃ `commit phase` / `query phase`), so the boundaries come for
//!   free. At every span enter/exit on the measuring thread the layer calls
//!   [`mark`], which closes one window: the stretch between two boundaries.
//!   Windows with no span of their own (trace generation before `prove`, the
//!   stretch between `commit to trace data` and `quotient_values`, …) are
//!   reported as `· between` rows, so nothing the prover allocates is
//!   unaccounted for.
//!
//! The numbers are heap bytes as the Rust allocator sees them — not RSS (no
//! allocator overhead, no stacks, no binary). Timings taken with this build
//! are not publishable: every allocation pays two atomic operations.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The counting allocator. Install with `#[global_allocator]`.
pub struct Counting;

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

/// Bytes live right now.
pub fn live() -> usize {
    LIVE.load(Relaxed)
}

/// Close the current window: return its peak and start a new one at `live()`.
pub fn mark() -> usize {
    PEAK.swap(LIVE.load(Relaxed), Relaxed)
}

/// One report row: a span, or the unspanned stretch before a boundary.
struct Row {
    depth: usize,
    name: String,
    start: usize,
    peak: usize,
    end: usize,
}

struct Frame {
    row: usize,
    depth: usize,
    peak: usize,
    last: usize,
}

#[derive(Default)]
struct State {
    stack: Vec<Frame>,
    rows: Vec<Row>,
}

impl State {
    /// Record the window that just closed (`p` = its peak) as time spent
    /// directly in the innermost open span, with no child span running.
    fn close_window(&mut self, p: usize, now: usize, before: &str) {
        if let Some(f) = self.stack.last_mut() {
            f.peak = f.peak.max(p);
            let (depth, start) = (f.depth + 1, f.last);
            f.last = now;
            // Only a window that allocated something worth a row.
            if p > start.max(now) + (1 << 20) || start.abs_diff(now) > (1 << 20) {
                self.rows.push(Row { depth, name: format!("· between ({before})"), start, peak: p, end: now });
            }
        }
    }
}

/// The account behind the `tracing` layer ([`Shared`]) that turns span edges
/// into window boundaries. It only
/// follows spans entered on the thread that built it (the prover's own spans
/// run there; rayon workers' allocations still count in `LIVE`).
pub struct PhaseLayer {
    thread: std::thread::ThreadId,
    state: Mutex<State>,
}

impl PhaseLayer {
    pub fn new() -> Self {
        mark();
        PhaseLayer { thread: std::thread::current().id(), state: Mutex::new(State::default()) }
    }

    fn mine(&self) -> bool {
        std::thread::current().id() == self.thread
    }
}

impl PhaseLayer {
    fn enter(&self, name: String) {
        let p = mark();
        let now = live();
        let mut st = self.state.lock().unwrap();
        st.close_window(p, now, &format!("before `{name}`"));
        let depth = st.stack.len();
        let row = st.rows.len();
        st.rows.push(Row { depth, name, start: now, peak: now, end: now });
        st.stack.push(Frame { row, depth, peak: now, last: now });
    }

    fn exit(&self) {
        let p = mark();
        let now = live();
        let mut st = self.state.lock().unwrap();
        st.close_window(p, now, "to its end");
        let Some(f) = st.stack.pop() else { return };
        let r = &mut st.rows[f.row];
        r.peak = f.peak.max(p);
        r.end = now;
        if let Some(parent) = st.stack.last_mut() {
            parent.peak = parent.peak.max(f.peak).max(p);
            parent.last = now;
        }
    }
}

impl PhaseLayer {
    /// Print the account as a markdown table (GiB, three decimals).
    pub fn print(&self) {
        let st = self.state.lock().unwrap();
        let g = |b: usize| b as f64 / (1u64 << 30) as f64;
        println!("| phase | live at start GiB | peak inside GiB | peak − start GiB | live at end GiB |");
        println!("|---|---|---|---|---|");
        for r in &st.rows {
            let indent = "  ".repeat(r.depth);
            println!(
                "| {indent}{} | {:.3} | {:.3} | {:+.3} | {:.3} |",
                r.name,
                g(r.start),
                g(r.peak),
                g(r.peak) - g(r.start),
                g(r.end)
            );
        }
        if !st.stack.is_empty() {
            println!("\n⚠ {} span(s) still open when printed — their rows are incomplete.", st.stack.len());
        }
    }
}

/// A clonable handle so the caller can print after installing the layer.
#[derive(Clone)]
pub struct Shared(pub std::sync::Arc<PhaseLayer>);

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Shared {
    fn on_new_span(&self, _: &Attributes<'_>, _: &Id, _: Context<'_, S>) {}

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if self.0.mine() {
            self.0.enter(ctx.span(id).map_or("?", |s| s.metadata().name()).to_string());
        }
    }

    fn on_exit(&self, _id: &Id, _ctx: Context<'_, S>) {
        if self.0.mine() {
            self.0.exit();
        }
    }
}

/// Install the layer as the global subscriber and return a handle to print from.
pub fn install() -> Shared {
    use tracing_subscriber::layer::SubscriberExt;
    let shared = Shared(std::sync::Arc::new(PhaseLayer::new()));
    let sub = tracing_subscriber::registry().with(shared.clone());
    tracing::subscriber::set_global_default(sub).expect("no other global subscriber is installed");
    shared
}
