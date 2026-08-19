//! Progress lines during `blocks.log` recovery (lab #287).
//!
//! A live T0 host once sat silent for **15 m 31 s at 100 % CPU** while replaying
//! 1,987 records past a stale snapshot — observationally identical to a hang.
//! These lines go to the same place the final `RECOVERY … resumed at tip` line
//! goes (stdout), on a bounded cadence, so an operator can tell the two apart.
//!
//! # Cadence (stated in the PR / issue #287)
//!
//! A progress line is emitted when **either**:
//! - at least [`REPLAY_PROGRESS_EVERY_RECORDS`] records have been processed
//!   since the last line, **or**
//! - at least [`REPLAY_PROGRESS_EVERY_SECS`] seconds have elapsed since the
//!   last line (or the start line).
//!
//! On a 15-minute / ~2 records-per-second replay that is on the order of a few
//! dozen lines, not one and not one per record. The start line (total known up
//! front) is emitted even when the walk is short, so a multi-record replay is
//! never silent; a 0-record resume emits nothing here.
//!
//! # Total is derived, not guessed
//!
//! `Node::open` already loads every log record into memory before the walk
//! ([`crate::persist::read_records`]), so `records.len()` is free. The full
//! from-genesis path applies every record, so that length is also the final
//! `replayed_records`. The snapshot-assisted path walks the whole log too
//! (prefix blocks are no-ops; every finalization is offered to the live rule),
//! so the same length is the walk total. Progress reports walk position; the
//! final `RECOVERY` line still reports records that actually advanced state.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Emit a progress line after this many records since the last emission.
pub const REPLAY_PROGRESS_EVERY_RECORDS: usize = 100;

/// Emit a progress line after this many seconds since the last emission.
pub const REPLAY_PROGRESS_EVERY_SECS: u64 = 15;

/// Optional capture sink for tests. When set, every emitted line is also pushed
/// here (and still printed to stdout, matching the operator path).
static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// The live walk position, published for readers that must answer **while
/// `Node::open` is still running** (lab #365).
///
/// `LIVE_TOTAL == 0` means no replay is in flight — the same encoding
/// [`ReplayProgress::start`] already uses to mean "nothing to walk", so there is
/// no third state to keep consistent.
///
/// Why a process global rather than a handle threaded through `open`: the reader
/// is a *different thread* that exists before `open` is called and must answer
/// requests while it blocks. Passing a channel down would mean `Node::open` grows
/// an observability parameter every caller has to thread, for a value that is
/// already a single-writer counter. Writes are `Relaxed` — the reader wants a
/// recent number, not a synchronised one, and `tick` already pays for an
/// `Instant::elapsed` on every record.
static LIVE_PROCESSED: AtomicU64 = AtomicU64::new(0);
static LIVE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// How far a replay currently in flight has walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayPosition {
    pub processed: u64,
    pub total: u64,
}

impl ReplayPosition {
    /// Walk position as whole percent, floored. `0` when the total is unknown.
    pub fn percent(&self) -> u64 {
        self.processed.saturating_mul(100).checked_div(self.total).unwrap_or(0)
    }
}

/// The position of the replay in flight, or `None` when none is running.
///
/// **`None` does not mean "the node is up"** — it means no walk is in progress,
/// which is equally true before `open` starts and after it returns. The caller
/// owns that distinction; here it would be a guess.
pub fn live_replay_position() -> Option<ReplayPosition> {
    let total = LIVE_TOTAL.load(Ordering::Relaxed);
    if total == 0 {
        return None;
    }
    Some(ReplayPosition { processed: LIVE_PROCESSED.load(Ordering::Relaxed), total })
}

/// Test-only replay hold (lab #373): armed by [`hold_replay_at`], checked by
/// [`ReplayProgress::tick`]. The `AtomicBool` is the fast path — production
/// replays pay one relaxed load per record and never touch the mutex.
///
/// This exists because "answer `/v1/ready` while the replay is still running"
/// is a property a test can only assert deterministically if it can stop the
/// walk at a chosen record. A sleep race would assert it probabilistically,
/// which on this repo's record (`#309`'s truncation, `#106`'s restart fork) is
/// how a defect hides. Same posture as [`with_progress_capture`] and
/// `RunningNode::start_with_release`: a Rust API for tests, reachable from no
/// config, CLI or environment.
static HOLD_ARMED: AtomicBool = AtomicBool::new(false);
static REPLAY_HOLD: Mutex<Option<Arc<HoldInner>>> = Mutex::new(None);

struct HoldInner {
    /// The `processed` count at which the walking thread stops and waits.
    at: u64,
    state: Mutex<HoldState>,
    cv: Condvar,
}

struct HoldState {
    /// The walk arrived at `at` (set by the walking thread).
    reached: bool,
    /// The test let the walk continue (set by [`ReplayHold::release`] / `Drop`).
    released: bool,
}

/// A held replay: the walk blocks when it reaches the armed record until this
/// handle releases it. **Dropping releases** — a panicking test cannot leave
/// the replay thread parked forever.
pub struct ReplayHold {
    inner: Arc<HoldInner>,
}

/// Test-only: arm a hold that blocks the next replay walk when its `processed`
/// count reaches `at`, until the returned handle is released or dropped.
///
/// One hold at a time (arming replaces any previous one). If no walk ever
/// reaches `at` — the log is shorter, or the walk was already past it — the
/// hold is simply never reached and [`ReplayHold::wait_reached`] times out;
/// the walk itself is never blocked at any other record.
pub fn hold_replay_at(at: u64) -> ReplayHold {
    let inner = Arc::new(HoldInner {
        at,
        state: Mutex::new(HoldState { reached: false, released: false }),
        cv: Condvar::new(),
    });
    *REPLAY_HOLD.lock().expect("replay hold lock") = Some(Arc::clone(&inner));
    HOLD_ARMED.store(true, Ordering::Release);
    ReplayHold { inner }
}

impl ReplayHold {
    /// Block until the walk has actually arrived at the held record, or
    /// `timeout` passes. Returns whether it arrived — a test asserts `true`
    /// so a hold that never fires is a loud failure, not a vacuous pass.
    pub fn wait_reached(&self, timeout: Duration) -> bool {
        let guard = self.inner.state.lock().expect("replay hold state");
        let (state, _) = self
            .inner
            .cv
            .wait_timeout_while(guard, timeout, |s| !s.reached)
            .expect("replay hold state");
        state.reached
    }

    /// Let the held walk continue. Idempotent; also disarms the global so
    /// later replays in the same process run unimpeded.
    pub fn release(&self) {
        HOLD_ARMED.store(false, Ordering::Release);
        if let Ok(mut slot) = REPLAY_HOLD.lock() {
            *slot = None;
        }
        let mut state = self.inner.state.lock().expect("replay hold state");
        state.released = true;
        self.inner.cv.notify_all();
    }
}

impl Drop for ReplayHold {
    fn drop(&mut self) {
        self.release();
    }
}

/// The walking thread's side of the hold: called from [`ReplayProgress::tick`]
/// only when [`HOLD_ARMED`] reads true. Parks until released when `processed`
/// is the armed record; a non-matching count returns immediately.
fn maybe_hold(processed: u64) {
    let inner = match REPLAY_HOLD.lock() {
        Ok(slot) => slot.clone(),
        Err(_) => None,
    };
    let Some(inner) = inner else { return };
    if processed != inner.at {
        return;
    }
    let mut state = inner.state.lock().expect("replay hold state");
    state.reached = true;
    inner.cv.notify_all();
    while !state.released {
        state = inner.cv.wait(state).expect("replay hold state");
    }
}

/// Serialises [`with_progress_capture`] so parallel test threads cannot steal
/// each other's lines from the process-global sink.
static CAPTURE_GATE: Mutex<()> = Mutex::new(());

/// Run `f` while capturing every progress line emitted on this thread of
/// control. Holds a process-wide gate so parallel tests do not interleave.
pub fn with_progress_capture<F, R>(f: F) -> (R, Vec<String>)
where
    F: FnOnce() -> R,
{
    let _gate = CAPTURE_GATE.lock().expect("progress capture gate");
    {
        let mut guard = CAPTURE.lock().expect("progress capture lock");
        *guard = Some(Vec::new());
    }
    let result = f();
    let lines = {
        let mut guard = CAPTURE.lock().expect("progress capture lock");
        guard.take().unwrap_or_default()
    };
    (result, lines)
}

/// Begin capturing recovery-progress lines. Prefer [`with_progress_capture`]
/// in tests — it serialises against other capturers.
pub fn capture_progress() {
    let mut guard = CAPTURE.lock().expect("progress capture lock");
    *guard = Some(Vec::new());
}

/// Stop capturing and return the lines emitted since [`capture_progress`].
pub fn take_captured_progress() -> Vec<String> {
    let mut guard = CAPTURE.lock().expect("progress capture lock");
    guard.take().unwrap_or_default()
}

fn emit(line: String) {
    // Flush: docker logs / journald only show lines that have left the buffer,
    // and a silent multi-minute replay is exactly the failure mode this exists
    // to end. Swallow flush errors — a broken stdout must not abort recovery.
    qlab_devnet::jprintln!("{line}");
    let _ = io::stdout().flush();
    if let Ok(mut guard) = CAPTURE.lock() {
        if let Some(buf) = guard.as_mut() {
            buf.push(line);
        }
    }
}

/// Tracks walk progress through a known-length record list.
pub struct ReplayProgress {
    total: usize,
    processed: usize,
    last_emit_processed: usize,
    last_emit_at: Instant,
}

impl ReplayProgress {
    /// Start a progress session. When `total == 0`, emits nothing and every
    /// later [`tick`] is a no-op — a fresh snapshot / empty log must stay quiet.
    ///
    /// `context` is the free-form tail of the start line, e.g.
    /// `"past snapshot at height 1868"` or `"from genesis"`.
    pub fn start(total: usize, context: &str) -> Self {
        if total > 0 {
            emit(format!("RECOVERY replaying {total} records {context}"));
        }
        // Publish before the first record is walked, so a reader that arrives
        // during the slowest part of startup sees `0/total` rather than nothing.
        LIVE_PROCESSED.store(0, Ordering::Relaxed);
        LIVE_TOTAL.store(total as u64, Ordering::Relaxed);
        Self {
            total,
            processed: 0,
            last_emit_processed: 0,
            last_emit_at: Instant::now(),
        }
    }

    /// Note that one more log record has been visited. May emit a mid-walk line.
    pub fn tick(&mut self) {
        if self.total == 0 {
            return;
        }
        self.processed += 1;
        LIVE_PROCESSED.store(self.processed as u64, Ordering::Relaxed);
        // Lab #373's test hold — one relaxed-load no-op unless a test armed it.
        if HOLD_ARMED.load(Ordering::Acquire) {
            maybe_hold(self.processed as u64);
        }
        let by_count =
            self.processed.saturating_sub(self.last_emit_processed) >= REPLAY_PROGRESS_EVERY_RECORDS;
        let by_time = self.last_emit_at.elapsed().as_secs() >= REPLAY_PROGRESS_EVERY_SECS;
        // Always emit on the final record when we never fired mid-walk, so a
        // multi-record replay shorter than the count cadence still produces a
        // `n/n` line before the resume report. (The start line already fired;
        // this is the "at least one progress line with a percentage" signal.)
        let finishing = self.processed == self.total
            && self.processed > 0
            && self.last_emit_processed == 0
            && self.total < REPLAY_PROGRESS_EVERY_RECORDS;
        if by_count || by_time || finishing {
            self.emit_progress();
        }
    }

    fn emit_progress(&mut self) {
        let pct = if self.total == 0 {
            0
        } else {
            (self.processed.saturating_mul(100)) / self.total
        };
        emit(format!(
            "RECOVERY replaying: {}/{} records ({}%)",
            self.processed, self.total, pct
        ));
        self.last_emit_processed = self.processed;
        self.last_emit_at = Instant::now();
    }
}

/// Retire the live position when the walk ends — including when it ends by `?`
/// on a mid-replay error, which is exactly when a reader must not be left
/// looking at a frozen percentage forever.
impl Drop for ReplayProgress {
    fn drop(&mut self) {
        LIVE_TOTAL.store(0, Ordering::Relaxed);
        LIVE_PROCESSED.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lab #365: the live position is what a surface bound *before* `Node::open`
    /// renders, so it must be published from the first record and retired when the
    /// walk ends — including on the error path, where a frozen percentage would
    /// outlive the process it described.
    #[test]
    fn the_live_position_tracks_the_walk_and_is_retired_after_it() {
        let (_, _lines) = with_progress_capture(|| {
            assert_eq!(live_replay_position(), None, "nothing in flight before start");

            let mut p = ReplayProgress::start(4, "from genesis");
            assert_eq!(
                live_replay_position(),
                Some(ReplayPosition { processed: 0, total: 4 }),
                "published before the first record, not after it"
            );
            p.tick();
            p.tick();
            let at_half = live_replay_position().expect("in flight");
            assert_eq!(at_half, ReplayPosition { processed: 2, total: 4 });
            assert_eq!(at_half.percent(), 50);

            drop(p);
            assert_eq!(live_replay_position(), None, "retired when the walk ends");

            // A zero-record resume never claims to be in flight.
            let p0 = ReplayProgress::start(0, "from genesis");
            assert_eq!(live_replay_position(), None);
            drop(p0);
        });
    }

    /// Lab #373: the hold parks the walking thread at exactly the armed record,
    /// the live position reads that record while parked, and release lets the
    /// walk finish. A hold armed past the log's end never fires and never
    /// blocks the walk.
    #[test]
    fn the_hold_parks_the_walk_at_the_armed_record_and_release_resumes_it() {
        let (_, _lines) = with_progress_capture(|| {
            let hold = hold_replay_at(2);
            let walker = std::thread::spawn(|| {
                let mut p = ReplayProgress::start(4, "from genesis");
                for _ in 0..4 {
                    p.tick();
                }
            });
            assert!(hold.wait_reached(Duration::from_secs(10)), "the walk reached record 2");
            assert_eq!(
                live_replay_position(),
                Some(ReplayPosition { processed: 2, total: 4 }),
                "the held walk publishes exactly the held record"
            );
            hold.release();
            walker.join().expect("released walk finishes");
            assert_eq!(live_replay_position(), None, "retired after release + drop");

            // A hold the walk never reaches blocks nothing.
            let idle = hold_replay_at(99);
            let mut p = ReplayProgress::start(3, "from genesis");
            for _ in 0..3 {
                p.tick();
            }
            assert!(!idle.wait_reached(Duration::from_millis(50)), "never reached, never parked");
        });
    }

    #[test]
    fn zero_total_emits_nothing() {
        let (_, lines) = with_progress_capture(|| {
            let mut p = ReplayProgress::start(0, "from genesis");
            p.tick();
            p.tick();
        });
        assert!(lines.is_empty(), "0-record resume must stay silent: {lines:?}");
    }

    #[test]
    fn multi_record_emits_start_and_finishing_percentage() {
        let (_, lines) = with_progress_capture(|| {
            let mut p = ReplayProgress::start(3, "from genesis");
            p.tick();
            p.tick();
            p.tick();
        });
        assert_eq!(
            lines.first().map(String::as_str),
            Some("RECOVERY replaying 3 records from genesis")
        );
        assert!(
            lines.iter().any(|l| l == "RECOVERY replaying: 3/3 records (100%)"),
            "short multi-record walk must still print a percentage line: {lines:?}"
        );
    }

    #[test]
    fn count_cadence_fires_every_k_records() {
        let n = REPLAY_PROGRESS_EVERY_RECORDS + 1;
        let (_, lines) = with_progress_capture(|| {
            let mut p = ReplayProgress::start(n, "from genesis");
            for _ in 0..n {
                p.tick();
            }
        });
        let mid = format!(
            "RECOVERY replaying: {}/{} records ({}%)",
            REPLAY_PROGRESS_EVERY_RECORDS,
            n,
            (REPLAY_PROGRESS_EVERY_RECORDS * 100) / n
        );
        assert!(
            lines.iter().any(|l| l == &mid),
            "expected mid-cadence line `{mid}` in {lines:?}"
        );
    }
}
