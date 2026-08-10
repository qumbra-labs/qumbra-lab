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
use std::sync::Mutex;
use std::time::Instant;

/// Emit a progress line after this many records since the last emission.
pub const REPLAY_PROGRESS_EVERY_RECORDS: usize = 100;

/// Emit a progress line after this many seconds since the last emission.
pub const REPLAY_PROGRESS_EVERY_SECS: u64 = 15;

/// Optional capture sink for tests. When set, every emitted line is also pushed
/// here (and still printed to stdout, matching the operator path).
static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

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
    println!("{line}");
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

#[cfg(test)]
mod tests {
    use super::*;

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
