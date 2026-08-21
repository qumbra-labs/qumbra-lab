//! Template-poll health. Two bounds, one cadence.
//!
//! The failure count and the wall-clock age are both in config. When the
//! age is left unset it is derived as `failures × poll_ms` so the two
//! bounds cannot silently disagree (`derived-not-duplicated.md` §4).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TemplateWatch {
    max_failures: u64,
    max_age: Duration,
    consecutive: AtomicU64,
    total_failures: AtomicU64,
    last_good: Mutex<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchSnapshot {
    pub template_poll_failures: u64,
    pub consecutive_failures: u64,
    pub seconds_since_last_good_template: u64,
}

impl TemplateWatch {
    pub fn new(max_failures: u64, max_age: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            max_age,
            consecutive: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            last_good: Mutex::new(Instant::now()),
        }
    }

    pub fn record_ok(&self) {
        self.consecutive.store(0, Ordering::SeqCst);
        *self.last_good.lock().expect("watch mutex") = Instant::now();
    }

    /// Count a failed poll. Returns a named stall reason when either bound
    /// is crossed (and on every subsequent failure until [`Self::record_ok`]).
    pub fn record_err(&self) -> Option<String> {
        let consecutive = self.consecutive.fetch_add(1, Ordering::SeqCst) + 1;
        self.total_failures.fetch_add(1, Ordering::SeqCst);
        self.reason_if_stalled(consecutive)
    }

    pub fn snapshot(&self) -> WatchSnapshot {
        WatchSnapshot {
            template_poll_failures: self.total_failures.load(Ordering::SeqCst),
            consecutive_failures: self.consecutive.load(Ordering::SeqCst),
            seconds_since_last_good_template: self
                .last_good
                .lock()
                .expect("watch mutex")
                .elapsed()
                .as_secs(),
        }
    }

    fn reason_if_stalled(&self, consecutive: u64) -> Option<String> {
        let age = self.last_good.lock().expect("watch mutex").elapsed();
        if consecutive < self.max_failures && age < self.max_age {
            return None;
        }
        Some(format!(
            "template-unavailable: {consecutive} consecutive poll failures (max {}) / {}ms since last good template (max {}ms)",
            self.max_failures,
            age.as_millis(),
            self.max_age.as_millis()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stall_after_n_failures_and_recovers_on_ok() {
        let watch = TemplateWatch::new(3, Duration::from_secs(60));
        assert!(watch.record_err().is_none());
        assert!(watch.record_err().is_none());
        let reason = watch.record_err().expect("third failure stalls");
        assert!(reason.starts_with("template-unavailable:"));
        assert!(reason.contains("3 consecutive"));
        assert_eq!(watch.snapshot().template_poll_failures, 3);
        assert_eq!(watch.snapshot().consecutive_failures, 3);

        watch.record_ok();
        assert_eq!(watch.snapshot().consecutive_failures, 0);
        assert!(watch.record_err().is_none());
    }

    #[test]
    fn stall_on_age_even_with_a_high_failure_cap() {
        let watch = TemplateWatch::new(100, Duration::from_millis(20));
        watch.record_ok();
        std::thread::sleep(Duration::from_millis(30));
        let reason = watch.record_err().expect("age bound stalls");
        assert!(reason.starts_with("template-unavailable:"));
        assert!(reason.contains("since last good template"));
    }
}
