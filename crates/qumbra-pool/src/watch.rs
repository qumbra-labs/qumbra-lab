//! Template-poll health. Suspension and failover are separate decisions.
//!
//! The failure count and the wall-clock age are both in config. When the
//! age is left unset it is derived as `failures × poll_ms` so the two
//! suspension bounds cannot silently disagree (`derived-not-duplicated.md`
//! §4). A separate minutes-scale wall-clock bound ends a sustained outage.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TemplateWatch {
    max_failures: u64,
    max_age: Duration,
    disconnect_after: Duration,
    consecutive: AtomicU64,
    total_failures: AtomicU64,
    last_good: Mutex<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAction {
    /// Stop issuing jobs but keep the session registered for recovery.
    Suspend(String),
    /// The outage crossed its minutes-scale bound; end the session for failover.
    Disconnect(String),
}

impl WatchAction {
    pub fn reason(&self) -> &str {
        match self {
            Self::Suspend(reason) | Self::Disconnect(reason) => reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchSnapshot {
    pub template_poll_failures: u64,
    pub consecutive_failures: u64,
    pub seconds_since_last_good_template: u64,
}

impl TemplateWatch {
    pub fn new(max_failures: u64, max_age: Duration, disconnect_after: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            max_age,
            disconnect_after,
            consecutive: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            last_good: Mutex::new(Instant::now()),
        }
    }

    pub fn record_ok(&self) {
        self.consecutive.store(0, Ordering::SeqCst);
        *self.last_good.lock().expect("watch mutex") = Instant::now();
    }

    /// Count a failed poll. The count/age suspension clauses never disconnect;
    /// only the separate sustained-outage bound does that.
    pub fn record_err(&self) -> Option<WatchAction> {
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

    fn reason_if_stalled(&self, consecutive: u64) -> Option<WatchAction> {
        let age = self.last_good.lock().expect("watch mutex").elapsed();
        if consecutive < self.max_failures && age < self.max_age {
            return None;
        }
        let reason = format!(
            "template-unavailable: {consecutive} consecutive poll failures (max {}) / {}ms since last good template (max {}ms)",
            self.max_failures,
            age.as_millis(),
            self.max_age.as_millis()
        );
        if age >= self.disconnect_after {
            Some(WatchAction::Disconnect(reason))
        } else {
            Some(WatchAction::Suspend(reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stall_after_n_failures_and_recovers_on_ok() {
        let watch = TemplateWatch::new(3, Duration::from_secs(60), Duration::from_secs(300));
        assert!(watch.record_err().is_none());
        assert!(watch.record_err().is_none());
        let WatchAction::Suspend(reason) = watch.record_err().expect("third failure stalls") else {
            panic!("failure-count threshold must suspend before the outage bound");
        };
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
        let watch = TemplateWatch::new(100, Duration::from_millis(20), Duration::from_secs(1));
        watch.record_ok();
        std::thread::sleep(Duration::from_millis(30));
        let WatchAction::Suspend(reason) = watch.record_err().expect("age bound stalls") else {
            panic!("age threshold must suspend before the outage bound");
        };
        assert!(reason.starts_with("template-unavailable:"));
        assert!(reason.contains("since last good template"));
    }

    #[test]
    fn sustained_outage_eventually_demands_disconnect() {
        let watch = TemplateWatch::new(1, Duration::from_millis(1), Duration::from_millis(100));
        assert!(matches!(watch.record_err(), Some(WatchAction::Suspend(_))));
        std::thread::sleep(Duration::from_millis(150));
        let WatchAction::Disconnect(reason) = watch.record_err().expect("bounded outage") else {
            panic!("sustained outage must disconnect for miner failover");
        };
        assert!(reason.contains("2 consecutive poll failures"), "got: {reason}");
        assert!(reason.contains("ms since last good template"), "got: {reason}");
    }
}
