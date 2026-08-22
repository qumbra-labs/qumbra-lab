//! Latest-value per-session outbox.
//!
//! The poll thread deposits a fresh [`Job`] (or a named work-state change) under a
//! session id; the connection thread drains it. A queue of superseded
//! tips would only make XMRig hash work the pool has already marked
//! stale, so a later push overwrites an unread one.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use qlab_stratum::types::Job;

#[derive(Debug, Clone)]
pub enum SessionPush {
    Job(Job),
    /// Named reason the pool has no current work. The connection writes
    /// it on the wire but remains registered for the recovery job.
    Suspended(String),
    /// Named reason the pool has no current work. The connection writes
    /// it on the wire and then disconnects so the miner can fail over.
    Unavailable(String),
}

#[derive(Debug, Default)]
pub struct JobOutbox {
    inner: Mutex<Inner>,
    jobs_pushed: AtomicU64,
}

#[derive(Debug, Default)]
struct Inner {
    live: HashSet<String>,
    pending: HashMap<String, SessionPush>,
}

impl JobOutbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, sid: String) {
        self.inner.lock().expect("outbox mutex").live.insert(sid);
    }

    pub fn unregister(&self, sid: &str) {
        let mut g = self.inner.lock().expect("outbox mutex");
        g.live.remove(sid);
        g.pending.remove(sid);
    }

    pub fn push_job(&self, sid: String, job: Job) {
        let mut g = self.inner.lock().expect("outbox mutex");
        g.pending.insert(sid, SessionPush::Job(job));
        self.jobs_pushed.fetch_add(1, Ordering::SeqCst);
    }

    /// Deposit every `(session, job)` pair. Returns how many were stored.
    /// Overwrites an unread previous job for the same session.
    pub fn push_all(&self, jobs: Vec<(String, Job)>) -> u64 {
        let n = jobs.len() as u64;
        if n == 0 {
            return 0;
        }
        let mut g = self.inner.lock().expect("outbox mutex");
        for (sid, job) in jobs {
            g.pending.insert(sid, SessionPush::Job(job));
        }
        self.jobs_pushed.fetch_add(n, Ordering::SeqCst);
        n
    }

    /// Tell every live session there is temporarily no current work.
    pub fn suspend_all(&self, reason: String) {
        let mut g = self.inner.lock().expect("outbox mutex");
        let live: Vec<String> = g.live.iter().cloned().collect();
        for sid in live {
            g.pending
                .insert(sid, SessionPush::Suspended(reason.clone()));
        }
    }

    /// Tell every live session there is no current work and it must fail over.
    pub fn unavailable_all(&self, reason: String) {
        let mut g = self.inner.lock().expect("outbox mutex");
        let live: Vec<String> = g.live.iter().cloned().collect();
        for sid in live {
            g.pending
                .insert(sid, SessionPush::Unavailable(reason.clone()));
        }
    }

    pub fn take(&self, sid: &str) -> Option<SessionPush> {
        self.inner.lock().expect("outbox mutex").pending.remove(sid)
    }

    pub fn jobs_pushed(&self) -> u64 {
        self.jobs_pushed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str, height: u64) -> Job {
        Job {
            blob: "00".into(),
            job_id: id.into(),
            target: "ffffffffffffffff".into(),
            algo: Some("rx/0".into()),
            height: Some(height),
            seed_hash: None,
            next_seed_hash: None,
            id: None,
        }
    }

    #[test]
    fn latest_value_wins_and_work_state_changes_cover_live_sessions() {
        let box_ = JobOutbox::new();
        box_.register("s1".into());
        box_.push_job("s1".into(), job("j1", 1));
        box_.push_job("s1".into(), job("j2", 2));
        match box_.take("s1") {
            Some(SessionPush::Job(j)) => {
                assert_eq!(j.job_id, "j2");
                assert_eq!(j.height, Some(2));
            }
            other => panic!("{other:?}"),
        }
        assert!(box_.take("s1").is_none());
        assert_eq!(box_.jobs_pushed(), 2);

        box_.suspend_all("template-unavailable: test".into());
        match box_.take("s1") {
            Some(SessionPush::Suspended(r)) => {
                assert!(r.starts_with("template-unavailable:"));
            }
            other => panic!("{other:?}"),
        }
        box_.unavailable_all("template-unavailable: sustained".into());
        match box_.take("s1") {
            Some(SessionPush::Unavailable(r)) => {
                assert!(r.starts_with("template-unavailable:"));
            }
            other => panic!("{other:?}"),
        }
        box_.unregister("s1");
        box_.unavailable_all("template-unavailable: gone".into());
        assert!(box_.take("s1").is_none());
    }
}
