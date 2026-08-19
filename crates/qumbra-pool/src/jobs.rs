//! Job lifecycle: extra-nonce allocator, job ids, stale-on-tip-change.

use std::collections::HashMap;

use qlab_devnet::forms::GenesisForm;

/// Per-connection extra-nonce. Starts at 1 so 0 stays the solo-shaped
/// empty partition. Wraps; 0 is skipped on wrap.
#[derive(Debug)]
pub struct ExtraNonceAllocator {
    next: u32,
}

impl Default for ExtraNonceAllocator {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl ExtraNonceAllocator {
    pub fn next(&mut self) -> [u8; 4] {
        let n = self.next;
        self.next = self.next.wrapping_add(1);
        if self.next == 0 {
            self.next = 1;
        }
        n.to_le_bytes()
    }
}

/// A job the pool has handed a miner. `blob` already has this
/// connection's extra-nonce written and the miner window zeroed.
#[derive(Clone, Debug)]
pub struct IssuedJob {
    pub job_id: String,
    pub session_id: String,
    pub extra: [u8; 4],
    pub blob: Vec<u8>,
    pub target: u64,
    pub difficulty: u64,
    pub height: u64,
    pub seed_hash: [u8; 32],
    pub next_seed_hash: Option<[u8; 32]>,
    pub form: GenesisForm,
    pub consensus_difficulty: u64,
    pub stale: bool,
    /// Body from the live node template, if any. A block-class share
    /// POSTs this with the completed header.
    pub body: Option<crate::template::TemplateBody>,
}

#[derive(Debug, Default)]
pub struct JobStore {
    by_id: HashMap<String, IssuedJob>,
}

impl JobStore {
    pub fn insert(&mut self, job: IssuedJob) {
        self.by_id.insert(job.job_id.clone(), job);
    }

    pub fn get(&self, id: &str) -> Option<&IssuedJob> {
        self.by_id.get(id)
    }

    pub fn mark_all_stale(&mut self) {
        for job in self.by_id.values_mut() {
            job.stale = true;
        }
    }

    pub fn is_stale(&self, id: &str) -> bool {
        self.by_id.get(id).map(|j| j.stale).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn extra_nonce_is_monotonic_and_skips_zero() {
        let mut a = ExtraNonceAllocator::default();
        let mut seen = HashSet::new();
        for _ in 0..16 {
            let e = a.next();
            assert_ne!(e, [0, 0, 0, 0]);
            assert!(seen.insert(e), "extra-nonce reused: {e:?}");
        }
        // The first value is 1 LE.
        let mut b = ExtraNonceAllocator::default();
        assert_eq!(b.next(), 1u32.to_le_bytes());
        assert_eq!(b.next(), 2u32.to_le_bytes());
    }

    #[test]
    fn mark_all_stale_invalidates_outstanding_jobs() {
        let mut store = JobStore::default();
        store.insert(IssuedJob {
            job_id: "j1".into(),
            session_id: "s1".into(),
            extra: [1, 0, 0, 0],
            blob: vec![0; 97],
            target: 1,
            difficulty: 1,
            height: 1,
            seed_hash: [0; 32],
            next_seed_hash: None,
            form: GenesisForm::V5,
            consensus_difficulty: 1,
            stale: false,
            body: None,
        });
        assert!(!store.is_stale("j1"));
        store.mark_all_stale();
        assert!(store.is_stale("j1"));
        assert!(store.is_stale("missing"));
    }
}
