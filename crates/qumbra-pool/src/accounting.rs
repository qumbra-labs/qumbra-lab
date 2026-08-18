//! Share accounting. Stage 1 records; stage 2 is the PPLNS window and
//! payee-list assembly. A share that passed structural checks but has
//! not been PoW-checked is [`ShareStatus::AcceptedStructural`] — the
//! #490 predicate is not mirrored here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareStatus {
    /// Structural checks passed. PoW target check is deferred to the
    /// commit that consumes #490's exported predicate.
    AcceptedStructural,
    Stale,
    Duplicate,
    BadAlgo,
    BadSession,
    /// Login refused: v4 net, stock xmrig is UNCLEAN (#356).
    UncleanV4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRecord {
    pub login: String,
    pub session_id: String,
    pub job_id: String,
    pub height: u64,
    pub difficulty: u64,
    pub nonce: [u8; 4],
    pub result: [u8; 32],
    pub status: ShareStatus,
}

#[derive(Clone, Debug, Default)]
pub struct Ledger {
    records: Vec<ShareRecord>,
}

impl Ledger {
    pub fn record(&mut self, rec: ShareRecord) {
        self.records.push(rec);
    }

    pub fn records(&self) -> &[ShareRecord] {
        &self.records
    }

    pub fn accepted_for<'a>(
        &'a self,
        login: &'a str,
    ) -> impl Iterator<Item = &'a ShareRecord> + 'a {
        self.records
            .iter()
            .filter(move |r| r.login == login && r.status == ShareStatus::AcceptedStructural)
    }

    pub fn accepted_count(&self, login: &str) -> u64 {
        self.accepted_for(login).count() as u64
    }

    pub fn accepted_difficulty_sum(&self, login: &str) -> u128 {
        self.accepted_for(login).map(|r| r.difficulty as u128).sum()
    }

    pub fn has_duplicate(&self, job_id: &str, nonce: &[u8; 4]) -> bool {
        self.records.iter().any(|r| {
            r.job_id == job_id && r.nonce == *nonce && r.status == ShareStatus::AcceptedStructural
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(login: &str, job: &str, nonce: u8, status: ShareStatus) -> ShareRecord {
        ShareRecord {
            login: login.into(),
            session_id: "s".into(),
            job_id: job.into(),
            height: 1,
            difficulty: 1024,
            nonce: [nonce, 0, 0, 0],
            result: [0; 32],
            status,
        }
    }

    #[test]
    fn records_accepted_shares_and_sums_difficulty() {
        let mut l = Ledger::default();
        l.record(rec("alice", "j1", 1, ShareStatus::AcceptedStructural));
        l.record(rec("alice", "j1", 1, ShareStatus::Duplicate));
        l.record(rec("bob", "j2", 2, ShareStatus::AcceptedStructural));
        l.record(rec("alice", "j3", 3, ShareStatus::AcceptedStructural));
        assert_eq!(l.accepted_count("alice"), 2);
        assert_eq!(l.accepted_difficulty_sum("alice"), 2048);
        assert_eq!(l.accepted_count("bob"), 1);
        assert!(l.has_duplicate("j1", &[1, 0, 0, 0]));
        assert!(!l.has_duplicate("j1", &[9, 0, 0, 0]));
    }
}
