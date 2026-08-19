//! Login / job / submit / keepalived state machine.
//!
//! No sockets here. The endpoint feeds lines in and writes [`Outgoing`]
//! lines out. Share-PoW consumes [`qlab_devnet::pow::hash_to_work_value_for`]
//! and applies xmrig's strict `<` at the share filter only.

use std::collections::HashMap;
use std::sync::Mutex;

use qlab_pow::KeyBlockSchedule;
use qlab_stratum::blob::apply_miner_nonce;
use qlab_stratum::codec::{decode_line, DecodedLine};
use qlab_stratum::target::{encode_target_le_hex, target_from_difficulty};
use qlab_stratum::types::{
    Job, KeepalivedParams, LoginParams, LoginResult, StratumRequest, StratumResponse, SubmitParams,
};

use crate::accounting::{Ledger, ShareRecord, ShareStatus};
use crate::hasher::{FixedHasher, ShareHasher};
use crate::hexutil;
use crate::jobs::{ExtraNonceAllocator, IssuedJob, JobStore};
use crate::payee::{assemble_coinbase, Accounts, AssembleError, AssembledCoinbase};
use crate::pplns::{PplnsWindow, WindowShare};
use crate::share::{is_block_candidate, share_meets_target};
use crate::template::{next_seed_in_preload_window, Template, TemplateError, TemplateSource};

/// xmrig-proxy-shaped error codes we actually emit.
pub const ERR_INVALID: i64 = -1;
pub const ERR_UNKNOWN_JOB: i64 = 20;
pub const ERR_DUPLICATE: i64 = 21;
pub const ERR_LOW_DIFF: i64 = 22;
pub const ERR_UNAUTHORIZED: i64 = 23;
pub const ERR_BAD_ALGO: i64 = 24;
pub const ERR_UNCLEAN_V4: i64 = 25;
pub const ERR_BAD_HASH: i64 = 26;

const ALGO_RX0: &str = "rx/0";

pub enum Outgoing {
    Reply(StratumResponse),
    Notify(StratumRequest),
}

#[derive(Debug)]
pub enum PoolError {
    Codec(String),
    Template(TemplateError),
    Target(String),
    Assemble(AssembleError),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Codec(s) => write!(f, "codec: {s}"),
            PoolError::Template(e) => write!(f, "template: {e}"),
            PoolError::Target(s) => write!(f, "target: {s}"),
            PoolError::Assemble(e) => write!(f, "assemble: {e}"),
        }
    }
}

impl std::error::Error for PoolError {}

struct Session {
    login: String,
    extra: [u8; 4],
}

struct Inner {
    source: Box<dyn TemplateSource>,
    jobs: JobStore,
    ledger: Ledger,
    extra: ExtraNonceAllocator,
    sessions: HashMap<String, Session>,
    share_difficulty: u64,
    job_seq: u64,
    session_seq: u64,
    schedule: KeyBlockSchedule,
    hasher: Box<dyn ShareHasher>,
    pplns: PplnsWindow,
    accounts: Accounts,
    pool_rkm: [u64; 4],
}

pub struct Pool {
    inner: Mutex<Inner>,
}

impl Pool {
    /// Test constructor: [`FixedHasher::zeros`] so existing submits of an
    /// all-zero `result` still match. Production uses
    /// [`Self::new_with_hasher`] with [`crate::hasher::RandomXShareHasher`].
    pub fn new(share_difficulty: u64, source: Box<dyn TemplateSource>) -> Result<Self, PoolError> {
        Self::new_with_hasher(
            share_difficulty,
            source,
            Box::new(FixedHasher::zeros()),
            [9, 0, 0, 0],
        )
    }

    pub fn new_with_hasher(
        share_difficulty: u64,
        source: Box<dyn TemplateSource>,
        hasher: Box<dyn ShareHasher>,
        pool_rkm: [u64; 4],
    ) -> Result<Self, PoolError> {
        if share_difficulty == 0 {
            return Err(PoolError::Target("share_difficulty must be ≥ 1".into()));
        }
        if pool_rkm == [0u64; 4] {
            return Err(PoolError::Assemble(AssembleError::ZeroPoolRkm));
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                source,
                jobs: JobStore::default(),
                ledger: Ledger::default(),
                extra: ExtraNonceAllocator::default(),
                sessions: HashMap::new(),
                share_difficulty,
                job_seq: 0,
                session_seq: 0,
                schedule: KeyBlockSchedule::default(),
                hasher,
                pplns: PplnsWindow::default(),
                accounts: Accounts::default(),
                pool_rkm,
            }),
        })
    }

    pub fn register_account(&self, login: impl Into<String>, rkm: [u64; 4]) {
        self.inner
            .lock()
            .expect("pool mutex")
            .accounts
            .register(login, rkm);
    }

    /// Form-keyed coinbase for the current tip height.
    pub fn assemble_now(&self) -> Result<AssembledCoinbase, PoolError> {
        let g = self.inner.lock().expect("pool mutex");
        let t = g.source.current();
        assemble_coinbase(t.form, t.header.height, &g.pplns, &g.accounts, g.pool_rkm)
            .map_err(PoolError::Assemble)
    }

    pub fn pplns_len(&self) -> usize {
        self.inner.lock().expect("pool mutex").pplns.len()
    }

    pub fn handle_line(
        &self,
        session_id: &mut Option<String>,
        line: &str,
    ) -> Result<Vec<Outgoing>, PoolError> {
        let decoded = decode_line(line).map_err(|e| PoolError::Codec(e.to_string()))?;
        let DecodedLine::Request(req) = decoded else {
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                0,
                ERR_INVALID,
                "pool does not accept responses on this socket",
            ))]);
        };
        let rid = req.id.unwrap_or(0);
        match req.method.as_str() {
            "login" => self.on_login(session_id, rid, &req),
            "submit" => self.on_submit(session_id, rid, &req),
            "keepalived" => self.on_keepalived(session_id, rid, &req),
            other => Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_INVALID,
                format!("unknown method `{other}`"),
            ))]),
        }
    }

    /// Replace the template source's current tip. Outstanding jobs become
    /// stale; each live session gets a fresh job. The endpoint fans the
    /// returned `(session_id, Job)` pairs out as `job` notifications.
    ///
    /// Stage 1's live binary holds a static template; tests call this to
    /// prove the stale-job path.
    pub fn replace_template(
        &self,
        source: Box<dyn TemplateSource>,
    ) -> Result<Vec<(String, Job)>, PoolError> {
        let mut g = self.inner.lock().expect("pool mutex");
        g.source = source;
        g.jobs.mark_all_stale();
        let template = g.source.current();
        if !template.serves_stock_xmrig() {
            return Ok(Vec::new());
        }
        let session_ids: Vec<String> = g.sessions.keys().cloned().collect();
        let mut out = Vec::new();
        for sid in session_ids {
            let extra = g.sessions[&sid].extra;
            let job = issue_job(&mut g, &sid, extra, &template)?;
            out.push((sid, job));
        }
        Ok(out)
    }

    pub fn ledger_snapshot(&self) -> Ledger {
        self.inner.lock().expect("pool mutex").ledger.clone()
    }

    pub fn current_template(&self) -> Template {
        self.inner.lock().expect("pool mutex").source.current()
    }

    fn on_login(
        &self,
        session_id: &mut Option<String>,
        rid: u64,
        req: &StratumRequest,
    ) -> Result<Vec<Outgoing>, PoolError> {
        let params: LoginParams = match req.parse_login_params() {
            Ok(p) => p,
            Err(e) => {
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_INVALID,
                    format!("login params: {e}"),
                ))]);
            }
        };
        if let Some(algos) = &params.algo {
            if !algos.iter().any(|a| a == ALGO_RX0) {
                let mut g = self.inner.lock().expect("pool mutex");
                g.ledger.record(ShareRecord {
                    login: params.login.clone(),
                    session_id: String::new(),
                    job_id: String::new(),
                    height: 0,
                    difficulty: 0,
                    nonce: [0; 4],
                    result: [0; 32],
                    status: ShareStatus::BadAlgo,
                    block_candidate: false,
                });
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_BAD_ALGO,
                    "algo must include rx/0",
                ))]);
            }
        }

        let mut g = self.inner.lock().expect("pool mutex");
        let template = g.source.current();
        if !template.serves_stock_xmrig() {
            g.ledger.record(ShareRecord {
                login: params.login.clone(),
                session_id: String::new(),
                job_id: String::new(),
                height: template.header.height,
                difficulty: 0,
                nonce: [0; 4],
                result: [0; 32],
                status: ShareStatus::UncleanV4,
                block_candidate: false,
            });
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNCLEAN_V4,
                "v4-net-unclean-for-stock-xmrig",
            ))]);
        }

        g.session_seq += 1;
        let sid = format!("s{:08x}", g.session_seq);
        let extra = g.extra.next();
        let job = issue_job(&mut g, &sid, extra, &template)?;
        g.sessions.insert(
            sid.clone(),
            Session {
                login: params.login,
                extra,
            },
        );
        *session_id = Some(sid.clone());
        let result = LoginResult {
            id: sid,
            job,
            status: "OK".into(),
            extensions: None,
        };
        Ok(vec![Outgoing::Reply(
            StratumResponse::ok_login(rid, &result).map_err(|e| PoolError::Codec(e.to_string()))?,
        )])
    }

    fn on_submit(
        &self,
        session_id: &mut Option<String>,
        rid: u64,
        req: &StratumRequest,
    ) -> Result<Vec<Outgoing>, PoolError> {
        let params: SubmitParams = match req.parse_submit_params() {
            Ok(p) => p,
            Err(e) => {
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_INVALID,
                    format!("submit params: {e}"),
                ))]);
            }
        };
        let Some(local) = session_id.as_deref() else {
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNAUTHORIZED,
                "not logged in",
            ))]);
        };
        if params.id != local {
            return Ok(self.refuse_submit(
                &params,
                ShareStatus::BadSession,
                rid,
                ERR_UNAUTHORIZED,
                "session id mismatch",
            ));
        }
        if let Some(algo) = &params.algo {
            if algo != ALGO_RX0 {
                return Ok(self.refuse_submit(
                    &params,
                    ShareStatus::BadAlgo,
                    rid,
                    ERR_BAD_ALGO,
                    "algo must be rx/0",
                ));
            }
        }
        let nonce = match hexutil::decode_exact::<4>(&params.nonce) {
            Ok(n) => n,
            Err(e) => {
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_INVALID,
                    format!("nonce: {e}"),
                ))]);
            }
        };
        let result = match hexutil::decode_exact::<32>(&params.result) {
            Ok(r) => r,
            Err(e) => {
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_INVALID,
                    format!("result: {e}"),
                ))]);
            }
        };

        let mut g = self.inner.lock().expect("pool mutex");
        let login = g
            .sessions
            .get(local)
            .map(|s| s.login.clone())
            .unwrap_or_default();

        let Some(job) = g.jobs.get(&params.job_id).cloned() else {
            g.ledger.record(ShareRecord {
                login,
                session_id: local.to_string(),
                job_id: params.job_id.clone(),
                height: 0,
                difficulty: 0,
                nonce,
                result,
                status: ShareStatus::Stale,
                block_candidate: false,
            });
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNKNOWN_JOB,
                "unknown job id",
            ))]);
        };
        if job.stale || job.session_id != local {
            let status = if job.stale {
                ShareStatus::Stale
            } else {
                ShareStatus::BadSession
            };
            g.ledger.record(ShareRecord {
                login,
                session_id: local.to_string(),
                job_id: params.job_id.clone(),
                height: job.height,
                difficulty: job.difficulty,
                nonce,
                result,
                status,
                block_candidate: false,
            });
            let (code, msg) = if job.stale {
                (ERR_UNKNOWN_JOB, "stale job")
            } else {
                (ERR_UNAUTHORIZED, "job belongs to another session")
            };
            return Ok(vec![Outgoing::Reply(StratumResponse::err(rid, code, msg))]);
        }
        if g.ledger.has_duplicate(&params.job_id, &nonce) {
            g.ledger.record(ShareRecord {
                login,
                session_id: local.to_string(),
                job_id: params.job_id.clone(),
                height: job.height,
                difficulty: job.difficulty,
                nonce,
                result,
                status: ShareStatus::Duplicate,
                block_candidate: false,
            });
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_DUPLICATE,
                "duplicate share",
            ))]);
        }

        // Prove the miner window is writable without touching extra-nonce.
        let mut blob = job.blob.clone();
        apply_miner_nonce(&mut blob, &nonce).map_err(|e| PoolError::Codec(e.to_string()))?;

        // Share-PoW execution: hasher(seed, blob) must equal the claimed result.
        // Production injects RandomXShareHasher; tests inject FixedHasher.
        let computed = g.hasher.hash(&job.seed_hash, &blob);
        if computed != result {
            g.ledger.record(ShareRecord {
                login,
                session_id: local.to_string(),
                job_id: params.job_id.clone(),
                height: job.height,
                difficulty: job.difficulty,
                nonce,
                result,
                status: ShareStatus::BadHash,
                block_candidate: false,
            });
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_BAD_HASH,
                "Invalid share hash",
            ))]);
        }

        // Share filter: #490's work-value export + xmrig's strict `<`.
        if !share_meets_target(&result, job.target, job.form) {
            g.ledger.record(ShareRecord {
                login,
                session_id: local.to_string(),
                job_id: params.job_id.clone(),
                height: job.height,
                difficulty: job.difficulty,
                nonce,
                result,
                status: ShareStatus::LowDifficulty,
                block_candidate: false,
            });
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_LOW_DIFF,
                "Low difficulty share",
            ))]);
        }

        g.pplns.push(WindowShare {
            login: login.clone(),
            difficulty: job.difficulty,
        });
        let block = is_block_candidate(&result, job.consensus_difficulty, job.form);
        g.ledger.record(ShareRecord {
            login,
            session_id: local.to_string(),
            job_id: params.job_id.clone(),
            height: job.height,
            difficulty: job.difficulty,
            nonce,
            result,
            status: ShareStatus::Accepted,
            block_candidate: block,
        });
        Ok(vec![Outgoing::Reply(StratumResponse::ok_status(rid, "OK"))])
    }

    fn on_keepalived(
        &self,
        session_id: &mut Option<String>,
        rid: u64,
        req: &StratumRequest,
    ) -> Result<Vec<Outgoing>, PoolError> {
        let params: KeepalivedParams = match serde_json::from_value(req.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return Ok(vec![Outgoing::Reply(StratumResponse::err(
                    rid,
                    ERR_INVALID,
                    format!("keepalived params: {e}"),
                ))]);
            }
        };
        match session_id.as_deref() {
            Some(sid) if sid == params.id => Ok(vec![Outgoing::Reply(StratumResponse::ok_status(
                rid,
                "KEEPALIVED",
            ))]),
            _ => Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNAUTHORIZED,
                "keepalived session mismatch",
            ))]),
        }
    }

    fn refuse_submit(
        &self,
        params: &SubmitParams,
        status: ShareStatus,
        rid: u64,
        code: i64,
        msg: &str,
    ) -> Vec<Outgoing> {
        let nonce = hexutil::decode_exact::<4>(&params.nonce).unwrap_or([0; 4]);
        let result = hexutil::decode_exact::<32>(&params.result).unwrap_or([0; 32]);
        let mut g = self.inner.lock().expect("pool mutex");
        let login = g
            .sessions
            .get(&params.id)
            .map(|s| s.login.clone())
            .unwrap_or_else(|| params.id.clone());
        g.ledger.record(ShareRecord {
            login,
            session_id: params.id.clone(),
            job_id: params.job_id.clone(),
            height: 0,
            difficulty: 0,
            nonce,
            result,
            status,
            block_candidate: false,
        });
        vec![Outgoing::Reply(StratumResponse::err(rid, code, msg))]
    }
}

fn issue_job(
    g: &mut Inner,
    session_id: &str,
    extra: [u8; 4],
    template: &Template,
) -> Result<Job, PoolError> {
    g.job_seq += 1;
    let job_id = format!("j{:08x}", g.job_seq);
    let blob = template
        .blob_with_extranonce(extra)
        .map_err(PoolError::Template)?;
    let target =
        target_from_difficulty(g.share_difficulty).map_err(|e| PoolError::Target(e.to_string()))?;
    // Far from a rotation: omit. Tests that want the field on the wire
    // set height inside the window. A source-supplied next hash outside
    // the window is still omitted — the window is pool policy.
    let next = if next_seed_in_preload_window(template.header.height, g.schedule) {
        template.next_seed_hash
    } else {
        None
    };
    let issued = IssuedJob {
        job_id: job_id.clone(),
        session_id: session_id.to_string(),
        extra,
        blob: blob.clone(),
        target,
        difficulty: g.share_difficulty,
        height: template.header.height,
        seed_hash: template.seed_hash,
        next_seed_hash: next,
        form: template.form,
        consensus_difficulty: template.header.difficulty,
        stale: false,
    };
    let job = Job {
        blob: hexutil::encode(&blob),
        job_id: job_id.clone(),
        target: encode_target_le_hex(target),
        algo: Some(ALGO_RX0.into()),
        height: Some(template.header.height),
        seed_hash: Some(hexutil::encode(&template.seed_hash)),
        next_seed_hash: next.map(|h| hexutil::encode(&h)),
        id: Some(session_id.to_string()),
    };
    g.jobs.insert(issued);
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::HeldTemplateSource;
    use qlab_devnet::forms::GenesisForm;
    use qlab_devnet::header::{AggregateProofSlot, BlockHeader, EpochSupplyAttestation};
    use qlab_stratum::blob::{extranonce_of, miner_nonce_of, V5_BLOB_LEN};
    use qlab_stratum::codec::{encode_request, encode_response};

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            prev: [0x11; 32],
            height,
            timestamp: 1_785_000_000,
            difficulty: 256,
            nonce: 0,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    fn template(form: GenesisForm, height: u64) -> Template {
        Template {
            form,
            header: header(height),
            seed_hash: [0x33; 32],
            next_seed_hash: Some([0x44; 32]),
        }
    }

    fn pool_v5() -> Pool {
        Pool::new(
            1024,
            Box::new(HeldTemplateSource::new(template(GenesisForm::V5, 100))),
        )
        .unwrap()
    }

    fn login_line(algo: Option<Vec<String>>) -> String {
        let req = StratumRequest::login(
            1,
            &LoginParams {
                login: "alice".into(),
                pass: "x".into(),
                agent: Some("XMRig/6.21.0".into()),
                algo,
                rigid: None,
            },
        )
        .unwrap();
        encode_request(&req).unwrap()
    }

    fn login_ok(pool: &Pool) -> (Option<String>, LoginResult) {
        let mut sid = None;
        let out = pool
            .handle_line(&mut sid, &login_line(Some(vec!["rx/0".into()])))
            .unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("expected reply");
        };
        (sid, resp.parse_login_result().unwrap())
    }

    /// All-zero hash: v5 tail-LE work value is 0, which is `<` any real target.
    fn passing_result() -> String {
        "00".repeat(32)
    }

    fn submit_line(
        sid: &str,
        job_id: &str,
        nonce: &str,
        result: &str,
        algo: Option<&str>,
    ) -> String {
        let req = StratumRequest::submit(
            2,
            &SubmitParams {
                id: sid.into(),
                job_id: job_id.into(),
                nonce: nonce.into(),
                result: result.into(),
                algo: algo.map(str::to_string),
            },
        )
        .unwrap();
        encode_request(&req).unwrap()
    }

    fn reply_status(out: &[Outgoing]) -> (Option<i64>, Option<String>) {
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("expected reply");
        };
        let code = resp.error.as_ref().map(|e| e.code);
        let status = resp
            .result
            .as_ref()
            .and_then(|v| v.get("status"))
            .and_then(|s| s.as_str())
            .map(str::to_string);
        (code, status)
    }

    #[test]
    fn login_requires_rx0_and_returns_partitioned_v5_job() {
        let pool = pool_v5();
        let mut sid = None;
        let out = pool
            .handle_line(&mut sid, &login_line(Some(vec!["cn/r".into()])))
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_BAD_ALGO));

        let (sid, result) = login_ok(&pool);
        assert!(sid.is_some());
        assert_eq!(result.status, "OK");
        let blob = hexutil::decode(&result.job.blob).unwrap();
        assert_eq!(blob.len(), V5_BLOB_LEN);
        assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
        assert_ne!(extranonce_of(&blob).unwrap(), [0, 0, 0, 0]);
        assert_eq!(result.job.algo.as_deref(), Some("rx/0"));
        assert_eq!(result.job.height, Some(100));
        // height 100 is far from the first rotation (2113); next_seed omitted.
        assert!(result.job.next_seed_hash.is_none());
    }

    #[test]
    fn login_on_v4_is_refused_by_name() {
        let pool = Pool::new(
            1024,
            Box::new(HeldTemplateSource::new(template(GenesisForm::V4, 100))),
        )
        .unwrap();
        let mut sid = None;
        let out = pool
            .handle_line(&mut sid, &login_line(Some(vec!["rx/0".into()])))
            .unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("expected reply");
        };
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, ERR_UNCLEAN_V4);
        assert!(err.message.contains("v4-net-unclean-for-stock-xmrig"));
        assert!(sid.is_none());
        assert_eq!(
            pool.ledger_snapshot().records()[0].status,
            ShareStatus::UncleanV4
        );
    }

    #[test]
    fn submit_structural_ok_then_duplicate_then_stale() {
        let pool = pool_v5();
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id.clone();

        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "d0030040", &passing_result(), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).1.as_deref(), Some("OK"));
        assert_eq!(pool.ledger_snapshot().accepted_count("alice"), 1);

        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "d0030040", &passing_result(), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_DUPLICATE));

        pool.replace_template(Box::new(HeldTemplateSource::new(template(
            GenesisForm::V5,
            101,
        ))))
        .unwrap();
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "aabbccdd", &passing_result(), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_UNKNOWN_JOB));
    }

    #[test]
    fn submit_wrong_session_and_bad_algo_are_named() {
        let pool = pool_v5();
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id;
        let mut s = Some(sid.clone());

        let out = pool
            .handle_line(
                &mut s,
                &submit_line(
                    "s-other",
                    &job_id,
                    "d0030040",
                    &passing_result(),
                    Some("rx/0"),
                ),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_UNAUTHORIZED));

        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "d0030040", &passing_result(), Some("cn/r")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_BAD_ALGO));
    }

    #[test]
    fn keepalived_and_job_reissue_on_rotate() {
        let pool = pool_v5();
        let (sid, first) = login_ok(&pool);
        let sid = sid.unwrap();
        let req = StratumRequest::keepalived(3, &KeepalivedParams { id: sid.clone() }).unwrap();
        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(&mut s, &encode_request(&req).unwrap())
            .unwrap();
        assert_eq!(reply_status(&out).1.as_deref(), Some("KEEPALIVED"));

        let new_jobs = pool
            .replace_template(Box::new(HeldTemplateSource::new(template(
                GenesisForm::V5,
                2112, // first rotation is 2113; inside the 64-block window
            ))))
            .unwrap();
        assert_eq!(new_jobs.len(), 1);
        assert_eq!(new_jobs[0].0, sid);
        assert_ne!(new_jobs[0].1.job_id, first.job.job_id);
        assert_eq!(new_jobs[0].1.height, Some(2112));
        assert!(new_jobs[0].1.next_seed_hash.is_some());
        // encode_response is reachable for the endpoint; keep it compiling
        // against the login reply shape.
        let _ = encode_response(&StratumResponse::ok_status(1, "OK")).unwrap();
    }

    fn pool_with_digest(digest: [u8; 32]) -> Pool {
        Pool::new_with_hasher(
            1024,
            Box::new(HeldTemplateSource::new(template(GenesisForm::V5, 100))),
            Box::new(crate::hasher::FixedHasher { digest }),
            [9, 0, 0, 0],
        )
        .unwrap()
    }

    #[test]
    fn submit_low_diff_is_named_and_uses_the_v5_window() {
        // Hasher returns the claimed digest so this test isolates the target
        // filter from the integrity check.
        let pool = pool_with_digest([0xFF; 32]);
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id.clone();
        let mut s = Some(sid.clone());

        // All-0xFF: v5 tail-LE is u64::MAX, which is not < any real target.
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "01020304", &"ff".repeat(32), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_LOW_DIFF));
        assert_eq!(
            pool.ledger_snapshot().records().last().unwrap().status,
            ShareStatus::LowDifficulty
        );
        assert_eq!(pool.ledger_snapshot().accepted_count("alice"), 0);

        // Tail-LE = 7, head = 0xFF: v5 accepts, proving the filter consumed
        // hash_to_work_value_for(..., V5) rather than the v4 head-BE read.
        let mut tail_wins = [0xFFu8; 32];
        tail_wins[24..32].copy_from_slice(&7u64.to_le_bytes());
        let pool = pool_with_digest(tail_wins);
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id.clone();
        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(
                    &sid,
                    &job_id,
                    "05060708",
                    &hexutil::encode(&tail_wins),
                    Some("rx/0"),
                ),
            )
            .unwrap();
        assert_eq!(reply_status(&out).1.as_deref(), Some("OK"));
        assert_eq!(pool.ledger_snapshot().accepted_count("alice"), 1);
    }

    #[test]
    fn submit_bad_hash_is_named_and_does_not_score() {
        let pool = pool_v5();
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id.clone();
        let mut s = Some(sid.clone());
        // FixedHasher::zeros expects 00..00; ff..ff is a lie.
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "11111111", &"ff".repeat(32), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).0, Some(ERR_BAD_HASH));
        assert_eq!(
            pool.ledger_snapshot().records().last().unwrap().status,
            ShareStatus::BadHash
        );
        assert_eq!(pool.pplns_len(), 0);
    }

    #[test]
    fn accepted_share_scores_pplns_and_assembles_v5_n1() {
        let pool = pool_v5();
        pool.register_account("alice", [1, 0, 0, 0]);
        let (sid, result) = login_ok(&pool);
        let sid = sid.unwrap();
        let job_id = result.job.job_id.clone();
        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &job_id, "d0030040", &passing_result(), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(reply_status(&out).1.as_deref(), Some("OK"));
        assert_eq!(pool.pplns_len(), 1);
        match pool.assemble_now().unwrap() {
            AssembledCoinbase::V5 { payees } => {
                assert_eq!(payees.len(), 1);
                assert_eq!(payees[0].rkm, [1, 0, 0, 0]);
            }
            other => panic!("{other:?}"),
        }
    }
}
