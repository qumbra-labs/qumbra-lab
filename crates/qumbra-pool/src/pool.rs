//! Login / job / submit / keepalived state machine.
//!
//! No sockets here. The endpoint feeds lines in and writes [`Outgoing`]
//! lines out. Share-PoW consumes [`qlab_devnet::pow::hash_to_work_value_for`]
//! and applies xmrig's strict `<` at the share filter only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use qlab_pow::KeyBlockSchedule;
use qlab_stratum::blob::apply_miner_nonce;
use qlab_stratum::codec::{decode_line, DecodedLine};
use qlab_stratum::target::{encode_target_le_hex, target_from_difficulty};
use qlab_stratum::types::{
    job_notification, Job, KeepalivedParams, LoginParams, LoginResult, StratumRequest,
    StratumResponse, SubmitParams,
};

use crate::outbox::JobOutbox;

use crate::accounting::{Ledger, ShareRecord, ShareStatus};
use crate::hasher::{FixedHasher, ShareHasher};
use crate::hexutil;
use crate::jobs::{ExtraNonceAllocator, IssuedJob, JobStore};
use crate::payee::{
    assemble_coinbase, check_body_payee, Accounts, AssembleError, AssembledCoinbase, PayeeRefusal,
};
use crate::pplns::{PplnsWindow, WindowShare};
use crate::share::{is_block_candidate, share_meets_target};
use crate::template::{
    next_seed_in_preload_window, Template, TemplateBody, TemplateError, TemplateSource,
};

/// Where a block-class share is submitted (lab #511). Production injects
/// [`crate::node_rpc::NodeRpcClient`]; tests leave this unset and only
/// record the ledger.
pub trait BlockSubmitter: Send + Sync {
    /// POST the completed header preimage + template body. Returns the
    /// node's named verdict body (`accepted …` / `refused: …`).
    fn submit_block(
        &self,
        form: qlab_devnet::forms::GenesisForm,
        header_preimage: &[u8],
        body: &TemplateBody,
    ) -> Result<String, String>;
}

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
    /// The template names a payee this pool will not let reach the chain
    /// (lab #547). At construction this refuses startup: a service that
    /// cannot name a spendable coinbase must refuse before accepting
    /// miners, exactly as `payout_rkm` already does.
    Payee(PayeeRefusal),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Codec(s) => write!(f, "codec: {s}"),
            PoolError::Template(e) => write!(f, "template: {e}"),
            PoolError::Target(s) => write!(f, "target: {s}"),
            PoolError::Assemble(e) => write!(f, "assemble: {e}"),
            PoolError::Payee(e) => write!(f, "template payee: {e}"),
        }
    }
}

impl std::error::Error for PoolError {}

struct Session {
    login: String,
    extra: [u8; 4],
    latest_job_id: String,
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
    submitter: Option<Arc<dyn BlockSubmitter>>,
    outbox: Option<Arc<JobOutbox>>,
    unavailable: Option<String>,
    jobs_issued: u64,
}

/// Operator counters. Poll-failure / last-good-age live on
/// [`crate::watch::TemplateWatch`] (the poll thread owns those).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCounters {
    pub jobs_issued: u64,
    pub work_unavailable: Option<String>,
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
        // The payee gate at the earliest point it can run (lab #547). No
        // account is registered and no session exists yet, so the only
        // payee acceptable here is `pool_rkm` itself — which is the honest
        // bar: on today's node RPC the template's payee is the node's own
        // `miner_rkm`, so a pool whose node pays somewhere else can never
        // submit a block it owns, and should say so at startup rather than
        // discover it on a block find.
        if let Some(body) = source.current().body.as_ref() {
            check_body_payee(body, pool_rkm, &Accounts::default(), std::iter::empty())
                .map_err(PoolError::Payee)?;
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
                submitter: None,
                outbox: None,
                unavailable: None,
                jobs_issued: 0,
            }),
        })
    }

    /// Install the node-RPC submit path. A block-class share then POSTs.
    pub fn set_submitter(&self, submitter: Arc<dyn BlockSubmitter>) {
        self.inner.lock().expect("pool mutex").submitter = Some(submitter);
    }

    /// Install the job outbox the endpoint drains. [`Self::replace_template`]
    /// deposits into it so a discarded `Ok` value cannot swallow the push.
    pub fn set_outbox(&self, outbox: Arc<JobOutbox>) {
        self.inner.lock().expect("pool mutex").outbox = Some(outbox);
    }

    /// Connection gone. Outstanding jobs for this session stay stale in
    /// the store; they are not re-issued.
    pub fn drop_session(&self, sid: &str) {
        self.inner.lock().expect("pool mutex").sessions.remove(sid);
    }

    /// Stop issuing work and mark every outstanding job stale. Live
    /// sessions are told via the outbox (named reason, then disconnect).
    pub fn suspend_work(&self, reason: impl Into<String>) {
        let mut g = self.inner.lock().expect("pool mutex");
        let reason = reason.into();
        g.unavailable = Some(reason.clone());
        g.jobs.mark_all_stale();
        let outbox = g.outbox.clone();
        drop(g);
        if let Some(outbox) = outbox {
            outbox.unavailable_all(reason);
        }
    }

    pub fn is_unavailable(&self) -> bool {
        self.inner.lock().expect("pool mutex").unavailable.is_some()
    }

    pub fn counters(&self) -> PoolCounters {
        let g = self.inner.lock().expect("pool mutex");
        PoolCounters {
            jobs_issued: g.jobs_issued,
            work_unavailable: g.unavailable.clone(),
        }
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
    /// stale; each live session gets a fresh job. The pairs are deposited
    /// into the installed [`JobOutbox`] (if any) as well as returned, so
    /// a caller that discards `Ok` still cannot swallow the push.
    pub fn replace_template(
        &self,
        source: Box<dyn TemplateSource>,
    ) -> Result<Vec<(String, Job)>, PoolError> {
        let mut g = self.inner.lock().expect("pool mutex");
        g.source = source;
        g.unavailable = None;
        g.jobs.mark_all_stale();
        let template = g.source.current();
        // Refuse the *template*, not just the block (lab #547). Gating here
        // rather than only at submit is the difference between impossible
        // and expensive: no miner spends a hash on work whose payout we
        // would have to throw away. Named-unavailable rather than an error
        // so live sessions are told why and the poller recovers on its own
        // when a sound template arrives.
        if let Err(refusal) = payee_gate(&g, &template) {
            let reason = format!("work-unavailable: {refusal}");
            g.unavailable = Some(reason.clone());
            let outbox = g.outbox.clone();
            drop(g);
            if let Some(outbox) = outbox {
                outbox.unavailable_all(reason);
            }
            return Ok(Vec::new());
        }
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
        let outbox = g.outbox.clone();
        drop(g);
        if let Some(outbox) = outbox {
            outbox.push_all(out.clone());
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
        if let Some(reason) = g.unavailable.clone() {
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_INVALID,
                reason,
            ))]);
        }
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
                latest_job_id: job.job_id.clone(),
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
            return Ok(stale_followup(&mut g, local, rid, "unknown job id"));
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
            if job.stale {
                return Ok(stale_followup(&mut g, local, rid, "stale job"));
            }
            return Ok(vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNAUTHORIZED,
                "job belongs to another session",
            ))]);
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
        let pending_submit = if block {
            job.body
                .clone()
                .map(|body| (job.form, blob, body, g.submitter.clone()))
        } else {
            None
        };
        // The last gate before a payee becomes permanent (lab #547). The
        // intake gate should already have refused this template, so this is
        // the backstop for a body that reached a job by another route — a
        // source swapped without `replace_template`, a future caller, a
        // template mutated in place. It re-checks against the window as it
        // stands now, which is the set `assemble_coinbase` would draw a
        // winner from at this height.
        let payee_refusal = pending_submit.as_ref().and_then(|(_, _, body, _)| {
            let logins = known_logins(&g);
            check_body_payee(
                body,
                g.pool_rkm,
                &g.accounts,
                logins.iter().map(|s| s.as_str()),
            )
            .err()
        });
        drop(g);
        if let Some(refusal) = payee_refusal {
            // The share is valid and the miner did nothing wrong — it keeps
            // the Accepted record and the PPLNS credit taken above. What we
            // refuse is *our own* block, and we stop issuing work rather
            // than repeat the refusal on every find against this template.
            let reason = format!("work-unavailable: {refusal}");
            eprintln!("pool block NOT submitted, payee refused: {refusal}");
            self.suspend_work(reason);
            return Ok(vec![Outgoing::Reply(StratumResponse::ok_status(rid, "OK"))]);
        }
        if let Some((form, preimage, body, submitter)) = pending_submit {
            match submitter {
                Some(sub) => match sub.submit_block(form, &preimage, &body) {
                    Ok(msg) => eprintln!("pool block submit: {msg}"),
                    Err(e) => eprintln!("pool block refused: {e}"),
                },
                None => {
                    eprintln!(
                        "pool block candidate at height (no submitter installed; logged only)"
                    )
                }
            }
        }
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

/// On a stale/unknown-job reject: if we have current work, piggyback a
/// `job` notify so the miner is not left hashing something we will
/// reject; if we do not, name why on the error itself.
fn stale_followup(g: &mut Inner, sid: &str, rid: u64, msg: &str) -> Vec<Outgoing> {
    if let Some(reason) = g.unavailable.clone() {
        return vec![Outgoing::Reply(StratumResponse::err(
            rid,
            ERR_UNKNOWN_JOB,
            format!("{msg}; {reason}"),
        ))];
    }
    let fresh = g
        .sessions
        .get(sid)
        .and_then(|s| g.jobs.get(&s.latest_job_id).cloned())
        .filter(|j| !j.stale);
    let job = if let Some(issued) = fresh {
        Some(job_from_issued(&issued))
    } else if let Some(extra) = g.sessions.get(sid).map(|s| s.extra) {
        let template = g.source.current();
        if template.serves_stock_xmrig() {
            issue_job(g, sid, extra, &template).ok()
        } else {
            None
        }
    } else {
        None
    };
    match job {
        Some(job) => {
            let mut out = vec![Outgoing::Reply(StratumResponse::err(
                rid,
                ERR_UNKNOWN_JOB,
                msg,
            ))];
            if let Ok(req) = job_notification(&job) {
                out.push(Outgoing::Notify(req));
            }
            out
        }
        None => vec![Outgoing::Reply(StratumResponse::err(
            rid,
            ERR_UNKNOWN_JOB,
            format!("{msg}; no-fresh-job"),
        ))],
    }
}

/// Every login this pool currently knows: live sessions plus the PPLNS
/// window. A miner whose connection dropped is still a legitimate payee
/// while its shares are in the window, which is exactly the set
/// [`assemble_coinbase`] draws a winner from.
fn known_logins(g: &Inner) -> Vec<String> {
    let mut out: Vec<String> = g.sessions.values().map(|s| s.login.clone()).collect();
    for (login, _) in g.pplns.weights() {
        if !out.contains(&login) {
            out.push(login);
        }
    }
    out
}

/// The payee gate over a template (lab #547).
///
/// `body == None` is a static `[template]` file: a block-class share is
/// logged and never POSTed (see [`Template::body`]), so no payee can reach
/// the chain from it and there is nothing to refuse.
fn payee_gate(g: &Inner, template: &Template) -> Result<(), PayeeRefusal> {
    let Some(body) = template.body.as_ref() else {
        return Ok(());
    };
    let logins = known_logins(g);
    check_body_payee(
        body,
        g.pool_rkm,
        &g.accounts,
        logins.iter().map(|s| s.as_str()),
    )
}

fn job_from_issued(issued: &IssuedJob) -> Job {
    Job {
        blob: hexutil::encode(&issued.blob),
        job_id: issued.job_id.clone(),
        target: encode_target_le_hex(issued.target),
        algo: Some(ALGO_RX0.into()),
        height: Some(issued.height),
        seed_hash: Some(hexutil::encode(&issued.seed_hash)),
        next_seed_hash: issued.next_seed_hash.map(|h| hexutil::encode(&h)),
        id: Some(issued.session_id.clone()),
    }
}

fn issue_job(
    g: &mut Inner,
    session_id: &str,
    extra: [u8; 4],
    template: &Template,
) -> Result<Job, PoolError> {
    g.job_seq += 1;
    g.jobs_issued += 1;
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
        body: template.body.clone(),
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
    if let Some(session) = g.sessions.get_mut(session_id) {
        session.latest_job_id = job.job_id.clone();
    }
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
            body: None,
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

    #[test]
    fn stale_reject_piggybacks_the_fresh_job() {
        let pool = pool_v5();
        let (sid, first) = login_ok(&pool);
        let sid = sid.unwrap();
        let old = first.job.job_id.clone();
        let new_jobs = pool
            .replace_template(Box::new(HeldTemplateSource::new(template(
                GenesisForm::V5,
                101,
            ))))
            .unwrap();
        assert_eq!(new_jobs[0].1.height, Some(101));

        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(&sid, &old, "aabbccdd", &passing_result(), Some("rx/0")),
            )
            .unwrap();
        assert_eq!(out.len(), 2, "stale reply + job notify, got {}", out.len());
        assert_eq!(reply_status(&out).0, Some(ERR_UNKNOWN_JOB));
        let Outgoing::Notify(req) = &out[1] else {
            panic!("expected job notify after stale reject");
        };
        assert_eq!(req.method, "job");
        let height = req.params.get("height").and_then(|v| v.as_u64());
        assert_eq!(height, Some(101));
        assert_ne!(
            req.params.get("job_id").and_then(|v| v.as_str()),
            Some(old.as_str())
        );
    }

    #[test]
    fn suspend_refuses_login_and_names_stale_reject() {
        let pool = pool_v5();
        let (sid, first) = login_ok(&pool);
        let sid = sid.unwrap();
        let issued = pool.counters().jobs_issued;
        pool.suspend_work("template-unavailable: 3 consecutive poll failures (max 3) / 3000ms since last good template (max 3000ms)");
        assert!(pool.is_unavailable());
        assert!(pool
            .counters()
            .work_unavailable
            .as_deref()
            .unwrap()
            .starts_with("template-unavailable:"));

        let mut fresh = None;
        let out = pool
            .handle_line(&mut fresh, &login_line(Some(vec!["rx/0".into()])))
            .unwrap();
        assert!(fresh.is_none());
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("expected reply");
        };
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, ERR_INVALID);
        assert!(err.message.starts_with("template-unavailable:"));
        assert_eq!(
            pool.counters().jobs_issued,
            issued,
            "a stall must not issue more jobs"
        );

        let mut s = Some(sid.clone());
        let out = pool
            .handle_line(
                &mut s,
                &submit_line(
                    &sid,
                    &first.job.job_id,
                    "aabbccdd",
                    &passing_result(),
                    Some("rx/0"),
                ),
            )
            .unwrap();
        assert_eq!(out.len(), 1, "no job to piggyback while unavailable");
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("expected reply");
        };
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, ERR_UNKNOWN_JOB);
        assert!(err.message.contains("stale job"));
        assert!(err.message.contains("template-unavailable:"));
    }
}
