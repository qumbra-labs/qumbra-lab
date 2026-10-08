//! **The Annulet proving service** (lab #924 5A-D3/D4): a prover for
//! Candidate A holder spends that **cannot spend, re-aim or re-sign** them.
//!
//! A client — a wallet that keeps its keys — uploads a
//! [`ProvingBundle`]: its S or P transaction with the proof empty and its
//! ML-DSA authorization section already attached, plus the witness. The
//! intent the section signs binds every public field but the proof, so the
//! only thing this service can add is the proof; a proof of anything else
//! fails the node's PV binding, and a changed byte fails the section.
//!
//! **Admission, in order, refusing by name before anything is spawned:**
//! 1. the bearer token ([`crate::token`]): signature, window, net, revocation;
//! 2. the token's quota (admitted jobs per UTC day) and its one in-flight job;
//! 3. the body's byte ceiling ([`MAX_ANNULET_BUNDLE_BYTES`]), read bounded;
//! 4. [`ProvingBundle::decode`] — S/P only, `D_AUTH` fixed, every field
//!    bounded; an issuer operation is refused as `issuer-shape`;
//! 5. [`ProvingBundle::check`] on this net: the witness states the
//!    transaction, the openings resolve, the section verifies. Its intent
//!    digest is the idempotency key.
//!
//! Then one job: queued → proving (a fresh child process, one at a time,
//! core dumps off, scratch on tmpfs, no network) → submitting (this process
//! checks the child returned the bundle's transaction plus a proof and
//! nothing else, then `POST /v1/tx` to the pinned node, and to the relay if
//! one is configured) → submitted with the tx id. **The job URL is a
//! capability**: 32 random bytes, valid for the result TTL after the job
//! ends; whoever holds it can read or cancel the job, and the popup that
//! uploaded the bundle is the one that holds it.
//!
//! **Per-day counts live in memory and reset on restart**; so do the jobs.
//! Logs carry a job-id prefix, the shape, sizes, durations and an outcome
//! code — never bundle or transaction bytes, a token id or a tx id. Refusals
//! are counted per code under a short hash of the token id, so abuse shows
//! without naming the user.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qlab_devnet::annulet::{AuthContext, L2ShapeTag};
use qlab_devnet::body::TxEntry;
use qlab_devnet::forms::L2AuthForm;
use qlab_l2spend::bundle::{BundleError, ProvingBundle};
use qlab_remote_auth::{keccak256, Hash32};
use rand::TryRng;
use serde::Serialize;
use zeroize::Zeroize;

use crate::token::{hex, hex_decode, Claims, TokenKeys};
use crate::{
    env_required, lock, parse_env_or, validate_base_url, ApiError,
};

/// The Annulet API's protocol version.
pub const ANNULET_PROTOCOL_VERSION: u32 = 1;
/// The bundle ceiling: a P bundle is about 14 KiB beside its 64 KiB
/// transaction bound ([`qlab_l2spend::bundle::MAX_BUNDLE_TX_BYTES`]).
pub const MAX_ANNULET_BUNDLE_BYTES: usize = 80 * 1024;
/// The proved transaction's ceiling: the node's Annulet `/v1/tx` bound
/// (`qumbra_node::discovery_server::MAX_TX_WIRE_BYTES_ANNULET`).
pub const MAX_ANNULET_TX_BYTES: usize = 512 * 1024;
/// Most queued jobs (the running one not counted).
pub const MAX_ANNULET_QUEUE: usize = 8;
/// Retained jobs, live and finished, before admission refuses.
pub const MAX_ANNULET_JOBS: usize = 64;
/// The operator's default admitted jobs per token per UTC day.
pub const DEFAULT_PER_DAY: u16 = 20;
/// Allowance for submission after the prove, in the validity estimate.
pub const SUBMIT_SLACK_SECS: u64 = 60;
/// How long an admitted upload may take to arrive (80 KiB at 3 KiB/s).
pub const ANNULET_UPLOAD_DEADLINE: Duration = Duration::from_secs(30);
/// The worker child's protocol tag.
pub const ANNULET_WORKER_PROTOCOL: &str = "qumbra-prover-annulet-worker-v1";

/// Lab #924 PR 3g: the Annulet mode's own acknowledgement for a plain-http
/// node or relay link (the L1 experiment's `QUMBRA_PROVER_ALLOW_INSECURE_NODE_HTTP`,
/// worded "private and valueless", does not fit and no longer applies here).
/// It states what the link is: plaintext, its exposure bounded by a firewall
/// that admits only this host. What crosses it is a signed, proved
/// transaction — public once submitted, and any alteration invalidates it —
/// so the plaintext costs at most a dropped submission.
pub const ANNULET_PLAIN_HTTP_VAR: &str = "QUMBRA_PROVER_ANNULET_ALLOW_PLAIN_HTTP_NODE";
pub const ANNULET_PLAIN_HTTP_ACK: &str = "I_UNDERSTAND_THE_NODE_LINK_IS_PLAINTEXT_AND_FIREWALLED_TO_THIS_HOST";

/// An Annulet node or relay base URL: https, or plain http with exactly
/// [`ANNULET_PLAIN_HTTP_ACK`] in [`ANNULET_PLAIN_HTTP_VAR`] (`ack`).
fn annulet_node_url(name: &str, value: &str, ack: Option<&str>) -> Result<String, String> {
    let plain_ok = ack == Some(ANNULET_PLAIN_HTTP_ACK);
    validate_base_url(name, value, plain_ok).map_err(|e| {
        if !plain_ok && value.starts_with("http://") {
            format!("{name} must use https; a plain http node link needs {ANNULET_PLAIN_HTTP_VAR}={ANNULET_PLAIN_HTTP_ACK}")
        } else {
            e
        }
    })
}

const TMPFS_MAGIC: i64 = 0x0102_1994;

/// Fail-closed Annulet configuration (all `QUMBRA_PROVER_ANNULET_*`, plus
/// the token key files and the scratch directory).
pub struct AnnuletConfig {
    pub genesis_hash: Hash32,
    pub slot_secs: u64,
    pub queue_capacity: usize,
    pub prove_timeout: Duration,
    pub result_ttl: Duration,
    pub per_day_default: u16,
    pub node_url: String,
    pub relay_url: Option<String>,
    pub scratch: PathBuf,
    pub tokens: TokenKeys,
    pub deny_file: Option<PathBuf>,
}

impl AnnuletConfig {
    /// `None` when `QUMBRA_PROVER_ANNULET_GENESIS_HASH` is unset: the
    /// Annulet mode is off.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(hash) = std::env::var("QUMBRA_PROVER_ANNULET_GENESIS_HASH") else {
            return Ok(None);
        };
        let genesis_hash: Hash32 = (hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .then(|| hex_decode(&hash))
        .flatten()
        .and_then(|b| b.try_into().ok())
        .ok_or("QUMBRA_PROVER_ANNULET_GENESIS_HASH must be 64 lowercase hexadecimal characters")?;
        let slot_secs: u64 = env_required("QUMBRA_PROVER_ANNULET_SLOT_SECS")?
            .parse()
            .map_err(|_| "QUMBRA_PROVER_ANNULET_SLOT_SECS is invalid".to_string())?;
        if !(1..=600).contains(&slot_secs) {
            return Err("QUMBRA_PROVER_ANNULET_SLOT_SECS must be between 1 and 600".into());
        }
        let queue_capacity = parse_env_or("QUMBRA_PROVER_ANNULET_QUEUE", 3usize)?;
        if !(1..=MAX_ANNULET_QUEUE).contains(&queue_capacity) {
            return Err(format!(
                "QUMBRA_PROVER_ANNULET_QUEUE must be between 1 and {MAX_ANNULET_QUEUE}"
            ));
        }
        let timeout = parse_env_or("QUMBRA_PROVER_ANNULET_TIMEOUT_SECS", 300u64)?;
        if !(30..=1800).contains(&timeout) {
            return Err("QUMBRA_PROVER_ANNULET_TIMEOUT_SECS must be between 30 and 1800".into());
        }
        let ttl = parse_env_or("QUMBRA_PROVER_ANNULET_RESULT_TTL_SECS", 600u64)?;
        if !(60..=3600).contains(&ttl) {
            return Err("QUMBRA_PROVER_ANNULET_RESULT_TTL_SECS must be between 60 and 3600".into());
        }
        let per_day_default = parse_env_or("QUMBRA_PROVER_ANNULET_PER_DAY", DEFAULT_PER_DAY)?;
        if !(1..=1000).contains(&per_day_default) {
            return Err("QUMBRA_PROVER_ANNULET_PER_DAY must be between 1 and 1000".into());
        }
        let plain_ack = std::env::var(ANNULET_PLAIN_HTTP_VAR).ok();
        let node_url = annulet_node_url(
            "QUMBRA_PROVER_ANNULET_NODE_URL",
            &env_required("QUMBRA_PROVER_ANNULET_NODE_URL")?,
            plain_ack.as_deref(),
        )?;
        let relay_url = match std::env::var("QUMBRA_PROVER_ANNULET_RELAY_URL") {
            Ok(url) => Some(annulet_node_url(
                "QUMBRA_PROVER_ANNULET_RELAY_URL",
                &url,
                plain_ack.as_deref(),
            )?),
            Err(_) => None,
        };
        let scratch = PathBuf::from(env_required("QUMBRA_PROVER_SCRATCH")?);
        scratch_is_tmpfs(&scratch)?;
        let keys_file = env_required("QUMBRA_PROVER_TOKEN_KEYS_FILE")?;
        let mut tokens = TokenKeys::parse(
            &std::fs::read_to_string(&keys_file)
                .map_err(|_| "QUMBRA_PROVER_TOKEN_KEYS_FILE could not be read".to_string())?,
        )?;
        let deny_file = std::env::var_os("QUMBRA_PROVER_TOKEN_DENY_FILE").map(PathBuf::from);
        if let Some(path) = &deny_file {
            tokens
                .set_denied(&std::fs::read_to_string(path).map_err(|_| {
                    "QUMBRA_PROVER_TOKEN_DENY_FILE could not be read".to_string()
                })?)?;
        }
        Ok(Some(Self {
            genesis_hash,
            slot_secs,
            queue_capacity,
            prove_timeout: Duration::from_secs(timeout),
            result_ttl: Duration::from_secs(ttl),
            per_day_default,
            node_url,
            relay_url,
            scratch,
            tokens,
            deny_file,
        }))
    }

    /// The net a bundle must verify on.
    pub fn auth_context(&self) -> AuthContext {
        AuthContext::candidate_a(self.genesis_hash)
    }

    /// The validity a client should sign with so its transaction can still
    /// land after the worst wait here: every queued job and the running one
    /// at the full timeout, then submission — in blocks, rounded up.
    pub fn recommended_valid_for_blocks(&self) -> u64 {
        let worst =
            (self.queue_capacity as u64 + 1) * self.prove_timeout.as_secs() + SUBMIT_SLACK_SECS;
        worst.div_ceil(self.slot_secs)
    }
}

/// The scratch directory must be on tmpfs: a proof's working memory never
/// reaches a disk.
#[cfg(target_os = "linux")]
pub fn scratch_is_tmpfs(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "QUMBRA_PROVER_SCRATCH is not a path".to_string())?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` a zeroed, owned
    // `statfs` the call writes into.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err("QUMBRA_PROVER_SCRATCH does not exist".into());
    }
    if st.f_type as i64 != TMPFS_MAGIC {
        return Err("QUMBRA_PROVER_SCRATCH must be a tmpfs mount".into());
    }
    Ok(())
}

/// Off Linux there is no tmpfs to prove the scratch is on: the Annulet mode
/// does not start.
#[cfg(not(target_os = "linux"))]
pub fn scratch_is_tmpfs(_: &std::path::Path) -> Result<(), String> {
    let _ = TMPFS_MAGIC;
    Err("the Annulet mode runs on Linux only (QUMBRA_PROVER_SCRATCH must be a tmpfs mount)".into())
}

// ------------------------------------------------------------- the seams

/// Proves a checked bundle: the proved transaction's Annulet wire bytes, or
/// a fixed code.
pub trait AnnuletProver: Send + Sync + 'static {
    fn prove(&self, bundle: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, &'static str>;
}

/// Hands a proved transaction to the network.
pub trait Submitter: Send + Sync + 'static {
    /// `POST /v1/tx` to the pinned node. `Err` is a fixed or sanitized code.
    fn submit(&self, wire: &[u8]) -> Result<(), String>;
    /// The relay, best-effort.
    fn relay(&self, wire: &[u8]) -> Result<(), String>;
}

/// The node and relay over HTTP(S), the wallet's own transport.
pub struct HttpSubmitter {
    pub node_url: String,
    pub relay_url: Option<String>,
}

impl HttpSubmitter {
    fn post(url: &str, wire: &[u8]) -> Result<(), String> {
        match qumbra_wallet::net::http_post_bytes(url, "/v1/tx", wire) {
            Ok((202 | 200, _)) => Ok(()),
            Ok((_, body)) => Err(format!("node-refused:{}", sanitize(&body))),
            Err(_) => Err("node-unreachable".into()),
        }
    }
}

impl Submitter for HttpSubmitter {
    fn submit(&self, wire: &[u8]) -> Result<(), String> {
        Self::post(&self.node_url, wire)
    }
    fn relay(&self, wire: &[u8]) -> Result<(), String> {
        match &self.relay_url {
            Some(url) => Self::post(url, wire).map_err(|_| "relay-failed".into()),
            None => Ok(()),
        }
    }
}

/// The first 48 of the node's answer, lowercase letters, digits and `-:_`
/// only: a refusal code, never echoed text.
fn sanitize(body: &[u8]) -> String {
    let s: String = body
        .iter()
        .map(|b| b.to_ascii_lowercase() as char)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '_' | ' '))
        .take(48)
        .collect();
    let s = s.trim().replace(' ', "-");
    if s.is_empty() {
        "unnamed".into()
    } else {
        s
    }
}

// ------------------------------------------------------------- the API

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnnuletJobView {
    pub protocol_version: u32,
    pub job_url: String,
    pub state: &'static str,
    pub queue_position: Option<usize>,
    pub tx_id: Option<String>,
    pub refusal: Option<String>,
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InfoView {
    pub protocol_version: u32,
    pub genesis_format: u32,
    pub genesis_hash: String,
    pub shapes: [&'static str; 2],
    pub d_auth: usize,
    pub max_bundle_bytes: usize,
    pub queue_capacity: usize,
    pub prove_timeout_secs: u64,
    pub slot_secs: u64,
    pub recommended_valid_for_blocks: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QuotaView {
    pub per_day: u16,
    pub used_today: u16,
    pub in_flight: bool,
}

enum Phase {
    Queued,
    Proving,
    Submitting,
    Submitted(Hash32),
    Refused(&'static str),
    Failed(String),
    Cancelled,
}

impl Phase {
    fn terminal(&self) -> bool {
        matches!(
            self,
            Phase::Submitted(_) | Phase::Refused(_) | Phase::Failed(_) | Phase::Cancelled
        )
    }
}

struct Job {
    phase: Phase,
    updated: Instant,
    cancel: Arc<AtomicBool>,
    token_id: [u8; 16],
    shape: L2ShapeTag,
    bundle_bytes: usize,
    /// The bundle's transaction on the wire, proof empty: what the child's
    /// answer must equal but for the proof.
    tx_wire: Vec<u8>,
}

#[derive(Default)]
struct State {
    jobs: HashMap<String, Job>,
    by_intent: HashMap<Hash32, String>,
    usage: HashMap<[u8; 16], (u64, u16)>,
    /// The live queue: the dispatcher pulls from its front; a cancel takes
    /// its job out at once, so a cancelled job holds no slot (lab #924 F2).
    pending: VecDeque<WorkItem>,
    /// Tokens with an upload being read (one at a time per token).
    reading: HashSet<[u8; 16]>,
    refusals: BTreeMap<(String, &'static str), u64>,
}

impl State {
    fn in_flight(&self, token_id: &[u8; 16]) -> bool {
        self.jobs
            .values()
            .any(|j| j.token_id == *token_id && !j.phase.terminal())
    }
    fn used_today(&self, token_id: &[u8; 16], day: u64) -> u16 {
        match self.usage.get(token_id) {
            Some((d, used)) if *d == day => *used,
            _ => 0,
        }
    }
    fn refuse(&mut self, who: String, code: &'static str) {
        *self.refusals.entry((who, code)).or_default() += 1;
    }
    fn cleanup(&mut self, ttl: Duration) {
        self.jobs
            .retain(|_, j| !j.phase.terminal() || j.updated.elapsed() < ttl);
        let jobs = &self.jobs;
        self.by_intent.retain(|_, cap| jobs.contains_key(cap));
    }
}

struct WorkItem {
    cap: String,
    bundle: Vec<u8>,
    cancel: Arc<AtomicBool>,
}

/// The Annulet API: admission, jobs, the dispatcher.
#[derive(Clone)]
pub struct AnnuletApi {
    inner: Arc<Inner>,
}

struct Inner {
    config: Arc<AnnuletConfig>,
    tokens: RwLock<TokenKeys>,
    state: Arc<Mutex<State>>,
    work: Arc<Condvar>,
    now: fn() -> u64,
}

/// A token admitted to upload (steps 1–2 passed): it holds the token's one
/// reading slot until dropped, so a slow upload occupies its own token only.
pub struct Admission {
    claims: Claims,
    state: Arc<Mutex<State>>,
}

impl Admission {
    pub fn claims(&self) -> &Claims {
        &self.claims
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        lock(&self.state).reading.remove(&self.claims.token_id);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A token id's short log hash: abuse is visible per token, the token is not.
fn token_tag(token_id: &[u8; 16]) -> String {
    hex(&keccak256(&[b"qumbra:prover-token-log:v1", token_id])[..4])
}

fn err(status: u16, code: &'static str) -> ApiError {
    ApiError { status, code }
}

fn bundle_refusal(e: &BundleError) -> ApiError {
    match e {
        BundleError::Malformed(_) => err(400, "bundle-malformed"),
        BundleError::IssuerShape(_) => err(403, "issuer-shape"),
        BundleError::ProofPresent => err(422, "proof-present"),
        BundleError::AuthMissing => err(422, "auth-missing"),
        BundleError::StatementMismatch(_) => err(422, "statement-mismatch"),
        BundleError::Unauthorized(_) => err(422, "unauthorized-section"),
    }
}

impl AnnuletApi {
    pub fn new(
        config: AnnuletConfig,
        prover: Arc<dyn AnnuletProver>,
        submitter: Arc<dyn Submitter>,
    ) -> Self {
        Self::with_clock(config, prover, submitter, unix_now)
    }

    /// [`Self::new`] with an explicit unix clock (tests).
    pub fn with_clock(
        mut config: AnnuletConfig,
        prover: Arc<dyn AnnuletProver>,
        submitter: Arc<dyn Submitter>,
        now: fn() -> u64,
    ) -> Self {
        let tokens = std::mem::take(&mut config.tokens);
        let config = Arc::new(config);
        let work = Arc::new(Condvar::new());
        let state = Arc::new(Mutex::new(State::default()));
        let inner = Arc::new(Inner {
            config: Arc::clone(&config),
            tokens: RwLock::new(tokens),
            state: Arc::clone(&state),
            work: Arc::clone(&work),
            now,
        });
        let s = Arc::clone(&state);
        std::thread::Builder::new()
            .name("annulet-dispatch".into())
            .spawn(move || dispatch(s, work, prover, submitter))
            .expect("the Annulet dispatcher starts");
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new()
            .name("annulet-housekeeping".into())
            .spawn(move || housekeeping(weak))
            .expect("the Annulet housekeeping thread starts");
        Self { inner }
    }

    fn day(&self) -> u64 {
        (self.inner.now)() / 86_400
    }

    fn per_day(&self, claims: &Claims) -> u16 {
        if claims.per_day == 0 {
            self.inner.config.per_day_default
        } else {
            claims.per_day
        }
    }

    /// The token alone (step 1): signature, window, net, revocation.
    pub fn authorize_only(&self, authorization: Option<&str>) -> Result<Claims, ApiError> {
        let verdict = match authorization.and_then(|a| a.strip_prefix("Bearer ")) {
            None => Err("unauthorized"),
            Some(token) => {
                let tokens = self
                    .inner
                    .tokens
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                tokens.verify(token, &self.inner.config.genesis_hash, (self.inner.now)())
            }
        };
        verdict.map_err(|code| {
            lock(&self.inner.state).refuse("-".into(), code);
            err(401, code)
        })
    }

    /// **Steps 1–2**: the token, then its quota, its in-flight job and its
    /// one reading slot — before the body is read. The slot is held until
    /// the returned [`Admission`] drops.
    pub fn authorize(&self, authorization: Option<&str>) -> Result<Admission, ApiError> {
        let claims = self.authorize_only(authorization)?;
        let mut state = lock(&self.inner.state);
        state.cleanup(self.inner.config.result_ttl);
        if state.in_flight(&claims.token_id) || state.reading.contains(&claims.token_id) {
            state.refuse(token_tag(&claims.token_id), "token-busy");
            return Err(err(429, "token-busy"));
        }
        if state.used_today(&claims.token_id, self.day()) >= self.per_day(&claims) {
            state.refuse(token_tag(&claims.token_id), "quota-exhausted");
            return Err(err(429, "quota-exhausted"));
        }
        state.reading.insert(claims.token_id);
        Ok(Admission {
            claims,
            state: Arc::clone(&self.inner.state),
        })
    }

    /// Count a refusal the HTTP layer made after admission (`415`, `413`,
    /// an upload past its deadline) under the token's tag.
    pub fn count_refusal(&self, claims: &Claims, code: &'static str) {
        lock(&self.inner.state).refuse(token_tag(&claims.token_id), code);
    }

    /// **Steps 3–5 and the job**: the bundle's bytes (already bounded by the
    /// caller's read), decoded and checked, then queued.
    pub fn submit(
        &self,
        admission: &Admission,
        mut bundle: Vec<u8>,
    ) -> Result<(AnnuletJobView, bool), ApiError> {
        let claims = &admission.claims;
        let who = token_tag(&claims.token_id);
        let refuse = |e: ApiError| {
            lock(&self.inner.state).refuse(who.clone(), e.code);
            e
        };
        if bundle.is_empty() || bundle.len() > MAX_ANNULET_BUNDLE_BYTES {
            bundle.zeroize();
            return Err(refuse(err(413, "bundle-too-large")));
        }
        let checked = ProvingBundle::decode(&bundle).and_then(|b| {
            b.check(&self.inner.config.auth_context())
                .map(|intent| (b, intent))
        });
        let (parsed, intent) = match checked {
            Ok(x) => x,
            Err(e) => {
                bundle.zeroize();
                return Err(refuse(bundle_refusal(&e)));
            }
        };
        let tx_wire = qlab_p2p::codec::encode_tx_annulet(parsed.tx());
        let shape = parsed.shape();
        drop(parsed); // its witness is wiped on drop

        let mut state = lock(&self.inner.state);
        let ttl = self.inner.config.result_ttl;
        state.cleanup(ttl);
        if let Some(cap) = state.by_intent.get(&intent).cloned() {
            let job = state
                .jobs
                .get(&cap)
                .expect("by_intent points at retained jobs");
            if job.token_id != claims.token_id {
                drop(state);
                bundle.zeroize();
                return Err(refuse(err(409, "intent-in-flight")));
            }
            if matches!(
                job.phase,
                Phase::Refused(_) | Phase::Failed(_) | Phase::Cancelled
            ) {
                // A retry of a job that ended without a transaction.
                state.jobs.remove(&cap);
                state.by_intent.remove(&intent);
            } else {
                bundle.zeroize();
                return Ok((view(&cap, job, &state.pending, ttl), false));
            }
        }
        // The race between `authorize` and here: re-check under the lock.
        if state.in_flight(&claims.token_id) {
            state.refuse(who, "token-busy");
            bundle.zeroize();
            return Err(err(429, "token-busy"));
        }
        let day = self.day();
        let used = state.used_today(&claims.token_id, day);
        if used >= self.per_day(claims) {
            state.refuse(who, "quota-exhausted");
            bundle.zeroize();
            return Err(err(429, "quota-exhausted"));
        }
        if state.jobs.len() >= MAX_ANNULET_JOBS {
            state.refuse(who, "retained-job-limit");
            bundle.zeroize();
            return Err(err(503, "retained-job-limit"));
        }
        // Live queued jobs only: a cancelled one has already left.
        if state.pending.len() >= self.inner.config.queue_capacity {
            state.refuse(who, "prover-busy");
            bundle.zeroize();
            return Err(err(503, "prover-busy"));
        }
        let cap = loop {
            let mut b = [0u8; 32];
            // The capability straight from the OS, not a userspace generator.
            if rand::rngs::SysRng.try_fill_bytes(&mut b).is_err() {
                bundle.zeroize();
                return Err(err(503, "entropy-unavailable"));
            }
            let c = hex(&b);
            if !state.jobs.contains_key(&c) {
                break c;
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let bundle_bytes = bundle.len();
        state.pending.push_back(WorkItem {
            cap: cap.clone(),
            bundle,
            cancel: Arc::clone(&cancel),
        });
        self.inner.work.notify_one();
        state.jobs.insert(
            cap.clone(),
            Job {
                phase: Phase::Queued,
                updated: Instant::now(),
                cancel,
                token_id: claims.token_id,
                shape,
                bundle_bytes,
                tx_wire,
            },
        );
        state.by_intent.insert(intent, cap.clone());
        state.usage.insert(claims.token_id, (day, used + 1));
        let job = state.jobs.get(&cap).expect("just inserted");
        Ok((view(&cap, job, &state.pending, ttl), true))
    }

    /// A job by its capability.
    pub fn get(&self, cap: &str) -> Result<AnnuletJobView, ApiError> {
        valid_cap(cap)?;
        let mut state = lock(&self.inner.state);
        state.cleanup(self.inner.config.result_ttl);
        let job = state.jobs.get(cap).ok_or(err(404, "job-not-found"))?;
        Ok(view(cap, job, &state.pending, self.inner.config.result_ttl))
    }

    /// Cancel a queued or proving job; a submitting or finished one is left
    /// as it is.
    pub fn cancel(&self, cap: &str) -> Result<AnnuletJobView, ApiError> {
        valid_cap(cap)?;
        let mut state = lock(&self.inner.state);
        state.cleanup(self.inner.config.result_ttl);
        let job = state.jobs.get_mut(cap).ok_or(err(404, "job-not-found"))?;
        if matches!(job.phase, Phase::Queued | Phase::Proving) {
            job.cancel.store(true, Ordering::Release);
            job.phase = Phase::Cancelled;
            job.updated = Instant::now();
        }
        // A queued job leaves the queue now, freeing its slot.
        if let Some(i) = state.pending.iter().position(|w| w.cap == cap) {
            if let Some(mut item) = state.pending.remove(i) {
                item.bundle.zeroize();
            }
        }
        let job = state.jobs.get(cap).expect("present");
        Ok(view(cap, job, &state.pending, self.inner.config.result_ttl))
    }

    /// The service's pins and sizing, for a client to check before it uploads.
    pub fn info(&self) -> InfoView {
        let c = &self.inner.config;
        InfoView {
            protocol_version: ANNULET_PROTOCOL_VERSION,
            genesis_format: c.auth_context().genesis_format(),
            genesis_hash: hex(&c.genesis_hash),
            shapes: ["S", "P"],
            d_auth: qlab_air::l2::D_AUTH,
            max_bundle_bytes: MAX_ANNULET_BUNDLE_BYTES,
            queue_capacity: c.queue_capacity,
            prove_timeout_secs: c.prove_timeout.as_secs(),
            slot_secs: c.slot_secs,
            recommended_valid_for_blocks: c.recommended_valid_for_blocks(),
        }
    }

    /// A token's standing today (the token already verified).
    pub fn quota(&self, claims: &Claims) -> QuotaView {
        let state = lock(&self.inner.state);
        QuotaView {
            per_day: self.per_day(claims),
            used_today: state.used_today(&claims.token_id, self.day()),
            in_flight: state.in_flight(&claims.token_id),
        }
    }

    /// The refusal counters since the last drain: `(token tag or "-", code)`.
    pub fn drain_refusals(&self) -> Vec<((String, &'static str), u64)> {
        std::mem::take(&mut lock(&self.inner.state).refusals)
            .into_iter()
            .collect()
    }
}

fn valid_cap(cap: &str) -> Result<(), ApiError> {
    if cap.len() == 64
        && cap
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(err(404, "job-not-found"))
    }
}

fn view(cap: &str, job: &Job, queue: &VecDeque<WorkItem>, ttl: Duration) -> AnnuletJobView {
    let (state, tx_id, refusal) = match &job.phase {
        Phase::Queued => ("queued", None, None),
        Phase::Proving => ("proving", None, None),
        Phase::Submitting => ("submitting", None, None),
        Phase::Submitted(id) => ("submitted", Some(hex(id)), None),
        Phase::Refused(code) => ("refused", None, Some((*code).to_string())),
        Phase::Failed(code) => ("failed", None, Some(code.clone())),
        Phase::Cancelled => ("cancelled", None, None),
    };
    AnnuletJobView {
        protocol_version: ANNULET_PROTOCOL_VERSION,
        job_url: format!("/v2/annulet/jobs/{cap}"),
        state,
        queue_position: queue.iter().position(|w| w.cap == cap).map(|i| i + 1),
        tx_id,
        refusal,
        expires_in_secs: job
            .phase
            .terminal()
            .then(|| ttl.saturating_sub(job.updated.elapsed()).as_secs()),
    }
}

/// The child's answer must be the bundle's transaction with a proof added
/// and nothing else: decoded on this net's wire, a non-empty proof, every
/// other byte the bundle's.
pub fn proof_added(bundle_tx_wire: &[u8], proved_wire: &[u8]) -> Result<TxEntry, &'static str> {
    let tx = qlab_p2p::codec::decode_tx_annulet_with(proved_wire, L2AuthForm::CandidateA)
        .map_err(|_| "proof-mismatch")?;
    if tx.proof.is_empty()
        || tx.rider != qlab_devnet::names::RIDER_ABSENT
        || tx.l2 == qlab_devnet::annulet::L2_SURFACE_ABSENT
    {
        return Err("proof-mismatch");
    }
    // The bytes submitted are exactly the canonical encoding of what decoded.
    if qlab_p2p::codec::encode_tx_annulet(&tx) != proved_wire {
        return Err("proof-mismatch");
    }
    let mut stripped = tx.clone();
    stripped.proof = Vec::new();
    if qlab_p2p::codec::encode_tx_annulet(&stripped) != bundle_tx_wire {
        return Err("proof-mismatch");
    }
    Ok(tx)
}

fn dispatch(
    state: Arc<Mutex<State>>,
    work: Arc<Condvar>,
    prover: Arc<dyn AnnuletProver>,
    submitter: Arc<dyn Submitter>,
) {
    loop {
        let queued_at;
        let mut item;
        {
            let mut s = lock(&state);
            item = loop {
                if let Some(next) = s.pending.pop_front() {
                    break next;
                }
                s = work
                    .wait(s)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            };
            let Some(job) = s.jobs.get_mut(&item.cap) else {
                item.bundle.zeroize();
                continue;
            };
            if item.cancel.load(Ordering::Acquire) {
                item.bundle.zeroize();
                continue;
            }
            queued_at = job.updated;
            job.phase = Phase::Proving;
            job.updated = Instant::now();
        }
        let started = Instant::now();
        let outcome = prover.prove(&item.bundle, &item.cancel);
        item.bundle.zeroize();
        let prove_ms = started.elapsed().as_millis();

        let (shape, bundle_bytes, expected) = {
            let s = lock(&state);
            let Some(job) = s.jobs.get(&item.cap) else {
                continue;
            };
            (job.shape, job.bundle_bytes, job.tx_wire.clone())
        };
        let finish = |phase: Phase, artifact: usize| {
            let code = match &phase {
                Phase::Submitted(_) => "submitted".to_string(),
                Phase::Refused(c) => (*c).to_string(),
                Phase::Failed(c) => c.clone(),
                Phase::Cancelled => "cancelled".into(),
                _ => "unfinished".into(),
            };
            eprintln!(
                "qumbra-prover-service: annulet job {}: shape={shape:?} bundle={bundle_bytes}B tx={artifact}B wait={}ms \
                 prove={prove_ms}ms outcome={code}",
                &item.cap[..8],
                started.duration_since(queued_at).as_millis(),
            );
            let mut s = lock(&state);
            if let Some(job) = s.jobs.get_mut(&item.cap) {
                if !matches!(job.phase, Phase::Cancelled) || matches!(phase, Phase::Submitted(_)) {
                    job.phase = phase;
                }
                job.updated = Instant::now();
            }
        };
        if item.cancel.load(Ordering::Acquire) {
            finish(Phase::Cancelled, 0);
            continue;
        }
        let wire = match outcome {
            Ok(w) => w,
            Err("bundle-refused") => {
                finish(Phase::Refused("bundle-refused"), 0);
                continue;
            }
            Err(code) => {
                finish(Phase::Failed(code.into()), 0);
                continue;
            }
        };
        let tx = match proof_added(&expected, &wire) {
            Ok(tx) => tx,
            Err(code) => {
                finish(Phase::Failed(code.into()), wire.len());
                continue;
            }
        };
        {
            let mut s = lock(&state);
            match s.jobs.get_mut(&item.cap) {
                Some(job) if !item.cancel.load(Ordering::Acquire) => {
                    job.phase = Phase::Submitting;
                    job.updated = Instant::now();
                }
                _ => {
                    drop(s);
                    finish(Phase::Cancelled, wire.len());
                    continue;
                }
            }
        }
        let phase = match submitter.submit(&wire) {
            Ok(()) => {
                let _ = submitter.relay(&wire);
                Phase::Submitted(qlab_p2p::codec::tx_id(&tx))
            }
            Err(code) => Phase::Failed(code),
        };
        finish(phase, wire.len());
    }
}

/// Every second: drop expired jobs. Every minute: log the refusal counters
/// and reload the deny list.
fn housekeeping(inner: std::sync::Weak<Inner>) {
    let mut tick = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let Some(inner) = inner.upgrade() else { return };
        lock(&inner.state).cleanup(inner.config.result_ttl);
        tick += 1;
        if !tick.is_multiple_of(60) {
            continue;
        }
        let counts = std::mem::take(&mut lock(&inner.state).refusals);
        if !counts.is_empty() {
            let line: Vec<String> = counts
                .iter()
                .map(|((who, code), n)| format!("{who}:{code}={n}"))
                .collect();
            eprintln!(
                "qumbra-prover-service: annulet admission refusals (60 s): {}",
                line.join(" ")
            );
        }
        if let Some(path) = &inner.config.deny_file {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let mut tokens = inner.tokens.write().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Err(e) = tokens.set_denied(&text) {
                        eprintln!("qumbra-prover-service: the token deny file was not reloaded: {e}");
                    }
                }
                Err(_) => eprintln!("qumbra-prover-service: the token deny file could not be read; keeping the last list"),
            }
        }
    }
}

// ------------------------------------------------------------- the child

/// Proves in a fresh child process: `executable annulet-worker`, the
/// environment cleared but for the protocol tag and the net, no URL, no
/// token; core dumps off; cwd and `TMPDIR` the tmpfs scratch; stderr closed.
pub struct AnnuletProcessProver {
    pub executable: PathBuf,
    pub genesis_hash: Hash32,
    pub scratch: PathBuf,
    pub timeout: Duration,
}

impl AnnuletProver for AnnuletProcessProver {
    fn prove(&self, bundle: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, &'static str> {
        let mut command = Command::new(&self.executable);
        command
            .arg("annulet-worker")
            .env_clear()
            .env("QUMBRA_PROVER_WORKER_PROTOCOL", ANNULET_WORKER_PROTOCOL)
            .env(
                "QUMBRA_PROVER_ANNULET_GENESIS_HASH",
                hex(&self.genesis_hash),
            )
            .env("TMPDIR", &self.scratch)
            .current_dir(&self.scratch)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        no_core_dumps(&mut command);
        let mut child = command.spawn().map_err(|_| "worker-spawn-failed")?;
        // The bundle (≤ 80 KiB) can exceed a pipe's buffer: write it from
        // its own thread so the timeout below covers a child that stalls
        // before reading.
        let Some(mut stdin) = child.stdin.take() else {
            terminate(&mut child);
            return Err("worker-input-failed");
        };
        let mut input = Vec::with_capacity(4 + bundle.len());
        input.extend_from_slice(&(bundle.len() as u32).to_le_bytes());
        input.extend_from_slice(bundle);
        let writer = std::thread::spawn(move || {
            let ok = stdin.write_all(&input).and_then(|()| stdin.flush()).is_ok();
            input.zeroize();
            ok
        });
        let Some(stdout) = child.stdout.take() else {
            terminate(&mut child);
            let _ = writer.join();
            return Err("worker-output-missing");
        };
        let reader = std::thread::spawn(move || read_framed(stdout));
        let started = Instant::now();
        loop {
            if cancel.load(Ordering::Acquire) {
                terminate(&mut child);
                let _ = reader.join();
                return Err("cancelled");
            }
            if started.elapsed() >= self.timeout {
                terminate(&mut child);
                let _ = reader.join();
                return Err("worker-timeout");
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !writer.join().unwrap_or(false) {
                        let _ = reader.join();
                        return Err("worker-input-failed");
                    }
                    let out = reader.join().map_err(|_| "worker-output-invalid")?;
                    return match (status.success(), out) {
                        (true, Ok((0, payload))) => Ok(payload),
                        (true, Ok((1, code))) => Err(worker_code(&code)),
                        _ => Err("worker-failed"),
                    };
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => {
                    terminate(&mut child);
                    let _ = reader.join();
                    return Err("worker-wait-failed");
                }
            }
        }
    }
}

/// `ulimit -c 0` for the child, set between fork and exec. (Not-dumpable
/// does not survive `execve` — the kernel resets it for a non-setuid exec —
/// so the child sets that itself, first thing: [`harden_process`].)
#[cfg(unix)]
fn no_core_dumps(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the forked child before exec and calls only
    // `setrlimit`, async-signal-safe, allocating nothing.
    unsafe {
        command.pre_exec(|| {
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn no_core_dumps(_: &mut Command) {}

/// **This process holds witnesses**: no core file, and on Linux not
/// dumpable — no same-uid `ptrace`, no readable `/proc/<pid>/mem`. Called
/// by the server at startup and by the worker child before it reads its
/// bundle (lab #924 F1).
pub fn harden_process() -> Result<(), String> {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a plain syscall on a stack value.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
            return Err("RLIMIT_CORE could not be set to 0".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a plain syscall; PR_SET_DUMPABLE takes no pointer.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err("PR_SET_DUMPABLE could not be cleared".into());
        }
    }
    Ok(())
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// The child's answer: kind (0 = the proved tx, 1 = a code), u32 length,
/// payload — the length checked against the kind's ceiling before any
/// allocation, and nothing after it.
pub fn read_framed(mut out: impl Read) -> Result<(u8, Vec<u8>), &'static str> {
    let mut head = [0u8; 5];
    out.read_exact(&mut head)
        .map_err(|_| "worker-output-torn")?;
    let len = u32::from_le_bytes(head[1..5].try_into().expect("4 bytes")) as usize;
    let limit = match head[0] {
        0 => MAX_ANNULET_TX_BYTES,
        1 => 64,
        _ => return Err("worker-output-kind-unknown"),
    };
    if len > limit {
        return Err("worker-output-too-large");
    }
    let mut payload = vec![0u8; len];
    out.read_exact(&mut payload)
        .map_err(|_| "worker-output-torn")?;
    let mut extra = [0u8; 1];
    if out
        .read(&mut extra)
        .map_err(|_| "worker-output-unreadable")?
        != 0
    {
        return Err("worker-output-trailing");
    }
    Ok((head[0], payload))
}

/// The child's codes: an allowlist, never passed-through text.
fn worker_code(code: &[u8]) -> &'static str {
    match code {
        b"bundle-refused" => "bundle-refused",
        b"proof-refused" => "proof-refused",
        b"worker-protocol-refused" => "worker-protocol-refused",
        _ => "worker-error-unknown",
    }
}

/// **The child**: read one framed bundle from `input`, decode and prove it
/// on the net `genesis_hash` names ([`ProvingBundle::prove`] runs the lock
/// again), answer the proved transaction's wire bytes. No network, no file.
pub fn annulet_worker_once(
    mut input: impl Read,
    genesis_hash: &Hash32,
) -> Result<Vec<u8>, &'static str> {
    let mut len = [0u8; 4];
    input
        .read_exact(&mut len)
        .map_err(|_| "worker-protocol-refused")?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_ANNULET_BUNDLE_BYTES {
        return Err("bundle-refused");
    }
    let mut raw = vec![0u8; len];
    input.read_exact(&mut raw).map_err(|_| "bundle-refused")?;
    let bundle = ProvingBundle::decode(&raw);
    raw.zeroize();
    let bundle = bundle.map_err(|_| "bundle-refused")?;
    // The server checked this bundle before queueing it; a refusal here is
    // the same lock on the same bytes, so it is the bundle's, by name.
    let tx = bundle
        .prove(&AuthContext::candidate_a(*genesis_hash))
        .map_err(|_| "bundle-refused")?;
    drop(bundle); // its witness is wiped on drop
    let wire = qlab_p2p::codec::encode_tx_annulet(&tx);
    if wire.len() > MAX_ANNULET_TX_BYTES {
        return Err("proof-refused");
    }
    Ok(wire)
}

/// Frame an answer for [`read_framed`].
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
#[path = "annulet_tests.rs"]
mod tests;
