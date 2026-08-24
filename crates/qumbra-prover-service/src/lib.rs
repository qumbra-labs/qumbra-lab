//! Mechanics-only shared proving service.
//!
//! This crate deliberately serves the current [`qumbra_wallet::bundle::WitnessBundle`]
//! only behind an explicit valueless-experiment acknowledgement. That bundle is
//! spend authority under today's transaction format: Candidate A is not yet bound
//! into the AIR, transaction wire, or node verifier. Accepting a research signature
//! beside it would not change that fact, so this API does not pretend otherwise.
//!
//! The service never submits a transaction. It authenticates before reading an
//! upload, applies byte ceilings, pins network facts and read-only endpoints in
//! operator configuration, admits work through a bounded in-memory channel, and
//! runs every proof in a fresh child process. Results are capability-addressed,
//! short-lived, and kept only in memory.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_wallet::uri::{b64url_decode, b64url_encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: u32 = 1;
pub const SERVICE_MODE: &str = "valueless-current-witness-v1";
pub const EXPERIMENT_ACK: &str = "VALUELESS_ONLY_CURRENT_WITNESS_BUNDLE_IS_SPEND_AUTHORITY";
pub const STARTUP_ACK: &str = "I_UNDERSTAND_THIS_CANNOT_CARRY_REAL_VALUE";

/// A current bundle is normally only a few KiB. This provisional experiment
/// cap is intentionally much lower than the old 64/128 MiB transport caps.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024;
/// JSON plus unpadded base64url overhead and fixed request metadata.
pub const MAX_REQUEST_BYTES: usize = 96 * 1024;
/// Matches the node's measured 2x2 transaction-wire admission ceiling.
pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
pub const MAX_RETAINED_JOBS: usize = 64;
pub const MAX_QUEUE_CAPACITY: usize = 8;
pub const DEFAULT_MAX_UPSTREAM_BYTES: usize = 8 * 1024 * 1024;
pub const MIN_MAX_UPSTREAM_BYTES: usize = 64 * 1024;
pub const MAX_MAX_UPSTREAM_BYTES: usize = 64 * 1024 * 1024;

const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 256;
const MIN_IDEMPOTENCY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_BYTES: usize = 64;
const NON_LOOPBACK_ACK: &str = "I_UNDERSTAND_TLS_AND_RATE_LIMIT_LIVE_AT_INGRESS";
const INSECURE_NODE_HTTP_ACK: &str = "I_UNDERSTAND_NODE_HTTP_IS_PRIVATE_AND_VALUELESS";

pub fn build_revision() -> &'static str {
    option_env!("QUMBRA_BUILD_REV").unwrap_or("unstamped")
}

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ApiToken(Vec<u8>);

impl ApiToken {
    fn matches(&self, candidate: &[u8]) -> bool {
        bool::from(self.0.as_slice().ct_eq(candidate))
    }
}

impl Drop for ApiToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Fail-closed service configuration. Client requests never carry node URLs.
pub struct Config {
    pub listen: SocketAddr,
    pub scan_url: String,
    pub node_url: String,
    pub genesis_format: u32,
    pub genesis_hash: String,
    pub consensus_label: String,
    pub queue_capacity: usize,
    pub result_ttl: Duration,
    pub prove_timeout: Duration,
    pub max_upstream_bytes: usize,
    api_token: ApiToken,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        if env_required("QUMBRA_PROVER_VALUELESS_EXPERIMENT")? != STARTUP_ACK {
            return Err(format!(
                "QUMBRA_PROVER_VALUELESS_EXPERIMENT must equal {STARTUP_ACK}; refusing to start"
            ));
        }

        let listen_text =
            std::env::var("QUMBRA_PROVER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8087".to_string());
        let listen: SocketAddr = listen_text
            .parse()
            .map_err(|_| "QUMBRA_PROVER_LISTEN is not an IP socket address".to_string())?;
        if !listen.ip().is_loopback()
            && std::env::var("QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN").as_deref()
                != Ok(NON_LOOPBACK_ACK)
        {
            return Err(format!(
                "non-loopback listen requires QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN={NON_LOOPBACK_ACK}"
            ));
        }

        let insecure_http = std::env::var("QUMBRA_PROVER_ALLOW_INSECURE_NODE_HTTP").as_deref()
            == Ok(INSECURE_NODE_HTTP_ACK);
        let scan_url = validate_base_url(
            "QUMBRA_PROVER_SCAN_URL",
            &env_required("QUMBRA_PROVER_SCAN_URL")?,
            insecure_http,
        )?;
        let node_url = validate_base_url(
            "QUMBRA_PROVER_NODE_URL",
            &env_required("QUMBRA_PROVER_NODE_URL")?,
            insecure_http,
        )?;

        let genesis_format = parse_env("QUMBRA_PROVER_GENESIS_FORMAT")?;
        let genesis_hash = env_required("QUMBRA_PROVER_GENESIS_HASH")?;
        if genesis_hash.len() != 64
            || !genesis_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(
                "QUMBRA_PROVER_GENESIS_HASH must be exactly 64 lowercase hexadecimal characters"
                    .into(),
            );
        }
        let consensus_label = env_required("QUMBRA_PROVER_CONSENSUS_LABEL")?;
        if consensus_label.is_empty()
            || consensus_label.len() > 64
            || !consensus_label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(
                "QUMBRA_PROVER_CONSENSUS_LABEL must be 1..64 ASCII letters, digits, '.', '-' or '_'"
                    .into(),
            );
        }

        let queue_capacity = parse_env_or("QUMBRA_PROVER_QUEUE_CAPACITY", 1usize)?;
        if !(1..=MAX_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(format!(
                "QUMBRA_PROVER_QUEUE_CAPACITY must be between 1 and {MAX_QUEUE_CAPACITY}"
            ));
        }
        let ttl_secs = parse_env_or("QUMBRA_PROVER_RESULT_TTL_SECS", 600u64)?;
        if !(60..=3600).contains(&ttl_secs) {
            return Err("QUMBRA_PROVER_RESULT_TTL_SECS must be between 60 and 3600".into());
        }
        let prove_timeout_secs = parse_env_or("QUMBRA_PROVER_TIMEOUT_SECS", 300u64)?;
        if !(30..=1800).contains(&prove_timeout_secs) {
            return Err("QUMBRA_PROVER_TIMEOUT_SECS must be between 30 and 1800".into());
        }
        let max_upstream_bytes = parse_env_or(
            "QUMBRA_PROVER_MAX_UPSTREAM_BYTES",
            DEFAULT_MAX_UPSTREAM_BYTES,
        )?;
        if !(MIN_MAX_UPSTREAM_BYTES..=MAX_MAX_UPSTREAM_BYTES).contains(&max_upstream_bytes) {
            return Err(format!(
                "QUMBRA_PROVER_MAX_UPSTREAM_BYTES must be between {MIN_MAX_UPSTREAM_BYTES} and {MAX_MAX_UPSTREAM_BYTES}"
            ));
        }

        let api_token = read_api_token()?;
        Ok(Self {
            listen,
            scan_url,
            node_url,
            genesis_format,
            genesis_hash,
            consensus_label,
            queue_capacity,
            result_ttl: Duration::from_secs(ttl_secs),
            prove_timeout: Duration::from_secs(prove_timeout_secs),
            max_upstream_bytes,
            api_token: ApiToken(api_token),
        })
    }

    pub fn authorizes(&self, authorization: &str) -> bool {
        authorization
            .strip_prefix("Bearer ")
            .is_some_and(|candidate| self.api_token.matches(candidate.as_bytes()))
    }

    pub fn worker_config(&self) -> WorkerConfig {
        WorkerConfig {
            scan_url: self.scan_url.clone(),
            node_url: self.node_url.clone(),
            prove_timeout: self.prove_timeout,
            max_upstream_bytes: self.max_upstream_bytes,
        }
    }
}

pub struct WorkerConfig {
    pub scan_url: String,
    pub node_url: String,
    pub prove_timeout: Duration,
    pub max_upstream_bytes: usize,
}

fn read_api_token() -> Result<Vec<u8>, String> {
    let direct = std::env::var_os("QUMBRA_PROVER_API_TOKEN");
    let file = std::env::var_os("QUMBRA_PROVER_API_TOKEN_FILE");
    let mut token = match (direct, file) {
        (Some(_), Some(_)) => {
            return Err(
                "set exactly one of QUMBRA_PROVER_API_TOKEN or QUMBRA_PROVER_API_TOKEN_FILE".into(),
            )
        }
        (Some(value), None) => value.to_string_lossy().as_bytes().to_vec(),
        (None, Some(path)) => fs::read(PathBuf::from(path))
            .map_err(|_| "QUMBRA_PROVER_API_TOKEN_FILE could not be read".to_string())?,
        (None, None) => {
            return Err(
                "set QUMBRA_PROVER_API_TOKEN_FILE (preferred) or QUMBRA_PROVER_API_TOKEN".into(),
            )
        }
    };
    while token.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
        token.pop();
    }
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len()) {
        token.zeroize();
        return Err(format!(
            "prover API token must contain {MIN_TOKEN_BYTES}..={MAX_TOKEN_BYTES} bytes"
        ));
    }
    Ok(token)
}

fn validate_base_url(name: &str, value: &str, insecure_http: bool) -> Result<String, String> {
    let (scheme, authority) = value
        .split_once("://")
        .ok_or_else(|| format!("{name} must be an absolute https base URL"))?;
    if scheme != "https" && !(scheme == "http" && insecure_http) {
        return Err(format!(
            "{name} must use https; private valueless HTTP requires the exact insecure-node acknowledgement"
        ));
    }
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "{name} must contain only scheme and authority; paths, queries, fragments and userinfo are refused"
        ));
    }
    Ok(format!("{scheme}://{authority}"))
}

fn env_required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn parse_env<T>(name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    env_required(name)?
        .parse()
        .map_err(|_| format!("{name} is invalid"))
}

fn parse_env_or<T>(name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
{
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("{name} is invalid")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is invalid")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    pub protocol_version: u32,
    pub mode: String,
    pub experiment_ack: String,
    pub genesis_format: u32,
    pub genesis_hash: String,
    pub consensus_label: String,
    pub bundle_b64: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JobView {
    pub protocol_version: u32,
    pub job_id: String,
    pub state: String,
    pub artifact_b64: Option<String>,
    pub artifact_bytes: Option<usize>,
    pub artifact_hash: Option<String>,
    pub refusal: Option<String>,
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthView {
    pub alive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
}

impl ApiError {
    fn new(status: u16, code: &'static str) -> Self {
        Self { status, code }
    }
}

pub enum WorkerOutcome {
    Succeeded(SecretBytes),
    Refused(&'static str),
}

pub trait Worker: Send + Sync + 'static {
    fn prove(&self, bundle: SecretBytes, cancel: &AtomicBool) -> WorkerOutcome;
}

#[derive(Clone)]
pub struct Api {
    inner: Arc<ApiInner>,
}

struct ApiInner {
    config: Arc<Config>,
    state: Arc<Mutex<State>>,
    work: mpsc::SyncSender<WorkItem>,
}

struct State {
    jobs: HashMap<String, JobRecord>,
    idempotency: HashMap<String, (String, [u8; 32])>,
}

struct JobRecord {
    state: JobState,
    updated: Instant,
    cancel: Arc<AtomicBool>,
}

enum JobState {
    Queued,
    Running,
    Succeeded(SecretBytes),
    Refused(&'static str),
    Cancelled,
}

impl JobState {
    fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded(_) | Self::Refused(_) | Self::Cancelled
        )
    }
}

struct WorkItem {
    job_id: String,
    bundle: SecretBytes,
    cancel: Arc<AtomicBool>,
}

impl Api {
    pub fn new(config: Arc<Config>, worker: Arc<dyn Worker>) -> Self {
        let (work, receiver) = mpsc::sync_channel(config.queue_capacity);
        let state = Arc::new(Mutex::new(State {
            jobs: HashMap::new(),
            idempotency: HashMap::new(),
        }));
        let inner = Arc::new(ApiInner {
            config: Arc::clone(&config),
            state: Arc::clone(&state),
            work,
        });
        let dispatcher_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("prover-dispatch".into())
            .spawn(move || dispatch(dispatcher_state, receiver, worker))
            .expect("prover dispatcher thread starts");
        let cleanup_state = Arc::downgrade(&state);
        std::thread::Builder::new()
            .name("prover-retention".into())
            .spawn(move || retention_sweep(cleanup_state, config.result_ttl))
            .expect("prover retention thread starts");
        Self { inner }
    }

    pub fn submit(
        &self,
        idempotency_key: &str,
        mut request: SubmitRequest,
    ) -> Result<(JobView, bool), ApiError> {
        validate_idempotency_key(idempotency_key)?;
        self.validate_request(&request)?;
        if request.bundle_b64.len() > MAX_REQUEST_BYTES {
            request.bundle_b64.zeroize();
            return Err(ApiError::new(413, "bundle-too-large"));
        }
        let decoded = b64url_decode(&request.bundle_b64)
            .map_err(|_| ApiError::new(400, "bundle-base64-invalid"));
        request.bundle_b64.zeroize();
        let bundle = SecretBytes::new(decoded?);
        if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
            return Err(ApiError::new(413, "bundle-too-large"));
        }
        if !bundle
            .as_slice()
            .starts_with(qumbra_wallet::bundle::WITNESS_BUNDLE_MAGIC)
        {
            return Err(ApiError::new(400, "bundle-magic-invalid"));
        }
        let fingerprint = request_fingerprint(&request, bundle.as_slice());

        let mut state = lock(&self.inner.state);
        cleanup(&mut state, self.inner.config.result_ttl);
        if let Some((job_id, existing_fingerprint)) = state.idempotency.get(idempotency_key) {
            if *existing_fingerprint != fingerprint {
                return Err(ApiError::new(409, "idempotency-key-reused"));
            }
            let record = state
                .jobs
                .get(job_id)
                .expect("idempotency entries point at retained jobs");
            return Ok((
                job_view(job_id, record, self.inner.config.result_ttl),
                false,
            ));
        }
        if state.jobs.len() >= MAX_RETAINED_JOBS {
            return Err(ApiError::new(503, "retained-job-limit"));
        }

        let job_id = loop {
            let candidate = random_job_id();
            if !state.jobs.contains_key(&candidate) {
                break candidate;
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        state.jobs.insert(
            job_id.clone(),
            JobRecord {
                state: JobState::Queued,
                updated: Instant::now(),
                cancel: Arc::clone(&cancel),
            },
        );
        state
            .idempotency
            .insert(idempotency_key.to_string(), (job_id.clone(), fingerprint));
        let item = WorkItem {
            job_id: job_id.clone(),
            bundle,
            cancel,
        };
        match self.inner.work.try_send(item) {
            Ok(()) => {
                let record = state.jobs.get(&job_id).expect("new job retained");
                Ok((
                    job_view(&job_id, record, self.inner.config.result_ttl),
                    true,
                ))
            }
            Err(mpsc::TrySendError::Full(_)) => {
                state.jobs.remove(&job_id);
                state.idempotency.remove(idempotency_key);
                Err(ApiError::new(503, "prover-busy"))
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                state.jobs.remove(&job_id);
                state.idempotency.remove(idempotency_key);
                Err(ApiError::new(503, "prover-unavailable"))
            }
        }
    }

    pub fn get(&self, job_id: &str) -> Result<JobView, ApiError> {
        validate_job_id(job_id)?;
        let mut state = lock(&self.inner.state);
        cleanup(&mut state, self.inner.config.result_ttl);
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| ApiError::new(404, "job-not-found"))?;
        Ok(job_view(job_id, record, self.inner.config.result_ttl))
    }

    pub fn cancel(&self, job_id: &str) -> Result<JobView, ApiError> {
        validate_job_id(job_id)?;
        let mut state = lock(&self.inner.state);
        cleanup(&mut state, self.inner.config.result_ttl);
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| ApiError::new(404, "job-not-found"))?;
        if !record.state.terminal() {
            record.cancel.store(true, Ordering::Release);
            record.state = JobState::Cancelled;
            record.updated = Instant::now();
        }
        Ok(job_view(job_id, record, self.inner.config.result_ttl))
    }

    pub fn health(&self) -> HealthView {
        HealthView { alive: true }
    }

    fn validate_request(&self, request: &SubmitRequest) -> Result<(), ApiError> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(ApiError::new(400, "protocol-version-unsupported"));
        }
        if request.mode != SERVICE_MODE {
            return Err(ApiError::new(400, "mode-unsupported"));
        }
        if request.experiment_ack != EXPERIMENT_ACK {
            return Err(ApiError::new(400, "valueless-ack-required"));
        }
        if request.genesis_format != self.inner.config.genesis_format
            || request.genesis_hash != self.inner.config.genesis_hash
            || request.consensus_label != self.inner.config.consensus_label
        {
            return Err(ApiError::new(409, "network-pin-mismatch"));
        }
        Ok(())
    }
}

fn dispatch(state: Arc<Mutex<State>>, receiver: mpsc::Receiver<WorkItem>, worker: Arc<dyn Worker>) {
    while let Ok(item) = receiver.recv() {
        {
            let mut state = lock(&state);
            let Some(record) = state.jobs.get_mut(&item.job_id) else {
                continue;
            };
            if record.cancel.load(Ordering::Acquire) {
                record.state = JobState::Cancelled;
                record.updated = Instant::now();
                continue;
            }
            record.state = JobState::Running;
            record.updated = Instant::now();
        }

        let outcome = worker.prove(item.bundle, &item.cancel);
        let mut state = lock(&state);
        let Some(record) = state.jobs.get_mut(&item.job_id) else {
            continue;
        };
        record.state = if item.cancel.load(Ordering::Acquire) {
            JobState::Cancelled
        } else {
            match outcome {
                WorkerOutcome::Succeeded(artifact) => JobState::Succeeded(artifact),
                WorkerOutcome::Refused(code) => JobState::Refused(code),
            }
        };
        record.updated = Instant::now();
    }
}

fn retention_sweep(state: std::sync::Weak<Mutex<State>>, ttl: Duration) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let Some(state) = state.upgrade() else {
            return;
        };
        cleanup(&mut lock(&state), ttl);
    }
}

fn job_view(job_id: &str, record: &JobRecord, ttl: Duration) -> JobView {
    let (state, artifact_b64, artifact_bytes, artifact_hash, refusal) = match &record.state {
        JobState::Queued => ("queued", None, None, None, None),
        JobState::Running => ("running", None, None, None, None),
        JobState::Succeeded(artifact) => (
            "succeeded",
            Some(b64url_encode(artifact.as_slice())),
            Some(artifact.len()),
            Some(hex32(&keccak256(artifact.as_slice()))),
            None,
        ),
        JobState::Refused(code) => ("refused", None, None, None, Some((*code).to_string())),
        JobState::Cancelled => ("cancelled", None, None, None, None),
    };
    JobView {
        protocol_version: PROTOCOL_VERSION,
        job_id: job_id.to_string(),
        state: state.to_string(),
        artifact_b64,
        artifact_bytes,
        artifact_hash,
        refusal,
        expires_in_secs: record
            .state
            .terminal()
            .then(|| ttl.saturating_sub(record.updated.elapsed()).as_secs()),
    }
}

fn cleanup(state: &mut State, ttl: Duration) {
    state
        .jobs
        .retain(|_, job| !job.state.terminal() || job.updated.elapsed() < ttl);
    state
        .idempotency
        .retain(|_, (job_id, _)| state.jobs.contains_key(job_id));
}

fn validate_idempotency_key(key: &str) -> Result<(), ApiError> {
    if !(MIN_IDEMPOTENCY_BYTES..=MAX_IDEMPOTENCY_BYTES).contains(&key.len())
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
    {
        return Err(ApiError::new(400, "idempotency-key-invalid"));
    }
    Ok(())
}

fn validate_job_id(job_id: &str) -> Result<(), ApiError> {
    if job_id.len() != 64
        || !job_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ApiError::new(404, "job-not-found"));
    }
    Ok(())
}

fn request_fingerprint(request: &SubmitRequest, bundle: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(b"qumbra:prover-service:idempotency:v1");
    hasher.update(&request.protocol_version.to_le_bytes());
    hasher.update(request.mode.as_bytes());
    hasher.update(&request.genesis_format.to_le_bytes());
    hasher.update(request.genesis_hash.as_bytes());
    hasher.update(request.consensus_label.as_bytes());
    hasher.update(bundle);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn random_job_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex32(&bytes)
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct EchoWorker {
        calls: AtomicUsize,
    }

    impl Worker for EchoWorker {
        fn prove(&self, bundle: SecretBytes, cancel: &AtomicBool) -> WorkerOutcome {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if cancel.load(Ordering::Acquire) {
                return WorkerOutcome::Refused("cancelled");
            }
            WorkerOutcome::Succeeded(SecretBytes::new(bundle.as_slice()[..8].to_vec()))
        }
    }

    fn config() -> Arc<Config> {
        Arc::new(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            scan_url: "https://scan.invalid".into(),
            node_url: "https://node.invalid".into(),
            genesis_format: 5,
            genesis_hash: "11".repeat(32),
            consensus_label: "t2-b16-v1".into(),
            queue_capacity: 1,
            result_ttl: Duration::from_secs(60),
            prove_timeout: Duration::from_secs(30),
            max_upstream_bytes: DEFAULT_MAX_UPSTREAM_BYTES,
            api_token: ApiToken(vec![b'x'; 32]),
        })
    }

    fn request(byte: u8) -> SubmitRequest {
        let mut bundle = qumbra_wallet::bundle::WITNESS_BUNDLE_MAGIC.to_vec();
        bundle.extend_from_slice(&[byte; 64]);
        SubmitRequest {
            protocol_version: PROTOCOL_VERSION,
            mode: SERVICE_MODE.into(),
            experiment_ack: EXPERIMENT_ACK.into(),
            genesis_format: 5,
            genesis_hash: "11".repeat(32),
            consensus_label: "t2-b16-v1".into(),
            bundle_b64: b64url_encode(&bundle),
        }
    }

    #[test]
    fn idempotency_reuses_one_job_and_rejects_changed_payload() {
        let worker = Arc::new(EchoWorker {
            calls: AtomicUsize::new(0),
        });
        let api = Api::new(config(), worker);
        let (first, created) = api.submit("device-job-key-0001", request(1)).unwrap();
        assert!(created);
        let (same, created) = api.submit("device-job-key-0001", request(1)).unwrap();
        assert!(!created);
        assert_eq!(first.job_id, same.job_id);
        assert_eq!(
            api.submit("device-job-key-0001", request(2))
                .unwrap_err()
                .code,
            "idempotency-key-reused"
        );
    }

    #[test]
    fn network_and_valueless_ack_mismatches_fail_before_admission() {
        let worker = Arc::new(EchoWorker {
            calls: AtomicUsize::new(0),
        });
        let api = Api::new(config(), worker);
        let mut wrong = request(1);
        wrong.experiment_ack = "production".into();
        assert_eq!(
            api.submit("device-job-key-0002", wrong).unwrap_err().code,
            "valueless-ack-required"
        );
        let mut wrong = request(1);
        wrong.genesis_hash = "22".repeat(32);
        assert_eq!(
            api.submit("device-job-key-0003", wrong).unwrap_err().code,
            "network-pin-mismatch"
        );
    }

    #[test]
    fn capability_ids_and_authorization_are_strict() {
        let cfg = config();
        assert!(cfg.authorizes(&format!("Bearer {}", "x".repeat(32))));
        assert!(!cfg.authorizes(&format!("Bearer {}", "x".repeat(31))));
        assert!(!cfg.authorizes("Basic eA=="));
        let worker = Arc::new(EchoWorker {
            calls: AtomicUsize::new(0),
        });
        let api = Api::new(cfg, worker);
        assert_eq!(
            api.get("not-a-capability").unwrap_err().code,
            "job-not-found"
        );
    }

    #[test]
    fn request_limits_are_smaller_than_the_node_artifact_limit() {
        let bundle = std::hint::black_box(MAX_BUNDLE_BYTES);
        let request = std::hint::black_box(MAX_REQUEST_BYTES);
        let artifact = std::hint::black_box(MAX_ARTIFACT_BYTES);
        assert!(bundle < artifact);
        assert_eq!(artifact, 256 * 1024);
        assert!(request >= bundle * 4 / 3);
    }

    #[test]
    fn public_health_is_liveness_only() {
        let encoded = serde_json::to_string(&HealthView { alive: true }).unwrap();
        assert_eq!(encoded, r#"{"alive":true}"#);
    }
}
