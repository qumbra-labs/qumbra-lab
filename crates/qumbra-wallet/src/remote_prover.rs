//! **The remote-prove client** (lab #937 cut-over, D-C7 and D-C8): the Rust
//! twin of the extension's `ext/prover.js`, written once here so the macOS
//! bridge and the drill share it. On a format-34 net a wallet that does not
//! prove its own spend hands the **signed** bundle to a prover service, which
//! proves it, submits it to its node, and is paid by the transaction's third
//! output (asset 0, to the network's pinned payee —
//! [`crate::prover_pins::admit`]). No token, no account.
//!
//! The protocol (`docs/prover-service-annulet.md`, "Format 34"):
//! - `GET /v2/annulet/info` — the advertisement; its **raw bytes** go to
//!   [`crate::prover_pins::admit`] (never a re-serialization of them).
//! - `POST /v2/annulet/jobs` — the bundle; `202` (or `200`, the same intent's
//!   existing job) with the job's view, its `job_url` the capability.
//! - `GET <job_url>` — the job: `queued` / `proving` / `submitting` /
//!   `submitted` (with `tx_id`) / `failed` / `refused` / `cancelled`.
//!
//! **Retry semantics (D-C8).** A bundle is signed once and kept: it is
//! [`record`]ed **before** its first upload, so a crash between the take and
//! the answer leaves the very bytes to re-POST. The service keys a job by the
//! signed intent, so a byte-identical re-POST is idempotent.
//! - **Not now** — `429 ip-busy`, `503 prover-busy`, `503
//!   nullifiers-catching-up`, `503 nullifiers-stale`, a transport error (and
//!   any other 5xx, an ingress's 502/504 included); and a job that ended
//!   `failed` on the service's side (`worker-*`, `proof-mismatch`,
//!   `node-unreachable`) or `cancelled` — nothing landed, and the service
//!   releases such a job's nullifier claim and re-admits its intent (D-C8 as
//!   amended 2026-10-16): the same bytes are re-POSTed with backoff until the
//!   transaction's validity height has passed. No leaf is wasted.
//! - **Already ours in flight** — `409 nullifier-in-flight`, `409
//!   intent-in-flight`: this intent is already with the service (an earlier
//!   upload, perhaps from another address); the wallet waits and lets the
//!   scan settle it.
//! - **Definitive** — `400`, `402 prover-fee-*`, `403`, `409
//!   nullifier-landed`, `413`, `422`, any other 4xx; a job that ended
//!   `refused` (the worker's lock refused the bundle) or `failed` with
//!   `node-refused:…` (the node's refusal of these bytes is deterministic: a
//!   re-send only proves them again): the spend failed; its leaves stay used
//!   (the journal never rolls back) and a retry is a new take. A transaction
//!   that did land is caught on the re-send as `409 nullifier-landed`. The
//!   new take of the same note replaces the record, the old pair kept beside
//!   it ([`record`], lab #957).

use std::path::{Path, PathBuf};
use std::time::Duration;

use qlab_devnet::annulet::L2ShapeTag;

/// The protocol this client speaks (`ANNULET_PROTOCOL_VERSION`).
pub const PROTOCOL_VERSION: u64 = 1;
/// The longest `/v2/annulet/info` read (the kernel's own bound).
pub const MAX_INFO_BYTES: usize = 16 * 1024;
/// The longest job view or refusal read.
pub const MAX_VIEW_BYTES: usize = 8 * 1024;
/// The first wait before a not-now re-POST; doubled each time, to
/// [`MAX_BACKOFF`].
pub const FIRST_BACKOFF: Duration = Duration::from_secs(5);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// The wait between two reads of a live job.
pub const POLL_EVERY: Duration = Duration::from_secs(3);

/// One request to the prover service: `(status, body)`, every status a
/// payload; `Err` is a transport failure (not now).
pub trait ProverTransport {
    fn call(&mut self, method: &str, path: &str, body: Option<&[u8]>, max_bytes: usize) -> Result<(u16, Vec<u8>), String>;
}

/// The service at `base` (e.g. `https://annulet-prover.qumbra.org`), over
/// this crate's HTTP/1.1 + rustls.
#[cfg(feature = "net")]
pub struct HttpProver {
    pub base: String,
}

#[cfg(feature = "net")]
impl ProverTransport for HttpProver {
    fn call(&mut self, method: &str, path: &str, body: Option<&[u8]>, max_bytes: usize) -> Result<(u16, Vec<u8>), String> {
        crate::net::http_call(self.base.trim_end_matches('/'), method, path, body, max_bytes).map_err(|e| e.to_string())
    }
}

/// A job's state, as the service names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Proving,
    Submitting,
    Submitted,
    Failed,
    Refused,
    Cancelled,
}

impl JobState {
    fn parse(s: &str) -> Option<JobState> {
        Some(match s {
            "queued" => JobState::Queued,
            "proving" => JobState::Proving,
            "submitting" => JobState::Submitting,
            "submitted" => JobState::Submitted,
            "failed" => JobState::Failed,
            "refused" => JobState::Refused,
            "cancelled" => JobState::Cancelled,
            _ => return None,
        })
    }

    /// The job ended, one way or another.
    pub fn terminal(self) -> bool {
        matches!(self, JobState::Submitted | JobState::Failed | JobState::Refused | JobState::Cancelled)
    }
}

/// A job, as this client read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobView {
    /// `/v2/annulet/jobs/<64 hex>`: the capability. A secret — never logged.
    pub job_url: String,
    pub state: JobState,
    pub queue_position: Option<u64>,
    /// Set exactly when `state` is `Submitted`.
    pub tx_id: Option<[u8; 32]>,
    /// The service's refusal code (`[a-z0-9:-]`, ≤ 64), when it gave one.
    pub refusal: Option<String>,
}

fn is_code(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b':')
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn is_job_url(s: &str) -> bool {
    s.strip_prefix("/v2/annulet/jobs/").and_then(hex32).is_some()
}

/// Read a job view — refused by name unless it is this protocol's, its URL a
/// job capability, its state known, and a `submitted` one carries its id.
pub fn parse_job(bytes: &[u8]) -> Result<JobView, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "the job view is not JSON".to_string())?;
    if v.get("protocol_version").and_then(serde_json::Value::as_u64) != Some(PROTOCOL_VERSION) {
        return Err("the job view is not protocol 1".into());
    }
    let job_url = v.get("job_url").and_then(|u| u.as_str()).filter(|u| is_job_url(u)).ok_or("the job view has no job URL")?;
    let state = v
        .get("state")
        .and_then(|s| s.as_str())
        .and_then(JobState::parse)
        .ok_or("the job view names an unknown state")?;
    let tx_id = match v.get("tx_id").and_then(|t| t.as_str()) {
        Some(t) => Some(hex32(t).ok_or("the job's tx_id is not 64 hex")?),
        None => None,
    };
    if (state == JobState::Submitted) != tx_id.is_some() {
        return Err("the job's tx_id does not match its state".into());
    }
    let refusal = v.get("refusal").and_then(|r| r.as_str()).filter(|r| is_code(r)).map(str::to_string);
    let queue_position = v.get("queue_position").and_then(serde_json::Value::as_u64);
    Ok(JobView { job_url: job_url.to_string(), state, queue_position, tx_id, refusal })
}

/// The refusal code of a non-2xx answer (`{"error": code}`), or `unnamed`.
pub fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).filter(|c| is_code(c)).map(str::to_string))
        .unwrap_or_else(|| "unnamed".into())
}

/// What an upload's refusal means for the bundle (D-C8, module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Re-POST the same bytes later.
    NotNow { status: u16, code: String },
    /// This intent is already with the service: wait; the scan settles it.
    InFlight { code: String },
    /// The spend failed; a retry is a new take.
    Definitive { status: u16, code: String },
}

/// D-C8's table, by status and code.
pub fn classify(status: u16, code: &str) -> Verdict {
    let code = code.to_string();
    match (status, code.as_str()) {
        (429, _) => Verdict::NotNow { status, code },
        (409, "nullifier-in-flight" | "intent-in-flight") => Verdict::InFlight { code },
        (500..=599, _) => Verdict::NotNow { status, code },
        _ => Verdict::Definitive { status, code },
    }
}

/// What a job's end without a transaction means for the bundle (D-C8 as
/// amended): `refused`, and `failed` with `node-refused:…`, are definitive;
/// any other `failed`, and `cancelled`, are the service's — not now.
pub fn job_end(view: &JobView) -> Verdict {
    let code = view.refusal.clone().unwrap_or_else(|| format!("{:?}", view.state).to_lowercase()); // debug-ok: a state name
    match view.state {
        JobState::Refused => Verdict::Definitive { status: 0, code },
        JobState::Failed if code.starts_with("node-refused:") => Verdict::Definitive { status: 0, code },
        _ => Verdict::NotNow { status: 0, code },
    }
}

/// `GET /v2/annulet/info`, its bytes as served (for
/// [`crate::prover_pins::admit`]).
pub fn info(t: &mut dyn ProverTransport) -> Result<Vec<u8>, String> {
    match t.call("GET", "/v2/annulet/info", None, MAX_INFO_BYTES)? {
        (200, body) => Ok(body),
        (status, body) => Err(format!("/v2/annulet/info answered HTTP {status} {}", error_code(&body))),
    }
}

/// One upload: the job, or what its refusal means.
pub fn upload(t: &mut dyn ProverTransport, bundle: &[u8]) -> Result<JobView, Verdict> {
    match t.call("POST", "/v2/annulet/jobs", Some(bundle), MAX_VIEW_BYTES) {
        Err(why) => Err(Verdict::NotNow { status: 0, code: format!("transport: {why}") }),
        Ok((200 | 202, body)) => parse_job(&body).map_err(|why| Verdict::NotNow { status: 0, code: why }),
        Ok((status, body)) => Err(classify(status, &error_code(&body))),
    }
}

/// One read of a job by its capability.
pub fn job(t: &mut dyn ProverTransport, job_url: &str) -> Result<JobView, String> {
    if !is_job_url(job_url) {
        return Err("not a job URL of this service".into());
    }
    match t.call("GET", job_url, None, MAX_VIEW_BYTES)? {
        (200, body) => parse_job(&body),
        (status, body) => Err(format!("the job answered HTTP {status} {}", error_code(&body))),
    }
}

/// What happened to a bundle handed to the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The service submitted it: its node accepted the transaction.
    Submitted { tx_id: [u8; 32] },
    /// This intent was already with the service; nothing more is known here.
    InFlight { code: String },
    /// The spend failed (an upload refused definitively, or the job ended
    /// without a transaction).
    Failed { status: u16, code: String },
    /// The validity height passed while the service kept saying not now.
    Expired { last: String },
}

/// What [`prove_remote`] reports as it goes (the drill times them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// An upload is about to be sent (`attempt` from 1).
    Uploading { attempt: u32 },
    /// Not now: the bytes are kept and re-POSTed after `wait`.
    NotNow { status: u16, code: String, wait: Duration },
    /// The service holds the job (its state as first read).
    Accepted { state: JobState, queue_position: Option<u64> },
    /// The job moved to `state`.
    State { state: JobState, queue_position: Option<u64> },
}

/// **Hand one signed bundle to the service and follow it to its end** (D-C8).
/// `expired()` says whether the transaction can no longer land — its validity
/// height passed, or the caller's wall-clock bound for it ([`Deadline`]) —
/// and is asked before the first upload, before every re-send and at every
/// poll; `sleep` waits (a test passes a no-op). The
/// bundle must already be [`record`]ed: this function only re-sends those
/// bytes.
pub fn prove_remote(
    t: &mut dyn ProverTransport,
    bundle: &[u8],
    expired: &mut dyn FnMut() -> bool,
    sleep: &mut dyn FnMut(Duration),
    events: &mut dyn FnMut(Event),
) -> Outcome {
    let mut wait = FIRST_BACKOFF;
    let mut attempt = 0;
    // Not now: the same bytes again after a growing wait, or Expired.
    fn again(
        status: u16,
        code: String,
        wait: &mut Duration,
        expired: &mut dyn FnMut() -> bool,
        sleep: &mut dyn FnMut(Duration),
        events: &mut dyn FnMut(Event),
    ) -> Option<Outcome> {
        if expired() {
            return Some(Outcome::Expired { last: code });
        }
        events(Event::NotNow { status, code, wait: *wait });
        sleep(*wait);
        *wait = (*wait * 2).min(MAX_BACKOFF);
        None
    }
    loop {
        if attempt == 0 && expired() {
            return Outcome::Expired { last: "the validity had passed before the first upload".into() };
        }
        attempt += 1;
        events(Event::Uploading { attempt });
        let mut view = match upload(t, bundle) {
            Ok(v) => v,
            Err(Verdict::InFlight { code }) => return Outcome::InFlight { code },
            Err(Verdict::Definitive { status, code }) => return Outcome::Failed { status, code },
            Err(Verdict::NotNow { status, code }) => match again(status, code, &mut wait, expired, sleep, events) {
                Some(end) => return end,
                None => continue,
            },
        };
        events(Event::Accepted { state: view.state, queue_position: view.queue_position });
        let mut misses = 0u32;
        loop {
            match view.state {
                JobState::Submitted => {
                    return Outcome::Submitted { tx_id: view.tx_id.expect("parse_job: submitted carries its id") }
                }
                JobState::Failed | JobState::Refused | JobState::Cancelled => break,
                JobState::Queued | JobState::Proving | JobState::Submitting => {}
            }
            // The poll's own pace, not the backoff's — and the validity is
            // judged at every poll: a job that never ends is not waited on
            // past it.
            if expired() {
                return Outcome::Expired { last: format!("{:?}", view.state).to_lowercase() }; // debug-ok: a state name
            }
            sleep(POLL_EVERY);
            match job(t, &view.job_url) {
                Ok(next) => {
                    misses = 0;
                    if (next.state, next.queue_position) != (view.state, view.queue_position) {
                        events(Event::State { state: next.state, queue_position: next.queue_position });
                    }
                    view = next;
                }
                // A read that fails is not the job failing: keep reading until
                // the validity has passed (the job may have landed meanwhile —
                // the scan says).
                Err(_) => {
                    misses += 1;
                    if misses > 3 {
                        sleep(wait);
                        wait = (wait * 2).min(MAX_BACKOFF);
                    }
                }
            }
        }
        // The job ended without a transaction.
        match job_end(&view) {
            Verdict::Definitive { status, code } => return Outcome::Failed { status, code },
            Verdict::InFlight { code } => return Outcome::InFlight { code },
            Verdict::NotNow { status, code } => {
                if let Some(end) = again(status, code, &mut wait, expired, sleep, events) {
                    return end;
                }
            }
        }
    }
}

/// When a transaction can no longer land, judged without trusting a read:
/// the node's stated tip at or past `valid_until`, **or** the wall clock past
/// `valid_until − tip₀` slots of `slot_secs` (from `/info`) plus a minute
/// after `started`. A tip that cannot be read is unknown — never "not yet" —
/// so a dead node cannot keep a send waiting forever.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    pub valid_until: u64,
    pub wall: std::time::Instant,
}

impl Deadline {
    /// The bound for a transaction valid until `valid_until`, signed when the
    /// verified tip was `tip`, on a net of `slot_secs`-second slots.
    pub fn new(valid_until: u64, tip: u64, slot_secs: u64, started: std::time::Instant) -> Deadline {
        // Bounded so `Instant + Duration` cannot overflow: a week is past any
        // validity (≤ 1,152 slots of ≤ MAX_SLOT_SECS).
        let secs = valid_until.saturating_sub(tip).saturating_mul(slot_secs.max(1)).saturating_add(60).min(7 * 86_400);
        Deadline { valid_until, wall: started + Duration::from_secs(secs) }
    }

    /// Passed, given the node's stated tip if it could be read.
    pub fn passed(&self, stated_tip: Option<u64>, now: std::time::Instant) -> bool {
        stated_tip.is_some_and(|t| t >= self.valid_until) || now >= self.wall
    }
}

/// The longest slot a service may state (the service's own configuration
/// range).
pub const MAX_SLOT_SECS: u64 = 600;

/// `slot_secs` from a `/v2/annulet/info` answer: what the wall-clock bound is
/// counted in. Refused by name when absent, zero or over [`MAX_SLOT_SECS`].
pub fn slot_secs_of(info: &[u8]) -> Result<u64, String> {
    let s = serde_json::from_slice::<serde_json::Value>(info)
        .ok()
        .and_then(|v| v.get("slot_secs").and_then(serde_json::Value::as_u64))
        .ok_or_else(|| "the prover's /v2/annulet/info names no slot_secs".to_string())?;
    if s == 0 || s > MAX_SLOT_SECS {
        return Err(format!("the prover's /v2/annulet/info states slot_secs {s}, outside 1..={MAX_SLOT_SECS}"));
    }
    Ok(s)
}

/// Where [`record`] keeps signed bundles: `<wallet>/remote.v1/`.
pub const RECORD_DIR: &str = "remote.v1";

/// **Record before upload** (D-C8): write the signed `bundle` under the
/// wallet, named by `key` (the transaction's first nullifier, hex), through
/// a temporary file, owner-only (0600 where the platform has permission
/// bits), fsynced, before it is sent anywhere. Returns the file.
///
/// A record of the same key takes other bytes only once its bundle has
/// **ended definitively** (lab #957): its `<key>.outcome` reads
/// `failed <4xx> …`, `failed 0 …` (the job refused, or the node refused the
/// bytes) or `expired …`. The spend failed and a retry is a new take of the
/// same note — so the old pair is kept beside it as `<key>.<n>.outcome` /
/// `<key>.<n>.bundle` (the first free `n` from 1) and the new bundle takes
/// the key. `submitted`, `in-flight` and no outcome at all still refuse: the
/// nullifier is with the service, landed, or its upload's answer is unknown.
pub fn record(wallet_dir: &Path, key: &[u8; 32], bundle: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let dir = wallet_dir.join(RECORD_DIR);
    std::fs::create_dir_all(&dir)?;
    let name: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{name}.bundle"));
    if let Ok(existing) = std::fs::read(&path) {
        if existing == bundle {
            return Ok(path);
        }
        let outcome = dir.join(format!("{name}.outcome"));
        let ended = std::fs::read_to_string(&outcome).ok();
        if !ended.as_deref().is_some_and(ended_definitively) {
            let why = ended.as_deref().map_or("no outcome yet".to_string(), |l| format!("its outcome: {}", l.trim_end()));
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} holds another bundle for this nullifier ({why})", path.display()),
            ));
        }
        let n = (1u32..)
            .find(|n| {
                !dir.join(format!("{name}.{n}.bundle")).exists() && !dir.join(format!("{name}.{n}.outcome")).exists()
            })
            .expect("a free archive number");
        // The outcome first: a crash between the two renames leaves a bundle
        // with no outcome — refused again, never a new bundle beside an old
        // bundle's definitive outcome.
        std::fs::rename(&outcome, dir.join(format!("{name}.{n}.outcome")))?;
        std::fs::rename(&path, dir.join(format!("{name}.{n}.bundle")))?;
    }
    let tmp = dir.join(format!("{name}.bundle.tmp"));
    {
        let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bundle)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(path)
}

/// Whether an `<key>.outcome` line ([`record_outcome`]'s or
/// [`settle_records`]') is a definitive end (D-C8): `failed` with a 4xx
/// status, or with status 0 (a job that ended `refused`, or `failed` with
/// `node-refused:…` — [`job_end`]'s only definitive endings), `expired` (the
/// validity height passed), or `landed` (lab #989: the chain carries it — its
/// nullifier is spent, and a planner that asks hears "landed", not "in
/// flight"). `submitted`, `in-flight` and [`PENDING`] are not, with or
/// without a trailing `unlanded-through <p>` (lab #992).
pub fn ended_definitively(line: &str) -> bool {
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some("failed"), Some(status)) => {
            status.parse::<u16>().is_ok_and(|s| s == 0 || (400..500).contains(&s))
        }
        (Some("expired" | "landed"), _) => true,
        _ => false,
    }
}

/// The intent digest a recorded bundle signed (lab #989): the bundle's
/// transaction, rebuilt as a landed transaction is
/// ([`crate::auth_check::LandedSpend::intent_digest`]) — one rebuild for both.
pub fn intent_digest_of_bundle(
    bundle: &[u8],
    form: qlab_devnet::forms::L2AuthForm,
    genesis_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    bundle_intent(bundle, form, genesis_hash).map(|(digest, _)| digest)
}

/// The digest and the section's validity height of a recorded bundle.
fn bundle_intent(
    bundle: &[u8],
    form: qlab_devnet::forms::L2AuthForm,
    genesis_hash: &[u8; 32],
) -> Result<([u8; 32], u64), String> {
    let b = qlab_l2spend::bundle::ProvingBundle::decode(bundle).map_err(|e| format!("the bundle does not decode: {e}"))?;
    crate::auth_check::intent_of(b.tx(), form, genesis_hash)
}

/// [`bundle_intent`] for the settle path (lab #991): `Ok(Err(why))` is a
/// bundle whose auth section does not verify against the intent rebuilt for
/// `genesis_hash` — another net's record (`remote.v1/` is per wallet, not per
/// net), which this net must not judge.
fn verified_bundle_intent(
    bundle: &[u8],
    form: qlab_devnet::forms::L2AuthForm,
    genesis_hash: &[u8; 32],
) -> Result<Result<([u8; 32], u64), String>, String> {
    let b = qlab_l2spend::bundle::ProvingBundle::decode(bundle).map_err(|e| format!("the bundle does not decode: {e}"))?;
    crate::auth_check::verified_intent_of(b.tx(), form, genesis_hash)
}

/// One record as [`settle_records`] reads it: the key (the transaction's
/// first nullifier), the bundle's bytes, and its `<key>.outcome` line if any.
#[derive(Clone, Debug)]
pub struct SettleRecord {
    pub key: [u8; 32],
    pub bundle: Vec<u8>,
    pub outcome: Option<String>,
}

/// What [`settle_records`] found (lab #989).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettleReport {
    /// The new `<key>.outcome` line of each record it settled (no newline).
    pub lines: Vec<([u8; 32], String)>,
    /// `(key, height, the chain's tx_id)`.
    pub landed: Vec<([u8; 32], u64, [u8; 32])>,
    /// `(key, valid_until_height)`.
    pub expired: Vec<([u8; 32], u64)>,
    /// A record still open whose bundle does not rebuild: `(key, why)`.
    pub undecodable: Vec<([u8; 32], String)>,
    /// A record still open whose auth section does not verify against the
    /// intent rebuilt for this net's genesis (lab #991): not this net's, so
    /// not judged — no line, it stays open. `(key, why)`.
    pub foreign: Vec<([u8; 32], String)>,
    /// A record still open, not landed in this walk, whose unlanded span is
    /// not covered from the earliest height it could land (lab #992): no
    /// line. `(key, lo, walked_from)` — a restore of this net walks from 0
    /// and settles it.
    pub uncovered: Vec<([u8; 32], u64, u64)>,
}

/// The first token [`settle_records`] gives a record that had no outcome
/// when it wrote its progress (lab #992). Open, as `submitted` and
/// `in-flight` are: [`ended_definitively`] is false for it.
pub const PENDING: &str = "pending";

/// An open outcome line split into its form and its trailing progress
/// `unlanded-through <p>` (lab #992); no line is [`PENDING`] with none.
fn open_line_parts(line: &str) -> (String, Option<u64>) {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        [] => (PENDING.to_string(), None),
        [form @ .., "unlanded-through", p] if !form.is_empty() => (form.join(" "), p.parse().ok()),
        _ => (words.join(" "), None),
    }
}

fn hex_of(x: &[u8; 32]) -> String {
    x.iter().map(|b| format!("{b:02x}")).collect()
}

/// **Settle recorded remote sends from the chain** (lab #989). For each
/// record still open — no outcome, `submitted …` or `in-flight …` — the
/// bundle's intent is rebuilt for `genesis_hash` and its auth section verified
/// against it (lab #991: a section signed for another net's genesis does not
/// verify, and that record is `foreign` — never judged by this net's heights);
/// then:
/// - a landed spend with that digest (matched by digest only: never by the
///   prover's `tx_id`, never by key or nullifier — a landed spend of this
///   key's leaves under another intent is another send) settles it
///   `landed <height> <tx_id>`; when the record said `submitted <tx>` and the
///   chain's id differs, `landed <height> <chain tx_id> prover-said <tx>`;
/// - else only with **coverage** (lab #992): the node lands the bundle at
///   no height below `lo = valid_until − MAX_AUTH_VALIDITY_BLOCKS`, so the
///   walks must have covered `[lo, checked_to]` without a gap. This walk
///   began at `walked_from`; the record carries what earlier walks proved as a
///   trailing `unlanded-through <p>` on its open line. Covered iff
///   `walked_from ≤ lo` or `walked_from ≤ p + 1`. Then:
///   - `valid_until < checked_to` (the node refuses a height above it):
///     `expired <valid_until> unlanded-through <checked_to>`;
///   - else the open line with `unlanded-through <checked_to>` — progress
///     (a record with no outcome takes the [`PENDING`] form);
/// - not covered: nothing written, the record in `uncovered`.
///
/// `landed`, `walked_from` and `checked_to` are a finished check's
/// ([`crate::auth_check::AuthCheck::landed_spends`], the first height it
/// walked — the previous checked height + 1 in check mode, 0 for a restore
/// or a first — and its journal's checked height); every other record is
/// left as it is.
pub fn settle_records(
    records: &[SettleRecord],
    form: qlab_devnet::forms::L2AuthForm,
    genesis_hash: &[u8; 32],
    landed: &[crate::auth_check::LandedSpend],
    walked_from: u64,
    checked_to: u64,
) -> SettleReport {
    let mut report = SettleReport::default();
    for r in records {
        let current = r.outcome.as_deref().map_or("", str::trim);
        let open = current.is_empty() || matches!(current.split_whitespace().next(), Some("submitted" | "in-flight" | PENDING));
        if !open {
            continue;
        }
        let (digest, valid_until) = match verified_bundle_intent(&r.bundle, form, genesis_hash) {
            Ok(Ok(x)) => x,
            Ok(Err(why)) => {
                report.foreign.push((r.key, why));
                continue;
            }
            Err(why) => {
                report.undecodable.push((r.key, why));
                continue;
            }
        };
        if let Some(s) = landed.iter().find(|s| s.intent_digest == digest) {
            let said = r.outcome.as_deref().and_then(|l| {
                let mut w = l.split_whitespace();
                (w.next() == Some("submitted")).then(|| w.next()).flatten()
            });
            let chain = hex_of(&s.tx_id);
            let line = match said {
                Some(tx) if tx != chain => format!("landed {} {chain} prover-said {tx}", s.height),
                _ => format!("landed {} {chain}", s.height),
            };
            report.lines.push((r.key, line));
            report.landed.push((r.key, s.height, s.tx_id));
        } else {
            let lo = valid_until.saturating_sub(qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS);
            let (open_form, progress) = open_line_parts(current);
            let covered = walked_from <= lo || progress.is_some_and(|p| walked_from <= p.saturating_add(1));
            if !covered {
                report.uncovered.push((r.key, lo, walked_from));
            } else if valid_until < checked_to {
                report.lines.push((r.key, format!("expired {valid_until} unlanded-through {checked_to}")));
                report.expired.push((r.key, valid_until));
            } else {
                let line = format!("{open_form} unlanded-through {checked_to}");
                if line != current {
                    report.lines.push((r.key, line));
                }
            }
        }
    }
    report
}

/// [`settle_records`] over the wallet's own records (`<wallet>/remote.v1/`):
/// each keyed `<key>.bundle` (never a `<key>.<n>` history pair) with its
/// `<key>.outcome`; every settled line is written beside it through a
/// temporary file, fsynced, renamed. No record directory is no record.
pub fn settle(
    wallet_dir: &Path,
    form: qlab_devnet::forms::L2AuthForm,
    genesis_hash: &[u8; 32],
    landed: &[crate::auth_check::LandedSpend],
    walked_from: u64,
    checked_to: u64,
) -> std::io::Result<SettleReport> {
    use std::io::Write;
    let dir = wallet_dir.join(RECORD_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SettleReport::default()),
        Err(e) => return Err(e),
    };
    let mut records = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".bundle")) else { continue };
        let Some(key) = hex32(stem) else { continue };
        let bundle = std::fs::read(dir.join(format!("{stem}.bundle")))?;
        let outcome = match std::fs::read_to_string(dir.join(format!("{stem}.outcome"))) {
            Ok(l) => Some(l),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        records.push(SettleRecord { key, bundle, outcome });
    }
    records.sort_by_key(|r| r.key);
    let report = settle_records(&records, form, genesis_hash, landed, walked_from, checked_to);
    for (key, line) in &report.lines {
        let name = hex_of(key);
        let tmp = dir.join(format!("{name}.outcome.tmp"));
        {
            let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
            f.write_all(format!("{line}\n").as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(format!("{name}.outcome")))?;
    }
    #[cfg(unix)]
    if !report.lines.is_empty() {
        std::fs::File::open(&dir)?.sync_all()?;
    }
    Ok(report)
}

/// Note the end of a recorded bundle beside it (`<key>.outcome`, one line):
/// the record stays — it is what the wallet sent.
pub fn record_outcome(wallet_dir: &Path, key: &[u8; 32], outcome: &Outcome) -> std::io::Result<()> {
    let name: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let line = match outcome {
        Outcome::Submitted { tx_id } => format!("submitted {}\n", tx_id.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        Outcome::InFlight { code } => format!("in-flight {code}\n"),
        Outcome::Failed { status, code } => format!("failed {status} {code}\n"),
        Outcome::Expired { last } => format!("expired {}\n", last.replace('\n', " ")),
    };
    std::fs::write(wallet_dir.join(RECORD_DIR).join(format!("{name}.outcome")), line)
}

/// The price a step of `shape` pays an admitted prover.
pub fn price_of(p: &crate::prover_pins::AdmittedProver, shape: L2ShapeTag) -> u64 {
    p.price.of(shape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const CAP: &str = "/v2/annulet/jobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TX: &str = "aa00000000000000000000000000000000000000000000000000000000000000";

    fn view(state: &str, tx: Option<&str>) -> Vec<u8> {
        let tx = tx.map(|t| format!(r#","tx_id":"{t}""#)).unwrap_or_default();
        format!(r#"{{"protocol_version":1,"job_url":"{CAP}","state":"{state}","queue_position":null{tx},"refusal":null}}"#)
            .into_bytes()
    }

    fn err(code: &str) -> Vec<u8> {
        format!(r#"{{"error":"{code}"}}"#).into_bytes()
    }

    /// A scripted service: each call takes the next answer, and every call
    /// is kept (method, path, body) so a test can read what was sent.
    struct Script {
        answers: VecDeque<Result<(u16, Vec<u8>), String>>,
        calls: Vec<(String, String, Option<Vec<u8>>)>,
    }

    impl Script {
        fn new(answers: Vec<Result<(u16, Vec<u8>), String>>) -> Script {
            Script { answers: answers.into(), calls: Vec::new() }
        }
    }

    impl ProverTransport for Script {
        fn call(&mut self, method: &str, path: &str, body: Option<&[u8]>, _max: usize) -> Result<(u16, Vec<u8>), String> {
            self.calls.push((method.into(), path.into(), body.map(<[u8]>::to_vec)));
            self.answers.pop_front().expect("the script has an answer")
        }
    }

    fn run(s: &mut Script, expire_after: usize) -> (Outcome, Vec<Event>, Vec<Duration>) {
        let mut asked = 0;
        let mut expired = || {
            asked += 1;
            asked > expire_after
        };
        let mut slept = Vec::new();
        let mut events = Vec::new();
        let o = prove_remote(s, b"bundle", &mut expired, &mut |d| slept.push(d), &mut |e| events.push(e));
        (o, events, slept)
    }

    /// D-C8's table, row by row.
    #[test]
    fn the_retry_table_is_d_c8s() {
        for (status, code) in [(429, "ip-busy"), (503, "prover-busy"), (503, "nullifiers-catching-up"), (503, "nullifiers-stale"), (502, "unnamed")] {
            assert!(matches!(classify(status, code), Verdict::NotNow { .. }), "{status} {code}");
        }
        for code in ["nullifier-in-flight", "intent-in-flight"] {
            assert_eq!(classify(409, code), Verdict::InFlight { code: code.into() });
        }
        for (status, code) in [
            (400, "client-ip-unknown"),
            (400, "bundle-malformed"),
            (402, "prover-fee-missing"),
            (402, "prover-fee-short"),
            (403, "issuer-shape"),
            (409, "nullifier-landed"),
            (413, "bundle-too-large"),
            (422, "fee-note-not-exact"),
            (404, "not-found"),
        ] {
            assert!(matches!(classify(status, code), Verdict::Definitive { .. }), "{status} {code}");
        }
    }

    /// Not now → the **same bytes** again after a growing wait; then the job
    /// is followed to `submitted` and its id returned.
    #[test]
    fn not_now_re_posts_the_same_bytes_then_follows_the_job() {
        let mut s = Script::new(vec![
            Ok((503, err("prover-busy"))),
            Err("connection reset".into()),
            Ok((429, err("ip-busy"))),
            Ok((202, view("queued", None))),
            Ok((200, view("proving", None))),
            Ok((200, view("submitted", Some(TX)))),
        ]);
        let (o, events, slept) = run(&mut s, usize::MAX);
        assert_eq!(o, Outcome::Submitted { tx_id: hex32(TX).unwrap() });
        let posts: Vec<_> = s.calls.iter().filter(|c| c.0 == "POST").collect();
        assert_eq!(posts.len(), 4);
        assert!(posts.iter().all(|c| c.1 == "/v2/annulet/jobs" && c.2.as_deref() == Some(&b"bundle"[..])), "byte-identical");
        assert!(s.calls.iter().filter(|c| c.0 == "GET").all(|c| c.1 == CAP), "polled by its capability");
        assert_eq!(&slept[..3], &[FIRST_BACKOFF, FIRST_BACKOFF * 2, FIRST_BACKOFF * 4]);
        assert!(events.contains(&Event::Accepted { state: JobState::Queued, queue_position: None }));
        assert!(events.contains(&Event::State { state: JobState::Proving, queue_position: None }));
    }

    #[test]
    fn not_now_until_the_validity_passes_is_expired() {
        // expired() is asked before the first upload, then after each not-now.
        let mut s = Script::new(vec![Ok((503, err("nullifiers-stale"))), Ok((503, err("nullifiers-stale")))]);
        let (o, ..) = run(&mut s, 2);
        assert_eq!(o, Outcome::Expired { last: "nullifiers-stale".into() });
        assert_eq!(s.calls.len(), 2);
        // Passed before anything is sent: nothing is sent.
        let mut s = Script::new(vec![]);
        assert!(matches!(run(&mut s, 0).0, Outcome::Expired { .. }));
        assert!(s.calls.is_empty());
    }

    /// A job that stays live is not waited on past the validity: every poll
    /// asks.
    #[test]
    fn a_job_that_never_ends_is_not_waited_on_past_the_validity() {
        let mut s = Script::new(vec![
            Ok((202, view("queued", None))),
            Ok((200, view("proving", None))),
            Ok((200, view("proving", None))),
        ]);
        // 1 before the upload, then 1 per poll: the third poll's ask passes.
        let (o, ..) = run(&mut s, 3);
        assert_eq!(o, Outcome::Expired { last: "proving".into() });
    }

    /// The wall-clock bound holds when the node's tip cannot be read.
    #[test]
    fn the_deadline_does_not_trust_an_unreadable_tip() {
        let t0 = std::time::Instant::now();
        let d = Deadline::new(150, 100, 10, t0);
        assert_eq!(d.wall, t0 + Duration::from_secs(50 * 10 + 60));
        assert!(!d.passed(None, t0), "unknown tip, before the wall bound");
        assert!(d.passed(None, t0 + Duration::from_secs(560)), "unknown tip, past it");
        assert!(d.passed(Some(150), t0), "the tip reached valid_until");
        assert!(!d.passed(Some(149), t0));
        assert_eq!(slot_secs_of(br#"{"slot_secs":10}"#), Ok(10));
        assert!(slot_secs_of(br#"{"slot_secs":0}"#).is_err() && slot_secs_of(b"{}").is_err());
        assert_eq!(slot_secs_of(br#"{"slot_secs":600}"#), Ok(600));
        assert!(slot_secs_of(br#"{"slot_secs":601}"#).is_err());
        assert!(slot_secs_of(br#"{"slot_secs":18446744073709551615}"#).is_err());
        // However large the inputs, the bound is a week and never overflows.
        let far = Deadline::new(u64::MAX, 0, u64::MAX, t0);
        assert_eq!(far.wall, t0 + Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn in_flight_and_definitive_stop_at_once() {
        let mut s = Script::new(vec![Ok((409, err("nullifier-in-flight")))]);
        assert_eq!(run(&mut s, usize::MAX).0, Outcome::InFlight { code: "nullifier-in-flight".into() });
        let mut s = Script::new(vec![Ok((402, err("prover-fee-short")))]);
        assert_eq!(run(&mut s, usize::MAX).0, Outcome::Failed { status: 402, code: "prover-fee-short".into() });
        let mut s = Script::new(vec![Ok((409, err("nullifier-landed")))]);
        assert_eq!(run(&mut s, usize::MAX).0, Outcome::Failed { status: 409, code: "nullifier-landed".into() });
        assert_eq!(s.calls.len(), 1);
    }

    /// D-C8 as amended: a job's end without a transaction, by state and code.
    #[test]
    fn a_jobs_end_is_classified_by_who_refused() {
        let end = |state: JobState, refusal: Option<&str>| {
            job_end(&JobView { job_url: CAP.into(), state, queue_position: None, tx_id: None, refusal: refusal.map(str::to_string) })
        };
        for code in ["worker-timeout", "worker-failed", "worker-output-torn", "proof-mismatch", "proof-refused", "node-unreachable"] {
            assert!(matches!(end(JobState::Failed, Some(code)), Verdict::NotNow { .. }), "{code}");
        }
        assert!(matches!(end(JobState::Cancelled, None), Verdict::NotNow { .. }));
        assert!(matches!(end(JobState::Failed, Some("node-refused:validity")), Verdict::Definitive { .. }));
        assert!(matches!(end(JobState::Refused, Some("bundle-refused")), Verdict::Definitive { .. }));
    }

    /// The service's own failure (a worker timeout) or a cancellation: the
    /// same bytes again, and the re-admitted job followed to `submitted`.
    #[test]
    fn a_job_the_service_lost_is_sent_again() {
        let timed_out = br#"{"protocol_version":1,"job_url":"/v2/annulet/jobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","state":"failed","refusal":"worker-timeout"}"#;
        let mut s = Script::new(vec![
            Ok((202, view("queued", None))),
            Ok((200, timed_out.to_vec())),
            Ok((202, view("queued", None))),
            Ok((200, view("cancelled", None))),
            Ok((202, view("proving", None))),
            Ok((200, view("submitted", Some(TX)))),
        ]);
        let (o, events, _) = run(&mut s, usize::MAX);
        assert_eq!(o, Outcome::Submitted { tx_id: hex32(TX).unwrap() });
        let posts: Vec<_> = s.calls.iter().filter(|c| c.0 == "POST").collect();
        assert_eq!(posts.len(), 3, "the bundle three times");
        assert!(posts.iter().all(|c| c.2.as_deref() == Some(&b"bundle"[..])), "byte-identical");
        assert!(events.iter().any(|e| matches!(e, Event::NotNow { code, .. } if code == "worker-timeout")));
        assert!(events.iter().any(|e| matches!(e, Event::NotNow { code, .. } if code == "cancelled")));
    }

    /// A job the node refused, or the worker's lock refused, is the spend
    /// failing; its code is the service's.
    #[test]
    fn a_job_that_ends_without_a_transaction_fails() {
        let failed = br#"{"protocol_version":1,"job_url":"/v2/annulet/jobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","state":"failed","refusal":"node-refused:validity"}"#;
        let mut s = Script::new(vec![Ok((202, view("queued", None))), Ok((200, failed.to_vec()))]);
        assert_eq!(run(&mut s, usize::MAX).0, Outcome::Failed { status: 0, code: "node-refused:validity".into() });
    }

    /// A job view this client cannot read is refused by name — never guessed.
    #[test]
    fn job_views_are_read_strictly() {
        assert!(parse_job(&view("submitted", Some(TX))).is_ok());
        assert!(parse_job(&view("submitted", None)).is_err(), "submitted without its id");
        assert!(parse_job(&view("queued", Some(TX))).is_err(), "an id before submission");
        assert!(parse_job(&view("landed", None)).is_err(), "an unknown state");
        assert!(parse_job(&view("queued", Some("AA"))).is_err());
        let other = String::from_utf8(view("queued", None)).unwrap().replace("/v2/annulet/jobs/", "/elsewhere/");
        assert!(parse_job(other.as_bytes()).is_err(), "a URL that is not a job capability");
        let v2 = String::from_utf8(view("queued", None)).unwrap().replace(r#""protocol_version":1"#, r#""protocol_version":2"#);
        assert!(parse_job(v2.as_bytes()).is_err(), "another protocol");
        assert_eq!(error_code(b"<html>bad gateway</html>"), "unnamed");
        assert_eq!(error_code(&err("ip-busy")), "ip-busy");
    }

    /// Record before upload: the bytes are on disk, owner-only, and the same
    /// key never takes other bytes.
    #[test]
    fn a_bundle_is_recorded_once_with_its_bytes() {
        let d = std::env::temp_dir().join(format!("qmb_remote_record_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let key = [7u8; 32];
        let p = record(&d, &key, b"signed").expect("recorded");
        assert_eq!(std::fs::read(&p).unwrap(), b"signed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(record(&d, &key, b"signed").expect("the same bytes again"), p);
        assert!(record(&d, &key, b"other").is_err(), "never other bytes under the same nullifier");
        record_outcome(&d, &key, &Outcome::Submitted { tx_id: [0xab; 32] }).unwrap();
        let line = std::fs::read_to_string(p.with_extension("outcome")).unwrap();
        assert!(line.starts_with("submitted abab"), "{line}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Lab #957: after a definitive end, a new take of the same note — other
    /// bytes under the same nullifier — is recorded, and the old pair is kept
    /// as `<key>.<n>.*`; `submitted`, `in-flight` and no outcome still refuse.
    #[test]
    fn a_definitive_end_lets_a_new_take_of_the_note_be_recorded() {
        let d = std::env::temp_dir().join(format!("qmb_remote_retake_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let key = [9u8; 32];
        let name = "09".repeat(32);
        let at = |f: &str| d.join(RECORD_DIR).join(format!("{name}{f}"));

        // No outcome yet: the upload's answer is unknown — refused.
        record(&d, &key, b"take-1").unwrap();
        let e = record(&d, &key, b"take-2").unwrap_err();
        assert!(e.to_string().contains("holds another bundle for this nullifier (no outcome yet)"), "{e}");
        // In flight, submitted: the nullifier is with the service or landed — refused.
        for o in [Outcome::InFlight { code: "nullifier-in-flight".into() }, Outcome::Submitted { tx_id: [0xab; 32] }] {
            record_outcome(&d, &key, &o).unwrap();
            let e = record(&d, &key, b"take-2").unwrap_err();
            assert!(e.to_string().contains("its outcome: "), "{e}");
            assert_eq!(std::fs::read(at(".bundle")).unwrap(), b"take-1");
        }

        // Each definitive end: the new take is recorded, the old pair kept.
        let ends = [
            Outcome::Failed { status: 402, code: "prover-fee-missing".into() },
            Outcome::Failed { status: 0, code: "node-refused:validity".into() },
            Outcome::Failed { status: 0, code: "unprovable".into() },
            Outcome::Expired { last: "nullifiers-stale".into() },
        ];
        for (i, o) in ends.iter().enumerate() {
            let n = i + 1;
            let old = format!("take-{n}");
            let new = format!("take-{}", n + 1);
            record_outcome(&d, &key, o).unwrap();
            let line = std::fs::read_to_string(at(".outcome")).unwrap();
            assert_eq!(record(&d, &key, new.as_bytes()).unwrap(), at(".bundle"));
            assert_eq!(std::fs::read(at(".bundle")).unwrap(), new.as_bytes());
            assert!(!at(".outcome").exists(), "the new take has no outcome yet");
            assert_eq!(std::fs::read(at(&format!(".{n}.bundle"))).unwrap(), old.as_bytes());
            assert_eq!(std::fs::read_to_string(at(&format!(".{n}.outcome"))).unwrap(), line);
            // And the new take is guarded again until it, too, ends.
            assert!(record(&d, &key, b"another").is_err());
        }

        assert!(!ended_definitively("submitted abab"));
        assert!(!ended_definitively("in-flight nullifier-in-flight"));
        assert!(!ended_definitively("failed 503 prover-busy"), "a 5xx is never recorded as failed, and is not definitive");
        assert!(!ended_definitively(""));
        let _ = std::fs::remove_dir_all(&d);
    }
}
