//! The `/metrics` scrape endpoint (lab #976): what the production alerts read
//! — "prover queue full or 5xx rate > 5 % for 5 min" — in the Prometheus text
//! format, on a listener of its own.
//!
//! ## A second listener, never the API's
//! The listener is **off unless `QUMBRA_PROVER_METRICS_LISTEN` is set**, and
//! it serves `GET /metrics` and nothing else. It shares no socket with the
//! API, so no ingress route can reach it: "never on the public ingress" holds
//! by construction rather than by a Caddyfile rule. Off loopback it needs the
//! same acknowledgement as the API's listener ([`crate::metrics_listen`]).
//! Nothing here authenticates, so the exposure belongs to the network it is
//! bound on — the shape of `qumbra-node`'s `metrics_addr` (issue #87).
//!
//! ## No identity
//! Every label value is from a fixed set: an outcome, a refusal's existing
//! code, a status class, a shape. A refusal is counted by its code only,
//! never under the submitter's tag (the minute log line keeps the tag; this
//! does not), and a code outside [`REFUSAL_CODES`] is counted as `other`, so
//! no input can grow the series.
//!
//! ## What counts
//! - `qumbra_prover_queue_depth`, `qumbra_prover_in_flight`: read from the
//!   Annulet state at scrape time (queued jobs, the running one not counted;
//!   jobs proving or submitting, 0 or 1).
//! - `qumbra_prover_jobs_total{outcome}`: `admitted` when a job is queued;
//!   then one of `refused` (the child refused the bundle), `failed` (the
//!   child failed, its answer was not the bundle's transaction plus a proof,
//!   or the node refused it) — or `proved` and then `submitted` or `failed`.
//!   A cancelled job ends under no outcome. Admission refusals are not jobs:
//!   they are `qumbra_prover_refusals_total`.
//! - `qumbra_prover_refusals_total{reason}`: every refusal the Annulet state
//!   counts — the same events as the minute log line, never drained.
//! - `qumbra_prover_http_responses_total{class}`: every response the API's
//!   listener writes, both modes (an upload past its deadline gets none; it
//!   is the refusal `upload-deadline`).
//! - `qumbra_prover_prove_seconds{shape}`: the child's wall time, for every
//!   prove that answered and was not cancelled. Shape R is never a bundle.
//!
//! The valueless L1 mode exports the HTTP classes only.

use std::fmt::Write as _;
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qlab_devnet::annulet::L2ShapeTag;

/// Prometheus text exposition format v0.0.4.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The upper bounds of `qumbra_prover_prove_seconds`, then `+Inf`. S proves
/// in about 51 s and P in about 56 s on prover-1; 300 s is the default
/// timeout.
pub const PROVE_BUCKETS_SECS: [u64; 10] = [5, 10, 20, 30, 45, 60, 90, 120, 180, 300];

/// A job's outcomes, in exposition order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    Admitted,
    Refused,
    Proved,
    Submitted,
    Failed,
}

const JOB_OUTCOMES: [(JobOutcome, &str); 5] = [
    (JobOutcome::Admitted, "admitted"),
    (JobOutcome::Refused, "refused"),
    (JobOutcome::Proved, "proved"),
    (JobOutcome::Submitted, "submitted"),
    (JobOutcome::Failed, "failed"),
];

/// Every code the Annulet state counts as a refusal, sorted: the label
/// values of `qumbra_prover_refusals_total`, exported from zero so an alert
/// sees the series before the first refusal. A new refusal code joins this
/// list (`every_refusal_code_in_the_source_is_classified` fails until it
/// does); one that does not is counted as `other`.
pub const REFUSAL_CODES: [&str; 35] = [
    "auth-missing",
    "bundle-malformed",
    "bundle-too-large",
    "client-ip-unknown",
    "content-type-required",
    "fee-note-not-exact",
    "ingress-busy",
    "intent-in-flight",
    "ip-busy",
    "issuer-shape",
    "nullifier-in-flight",
    "nullifier-landed",
    "nullifiers-catching-up",
    "nullifiers-stale",
    "outputs-not-the-nets",
    "proof-present",
    "prover-busy",
    "prover-fee-missing",
    "prover-fee-short",
    "quota-exhausted",
    "request-unreadable",
    "retained-job-limit",
    "statement-mismatch",
    "third-output-asset",
    "token-busy",
    "token-expired",
    "token-key-unknown",
    "token-malformed",
    "token-revoked",
    "token-signature-invalid",
    "token-window-invalid",
    "token-wrong-net",
    "unauthorized",
    "unauthorized-section",
    "upload-deadline",
];

/// The label value for a code outside [`REFUSAL_CODES`].
const OTHER: &str = "other";

/// The counter index of `code`: its place in [`REFUSAL_CODES`], or
/// [`OTHER`]'s, one past the end.
fn refusal_index(code: &str) -> usize {
    REFUSAL_CODES.binary_search(&code).unwrap_or(REFUSAL_CODES.len())
}

/// One shape's prove-time histogram: per-bucket counts (the last is `+Inf`),
/// not cumulative; the sum in milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProveHistogram {
    buckets: [u64; PROVE_BUCKETS_SECS.len() + 1],
    sum_ms: u64,
}

impl ProveHistogram {
    pub fn observe(&mut self, ms: u64) {
        let i = PROVE_BUCKETS_SECS
            .iter()
            .position(|&le| ms <= le * 1000)
            .unwrap_or(PROVE_BUCKETS_SECS.len());
        self.buckets[i] += 1;
        self.sum_ms = self.sum_ms.saturating_add(ms);
    }

    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
}

/// The Annulet counters, kept in its state beside the jobs (so they move
/// under the lock the events already take).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnuletCounters {
    jobs: [u64; JOB_OUTCOMES.len()],
    refusals: [u64; REFUSAL_CODES.len() + 1],
    prove: [ProveHistogram; 2],
}

impl Default for AnnuletCounters {
    fn default() -> Self {
        Self {
            jobs: [0; JOB_OUTCOMES.len()],
            refusals: [0; REFUSAL_CODES.len() + 1],
            prove: Default::default(),
        }
    }
}

impl AnnuletCounters {
    pub fn job(&mut self, outcome: JobOutcome) {
        let i = JOB_OUTCOMES
            .iter()
            .position(|(o, _)| *o == outcome)
            .expect("every outcome is listed");
        self.jobs[i] += 1;
    }

    pub fn refusal(&mut self, code: &str) {
        self.refusals[refusal_index(code)] += 1;
    }

    pub fn prove(&mut self, shape: L2ShapeTag, ms: u64) {
        match shape {
            L2ShapeTag::S => self.prove[0].observe(ms),
            L2ShapeTag::P => self.prove[1].observe(ms),
            L2ShapeTag::R => {}
        }
    }

    pub fn jobs(&self, outcome: JobOutcome) -> u64 {
        let i = JOB_OUTCOMES
            .iter()
            .position(|(o, _)| *o == outcome)
            .expect("every outcome is listed");
        self.jobs[i]
    }

    pub fn refusals(&self, code: &str) -> u64 {
        self.refusals[refusal_index(code)]
    }

    pub fn proves(&self, shape: L2ShapeTag) -> &ProveHistogram {
        match shape {
            L2ShapeTag::S => &self.prove[0],
            _ => &self.prove[1],
        }
    }
}

/// What a scrape reads from the Annulet API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnnuletSnapshot {
    pub queue_depth: usize,
    pub in_flight: usize,
    pub counters: AnnuletCounters,
}

/// The API listener's responses by status class: 2xx, 4xx, 5xx.
pub struct HttpClasses([AtomicU64; 3]);

impl HttpClasses {
    pub const fn new() -> Self {
        Self([AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)])
    }

    /// Count one response; a status outside the three classes is not
    /// counted (the service writes none).
    pub fn observe(&self, status: u16) {
        let i = match status {
            200..=299 => 0,
            400..=499 => 1,
            500..=599 => 2,
            _ => return,
        };
        self.0[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> [u64; 3] {
        [0, 1, 2].map(|i| self.0[i].load(Ordering::Relaxed))
    }
}

impl Default for HttpClasses {
    fn default() -> Self {
        Self::new()
    }
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// The exposition: the HTTP classes, and the Annulet metrics when that mode
/// runs.
pub fn render(http: &HttpClasses, annulet: Option<&AnnuletSnapshot>) -> String {
    let mut out = String::new();
    let name = "qumbra_prover_http_responses_total";
    header(&mut out, name, "counter", "Responses the API listener wrote, by status class.");
    for (class, n) in ["2xx", "4xx", "5xx"].iter().zip(http.get()) {
        let _ = writeln!(out, "{name}{{class=\"{class}\"}} {n}");
    }
    let Some(a) = annulet else { return out };

    let name = "qumbra_prover_queue_depth";
    header(&mut out, name, "gauge", "Annulet jobs queued, the running one not counted.");
    let _ = writeln!(out, "{name} {}", a.queue_depth);
    let name = "qumbra_prover_in_flight";
    header(&mut out, name, "gauge", "Annulet jobs proving or submitting.");
    let _ = writeln!(out, "{name} {}", a.in_flight);

    let name = "qumbra_prover_jobs_total";
    header(&mut out, name, "counter", "Annulet jobs by outcome.");
    for ((_, outcome), n) in JOB_OUTCOMES.iter().zip(a.counters.jobs) {
        let _ = writeln!(out, "{name}{{outcome=\"{outcome}\"}} {n}");
    }

    let name = "qumbra_prover_refusals_total";
    header(&mut out, name, "counter", "Annulet refusals by code.");
    for (reason, n) in REFUSAL_CODES.iter().chain([&OTHER]).zip(a.counters.refusals) {
        let _ = writeln!(out, "{name}{{reason=\"{reason}\"}} {n}");
    }

    let name = "qumbra_prover_prove_seconds";
    header(&mut out, name, "histogram", "Annulet prove wall time by shape.");
    for (shape, h) in ["S", "P"].iter().zip(&a.counters.prove) {
        let mut cumulative = 0;
        for (le, n) in PROVE_BUCKETS_SECS.iter().zip(h.buckets) {
            cumulative += n;
            let _ = writeln!(out, "{name}_bucket{{shape=\"{shape}\",le=\"{le}\"}} {cumulative}");
        }
        let _ = writeln!(out, "{name}_bucket{{shape=\"{shape}\",le=\"+Inf\"}} {}", h.count());
        let _ = writeln!(out, "{name}_sum{{shape=\"{shape}\"}} {}.{:03}", h.sum_ms / 1000, h.sum_ms % 1000);
        let _ = writeln!(out, "{name}_count{{shape=\"{shape}\"}} {}", h.count());
    }
    out
}

/// Bind `listen` and serve `GET /metrics` from `render` on a thread of its
/// own, one request at a time: `405` for another method, `404` for another
/// path. Returns the bound address.
pub fn serve(
    listen: SocketAddr,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> Result<SocketAddr, String> {
    let server = tiny_http::Server::http(listen)
        .map_err(|_| "metrics listener could not bind".to_string())?;
    let bound = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| "metrics listener did not bind an IP socket".to_string())?;
    std::thread::Builder::new()
        .name("prover-metrics".into())
        .spawn(move || {
            for mut request in server.incoming_requests() {
                // Nothing is read from a body; drain a small one so the
                // answer is not a reset.
                let _ = std::io::copy(&mut request.as_reader().take(4096), &mut std::io::sink());
                let response = if request.url() != "/metrics" {
                    tiny_http::Response::from_string("not found").with_status_code(404)
                } else if *request.method() != tiny_http::Method::Get {
                    tiny_http::Response::from_string("method not allowed")
                        .with_status_code(405)
                        .with_header(
                            tiny_http::Header::from_bytes("Allow", "GET").expect("static header"),
                        )
                } else {
                    tiny_http::Response::from_string(render()).with_header(
                        tiny_http::Header::from_bytes("Content-Type", CONTENT_TYPE)
                            .expect("static header"),
                    )
                };
                let _ = request.respond(response);
            }
        })
        .map_err(|_| "metrics listener thread could not start".to_string())?;
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn the_refusal_codes_are_sorted_and_a_stranger_is_other() {
        assert!(REFUSAL_CODES.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicate");
        assert!(!REFUSAL_CODES.contains(&OTHER));
        assert!(REFUSAL_CODES
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
        let mut c = AnnuletCounters::default();
        c.refusal("prover-busy");
        c.refusal("a0b1c2d3");
        c.refusal("not-a-code-anyone-wrote");
        assert_eq!(c.refusals("prover-busy"), 1);
        assert_eq!(c.refusals("other"), 2);
        let text = render(&HttpClasses::new(), Some(&AnnuletSnapshot { counters: c, ..Default::default() }));
        assert!(!text.contains("a0b1c2d3") && !text.contains("not-a-code"));
        assert!(text.contains("qumbra_prover_refusals_total{reason=\"other\"} 2\n"));
    }

    #[test]
    fn the_prove_histogram_is_cumulative_with_inf_and_sum() {
        let mut c = AnnuletCounters::default();
        // 5 s exactly is in le="5"; 51.2 s in le="60"; 400 s only in +Inf.
        for ms in [5_000, 51_200, 400_000] {
            c.prove(L2ShapeTag::S, ms);
        }
        c.prove(L2ShapeTag::P, 56_000);
        c.prove(L2ShapeTag::R, 1);
        let text = render(&HttpClasses::new(), Some(&AnnuletSnapshot { counters: c, ..Default::default() }));
        let line = |s: &str| assert!(text.contains(&format!("{s}\n")), "missing {s:?} in\n{text}");
        line("qumbra_prover_prove_seconds_bucket{shape=\"S\",le=\"5\"} 1");
        line("qumbra_prover_prove_seconds_bucket{shape=\"S\",le=\"45\"} 1");
        line("qumbra_prover_prove_seconds_bucket{shape=\"S\",le=\"60\"} 2");
        line("qumbra_prover_prove_seconds_bucket{shape=\"S\",le=\"300\"} 2");
        line("qumbra_prover_prove_seconds_bucket{shape=\"S\",le=\"+Inf\"} 3");
        line("qumbra_prover_prove_seconds_sum{shape=\"S\"} 456.200");
        line("qumbra_prover_prove_seconds_count{shape=\"S\"} 3");
        line("qumbra_prover_prove_seconds_bucket{shape=\"P\",le=\"60\"} 1");
        line("qumbra_prover_prove_seconds_count{shape=\"P\"} 1");
        assert!(!text.contains("shape=\"R\""));
    }

    #[test]
    fn the_exposition_golden() {
        let http = HttpClasses::new();
        for status in [200, 202, 404, 429, 503, 301] {
            http.observe(status);
        }
        assert_eq!(http.get(), [2, 2, 1]);
        // The valueless L1 mode: the classes only.
        assert_eq!(
            render(&http, None),
            "# HELP qumbra_prover_http_responses_total Responses the API listener wrote, by status class.\n\
             # TYPE qumbra_prover_http_responses_total counter\n\
             qumbra_prover_http_responses_total{class=\"2xx\"} 2\n\
             qumbra_prover_http_responses_total{class=\"4xx\"} 2\n\
             qumbra_prover_http_responses_total{class=\"5xx\"} 1\n"
        );
        let mut counters = AnnuletCounters::default();
        counters.job(JobOutcome::Admitted);
        counters.job(JobOutcome::Admitted);
        counters.job(JobOutcome::Proved);
        counters.job(JobOutcome::Submitted);
        let text = render(&http, Some(&AnnuletSnapshot { queue_depth: 1, in_flight: 1, counters }));
        assert!(text.starts_with(&render(&http, None)));
        let annulet = &text[render(&http, None).len()..];
        let head: Vec<&str> = annulet.lines().take(15).collect();
        assert_eq!(
            head,
            [
                "# HELP qumbra_prover_queue_depth Annulet jobs queued, the running one not counted.",
                "# TYPE qumbra_prover_queue_depth gauge",
                "qumbra_prover_queue_depth 1",
                "# HELP qumbra_prover_in_flight Annulet jobs proving or submitting.",
                "# TYPE qumbra_prover_in_flight gauge",
                "qumbra_prover_in_flight 1",
                "# HELP qumbra_prover_jobs_total Annulet jobs by outcome.",
                "# TYPE qumbra_prover_jobs_total counter",
                "qumbra_prover_jobs_total{outcome=\"admitted\"} 2",
                "qumbra_prover_jobs_total{outcome=\"refused\"} 0",
                "qumbra_prover_jobs_total{outcome=\"proved\"} 1",
                "qumbra_prover_jobs_total{outcome=\"submitted\"} 1",
                "qumbra_prover_jobs_total{outcome=\"failed\"} 0",
                "# HELP qumbra_prover_refusals_total Annulet refusals by code.",
                "# TYPE qumbra_prover_refusals_total counter",
            ]
        );
        // Every named code and `other`, from zero; then 2 × (10 + 1) buckets,
        // a sum and a count per shape.
        let refusal_lines = annulet.lines().filter(|l| l.starts_with("qumbra_prover_refusals_total{")).count();
        assert_eq!(refusal_lines, REFUSAL_CODES.len() + 1);
        assert_eq!(annulet.lines().filter(|l| l.starts_with("qumbra_prover_prove_seconds_")).count(), 2 * 13);
        assert!(text.ends_with("qumbra_prover_prove_seconds_count{shape=\"P\"} 0\n"));
    }

    /// Every quoted code a refusal or an API error is built from, in the
    /// service's sources and the token crate's, is either a refusal code or
    /// named here as something the Annulet state never counts as one — so a
    /// new refusal cannot land as `other` unnoticed.
    #[test]
    fn every_refusal_code_in_the_source_is_classified() {
        const NOT_REFUSALS: &[&str] = &[
            // Job outcomes and the child's codes (a job's `refusal` field).
            "artifact-too-large", "bundle-refused", "cancelled", "proof-mismatch", "proof-refused",
            "worker-failed", "worker-input-failed", "worker-output-kind-unknown", "worker-output-missing",
            "worker-output-too-large", "worker-output-trailing", "worker-protocol-refused",
            "worker-timeout", "worker-wait-failed", "worker-output-invalid", "worker-output-torn",
            "worker-output-unreadable", "worker-spawn-failed", "worker-error-invalid",
            "node-preflight-refused", "relay-failed",
            // Answers that are not admission: a job's GET/DELETE, routing, entropy.
            "entropy-unavailable", "job-not-found", "not-found", "quota-not-served",
            // The valueless L1 mode, which counts no refusals.
            "idempotency-key-required", "request-json-invalid", "request-too-large",
        ];
        let sources = [
            include_str!("annulet.rs"),
            include_str!("annulet_v3.rs"),
            include_str!("main.rs"),
            include_str!("../../qlab-prover-token/src/lib.rs"),
        ];
        let prefixes = ["err(", "code: \"", "refuse(request, ", "count_refusal(who, \"", "Err(\""];
        let mut seen = 0;
        for src in sources {
            for prefix in prefixes {
                for (at, _) in src.match_indices(prefix) {
                    let rest = &src[at + prefix.len()..];
                    let Some(open) = rest.find('"').filter(|&i| i <= 12) else { continue };
                    let lit = &rest[open + 1..];
                    let code = &lit[..lit.find('"').expect("closed")];
                    if code.is_empty() || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
                        continue;
                    }
                    seen += 1;
                    assert!(
                        REFUSAL_CODES.contains(&code) || NOT_REFUSALS.contains(&code),
                        "the code {code:?} is neither a refusal code nor named as not one"
                    );
                }
            }
        }
        assert!(seen > 40, "the scan read the sources ({seen} codes)");
    }

    fn http_get(addr: SocketAddr, request: &str) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn the_listener_serves_get_metrics_only() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(|| "qumbra_prover_queue_depth 0\n".to_string()),
        )
        .unwrap();
        let ok = http_get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains(&format!("Content-Type: {CONTENT_TYPE}")), "{ok}");
        assert!(ok.ends_with("qumbra_prover_queue_depth 0\n"), "{ok}");
        let post = http_get(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        assert!(post.contains("Allow: GET"), "{post}");
        for path in ["/", "/healthz", "/v2/annulet/info", "/metrics?x=1"] {
            let other = http_get(addr, &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
            assert!(other.starts_with("HTTP/1.1 404"), "{path}: {other}");
        }
    }
}
