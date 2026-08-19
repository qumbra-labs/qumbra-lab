//! 🔴 **The span tree, end to end, against an in-process exporter** — piece 1 of
//! the svc-lane kit (observability-plan §C.1) on the explorer, plus the two edges
//! that make pieces 2 and 3 provably the *same* trace.
//!
//! | claim | where it is asserted |
//! |---|---|
//! | one span per request, named, with the matched route and the status | [`a_request_produces_one_named_span_with_the_matched_route`] |
//! | resource carries `service.name` + `service.namespace` | same test |
//! | the raw path never reaches a span attribute or a metric label | [`a_probe_path_is_collapsed_and_never_reaches_a_span_or_label`] |
//! | a range request has an `explorer.page_build` CHILD span | [`a_range_request_has_a_page_build_child_span`] |
//! | the projection walks emit spans, and ONLY when the chain moved | [`the_projection_walks_emit_spans_only_when_the_chain_moved`] |
//! | the journal `trace_id=` and the exemplar `trace_id` are one id | [`the_log_line_and_the_exemplar_carry_the_same_trace_id`] |
//!
//! **Why one integration binary, and why every test takes a lock**: `tracing`
//! allows one global subscriber per process, so the tests share one installed
//! tracer through a `OnceLock` — and a shared recorder plus parallel tests makes
//! every negative assertion a race. The faucet's `otel_spans.rs` paid for that
//! lesson with a real one-in-ten flake; both of its fixes are inherited here
//! unchanged: a `serial()` mutex, and negatives counted by the span names the
//! code under test can produce rather than by recorder length.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use opentelemetry_sdk::Resource;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{genesis_block, MemNode};
use qumbra_explorer::http::{ExplorerServer, Surfaces, UNMATCHED_ROUTE};
use qumbra_explorer::telemetry::{ExplorerMetrics, Telemetry};
use qumbra_explorer::{blocks, names, txlist};

// ---------------------------------------------------------------------------
// An in-process span exporter that keeps what it is given
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Recorder {
    spans: Arc<Mutex<Vec<SpanData>>>,
    resource: Arc<Mutex<Option<Resource>>>,
}

impl Recorder {
    fn spans(&self) -> Vec<SpanData> {
        self.spans.lock().expect("recorder lock").clone()
    }

    fn named(&self, name: &str) -> Vec<SpanData> {
        self.spans().into_iter().filter(|s| s.name == name).collect()
    }

    fn resource(&self) -> Option<Resource> {
        self.resource.lock().expect("resource lock").clone()
    }
}

impl SpanExporter for Recorder {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        self.spans.lock().expect("recorder lock").extend(batch);
        std::future::ready(Ok(()))
    }

    fn set_resource(&mut self, resource: &Resource) {
        *self.resource.lock().expect("resource lock") = Some(resource.clone());
    }
}

// ---------------------------------------------------------------------------
// One installed tracer for the whole binary
// ---------------------------------------------------------------------------

struct Rig {
    recorder: Recorder,
    metrics: Arc<ExplorerMetrics>,
}

/// The lock every test in this binary takes for its whole body — see the module
/// docs. Poisoning is ignored: a panicking test has already failed, and wedging
/// the rest behind it turns one failure into four.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn rig() -> &'static Rig {
    static RIG: OnceLock<Rig> = OnceLock::new();
    RIG.get_or_init(|| {
        let recorder = Recorder::default();
        let metrics = Arc::new(ExplorerMetrics::new());
        // Leaked on purpose: the tracer must outlive every test in this binary,
        // and dropping the guard would shut the provider down under a
        // still-running one.
        let telemetry = Telemetry::install_with_exporter(recorder.clone(), Arc::clone(&metrics));
        std::mem::forget(telemetry);
        Rig { recorder, metrics }
    })
}

// ---------------------------------------------------------------------------
// A real HTTP/1.1 client — sockets, not handlers
// ---------------------------------------------------------------------------

fn http(addr: SocketAddr, raw: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(raw.as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let status = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {out}"));
    (status, out)
}

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    http(addr, &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
}

fn server_for(metrics: Arc<ExplorerMetrics>) -> ExplorerServer {
    ExplorerServer::start_with_telemetry(
        "127.0.0.1:0",
        Surfaces {
            health: Arc::new(RwLock::new("{\"v\":1}".to_string())),
            ..Surfaces::default()
        },
        metrics,
    )
    .expect("bind")
}

fn attr<'a>(span: &'a SpanData, key: &str) -> Option<&'a opentelemetry::Value> {
    span.attributes.iter().find(|kv| kv.key.as_str() == key).map(|kv| &kv.value)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// 🔴 One request, one span, and the span says what the request was — with the
/// resource the plan's standards line pins. Every route the gate comment names
/// (R1–R4 included) takes the same seam, so one pre-serialized route and one
/// range route stand in for all of them here; the route table itself is
/// exercised in `http.rs`'s own tests.
#[test]
fn a_request_produces_one_named_span_with_the_matched_route() {
    let _serial = serial();
    let rig = rig();
    let server = server_for(Arc::clone(&rig.metrics));

    assert_eq!(get(server.addr(), "/healthz").0, 200);
    assert_eq!(get(server.addr(), "/v1/health.json").0, 200);
    // Shutdown joins the worker, so the spans below are guaranteed exported.
    server.shutdown();

    for (route, expect_status) in [("/healthz", "200"), ("/v1/health.json", "200")] {
        let span = rig
            .recorder
            .named("explorer.request")
            .into_iter()
            .find(|s| attr(s, "http.route").map(|v| v.to_string()) == Some(route.to_string()))
            .unwrap_or_else(|| panic!("an explorer.request span for {route}"));
        assert_eq!(
            attr(&span, "http.request.method").map(|v| v.to_string()),
            Some("GET".into()),
            "{route}"
        );
        assert_eq!(
            attr(&span, "http.response.status_code").map(|v| v.to_string()),
            Some(expect_status.to_string()),
            "{route}"
        );
        // Nothing about the client is on a span — this surface records no client
        // identity anywhere, and a span leaves the host.
        for forbidden in ["client.address", "subnet", "http.request.header.x-forwarded-for"] {
            assert!(attr(&span, forbidden).is_none(), "{forbidden} must not be on a span");
        }
        assert!(span.span_context.is_valid(), "the span must carry a real trace id");
    }

    // The resource, from `telemetry::resource()` — the same function `main` uses.
    let resource = rig.recorder.resource().expect("the exporter is given a resource");
    assert_eq!(
        resource.get(&opentelemetry::Key::from_static_str("service.name")).map(|v| v.to_string()),
        Some("qumbra-explorer".to_string())
    );
    assert_eq!(
        resource
            .get(&opentelemetry::Key::from_static_str("service.namespace"))
            .map(|v| v.to_string()),
        Some("qumbra".to_string())
    );
}

/// 🔴 A probe path is `{unmatched}` on the span and on the metric label — never
/// the raw path. On this surface that is not only a cardinality rule: an
/// unmatched path can carry a NAME (`/v1/names/larry`), the exact thing the
/// resolve-by-name refusal exists to avoid learning, and it must not survive
/// into a span, a label, or the journal.
#[test]
fn a_probe_path_is_collapsed_and_never_reaches_a_span_or_label() {
    let _serial = serial();
    let rig = rig();
    let server = server_for(Arc::clone(&rig.metrics));

    assert_eq!(get(server.addr(), "/v1/names/larry").0, 404);
    assert_eq!(get(server.addr(), "/v1/tx/deadbeef").0, 404);
    let post = http(
        server.addr(),
        "POST /v1/txlist HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
    );
    assert_eq!(post.0, 405);
    let journal = server.journal();
    server.shutdown();

    let routes: Vec<String> = rig
        .recorder
        .named("explorer.request")
        .iter()
        .filter_map(|s| attr(s, "http.route").map(|v| v.to_string()))
        .collect();
    assert!(routes.contains(&UNMATCHED_ROUTE.to_string()), "{routes:?}");
    for leaked in ["larry", "deadbeef"] {
        assert!(
            !routes.iter().any(|r| r.contains(leaked)),
            "a raw path reached a span: {routes:?}"
        );
    }

    let exposition = rig.metrics.encode();
    assert!(exposition.contains(&format!("route=\"{UNMATCHED_ROUTE}\"")), "{exposition}");
    assert!(!exposition.contains("larry"), "a probed name reached a metric label:\n{exposition}");

    // …and the journal logs the token, not the path — the module docs' rule.
    assert!(
        journal.iter().any(|l| l.contains(UNMATCHED_ROUTE)),
        "the journal logs the unmatched token: {journal:?}"
    );
    assert!(
        !journal.iter().any(|l| l.contains("larry")),
        "a probed name reached the journal: {journal:?}"
    );
}

/// The per-request "page build" — the range walk + encode — is a CHILD of the
/// request span: same trace, parent = the request. The pre-serialized routes
/// have no child, which is also asserted so the child stays meaningful.
#[test]
fn a_range_request_has_a_page_build_child_span() {
    let _serial = serial();
    let rig = rig();
    let server = server_for(Arc::clone(&rig.metrics));

    assert_eq!(get(server.addr(), "/v1/txlist?from=0&to=10").0, 200);
    assert_eq!(get(server.addr(), "/healthz").0, 200);
    server.shutdown();

    let request = rig
        .recorder
        .named("explorer.request")
        .into_iter()
        .find(|s| attr(s, "http.route").map(|v| v.to_string()) == Some("/v1/txlist".to_string()))
        .expect("an explorer.request span for /v1/txlist");
    let child = rig
        .recorder
        .named("explorer.page_build")
        .into_iter()
        .find(|s| s.parent_span_id == request.span_context.span_id())
        .expect("explorer.page_build must be a CHILD of the request span");
    assert_eq!(
        child.span_context.trace_id(),
        request.span_context.trace_id(),
        "a child shares the trace"
    );
    assert_eq!(
        attr(&child, "http.route").map(|v| v.to_string()),
        Some("/v1/txlist".to_string())
    );

    // A pre-serialized route is one string clone and gets no page_build child.
    let healthz = rig
        .recorder
        .named("explorer.request")
        .into_iter()
        .filter(|s| attr(s, "http.route").map(|v| v.to_string()) == Some("/healthz".to_string()))
        .map(|s| s.span_context.span_id())
        .collect::<Vec<_>>();
    assert!(
        !rig.recorder
            .named("explorer.page_build")
            .iter()
            .any(|s| healthz.contains(&s.parent_span_id)),
        "/healthz must not grow a page_build child"
    );
}

/// 🔴 The projection walks are spans — including R4's incremental walk, the one
/// the task book names — and a loop pass over an UNCHANGED chain emits none.
/// The run loop calls these every iteration forever, so the negative is what
/// keeps the instrumentation affordable (the faucet's idle-tick rule).
#[test]
fn the_projection_walks_emit_spans_only_when_the_chain_moved() {
    let _serial = serial();
    let rig = rig();

    let node = MemNode::in_memory(genesis_block(GENESIS_DIFFICULTY, 0));
    let txlist_slot = Arc::new(Mutex::new(Arc::new(txlist::TxListView::default())));
    let blocks_slot = Arc::new(Mutex::new(Arc::new(blocks::BlocksView::default())));
    let names_slot = Arc::new(Mutex::new(Arc::new(names::NameEventsView::default())));

    let walk_count = |r: &Recorder, name: &str| r.named(name).len();
    let names_of = ["explorer.txlist_walk", "explorer.blocks_walk", "explorer.names_walk"];
    let before: Vec<usize> = names_of.iter().map(|n| walk_count(&rig.recorder, n)).collect();

    // First projection: the chain moved (from "never projected"), so each walk
    // runs and each emits exactly one span.
    assert!(txlist::refresh_shared(&txlist_slot, node.chain()));
    assert!(blocks::refresh_shared(&blocks_slot, node.chain()));
    assert!(names::refresh_shared(&names_slot, node.chain()));
    for (i, n) in names_of.iter().enumerate() {
        assert_eq!(
            walk_count(&rig.recorder, n),
            before[i] + 1,
            "{n} must emit one span for a real walk"
        );
    }

    // Steady chain: the cheap tip check answers first — no walk, NO span.
    assert!(!txlist::refresh_shared(&txlist_slot, node.chain()));
    assert!(!blocks::refresh_shared(&blocks_slot, node.chain()));
    assert!(!names::refresh_shared(&names_slot, node.chain()));
    for (i, n) in names_of.iter().enumerate() {
        assert_eq!(
            walk_count(&rig.recorder, n),
            before[i] + 1,
            "{n} must emit NOTHING on an unchanged chain — the run loop calls this forever"
        );
    }
}

/// 🔴 Pieces 2 and 3 are the SAME id: the token on the journal line is the token
/// in the histogram exemplar is the trace id of the exported span. A trace found
/// from a log line and a trace found from a slow bucket are one trace, or the
/// correlation the plan buys is imaginary.
#[test]
fn the_log_line_and_the_exemplar_carry_the_same_trace_id() {
    let _serial = serial();
    let rig = rig();
    // A private registry for this test, so the exemplar assertion is about the
    // one request below and not whichever test ran first.
    let metrics = Arc::new(ExplorerMetrics::new());
    let server = server_for(Arc::clone(&metrics));

    assert_eq!(get(server.addr(), "/healthz").0, 200);
    let journal = server.journal();
    server.shutdown();

    let line = journal.iter().find(|l| l.contains("/healthz")).expect("a journal line");
    // The exact token shape the Loki derived-field regex matches.
    let id = line
        .split("trace_id=")
        .nth(1)
        .expect("the journal line must carry trace_id=")
        .trim()
        .to_string();
    assert_eq!(id.len(), 32, "trace_id must be 32 hex characters: {line}");
    assert!(
        id.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "trace_id must match [0-9a-f]{{32}}: {line}"
    );
    assert_ne!(id, "0".repeat(32), "an all-zero trace id is the lie, not the feature");
    // The fields before it, in order: method, matched route, status — and no
    // client field between them and the id.
    assert!(line.starts_with("EXPLORER GET /healthz 200 trace_id="), "{line}");

    // …and the same id is the exemplar on the bucket the request landed in.
    let exposition = metrics.encode();
    assert!(
        exposition.contains(&format!("# {{trace_id=\"{id}\"}}")),
        "the exemplar must carry the journal line's id {id}:\n{exposition}"
    );

    // …and it is the trace id of a span that was actually exported.
    let exported: Vec<String> = rig
        .recorder
        .named("explorer.request")
        .iter()
        .map(|s| s.span_context.trace_id().to_string())
        .collect();
    assert!(exported.contains(&id), "no exported span carries {id}: {exported:?}");
}
