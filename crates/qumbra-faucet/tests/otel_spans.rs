//! 🔴 **The span tree, end to end, against an in-process exporter** — piece 1 of the
//! svc-lane kit (observability-plan §C.1), plus the two edges that make pieces 2 and
//! 3 provably the *same* trace.
//!
//! | claim | where it is asserted |
//! |---|---|
//! | one span per request, named, with the matched route and the status | [`a_request_produces_one_named_span_with_the_matched_route`] |
//! | resource carries `service.name` + `service.namespace` | same test |
//! | the raw URL never reaches a span attribute or a metric label | [`a_receipt_lookup_is_collapsed_to_a_route_template`] |
//! | `POST /request` has a `faucet.gate` CHILD span | [`the_grant_path_is_a_linked_span_tree_not_a_lie_about_nesting`] |
//! | the grant stages are their own tree, LINKED to the request | same test |
//! | an idle tick emits NOTHING | same test |
//! | the journal `trace_id=` and the exemplar `trace_id` are one id | [`the_log_line_and_the_exemplar_carry_the_same_trace_id`] |
//!
//! **Why this is one integration binary and not unit tests.** `tracing` allows one
//! global subscriber per process. Every test here needs the same installed tracer,
//! so they share it through a `OnceLock` and each filters the recorder by the span
//! attributes it created — which is also why the recorder is never reset.
//!
//! **And why they take a lock.** Sharing one recorder across threads makes any
//! assertion about *what is not there* a race with whatever else is running. This
//! file had exactly that bug for one commit: `an idle tick emits no spans` compared
//! total recorder length before and after, and a concurrent test's request landing
//! in between failed it about one run in ten. Two fixes, both kept, because either
//! alone would leave the next test author to rediscover it: the tests run under a
//! `serial()` mutex, AND the idle assertion counts only the span names that tick
//! can produce.
//!
//! **No proof is run here, deliberately.** The grant tree is exercised on a faucet
//! with no inventory, so `Faucet::dispense` stalls in microseconds and the span tree
//! is identical in shape to the one a real grant produces. A real 2×2 proof is
//! ~2.3 s and ~11.8 GB — `acceptance.rs` runs exactly one and this file runs none.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};

use opentelemetry::trace::{SpanId, TraceId};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use opentelemetry_sdk::Resource;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_faucet::{Faucet, FaucetConfig, FaucetLimits, GrantPlan, TicketPolicy, TicketSecret};
use qlab_node::{genesis_block, ChainStore, MemNode, NodeState};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;
use qumbra_faucet::http::{FaucetServer, TrustedProxies};
use qumbra_faucet::service::{FaucetNode, FaucetService, LocalSubmit};
use qumbra_faucet::state::{Availability, ServiceStatus};
use qumbra_faucet::telemetry::{FaucetMetrics, Telemetry};

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
    metrics: Arc<FaucetMetrics>,
}

/// The lock every test in this binary takes for its whole body. See the module
/// docs: a shared recorder plus parallel tests is a race on every negative
/// assertion. Poisoning is ignored — a panicking test has already failed, and
/// wedging the rest behind it turns one failure into four.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn rig() -> &'static Rig {
    static RIG: OnceLock<Rig> = OnceLock::new();
    RIG.get_or_init(|| {
        let recorder = Recorder::default();
        let metrics = Arc::new(FaucetMetrics::new());
        // Leaked on purpose: the tracer must outlive every test in this binary, and
        // dropping the guard would shut the provider down under a still-running one.
        let telemetry =
            Telemetry::install_with_exporter(recorder.clone(), Arc::clone(&metrics));
        std::mem::forget(telemetry);
        Rig { recorder, metrics }
    })
}

// ---------------------------------------------------------------------------
// A real HTTP/1.1 client — same shape as `acceptance.rs`, so these tests exercise
// sockets rather than handlers
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

fn post_request(addr: SocketAddr, address: &str) -> (u16, String) {
    let body = format!("address={address}");
    http(
        addr,
        &format!(
            "POST /request HTTP/1.1\r\nHost: localhost\r\nContent-Type: \
             application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: \
             close\r\n\r\n{body}",
            body.len()
        ),
    )
}

// ---------------------------------------------------------------------------
// A faucet that admits requests and a node that has nothing to give
// ---------------------------------------------------------------------------

/// The smallest [`FaucetNode`] that answers: one finalized genesis block and no
/// funds. `dispense` against it stalls rather than proving, which is exactly what
/// this file wants — the span tree's shape does not depend on whether the proof ran.
struct EmptyNode {
    node: MemNode,
}

impl EmptyNode {
    fn new() -> EmptyNode {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis);
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
        EmptyNode { node }
    }
}

impl FaucetNode for EmptyNode {
    fn chain_state(&self) -> &MemNode {
        &self.node
    }
    fn submit_local(&mut self, _plan: &GrantPlan) -> LocalSubmit {
        unreachable!("this node is never asked to submit: the faucet holds no notes")
    }
    fn peers(&self) -> u64 {
        0
    }
    fn chain_views(&self) -> qlab_node::StateLag {
        let tip = self.node.tip_height();
        qlab_node::StateLag::new(tip, tip)
    }
}

fn requester_address(seed: u64) -> String {
    Wallet::from_seed_lanes([seed; 4]).address(Diversifier::default()).encode()
}

/// A service in **open mode** — a bare address is admitted, so `Faucet::accept`
/// runs and a receipt is issued without an operator ticket in the fixture.
fn open_service() -> FaucetService {
    let wallet = Wallet::from_seed_lanes([0x0770_0000_0000_0001; 4]);
    let d = Diversifier::default();
    let faucet = Faucet::new(
        wallet.clone(),
        d,
        TicketSecret::from_bytes([0x3B; 32]),
        FaucetConfig {
            limits: FaucetLimits {
                ticket_policy: TicketPolicy::Disabled,
                ..FaucetLimits::default()
            },
            ..FaucetConfig::default()
        },
    );
    FaucetService::new(faucet, wallet, d)
}

/// A status snapshot that admits requests.
///
/// Supplied to the listener directly rather than taken from the service, because
/// the service's own snapshot starts at `Starting` and a `Starting` faucet refuses
/// before `Faucet::accept` — correctly (lab #365), and that refusal is a different
/// test's subject. Nothing about the span tree depends on which of the two the
/// listener reads.
fn admitting_status() -> Arc<Mutex<ServiceStatus>> {
    Arc::new(Mutex::new(ServiceStatus {
        chain: Some(qlab_node::StateLag::new(200, 200)),
        finalized_height: Some(200),
        peers: 3,
        availability: Availability::Ready { grants: 1 },
        queued: 0,
        queue_capacity: 32,
        wait_blocks: 1,
        grant_value: qlab_faucet::DEFAULT_GRANT_BESSEL,
        tickets_required: false,
        confirmed: 0,
        refused: 0,
        notes_held: 2,
        notes_maturing: 0,
    }))
}

fn server_for(service: &FaucetService, metrics: Arc<FaucetMetrics>) -> FaucetServer {
    FaucetServer::start_with_telemetry(
        "127.0.0.1:0",
        service.gate(),
        admitting_status(),
        TrustedProxies::default(),
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
/// resource the plan's standards line pins.
#[test]
fn a_request_produces_one_named_span_with_the_matched_route() {
    let _serial = serial();
    let rig = rig();
    let service = open_service();
    let server = server_for(&service, Arc::clone(&rig.metrics));

    let (status, _) = get(server.addr(), "/healthz");
    assert_eq!(status, 200);
    server.shutdown();

    let span = rig
        .recorder
        .named("faucet.request")
        .into_iter()
        .find(|s| attr(s, "http.route").map(|v| v.to_string()) == Some("/healthz".to_string()))
        .expect("a faucet.request span for /healthz");

    assert_eq!(attr(&span, "http.request.method").map(|v| v.to_string()), Some("GET".into()));
    assert_eq!(
        attr(&span, "http.response.status_code").map(|v| v.to_string()),
        Some("200".into())
    );
    // Nothing about the requester is on the span — not even the subnet the journal
    // line carries. A span leaves the host; the journal line does not.
    for forbidden in ["client.address", "subnet", "http.request.header.x-forwarded-for"] {
        assert!(attr(&span, forbidden).is_none(), "{forbidden} must not be on a span");
    }
    assert!(span.span_context.is_valid(), "the span must carry a real trace id");

    // The resource, from `telemetry::resource()` — the same function `main` uses.
    let resource = rig.recorder.resource().expect("the exporter is given a resource");
    assert_eq!(
        resource.get(&opentelemetry::Key::from_static_str("service.name")).map(|v| v.to_string()),
        Some("qumbra-faucet".to_string())
    );
    assert_eq!(
        resource
            .get(&opentelemetry::Key::from_static_str("service.namespace"))
            .map(|v| v.to_string()),
        Some("qumbra".to_string())
    );
}

/// 🔴 A receipt lookup is `/r/{receipt}` on the span and on the metric label — never
/// `/r/17`. An unbounded route label is both a cardinality bomb and a published
/// record of which receipts somebody went looking at.
#[test]
fn a_receipt_lookup_is_collapsed_to_a_route_template() {
    let _serial = serial();
    let rig = rig();
    let service = open_service();
    let server = server_for(&service, Arc::clone(&rig.metrics));

    assert_eq!(get(server.addr(), "/r/424242").0, 404);
    assert_eq!(get(server.addr(), "/definitely-not-a-route").0, 404);
    server.shutdown();

    let routes: Vec<String> = rig
        .recorder
        .named("faucet.request")
        .iter()
        .filter_map(|s| attr(s, "http.route").map(|v| v.to_string()))
        .collect();
    assert!(routes.contains(&"/r/{receipt}".to_string()), "{routes:?}");
    assert!(routes.contains(&"{unmatched}".to_string()), "{routes:?}");
    assert!(!routes.iter().any(|r| r.contains("424242")), "a receipt reached a span: {routes:?}");
    assert!(
        !routes.iter().any(|r| r.contains("definitely-not-a-route")),
        "a raw path reached a span: {routes:?}"
    );

    let exposition = rig.metrics.encode();
    assert!(exposition.contains("route=\"/r/{receipt}\""), "{exposition}");
    assert!(!exposition.contains("424242"), "a receipt reached a metric label:\n{exposition}");
}

/// 🔴 **The claim the baton's premise needed corrected, asserted as it actually is.**
///
/// The request span has a `faucet.gate` CHILD, because the gate really does run
/// inside the request. The grant stages are a SEPARATE tree — `faucet.grant` with
/// `faucet.harvest` and `faucet.prove` under it — because they really do run later,
/// on the node's loop thread, and that tree carries a **link** to the request span
/// rather than pretending to be nested in it.
///
/// And the last assertion is the one that keeps the whole thing affordable: a tick
/// with an empty queue emits nothing at all.
#[test]
fn the_grant_path_is_a_linked_span_tree_not_a_lie_about_nesting() {
    let _serial = serial();
    let rig = rig();
    let mut service = open_service();
    let mut node = EmptyNode::new();
    let mut rng = rand::rng();

    // (0) An idle tick, BEFORE anything is queued: no spans, at 50 ticks a second
    // for the life of the process.
    //
    // Counted by NAME rather than by recorder length. Length is a claim about the
    // whole process and this recorder is shared; the four names below are the only
    // ones `tick` can produce, and nothing else in this binary produces them.
    let tick_spans = |r: &Recorder| {
        r.spans()
            .iter()
            .filter(|s| {
                matches!(
                    s.name.as_ref(),
                    "faucet.grant" | "faucet.harvest" | "faucet.prove" | "faucet.submit"
                )
            })
            .count()
    };
    let before = tick_spans(&rig.recorder);
    service.tick(&mut node, &mut rng);
    service.tick(&mut node, &mut rng);
    assert_eq!(
        tick_spans(&rig.recorder),
        before,
        "an idle tick must emit NO spans — run_until_with calls it ~50x/s forever"
    );

    // (1) A request that is admitted.
    let server = server_for(&service, Arc::clone(&rig.metrics));
    let address = requester_address(0xC0DE_0100);
    let (status, _) = post_request(server.addr(), &address);
    assert_eq!(status, 202, "open mode admits a bare address");
    server.shutdown();

    let request_span = rig
        .recorder
        .named("faucet.request")
        .into_iter()
        .find(|s| attr(s, "http.route").map(|v| v.to_string()) == Some("/request".to_string()))
        .expect("a faucet.request span for POST /request");

    // (2) …with the gate as a real child: same trace, parent = the request.
    let gate = rig
        .recorder
        .named("faucet.gate")
        .into_iter()
        .find(|s| s.parent_span_id == request_span.span_context.span_id())
        .expect("faucet.gate must be a CHILD of the request span");
    assert_eq!(
        gate.span_context.trace_id(),
        request_span.span_context.trace_id(),
        "a child shares the trace"
    );

    // (3) The tick that tries to serve it: its own tree, linked back.
    service.tick(&mut node, &mut rng);

    let grant = rig.recorder.named("faucet.grant").pop().expect("a faucet.grant span");
    assert_eq!(
        attr(&grant, "faucet.outcome").map(|v| v.to_string()),
        Some("stalled".to_string()),
        "an unfunded faucet stalls — no proof is run in this file"
    );
    assert_eq!(attr(&grant, "faucet.receipt").map(|v| v.to_string()), Some("1".to_string()));

    // 🔴 A LINK, not a parent. This is the edge that makes "request → grant stages"
    // true rather than a diagram: the grant is a different trace, because it is a
    // different unit of work minutes later on a different thread.
    assert_ne!(
        grant.span_context.trace_id(),
        request_span.span_context.trace_id(),
        "the grant is not inside the request's trace"
    );
    assert_ne!(grant.parent_span_id, request_span.span_context.span_id());
    let linked: Vec<(TraceId, SpanId)> = grant
        .links
        .iter()
        .map(|l| (l.span_context.trace_id(), l.span_context.span_id()))
        .collect();
    assert!(
        linked.contains(&(
            request_span.span_context.trace_id(),
            request_span.span_context.span_id()
        )),
        "the grant span must link to the request that queued the receipt: {linked:?}"
    );

    // (4) …and the stages are under it.
    for stage in ["faucet.harvest", "faucet.prove"] {
        let child = rig
            .recorder
            .named(stage)
            .into_iter()
            .find(|s| s.parent_span_id == grant.span_context.span_id());
        assert!(child.is_some(), "{stage} must be a child of faucet.grant");
    }
}

/// 🔴 Pieces 2 and 3 are the SAME id: the token on the journal line is the token in
/// the histogram exemplar is the trace id of the exported span. A trace found from a
/// log line and a trace found from a slow bucket are one trace, or the correlation
/// the plan buys is imaginary.
#[test]
fn the_log_line_and_the_exemplar_carry_the_same_trace_id() {
    let _serial = serial();
    let rig = rig();
    let service = open_service();
    // A private registry for this test, so the exemplar assertion is about the one
    // request below and not about whichever test happened to run first.
    let metrics = Arc::new(FaucetMetrics::new());
    let server = FaucetServer::start_with_telemetry(
        "127.0.0.1:0",
        service.gate(),
        admitting_status(),
        TrustedProxies::default(),
        Arc::clone(&metrics),
    )
    .expect("bind");

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
    // The four fields that were there before it still are, and in order.
    assert!(line.starts_with("FAUCET GET /healthz 200 subnet="), "{line}");

    // …and the same id is the exemplar on the bucket the request landed in.
    let exposition = metrics.encode();
    assert!(
        exposition.contains(&format!("# {{trace_id=\"{id}\"}}")),
        "the exemplar must carry the journal line's id {id}:\n{exposition}"
    );

    // …and it is the trace id of a span that was actually exported.
    let exported: Vec<String> = rig
        .recorder
        .named("faucet.request")
        .iter()
        .map(|s| s.span_context.trace_id().to_string())
        .collect();
    assert!(exported.contains(&id), "no exported span carries {id}: {exported:?}");
}
