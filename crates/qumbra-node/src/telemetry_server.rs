//! The `/v1/telemetry` read endpoint (issue #117).
//!
//! ## Why this exists at all
//!
//! `qlab_node::rpc` has served `/v1/telemetry` since M10-T0-2 — but **only
//! in-process**. `NodeRpc` and `qlab_node::rpc::serve` are constructed by that
//! crate's own tests and by nothing else; this binary never built one, `NodeConfig`
//! carried no address for one, and `deploy/docker/docker-compose.yml` publishes no
//! ports. So a T0 node has, until now, shipped **no readable telemetry wire at
//! all**: the only operator surfaces reaching outside the process were the
//! `TELEMETRY` stdout line (readable only by whoever can read the node's logs) and
//! `/metrics`, which is off unless `metrics_addr` is set.
//!
//! An agreement view over a list of node endpoints has nothing to poll without
//! this. It is the precondition, not the feature.
//!
//! ## What it is, and what it deliberately is not
//!
//! Exactly one route, `GET /v1/telemetry`, serving [`qlab_node::Telemetry`]'s
//! versioned bytes — the same wire, from the same encoder, that `qlab_node::rpc`
//! serves in-process. **Not** the wallet-facing RPC: `/v1/status`, `/v1/anchors`,
//! `/v1/compact`, `/v1/…/full` and `/v1/tree/frontier` are not served here, which
//! is why the config key is `telemetry_addr` and not `rpc_addr`. Wiring those is a
//! composition change (this binary's state lives in `qlab_p2p::NodeAdapter`, not in
//! a `qlab_node::NodeRpc`), not a config key, and it is not this issue's job.
//!
//! ## Shape, borrowed wholesale from `metrics_server` (issue #87)
//!
//! - **Off unless `telemetry_addr` is set.** An endpoint that exists only where
//!   somebody asked for it is an endpoint that cannot be forgotten open.
//! - **A pre-rendered snapshot, not live state.** If a poll took the lock on node
//!   state, an observer could contend with the consensus loop and the frequency of
//!   that contention would be set by whoever configured the poller. The node
//!   decides how often it pays; a request costs a clone of ~90 bytes.
//! - **GET only, read-only, no parameters.** No writes, no submission path, no
//!   control endpoint. The query string is ignored, so there is no input surface.
//! - **Binding is an operator act.** `127.0.0.1:9410` keeps it host-local;
//!   `0.0.0.0:9410` exposes it to whatever the host firewall admits, and on a real
//!   host that means pairing it with a source-restricted inbound rule (standalone
//!   `aws_security_group_rule` resources only — the inline-rule incident of
//!   2026-07-26 is why). Nothing here authenticates.
//!
//! ## The staleness the snapshot buys, and why it is safe for THIS question
//!
//! A served snapshot is at most [`crate::run::TELEMETRY_REFRESH`] old, and unlike
//! `/metrics` this wire carries no render timestamp to tell a reader which. That
//! bounded staleness cannot manufacture the alarm this endpoint exists to raise:
//! a finalized checkpoint is never reverted, so a node's `fid` **at a given
//! `finalized_height`** is the same value whenever it is read. A stale snapshot can
//! therefore only make a node look *behind* — which the operator view renders as
//! lag, explicitly not as disagreement — and can never make two honest nodes appear
//! to have finalized different checkpoints at one height.
//!
//! Observation must not become a dependency of the node
//! (`qumbra-design/observability-and-evidence.md` §5.2): the node never learns that
//! anything polled it, never waits for a poller, and behaves identically if every
//! reader vanishes. The only coupling is one `Mutex<Vec<u8>>` the run loop writes.
//!
//! ## `/v1/ready` — the server exists before the node does (lab #373)
//!
//! `RunningNode::start` contains the `blocks.log` replay — hours, on a
//! snapshotless host (#359) — and when this listener was bound *after* it, a
//! healthy replaying host and a dead one were indistinguishable to every HTTP
//! reader (node3 read `UNREACHABLE-OR-SILENT` for 3h34m on 2026-08-11 while
//! replaying 11,751 records). So the server now starts in a **starting** state,
//! owned by the binary rather than spawned by a `RunningNode` method, and is
//! handed the live node when `start` returns
//! ([`crate::run::RunningNode::adopt_telemetry_server`]):
//!
//! - **`GET /v1/ready`** answers from the moment of bind, in BOTH phases — a
//!   stable probe, not a startup-only artifact. Minimal JSON: a `state`
//!   discriminant (`starting`/`ready`), plus the live walk position from
//!   [`qlab_node::live_replay_position`] (#287's own counter, not a second one)
//!   when a replay is in flight: `{"state":"starting","replayed":N,"total":M}`.
//! - **`GET /v1/telemetry`** 404s until the handover, then serves exactly the
//!   bytes it always served. Per the house rule ratified at PR #315 (recorded
//!   at `qlab_node::rpc`): a pure route addition does **not** bump
//!   `RPC_VERSION`, and a 404 is the one capability probe that works across
//!   reader vintages — which is also why "starting" is a 404 here and not a
//!   partial telemetry page: a page of zeroes reads as *healthy and current*
//!   (the `StateLag::default()` mistake #372 deleted from the faucet).
//!
//! What the bound-before-the-node listener answers in the window where no node
//! exists: `/v1/ready` (from the process-global replay counter — no node state
//! is touched), 404 for `/v1/telemetry` and every other path, 405 for non-GET.
//! Nothing it serves in that window can reach node state, so nothing can panic
//! on state that does not exist yet.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The versioned-wire route (issue #117).
pub const TELEMETRY_PATH: &str = "/v1/telemetry";

/// The readiness route (lab #373), served from the moment of bind.
pub const READY_PATH: &str = "/v1/ready";

/// Content type for the versioned binary wire. It is bytes, not text: the wire is
/// `RPC_VERSION`-led little-endian fields, and labelling it anything else would
/// invite a reader to treat it as a string.
const CONTENT_TYPE_HEADER: &[u8] = b"Content-Type";
const CONTENT_TYPE_VALUE: &[u8] = b"application/octet-stream";

/// Content type for `/v1/ready` — JSON, same label the explorer's JSON routes use.
const READY_CONTENT_TYPE: &[u8] = b"application/json; charset=utf-8";

/// The `/v1/ready` body: the state discriminant, plus the live walk position
/// while one is in flight. A free function over its two inputs so the exact
/// bytes are testable without a socket.
///
/// `replay` is meaningful only in the starting state: after the handover no
/// walk is in flight, and before `open` begins (or after the walk ends while
/// the rest of startup runs) an honest `{"state":"starting"}` carries no
/// number it has not got — the #296 rule.
fn ready_body(ready: bool, replay: Option<qlab_node::ReplayPosition>) -> String {
    if ready {
        return r#"{"state":"ready"}"#.to_string();
    }
    match replay {
        Some(p) => format!(
            r#"{{"state":"starting","replayed":{},"total":{}}}"#,
            p.processed, p.total
        ),
        None => r#"{"state":"starting"}"#.to_string(),
    }
}

/// A running telemetry listener: bound address + worker thread + the shared
/// snapshot the run loop refreshes + the readiness latch the handover flips.
pub struct TelemetryServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
    /// The `/v1/telemetry` payload. Owned here (not by `RunningNode`) because
    /// this server may exist before any node does; the node adopts this `Arc`
    /// at handover and refreshes it from then on.
    snapshot: Arc<Mutex<Vec<u8>>>,
    /// `false` from bind until [`Self::mark_ready`]: `/v1/ready` says
    /// `starting` and `/v1/telemetry` 404s. Never cleared — a node is not
    /// un-opened.
    ready: Arc<AtomicBool>,
}

impl TelemetryServer {
    /// Bind `addr` in the **starting** state: [`READY_PATH`] answers from this
    /// moment, [`TELEMETRY_PATH`] 404s until the node exists and
    /// [`crate::run::RunningNode::adopt_telemetry_server`] flips the latch.
    ///
    /// An unbindable address is an **error**, never a silent no-op — a node whose
    /// operator believes it is readable and which is not is exactly the failure
    /// this endpoint exists to remove (the same rule `metrics_server` follows).
    pub fn start(addr: &str) -> io::Result<Self> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("telemetry_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("telemetry listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));
        let snapshot: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let ready = Arc::new(AtomicBool::new(false));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let worker_snapshot = Arc::clone(&snapshot);
        let worker_ready = Arc::clone(&ready);
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                // Read-only means read-only: anything that is not a GET is refused
                // before the path is even looked at.
                if *request.method() != tiny_http::Method::Get {
                    let _ = request.respond(
                        tiny_http::Response::from_string("method not allowed").with_status_code(405),
                    );
                    continue;
                }
                // The query string is ignored: this endpoint takes no parameters, so
                // there is no input surface to get wrong.
                let path = request.url().split('?').next().unwrap_or("").to_string();
                if path == READY_PATH {
                    // Served in BOTH phases (a ready node answers `ready`), so the
                    // route is a stable probe. The position is read per request from
                    // the process-global walk counter — the one thing that exists
                    // while `Node::open` still runs; no node state is touched.
                    let body = ready_body(
                        worker_ready.load(Ordering::Acquire),
                        qlab_node::live_replay_position(),
                    );
                    let header =
                        tiny_http::Header::from_bytes(CONTENT_TYPE_HEADER, READY_CONTENT_TYPE)
                            .expect("static content type parses");
                    let _ =
                        request.respond(tiny_http::Response::from_string(body).with_header(header));
                    continue;
                }
                if path != TELEMETRY_PATH {
                    let _ = request.respond(
                        tiny_http::Response::from_string(format!(
                            "not found: try {TELEMETRY_PATH} or {READY_PATH}"
                        ))
                        .with_status_code(404),
                    );
                    continue;
                }
                // Lab #373: before the handover there is no node and therefore no
                // telemetry. A 404 — not a partial page — because a reader's
                // `Reader::version` equality check makes 404-vs-200 the one probe
                // that works across vintages, and a page of zeroes reads as
                // healthy (the faucet's deleted `StateLag::default()` mistake).
                if !worker_ready.load(Ordering::Acquire) {
                    let _ = request.respond(
                        tiny_http::Response::from_string(format!(
                            "not found: the node is still starting; try {READY_PATH}"
                        ))
                        .with_status_code(404),
                    );
                    continue;
                }
                // Clone under the lock and release it before writing to the socket —
                // a slow or half-dead reader must not hold the snapshot lock while
                // the run loop wants to refresh it.
                let body = worker_snapshot.lock().map(|s| s.clone()).unwrap_or_default();
                let header = tiny_http::Header::from_bytes(CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE)
                    .expect("static content type parses");
                let _ = request.respond(tiny_http::Response::from_data(body).with_header(header));
            }
        });

        Ok(TelemetryServer { addr: bound, server, thread: Some(thread), served, snapshot, ready })
    }

    /// The snapshot slot this server serves — the node adopts this `Arc` at
    /// handover so its refresh cadence writes what this server reads.
    pub(crate) fn snapshot(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.snapshot)
    }

    /// Flip the latch: `/v1/ready` answers `ready`, `/v1/telemetry` serves.
    /// Called by [`crate::run::RunningNode::adopt_telemetry_server`] AFTER the
    /// first real snapshot is in place, so the first 200 is never empty bytes.
    pub(crate) fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// The bound address (useful when the config asked for port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Requests handled since start (including 404s and 405s).
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// Stop serving and join the worker.
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::telemetry::LocalCommitment;
    use qlab_node::Telemetry;
    use qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS as MAX_LAG;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// A minimal HTTP/1.1 GET returning (status line, body bytes), so the test
    /// exercises the real socket path rather than the handler in isolation.
    fn get(addr: SocketAddr, path: &str) -> (String, Vec<u8>) {
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).expect("read");
        let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
        let head = String::from_utf8_lossy(&raw[..sep]).to_string();
        let status = head.lines().next().unwrap_or_default().to_string();
        (status, raw[sep + 4..].to_vec())
    }

    fn sample() -> Telemetry {
        Telemetry::assemble_with_halt(3800, Some(3776), 1800, 0, 3, 2, MAX_LAG, None)
            .with_checkpoint(
                Some(0x3f1a_9c2b_0d41),
                Some(LocalCommitment { slot: 3776, id: Some(0x3f1a_9c2b_0d41) }),
            )
    }

    /// The read path end to end over a real socket: the served bytes decode back to
    /// the exact snapshot the node put there, checkpoint identity included.
    ///
    /// The body is compared through `Telemetry::from_bytes` rather than byte-for-
    /// byte alone, because "the wire the view actually parses" is the property
    /// under test — a framing change that broke decoding while preserving the bytes
    /// would still be a break.
    /// Bind a server and put it in the served state the pre-#373 code was born
    /// in: snapshot in place, latch flipped — the same two steps
    /// `adopt_telemetry_server` performs, minus the node.
    fn started_ready(t: &Telemetry) -> (TelemetryServer, Arc<Mutex<Vec<u8>>>) {
        let srv = TelemetryServer::start("127.0.0.1:0").expect("bind");
        let snap = srv.snapshot();
        *snap.lock().unwrap() = t.to_bytes();
        srv.mark_ready();
        (srv, snap)
    }

    #[test]
    fn serves_the_telemetry_wire_at_v1_telemetry_over_a_real_socket() {
        let t = sample();
        let (srv, snap) = started_ready(&t);
        let addr = srv.addr();

        let (status, body) = get(addr, TELEMETRY_PATH);
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(body, t.to_bytes());
        let decoded = Telemetry::from_bytes(&body).expect("the served bytes are the versioned wire");
        assert_eq!(decoded, t);
        assert_eq!(decoded.fid_field(), "3f1a9c2b0d41", "the field this issue exists for");

        // A refreshed snapshot is what the next read sees.
        let later = t.clone().with_checkpoint(Some(0x00_0000_0002), None);
        *snap.lock().unwrap() = later.to_bytes();
        let (_, body2) = get(addr, TELEMETRY_PATH);
        assert_eq!(Telemetry::from_bytes(&body2).unwrap(), later);

        // Query strings are ignored rather than being an input surface.
        let (s3, body3) = get(addr, "/v1/telemetry?anything=1");
        assert!(s3.starts_with("HTTP/1.1 200"));
        assert_eq!(body3, later.to_bytes());

        srv.shutdown();
    }

    /// Nothing else is served. In particular the wallet-facing RPC routes are 404
    /// here and not half-implemented — the config key is `telemetry_addr` because
    /// this is not an RPC server, and the 404s are how that promise is kept.
    #[test]
    fn only_v1_telemetry_is_served_and_writes_are_refused() {
        let (srv, _snap) = started_ready(&sample());
        let addr = srv.addr();

        for path in ["/", "/metrics", "/v1/status", "/v1/anchors", "/v1/compact?from=0&to=1"] {
            let (status, _) = get(addr, path);
            assert!(status.starts_with("HTTP/1.1 404"), "{path} => {status}");
        }

        // A non-GET is refused before the path is examined.
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(s, "POST {TELEMETRY_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).expect("read");
        assert!(raw.starts_with("HTTP/1.1 405"), "{raw}");

        srv.shutdown();
    }

    /// A bad `telemetry_addr` fails loudly at start rather than silently leaving
    /// the node unreadable — a node its operator believes is observable and is not
    /// is the failure mode this whole surface exists to remove.
    #[test]
    fn an_unbindable_address_is_an_error_not_a_silent_no_op() {
        assert!(TelemetryServer::start("256.256.256.256:9").is_err());
    }

    /// **Lab #373, the starting window over a real socket**: from the moment of
    /// bind `/v1/ready` answers — `starting` bare, `starting` with the live walk
    /// position while one is in flight, and (crucially for a probe) it degrades
    /// back to bare `starting` when the walk ends rather than freezing a
    /// percentage — while `/v1/telemetry` 404s throughout. Then the handover's
    /// two steps flip the same listener to `ready` + the exact wire bytes.
    ///
    /// The position is driven through a real `ReplayProgress`, because that is
    /// the counter the route reads in production — not a second one.
    #[test]
    fn ready_answers_from_bind_with_the_live_walk_position_and_telemetry_404s_until_ready() {
        // The walk counter is a process global: serialize against any other test
        // that starts a ReplayProgress (the capture gate is that serialization).
        let (_, _lines) = qlab_node::with_progress_capture(|| {
            let srv = TelemetryServer::start("127.0.0.1:0").expect("bind");
            let addr = srv.addr();

            // Bound, no node, no walk: an honest bare `starting`.
            let (status, body) = get(addr, READY_PATH);
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
            assert_eq!(body, br#"{"state":"starting"}"#);

            // …and the versioned wire is ABSENT, not zeroed: 404, named hint.
            let (status, body) = get(addr, TELEMETRY_PATH);
            assert!(status.starts_with("HTTP/1.1 404"), "{status}");
            assert!(
                String::from_utf8_lossy(&body).contains(READY_PATH),
                "the refusal points a reader at the probe that does answer"
            );

            // A walk in flight: the route carries #287's own counter.
            let mut p = qlab_node::ReplayProgress::start(4, "from genesis");
            p.tick();
            p.tick();
            let (status, body) = get(addr, READY_PATH);
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
            assert_eq!(body, br#"{"state":"starting","replayed":2,"total":4}"#);
            let (status, _) = get(addr, TELEMETRY_PATH);
            assert!(status.starts_with("HTTP/1.1 404"), "still starting: {status}");

            // Walk over (drop retires the counter), node not yet handed over:
            // back to bare `starting` — never a frozen 2/4.
            drop(p);
            let (_, body) = get(addr, READY_PATH);
            assert_eq!(body, br#"{"state":"starting"}"#);

            // The handover, exactly as `adopt_telemetry_server` performs it:
            // snapshot first, latch second — the first 200 is never empty.
            let t = sample();
            *srv.snapshot().lock().unwrap() = t.to_bytes();
            srv.mark_ready();

            let (status, body) = get(addr, READY_PATH);
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
            assert_eq!(body, br#"{"state":"ready"}"#, "a stable probe, not a startup artifact");
            let (status, body) = get(addr, TELEMETRY_PATH);
            assert!(status.starts_with("HTTP/1.1 200"), "the 404-then-200 transition: {status}");
            assert_eq!(body, t.to_bytes(), "byte-identical to the pre-#373 wire");

            srv.shutdown();
        });
    }

    /// House rule (ratified PR #315, recorded at `qlab_node::rpc`): a pure route
    /// addition does not bump `RPC_VERSION`. `/v1/ready` remains a pure addition;
    /// #553 legitimately moved the shared node-RPC release boundary to `0x07`
    /// when the existing mine routes changed shape.
    #[test]
    fn the_ready_route_remains_a_pure_addition_at_the_current_rpc_version() {
        assert_eq!(qlab_node::RPC_VERSION, 0x07);
    }
}
