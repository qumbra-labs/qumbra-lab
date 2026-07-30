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

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The route this endpoint serves, and the only one.
pub const TELEMETRY_PATH: &str = "/v1/telemetry";

/// Content type for the versioned binary wire. It is bytes, not text: the wire is
/// `RPC_VERSION`-led little-endian fields, and labelling it anything else would
/// invite a reader to treat it as a string.
const CONTENT_TYPE_HEADER: &[u8] = b"Content-Type";
const CONTENT_TYPE_VALUE: &[u8] = b"application/octet-stream";

/// A running `/v1/telemetry` endpoint: bound address + worker thread + the shared
/// snapshot the run loop refreshes.
pub struct TelemetryServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl TelemetryServer {
    /// Bind `addr` and serve `snapshot` at [`TELEMETRY_PATH`] until
    /// [`Self::shutdown`].
    ///
    /// An unbindable address is an **error**, never a silent no-op — a node whose
    /// operator believes it is readable and which is not is exactly the failure
    /// this endpoint exists to remove (the same rule `metrics_server` follows).
    pub fn start(addr: &str, snapshot: Arc<Mutex<Vec<u8>>>) -> io::Result<Self> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("telemetry_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("telemetry listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
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
                if path != TELEMETRY_PATH {
                    let _ = request.respond(
                        tiny_http::Response::from_string(format!("not found: try {TELEMETRY_PATH}"))
                            .with_status_code(404),
                    );
                    continue;
                }
                // Clone under the lock and release it before writing to the socket —
                // a slow or half-dead reader must not hold the snapshot lock while
                // the run loop wants to refresh it.
                let body = snapshot.lock().map(|s| s.clone()).unwrap_or_default();
                let header = tiny_http::Header::from_bytes(CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE)
                    .expect("static content type parses");
                let _ = request.respond(tiny_http::Response::from_data(body).with_header(header));
            }
        });

        Ok(TelemetryServer { addr: bound, server, thread: Some(thread), served })
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
    #[test]
    fn serves_the_telemetry_wire_at_v1_telemetry_over_a_real_socket() {
        let t = sample();
        let snap = Arc::new(Mutex::new(t.to_bytes()));
        let srv = TelemetryServer::start("127.0.0.1:0", Arc::clone(&snap)).expect("bind");
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
        let snap = Arc::new(Mutex::new(sample().to_bytes()));
        let srv = TelemetryServer::start("127.0.0.1:0", Arc::clone(&snap)).expect("bind");
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
        let snap = Arc::new(Mutex::new(Vec::new()));
        assert!(TelemetryServer::start("256.256.256.256:9", snap).is_err());
    }
}
