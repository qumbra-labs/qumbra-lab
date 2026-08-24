//! Reading `/v1/telemetry` from a configured list of node endpoints.
//!
//! # A node that does not answer is not a node that disagrees
//!
//! This module exists mostly to keep those two apart. A timeout is **missing
//! evidence**; a different `fid` at the same height is **conflicting evidence**.
//! Rendering the first as the second would produce exactly the false alarm the
//! agreement view exists to prevent — and an alarm that cries wolf on a restart or
//! a firewall rule is an alarm an operator learns to ignore, which is worse than
//! not having one.
//!
//! So every failure mode of a read — DNS, connect, deadline, a non-200, a body
//! that is not the versioned wire, a version this build does not speak — lands in
//! [`Reading::Unreachable`] with its reason, and [`crate::agree`] computes
//! agreement over the nodes that *answered*.
//!
//! # A host that has not been rolled yet is a THIRD thing (issue #212)
//!
//! It is neither missing evidence nor conflicting evidence: it answers, its
//! pre-existing fields are all readable and true, and the field the newest bump
//! added is simply not on its wire. Rendering that as `Unreachable` would take the
//! whole cross-host comparison offline for the length of a roll — T0 rolls one host
//! at a time, and the last full roll took 23 minutes — which is how a version bump
//! reintroduces exactly the blindness it was made to remove.
//!
//! So this module reads every version in
//! [`READABLE_TELEMETRY_VERSIONS`] and keeps the one it read, on
//! [`Reading::Ok::wire_version`]. That is what lets [`crate::agree`] say *"node0
//! predates this field"* instead of `-`.
//!
//! # Deadlines
//!
//! Every endpoint gets the same wall-clock budget ([`PollOptions::timeout`]),
//! applied to connect, write and read. **DNS resolution is the one step std gives
//! no deadline for**, so a name that resolves slowly can exceed the budget; on the
//! docker harness and on a hosts-file deployment the endpoints resolve locally, and
//! an operator polling by IP has no exposure at all. Named honestly rather than
//! papered over.
//!
//! # Simultaneity
//!
//! The endpoints are polled **concurrently**, one thread each. That is not for
//! speed — with four nodes and a 3 s budget the serial worst case is 12 s, which
//! nobody would notice. It is because the comparison is only as good as how close
//! together the samples were taken: four readings spread over 12 s of a live chain
//! would show height skew that is an artifact of the poll, not of the net.
//!
//! # The node does not know this exists
//!
//! A plain HTTP GET against a read-only endpoint. Nothing here writes, submits, or
//! controls anything; nothing registers; nothing is retried in a way a node could
//! feel. If this tool never runs, the net is unchanged
//! (`observability-and-evidence.md` §5.2).

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use qlab_node::{Telemetry, DURABLE_HEAD_SINCE_VERSION, READABLE_TELEMETRY_VERSIONS};

/// The route a node serves its versioned telemetry wire on.
pub const TELEMETRY_PATH: &str = "/v1/telemetry";

/// The default per-endpoint deadline.
///
/// Chosen against what it is measuring, not by taste: a node's snapshot is
/// re-encoded on a 5 s cadence and the chain moves on a FROZEN 75 s block time, so
/// a read that has not completed in three seconds is not "slow", it is a node with
/// a problem — which is a thing the operator wants rendered, promptly, as
/// unreachable-with-a-reason rather than waited on.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// One configured node endpoint. The label is what the operator calls the host;
/// it never comes from the node, because a node naming itself in a view about
/// whether nodes are honest would be a strange thing to trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub label: String,
    /// `http://host:port` — the base, without the path.
    pub base_url: String,
}

impl Endpoint {
    /// Parse one configured entry: `label=http://host:port`, or `http://host:port`
    /// alone (in which case the authority is its own label). A bare `host:port` is
    /// accepted and assumed `http://`, because that is what an operator types.
    pub fn parse(s: &str) -> Result<Endpoint, String> {
        let (label, url) = match s.split_once('=') {
            // Don't split "http://host:port" on the '=' of a query string, and don't
            // mistake a scheme for a label.
            Some((l, u)) if !l.contains("//") && !l.is_empty() => (l.to_string(), u.to_string()),
            _ => (String::new(), s.to_string()),
        };
        let url = if url.starts_with("http://") { url } else { format!("http://{url}") };
        let authority = url.trim_start_matches("http://");
        if authority.is_empty() || !authority.contains(':') {
            return Err(format!("endpoint `{s}` needs a host:port"));
        }
        let label = if label.is_empty() { authority.to_string() } else { label };
        Ok(Endpoint { label, base_url: url })
    }
}

/// How to poll.
#[derive(Clone, Copy, Debug)]
pub struct PollOptions {
    /// Per-endpoint deadline for connect, write and read.
    pub timeout: Duration,
}

impl Default for PollOptions {
    fn default() -> Self {
        Self { timeout: DEFAULT_TIMEOUT }
    }
}

/// What one endpoint said, or why it said nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// The node answered with a telemetry snapshot this build can decode, at the
    /// wire version it was stamped with.
    Ok {
        telemetry: Box<Telemetry>,
        /// **Which wire version the body carried** (issue #212) — a member of
        /// [`qlab_node::READABLE_TELEMETRY_VERSIONS`].
        ///
        /// Carried because it is the only thing that can attribute an absent field.
        /// A `0x03` node predates the durable head entirely and a `0x04` node whose
        /// composition does not inject one reports it absent; those decode to the
        /// same [`qlab_node::DurableView::Unavailable`] and are entirely different
        /// facts. During a one-host-at-a-time roll the first is the state of most of
        /// the net, and rendering it as the second would say the durable head is
        /// unreadable on hosts where it is merely not deployed yet.
        wire_version: u8,
    },
    /// The node did not answer, or answered something this build cannot read. The
    /// string is the operator-facing reason, and it is carried rather than
    /// collapsed to a boolean because "connection refused" and "unknown wire
    /// version 0x01" are entirely different problems with entirely different fixes.
    Unreachable(String),
}

impl Reading {
    /// A decoded snapshot, at whatever wire version served it.
    pub fn telemetry(&self) -> Option<&Telemetry> {
        match self {
            Reading::Ok { telemetry, .. } => Some(telemetry),
            Reading::Unreachable(_) => None,
        }
    }
    /// The wire version this node served, when it served one.
    pub fn wire_version(&self) -> Option<u8> {
        match self {
            Reading::Ok { wire_version, .. } => Some(*wire_version),
            Reading::Unreachable(_) => None,
        }
    }
    /// **Whether this node's wire carries the durable head at all** (issue #212).
    ///
    /// `false` on a host that has not been rolled yet — which is not the same as a
    /// host that carries the field and reports it absent.
    pub fn wire_carries_durable_head(&self) -> bool {
        self.wire_version().is_some_and(|v| v >= DURABLE_HEAD_SINCE_VERSION)
    }
    pub fn is_reachable(&self) -> bool {
        matches!(self, Reading::Ok { .. })
    }
}

/// One endpoint's reading, with the caliper on it.
#[derive(Clone, Debug)]
pub struct NodeReading {
    pub endpoint: Endpoint,
    pub reading: Reading,
    /// How long this read took, wall clock. Reported so a "3/4 reachable" line can
    /// be read alongside how close to the deadline the other three were.
    pub elapsed: Duration,
}

/// Poll every endpoint concurrently and return the readings **in the configured
/// order**, so the rendered table is stable across runs regardless of which node
/// answered first.
pub fn poll_all(endpoints: &[Endpoint], opts: PollOptions) -> Vec<NodeReading> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = endpoints
            .iter()
            .map(|e| scope.spawn(move || poll_one(e, opts)))
            .collect();
        handles
            .into_iter()
            .zip(endpoints)
            .map(|(h, e)| {
                h.join().unwrap_or_else(|_| NodeReading {
                    endpoint: e.clone(),
                    // A panicked reader is this tool's fault, not the node's, and
                    // must not be rendered as anything about the node.
                    reading: Reading::Unreachable("poll thread panicked (opview bug)".to_string()),
                    elapsed: Duration::ZERO,
                })
            })
            .collect()
    })
}

/// Read one endpoint. Never panics and never returns an error: every failure is a
/// [`Reading::Unreachable`] carrying its reason.
pub fn poll_one(endpoint: &Endpoint, opts: PollOptions) -> NodeReading {
    let started = Instant::now();
    let reading = match fetch(&endpoint.base_url, TELEMETRY_PATH, opts.timeout) {
        Err(e) => Reading::Unreachable(e),
        // Issue #212: `from_bytes_compat`, not `from_bytes`. A bump would otherwise
        // make this tool read NOTHING from every host still on the previous image,
        // for the whole length of a one-host-at-a-time roll — and its verdict is
        // cross-host agreement, which an instrument seeing two of four hosts cannot
        // answer. The set is bounded and named (`READABLE_TELEMETRY_VERSIONS`), the
        // version is kept, and everything outside the set is still refused.
        Ok(body) => match Telemetry::from_bytes_compat(&body) {
            Ok((wire_version, t)) => Reading::Ok { telemetry: Box::new(t), wire_version },
            // A decode failure is NOT a disagreement either. The commonest cause is
            // a node built before a bump this build no longer reads, whose wire it
            // refuses on purpose rather than best-effort parsing.
            Err(e) => Reading::Unreachable(format!(
                "answered, but the body is not a telemetry wire this build reads: {e:?} \
                 (this build reads wire versions {READABLE_TELEMETRY_VERSIONS:?}; \
                 older nodes report 0x01 or 0x02)"
            )),
        },
    };
    NodeReading { endpoint: endpoint.clone(), reading, elapsed: started.elapsed() }
}

/// A minimal HTTP/1.1 GET with a hard deadline on connect, write and read.
///
/// Deliberately not `qlab_cbserver::client::http_get`: that one is the light-client
/// scan's helper on the ratified compact-block path and has **no deadline**, so a
/// node that accepts a connection and then goes quiet would hang this view for the
/// OS default (~75 s on Linux/macOS) — turning "one node is sick" into "the
/// operator's view is hung", which is the failure this tool is supposed to report
/// rather than reproduce. Reaching into that crate to add deadlines for an operator
/// tool would couple two unrelated surfaces. Response framing is shared
/// ([`qlab_http_framing`], lab #631); the deadline and the GET still live here.
fn fetch(base_url: &str, path: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or_else(|| format!("`{base_url}` must start with http://"))?;

    // NOTE: std gives no deadline for resolution. See the module docs.
    let addr = authority
        .to_socket_addrs()
        .map_err(|e| format!("resolve {authority}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {authority}: no address"))?;

    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| format!("set read timeout: {e}"))?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| format!("set write timeout: {e}"))?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;

    // Lab #631: honour the framing the server sent. The pre-#631 reader
    // de-chunked but ignored `Content-Length`, so a keep-alive peer hung
    // this view to its read timeout — turning "one node is sick" into "the
    // operator's view is hung", which is the failure this tool is supposed
    // to report rather than reproduce.
    let resp = qlab_http_framing::read_response(&mut stream).map_err(|e| e.to_string())?;
    if !resp.status.contains(" 200") {
        return Err(format!("non-200 response: {}", resp.status.trim()));
    }
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing_accepts_what_an_operator_actually_types() {
        assert_eq!(
            Endpoint::parse("node0=http://127.0.0.1:9410").unwrap(),
            Endpoint { label: "node0".into(), base_url: "http://127.0.0.1:9410".into() }
        );
        // No label ⇒ the authority names itself.
        assert_eq!(
            Endpoint::parse("http://node2:9410").unwrap(),
            Endpoint { label: "node2:9410".into(), base_url: "http://node2:9410".into() }
        );
        // A bare host:port is assumed http://, because that is what gets typed.
        assert_eq!(
            Endpoint::parse("10.0.0.4:9410").unwrap(),
            Endpoint { label: "10.0.0.4:9410".into(), base_url: "http://10.0.0.4:9410".into() }
        );
        assert!(Endpoint::parse("node0").is_err(), "no port ⇒ refuse, don't guess one");
        assert!(Endpoint::parse("").is_err());
    }

    /// **A closed port is unreachable, promptly, with the reason** — not a
    /// disagreement, and not a hang. Binding an ephemeral port and dropping the
    /// listener gives a port that is genuinely closed on this machine.
    #[test]
    fn a_closed_port_reads_as_unreachable_with_its_reason() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let ep = Endpoint::parse(&format!("dead=http://{addr}")).unwrap();
        let r = poll_one(&ep, PollOptions { timeout: Duration::from_millis(500) });
        assert!(!r.reading.is_reachable());
        assert!(r.reading.telemetry().is_none());
        match &r.reading {
            Reading::Unreachable(why) => assert!(why.contains("connect"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert!(r.elapsed < Duration::from_secs(2), "a closed port fails fast, {:?}", r.elapsed);
    }

    // Lab #631: this client honours the framing the server sent.

    struct TinyServer {
        server: std::sync::Arc<tiny_http::Server>,
        addr: String,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl TinyServer {
        fn serving(body: String) -> Self {
            let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
            let addr = server.server_addr().to_ip().expect("ip").to_string();
            let s = std::sync::Arc::clone(&server);
            let join = std::thread::spawn(move || {
                while let Ok(request) = s.recv() {
                    let _ = request.respond(tiny_http::Response::from_string(body.clone()));
                }
            });
            Self { server, addr, join: Some(join) }
        }
        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    impl Drop for TinyServer {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    struct RawServer {
        addr: String,
        hold: std::sync::Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl RawServer {
        fn new(script: Vec<u8>, hold_open: bool) -> Self {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr").to_string();
            let hold = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(hold_open));
            let h = std::sync::Arc::clone(&hold);
            let join = std::thread::spawn(move || {
                let Ok((mut sock, _)) = listener.accept() else { return };
                let mut req = Vec::new();
                let mut byte = [0u8; 1];
                while !req.ends_with(b"\r\n\r\n") {
                    match sock.read(&mut byte) {
                        Ok(1) => req.push(byte[0]),
                        _ => return,
                    }
                }
                let _ = sock.write_all(&script);
                let _ = sock.flush();
                let deadline = Instant::now() + Duration::from_secs(20);
                while h.load(Ordering::SeqCst) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            Self { addr, hold, join: Some(join) }
        }
        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }
        fn release(&self) {
            self.hold.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Drop for RawServer {
        fn drop(&mut self) {
            self.release();
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    #[test]
    fn a_chunked_tiny_http_body_reassembles() {
        let body = "x".repeat(40_000);
        assert!(body.len() > 32_768);
        let server = TinyServer::serving(body.clone());
        let got = fetch(&server.url(), "/", Duration::from_secs(10)).expect("chunked");
        assert_eq!(got, body.as_bytes());
    }

    #[test]
    fn a_content_length_tiny_http_body_is_exact() {
        let body = "hello-opview";
        let server = TinyServer::serving(body.to_string());
        let got = fetch(&server.url(), "/", Duration::from_secs(5)).expect("content-length");
        assert_eq!(got, body.as_bytes());
    }

    #[test]
    fn a_content_length_body_ends_without_the_server_closing() {
        let body = b"keep-alive-body";
        let mut script = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        script.extend_from_slice(body);
        let server = RawServer::new(script, true);
        let started = Instant::now();
        let got = fetch(&server.url(), "/", Duration::from_secs(10));
        let elapsed = started.elapsed();
        server.release();
        assert_eq!(got.expect("must parse"), body);
        assert!(
            elapsed < Duration::from_secs(5),
            "must stop at the end of the body, not at EOF; took {elapsed:?}"
        );
    }

    #[test]
    fn a_close_delimited_body_still_reads_to_eof() {
        let body = b"close-delimited";
        let mut script = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n".to_vec();
        script.extend_from_slice(body);
        let server = RawServer::new(script, false);
        let got = fetch(&server.url(), "/", Duration::from_secs(5)).expect("close-delimited");
        assert_eq!(got, body);
    }

    #[test]
    fn transfer_encoding_without_space_after_the_colon_is_still_chunked() {
        let script = b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            .to_vec();
        let server = RawServer::new(script, false);
        let got = fetch(&server.url(), "/", Duration::from_secs(5)).expect("no-space chunked");
        assert_eq!(got, b"hello");
    }

    #[test]
    fn an_unknown_transfer_encoding_is_refused_by_name() {
        let script = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08".to_vec();
        let server = RawServer::new(script, false);
        let e = fetch(&server.url(), "/", Duration::from_secs(5)).expect_err("gzip");
        assert!(
            e.contains("http-framing: unsupported-transfer-encoding: `gzip`"),
            "got `{e}`"
        );
    }
}
