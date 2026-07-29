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

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use qlab_node::Telemetry;

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
    /// The node answered with a telemetry snapshot this build can decode.
    Ok(Box<Telemetry>),
    /// The node did not answer, or answered something this build cannot read. The
    /// string is the operator-facing reason, and it is carried rather than
    /// collapsed to a boolean because "connection refused" and "unknown wire
    /// version 0x01" are entirely different problems with entirely different fixes.
    Unreachable(String),
}

impl Reading {
    pub fn telemetry(&self) -> Option<&Telemetry> {
        match self {
            Reading::Ok(t) => Some(t),
            Reading::Unreachable(_) => None,
        }
    }
    pub fn is_reachable(&self) -> bool {
        matches!(self, Reading::Ok(_))
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
        Ok(body) => match Telemetry::from_bytes(&body) {
            Ok(t) => Reading::Ok(Box::new(t)),
            // A decode failure is NOT a disagreement either. The commonest cause is
            // the one this issue created: a node built before the `0x02` bump, whose
            // wire this build refuses on purpose rather than best-effort parsing.
            Err(e) => Reading::Unreachable(format!(
                "answered, but the body is not a telemetry wire this build reads: {e:?} \
                 (a node predating the 0x02 checkpoint-identity bump reports 0x01)"
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
/// tool would couple two unrelated surfaces; ~60 lines of HTTP here does not.
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

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("read: {e}"))?;

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "no HTTP header terminator".to_string())?;
    let header = &raw[..sep];
    let body = &raw[sep + 4..];

    let status_line =
        String::from_utf8_lossy(header.split(|&b| b == b'\n').next().unwrap_or(b"")).to_string();
    if !status_line.contains(" 200") {
        return Err(format!("non-200 response: {}", status_line.trim()));
    }

    // tiny_http answers with `Content-Length` for a known-size body and
    // `Transfer-Encoding: chunked` otherwise; handle both rather than assuming
    // which, since the wire is what matters and not how it was framed.
    let header_lc = header.to_ascii_lowercase();
    let chunked = header_lc
        .windows(b"transfer-encoding: chunked".len())
        .any(|w| w == b"transfer-encoding: chunked");
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

/// Decode an HTTP/1.1 `Transfer-Encoding: chunked` body: repeated
/// `<hex-size>\r\n<size bytes>\r\n`, terminated by a `0\r\n` chunk.
fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, String> {
    let bad = || "malformed chunked body".to_string();
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_str = String::from_utf8_lossy(&b[..line_end]).to_string();
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| bad())?;
        b = b.get(line_end + 2..).ok_or_else(bad)?;
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(b.get(..size).ok_or_else(bad)?);
        b = b.get(size + 2..).ok_or_else(bad)?;
    }
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
}
