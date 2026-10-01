//! The operator listener: `POST /v1/bundle` (lab #785 F5-5b, ruling Q-5b-1 (a)).
//!
//! ## Why a listener of its own
//!
//! The L2 sequencer hands its signed bundle to a producer's node here, and the
//! node puts it in its one-slot pool ([`qlab_p2p::adapter::NodeAdapter::admit_bundle`])
//! and gossips it. The discovery listener is the wrong home: it is on by default
//! and operators expose it, and this route makes the node verify a wrapper proof
//! for whoever calls it. So the route has its own key, `operator_addr`, **off
//! unless set and loopback only** — a non-loopback address is refused by name,
//! at config check and again at bind (the explorer's `discovery_addr` precedent,
//! PR #236). The public discovery listener carries no bundle route at all.
//!
//! **Reaching it.** The sequencer is either co-hosted with the producer's node
//! or reaches this port through a tunnel the operator sets up (an SSH forward, a
//! WireGuard peer). Nothing here authenticates the caller; the bundle's own
//! ML-DSA signature is what proves it came from the sequencer, and the rule
//! checks it before the proofs (`bundle.rs`, step 6 before step 7), so a caller
//! who is not the sequencer costs one signature check, not a proof verification.
//!
//! ## The one route
//!
//! `POST /v1/bundle`, the body the bundle's raw bytes, optional `?replace=1`:
//!
//! | answer | when |
//! |---|---|
//! | `202 admitted <id>` | verified at the tip and now held (and advertised) |
//! | `409 slot-held` | the slot already holds a bundle; first wins — retry with `?replace=1` to replace it |
//! | `400 refused: <reason>` | the bytes alone are wrong (codec, signature, l2 id, exit shape) |
//! | `422 refused: <reason>` | well-formed, but not valid at this tip (spacing, thread, proofs, state lag) |
//! | `503 unavailable: …` | not a V6 node, or no verdict in time |
//!
//! `400` and `422` are split on exactly the line the P2P path charges on
//! (ruling Q-5b-2): what the bytes alone prove versus what is judged against
//! this node's state.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;

use qlab_p2p::n1::BundleAdmit;

/// The route.
pub const BUNDLE_PATH: &str = "/v1/bundle";

/// The largest body read: a bundle never outgrows the V6 body bound it rides in.
pub const MAX_BUNDLE_POST_BYTES: usize = qlab_devnet::body::MAX_V6_BODY_BYTES;

/// How long a handler waits for the run loop (a proof verification included).
pub const BUNDLE_VERDICT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// One `POST /v1/bundle` handed to the run loop.
pub struct BundleSubmitRequest {
    pub bytes: Vec<u8>,
    pub replace: bool,
    pub reply: mpsc::SyncSender<BundleAdmit>,
}

/// Whether `host:port` is *obviously* loopback — no DNS, same rule as the
/// explorer's (`qumbra_explorer::metrics_server::is_loopback_hostport`).
pub fn is_loopback_hostport(hostport: &str) -> bool {
    use std::net::IpAddr;
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, _)) => h,
            None => return false,
        }
    };
    host == "localhost" || host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// The refusal a non-loopback `operator_addr` produces — one function, so the
/// config check and the bind path cannot drift into two explanations.
pub fn non_loopback_refusal(addr: &str) -> String {
    format!(
        "operator_addr = `{addr}` is not obviously loopback. `POST /v1/bundle` makes this node \
         verify a wrapper proof for whoever calls it, so it is served on loopback only \
         (lab #785 F5-5b, ruling Q-5b-1): co-host the sequencer, or reach this port through a \
         tunnel. Bind 127.0.0.1/[::1]/localhost, or remove `operator_addr` to serve nothing. \
         Non-loopback is refused BY NAME, never warned about."
    )
}

/// `(status, body)` for the run loop's verdict.
pub fn render_admit(verdict: &BundleAdmit) -> (u16, String) {
    match verdict {
        BundleAdmit::Admitted(id) => (202, format!("admitted {}", crate::genesis::hex_encode(id))),
        BundleAdmit::SlotHeld => (409, "slot-held — first wins; ?replace=1 replaces".into()),
        BundleAdmit::Refused { charged: true, reason } => (400, format!("refused: {reason}")),
        BundleAdmit::Refused { charged: false, reason } => (422, format!("refused: {reason}")),
        BundleAdmit::Unsupported => (503, "unavailable: not a V6 node".into()),
    }
}

/// The query grammar: empty, or exactly `replace=1`.
fn parse_replace(query: Option<&str>) -> Result<bool, String> {
    match query {
        None | Some("") => Ok(false),
        Some("replace=1") => Ok(true),
        Some(other) => Err(format!("unknown query `{other}` (want none or replace=1)")),
    }
}

/// One request's whole decision, as `(status, body)`, the socket left out so
/// it is testable.
fn handle(
    method: &tiny_http::Method,
    url: &str,
    body: Result<Vec<u8>, ()>,
    submits: &mpsc::SyncSender<BundleSubmitRequest>,
) -> (u16, String) {
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url, None),
    };
    if path != BUNDLE_PATH {
        return (404, "not found".into());
    }
    if *method != tiny_http::Method::Post {
        return (405, "method not allowed".into());
    }
    let replace = match parse_replace(query) {
        Ok(r) => r,
        Err(e) => return (400, format!("refused: {e}")),
    };
    let bytes = match body {
        Ok(b) => b,
        Err(()) => return (400, "refused: body-unreadable".into()),
    };
    if bytes.len() > MAX_BUNDLE_POST_BYTES {
        return (413, "refused: body-too-large".into());
    }
    if bytes.is_empty() {
        return (400, "refused: empty bundle".into());
    }
    let (tx, rx) = mpsc::sync_channel(1);
    if submits.try_send(BundleSubmitRequest { bytes, replace, reply: tx }).is_err() {
        return (503, "unavailable: bundle-queue-full — retry".into());
    }
    match rx.recv_timeout(BUNDLE_VERDICT_TIMEOUT) {
        Ok(verdict) => render_admit(&verdict),
        Err(_) => (503, "unavailable: no-verdict-in-time — retry".into()),
    }
}

/// A running operator listener.
pub struct OperatorServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
}

impl OperatorServer {
    /// Bind `addr` — refused unless it is loopback, checked on the spelling
    /// before binding and on the bound address after.
    pub fn start(addr: &str, submits: mpsc::SyncSender<BundleSubmitRequest>) -> io::Result<Self> {
        if !is_loopback_hostport(addr) {
            return Err(io::Error::other(non_loopback_refusal(addr)));
        }
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("operator_addr {addr}: {e}")))?;
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("operator listener has no ip address"))?;
        if !bound.ip().is_loopback() {
            return Err(io::Error::other(non_loopback_refusal(&bound.to_string())));
        }
        let server = Arc::new(server);
        let worker = Arc::clone(&server);
        let thread = std::thread::spawn(move || {
            for mut request in worker.incoming_requests() {
                let body = {
                    use std::io::Read;
                    let mut raw = Vec::new();
                    let cap = MAX_BUNDLE_POST_BYTES as u64 + 1;
                    request.as_reader().take(cap).read_to_end(&mut raw).map(|_| raw).map_err(|_| ())
                };
                let (code, text) = handle(request.method(), request.url(), body, &submits);
                let _ = request.respond(tiny_http::Response::from_string(text).with_status_code(code));
            }
        });
        Ok(Self { addr: bound, server, thread: Some(thread) })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for OperatorServer {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_obviously_loopback_address_binds() {
        for ok in ["127.0.0.1:0", "localhost:9430", "[::1]:9430", "127.8.9.1:1"] {
            assert!(is_loopback_hostport(ok), "{ok}");
        }
        for bad in ["0.0.0.0:9430", "10.0.0.1:9430", "[::]:9430", "example.org:1", "9430"] {
            assert!(!is_loopback_hostport(bad), "{bad}");
            let (tx, _rx) = mpsc::sync_channel(1);
            let err = OperatorServer::start(bad, tx).err().expect("refused");
            assert!(err.to_string().contains("refused BY NAME"), "{err}");
        }
    }

    #[test]
    fn the_verdicts_map_onto_the_route_table() {
        assert_eq!(render_admit(&BundleAdmit::Admitted([0xab; 32])).0, 202);
        assert_eq!(render_admit(&BundleAdmit::SlotHeld).0, 409);
        assert_eq!(render_admit(&BundleAdmit::Refused { charged: true, reason: "Signature".into() }), (400, "refused: Signature".into()));
        assert_eq!(render_admit(&BundleAdmit::Refused { charged: false, reason: "Spacing".into() }).0, 422);
        assert_eq!(render_admit(&BundleAdmit::Unsupported).0, 503);
    }

    #[test]
    fn the_handler_refuses_before_it_queues() {
        let (tx, rx) = mpsc::sync_channel(4);
        let post = tiny_http::Method::Post;
        assert_eq!(handle(&tiny_http::Method::Get, BUNDLE_PATH, Ok(vec![1]), &tx).0, 405);
        assert_eq!(handle(&post, "/v1/compact", Ok(vec![1]), &tx).0, 404);
        assert_eq!(handle(&post, "/v1/bundle?replace=yes", Ok(vec![1]), &tx).0, 400);
        assert_eq!(handle(&post, BUNDLE_PATH, Ok(vec![]), &tx).0, 400);
        assert_eq!(handle(&post, BUNDLE_PATH, Ok(vec![0; MAX_BUNDLE_POST_BYTES + 1]), &tx).0, 413);
        assert!(rx.try_recv().is_err(), "nothing reached the run loop");
    }

    /// End to end over a socket: the run loop's verdict comes back as the
    /// route's answer, and `?replace=1` reaches it.
    #[test]
    fn a_posted_bundle_reaches_the_run_loop_and_its_verdict_returns() {
        let (tx, rx) = mpsc::sync_channel(4);
        let srv = OperatorServer::start("127.0.0.1:0", tx).expect("bind loopback");
        let addr = srv.addr();
        let loop_side = std::thread::spawn(move || {
            let first = rx.recv().unwrap();
            assert_eq!((first.bytes.as_slice(), first.replace), (&[7u8, 8][..], false));
            first.reply.send(BundleAdmit::SlotHeld).unwrap();
            let second = rx.recv().unwrap();
            assert!(second.replace);
            second.reply.send(BundleAdmit::Admitted([1; 32])).unwrap();
        });
        let post = |path: &str| {
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n").unwrap();
            s.write_all(&[7, 8]).unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        assert!(post(BUNDLE_PATH).starts_with("HTTP/1.1 409"));
        let out = post("/v1/bundle?replace=1");
        assert!(out.starts_with("HTTP/1.1 202"), "{out}");
        assert!(out.ends_with(&format!("admitted {}", "01".repeat(32))), "{out}");
        loop_side.join().unwrap();
    }
}
