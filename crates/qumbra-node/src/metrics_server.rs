//! The `/metrics` scrape endpoint (issue #87, decision 1: **pull**).
//!
//! Deliberately the smallest possible thing that a Prometheus server can scrape:
//! one GET route, serving a **pre-rendered snapshot** that the run loop refreshes on
//! its own cadence.
//!
//! ## Why a snapshot and not live state
//! The node runs on a 2 vCPU host. If a scrape took the lock on node state, an
//! observer could contend with — or stall — the consensus loop, and the frequency of
//! that contention would be set by whoever configured Prometheus. Serving a snapshot
//! inverts that: **the node decides how often it pays**, a scrape costs a string
//! clone, and no external actor can influence the node's timing at all. The cost is
//! bounded staleness, which is why the exposition carries
//! `qumbra_metrics_rendered_timestamp_seconds` — the consumer reads the snapshot's
//! age instead of assuming scrape time.
//!
//! ## Deployment shape
//! The listener is **off unless `metrics_addr` is set in the node's TOML**. Binding
//! it — and especially binding it to anything other than a loopback address — is a
//! deliberate operator act that pairs with an inbound security-group rule. Nothing
//! here authenticates: the exposition carries no key material, no transaction
//! contents and no peer addresses, but it is still node-operational data, so the
//! access control belongs in the security group, source-restricted to the collector.
//! See the PR's pull-vs-push argument for why that restriction has to be a fixed
//! address rather than the operator's roaming one.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Prometheus text exposition format v0.0.4 content type, as (header, value).
const CONTENT_TYPE_HEADER: &[u8] = b"Content-Type";
const CONTENT_TYPE_VALUE: &[u8] = b"text/plain; version=0.0.4; charset=utf-8";

/// A running scrape endpoint: bound address + worker thread + the shared snapshot.
pub struct MetricsServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl MetricsServer {
    /// Bind `addr` and serve `snapshot` at `/metrics` until [`Self::shutdown`].
    ///
    /// `addr` is taken verbatim from config: `127.0.0.1:9090` keeps it local (and is
    /// the right choice when a node-local agent forwards it), `0.0.0.0:9090` exposes
    /// it to whatever the host's firewall allows in.
    pub fn start(addr: &str, snapshot: Arc<Mutex<String>>) -> io::Result<Self> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("metrics_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("metrics listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                if *request.method() != tiny_http::Method::Get {
                    let _ = request.respond(
                        tiny_http::Response::from_string("method not allowed").with_status_code(405),
                    );
                    continue;
                }
                // Ignore any query string: this endpoint takes no parameters, so
                // there is no input surface to get wrong.
                let path = request.url().split('?').next().unwrap_or("").to_string();
                if path != "/metrics" {
                    let _ = request.respond(
                        tiny_http::Response::from_string("not found: try /metrics")
                            .with_status_code(404),
                    );
                    continue;
                }
                // Clone under the lock and release it before writing to the socket —
                // a slow or half-dead scraper must not hold the snapshot lock while
                // the run loop wants to refresh it.
                let body = snapshot.lock().map(|s| s.clone()).unwrap_or_default();
                let header = tiny_http::Header::from_bytes(CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE)
                    .expect("static exposition content type parses");
                let _ = request.respond(tiny_http::Response::from_string(body).with_header(header));
            }
        });

        Ok(MetricsServer { addr: bound, server, thread: Some(thread), served })
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
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// A minimal HTTP/1.1 GET, so the test exercises the real socket path rather
    /// than the handler in isolation.
    fn get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).expect("read");
        out
    }

    /// The scrape path end to end: real socket, real exposition content type, and
    /// the served body is the snapshot the node last rendered.
    #[test]
    fn serves_the_snapshot_at_metrics_over_a_real_socket() {
        let snap = Arc::new(Mutex::new(String::from(
            "# HELP qumbra_tip_height help\n# TYPE qumbra_tip_height gauge\nqumbra_tip_height 7\n",
        )));
        let srv = MetricsServer::start("127.0.0.1:0", Arc::clone(&snap)).expect("bind");
        let addr = srv.addr();

        let res = get(addr, "/metrics");
        assert!(res.starts_with("HTTP/1.1 200"), "{res}");
        assert!(res.contains("text/plain; version=0.0.4"), "{res}");
        assert!(res.contains("qumbra_tip_height 7"), "{res}");

        // A refreshed snapshot is what the next scrape sees.
        *snap.lock().unwrap() = String::from("qumbra_tip_height 8\n");
        assert!(get(addr, "/metrics").contains("qumbra_tip_height 8"));
        // Query strings are ignored rather than being an input surface.
        assert!(get(addr, "/metrics?anything=1").contains("qumbra_tip_height 8"));

        // Nothing else is served.
        assert!(get(addr, "/").starts_with("HTTP/1.1 404"));
        assert!(get(addr, "/v1/status").starts_with("HTTP/1.1 404"));

        assert!(srv.requests_served() >= 5);
        srv.shutdown();
    }

    /// A bad `metrics_addr` fails loudly at start rather than silently leaving the
    /// node unobservable — the whole point of this issue is that silence lies.
    #[test]
    fn an_unbindable_address_is_an_error_not_a_silent_no_op() {
        let snap = Arc::new(Mutex::new(String::new()));
        assert!(MetricsServer::start("256.256.256.256:9", snap).is_err());
    }
}
