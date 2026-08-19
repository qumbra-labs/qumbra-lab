//! The faucet's `/metrics` endpoint — **loopback only, and off unless asked for**.
//!
//! Shaped after [`qumbra_node`'s `metrics_server`], with one deliberate divergence
//! that the PR argues at length and that is restated here because it is the kind of
//! thing a reader will assume is an oversight:
//!
//! ## Why this one REFUSES a non-loopback bind where the node only warns
//!
//! `qumbra-node`'s `metrics_addr` binds whatever it is given and prints a warning if
//! that is not loopback (`crates/qumbra-node/src/main.rs`). That is right for the
//! node: its exposition is node-operational data, the operator pairs the bind with a
//! source-restricted security group, and there are deployments where a remote
//! Prometheus is the collector.
//!
//! This process is different in one way that decides it: **it holds a hot spending
//! key**, and `testnet-plan.md` §6.2 is the rule that keeps that host's surface
//! minimal. The faucet's public HTTP surface is `listen_addr`, reviewed as such;
//! a second listener that an operator can accidentally expose with one config key
//! is exactly the shape the faucet's own `config` module already refuses in two
//! other places. `qumbra-explorer` took the same position on `discovery_addr`
//! (`ConfigRefusal::PublicDiscoveryAddr`) for the same reason, and its wording —
//! "not *obviously* loopback ⇒ refuse", no DNS resolution — is the wording reused
//! here. The scrape path off this host is a node-local agent (the plan's §B alloy
//! roll), which reaches loopback.
//!
//! The refusal names the address it refused, so an operator who meant it can see
//! immediately what to change.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::telemetry::{FaucetMetrics, OPENMETRICS_CONTENT_TYPE};

/// Whether `host:port` is *obviously* loopback: `localhost`, a loopback IPv4, or a
/// bracketed loopback IPv6.
///
/// **No DNS resolution.** A name that merely resolves to loopback today is not
/// obvious, and a startup check must not depend on a resolver — the same rule
/// `qumbra_explorer::config` states and `FaucetServiceConfig::binds_loopback`
/// follows. The one difference from `binds_loopback` is that `localhost` counts
/// here: this is a refusal, and refusing the spelling every compose file uses for a
/// node-local agent would be a refusal of the supported deployment.
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

/// The refusal message a non-loopback `metrics_addr` produces. One function so the
/// config check and the bind path cannot drift into two different explanations.
pub fn non_loopback_refusal(addr: &str) -> String {
    format!(
        "metrics_addr = `{addr}` is not obviously loopback, and this process holds a hot \
         spending key: its ONLY reviewed public surface is `listen_addr` (testnet-plan.md \
         §6.2). Bind metrics to 127.0.0.1/[::1]/localhost and let a node-local agent scrape \
         it, or remove `metrics_addr` to serve nothing. Refused rather than warned about — \
         unlike qumbra-node, which warns, because the node does not hold a spending key."
    )
}

/// A running scrape endpoint: the bound address, the worker thread, and the shared
/// registry it renders from.
pub struct MetricsServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl std::fmt::Debug for MetricsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsServer")
            .field("addr", &self.addr)
            .field("requests_served", &self.requests_served())
            .finish()
    }
}

impl MetricsServer {
    /// Bind `addr` and serve the exposition at `/metrics` until [`Self::shutdown`].
    ///
    /// Two ways this returns `Err`, and both are fatal to the caller for the reason
    /// `FaucetServer::start_with_trusted_proxies` gives: a listener the operator
    /// believes is up and which is not is discovered by nobody.
    ///
    ///   * `addr` is not obviously loopback — refused **before** the socket is
    ///     opened, so the port is never held even momentarily;
    ///   * the bind itself failed.
    pub fn start(addr: &str, metrics: Arc<FaucetMetrics>) -> io::Result<MetricsServer> {
        if !is_loopback_hostport(addr) {
            return Err(io::Error::other(non_loopback_refusal(addr)));
        }
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
                // Query strings are ignored: this endpoint takes no parameters, the
                // same rule the faucet's own surface follows.
                let path = request.url().split('?').next().unwrap_or("").to_string();
                if path != "/metrics" {
                    let _ = request.respond(
                        tiny_http::Response::from_string("not found: try /metrics")
                            .with_status_code(404),
                    );
                    continue;
                }
                let body = metrics.encode();
                let header = tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    OPENMETRICS_CONTENT_TYPE.as_bytes(),
                )
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

    /// Requests handled since start, including 404s and 405s.
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
    use crate::telemetry::RequestLabels;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).expect("read");
        out
    }

    /// 🔴 The refusal, by name, in every form that is easy to mistake for local —
    /// and it happens before a socket is opened, so a refused address is never
    /// briefly bound.
    #[test]
    fn a_non_loopback_metrics_addr_is_refused_by_name() {
        for addr in ["0.0.0.0:0", "[::]:0", "203.0.113.10:9451", "faucet.example:9451"] {
            let err = MetricsServer::start(addr, Arc::new(FaucetMetrics::new()))
                .expect_err("must refuse");
            let text = err.to_string();
            assert!(text.contains(addr), "the refusal must name the address: {text}");
            assert!(text.contains("hot spending key"), "{text}");
            assert!(text.contains("§6.2"), "{text}");
        }
        // …and the three loopback spellings are accepted.
        for addr in ["127.0.0.1:0", "[::1]:0", "localhost:0"] {
            let srv = MetricsServer::start(addr, Arc::new(FaucetMetrics::new()))
                .unwrap_or_else(|e| panic!("{addr} must bind: {e}"));
            assert!(srv.addr().ip().is_loopback(), "bound {}", srv.addr());
            srv.shutdown();
        }
    }

    /// The scrape path over a real socket: OpenMetrics content type, the registry's
    /// text, and nothing else served.
    #[test]
    fn serves_the_exposition_at_metrics_over_a_real_socket() {
        let metrics = Arc::new(FaucetMetrics::new());
        metrics.observe_request(
            RequestLabels { method: "GET".into(), route: "/healthz".into(), status: 200 },
            0.003,
            Some("4bf92f3577b34da6a3ce929d0e0e4736".into()),
        );
        let srv = MetricsServer::start("127.0.0.1:0", Arc::clone(&metrics)).expect("bind");
        let addr = srv.addr();

        let res = get(addr, "/metrics");
        assert!(res.starts_with("HTTP/1.1 200"), "{res}");
        assert!(res.contains("application/openmetrics-text"), "{res}");
        assert!(res.contains("qumbra_faucet_request_duration_seconds_count"), "{res}");
        assert!(res.contains("# {trace_id=\"4bf92f3577b34da6a3ce929d0e0e4736\"}"), "{res}");
        // Query strings are ignored rather than being an input surface.
        assert!(get(addr, "/metrics?x=1").starts_with("HTTP/1.1 200"));
        // Nothing else is served — in particular not the faucet's own page.
        assert!(get(addr, "/").starts_with("HTTP/1.1 404"));
        assert!(get(addr, "/request").starts_with("HTTP/1.1 404"));

        assert!(srv.requests_served() >= 4);
        srv.shutdown();
    }

    /// An unbindable loopback address is an error, not a silent no-op — the same
    /// posture `FaucetServer::start` and `qumbra-node`'s metrics listener take.
    ///
    /// The address is taken by binding port 0 and then asking for the port it got,
    /// rather than by picking a privileged port: a privileged-port test passes for
    /// the wrong reason under a root CI container, and this one does not depend on
    /// who the runner is.
    #[test]
    fn an_already_bound_address_is_an_error_not_a_silent_no_op() {
        let held = MetricsServer::start("127.0.0.1:0", Arc::new(FaucetMetrics::new()))
            .expect("first bind");
        let taken = held.addr().to_string();
        let err = MetricsServer::start(&taken, Arc::new(FaucetMetrics::new()));
        assert!(err.is_err(), "{taken} is already bound; a second listener must fail");
        assert!(err.unwrap_err().to_string().contains(&taken));
        held.shutdown();
    }
}
