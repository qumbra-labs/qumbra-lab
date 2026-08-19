//! The explorer's `/metrics` endpoint — **loopback only, and off unless asked
//! for**. The faucet's `metrics_server` (PR #498), reused in shape; what differs
//! is the reason the refusal gives, because this binary's §6.2 story is its own.
//!
//! ## The §6.2 ruling this module implements (coordinator, this baton)
//!
//! Until this baton, this process could open **no** metrics listener at all:
//! [`crate::config::ExplorerConfig::check_observer`] refused `metrics_addr` /
//! `telemetry_addr` by name, because §6.2 keeps the fleet's observability
//! surfaces off the public internet and the projection is this binary's only
//! reviewed public surface. **Coordinator ruling for the OTel baton: that
//! refusal was against PUBLIC listeners. A loopback-only `metrics_addr` exposes
//! nothing public and is compatible with §6.2's intent, so it is now ALLOWED —
//! the bind must be loopback, a non-loopback value stays refused by name, and
//! this message is the updated refusal the ruling asked for.** The scrape path
//! off this host is a node-local agent (the plan's §B alloy roll), which
//! reaches loopback.
//!
//! "Obviously loopback" is the same test the crate's config module has always
//! applied to `discovery_addr` — no DNS resolution, `localhost` accepted by
//! spelling — and this module's [`is_loopback_hostport`] is now the one copy
//! both checks share.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::telemetry::{ExplorerMetrics, OPENMETRICS_CONTENT_TYPE};

/// Whether `host:port` is *obviously* loopback: `localhost`, a loopback IPv4, or
/// a bracketed loopback IPv6.
///
/// **No DNS resolution.** A name that merely resolves to loopback today is not
/// obvious, and a startup check must not depend on a resolver — the rule
/// [`crate::config`] has stated for `discovery_addr` since PR #236. `localhost`
/// counts: refusing the spelling every compose file uses for a node-local agent
/// would be a refusal of the supported deployment.
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

/// The refusal message a non-loopback `metrics_addr` produces. One function so
/// the config check and the bind path cannot drift into two different
/// explanations.
pub fn non_loopback_refusal(addr: &str) -> String {
    format!(
        "metrics_addr = `{addr}` is not obviously loopback. §6.2 keeps this fleet's \
         observability surfaces off the public internet, and the explorer's projection is \
         its only reviewed public surface; the coordinator's ruling for the OTel baton \
         allows a metrics listener from this process ONLY on loopback (the old refusal was \
         against PUBLIC listeners — nothing public may be exposed). Bind metrics to \
         127.0.0.1/[::1]/localhost and let a node-local agent scrape it, or remove \
         `metrics_addr` to serve nothing. Non-loopback is refused BY NAME, never warned \
         about."
    )
}

/// A running scrape endpoint: the bound address, the worker thread, and the
/// shared registry it renders from.
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
    /// Bind `addr` and serve the exposition at `/metrics` until
    /// [`Self::shutdown`].
    ///
    /// Two ways this returns `Err`, and both are fatal to the caller — a
    /// listener the operator believes is up and which is not is discovered by
    /// nobody:
    ///
    ///   * `addr` is not obviously loopback — refused **before** the socket is
    ///     opened, so a refused address is never held even momentarily;
    ///   * the bind itself failed.
    pub fn start(addr: &str, metrics: Arc<ExplorerMetrics>) -> io::Result<MetricsServer> {
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
                        tiny_http::Response::from_string("method not allowed")
                            .with_status_code(405),
                    );
                    continue;
                }
                // Query strings are ignored: this endpoint takes no parameters,
                // the same rule the projection's own surface follows.
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
                let _ =
                    request.respond(tiny_http::Response::from_string(body).with_header(header));
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

    /// 🔴 The two halves the ruling names, at the bind seam: every form that is
    /// easy to mistake for local is refused BY NAME — before a socket is opened,
    /// so a refused address is never briefly bound — and the three loopback
    /// spellings are accepted.
    #[test]
    fn a_non_loopback_metrics_addr_is_refused_by_name_and_loopback_binds() {
        for addr in ["0.0.0.0:0", "[::]:0", "203.0.113.10:9480", "explorer.example:9480"] {
            let err = MetricsServer::start(addr, Arc::new(ExplorerMetrics::new()))
                .expect_err("must refuse");
            let text = err.to_string();
            assert!(text.contains(addr), "the refusal must name the address: {text}");
            assert!(text.contains("§6.2"), "{text}");
            assert!(text.contains("loopback"), "{text}");
        }
        for addr in ["127.0.0.1:0", "[::1]:0", "localhost:0"] {
            let srv = MetricsServer::start(addr, Arc::new(ExplorerMetrics::new()))
                .unwrap_or_else(|e| panic!("{addr} must bind: {e}"));
            assert!(srv.addr().ip().is_loopback(), "bound {}", srv.addr());
            srv.shutdown();
        }
    }

    /// The scrape path over a real socket: OpenMetrics content type, the
    /// registry's text, and nothing else served — in particular none of the
    /// projection's own routes.
    #[test]
    fn serves_the_exposition_at_metrics_over_a_real_socket() {
        let metrics = Arc::new(ExplorerMetrics::new());
        metrics.observe_request(
            RequestLabels { method: "GET".into(), route: "/v1/health.json".into(), status: 200 },
            0.003,
            Some("4bf92f3577b34da6a3ce929d0e0e4736".into()),
        );
        let srv = MetricsServer::start("127.0.0.1:0", Arc::clone(&metrics)).expect("bind");
        let addr = srv.addr();

        let res = get(addr, "/metrics");
        assert!(res.starts_with("HTTP/1.1 200"), "{res}");
        assert!(res.contains("application/openmetrics-text"), "{res}");
        assert!(res.contains("qumbra_explorer_request_duration_seconds_count"), "{res}");
        assert!(res.contains("# {trace_id=\"4bf92f3577b34da6a3ce929d0e0e4736\"}"), "{res}");
        // Query strings are ignored rather than being an input surface.
        assert!(get(addr, "/metrics?x=1").starts_with("HTTP/1.1 200"));
        // Nothing else is served — in particular not the projection.
        assert!(get(addr, "/").starts_with("HTTP/1.1 404"));
        assert!(get(addr, "/v1/health.json").starts_with("HTTP/1.1 404"));

        assert!(srv.requests_served() >= 4);
        srv.shutdown();
    }

    /// An unbindable loopback address is an error, not a silent no-op. The
    /// address is taken by binding port 0 and asking for the port it got, rather
    /// than by picking a privileged port — a privileged-port test passes for the
    /// wrong reason under a root CI container.
    #[test]
    fn an_already_bound_address_is_an_error_not_a_silent_no_op() {
        let held = MetricsServer::start("127.0.0.1:0", Arc::new(ExplorerMetrics::new()))
            .expect("first bind");
        let taken = held.addr().to_string();
        let err = MetricsServer::start(&taken, Arc::new(ExplorerMetrics::new()));
        assert!(err.is_err(), "{taken} is already bound; a second listener must fail");
        assert!(err.unwrap_err().to_string().contains(&taken));
        held.shutdown();
    }
}
