//! The projection's listener: `GET`-only, two routes, everything else refused.
//!
//! ```text
//!   GET  /v1/health.json  the chain-health projection (pre-serialized, swapped by
//!                         the run loop)
//!   GET  /healthz         "ok" — for a supervisor, no state
//!   GET  <anything>       404 JSON, and the body says why there is no /v1/tx/…
//!   non-GET               405 with `Allow: GET`
//! ```
//!
//! 🔴 **`GET /` is a 404 since issue #281**, and that is the split: the page left
//! this binary for `qumbra-explorer-web`, and svc0's Caddy routes only `/v1/*` and
//! `/healthz` here while serving the page from a file root. A stale copy of the old
//! page would be worse than a refusal, so there is no copy.
//!
//! The handler serves a **pre-serialized** body from an `RwLock<String>` the run
//! loop swaps — a request never touches node state, so a slow or hostile client
//! can hold a socket, not a lock the node loop wants. That seam is unchanged by the
//! split; only the route and the content type moved. Same `tiny_http` posture,
//! bind-is-fatal rule and shutdown shape as `qumbra-faucet`'s listener.
//!
//! Deliberately absent: an access journal. The faucet logs (redacted) because a
//! request carries a grant decision; this surface takes no input and makes no
//! decisions, so the only thing a per-request log could record is readership.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// The one data route. Caddy path-routes `/v1/*` here (issue #281); the prefix is
/// shared with the node's own `/v1` surfaces by convention, not by code.
pub const HEALTH_PATH: &str = "/v1/health.json";

/// What a 404 explains, once, in the place a probe for `/v1/tx/…` or
/// `/v1/address/…` actually lands (issue #235's exclusion, stated where it is
/// tested).
///
/// JSON, because this surface is JSON since issue #281 — and typed (`refusal`) like
/// every other refusal in the tree, so a client can branch on it while a human still
/// reads why.
const NOT_FOUND_BODY: &str = "{\"refusal\":\"not_found\",\"detail\":\"This explorer \
serves /v1/health.json and /healthz only. There is deliberately no transaction, \
address or note lookup — Qumbra is a single shielded pool and this is a \
chain-health surface, not an Etherscan. The human-readable page is served \
separately from these routes.\"}\n";

pub struct ExplorerServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl ExplorerServer {
    /// Bind `addr` and serve `page` until [`Self::shutdown`]. A failure to bind
    /// is an error, never a warning — same rule and same reason as the faucet's.
    pub fn start(addr: &str, page: Arc<RwLock<String>>) -> io::Result<ExplorerServer> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("listen_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("explorer listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                // Query strings are ignored: this surface takes no parameters.
                let path =
                    request.url().split('?').next().unwrap_or("/").trim_end_matches('/');
                let path = if path.is_empty() { "/" } else { path };

                let (code, body, content_type, allow) = match (request.method(), path) {
                    (tiny_http::Method::Get, HEALTH_PATH) => {
                        let body =
                            page.read().map(|p| p.clone()).unwrap_or_else(|e| e.into_inner().clone());
                        (200, body, &b"application/json; charset=utf-8"[..], false)
                    }
                    (tiny_http::Method::Get, "/healthz") => {
                        (200, "ok\n".to_string(), &b"text/plain; charset=utf-8"[..], false)
                    }
                    (tiny_http::Method::Get, _) => {
                        (404, NOT_FOUND_BODY.to_string(), &b"application/json; charset=utf-8"[..], false)
                    }
                    _ => (
                        405,
                        "GET only.\n".to_string(),
                        &b"text/plain; charset=utf-8"[..],
                        true,
                    ),
                };

                let mut response = tiny_http::Response::from_string(body)
                    .with_status_code(code)
                    .with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type)
                            .expect("static content type parses"),
                    );
                if allow {
                    if let Ok(h) = tiny_http::Header::from_bytes(&b"Allow"[..], &b"GET"[..]) {
                        response = response.with_header(h);
                    }
                }
                let _ = request.respond(response);
            }
        });

        Ok(ExplorerServer { addr: bound, server, thread: Some(thread), served })
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

impl Drop for ExplorerServer {
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
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// One raw HTTP exchange — status line + headers + body, no client library,
    /// because bytes off a socket are the thing this module can be wrong at.
    fn exchange(addr: SocketAddr, request: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.write_all(request.as_bytes()).expect("write");
        let mut out = String::new();
        s.read_to_string(&mut out).expect("read");
        out
    }

    fn get(addr: SocketAddr, path: &str) -> String {
        exchange(addr, &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    }

    fn server_with(page: &str) -> (ExplorerServer, Arc<RwLock<String>>) {
        let handle = Arc::new(RwLock::new(page.to_string()));
        let server = ExplorerServer::start("127.0.0.1:0", Arc::clone(&handle)).expect("bind");
        (server, handle)
    }

    #[test]
    fn the_projection_and_healthz_serve_and_a_swap_is_visible() {
        let (server, handle) = server_with("{\"v\":1,\"gen\":\"a\"}");
        let addr = server.addr();
        let resp = get(addr, HEALTH_PATH);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("application/json"), "the content type is JSON: {resp}");
        assert!(resp.contains("\"v\":1"));
        assert!(get(addr, "/healthz").contains("ok"));
        *handle.write().unwrap() = "{\"v\":1,\"gen\":\"b\"}".to_string();
        assert!(
            get(addr, HEALTH_PATH).contains("\"gen\":\"b\""),
            "the run loop's swap reaches readers"
        );
        assert_eq!(server.requests_served(), 3, "two projection reads and one healthz");
        server.shutdown();
    }

    /// 🔴 The exclusion, re-tested where it now matters: the probes are **adjacent to
    /// a real API**. Before the split `/api/v1/txs` sat next to nothing; now a `/v1`
    /// prefix exists and a plausible-looking route is one handler arm away.
    #[test]
    fn nothing_tx_or_address_shaped_exists_under_v1_and_the_404_says_why() {
        let (server, _handle) = server_with("{}");
        let addr = server.addr();
        for probe in [
            "/v1/tx/abc123",
            "/v1/address/qmb1xyz",
            "/v1/note/0",
            "/v1/txs",
            "/v1/block/7",
            "/v1/balance/qmb1xyz",
            "/tx/abc123",
            "/address/qmb1xyz",
            "/api/v1/txs",
        ] {
            let resp = get(addr, probe);
            assert!(resp.starts_with("HTTP/1.1 404"), "{probe}: {resp}");
            assert!(resp.contains("deliberately"), "{probe} explains the exclusion");
        }
        server.shutdown();
    }

    /// The page left this binary (issue #281): `/` is a named 404, never a blank and
    /// never a stale copy of the page it used to serve.
    #[test]
    fn the_root_no_longer_serves_a_page_and_says_where_it_went() {
        let (server, _handle) = server_with("{}");
        let resp = get(server.addr(), "/");
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        assert!(resp.contains(HEALTH_PATH), "it names the surface that does exist");
        assert!(!resp.contains("<html"), "and it is not a page: {resp}");
        server.shutdown();
    }

    /// A 404 from a JSON surface is JSON. Reachable only for paths Caddy routed here,
    /// so its reader is a probe or a confused client — both better served by something
    /// parseable that still states the exclusion in words.
    #[test]
    fn the_404_is_json_and_carries_a_typed_refusal() {
        let (server, _handle) = server_with("{}");
        let resp = get(server.addr(), "/v1/tx/1");
        assert!(resp.contains("application/json"), "{resp}");
        let body = resp.split("\r\n\r\n").nth(1).expect("a body");
        let v: serde_json::Value = serde_json::from_str(body).expect("the 404 body is JSON");
        assert_eq!(v["refusal"], "not_found");
        assert!(
            v["detail"].as_str().expect("detail").contains("deliberately"),
            "the exclusion is stated, not implied"
        );
    }

    #[test]
    fn non_get_is_405_with_allow_get_never_a_write_path() {
        let (server, _handle) = server_with("<html>x</html>");
        let addr = server.addr();
        let resp = exchange(
            addr,
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
        assert!(resp.contains("Allow: GET"), "{resp}");
        server.shutdown();
    }
}
