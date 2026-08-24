//! `qlab_cbserver::client::http_get` against real sockets (lab #631).
//!
//! The decoder lives in `qlab-http-framing`; these tests prove this client
//! actually calls it. Pre-fix, `http_get` de-chunked via a literal
//! `"transfer-encoding: chunked"` match and ignored `Content-Length`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qlab_cbserver::client::http_get;

struct TinyServer {
    server: Arc<tiny_http::Server>,
    addr: String,
    join: Option<JoinHandle<()>>,
}

impl TinyServer {
    fn serving(body: String) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
        let addr = server.server_addr().to_ip().expect("ip").to_string();
        let s = Arc::clone(&server);
        let join = std::thread::spawn(move || {
            while let Ok(request) = s.recv() {
                let _ = request.respond(tiny_http::Response::from_string(body.clone()));
            }
        });
        Self {
            server,
            addr,
            join: Some(join),
        }
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
    hold: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl RawServer {
    fn new(script: Vec<u8>, hold_open: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let hold = Arc::new(AtomicBool::new(hold_open));
        let h = Arc::clone(&hold);
        let join = std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
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
        Self {
            addr,
            hold,
            join: Some(join),
        }
    }
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
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

fn get(url: &str) -> std::io::Result<Vec<u8>> {
    http_get(url, "/")
}

#[test]
fn a_chunked_tiny_http_body_reassembles() {
    let body = "x".repeat(40_000);
    assert!(body.len() > 32_768);
    let server = TinyServer::serving(body.clone());
    let got = get(&server.url()).expect("chunked body must reassemble");
    assert_eq!(got, body.as_bytes());
}

#[test]
fn a_content_length_tiny_http_body_is_exact() {
    let body = "hello-cbserver";
    let server = TinyServer::serving(body.to_string());
    let got = get(&server.url()).expect("Content-Length body must round-trip");
    assert_eq!(got, body.as_bytes());
}

#[test]
fn a_content_length_body_ends_without_the_server_closing() {
    let body = b"keep-alive-body";
    let mut script =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    script.extend_from_slice(body);
    let server = RawServer::new(script, true);
    let started = Instant::now();
    let got = get(&server.url());
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
    let got = get(&server.url()).expect("close-delimited must still work");
    assert_eq!(got, body);
}

#[test]
fn transfer_encoding_without_space_after_the_colon_is_still_chunked() {
    // Legal HTTP. The pre-#631 substring `"transfer-encoding: chunked"`
    // required exactly one space after the colon and would have returned
    // `5\r\nhello\r\n0\r\n\r\n` as the body.
    let script =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
    let server = RawServer::new(script, false);
    let got = get(&server.url()).expect("no-space chunked must decode");
    assert_eq!(got, b"hello");
}

#[test]
fn an_unknown_transfer_encoding_is_refused_by_name() {
    let script = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08".to_vec();
    let server = RawServer::new(script, false);
    let e = get(&server.url()).expect_err("gzip must be refused");
    let msg = e.to_string();
    assert!(
        msg.contains("http-framing: unsupported-transfer-encoding: `gzip`"),
        "got `{msg}`"
    );
}
