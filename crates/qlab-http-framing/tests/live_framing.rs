//! The shared decoder against a real `tiny_http` on a loopback port (lab #631).
//!
//! A hand-written fixture encodes the author's belief about what the server
//! sends, **and in #626 that belief was the bug** — twice: once when the
//! client was written, and once again in the issue's own analysis, which
//! says `tiny-http` "switches to chunked above 8192 bytes". It does not.
//! 8192 is the *chunk size* (which is why the capture shows `2000`); the
//! switch threshold is `Response::chunked_threshold()`, **32768** by
//! default. A fixture sized to the 8192 number is `Content-Length`-framed
//! by a real server and exercises nothing.
//!
//! Named refusals and the keep-alive case use a raw `TcpListener` writing
//! exact bytes: a well-behaved `tiny_http` cannot produce gzip, a truncated
//! chunk, or a peer that keeps the connection open after the body.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qlab_http_framing::{read_response, FramingError, Response};

// ------------------------------------------------------------- the servers

/// A real `tiny_http` serving one fixed body — the server that broke the
/// pool, chosen over a fixture on purpose (see the module doc).
struct TinyServer {
    server: Arc<tiny_http::Server>,
    addr: String,
    join: Option<JoinHandle<()>>,
}

impl TinyServer {
    fn serving(body: String) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind loopback"));
        let addr = server
            .server_addr()
            .to_ip()
            .expect("loopback is an IP addr")
            .to_string();
        let s = Arc::clone(&server);
        let join = std::thread::spawn(move || {
            while let Ok(request) = s.recv() {
                let header =
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("static header parses");
                let _ = request
                    .respond(tiny_http::Response::from_string(body.clone()).with_header(header));
            }
        });
        Self {
            server,
            addr,
            join: Some(join),
        }
    }

    fn addr(&self) -> &str {
        &self.addr
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

/// A loopback server that writes exactly the bytes it is handed, and — when
/// asked — **keeps the connection open afterwards**. EOF is precisely the
/// signal the pre-#626 clients depended on to stop reading.
struct RawServer {
    addr: String,
    hold: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl RawServer {
    fn replying(script: Vec<u8>) -> Self {
        Self::new(script, false)
    }

    fn replying_and_holding_open(script: Vec<u8>) -> Self {
        Self::new(script, true)
    }

    fn new(script: Vec<u8>, hold_open: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
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

    fn addr(&self) -> &str {
        &self.addr
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

fn get(addr: &str) -> Result<Response, FramingError> {
    let mut s = TcpStream::connect(addr).expect("connect loopback");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    read_response(&mut s)
}

/// One raw `GET`, the whole response verbatim. Used to read the framing the
/// server actually chose rather than the one we expect it to choose.
fn raw_get(addr: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect loopback");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).expect("read response");
    String::from_utf8_lossy(&raw).to_string()
}

fn chunked(body: &[u8], first_ext: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, part) in body.chunks(8192).enumerate() {
        let ext = match (i, first_ext) {
            (0, Some(e)) => format!(";{e}"),
            _ => String::new(),
        };
        out.extend_from_slice(format!("{:x}{ext}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn response(head_fields: &str, framed_body: &[u8]) -> Vec<u8> {
    let mut out =
        format!("HTTP/1.1 200 OK\r\nServer: tiny-http (Rust)\r\n{head_fields}\r\n").into_bytes();
    out.extend_from_slice(framed_body);
    out
}

fn filler(n: usize) -> String {
    "x".repeat(n)
}

// ------------------------------------------------- tiny_http, the real wire

/// 30 kB puts the body over `tiny_http`'s 32768-byte chunking threshold, so
/// the server chunks it into 8192-byte pieces exactly as it did on the wire.
#[test]
fn a_chunked_tiny_http_body_reassembles() {
    let body = filler(40_000);
    assert!(
        body.len() > 32_768,
        "the fixture must cross tiny_http's chunked_threshold; got {}",
        body.len()
    );
    let server = TinyServer::serving(body.clone());
    let got = get(server.addr()).expect("a chunked body must reassemble");
    assert_eq!(got.body_string(), body);
}

/// The belief-check. #626's analysis says `tiny-http` switches to chunked
/// "above 8192 bytes"; the real default is 32768, and 8192 is the chunk
/// size. Asserted against the server, not against the reading.
#[test]
fn tiny_http_chunks_a_large_body_and_not_a_small_one() {
    let small = filler(500);
    let small_len = small.len();
    let server = TinyServer::serving(small);
    let raw = raw_get(server.addr());
    assert!(
        raw.contains(&format!("Content-Length: {small_len}")),
        "a sub-threshold body must be Content-Length framed; head was:\n{}",
        raw.split("\r\n\r\n").next().unwrap_or_default()
    );
    assert!(
        !raw.to_ascii_lowercase().contains("transfer-encoding"),
        "a sub-threshold body must not be chunked"
    );
    drop(server);

    let big = filler(40_000);
    let server = TinyServer::serving(big);
    let raw = raw_get(server.addr());
    let (head, body) = raw.split_once("\r\n\r\n").expect("a header terminator");
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "an over-threshold body must be chunked; head was:\n{head}"
    );
    assert!(
        body.starts_with("2000\r\n"),
        "the first chunk-size line is the `2000` from the T2 capture; got {:?}",
        &body[..body.len().min(16)]
    );
}

#[test]
fn a_content_length_tiny_http_body_is_exact() {
    let body = filler(500);
    let server = TinyServer::serving(body.clone());
    let got = get(server.addr()).expect("a Content-Length body must round-trip");
    assert_eq!(got.body_string(), body);
}

/// The other half of #626: `read_to_end` terminated only because the server
/// closed. This peer does not close. Pre-fix, every client that skipped
/// `Content-Length` blocked here until its read timeout.
#[test]
fn a_content_length_body_ends_without_the_server_closing() {
    let body = filler(500);
    let script = response(
        &format!(
            "Content-Type: text/plain\r\nContent-Length: {}\r\n",
            body.len()
        ),
        body.as_bytes(),
    );
    let server = RawServer::replying_and_holding_open(script);

    let started = Instant::now();
    let got = get(server.addr());
    let elapsed = started.elapsed();
    server.release();

    assert_eq!(got.expect("must parse").body_string(), body);
    assert!(
        elapsed < Duration::from_secs(5),
        "the read must end at the end of the body, not at EOF; took {elapsed:?}"
    );
}

/// The close-delimited case — no `Content-Length`, no `Transfer-Encoding`.
/// Still supported; it is just no longer the only path.
#[test]
fn a_close_delimited_body_still_reads_to_eof() {
    let body = filler(500);
    let script = response("Content-Type: text/plain\r\n", body.as_bytes());
    let server = RawServer::replying(script);
    let got = get(server.addr()).expect("a close-delimited body must round-trip");
    assert_eq!(got.body_string(), body);
}

#[test]
fn a_chunk_extension_is_ignored() {
    let body = filler(20_000);
    let framed = chunked(body.as_bytes(), Some("foo=bar"));
    assert!(
        framed.starts_with(b"2000;foo=bar\r\n"),
        "the fixture must carry the extension on the first size line"
    );
    let server = RawServer::replying(response("Transfer-Encoding: chunked\r\n", &framed));
    let got = get(server.addr()).expect("a chunk extension must not fail the parse");
    assert_eq!(got.body_string(), body);
}

#[test]
fn transfer_encoding_wins_over_a_stale_content_length() {
    let body = filler(20_000);
    let framed = chunked(body.as_bytes(), None);
    let server = RawServer::replying(response(
        "Content-Length: 41\r\nTransfer-Encoding: chunked\r\n",
        &framed,
    ));
    let got = get(server.addr()).expect("chunked must win over the length");
    assert_eq!(got.body_string(), body);
}

fn assert_framing_error(e: &FramingError, name: &str) {
    let s = e.to_string();
    assert!(
        s.contains(name),
        "the refusal must name the framing defect; got `{s}`"
    );
    assert!(
        !s.contains("expected struct"),
        "a framing defect must not be reported as a parse error; got `{s}`"
    );
}

#[test]
fn an_unknown_transfer_encoding_is_refused_by_name() {
    let server = RawServer::replying(response(
        "Transfer-Encoding: gzip\r\n",
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00",
    ));
    let e = get(server.addr()).expect_err("gzip must be refused");
    assert_framing_error(&e, "http-framing: unsupported-transfer-encoding: `gzip`");
}

#[test]
fn a_non_hex_chunk_size_is_refused_by_name() {
    let server = RawServer::replying(response(
        "Transfer-Encoding: chunked\r\n",
        b"zzzz\r\nhi\r\n0\r\n\r\n",
    ));
    let e = get(server.addr()).expect_err("a non-hex chunk size must be refused");
    assert_framing_error(&e, "http-framing: bad-chunk-size: `zzzz`");
}

#[test]
fn a_truncated_chunk_is_refused_by_name() {
    let server = RawServer::replying(response("Transfer-Encoding: chunked\r\n", b"2000\r\nshort"));
    let e = get(server.addr()).expect_err("a truncated chunk must be refused");
    assert_framing_error(&e, "http-framing: truncated-body: want 8192 bytes, got 5");
}

#[test]
fn a_short_content_length_body_is_refused_by_name() {
    let server = RawServer::replying(response("Content-Length: 4096\r\n", b"short"));
    let e = get(server.addr()).expect_err("a short body must be refused");
    assert_framing_error(&e, "http-framing: truncated-body: want 4096 bytes, got 5");
}

#[test]
fn a_non_numeric_content_length_is_refused_by_name() {
    let server = RawServer::replying(response("Content-Length: banana\r\n", b"hi"));
    let e = get(server.addr()).expect_err("a non-numeric length must be refused");
    assert_framing_error(&e, "http-framing: bad-content-length: `banana`");
}

#[test]
fn a_response_with_no_header_terminator_is_refused_by_name() {
    let server = RawServer::replying(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec());
    let e = get(server.addr()).expect_err("a headless response must be refused");
    assert_framing_error(&e, "http-framing: no-header-terminator");
}

#[test]
fn framing_fields_are_matched_case_insensitively() {
    let body = filler(20_000);
    let framed = chunked(body.as_bytes(), None);
    let server = RawServer::replying(response("tRaNsFeR-eNcOdInG: ChUnKeD\r\n", &framed));
    let got = get(server.addr()).expect("odd casing must still decode");
    assert_eq!(got.body_string(), body);

    let body = filler(500);
    let server = RawServer::replying_and_holding_open(response(
        &format!("content-length: {}\r\n", body.len()),
        body.as_bytes(),
    ));
    let got = get(server.addr()).expect("odd casing must still decode");
    server.release();
    assert_eq!(got.body_string(), body);
}
