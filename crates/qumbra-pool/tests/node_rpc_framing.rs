//! The pool's node-RPC client against real response framing (lab #626).
//!
//! `qumbra-pool` was offline for 2 h 32 min on T2 — 4,643 consecutive
//! `template JSON: invalid type: integer 2000, expected struct
//! MineTemplateWire at line 1 column 4`, both rigs at 0.00 H/s — because
//! `NodeRpcClient::request` took everything after `\r\n\r\n` as the body.
//! The node is served by `tiny_http`; a template carrying one transaction
//! (~151 kB on the wire) crosses its chunking threshold, so the body the
//! pool handed `serde_json` began with the chunk size line `2000\r\n`.
//!
//! ## Why a real server and not only byte fixtures
//!
//! Half of these drive an actual `tiny_http` on a loopback port. A
//! hand-written fixture encodes the author's belief about what the server
//! sends, **and in #626 that belief was the bug** — twice: once when the
//! client was written, and once again in the issue's own analysis, which
//! says `tiny-http` "switches to chunked above 8192 bytes". It does not.
//! 8192 is the *chunk size* (which is why the capture shows `2000`); the
//! switch threshold is `Response::chunked_threshold()`, **32768** by
//! default. A fixture sized to the 8192 number is `Content-Length`-framed
//! by a real server and exercises nothing. `tiny_http_chunks_a_large_template_and_not_a_small_one`
//! is that check, run against the server rather than assumed.
//!
//! The other half use a raw `TcpListener` writing exact bytes, for the
//! framings a well-behaved `tiny_http` cannot produce: chunk extensions, a
//! truncated chunk, a `Transfer-Encoding` this client refuses, and a peer
//! that keeps the connection open after the body.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qlab_devnet::body::CoinbasePayee;
use qlab_devnet::forms::GenesisForm;
use qumbra_pool::node_rpc::NodeRpcClient;
use qumbra_pool::template::Template;

// ---------------------------------------------------------------- fixtures

const PREV: [u8; 32] = [0x11; 32];
const COMMITMENT: [u8; 32] = [0x22; 32];
const SEED: [u8; 32] = [0x33; 32];
const NEXT_SEED: [u8; 32] = [0x44; 32];
const TX_BYTE: u8 = 0xab;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn payees() -> Vec<CoinbasePayee> {
    vec![CoinbasePayee {
        rkm: [0x0101_0101_0101_0101; 4],
        amount: 7,
    }]
}

/// The node's `MineTemplateWire` JSON, with a single transaction of
/// `tx_bytes` bytes. Field names are the ones `node_rpc` deserializes; a
/// rename there must break this file loudly.
fn template_json(tx_bytes: usize) -> String {
    let rkm = hex(&[0x01u8; 32]);
    let tx = hex(&vec![TX_BYTE; tx_bytes]);
    format!(
        r#"{{"form":"v5","prev":"{prev}","height":3574,"timestamp":1785000000,"difficulty":4096,"nonce":0,"tx_body_commitment":"{cm}","seed_hash":"{seed}","next_seed_hash":"{next}","coinbase_payees":[{{"rkm":"{rkm}","amount":7}}],"txs":["{tx}"]}}"#,
        prev = hex(&PREV),
        cm = hex(&COMMITMENT),
        seed = hex(&SEED),
        next = hex(&NEXT_SEED),
    )
}

/// What `fetch_template` must produce from [`template_json`]. Asserted
/// whole: a framing bug that ate or duplicated bytes anywhere in the body
/// has to show up here, not just in "it parsed".
fn expected_template(tx_bytes: usize) -> Template {
    use qumbra_pool::template::{header_from_parts, TemplateBody};
    let mut header = header_from_parts(&hex(&PREV), 3574, 1_785_000_000, 4096, &hex(&COMMITMENT))
        .expect("fixture header parses");
    header.nonce = 0;
    Template {
        form: GenesisForm::V5,
        header,
        seed_hash: SEED,
        next_seed_hash: Some(NEXT_SEED),
        body: Some(TemplateBody {
            coinbase_payees: payees(),
            txs: vec![vec![TX_BYTE; tx_bytes]],
        }),
    }
}

/// Frame `body` the way `chunked_transfer` does: 8192-byte chunks, a
/// zero-size chunk, then the terminating empty line. `first_ext` appends a
/// chunk extension to the first size line.
fn chunked(body: &str, first_ext: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, part) in body.as_bytes().chunks(8192).enumerate() {
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

// ------------------------------------------------------------- the servers

/// A real `tiny_http` serving one fixed JSON body — the server that broke
/// the pool, chosen over a fixture on purpose (see the module doc).
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
            // Same construction the node uses in `discovery_server.rs`:
            // `Response::from_string` + an explicit JSON content type. The
            // framing decision is `tiny_http`'s, which is the point.
            while let Ok(request) = s.recv() {
                let header = tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"application/json"[..],
                )
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

    fn url(&self) -> String {
        format!("http://{}", self.addr)
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
/// signal the pre-#626 client depended on to stop reading.
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
            // Drain the request head so the client's write cannot block.
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
            // Bounded so a regression is a failed assert, never a hung suite.
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

/// One raw `GET`, the whole response verbatim. Used to read the framing the
/// server actually chose rather than the one we expect it to choose.
fn raw_get(addr: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect loopback");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).expect("read response");
    String::from_utf8_lossy(&raw).to_string()
}

fn fetch(url: &str) -> Result<Template, String> {
    NodeRpcClient::parse(url)
        .expect("loopback url parses")
        .fetch_template(&payees())
}

// ------------------------------------------------- the one that fails today

/// 🔴 **This is the test that fails on `main`.** Pre-fix it reports
/// `template JSON: invalid type: integer 2000, expected struct
/// MineTemplateWire at line 1 column 4` — the T2 log line, reproduced.
///
/// 30 kB of transaction puts the body over `tiny_http`'s 32768-byte
/// chunking threshold, so the server chunks it into 8192-byte pieces
/// exactly as it did on the wire.
#[test]
fn a_chunked_template_spanning_several_chunks_deserializes() {
    let tx_bytes = 30_000;
    let json = template_json(tx_bytes);
    assert!(
        json.len() > 32_768,
        "the fixture must cross tiny_http's chunked_threshold; got {}",
        json.len()
    );
    let server = TinyServer::serving(json);
    let got = fetch(&server.url()).expect("a chunked template must deserialize");
    assert_eq!(got, expected_template(tx_bytes));
}

/// The belief-check. #626's analysis says `tiny-http` switches to chunked
/// "above 8192 bytes"; the real default is 32768, and 8192 is the chunk
/// size. Asserted against the server, not against the reading, because a
/// wrong number here silently turns the test above into a
/// `Content-Length` test that passes on `main`.
#[test]
fn tiny_http_chunks_a_large_template_and_not_a_small_one() {
    let small = template_json(500); // ~1.4 kB of JSON
    let small_len = small.len();
    let server = TinyServer::serving(small);
    let raw = raw_get(server.addr(), "/v1/mine/template");
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

    let big = template_json(30_000);
    let server = TinyServer::serving(big);
    let raw = raw_get(server.addr(), "/v1/mine/template");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a header terminator");
    assert!(
        head.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "an over-threshold body must be chunked; head was:\n{head}"
    );
    assert!(
        body.starts_with("2000\r\n"),
        "the first chunk-size line is the `2000` from the T2 capture; got {:?}",
        &body[..body.len().min(16)]
    );
    // And the exact bytes the pre-fix client fed to serde. The probe mirrors
    // `node_rpc`'s private `MineTemplateWire` closely enough to reproduce
    // #626's log line from the live wire rather than from a fixture.
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct MineTemplateWire {
        form: String,
    }
    let e = serde_json::from_str::<MineTemplateWire>(body)
        .expect_err("the raw chunked stream must not deserialize");
    assert_eq!(
        e.to_string(),
        "invalid type: integer `2000`, expected struct MineTemplateWire at line 1 column 4",
        "#626's log line, reproduced from the wire"
    );
}

// ------------------------------------------------------- Content-Length

#[test]
fn a_content_length_template_deserializes() {
    let tx_bytes = 500;
    let server = TinyServer::serving(template_json(tx_bytes));
    let got = fetch(&server.url()).expect("a Content-Length template must deserialize");
    assert_eq!(got, expected_template(tx_bytes));
}

/// The other half of #626: `read_to_end` terminated only because the server
/// closed. This peer does not close. Pre-fix, the client blocks here until
/// the 30 s read timeout — every template poll, against any keep-alive
/// server. Post-fix it stops at the end of the body and returns at once.
#[test]
fn a_content_length_body_ends_without_the_server_closing() {
    let tx_bytes = 500;
    let json = template_json(tx_bytes);
    let script = response(
        &format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            json.len()
        ),
        json.as_bytes(),
    );
    let server = RawServer::replying_and_holding_open(script);

    let started = Instant::now();
    let got = fetch(&server.url());
    let elapsed = started.elapsed();
    server.release();

    assert_eq!(got.expect("must parse"), expected_template(tx_bytes));
    assert!(
        elapsed < Duration::from_secs(5),
        "the read must end at the end of the body, not at EOF; took {elapsed:?}"
    );
}

/// The close-delimited case — no `Content-Length`, no `Transfer-Encoding`.
/// The only shape the pre-#626 client handled, and still supported.
#[test]
fn a_close_delimited_template_still_reads_to_eof() {
    let tx_bytes = 500;
    let json = template_json(tx_bytes);
    let script = response("Content-Type: application/json\r\n", json.as_bytes());
    let server = RawServer::replying(script);
    let got = fetch(&server.url()).expect("a close-delimited template must deserialize");
    assert_eq!(got, expected_template(tx_bytes));
}

// -------------------------------------------------------------- chunked

/// Chunk extensions are legal and carry nothing this client needs. Ignored,
/// never a failure — `tiny_http` does not emit them, so only a raw server
/// can pin this.
#[test]
fn a_chunk_extension_is_ignored() {
    let tx_bytes = 30_000;
    let json = template_json(tx_bytes);
    let framed = chunked(&json, Some("foo=bar"));
    assert!(
        framed.starts_with(b"2000;foo=bar\r\n"),
        "the fixture must carry the extension on the first size line"
    );
    let server = RawServer::replying(response("Transfer-Encoding: chunked\r\n", &framed));
    let got = fetch(&server.url()).expect("a chunk extension must not fail the parse");
    assert_eq!(got, expected_template(tx_bytes));
}

/// `Transfer-Encoding` wins over `Content-Length` (RFC 7230 §3.3.3). Taking
/// the length here would return the first `2000\r\n…` bytes and land back
/// in #626.
#[test]
fn transfer_encoding_wins_over_a_stale_content_length() {
    let tx_bytes = 30_000;
    let json = template_json(tx_bytes);
    let framed = chunked(&json, None);
    let server = RawServer::replying(response(
        "Content-Length: 41\r\nTransfer-Encoding: chunked\r\n",
        &framed,
    ));
    let got = fetch(&server.url()).expect("chunked must win over the length");
    assert_eq!(got, expected_template(tx_bytes));
}

// ------------------------------------------------- named framing refusals

/// The assertion that matters in every refusal below: the failure must not
/// arrive dressed as a data error about the node's template. #626 cost a
/// day because a transport defect was reported by `serde` as
/// `invalid type: integer 2000, expected struct MineTemplateWire`.
fn assert_framing_error(e: &str, name: &str) {
    assert!(
        e.contains(name),
        "the refusal must name the framing defect; got `{e}`"
    );
    assert!(
        !e.contains("expected struct MineTemplateWire"),
        "a framing defect must not be reported as a template parse error; got `{e}`"
    );
}

#[test]
fn an_unknown_transfer_encoding_is_refused_by_name() {
    let server = RawServer::replying(response(
        "Transfer-Encoding: gzip\r\n",
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00",
    ));
    let e = fetch(&server.url()).expect_err("gzip must be refused");
    assert_framing_error(&e, "http-framing: unsupported-transfer-encoding: `gzip`");
}

#[test]
fn a_non_hex_chunk_size_is_refused_by_name() {
    let server = RawServer::replying(response(
        "Transfer-Encoding: chunked\r\n",
        b"zzzz\r\n{\"form\":\"v5\"}\r\n0\r\n\r\n",
    ));
    let e = fetch(&server.url()).expect_err("a non-hex chunk size must be refused");
    assert_framing_error(&e, "http-framing: bad-chunk-size: `zzzz`");
}

#[test]
fn a_truncated_chunk_is_refused_by_name() {
    // 0x2000 promised, 5 delivered, then the peer goes away. Returning the
    // partial body would report a transport failure as malformed JSON.
    let server = RawServer::replying(response(
        "Transfer-Encoding: chunked\r\n",
        b"2000\r\nshort",
    ));
    let e = fetch(&server.url()).expect_err("a truncated chunk must be refused");
    assert_framing_error(&e, "http-framing: truncated-body: want 8192 bytes, got 5");
}

#[test]
fn a_short_content_length_body_is_refused_by_name() {
    let server = RawServer::replying(response("Content-Length: 4096\r\n", b"{\"form\":\"v5\"}"));
    let e = fetch(&server.url()).expect_err("a short body must be refused");
    assert_framing_error(&e, "http-framing: truncated-body: want 4096 bytes, got 13");
}

#[test]
fn a_non_numeric_content_length_is_refused_by_name() {
    let json = template_json(500);
    let server = RawServer::replying(response("Content-Length: banana\r\n", json.as_bytes()));
    let e = fetch(&server.url()).expect_err("a non-numeric length must be refused");
    assert_framing_error(&e, "http-framing: bad-content-length: `banana`");
}

#[test]
fn a_response_with_no_header_terminator_is_refused_by_name() {
    let server = RawServer::replying(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec());
    let e = fetch(&server.url()).expect_err("a headless response must be refused");
    assert_framing_error(&e, "http-framing: no-header-terminator");
}

/// Field names are case-insensitive, and `tiny_http` does not capitalise
/// the way this client's author assumed. A literal `"Transfer-Encoding: "`
/// match is #626 with extra steps.
#[test]
fn framing_fields_are_matched_case_insensitively() {
    let tx_bytes = 30_000;
    let json = template_json(tx_bytes);
    let framed = chunked(&json, None);
    let server = RawServer::replying(response("tRaNsFeR-eNcOdInG: ChUnKeD\r\n", &framed));
    let got = fetch(&server.url()).expect("odd casing must still decode");
    assert_eq!(got, expected_template(tx_bytes));

    let json = template_json(500);
    let server = RawServer::replying_and_holding_open(response(
        &format!("content-length: {}\r\n", json.len()),
        json.as_bytes(),
    ));
    let got = fetch(&server.url()).expect("odd casing must still decode");
    server.release();
    assert_eq!(got, expected_template(500));
}

/// A non-200 must still be read through its framing, or the pool logs an
/// empty reason for a refusal it needs to act on.
#[test]
fn an_error_status_body_is_read_through_its_framing() {
    let body = "unavailable: assemble-unavailable";
    let mut script =
        format!("HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\n\r\n", body.len())
            .into_bytes();
    script.extend_from_slice(body.as_bytes());
    let server = RawServer::replying_and_holding_open(script);
    let e = fetch(&server.url()).expect_err("503 must not be a template");
    server.release();
    assert!(e.contains("503"), "got `{e}`");
    assert!(e.contains("assemble-unavailable"), "got `{e}`");
}
