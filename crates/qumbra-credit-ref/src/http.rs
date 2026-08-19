//! The HTTP shell over [`crate::CreditEngine`] — the integration a CEX copies.
//!
//! Hand-rolled HTTP/1.1 like every lab edge (no hyper/tokio; the faucet's
//! posture): one route that decides, everything else refused by name.
//!
//! ```text
//! POST /v1/credit          body = the §3 envelope, raw bytes
//!   200 {"credited":{...}}                    the proven claim + coordinates
//!   4xx {"refusal":"<token>","detail":"..."}  a DECISION, named
//!   503 {"refusal":"<token>","detail":"..."}  cannot answer (upstream/scan)
//! GET  /v1/status          {"addr_commitment":"...","credited":N}
//! ```
//!
//! Out of reference scope, stated rather than implied: no TLS (the wallet's
//! #297 rustls layering is the pattern if an exchange wants the shell itself
//! hardened — most will put this behind their own edge), no rate limiter
//! (#308's lesson binds anyone adding one: key it on the real client, not the
//! proxy), single-threaded accept loop (crediting is upstream-bound; a real
//! service pools).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::{CreditEngine, Credited};

/// Cap on the request body — the envelope is a ~122 KB object (measured,
/// docs/disclosure-run1/2.md); 8× headroom, then a named 413.
pub const MAX_BODY: usize = 1 << 20;
/// Cap on the header block.
pub const MAX_HEAD: usize = 8 * 1024;

/// A parsed request: method, path, body. The only three things the shell
/// routes on.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Why a request never reached the engine. Shell-level refusals, same
/// token+status discipline as [`Refusal`].
#[derive(Debug, PartialEq, Eq)]
pub enum BadRequest {
    /// Malformed request line / header block, or headers over [`MAX_HEAD`].
    Unreadable(&'static str),
    /// Declared body over [`MAX_BODY`] — the envelope is ~122 KB; this is
    /// not one.
    TooLarge { declared: usize },
}

impl BadRequest {
    pub fn token(&self) -> &'static str {
        match self {
            BadRequest::Unreadable(_) => "bad-request",
            BadRequest::TooLarge { .. } => "envelope-too-large",
        }
    }
    pub fn http_status(&self) -> u16 {
        match self {
            BadRequest::Unreadable(_) => 400,
            BadRequest::TooLarge { .. } => 413,
        }
    }
    pub fn detail(&self) -> String {
        match self {
            BadRequest::Unreadable(why) => (*why).into(),
            BadRequest::TooLarge { declared } => {
                format!("declared body of {declared} B exceeds the {MAX_BODY} B cap (an envelope is ~122 KB)")
            }
        }
    }
}

/// Read one request. Blocking, bounded: header block capped at [`MAX_HEAD`],
/// body read to an exact `Content-Length` capped at [`MAX_BODY`]; no
/// chunked-transfer support (a reference client sends one measured buffer).
pub fn read_request(stream: &mut impl Read) -> Result<Request, BadRequest> {
    // Head, byte-at-a-time until CRLFCRLF (bounded, no over-read into body).
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(BadRequest::Unreadable("header block too large"));
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return Err(BadRequest::Unreadable("connection closed mid-request")),
        }
    }
    let head = String::from_utf8(head).map_err(|_| BadRequest::Unreadable("non-utf8 head"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, path) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(p), Some(v)) if v.starts_with("HTTP/1.") && !m.is_empty() && p.starts_with('/') => {
            (m.to_string(), p.to_string())
        }
        _ => return Err(BadRequest::Unreadable("malformed request line")),
    };
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v
                    .trim()
                    .parse()
                    .map_err(|_| BadRequest::Unreadable("bad content-length"))?;
            }
        }
    }
    if content_length > MAX_BODY {
        return Err(BadRequest::TooLarge { declared: content_length });
    }
    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .map_err(|_| BadRequest::Unreadable("connection closed mid-body"))?;
    Ok(Request { method, path, body })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Minimal JSON string escaping — quotes, backslashes, control bytes. The
/// only free-form strings crossing out are refusal details (which may quote
/// verifier internals), so this is load-bearing, not cosmetic.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn credited_json(c: &Credited) -> String {
    format!(
        concat!(
            "{{\"credited\":{{",
            "\"value\":{},",
            "\"tx_ref\":\"{}\",",
            "\"addr_commitment\":\"{}\",",
            "\"claim_output_index\":{},",
            "\"height\":{},",
            "\"tx_index\":{},",
            "\"output_index\":{},",
            "\"cm\":\"{}\",",
            "\"finalized_height\":{}",
            "}}}}"
        ),
        c.claim.value,
        hex(&c.claim.tx_ref),
        hex(&c.claim.addr_commitment),
        c.claim.output_index,
        c.height,
        c.tx_index,
        c.output_index,
        hex(&c.cm),
        c.finalized_height,
    )
}

pub fn refusal_json(token: &str, detail: &str) -> String {
    format!("{{\"refusal\":\"{}\",\"detail\":\"{}\"}}", token, json_escape(detail))
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Response",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

/// Serve forever on `listener`. `upstream` is the node discovery endpoint's
/// base URL; the engine's fetch is [`qlab_cbserver::client::http_get`] over
/// it — the same plaintext client the reference wallet uses.
pub fn serve(listener: TcpListener, mut engine: CreditEngine, upstream: String) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let req = match read_request(&mut stream) {
            Ok(req) => req,
            Err(bad) => {
                respond(
                    &mut stream,
                    bad.http_status(),
                    &refusal_json(bad.token(), &bad.detail()),
                );
                continue;
            }
        };
        match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/v1/credit") => {
                let mut fetch = |path: &str| {
                    qlab_cbserver::client::http_get(&upstream, path).map_err(|e| e.to_string())
                };
                match engine.try_credit(&req.body, &mut fetch) {
                    Ok(credited) => respond(&mut stream, 200, &credited_json(&credited)),
                    Err(refusal) => respond(
                        &mut stream,
                        refusal.http_status(),
                        &refusal_json(refusal.token(), &refusal.detail()),
                    ),
                }
            }
            ("GET", "/v1/status") => {
                let body = format!(
                    "{{\"addr_commitment\":\"{}\",\"credited\":{}}}",
                    hex(&engine.keys_addr_commitment()),
                    engine.credited_count()
                );
                respond(&mut stream, 200, &body);
            }
            ("POST", _) | ("GET", _) => {
                respond(&mut stream, 404, &refusal_json("no-such-route", "POST /v1/credit and GET /v1/status are the surface"));
            }
            _ => {
                respond(&mut stream, 405, &refusal_json("method-not-allowed", "POST /v1/credit and GET /v1/status are the surface"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(bytes: &[u8]) -> Result<Request, BadRequest> {
        read_request(&mut std::io::Cursor::new(bytes.to_vec()))
    }

    /// The parser reads exactly what the reference client sends: a request
    /// line, a content-length, a body.
    #[test]
    fn a_post_with_a_body_parses() {
        let r = req(b"POST /v1/credit HTTP/1.1\r\ncontent-length: 4\r\n\r\nabcd").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/v1/credit");
        assert_eq!(r.body, b"abcd");
    }

    /// Shell refusals are named and 4xx: oversize is 413 by declared length
    /// (never buffered first), garbage is 400.
    #[test]
    fn shell_refusals_are_named_and_bounded() {
        let over = format!("POST /v1/credit HTTP/1.1\r\ncontent-length: {}\r\n\r\n", MAX_BODY + 1);
        let r = req(over.as_bytes()).unwrap_err();
        assert_eq!(r.token(), "envelope-too-large");
        assert_eq!(r.http_status(), 413);

        let r = req(b"garbage\r\n\r\n").unwrap_err();
        assert_eq!(r.token(), "bad-request");
        assert_eq!(r.http_status(), 400);

        let r = req(b"GET / HTTP/1.1\r\ncontent-length: zz\r\n\r\n").unwrap_err();
        assert_eq!(r.http_status(), 400);
    }

    /// The escaper survives the strings a verifier reason can carry.
    #[test]
    fn json_escaping_is_load_bearing() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        let body = refusal_json("proof-refused", "why: \"quoted\"\nline2");
        assert!(body.contains("\\\"quoted\\\""));
        assert!(!body.contains('\n'));
    }
}
