//! HTTP/1.1 **response framing** for the four hand-rolled clients in this
//! workspace (lab #631).
//!
//! Lifted out of `qumbra-pool` (lab #626 / PR #628) so the pool, the compact
//! client, opview and the wallet share one decoder. Four copies that happen
//! to agree is how #626 survived until an outage found it.
//!
//! ## Why this crate exists
//!
//! The pool's client used to do this:
//!
//! ```text
//! s.read_to_end(&mut raw)?;
//! let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
//! let body = String::from_utf8_lossy(&raw[sep + 4..]);   // <- everything after
//! ```
//!
//! Everything after the header terminator was taken as the body, verbatim.
//! The node is served by `tiny_http`, which switches a response to
//! `Transfer-Encoding: chunked` once the entity is large enough — and a
//! template carrying **one** transaction is ~151 kB. So the pool handed
//! `serde_json` a buffer beginning `2000\r\n{…` (`2000` = hex 8192, the
//! chunk size) and got back
//! `invalid type: integer 2000, expected struct MineTemplateWire at line 1
//! column 4`. Measured on T2: 4,643 consecutive parse failures, the pool
//! dead 2 h 32 min, and it recovered only when a restart emptied the
//! node's mempool. **Any single pending transaction took the pool offline
//! for as long as it stayed pending.**
//!
//! The other three clients already de-chunked, but none honoured
//! `Content-Length`, and they matched the literal lowercased substring
//! `"transfer-encoding: chunked"` (one space after the colon, lowercase
//! value). Against a keep-alive peer each hung to its read timeout. The
//! wallet is the one that talks to a server its operator chose.
//!
//! Two things follow, and both are load-bearing here:
//!
//! 1. **The framing is read, never assumed.** `Content-Length` when
//!    present, chunked when the server says chunked, read-to-EOF only when
//!    the response says nothing (the HTTP/1.0-style close-delimited case
//!    the old code silently assumed always held).
//! 2. **A framing this client cannot decode is a named error** ([`FramingError`]),
//!    not raw bytes handed to a parser. `serde` reporting a chunk size as a
//!    type error is the whole reason #626 took a day to find; the next one
//!    should say `http-framing: unsupported-transfer-encoding: gzip` and be
//!    over in a minute.
//!
//! Field-name lookup is **case-insensitive** ([`Response::header`]). HTTP
//! field names are case-insensitive by definition and matching a literal
//! `"Transfer-Encoding: "` prefix is how a client ends up back where this
//! crate started.
//!
//! ## Deliberately a leaf crate, not an HTTP crate
//!
//! Zero runtime dependencies. A shared internal module is not a new
//! external crate, and that is the point: `qumbra-wallet` and
//! `qlab-cbserver` are the two graphs worth protecting, and putting this
//! decoder in either of them (or in the pool, or in `qlab-node`) would
//! pull the wrong crate into the other three. `ureq`/`hyper` would make
//! the four clients agree by replacing them; that trade, if ever taken,
//! is for all four at once, not for the one that happened to break.

use std::io::Read;

/// The head (status line + fields) may not exceed this before the client
/// gives up. Real heads here are a few hundred bytes; the cap exists so a
/// server that never sends `\r\n\r\n` fails by name instead of growing a
/// buffer until the read timeout.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Cap for a single framing line (a chunk-size line or a trailer). Chunk
/// extensions are short; anything longer is a broken peer.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Socket read granularity. Not a body cap — see [`FramingError::Truncated`]
/// for why a lying `Content-Length` costs a timeout rather than an
/// allocation: the body is accumulated as it arrives, never pre-allocated
/// from a number the peer chose.
const READ_CHUNK: usize = 16 * 1024;

/// A framing this client will not guess at. Every variant renders as
/// `http-framing: <kebab-name>[: detail]` so a log line names the defect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// The peer stopped before sending `\r\n\r\n`.
    NoHeaderTerminator,
    /// The head passed [`MAX_HEAD_BYTES`] with no terminator in it.
    HeadTooLarge { got: usize },
    /// `Content-Length` is not a plain decimal byte count.
    BadContentLength { got: String },
    /// A `Transfer-Encoding` this client cannot decode (`gzip`, `chunked,
    /// gzip`, …). Refused rather than passed through.
    UnsupportedTransferEncoding { got: String },
    /// A chunk-size line that is not `<hex>[;extension…]`.
    BadChunkSize { got: String },
    /// A chunk's data was not followed by CRLF.
    BadChunkTerminator,
    /// A framing line ran past [`MAX_LINE_BYTES`] with no CRLF.
    LineTooLong,
    /// A framing line had no CRLF before the peer went away.
    UnterminatedLine,
    /// The peer stopped before the framing said the body ended.
    Truncated { want: usize, got: usize },
    /// The socket itself failed.
    Io(String),
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FramingError::NoHeaderTerminator => {
                write!(f, "http-framing: no-header-terminator")
            }
            FramingError::HeadTooLarge { got } => {
                write!(
                    f,
                    "http-framing: head-too-large: {got} bytes with no CRLFCRLF"
                )
            }
            FramingError::BadContentLength { got } => {
                write!(f, "http-framing: bad-content-length: `{got}`")
            }
            FramingError::UnsupportedTransferEncoding { got } => {
                write!(f, "http-framing: unsupported-transfer-encoding: `{got}`")
            }
            FramingError::BadChunkSize { got } => {
                write!(f, "http-framing: bad-chunk-size: `{got}`")
            }
            FramingError::BadChunkTerminator => {
                write!(f, "http-framing: bad-chunk-terminator")
            }
            FramingError::LineTooLong => write!(f, "http-framing: line-too-long"),
            FramingError::UnterminatedLine => write!(f, "http-framing: unterminated-line"),
            FramingError::Truncated { want, got } => {
                write!(
                    f,
                    "http-framing: truncated-body: want {want} bytes, got {got}"
                )
            }
            FramingError::Io(e) => write!(f, "http-framing: io: {e}"),
        }
    }
}

impl std::error::Error for FramingError {}

impl From<FramingError> for std::io::Error {
    fn from(e: FramingError) -> Self {
        let kind = match e {
            FramingError::Io(_) => std::io::ErrorKind::Other,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, e)
    }
}

/// One decoded response: the status line verbatim, the fields in wire
/// order, and the body with all framing removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// e.g. `HTTP/1.1 200 OK`. Kept verbatim — callers match on `"200"`.
    pub status: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// First field with this name, **case-insensitively**. `tiny_http` does
    /// not capitalise the way this client's author assumed, and #626 is what
    /// a case-sensitive lookup costs.
    ///
    /// First-match, not join: a response repeating `Content-Length` with two
    /// values is a smuggling shape rather than a framing this client should
    /// average out.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as text. Lossy for the same reason the old client was: the
    /// node's JSON is UTF-8 and a replacement char fails in `serde` with a
    /// better message than a decode error here would give.
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Read one complete HTTP/1.1 response, honouring its framing.
///
/// Generic over [`Read`] on purpose: the decoders are exercised over
/// in-memory bytes in this crate's unit tests and over a real `tiny_http`
/// server in `tests/live_framing.rs`. A hand-written fixture alone
/// encodes the author's belief about what the server sends — and in #626
/// that belief was the bug.
///
/// **This returns at the end of the body**, not at EOF, whenever the
/// response is self-delimiting. That closes the second half of #626: the
/// old `read_to_end` terminated only because the server closed the
/// connection, so a keep-alive peer would have stalled every template poll
/// until the 30 s read timeout.
pub fn read_response<R: Read>(inner: R) -> Result<Response, FramingError> {
    let mut w = Wire::new(inner);

    let sep = loop {
        if let Some(i) = find(w.buffered(), b"\r\n\r\n") {
            break i;
        }
        if w.buffered().len() > MAX_HEAD_BYTES {
            return Err(FramingError::HeadTooLarge {
                got: w.buffered().len(),
            });
        }
        if !w.fill()? {
            return Err(FramingError::NoHeaderTerminator);
        }
    };

    let head = String::from_utf8_lossy(&w.buffered()[..sep]).to_string();
    w.consume(sep + 4);

    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default().trim().to_string();
    // Obsolete line folding (a continuation starting with SP/HTAB) is
    // deprecated by RFC 7230 §3.2.4 and `tiny_http` never emits it; such a
    // line has no colon and is dropped here rather than mis-parsed.
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    let body = match find_header(&headers, "Transfer-Encoding") {
        // RFC 7230 §3.3.3: Transfer-Encoding wins over Content-Length.
        Some(te) => {
            let codings: Vec<&str> = te
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            if codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked") {
                read_chunked(&mut w)?
            } else if codings.is_empty()
                || (codings.len() == 1 && codings[0].eq_ignore_ascii_case("identity"))
            {
                read_delimited(&mut w, &headers)?
            } else {
                // `gzip`, `chunked, gzip`, anything layered. Named, not guessed.
                return Err(FramingError::UnsupportedTransferEncoding {
                    got: te.to_string(),
                });
            }
        }
        None => read_delimited(&mut w, &headers)?,
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// `Content-Length` when present, otherwise read to EOF — the
/// close-delimited case, which is the only one the pre-#626 client handled.
fn read_delimited<R: Read>(
    w: &mut Wire<R>,
    headers: &[(String, String)],
) -> Result<Vec<u8>, FramingError> {
    match find_header(headers, "Content-Length") {
        Some(v) => {
            let n = parse_decimal(v)
                .ok_or_else(|| FramingError::BadContentLength { got: v.to_string() })?;
            w.take(n)
        }
        None => w.rest(),
    }
}

/// `<hex-size>[;ext]CRLF <data> CRLF`, repeated, terminated by a zero-size
/// chunk and optional trailer fields.
fn read_chunked<R: Read>(w: &mut Wire<R>) -> Result<Vec<u8>, FramingError> {
    let mut out = Vec::new();
    loop {
        let line = w.line()?;
        // Chunk extensions (`2000;foo=bar`) are legal and carry nothing this
        // client needs. Ignored, never a failure.
        let size_field = line.split(';').next().unwrap_or("").trim();
        let size =
            parse_hex(size_field).ok_or_else(|| FramingError::BadChunkSize { got: clip(&line) })?;
        if size == 0 {
            // Trailers, then the empty line that ends the message.
            loop {
                if w.line()?.is_empty() {
                    return Ok(out);
                }
            }
        }
        out.extend_from_slice(&w.take(size)?);
        if w.take(2)? != b"\r\n" {
            return Err(FramingError::BadChunkTerminator);
        }
    }
}

/// Strict decimal: `usize::from_str` would accept a leading `+`, and a
/// `Content-Length` that needs interpreting is one this client refuses.
fn parse_decimal(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Strict hex, same reasoning as [`parse_decimal`].
fn parse_hex(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(s, 16).ok()
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Bound what a malformed line puts in a log line.
fn clip(s: &str) -> String {
    let s: String = s.chars().take(64).collect();
    s
}

/// A buffered view of the socket that keeps whatever it read past the point
/// the caller asked for.
///
/// The framing decoders need to stop at the end of the body rather than at
/// EOF, and a `\r\n\r\n` scan necessarily overshoots into the body — so
/// "what was read but not consumed" has to be a real thing this client
/// owns. The old `read_to_end` had nowhere to put it, which is the shape
/// of the #626 bug as much as the missing decode is.
struct Wire<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> Wire<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
            eof: false,
        }
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    /// One more read from the peer. `Ok(false)` is EOF — the peer will send
    /// nothing further, so a caller still waiting on bytes has been truncated.
    fn fill(&mut self) -> Result<bool, FramingError> {
        if self.eof {
            return Ok(false);
        }
        // Drop what has already been consumed so a long chunked body costs
        // the body, not the body plus every chunk header before it.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let n = loop {
            match self.inner.read(&mut self.buf[start..]) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.buf.truncate(start);
                    return Err(FramingError::Io(e.to_string()));
                }
            }
        };
        self.buf.truncate(start + n);
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Exactly `n` more bytes, or [`FramingError::Truncated`].
    fn take(&mut self, n: usize) -> Result<Vec<u8>, FramingError> {
        while self.buffered().len() < n {
            if !self.fill()? {
                return Err(FramingError::Truncated {
                    want: n,
                    got: self.buffered().len(),
                });
            }
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// The next CRLF-terminated line; the CRLF is consumed, not returned.
    fn line(&mut self) -> Result<String, FramingError> {
        loop {
            if let Some(i) = find(self.buffered(), b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[self.pos..self.pos + i]).to_string();
                self.pos += i + 2;
                return Ok(line);
            }
            if self.buffered().len() > MAX_LINE_BYTES {
                return Err(FramingError::LineTooLong);
            }
            if !self.fill()? {
                return Err(FramingError::UnterminatedLine);
            }
        }
    }

    /// Everything until EOF.
    fn rest(&mut self) -> Result<Vec<u8>, FramingError> {
        while self.fill()? {}
        let out = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn read(bytes: &[u8]) -> Result<Response, FramingError> {
        read_response(Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn content_length_takes_exactly_that_many_bytes() {
        // Trailing junk after the body is NOT the body. The pre-#626 client
        // could not tell the difference because it never looked at a length.
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello-and-then-some").unwrap();
        assert_eq!(r.status, "HTTP/1.1 200 OK");
        assert_eq!(r.body_string(), "hello");
    }

    #[test]
    fn chunked_reassembles_across_chunks() {
        let r = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(r.body_string(), "hello world");
    }

    #[test]
    fn chunk_extensions_are_ignored_not_refused() {
        let r = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n0;done\r\n\r\n")
            .unwrap();
        assert_eq!(r.body_string(), "hello");
    }

    #[test]
    fn trailers_after_the_zero_chunk_are_skipped() {
        let r = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Trailer: 1\r\n\r\n")
            .unwrap();
        assert_eq!(r.body_string(), "hi");
    }

    #[test]
    fn chunked_is_recognised_without_a_space_after_the_colon() {
        // Legal HTTP, and the exact shape the other three clients' literal
        // `"transfer-encoding: chunked"` substring missed (lab #631).
        let r =
            read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                .unwrap();
        assert_eq!(r.body_string(), "hello");
    }

    #[test]
    fn field_names_are_matched_case_insensitively() {
        // The exact shape #626 turned on: a literal `"Transfer-Encoding: "`
        // match, or any case-sensitive lookup, hands `2000\r\n…` to serde.
        let r = read(b"HTTP/1.1 200 OK\r\ntRaNsFeR-eNcOdInG: ChUnKeD\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(r.body_string(), "hi");
        assert_eq!(r.header("transfer-encoding"), Some("ChUnKeD"));

        let r = read(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi").unwrap();
        assert_eq!(r.body_string(), "hi");
        assert_eq!(r.header("Content-Length"), Some("2"));
    }

    #[test]
    fn transfer_encoding_wins_over_content_length() {
        // RFC 7230 §3.3.3. A server sending both is telling us the length is
        // stale; reading 4 bytes here would return `2\r\nh`.
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(r.body_string(), "hi");
    }

    #[test]
    fn no_framing_at_all_reads_to_eof() {
        // The close-delimited case the old client assumed always held. It is
        // still legal and still supported — it is just no longer the only path.
        let r = read(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(r.body_string(), "{\"a\":1}");
    }

    #[test]
    fn identity_transfer_encoding_falls_through_to_content_length() {
        let r = read(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 2\r\n\r\nhi!!",
        )
        .unwrap();
        assert_eq!(r.body_string(), "hi");
    }

    #[test]
    fn an_unknown_transfer_encoding_is_named_not_decoded() {
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08")
            .expect_err("gzip must be refused");
        assert_eq!(
            e,
            FramingError::UnsupportedTransferEncoding { got: "gzip".into() }
        );
        assert_eq!(
            e.to_string(),
            "http-framing: unsupported-transfer-encoding: `gzip`"
        );
    }

    #[test]
    fn layered_chunked_plus_gzip_is_refused() {
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
            .expect_err("layered codings must be refused");
        assert!(matches!(
            e,
            FramingError::UnsupportedTransferEncoding { .. }
        ));
    }

    #[test]
    fn a_non_hex_chunk_size_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhi\r\n0\r\n\r\n")
            .expect_err("a non-hex chunk size must be refused");
        assert_eq!(e.to_string(), "http-framing: bad-chunk-size: `zz`");
    }

    #[test]
    fn a_chunk_not_followed_by_crlf_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXX0\r\n\r\n")
            .expect_err("a mis-terminated chunk must be refused");
        assert_eq!(e.to_string(), "http-framing: bad-chunk-terminator");
    }

    #[test]
    fn a_truncated_chunk_is_named_not_returned_short() {
        // The failure mode that matters most: returning the partial body
        // would hand serde a truncated JSON object and report it as a parse
        // error in the node's data. It is a transport failure and says so.
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort")
            .expect_err("a truncated chunk must be refused");
        assert_eq!(
            e,
            FramingError::Truncated { want: 16, got: 5 },
            "0x10 = 16 bytes promised, 5 delivered"
        );
    }

    #[test]
    fn a_short_content_length_body_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort")
            .expect_err("a short body must be refused");
        assert_eq!(
            e.to_string(),
            "http-framing: truncated-body: want 99 bytes, got 5"
        );
    }

    #[test]
    fn a_non_numeric_content_length_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nContent-Length: banana\r\n\r\nhi")
            .expect_err("a non-numeric length must be refused");
        assert_eq!(e.to_string(), "http-framing: bad-content-length: `banana`");
        // `+5` parses under `usize::from_str`; a length needing interpretation
        // is refused rather than guessed.
        assert!(read(b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello").is_err());
    }

    #[test]
    fn a_response_with_no_header_terminator_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n")
            .expect_err("a headless response must be refused");
        assert_eq!(e.to_string(), "http-framing: no-header-terminator");
    }

    #[test]
    fn an_unterminated_chunk_size_line_is_named() {
        let e = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n200")
            .expect_err("an unterminated size line must be refused");
        assert_eq!(e.to_string(), "http-framing: unterminated-line");
    }

    #[test]
    fn an_oversized_head_is_named_rather_than_buffered() {
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        raw.extend_from_slice(&vec![b'x'; MAX_HEAD_BYTES + 1024]);
        let e = read(&raw).expect_err("an unbounded head must be refused");
        assert!(matches!(e, FramingError::HeadTooLarge { .. }), "got {e}");
    }

    #[test]
    fn the_exact_626_wire_shape_deserializes_as_json() {
        // 8192 bytes of body split the way `chunked_transfer` splits it, with
        // the same `2000` first size line the T2 capture showed. Pre-fix this
        // buffer produced `invalid type: integer 2000, expected struct
        // MineTemplateWire at line 1 column 4`.
        let filler = "x".repeat(8192); // `{"txs":["…"]}` adds 12 -> 8204 total
        let json = format!("{{\"txs\":[\"{filler}\"]}}");
        assert_eq!(json.len(), 8204, "the body must cross one chunk boundary");
        let (a, b) = json.split_at(8192);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nServer: tiny-http (Rust)\r\nTransfer-Encoding: chunked\r\n\r\n\
             {:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
            a.len(),
            b.len()
        );
        assert!(
            raw.contains("\r\n\r\n2000\r\n"),
            "first size line is `2000`"
        );
        let r = read(raw.as_bytes()).unwrap();
        assert_eq!(r.body_string(), json);
        let v: serde_json::Value = serde_json::from_str(&r.body_string()).unwrap();
        assert!(v.get("txs").is_some());
    }
}
