//! The wallet's HTTP clients for the served send seams (issue #276, the wallet
//! half of the stamped A1+B1 decision).
//!
//! Three endpoints on one `qumbra-node` discovery server:
//!
//! - `GET /v1/tree/leaves?from=N` — [`HttpLeafSource`], the witness source (B1).
//! - `GET /v1/anchors` — [`HttpAnchorSource`], which leaf count a witness may
//!   legally be built at. See [`crate::sync`] for why the leaf stream alone
//!   cannot answer that.
//! - `POST /v1/tx` — [`submit_tx`], the way in (A1).
//!
//! # This module decodes nothing itself
//!
//! Every wire here is `qlab_node`'s, and this module calls **its** decoders —
//! `TreeLeaves::from_bytes` and `AnchorSet::from_bytes`. #275 froze the
//! leaf-stream framing with golden vectors (stamp rider 1) precisely so there
//! would be one reading of it; a wallet-side re-implementation would be the
//! drift those vectors exist to prevent. What this module owns is the *paging*
//! (`from + n` until `from + n == total`) and the transport.
//!
//! # Why the submit response is not parsed into a type here
//!
//! `POST /v1/tx` answers a status code and a text line whose **first token is
//! machine-usable** (`accepted` / `duplicate` / `refused: <name>` /
//! `unavailable: <name>` — pinned in `qumbra_node::discovery_server`'s module
//! docs). [`SubmitAnswer`] keeps the body **verbatim** and classifies it only
//! by that first token. Re-typing the refusal vocabulary wallet-side would mean
//! two lists to keep in step, and the failure mode is the boolean-blindness the
//! whole A1 choice was made to avoid: an unrecognised refusal must still reach
//! the user with its own words, not as "rejected".

use qlab_node::{AnchorSet, TreeLeaves};

use crate::sync::{AnchorSource, Anchors, LeafChunk, LeafSource};

/// Read timeout for every request this module makes.
///
/// Basis: the server's own `SUBMIT_VERDICT_TIMEOUT` is 60 s (a submission waits
/// on the consensus loop, and issue #107 measured deployed loop periods that
/// never got below 131 s), so a client that gave up sooner than the server
/// answers would turn its own impatience into a mystery. 90 s covers the
/// server's own ceiling with slack. Reads are safe to retry: a landed-but-
/// unanswered submission comes back `duplicate`.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// The leaf stream as a [`LeafSource`] — one `GET /v1/tree/leaves?from=N` per
/// call, decoded by `qlab_node`'s own `TreeLeaves::from_bytes`.
///
/// The paging loop lives in [`crate::sync::sync_tree`]; this is one page. The
/// server bounds a page at `MAX_TREE_LEAVES` and carries `n` explicitly, so a
/// client that keeps asking from `from + n` is correct without knowing that
/// bound — which is exactly what lets the bound move without touching the
/// golden.
pub struct HttpLeafSource {
    base_url: String,
}

impl HttpLeafSource {
    /// `base_url` is `http://host:port` — the node's `discovery_addr`.
    pub fn new(base_url: impl Into<String>) -> HttpLeafSource {
        HttpLeafSource { base_url: base_url.into() }
    }
}

impl LeafSource for HttpLeafSource {
    fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
        let bytes = http_get(&self.base_url, &format!("/v1/tree/leaves?from={from}"))
            .map_err(|e| format!("GET /v1/tree/leaves?from={from}: {e}"))?;
        let page = TreeLeaves::from_bytes(&bytes)
            .map_err(|e| format!("GET /v1/tree/leaves?from={from} did not decode: {e:?}"))?;
        Ok(LeafChunk { from: page.from, total: page.total, leaves: page.leaves })
    }
}

/// The node's valid-anchor set as an [`AnchorSource`] — `GET /v1/anchors`,
/// decoded by `qlab_node`'s own `AnchorSet::from_bytes`.
pub struct HttpAnchorSource {
    base_url: String,
}

impl HttpAnchorSource {
    pub fn new(base_url: impl Into<String>) -> HttpAnchorSource {
        HttpAnchorSource { base_url: base_url.into() }
    }
}

impl AnchorSource for HttpAnchorSource {
    fn anchors(&self) -> Result<Anchors, String> {
        let bytes = http_get(&self.base_url, "/v1/anchors")
            .map_err(|e| format!("GET /v1/anchors: {e}"))?;
        let set = AnchorSet::from_bytes(&bytes)
            .map_err(|e| format!("GET /v1/anchors did not decode: {e:?}"))?;
        Ok(Anchors {
            tip_height: set.tip_height,
            finalized_height: set.finalized_height,
            max_age_blocks: set.max_age_blocks,
            roots: set.roots,
        })
    }
}

/// What the node said about a submission — its **own words**, plus the class
/// read off the first token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitAnswer {
    /// HTTP status the node answered with (202 / 200 / 400 / 413 / 500 / 503).
    pub status: u16,
    /// The response line, **verbatim**. This is what a user is shown.
    pub body: String,
}

/// How a [`SubmitAnswer`] should be acted on — deliberately coarse. The reason
/// a refusal gives is [`SubmitAnswer::body`]'s job, not this enum's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitClass {
    /// `202 accepted <txid>` — admitted and relayed.
    Accepted,
    /// `200 duplicate <txid>` — already pending; the retry-safe answer.
    Duplicate,
    /// `4xx refused: <name>` — the transaction's own fault, named.
    Refused,
    /// `5xx unavailable: <name>` — the node's state, not the transaction's.
    /// Retrying later is meaningful; rebuilding the transaction is not.
    Unavailable,
    /// Anything this binary does not recognise. Never flattened into one of
    /// the above: a node newer than this wallet must be able to say something
    /// this wallet has never heard of, and have it reach the user intact.
    Unknown,
}

impl SubmitAnswer {
    /// The transaction id the node echoed, when it echoed one (`accepted` and
    /// `duplicate` both carry it — the statement tx id).
    pub fn txid_hex(&self) -> Option<&str> {
        let (head, rest) = self.body.split_once(' ')?;
        matches!(head, "accepted" | "duplicate").then_some(rest.trim())
    }

    pub fn class(&self) -> SubmitClass {
        match self.body.split_whitespace().next() {
            Some("accepted") => SubmitClass::Accepted,
            Some("duplicate") => SubmitClass::Duplicate,
            Some("refused:") => SubmitClass::Refused,
            Some("unavailable:") => SubmitClass::Unavailable,
            _ => SubmitClass::Unknown,
        }
    }

    /// True when the submission is known to be in the node's pool — the only
    /// two answers that mean "this transaction is in flight".
    pub fn is_in_flight(&self) -> bool {
        matches!(self.class(), SubmitClass::Accepted | SubmitClass::Duplicate)
    }
}

/// `POST /v1/tx` with the canonical transaction wire bytes as the body.
///
/// An `Err` here means the exchange never completed (no socket, no response) —
/// which is NOT the same as a refusal and must not be reported as one: a
/// submission whose response was lost may well have landed, and the honest
/// follow-up is resubmitting, which answers `duplicate`.
pub fn submit_tx(base_url: &str, wire_bytes: &[u8]) -> std::io::Result<SubmitAnswer> {
    let (status, body) = http_post(base_url, "/v1/tx", wire_bytes)?;
    Ok(SubmitAnswer { status, body })
}

// ---------------------------------------------------------------------------
// Transport — dependency-free std, the same posture as qlab_cbserver::client
// ---------------------------------------------------------------------------

/// `GET` returning the body bytes. Reuses `qlab_cbserver`'s client rather than
/// keeping a second HTTP GET in the workspace; both ends are ours.
fn http_get(base_url: &str, path_and_query: &str) -> std::io::Result<Vec<u8>> {
    qlab_cbserver::client::http_get(base_url, path_and_query)
}

/// Minimal dependency-free HTTP/1.1 `POST` over `TcpStream`, returning
/// `(status, body)`.
///
/// Unlike the GET helper this does **not** treat a non-200 as an error: on this
/// route the interesting answers are 202, 400 and 503, and their bodies are the
/// payload. Turning them into `io::Error` would discard exactly the typed
/// vocabulary A1 was chosen for.
fn http_post(base_url: &str, path: &str, body: &[u8]) -> std::io::Result<(u16, String)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let authority = base_url.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "base_url must be http://")
    })?;
    let mut stream = TcpStream::connect(authority)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP header terminator")
    })?;
    let header = &raw[..sep];
    let raw_body = &raw[sep + 4..];

    // "HTTP/1.1 202 Accepted" → 202.
    let status_line = String::from_utf8_lossy(header.split(|&b| b == b'\n').next().unwrap_or(b""));
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unparseable status line: {status_line}"),
            )
        })?;

    let header_lc = header.to_ascii_lowercase();
    let chunked = header_lc
        .windows(b"transfer-encoding: chunked".len())
        .any(|w| w == b"transfer-encoding: chunked");
    let bytes = if chunked { dechunk(raw_body)? } else { raw_body.to_vec() };
    Ok((status, String::from_utf8_lossy(&bytes).trim().to_string()))
}

/// Decode an HTTP/1.1 `Transfer-Encoding: chunked` body — tiny_http replies
/// chunked, so this is not optional.
fn dechunk(mut b: &[u8]) -> std::io::Result<Vec<u8>> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunked body");
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_tok = &b[..line_end];
        let hex_end = size_tok.iter().position(|&c| c == b';').unwrap_or(size_tok.len());
        let size_str = std::str::from_utf8(&size_tok[..hex_end]).map_err(|_| bad())?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| bad())?;
        b = &b[line_end + 2..];
        if size == 0 {
            break;
        }
        if b.len() < size + 2 {
            return Err(bad());
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> SubmitAnswer {
        SubmitAnswer { status, body: body.to_string() }
    }

    /// The four classes the server's pinned response wire actually produces,
    /// read off the first token — and the txid echo on the two that carry one.
    #[test]
    fn the_pinned_response_wire_classifies_by_its_first_token() {
        let acc = answer(202, "accepted 1f2e3d4c");
        assert_eq!(acc.class(), SubmitClass::Accepted);
        assert_eq!(acc.txid_hex(), Some("1f2e3d4c"));
        assert!(acc.is_in_flight());

        let dup = answer(200, "duplicate 1f2e3d4c");
        assert_eq!(dup.class(), SubmitClass::Duplicate);
        assert_eq!(dup.txid_hex(), Some("1f2e3d4c"));
        assert!(dup.is_in_flight(), "a duplicate IS in flight — retry is safe, not a failure");

        let ref_ = answer(400, "refused: wrong-fee expected=1000000 got=1");
        assert_eq!(ref_.class(), SubmitClass::Refused);
        assert_eq!(ref_.txid_hex(), None);
        assert!(!ref_.is_in_flight());

        let un = answer(503, "unavailable: state-lag — this node's applied state is behind");
        assert_eq!(un.class(), SubmitClass::Unavailable);
        assert!(!un.is_in_flight());
    }

    /// A refusal this binary has never heard of stays `Unknown` and keeps its
    /// own words. Flattening it would be the boolean blindness A1 exists to
    /// avoid, and a node is allowed to be newer than its wallet.
    #[test]
    fn an_unrecognised_answer_is_unknown_and_never_flattened() {
        let odd = answer(418, "refused-in-some-future-vocabulary: teapot");
        assert_eq!(odd.class(), SubmitClass::Unknown);
        assert!(!odd.is_in_flight(), "unknown is never treated as in flight");
        assert_eq!(odd.body, "refused-in-some-future-vocabulary: teapot", "verbatim, always");
        assert_eq!(odd.txid_hex(), None);
    }

    /// Every refusal name the server can currently render classifies as a
    /// refusal or an unavailability — the two the CLI renders differently. This
    /// is the wallet-side half of the "do not flatten the vocabulary" rule, and
    /// it is written against the strings `render_submit_outcome` produces.
    #[test]
    fn the_servers_whole_refusal_vocabulary_lands_in_the_right_class() {
        for name in [
            "refused: nullifier-repeated-in-tx",
            "refused: discovery-not-canonical",
            "refused: discovery-does-not-bind expected=1 got=2",
            "refused: wrong-fee expected=1000000 got=1",
            "refused: anchor-not-valid",
            "refused: nullifier-spent",
            "refused: nullifier-conflict-in-pool",
            "refused: proof-invalid",
            "refused: body-too-large (> 262144 bytes)",
            "refused: body-unreadable",
        ] {
            assert_eq!(answer(400, name).class(), SubmitClass::Refused, "{name}");
        }
        for name in [
            "unavailable: state-lag — this node's applied state is behind its chain",
            "unavailable: submit-queue-full — the node is behind on verdicts; retry",
            "unavailable: submit-busy — too many submissions in flight; retry",
            "unavailable: no-verdict-in-time — the node loop did not answer within 60s",
            "unavailable: node-shutting-down",
        ] {
            assert_eq!(answer(503, name).class(), SubmitClass::Unavailable, "{name}");
        }
    }

    #[test]
    fn a_non_http_base_url_is_refused_before_a_socket_is_opened() {
        let e = submit_tx("https://node.example", b"x").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn dechunk_reassembles_a_chunked_body() {
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n\r\n").unwrap(), b"hello");
        assert_eq!(dechunk(b"0\r\n\r\n").unwrap(), b"");
        assert!(dechunk(b"5\r\nhi\r\n0\r\n\r\n").is_err(), "a short chunk is malformed");
    }
}
