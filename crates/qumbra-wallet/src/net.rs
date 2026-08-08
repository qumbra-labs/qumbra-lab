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
//!
//! # `http://` and `https://`, one connect seam (issue #297)
//!
//! The deployed wallet-facing endpoint is https-only by decision
//! (`qumbra-design/t1-public-host-decision.md`), and this crate refused
//! anything but `http://` — so the stamped A1+B1 send path could not be walked
//! from a user's machine at all. The fix is deliberately *narrow*: [`connect`]
//! resolves the scheme and hands back a byte stream, rustls or plain, and
//! **every line of HTTP/1.1 above it is unchanged**. No `ureq`, no `hyper`:
//! the problem was never the HTTP, and replacing working code that speaks the
//! typed 202/400/503 vocabulary would have cost the thing A1 was chosen for.
//!
//! Classical TLS is accepted for the T1 wallet↔edge hop by coordinator ruling
//! (#297, 2026-08-08). The load-bearing property is **server authentication**;
//! the payload — tx wire bytes, tree leaves, compact blocks — is chain-public
//! by design, so confidentiality is not what is being bought. PQ-hybrid key
//! exchange at the Cloudflare edge is outside the wallet's control, and this is
//! testnet-tunable, revisited at T2.

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
    /// `base_url` is `http://host:port` or `https://host[:port]` — the node's
    /// `discovery_addr`, or the public edge in front of it.
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
// Transport — std, plus rustls as a stream layer. ONE connect seam (issue #297)
// ---------------------------------------------------------------------------

/// The refusal a `base_url` in neither accepted scheme gets. It names **both**
/// schemes, because the failure this string exists to explain is a user who
/// typed the wrong one, and a refusal that only names the alternative it is
/// not is how #297 read to the person who filed it.
pub const SCHEME_REFUSAL: &str = "base_url must be http://host:port or https://host[:port]";

/// Where a request goes and whether TLS wraps it — the whole of what a
/// `base_url` decides, resolved once, with no I/O.
///
/// Split out from [`connect`] on purpose: everything scheme-and-authority
/// parsing gets wrong is decided here, so the tests that pin it need no socket
/// and no server (issue #297 scope item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Exactly what `TcpStream::connect` is handed.
    pub dial: String,
    /// The `Host:` header — the authority **as the caller wrote it**, scheme
    /// stripped and nothing added. An https URL with no port dials `:443` and
    /// still sends `Host: host`, which is what an origin behind a proxy expects
    /// and what every other client sends.
    pub host: String,
    /// `Some(name)` under TLS — the SNI *and* the name the certificate is
    /// checked against, which are the same name by construction here.
    pub sni: Option<String>,
}

fn refuse(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

/// Resolve a `base_url` into an [`Endpoint`], or refuse it by name.
///
/// - `http://authority` — **unchanged from before #297**: the authority is used
///   verbatim and a port is still required, because nothing on this path has
///   ever defaulted one and silently inventing `:80` would change what an
///   existing command line means.
/// - `https://host[:port]` — port defaults to 443, SNI is the host.
/// - anything else — [`SCHEME_REFUSAL`], `InvalidInput`, before any socket.
pub fn endpoint_of(base_url: &str) -> std::io::Result<Endpoint> {
    if let Some(authority) = base_url.strip_prefix("http://") {
        if authority.is_empty() {
            return Err(refuse(SCHEME_REFUSAL));
        }
        return Ok(Endpoint {
            dial: authority.to_string(),
            host: authority.to_string(),
            sni: None,
        });
    }
    if let Some(authority) = base_url.strip_prefix("https://") {
        return https_endpoint(authority);
    }
    Err(refuse(SCHEME_REFUSAL))
}

fn https_endpoint(authority: &str) -> std::io::Result<Endpoint> {
    if authority.is_empty() {
        return Err(refuse(SCHEME_REFUSAL));
    }
    // A path is refused rather than ignored: `https://host/v1` would otherwise
    // become a `Host:` header with a slash in it and a request line with the
    // path twice. (The http arm is deliberately NOT given this check — its
    // behaviour is frozen at "verbatim", and changing it is not this baton's.)
    if authority.contains('/') {
        return Err(refuse(format!(
            "https base_url takes host[:port] and no path — got `{authority}`"
        )));
    }
    let (name, has_port) = match authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:9450`.
        Some(rest) => {
            let close =
                rest.find(']').ok_or_else(|| refuse("unterminated `[` in an IPv6 base_url"))?;
            let after = &rest[close + 1..];
            if !(after.is_empty() || after.starts_with(':')) {
                return Err(refuse(SCHEME_REFUSAL));
            }
            (rest[..close].to_string(), !after.is_empty())
        }
        None => match authority.split_once(':') {
            Some((h, _port)) => (h.to_string(), true),
            None => (authority.to_string(), false),
        },
    };
    if name.is_empty() {
        return Err(refuse(SCHEME_REFUSAL));
    }
    Ok(Endpoint {
        dial: if has_port { authority.to_string() } else { format!("{authority}:443") },
        host: authority.to_string(),
        sni: Some(name),
    })
}

/// The one process-wide client config: webpki roots, no client auth.
///
/// **Webpki roots only, and no `rustls-native-certs`** — reading the platform
/// trust store would make server authentication mean "whatever this machine has
/// been told to trust", and server authentication is the entire property
/// classical TLS buys the wallet (issue #297's PQ scope note: the payload is
/// chain-public, the *identity of who served it* is not). Certificate pinning
/// is a named non-goal of this baton.
fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let roots =
            rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// A connected byte stream — `TcpStream` or rustls-over-`TcpStream`, and the
/// HTTP/1.1 code above this line cannot tell which.
trait ReadWrite: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

/// **The connect seam.** Everything scheme-dependent in this module is here;
/// both verbs above it are written once, against a stream.
///
/// Returns the stream and the `Host:` header value, so no caller re-derives the
/// authority from the URL a second time.
fn connect(base_url: &str) -> std::io::Result<(Box<dyn ReadWrite>, String)> {
    let ep = endpoint_of(base_url)?;
    let tcp = std::net::TcpStream::connect(&ep.dial)?;
    tcp.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    tcp.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    match ep.sni {
        None => Ok((Box::new(tcp), ep.host)),
        Some(name) => {
            let server_name = rustls::pki_types::ServerName::try_from(name.clone())
                .map_err(|e| refuse(format!("`{name}` is not a valid TLS server name: {e}")))?;
            let mut conn = rustls::ClientConnection::new(tls_config(), server_name).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("TLS client setup failed: {e}"),
                )
            })?;
            let mut tcp = tcp;
            // Handshake **here**, explicitly, rather than letting the first
            // `write_all` do it lazily. Measured against badssl.com: driven
            // lazily, an expired or wrong-host certificate surfaces as
            // `Connection reset by peer (os error 54)` — rustls' fatal alert
            // races the peer's reset and the reset is what the user is shown.
            // A wallet that reports a certificate refusal as a network blip
            // invites exactly the retry that should never happen.
            //
            // A TLS failure is an error and never a silent downgrade: there is
            // no http fallback on this path, by decision (#297 stop points).
            conn.complete_io(&mut tcp).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("TLS handshake with `{name}` failed: {e}"),
                )
            })?;
            Ok((Box::new(rustls::StreamOwned::new(conn, tcp)), ep.host))
        }
    }
}

/// Read a whole `Connection: close` response: `(status, body bytes)`.
///
/// Shared by both verbs so the chunked/`Content-Length`-less handling cannot
/// drift between them.
fn read_response(stream: &mut dyn ReadWrite) -> std::io::Result<(u16, Vec<u8>)> {
    let mut raw = Vec::new();
    if let Err(e) = stream.read_to_end(&mut raw) {
        // A TLS peer that closes the connection without a `close_notify` — and
        // plenty do — surfaces as `UnexpectedEof` *after* the response is
        // already in hand. Failing a complete response over the peer's
        // shutdown manners would be a worse answer than the answer. An
        // `UnexpectedEof` with nothing read is still an error: that is a
        // truncated exchange and there is nothing to parse.
        if !(e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty()) {
            return Err(e);
        }
    }

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
    Ok((status, bytes))
}

/// `GET` returning the body bytes, over the connect seam. A non-200 is an
/// error here — unlike [`http_post`], this route has no typed non-200 answers.
///
/// **This used to delegate to `qlab_cbserver::client::http_get`** and no longer
/// can: that helper is plaintext-only and gaining a TLS stack would put rustls
/// into `qlab-node`'s (and therefore the consensus node's) build graph. The
/// duplication that delegation avoided is real, and the trade is stated on
/// issue #297 rather than made quietly.
fn http_get(base_url: &str, path_and_query: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Write;

    let (mut stream, host) = connect(base_url)?;
    let req = format!("GET {path_and_query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let (status, body) = read_response(stream.as_mut())?;
    if status != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("non-200 response: HTTP {status}"),
        ));
    }
    Ok(body)
}

/// The scan's fetch, over this module's connect seam — the closure
/// [`qlab_cbserver::client::light_client_scan_with`] runs on.
///
/// This exists because `light_client_scan`'s own fetch is built from
/// `qlab_cbserver`'s plaintext-only GET, so a `scan --url https://…` would
/// refuse in a crate this baton deliberately did not give a TLS stack to. The
/// scan *flow* is still qlab-cbserver's, unreimplemented and unmodified — only
/// the transport under it is this crate's.
pub fn scan_fetch(base_url: &str) -> impl FnMut(&str) -> Result<Vec<u8>, String> + '_ {
    move |path: &str| http_get(base_url, path).map_err(|e| e.to_string())
}

/// Minimal hand-rolled HTTP/1.1 `POST` over the connect seam, returning
/// `(status, body)`.
///
/// Unlike the GET helper this does **not** treat a non-200 as an error: on this
/// route the interesting answers are 202, 400 and 503, and their bodies are the
/// payload. Turning them into `io::Error` would discard exactly the typed
/// vocabulary A1 was chosen for.
fn http_post(base_url: &str, path: &str, body: &[u8]) -> std::io::Result<(u16, String)> {
    use std::io::Write;

    let (mut stream, host) = connect(base_url)?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let (status, bytes) = read_response(stream.as_mut())?;
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

    // -----------------------------------------------------------------------
    // The connect seam (issue #297). Pure: scheme and authority are resolved
    // with no I/O, so none of these opens a socket or needs a server.
    // -----------------------------------------------------------------------

    /// `https://host` with no port dials 443 and takes the host as SNI — and
    /// the `Host:` header stays the authority **as written**, without the port
    /// the URL did not carry. That last part is what an origin behind a proxy
    /// is matched on, so it is not cosmetic.
    #[test]
    fn https_defaults_to_443_and_carries_the_host_as_written() {
        let ep = endpoint_of("https://h").unwrap();
        assert_eq!(ep.dial, "h:443");
        assert_eq!(ep.host, "h");
        assert_eq!(ep.sni.as_deref(), Some("h"));

        let real = endpoint_of("https://seed.qumbra.org").unwrap();
        assert_eq!(real.dial, "seed.qumbra.org:443");
        assert_eq!(real.host, "seed.qumbra.org");
        assert_eq!(real.sni.as_deref(), Some("seed.qumbra.org"));
    }

    /// An explicit https port is dialled as given, and the SNI is still the
    /// bare host — a certificate is issued for a name, never for a port.
    #[test]
    fn an_explicit_https_port_is_kept_and_the_sni_is_the_bare_host() {
        let ep = endpoint_of("https://h:9450").unwrap();
        assert_eq!(ep.dial, "h:9450");
        assert_eq!(ep.host, "h:9450");
        assert_eq!(ep.sni.as_deref(), Some("h"));
    }

    /// The plaintext path is byte-for-byte what it was before #297: authority
    /// verbatim, no TLS, and **no defaulted port** — `http://h` stays a thing
    /// that fails at connect rather than silently becoming `h:80`, because
    /// nothing on this path has ever defaulted a port and inventing one would
    /// change what an existing command line means.
    #[test]
    fn http_is_unchanged_and_never_defaults_a_port() {
        let ep = endpoint_of("http://h:9490").unwrap();
        assert_eq!(ep.dial, "h:9490");
        assert_eq!(ep.host, "h:9490");
        assert_eq!(ep.sni, None, "no TLS on the plaintext path");

        let no_port = endpoint_of("http://h").unwrap();
        assert_eq!(no_port.dial, "h", "http does NOT gain a default port from #297");
    }

    /// An IPv6 literal keeps its brackets for the dial and loses them for the
    /// name — `ServerName` takes the address, not the URL syntax around it.
    #[test]
    fn an_ipv6_literal_is_bracketed_to_dial_and_bare_as_a_name() {
        let ep = endpoint_of("https://[::1]").unwrap();
        assert_eq!(ep.dial, "[::1]:443");
        assert_eq!(ep.sni.as_deref(), Some("::1"));

        let ported = endpoint_of("https://[::1]:9450").unwrap();
        assert_eq!(ported.dial, "[::1]:9450");
        assert_eq!(ported.sni.as_deref(), Some("::1"));
    }

    /// **The #297 lock, inverted.** `https://` was refused here and is now the
    /// point; what must still be refused — before a socket is opened — is a
    /// scheme this wallet does not speak, and the refusal must name *both* the
    /// schemes it does. A refusal that names only one is how the original
    /// `must be http://` read to the person who filed #297.
    #[test]
    fn an_unknown_scheme_is_refused_before_a_socket_and_names_both_schemes() {
        for url in ["ws://node.example", "file:///etc/passwd", "node.example:9490", ""] {
            let e = endpoint_of(url).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{url}");
            let msg = e.to_string();
            assert!(msg.contains("http://"), "{url}: refusal must name http:// — {msg}");
            assert!(msg.contains("https://"), "{url}: refusal must name https:// — {msg}");
        }
    }

    /// The same refusal reached through the real entry point, which is the
    /// property the retired `net.rs:335` assertion actually held: a bad scheme
    /// costs no socket. `ws://` cannot resolve, so an `Err` here is the parse
    /// refusing and not a connection failing.
    #[test]
    fn submit_tx_refuses_an_unspeakable_scheme_before_it_opens_a_socket() {
        let e = submit_tx("ws://node.example", b"x").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("https://"));
    }

    /// A path on an https base_url is refused by name rather than folded into
    /// the `Host:` header. (The http arm is deliberately left verbatim — its
    /// behaviour is frozen and widening it is not this baton's.)
    #[test]
    fn an_https_base_url_with_a_path_is_refused_by_name() {
        let e = endpoint_of("https://h/v1").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("no path"), "{e}");
    }

    /// The TLS config builds — the one thing in the rustls wiring that can
    /// fail at *runtime* rather than at compile time is the crypto provider not
    /// being installed, and it fails by panicking. This is that check, and it
    /// is also the assertion that the compiled-in Mozilla root program is not
    /// empty (an empty root store would trust nothing and fail every handshake
    /// with a bad-certificate error that looks like the server's fault).
    #[test]
    fn the_tls_config_builds_and_the_root_store_is_not_empty() {
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty(), "webpki roots compiled in");
        let a = tls_config();
        let b = tls_config();
        assert!(std::sync::Arc::ptr_eq(&a, &b), "one config, built once");
    }

    #[test]
    fn dechunk_reassembles_a_chunked_body() {
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n\r\n").unwrap(), b"hello");
        assert_eq!(dechunk(b"0\r\n\r\n").unwrap(), b"");
        assert!(dechunk(b"5\r\nhi\r\n0\r\n\r\n").is_err(), "a short chunk is malformed");
    }
}
