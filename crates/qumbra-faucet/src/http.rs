//! The HTTP surface — the part a person actually touches.
//!
//! ```text
//!   GET  /                a form, the faucet's state, and why it is in that state
//!   POST /request         address + ticket → 202 with a receipt, or a NAMED refusal
//!   GET  /r/<receipt>     what happened to one request
//!   GET  /healthz         "ok" — for a supervisor, no state
//!   GET  /favicon-{32,16}.png   the brand mark, compiled in (assets/brand/README.md)
//! ```
//!
//! ## Why `POST`, on a chain whose node deliberately has no write path
//!
//! The node's rule stands untouched: nothing here adds a route to the node, and the
//! only write this process makes to consensus is `RunningNode::submit_local_tx`,
//! which is the node's own local-origination path. The faucet, though, *is* a
//! service whose whole purpose is to accept a request, and a request is a write to
//! the faucet.
//!
//! `POST` rather than `GET ?address=…` is not merely REST taste — it is the
//! **redaction rule**. PR #103 truncates the requester address in `PendingRequest`
//! because *a full address in log rotation is a standing record of who asked for
//! funds on a privacy chain*. A query string is in the request line: it lands in
//! every access log, every proxy log, `Referer` headers and the browser's own
//! history. A form body lands in none of them. So the redaction requirement chooses
//! the method.
//!
//! ## What the log records, and what it refuses to
//!
//! [`FaucetServer`] journals one line per request: method, path, status, and the
//! client's **subnet**, at exactly the granularity `qlab_faucet::policy::subnet_key`
//! charges the rate limiter (/24 for v4, /48 for v6). Not the full client IP —
//! recording which individual asked for funds is the same leak as recording where
//! it went, and the only ops question a faucet log answers is "is one network
//! hammering me", which the subnet answers exactly as well.
//!
//! Never logged, at any level: the recipient address (truncated to 16 characters, the
//! same form and the same length `PendingRequest`'s `Debug` uses), the ticket (a
//! bearer credential), and any request body.
//!
//! ## Rendering
//!
//! No JavaScript, no external fetches, no cookies, no redirects. One `<form>`, text,
//! and two icons **this process serves itself**. A faucet page that pulls a font from
//! a CDN tells that CDN who is asking a privacy chain for money — and an icon is
//! exactly the sub-resource nobody counts as a request, which is why the same-origin
//! requirement is asserted by name in `the_page_has_no_script_and_no_external_reference`
//! rather than left to the no-scheme check that would have missed it.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use qlab_faucet::policy::{subnet_key, SubnetKey};
use qlab_faucet::{AcceptError, Refusal, Ticket};
use qlab_wallet::address::{Address, ADDR_HRP};

use crate::service::{FaucetGate, RequestState};
use crate::state::ServiceStatus;

/// The address shape the form advertises, **derived from the decoder's own HRP**
/// rather than restated (lab issue #296).
///
/// It read `qmb1…` from PR #128 until 2026-08-09 — a prefix
/// [`Address::decode`] rejects outright, sixteen lines above a test that uses
/// `"qmb1nonsense"` as its example of *invalid* input. The failure mode is worse
/// than a blank field: a visitor holding a real `qaddr1…` from `qumbra-wallet
/// address` reads the placeholder and concludes their own address is wrong, and
/// there is nothing else on the page to contradict it.
///
/// `ADDR_HRP` is imported, never copied, so the page cannot outlive an HRP change.
/// The `1` is bech32m's separator (BIP-350), fixed by the encoding rather than
/// chosen by Qumbra, and `qlab_wallet::bech32m` keeps it as a private literal
/// inside `encode` — so it is written here and then **locked against the encoder**
/// by `the_placeholder_is_the_shape_the_decoder_accepts`, which asserts a real
/// encoded address starts with exactly this string. Deriving the HRP alone would
/// not have caught a drift in the separator or the bech32m shape; the test does.
fn address_placeholder() -> String {
    format!("{ADDR_HRP}1…")
}

/// How many characters of an address ever appear anywhere — page, log or receipt.
/// The same 16 `qlab_faucet::PendingRequest`'s hand-written `Debug` shows, so the
/// two redactions cannot drift into two different definitions of "truncated".
pub const ADDR_SHOWN_CHARS: usize = 16;

/// Largest request body accepted, in bytes. An `Address` is 1,233 raw bytes and
/// ~2,000 bech32m characters, and a ticket is 57, so 8 KiB is generous for the one
/// legitimate shape and refuses a body nobody meant to send.
const MAX_BODY_BYTES: usize = 8 * 1024;

/// The brand mark, compiled in. **Copies** — `qumbra-design/brand/` is the source of
/// truth and `assets/brand/README.md` records the rest, including why these are PNG
/// when the canonical file is an SVG. They are `include_bytes!` rather than files on
/// disk because this process serves no static directory: two known byte strings at two
/// known paths is a smaller surface than a file server on the one host in the estate
/// that holds a hot spending key.
const FAVICON_32: &[u8] = include_bytes!("../assets/brand/favicon-32.png");
const FAVICON_16: &[u8] = include_bytes!("../assets/brand/favicon-16.png");

/// A response body and the content type that belongs to it.
///
/// The two travel together so a route cannot answer with one and be labelled the
/// other — which is not hypothetical: `/healthz` answered `"ok\n"` under
/// `text/html; charset=utf-8` for as long as the label was asserted once for every
/// route, and it was harmless only because nothing parsed it.
enum Body {
    Html(String),
    Text(String),
    Png(&'static [u8]),
}

impl Body {
    fn content_type(&self) -> &'static str {
        match self {
            Body::Html(_) => "text/html; charset=utf-8",
            Body::Text(_) => "text/plain; charset=utf-8",
            Body::Png(_) => "image/png",
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self {
            Body::Html(s) | Body::Text(s) => s.into_bytes(),
            Body::Png(b) => b.to_vec(),
        }
    }
}

/// What the listener did with one `POST /request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Admitted. The receipt is the handle; the position is a snapshot.
    Queued { receipt: u64, position: usize },
    /// The submitted address did not decode.
    BadAddress,
    /// The abuse gate refused it (ticket or throttle).
    Refused(Refusal),
    /// The queue is full — the faucet's capacity, not the requester's fault, and no
    /// ticket was burned.
    QueueFull { depth: usize },
    /// The faucet cannot serve inside the wait it quotes. Carries the explanation
    /// (which names the height at which the answer changes) — and no ticket was
    /// burned, because this check runs before the gate.
    Unavailable { explain: String, retry_after_secs: u64 },
}

impl RequestOutcome {
    /// The HTTP status this maps to. **No 5xx anywhere**: every one of these is a
    /// decision the faucet made on purpose, and a 500 would say the opposite.
    pub fn status(&self) -> u16 {
        match self {
            RequestOutcome::Queued { .. } => 202,
            RequestOutcome::BadAddress => 400,
            RequestOutcome::Refused(Refusal::TicketMissing | Refusal::TicketInvalid) => 403,
            RequestOutcome::Refused(Refusal::TicketSpent) => 409,
            RequestOutcome::Refused(Refusal::SubnetThrottled | Refusal::GlobalThrottled) => 429,
            RequestOutcome::QueueFull { .. } => 429,
            RequestOutcome::Unavailable { .. } => 503,
        }
    }

    /// One line for the requester.
    pub fn message(&self) -> String {
        match self {
            RequestOutcome::Queued { receipt, position } => format!(
                "queued at position {position}. Your receipt is {receipt} — check /r/{receipt}."
            ),
            RequestOutcome::BadAddress => "that is not a Qumbra address. Paste the whole \
                 bech32m string your wallet showed you, with no line breaks."
                .to_string(),
            RequestOutcome::Refused(r) => r.to_string(),
            RequestOutcome::QueueFull { depth } => format!(
                "the faucet queue is full ({depth} waiting). Nothing was charged — your ticket, \
                 if you presented one, is still unused."
            ),
            RequestOutcome::Unavailable { explain, .. } => format!(
                "the faucet cannot serve a request right now, and did not queue one it could not \
                 honour: {explain} Nothing was charged — your ticket, if you presented one, is \
                 still unused."
            ),
        }
    }
}

/// A running faucet listener: the bound address, the worker thread, and the shared
/// state it serves.
pub struct FaucetServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
    journal: Arc<Mutex<Vec<String>>>,
}

impl std::fmt::Debug for FaucetServer {
    /// Hand-written, and it shows the bound address and a count. Nothing here reaches
    /// the faucet, so no derived `Debug` on this type can ever print a request, a
    /// recipient address or a ticket — the redaction is structural rather than
    /// remembered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaucetServer")
            .field("addr", &self.addr)
            .field("requests_served", &self.requests_served())
            .finish()
    }
}

impl FaucetServer {
    /// Bind `addr` and serve until [`Self::shutdown`].
    ///
    /// **A failure to bind is an error, never a warning.** The caller is expected to
    /// treat it as fatal — a faucet whose operator believes it is listening and which
    /// is not is worse than one that refused to start, because the failure is
    /// discovered by a user who cannot get funds and has no way to report it.
    /// `metrics_addr`/`telemetry_addr` have exactly this shape.
    pub fn start(
        addr: &str,
        gate: Arc<Mutex<FaucetGate>>,
        status: Arc<Mutex<ServiceStatus>>,
    ) -> io::Result<FaucetServer> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("listen_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("faucet listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));
        let journal = Arc::new(Mutex::new(Vec::new()));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let worker_journal = Arc::clone(&journal);
        let thread = std::thread::spawn(move || {
            for mut request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                let client = request.remote_addr().map(|a| a.to_string()).unwrap_or_default();
                let method = request.method().clone();
                // Query strings are ignored everywhere: this surface takes no
                // parameters, so there is no input in a URL to get wrong — and
                // nothing a requester submits can end up in a log line.
                let path =
                    request.url().split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
                let path = if path.is_empty() { "/".to_string() } else { path };

                let (status_code, body, extra_header) = match (&method, path.as_str()) {
                    (tiny_http::Method::Get, "/healthz") => {
                        (200, Body::Text("ok\n".to_string()), None)
                    }
                    // The two brand icons, compiled in — see assets/brand/PROVENANCE.md
                    // for why they are copies and why they are PNG rather than the SVG.
                    // Cached hard: a favicon is refetched on every page load otherwise,
                    // and each fetch is another line in the access journal.
                    (tiny_http::Method::Get, "/favicon-32.png") => (
                        200,
                        Body::Png(FAVICON_32),
                        Some((
                            "Cache-Control".to_string(),
                            "public, max-age=604800, immutable".to_string(),
                        )),
                    ),
                    (tiny_http::Method::Get, "/favicon-16.png") => (
                        200,
                        Body::Png(FAVICON_16),
                        Some((
                            "Cache-Control".to_string(),
                            "public, max-age=604800, immutable".to_string(),
                        )),
                    ),
                    (tiny_http::Method::Get, "/") => {
                        (200, Body::Html(render_index(&snapshot(&status), None)), None)
                    }
                    (tiny_http::Method::Get, p) if p.starts_with("/r/") => {
                        let receipt = p.trim_start_matches("/r/").parse::<u64>().ok();
                        match receipt.and_then(|r| lock(&gate).state_of(r).map(|s| (r, s))) {
                            Some((r, state)) => {
                                (200, Body::Html(render_receipt(r, &state)), None)
                            }
                            None => (
                                404,
                                Body::Html(page(
                                    "unknown receipt",
                                    "<p>No such receipt. Receipts are per-process: a faucet \
                                     restart forgets them, and the grant — if it was made — is \
                                     on the chain regardless.</p>",
                                )),
                                None,
                            ),
                        }
                    }
                    (tiny_http::Method::Post, "/request") => {
                        let mut body = String::new();
                        // `Read::take` explicitly: `as_reader` hands back a
                        // `&mut dyn Read`, and method syntax would try to call
                        // `take` on the unsized trait object behind it.
                        let read = io::Read::read_to_string(
                            &mut io::Read::take(
                                request.as_reader(),
                                MAX_BODY_BYTES as u64 + 1,
                            ),
                            &mut body,
                        );
                        let outcome = match read {
                            Ok(n) if n <= MAX_BODY_BYTES => {
                                handle_request(&gate, &status, &body, &client)
                            }
                            // A body over the cap or not UTF-8 is the bad-address
                            // answer: it is a malformed submission, and it is not a
                            // server fault.
                            _ => RequestOutcome::BadAddress,
                        };
                        let retry = match &outcome {
                            RequestOutcome::Unavailable { retry_after_secs, .. } => {
                                Some(*retry_after_secs)
                            }
                            RequestOutcome::QueueFull { .. } => Some(75),
                            _ => None,
                        };
                        (
                            outcome.status(),
                            Body::Html(render_index(&snapshot(&status), Some(&outcome))),
                            retry.map(|s| ("Retry-After".to_string(), s.to_string())),
                        )
                    }
                    // `/request` exists but takes only POST — 405 with `Allow`, not
                    // 404, because "this route is not for GET" and "there is no such
                    // route" are different facts and a 404 here would send an
                    // operator looking for a routing bug.
                    (tiny_http::Method::Get, "/request") => (
                        405,
                        Body::Html(page(
                            "method not allowed",
                            "<p><code>/request</code> takes <code>POST</code>. It is a POST so \
                             that the address you submit never lands in a URL, and therefore \
                             never in an access log.</p>",
                        )),
                        Some(("Allow".to_string(), "POST".to_string())),
                    ),
                    (tiny_http::Method::Get, _) => (
                        404,
                        Body::Html(page(
                            "not found",
                            "<p>This faucet serves <code>/</code>, a receipt at \
                             <code>/r/&lt;n&gt;</code>, and its two icons.</p>",
                        )),
                        None,
                    ),
                    _ => (
                        405,
                        Body::Html(page(
                            "method not allowed",
                            "<p><code>GET</code> and <code>POST</code>.</p>",
                        )),
                        None,
                    ),
                };

                // The access journal. Subnet, not client IP; no body, no ticket, and
                // no address — see the module docs.
                let line = format!(
                    "FAUCET {method} {path} {status_code} subnet={}",
                    subnet_label(&client)
                );
                // Both, and the same string: an access log an operator cannot read is
                // not an access log, and a redaction asserted against an in-memory
                // copy that differs from what stdout gets is not a redaction. The
                // test reads `journal()`; the operator reads stdout; they are one
                // `format!`.
                println!("{line}");
                if let Ok(mut j) = worker_journal.lock() {
                    j.push(line);
                }

                // The content type travels WITH the body rather than being asserted
                // once for every route: `/healthz` used to answer "ok\n" labelled
                // `text/html`, which was harmless only because nothing parsed it.
                let content_type = body.content_type();
                let mut response = tiny_http::Response::from_data(body.into_bytes())
                    .with_status_code(status_code)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            content_type.as_bytes(),
                        )
                        .expect("static content type parses"),
                    );
                if let Some((name, value)) = extra_header {
                    if let Ok(h) =
                        tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes())
                    {
                        response = response.with_header(h);
                    }
                }
                let _ = request.respond(response);
            }
        });

        Ok(FaucetServer { addr: bound, server, thread: Some(thread), served, journal })
    }

    /// The bound address (useful when the config asked for port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Requests handled since start, including 404s and 405s.
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// The access journal, as written. Exposed so the redaction claim is a **test**
    /// against the real lines rather than a promise about them.
    pub fn journal(&self) -> Vec<String> {
        self.journal.lock().map(|j| j.clone()).unwrap_or_default()
    }

    /// Stop serving and join the worker.
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Lock a mutex, ignoring poisoning — a panicking handler must not wedge the faucet.
fn lock<T>(m: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn snapshot(status: &Arc<Mutex<ServiceStatus>>) -> ServiceStatus {
    lock(status).clone()
}

/// Wall-clock milliseconds — what the abuse gate's token buckets are driven by.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Take one submitted request through the availability check and then the core's
/// gate.
///
/// The order is the load-bearing part: **availability first**. `Faucet::accept`
/// burns the single-use ticket when it admits, so consulting the gate before knowing
/// whether the faucet can serve would spend a requester's one admission on the
/// faucet's own shortage. This is the same reasoning — and the same ordering — the
/// core already uses to check queue capacity before the gate.
pub fn handle_request(
    gate: &Arc<Mutex<FaucetGate>>,
    status: &Arc<Mutex<ServiceStatus>>,
    body: &str,
    client: &str,
) -> RequestOutcome {
    let snap = snapshot(status);
    if !snap.availability.admits_requests() {
        let blocks = snap.availability.blocks_until_servable();
        return RequestOutcome::Unavailable {
            explain: snap.availability.explain(),
            // A retry hint the faucet can actually keep: the blocks it must wait,
            // at the frozen block time. With nothing pending there is no honest
            // number, so it quotes one block interval rather than inventing one.
            retry_after_secs: blocks.unwrap_or(1).saturating_mul(75),
        };
    }

    let fields = parse_form(body);
    let Some(address) = fields
        .iter()
        .find(|(k, _)| k == "address")
        .and_then(|(_, v)| Address::decode(v.trim()))
    else {
        return RequestOutcome::BadAddress;
    };
    // A ticket that does not decode is passed through as `None`, so the gate reports
    // `TicketMissing` rather than this layer inventing a second vocabulary for
    // "your ticket is no good".
    let ticket = fields
        .iter()
        .find(|(k, _)| k == "ticket")
        .and_then(|(_, v)| Ticket::decode(v.trim()));

    match lock(gate).accept(client, address, ticket, now_ms()) {
        Ok((receipt, position)) => RequestOutcome::Queued { receipt, position },
        Err(AcceptError::Refused(r)) => RequestOutcome::Refused(r),
        Err(AcceptError::Queue(qlab_faucet::QueueError::Full { depth })) => {
            RequestOutcome::QueueFull { depth }
        }
    }
}

/// `application/x-www-form-urlencoded`, decoded.
///
/// Hand-rolled because the tree has no URL-encoding dependency and this needs
/// exactly two fields. `+` is a space and `%XX` is a byte; a malformed escape is
/// left literal rather than erroring, because the only consumer is
/// `Address::decode`/`Ticket::decode`, both of which reject anything that is not the
/// exact expected shape.
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The client's subnet at the granularity the rate limiter charges — the only client
/// identity that reaches a log line here.
fn subnet_label(client: &str) -> String {
    let limits = qlab_faucet::FaucetLimits::default();
    match subnet_key(client, limits.subnet_v4_bits, limits.subnet_v6_bits) {
        SubnetKey::V4(o, bits) => format!("{}.{}.{}.{}/{bits}", o[0], o[1], o[2], o[3]),
        SubnetKey::V6(o, bits) => {
            let groups: Vec<String> = o
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            format!("{}/{bits}", groups.join(":"))
        }
        // A client the gate could not parse as an IP. Its own key is the whole
        // string, but a hostname can identify one requester as precisely as an
        // address can, so it is not written out here.
        SubnetKey::Opaque(_) => "opaque".to_string(),
    }
}

/// An address as it is allowed to appear: the first [`ADDR_SHOWN_CHARS`] characters
/// and an ellipsis, exactly `PendingRequest`'s `Debug` form.
pub fn redact_address(a: &Address) -> String {
    let s = a.encode();
    let shown: String = s.chars().take(ADDR_SHOWN_CHARS).collect();
    format!("{shown}…")
}

// ---------------------------------------------------------------------------
// Rendering — no JS, no external resources, no cookies
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Qumbra testnet faucet — {}</title>\
         <link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"/favicon-32.png\">\
         <link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"/favicon-16.png\">\
         <style>body{{font-family:system-ui,sans-serif;max-width:44rem;margin:3rem auto;\
         padding:0 1rem;line-height:1.5}}code{{word-break:break-all}}\
         .state{{padding:.75rem 1rem;border-left:4px solid #888;background:#f6f6f6}}\
         .no{{border-color:#a33}}.yes{{border-color:#3a3}}\
         textarea{{width:100%;font-family:monospace}}</style></head><body>\n\
         <h1>Qumbra testnet faucet</h1>\n{}\n</body></html>\n",
        esc(title),
        body
    )
}

/// The QMB rendering of a bessel amount (1 QMB = 10⁸ bessel, frozen §8).
fn qmb(bessel: u64) -> String {
    format!("{}.{:08}", bessel / 100_000_000, bessel % 100_000_000)
}

fn render_index(s: &ServiceStatus, outcome: Option<&RequestOutcome>) -> String {
    let mut body = String::new();

    if let Some(o) = outcome {
        let class = if matches!(o, RequestOutcome::Queued { .. }) { "yes" } else { "no" };
        body.push_str(&format!(
            "<p class=\"state {class}\"><strong>{}</strong> — {}</p>\n",
            o.status(),
            esc(&o.message())
        ));
    }

    let class = if s.availability.admits_requests() { "yes" } else { "no" };
    body.push_str(&format!(
        "<p class=\"state {class}\">{}</p>\n",
        esc(&s.availability.explain())
    ));

    body.push_str(&format!(
        "<h2>Ask for {} QMB</h2>\n\
         <form method=\"post\" action=\"/request\">\n\
         <p><label for=\"address\">Your Qumbra address</label><br>\n\
         <textarea id=\"address\" name=\"address\" rows=\"4\" required \
         placeholder=\"{}\"></textarea></p>\n\
         <p><label for=\"ticket\">Grant ticket{}</label><br>\n\
         <input id=\"ticket\" name=\"ticket\" size=\"60\" placeholder=\"qft1…\"{}></p>\n\
         <p><button type=\"submit\">Request {} QMB</button></p>\n\
         </form>\n",
        qmb(s.grant_value),
        esc(&address_placeholder()),
        if s.tickets_required { "" } else { " (not required on this faucet)" },
        if s.tickets_required { " required" } else { "" },
        qmb(s.grant_value),
    ));

    // The service's own state. Position 3, as amended by lab issue #296: **three**
    // chain integers — applied height, header tip, and the gap between them — and
    // nothing else about the chain. No per-signer committee participation, ever,
    // and no second public surface.
    //
    // The stamp this replaces said "the two chain integers, and nothing else", and
    // the third is added with its reason rather than around it. #296 measured what
    // the stamp cost: showing only the applied height under the label `chain tip`
    // put `1930` on this page while `explorer.qumbra.org` showed `4116` for the
    // same chain, and a visitor could not tell which surface was lying. The
    // stamp's *stated* rationale was per-signer participation and a second public
    // surface, and the header tip is neither — the explorer already publishes it,
    // which is exactly why the disagreement was visible in the first place. What
    // stays closed is what the sentence was written to close.
    body.push_str("<h2>This faucet right now</h2>\n<table>\n");
    let mut row = |k: &str, v: String| {
        body.push_str(&format!("<tr><td>{}</td><td><code>{}</code></td></tr>\n", esc(k), esc(&v)));
    };
    // Named for what it is. A grant proof binds to applied state, so this — not
    // the header tip — is the number that decides whether the faucet can serve;
    // #296 is explicit that showing the header tip *instead* would be worse.
    row("applied height", s.chain.state_tip.to_string());
    row("chain tip (headers)", s.chain.fork_choice_tip.to_string());
    // `StateLag::blocks()` — the tree's one definition of the gap, the same call
    // the node's duty gate and its `slag=` telemetry field make. Never a
    // subtraction written out here.
    row("behind by", format!("{} block(s)", s.chain.blocks()));
    row(
        "finalized",
        match s.finalized_height {
            Some(h) => h.to_string(),
            None => "nothing finalized yet".to_string(),
        },
    );
    row("peers", s.peers.to_string());
    row("queue", format!("{} of {}", s.queued, s.queue_capacity));
    row("estimated wait", format!("{} block(s) at the note-starved rate", s.wait_blocks));
    row("notes spendable", s.notes_held.to_string());
    row("notes maturing", s.notes_maturing.to_string());
    row("grants confirmed (this process)", s.confirmed.to_string());
    body.push_str("</table>\n");

    // Lab issue #296: the sentence a visitor comparing this page with the explorer
    // needs, in the same register as the availability banner above it ("the faucet
    // may be funded and still unable to pay"). It names the other surface by host,
    // because that is the surface the comparison is actually made against.
    body.push_str(
        "<p><strong>Why this page's height may be lower than the explorer's.</strong> \
         <code>applied height</code> is how far this faucet's own node has <em>applied</em> \
         blocks; <code>chain tip (headers)</code> is how far the chain it follows has got. \
         <code>explorer.qumbra.org</code> publishes the second. This faucet serves grants \
         from the first, because a grant proof is bound to state this node has applied — so \
         while <code>behind by</code> is not zero, the two sites will disagree, and neither \
         is wrong.</p>\n",
    );

    body.push_str(
        "<h2>Two things worth knowing</h2>\n\
         <p>A grant is a real transaction carrying a real STARK proof, so it takes a \
         couple of seconds of proving and then has to be mined. It is not instant.</p>\n\
         <p>This faucet's stock is measured in <em>notes</em>, not value. Every grant \
         costs exactly one note whatever it is worth, and the only refill is a block \
         this faucet's node wins — so a faucet showing a large balance can still be \
         out of stock, and it will say so above rather than queue a request it cannot \
         serve.</p>\n\
         <p>Testnet coins. No value, no guarantees.</p>\n",
    );
    page("request funds", &body)
}

fn render_receipt(receipt: u64, state: &RequestState) -> String {
    let body = match state {
        RequestState::Queued { position } => format!(
            "<p class=\"state\">Receipt <code>{receipt}</code> — waiting, position \
             <code>{position}</code>. Each grant ahead of you costs one note and one proof.</p>"
        ),
        RequestState::Granted { txid_hex, value_bessel, submitted_at_tip } => format!(
            "<p class=\"state yes\">Receipt <code>{receipt}</code> — <strong>granted</strong>. \
             {} QMB, transaction <code>{}</code>, submitted at chain height \
             <code>{submitted_at_tip}</code>. It is in the transaction pool and will be mined \
             into a block; scan your wallet from that height.</p>",
            qmb(*value_bessel),
            esc(txid_hex),
        ),
        RequestState::GaveUp { reason } => format!(
            "<p class=\"state no\">Receipt <code>{receipt}</code> — <strong>gave up</strong>: \
             {}. This is the faucet's failure, not yours; if you held a ticket it was spent, so \
             ask the operator.</p>",
            esc(reason)
        ),
    };
    page("receipt", &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_faucet::{Faucet, FaucetConfig, FaucetLimits, TicketPolicy, TicketSecret};
    use qlab_wallet::address::Diversifier;
    use qlab_wallet::Wallet;

    fn a_status(availability: crate::state::Availability) -> Arc<Mutex<ServiceStatus>> {
        Arc::new(Mutex::new(ServiceStatus {
            chain: qlab_node::StateLag::new(200, 200),
            finalized_height: Some(200),
            peers: 3,
            availability,
            queued: 0,
            queue_capacity: 32,
            wait_blocks: 1,
            grant_value: qlab_faucet::DEFAULT_GRANT_BESSEL,
            tickets_required: false,
            confirmed: 0,
            refused: 0,
            notes_held: 2,
            notes_maturing: 0,
        }))
    }

    fn a_gate(policy: TicketPolicy) -> Arc<Mutex<FaucetGate>> {
        Arc::new(Mutex::new(FaucetGate::new(Faucet::new(
            Wallet::from_seed_lanes([0x9999; 4]),
            Diversifier::default(),
            TicketSecret::from_bytes([5; 32]),
            FaucetConfig {
                limits: FaucetLimits { ticket_policy: policy, ..FaucetLimits::unlimited() },
                ..FaucetConfig::default()
            },
        ))))
    }

    fn an_address() -> Address {
        Wallet::from_seed_lanes([0x1357; 4]).address(Diversifier::default())
    }

    fn form(address: &str, ticket: Option<&str>) -> String {
        let mut s = format!("address={address}");
        if let Some(t) = ticket {
            s.push_str(&format!("&ticket={t}"));
        }
        s
    }

    /// Every refusal is a 4xx and none is a 5xx. A 500 would say "the faucet broke",
    /// when in fact it decided.
    #[test]
    fn no_refusal_is_ever_a_server_error() {
        for o in [
            RequestOutcome::BadAddress,
            RequestOutcome::Refused(Refusal::TicketMissing),
            RequestOutcome::Refused(Refusal::TicketInvalid),
            RequestOutcome::Refused(Refusal::TicketSpent),
            RequestOutcome::Refused(Refusal::SubnetThrottled),
            RequestOutcome::Refused(Refusal::GlobalThrottled),
            RequestOutcome::QueueFull { depth: 32 },
            RequestOutcome::Unavailable { explain: "x".into(), retry_after_secs: 75 },
        ] {
            let s = o.status();
            assert!((400..500).contains(&s) || s == 503, "{o:?} → {s}");
            assert_ne!(s, 500, "{o:?} must not be a 500");
            assert!(!o.message().is_empty(), "{o:?} must say something");
        }
        assert_eq!(RequestOutcome::Queued { receipt: 1, position: 1 }.status(), 202);
    }

    /// 🔴 The unavailable path refuses **without consulting the gate**, so the
    /// requester's single-use ticket survives the faucet's own shortage.
    #[test]
    fn an_unavailable_faucet_refuses_without_burning_a_ticket() {
        let gate = a_gate(TicketPolicy::Required);
        let status = a_status(crate::state::Availability::Empty { held: 1 });
        let ticket = lock(&gate).issue_ticket(42).encode();
        let out = handle_request(
            &gate,
            &status,
            &form(&an_address().encode(), Some(&ticket)),
            "203.0.113.5:1234",
        );
        assert!(matches!(out, RequestOutcome::Unavailable { .. }), "{out:?}");
        assert_eq!(out.status(), 503);
        let g = lock(&gate);
        assert_eq!(g.faucet().gate_stats().tickets_spent, 0, "the ticket was never presented");
        assert_eq!(g.faucet().stats().refused, 0, "and the gate recorded no refusal of its own");
        assert!(g.faucet().queue().is_empty());
        // The refusal is actionable: it names the state, not just "unavailable".
        assert!(out.message().contains("one note regardless of value"), "{}", out.message());
    }

    /// A request through the HTTP layer reaches `Faucet::accept`, and a gate refusal
    /// comes back as that refusal — by name.
    #[test]
    fn a_request_reaches_the_core_and_a_refusal_keeps_its_name() {
        let gate = a_gate(TicketPolicy::Required);
        let status = a_status(crate::state::Availability::Ready { grants: 1 });
        let addr = an_address().encode();

        // No ticket → the core's own refusal, not a locally-invented one.
        let out = handle_request(&gate, &status, &form(&addr, None), "203.0.113.5:1234");
        assert_eq!(out, RequestOutcome::Refused(Refusal::TicketMissing));
        assert_eq!(out.status(), 403);
        assert_eq!(lock(&gate).faucet().stats().refused, 1, "the core counted it");

        // A valid ticket → queued, with a receipt.
        let ticket = lock(&gate).issue_ticket(1).encode();
        let out = handle_request(&gate, &status, &form(&addr, Some(&ticket)), "203.0.113.5:1234");
        assert_eq!(out, RequestOutcome::Queued { receipt: 1, position: 1 });
        assert_eq!(lock(&gate).faucet().stats().queued, 1);

        // Replay → the core's TicketSpent, as a 409 rather than a 403: the credential
        // was real, it is the state that refuses.
        let out = handle_request(&gate, &status, &form(&addr, Some(&ticket)), "198.51.100.7:5000");
        assert_eq!(out, RequestOutcome::Refused(Refusal::TicketSpent));
        assert_eq!(out.status(), 409);
    }

    /// A malformed address is a 400 and never reaches the gate — the ticket survives
    /// a typo, which is the most common way a real user gets this wrong.
    #[test]
    fn a_bad_address_is_a_400_and_costs_nothing() {
        let gate = a_gate(TicketPolicy::Required);
        let status = a_status(crate::state::Availability::Ready { grants: 1 });
        let ticket = lock(&gate).issue_ticket(3).encode();
        for bad in ["", "qmb1nonsense", "not-an-address", "0x1234"] {
            let out = handle_request(&gate, &status, &form(bad, Some(&ticket)), "203.0.113.5:1");
            assert_eq!(out, RequestOutcome::BadAddress, "{bad:?}");
        }
        assert_eq!(lock(&gate).faucet().gate_stats().tickets_spent, 0, "a typo burns no ticket");
    }

    /// Form decoding: a browser posts the address percent-encoded and may wrap it, so
    /// the two encodings a real `<textarea>` produces must both decode.
    #[test]
    fn the_form_decoder_handles_what_a_browser_actually_sends() {
        let f = parse_form("address=abc%3Adef&ticket=qft1+2");
        assert_eq!(f[0], ("address".to_string(), "abc:def".to_string()));
        assert_eq!(f[1], ("ticket".to_string(), "qft1 2".to_string()));
        // A trailing lone '%' is left literal rather than erroring.
        assert_eq!(parse_form("address=50%")[0].1, "50%");
        assert!(parse_form("").is_empty());
    }

    /// 🔴 The redaction, at its own seam: an address is only ever shown truncated,
    /// and to the same length `PendingRequest`'s `Debug` uses.
    #[test]
    fn an_address_is_only_ever_rendered_truncated() {
        let a = an_address();
        let full = a.encode();
        let shown = redact_address(&a);
        assert_eq!(ADDR_SHOWN_CHARS, 16);
        assert_eq!(shown.chars().count(), ADDR_SHOWN_CHARS + 1, "16 chars plus the ellipsis");
        assert!(full.starts_with(shown.trim_end_matches('…')));
        assert!(!shown.contains(&full), "the full address must not survive redaction");
        // The library's own truncation of the same address, for the same 16 chars.
        assert_eq!(
            shown.trim_end_matches('…'),
            &full[..ADDR_SHOWN_CHARS],
            "the two redactions must agree"
        );
    }

    /// The log's client identity is a subnet, not an address.
    #[test]
    fn the_journal_label_is_a_subnet_not_a_client() {
        let limits = qlab_faucet::FaucetLimits::default();
        assert_eq!(limits.subnet_v4_bits, 24, "the label's mask is the gate's mask");
        assert_eq!(limits.subnet_v6_bits, 64);
        assert_eq!(subnet_label("203.0.113.77:51234"), "203.0.113.0/24");
        assert_eq!(subnet_label("203.0.113.77"), "203.0.113.0/24");
        // The host part survives, the interface identifier does not.
        let v6 = subnet_label("[2001:db8::1]:443");
        assert!(v6.ends_with("/64"), "{v6}");
        assert!(v6.starts_with("2001:db8:"), "{v6}");
        assert!(!v6.contains(":1/"), "the low 64 bits must be masked away: {v6}");
        assert_eq!(subnet_label("some-proxy-hostname"), "opaque");
    }

    /// The rendered page carries no script, no external reference, and — the point —
    /// no address.
    #[test]
    fn the_page_has_no_script_and_no_external_reference() {
        let s = lock(&a_status(crate::state::Availability::Ready { grants: 2 })).clone();
        let html = render_index(&s, Some(&RequestOutcome::Queued { receipt: 9, position: 1 }));
        for forbidden in ["<script", "http://", "https://", "//cdn", "cookie"] {
            assert!(!html.to_lowercase().contains(forbidden), "page contains {forbidden}");
        }
        // The icons are the page's only sub-resource, and they are served by this
        // process at a root-relative path. Stated as its own assertion because the
        // loop above only proves no *scheme* appears: a protocol-relative or
        // otherwise off-origin icon would slip past it, and an icon is exactly the
        // sub-resource nobody thinks of as a request. On a faucet, whoever serves it
        // learns who is asking for money.
        for icon in ["href=\"/favicon-32.png\"", "href=\"/favicon-16.png\""] {
            assert!(html.contains(icon), "the page must declare {icon}: {html}");
        }
        assert!(html.contains("form method=\"post\" action=\"/request\""));
        assert!(html.contains("10.00000000"), "the grant value is rendered in QMB: {html}");
        assert!(html.contains("Receipt") || html.contains("receipt"));
    }
}
