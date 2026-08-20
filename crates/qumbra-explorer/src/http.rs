//! The projection's listener: `GET`-only, everything not named here refused.
//!
//! ```text
//!   GET  /v1/health.json   the chain-health projection (pre-serialized, swapped by
//!                          the run loop)
//!   GET  /v1/txlist?from=&to=
//!                          the transaction-EXISTENCE list (issue #326, D1/D2/D3),
//!                          encoded per request from the run loop's snapshot
//!   GET  /v1/blocks?from=&to=
//!                          per-height block facts (lab #486 items 1+3), snapshot
//!   GET  /v1/names/events?from=&to=
//!                          the name-event feed (lab #486 item 6), snapshot
//!   GET  /v1/checkpoints   the finality ticker (lab #486 item 2, pre-serialized)
//!   GET  /v1/vitals        net vitals over time (lab #486 item 4, pre-serialized)
//!   GET  /healthz          "ok" — for a supervisor; 503 "degraded" once a
//!                          projection writer has observed a poisoned lock
//!   GET  <anything>        404 JSON, and the body says why there is no /v1/tx/…
//!   non-GET                405 with `Allow: GET`
//! ```
//!
//! Every response carries `Cache-Control: no-store` — set at the source, so the
//! property survives any proxy change (the 71-minute CDN-frozen `health.json`
//! of lab #486 stage-0 finding (a)).
//!
//! 🔴 **`/v1/txlist/<txid>` is a 404 by shape, and that is D2** — the decision
//! brief's refusal of a lookup-by-id, enforced by there being no arm that could
//! match one rather than by an arm that declines to. A `/tx/<id>` query tells this
//! server which transaction the asker cares about; the page fetches ranges and
//! matches locally ([`crate::txlist::match_txid`]). Same rule the
//! nullifier-membership query was refused under at PR #315 decision 3.
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
//! ## The journal line (OTel baton, §C.1 piece 2) — and what it still refuses
//!
//! This module used to say *"deliberately absent: an access journal"*, because
//! the only thing a per-request log could record was readership. The OTel kit
//! needs a `trace_id=` on a request log line — that is the Loki↔Tempo
//! correlation the plan pins — so a journal line now exists, and the old
//! refusal narrows to what it was actually protecting:
//!
//!   * **No client identity, ever.** Not the IP, not even the subnet the faucet
//!     journals — the faucet logs subnets because it makes rate decisions; this
//!     surface makes none, so a client field would be pure readership record.
//!   * **The matched route, never the raw path.** Stricter than the faucet,
//!     which logs the path: an unmatched probe here can carry exactly the thing
//!     D2 refuses to learn (`/v1/names/larry` is *a name somebody cares about*),
//!     so what lands in the journal is the route template — an unmatched path
//!     logs as [`UNMATCHED_ROUTE`], and no requester-chosen byte reaches the
//!     journal, a span attribute, or a metric label.
//!
//! What the line records: method, matched route, status, and `trace_id=` — the
//! same id the span exports and the histogram exemplar carries, read once.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::blocks::{self, BlocksView};
use crate::names::{self, NameEventsView};
use crate::telemetry::{current_trace_id, ExplorerMetrics, RequestLabels};
use crate::txlist::{self, TxListView};

/// The `route` label and span attribute for anything that did not match a route.
///
/// One fixed token for every miss, because the alternative — the raw path — is
/// an unbounded-cardinality label AND a record of what somebody probed for,
/// which on this surface can be a name (see the module docs' journal rules).
pub const UNMATCHED_ROUTE: &str = "{unmatched}";

/// The chain-health route. Caddy path-routes `/v1/*` here (issue #281); the prefix
/// is shared with the node's own `/v1` surfaces by convention, not by code.
pub const HEALTH_PATH: &str = "/v1/health.json";

/// The transaction-existence route (issue #326 / `t1-explorer-tx-view-decision`).
///
/// **Range-only.** There is no `/v1/txlist/<txid>` and no `?txid=` — D2 is
/// structural here, not a check.
pub const TXLIST_PATH: &str = "/v1/txlist";

/// The finality ticker route (lab #486 item 2). Parameterless — the run loop
/// pre-serializes the bounded tail exactly as it does the health document.
pub const CHECKPOINTS_PATH: &str = "/v1/checkpoints";

/// The net-vitals series (lab #486 item 4). Parameterless and bounded (24 h of
/// 60 s samples), pre-serialized by the run loop when a sample is appended.
pub const VITALS_PATH: &str = "/v1/vitals";

/// The block ticker / chart data route (lab #486 items 1 + 3). **Range-only**;
/// there is no `/v1/blocks/<height>` and no `/v1/block/<hash>` — the D2 rule
/// extends to every new route (a by-height ask is cheap to correlate too, and a
/// range costs the asker nothing).
pub const BLOCKS_PATH: &str = "/v1/blocks";

/// The name-event feed (lab #486 scope item 6). **Range-only**, like every
/// route here: no `/v1/names/<name>` arm exists, and a `name=` query parameter
/// is refused BY NAME below (the node's own `/v1/names` precedent, #381) —
/// silently serving the unfiltered range to a client that asked a filtered
/// question would be worse than either answer.
pub const NAMES_EVENTS_PATH: &str = "/v1/names/events";

/// What a 404 explains, once, in the place a probe for `/v1/tx/…` or
/// `/v1/address/…` actually lands (issue #235's exclusion, stated where it is
/// tested).
///
/// JSON, because this surface is JSON since issue #281 — and typed (`refusal`) like
/// every other refusal in the tree, so a client can branch on it while a human still
/// reads why.
///
/// 🔴 It now has to say two different "no" s, because since issue #326 a
/// transaction surface **does** exist: there is a bulk existence list, and there is
/// deliberately no way to ask this server about one transaction. A 404 that still
/// said "no transaction lookup of any kind" would be read as *"the list is not
/// built yet"*, which is the opposite of the decision.
fn not_found_body() -> String {
    format!(
        "{{\"refusal\":\"not_found\",\"detail\":\"This explorer serves {HEALTH_PATH}, \
         {TXLIST_PATH}?from=&to=, {BLOCKS_PATH}?from=&to=, {NAMES_EVENTS_PATH}?from=&to=, \
         {CHECKPOINTS_PATH}, {VITALS_PATH} and /healthz only. The lists are bulk-only and \
         matched client-side: \
         there is deliberately NO lookup by transaction id and NO lookup by name, because \
         asking this server about one thing tells it which thing you care about. There is \
         no address, balance or note lookup at all — Qumbra is a single shielded pool and \
         the chain carries none of it. The human-readable page is served separately from \
         these routes.\"}}\n"
    )
}

/// A named bad-bounds refusal for [`TXLIST_PATH`], in the same typed shape.
///
/// **Never an empty success.** An empty list is the meaningful answer *"no
/// transactions in the covered range"*, and it must not also stand in for *"your
/// request was malformed"* — the same rule `/v1/nullifiers` states for itself.
fn bad_bounds(detail: &str) -> String {
    format!("{{\"refusal\":\"bad_bounds\",\"detail\":\"{detail}\"}}\n")
}

/// Publish a pre-serialized document into its slot, **writing through a
/// poisoned lock** and reporting whether poison was observed.
///
/// This replaces the silent `if let Ok(mut p) = page.write()` swallow at the
/// run loop (stage-0 finding (a)'s hardening, promoted to stage-1 scope by the
/// stage-0 review): that shape darks a projection **forever, with no log
/// line**, the first time any writer panics while holding the lock — while
/// `/healthz` keeps answering `ok`. Writing through is safe here because the
/// payload is a whole replacement `String` — there is no torn intermediate
/// state a panic could have left that the overwrite does not erase. The
/// caller's half of the contract: on `true`, say so LOUDLY and flip the
/// [`Surfaces::degraded`] flag so `/healthz` stops attesting health it cannot
/// vouch for.
pub fn publish(slot: &RwLock<String>, body: String) -> bool {
    match slot.write() {
        Ok(mut p) => {
            *p = body;
            false
        }
        Err(poisoned) => {
            *poisoned.into_inner() = body;
            true
        }
    }
}

/// One `u64` query parameter, or `None` if it is missing or does not parse.
/// Same shape as the discovery server's `query_u64`.
fn query_u64(query: &str, key: &str) -> Option<u64> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse::<u64>().ok())
}

/// The socket-free `/v1/txlist` core: a `from`/`to` query against a projection.
///
/// Refusals are `/v1/compact`'s and `/v1/nullifiers`' verbatim, because a client
/// paging this surface is the same kind of client: a missing or unparseable bound
/// is a 400, and an inverted range is a 400. A `to` **above the tip** is not a
/// refusal — it is answered honestly, clamped, with the tip and the covered range
/// on the document (see [`txlist::TxListPage::covered_to`]).
pub fn respond_txlist(view: &TxListView, query: &str) -> Result<String, (u16, String)> {
    let from = query_u64(query, "from").ok_or((
        400,
        bad_bounds(
            "missing or unparseable 'from'. This route is bulk-only: GET \
             /v1/txlist?from=<height>&to=<height>",
        ),
    ))?;
    let to = query_u64(query, "to").ok_or((
        400,
        bad_bounds(
            "missing or unparseable 'to'. This route is bulk-only: GET \
             /v1/txlist?from=<height>&to=<height>",
        ),
    ))?;
    if to < from {
        return Err((400, bad_bounds("'to' is below 'from'")));
    }
    Ok(txlist::document(&txlist::page(view, from, to)))
}

/// The socket-free `/v1/blocks` core — the txlist refusals verbatim.
pub fn respond_blocks(view: &BlocksView, query: &str) -> Result<String, (u16, String)> {
    let usage = "missing or unparseable bound. This route is bulk-only: GET \
                 /v1/blocks?from=<height>&to=<height>";
    let from = query_u64(query, "from").ok_or((400, bad_bounds(usage)))?;
    let to = query_u64(query, "to").ok_or((400, bad_bounds(usage)))?;
    if to < from {
        return Err((400, bad_bounds("'to' is below 'from'")));
    }
    Ok(blocks::document(&blocks::page(view, from, to)))
}

/// The socket-free `/v1/names/events` core — the txlist refusals, plus the
/// resolve-by-name refusal BY NAME (D2's fifth application; the node's own
/// `/v1/names` precedent): a `name=` parameter must not be silently ignored,
/// because the unfiltered range answered to a filtered question reads as
/// "this name has no events".
pub fn respond_names(view: &NameEventsView, query: &str) -> Result<String, (u16, String)> {
    if query.split('&').any(|kv| kv.split_once('=').is_some_and(|(k, _)| k == "name")) {
        return Err((
            400,
            "{\"refusal\":\"no_resolve_by_name\",\"detail\":\"There is deliberately NO \
             lookup by name (D2): sync the range and match locally. Asking this server \
             about one name tells it which name you care about.\"}\n"
                .to_string(),
        ));
    }
    let usage = "missing or unparseable bound. This route is bulk-only: GET \
                 /v1/names/events?from=<height>&to=<height>";
    let from = query_u64(query, "from").ok_or((400, bad_bounds(usage)))?;
    let to = query_u64(query, "to").ok_or((400, bad_bounds(usage)))?;
    if to < from {
        return Err((400, bad_bounds("'to' is below 'from'")));
    }
    Ok(names::document(&names::page(view, from, to)))
}

/// Every surface this listener serves, held the way its route needs: parameterless
/// documents pre-serialized by the run loop, range routes encoded per request from
/// an `Arc` snapshot the run loop swaps (see [`ExplorerServer::start`]).
pub struct Surfaces {
    /// `/v1/health.json` — pre-serialized.
    pub health: Arc<RwLock<String>>,
    /// `/v1/txlist?from=&to=` — snapshot, encoded per request.
    pub txlist: Arc<Mutex<Arc<TxListView>>>,
    /// `/v1/checkpoints` — pre-serialized.
    pub checkpoints: Arc<RwLock<String>>,
    /// `/v1/vitals` — pre-serialized.
    pub vitals: Arc<RwLock<String>>,
    /// `/v1/blocks?from=&to=` — snapshot, encoded per request.
    pub blocks: Arc<Mutex<Arc<BlocksView>>>,
    /// `/v1/names/events?from=&to=` — snapshot, encoded per request.
    pub names: Arc<Mutex<Arc<NameEventsView>>>,
    /// Set by the run loop when [`publish`] observed a poisoned lock — a writer
    /// panicked at some point in process history. The projections keep serving
    /// (publish writes through), but `/healthz` answers **503 `degraded`**
    /// instead of `ok`: a process that has eaten a panic in its serving path
    /// must not keep attesting health it cannot vouch for (stage-0 finding
    /// (a)'s exact complaint, inverted).
    pub degraded: Arc<AtomicBool>,
}

impl Default for Surfaces {
    /// Empty-but-honest defaults for every surface — each pre-serialized slot
    /// holds its document's real empty state, never a blank string, so a test
    /// (the only caller that defaults; the binary always projects before it
    /// binds) still serves parseable documents on the routes it is not
    /// exercising.
    fn default() -> Self {
        Surfaces {
            health: Arc::new(RwLock::new("{}".to_string())),
            txlist: Arc::new(Mutex::new(Arc::new(TxListView::default()))),
            checkpoints: Arc::new(RwLock::new(crate::checkpoints::document(
                &crate::checkpoints::CheckpointsView::default(),
            ))),
            vitals: Arc::new(RwLock::new(crate::vitals::VitalsRing::new().document())),
            blocks: Arc::new(Mutex::new(Arc::new(BlocksView::default()))),
            names: Arc::new(Mutex::new(Arc::new(NameEventsView::default()))),
            degraded: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub struct ExplorerServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    served: Arc<AtomicU64>,
    journal: Arc<Mutex<Vec<String>>>,
}

impl ExplorerServer {
    /// Bind `addr` and serve `page` + `txlist` until [`Self::shutdown`]. A failure
    /// to bind is an error, never a warning — same rule and same reason as the
    /// faucet's.
    ///
    /// The two surfaces are held differently on purpose. `/v1/health.json` takes no
    /// parameters, so the run loop pre-serializes it and a request is a string
    /// clone. `/v1/txlist` takes a range, so it cannot be pre-serialized; it is
    /// encoded per request from an `Arc` snapshot the run loop swaps — the `Arc` is
    /// cloned under the lock and the encode happens with the lock released, so a
    /// slow reader can never hold the snapshot while the run loop wants to replace
    /// it. Neither path touches node state, which is the property that keeps a
    /// hostile client off the consensus loop.
    ///
    /// Hands in a private metric registry: a caller that does not serve
    /// `/metrics` still gets the same measurements taken, they simply go nowhere
    /// — which is what keeps every existing test of this surface unchanged.
    pub fn start(addr: &str, surfaces: Surfaces) -> io::Result<ExplorerServer> {
        Self::start_with_telemetry(addr, surfaces, Arc::new(ExplorerMetrics::new()))
    }

    /// [`Self::start`], with the process's shared metric registry so the served
    /// requests land in the histogram the [`crate::metrics_server`] endpoint
    /// encodes. This is the constructor `main` uses.
    pub fn start_with_telemetry(
        addr: &str,
        surfaces: Surfaces,
        metrics: Arc<ExplorerMetrics>,
    ) -> io::Result<ExplorerServer> {
        let Surfaces { health: page, txlist, checkpoints, vitals, blocks, names, degraded } =
            surfaces;
        let server = tiny_http::Server::http(addr)
            .map_err(|e| io::Error::other(format!("listen_addr {addr}: {e}")))?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("explorer listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));
        let journal = Arc::new(Mutex::new(Vec::new()));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let worker_journal = Arc::clone(&journal);
        let worker_metrics = Arc::clone(&metrics);
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                let method = request.method().clone();
                let url = request.url().to_string();
                let (raw_path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
                let path = raw_path.trim_end_matches('/');
                let path = if path.is_empty() { "/" } else { path };

                // 🔴 Piece 1 of the kit: ONE span per request, opened at the
                // accept seam and closed when the response has been handed to the
                // socket. What is on it follows the journal's own redaction rule
                // (module docs): method, MATCHED route, status — never the raw
                // URL, never anything about the client.
                let span = tracing::info_span!(
                    "explorer.request",
                    otel.kind = "server",
                    "http.request.method" = %method,
                    "http.route" = tracing::field::Empty,
                    "http.response.status_code" = tracing::field::Empty,
                );
                let _enter = span.enter();
                let started = std::time::Instant::now();

                let (route, code, body, content_type, allow) = match (&method, path) {
                    (tiny_http::Method::Get, HEALTH_PATH) => {
                        let body =
                            page.read().map(|p| p.clone()).unwrap_or_else(|e| e.into_inner().clone());
                        (HEALTH_PATH, 200, body, &b"application/json; charset=utf-8"[..], false)
                    }
                    (tiny_http::Method::Get, TXLIST_PATH) => {
                        // The per-request "page build" — the range walk over the
                        // snapshot plus the encode — as a CHILD of the request
                        // span. This is the only real per-request stage this
                        // surface has; the pre-serialized routes are one string
                        // clone and get no child.
                        let pb = tracing::info_span!("explorer.page_build", "http.route" = TXLIST_PATH);
                        let _pb = pb.enter();
                        // Clone the Arc under the lock; encode with it released.
                        let snapshot = match txlist.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        match respond_txlist(&snapshot, query) {
                            Ok(doc) => {
                                (TXLIST_PATH, 200, doc, &b"application/json; charset=utf-8"[..], false)
                            }
                            Err((code, msg)) => {
                                (TXLIST_PATH, code, msg, &b"application/json; charset=utf-8"[..], false)
                            }
                        }
                    }
                    (tiny_http::Method::Get, CHECKPOINTS_PATH) => {
                        let body = checkpoints
                            .read()
                            .map(|p| p.clone())
                            .unwrap_or_else(|e| e.into_inner().clone());
                        (CHECKPOINTS_PATH, 200, body, &b"application/json; charset=utf-8"[..], false)
                    }
                    (tiny_http::Method::Get, VITALS_PATH) => {
                        let body = vitals
                            .read()
                            .map(|p| p.clone())
                            .unwrap_or_else(|e| e.into_inner().clone());
                        (VITALS_PATH, 200, body, &b"application/json; charset=utf-8"[..], false)
                    }
                    (tiny_http::Method::Get, BLOCKS_PATH) => {
                        let pb = tracing::info_span!("explorer.page_build", "http.route" = BLOCKS_PATH);
                        let _pb = pb.enter();
                        let snapshot = match blocks.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        match respond_blocks(&snapshot, query) {
                            Ok(doc) => {
                                (BLOCKS_PATH, 200, doc, &b"application/json; charset=utf-8"[..], false)
                            }
                            Err((code, msg)) => {
                                (BLOCKS_PATH, code, msg, &b"application/json; charset=utf-8"[..], false)
                            }
                        }
                    }
                    (tiny_http::Method::Get, NAMES_EVENTS_PATH) => {
                        let pb = tracing::info_span!(
                            "explorer.page_build",
                            "http.route" = NAMES_EVENTS_PATH
                        );
                        let _pb = pb.enter();
                        let snapshot = match names.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        match respond_names(&snapshot, query) {
                            Ok(doc) => (
                                NAMES_EVENTS_PATH,
                                200,
                                doc,
                                &b"application/json; charset=utf-8"[..],
                                false,
                            ),
                            Err((code, msg)) => (
                                NAMES_EVENTS_PATH,
                                code,
                                msg,
                                &b"application/json; charset=utf-8"[..],
                                false,
                            ),
                        }
                    }
                    (tiny_http::Method::Get, "/healthz") => {
                        if degraded.load(Ordering::Relaxed) {
                            (
                                "/healthz",
                                503,
                                "degraded: a projection writer observed a poisoned lock \
                                 (a panic happened in this process); the documents still \
                                 serve — see the process log\n"
                                    .to_string(),
                                &b"text/plain; charset=utf-8"[..],
                                false,
                            )
                        } else {
                            (
                                "/healthz",
                                200,
                                "ok\n".to_string(),
                                &b"text/plain; charset=utf-8"[..],
                                false,
                            )
                        }
                    }
                    (tiny_http::Method::Get, _) => (
                        UNMATCHED_ROUTE,
                        404,
                        not_found_body(),
                        &b"application/json; charset=utf-8"[..],
                        false,
                    ),
                    _ => (
                        UNMATCHED_ROUTE,
                        405,
                        "GET only.\n".to_string(),
                        &b"text/plain; charset=utf-8"[..],
                        true,
                    ),
                };

                span.record("http.route", route);
                span.record("http.response.status_code", code);
                let elapsed = started.elapsed().as_secs_f64();
                // 🔴 Piece 2: one id, read once, used by both the journal line
                // and the exemplar — so a trace found from a log line and a trace
                // found from a slow bucket are provably the same trace.
                let trace_id = current_trace_id();
                worker_metrics.observe_request(
                    RequestLabels {
                        method: method.to_string(),
                        route: route.to_string(),
                        status: code,
                    },
                    elapsed,
                    trace_id.clone(),
                );

                // The journal line — matched route only, no client identity (the
                // module docs' rules). `trace_id=` is omitted entirely when no
                // tracer is installed (unit tests driving this surface directly):
                // `trace_id=` followed by nothing usable would not match the Loki
                // derived-field regex either, and a reader would take zeros for a
                // real trace. `main` installs a tracer before it binds, so the
                // deployed binary always has one.
                let line = match &trace_id {
                    Some(id) => format!("EXPLORER {method} {route} {code} trace_id={id}"),
                    None => format!("EXPLORER {method} {route} {code}"),
                };
                // Both, and the same string: the operator reads stdout, the test
                // reads `journal()`, and they are one `format!` — the faucet's
                // rule, kept. Stdout additionally carries the journal stamp prefix
                // (lab #512): print-site metadata, not line content.
                qlab_devnet::jprintln!("{line}");
                if let Ok(mut j) = worker_journal.lock() {
                    j.push(line);
                }

                // 🔴 `Cache-Control: no-store` on EVERY response this listener
                // emits, at the SOURCE. The live incident behind this (lab #486
                // stage-0 finding (a), root-caused by T-ops): a CDN default-cached
                // `/v1/health.json` for 71 minutes while its own body said
                // `refresh_secs: 30` — every reader saw a frozen page and the only
                // way to tell it from a wedged binary was host access. The proxy
                // layer's copy of this header is the fast half; the binary owns the
                // property so it survives any future proxy change. Uniform over
                // refusals and `/healthz` too: a cached 404 or a cached `ok` is
                // also a lie about the present.
                let mut response = tiny_http::Response::from_string(body)
                    .with_status_code(code)
                    .with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type)
                            .expect("static content type parses"),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..])
                            .expect("static cache-control parses"),
                    );
                if allow {
                    if let Ok(h) = tiny_http::Header::from_bytes(&b"Allow"[..], &b"GET"[..]) {
                        response = response.with_header(h);
                    }
                }
                let _ = request.respond(response);
            }
        });

        Ok(ExplorerServer { addr: bound, server, thread: Some(thread), served, journal })
    }

    /// The bound address (useful when the config asked for port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Requests handled since start, including 404s and 405s.
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// The journal lines emitted so far — the same strings stdout got, in order.
    /// Exists so the `trace_id=` claim is testable without capturing stdout.
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

    /// A full surface set with defaults, so a test builds only what it exercises.
    fn surfaces(page: &str) -> Surfaces {
        Surfaces { health: Arc::new(RwLock::new(page.to_string())), ..Surfaces::default() }
    }

    fn start(s: &Surfaces) -> ExplorerServer {
        ExplorerServer::start(
            "127.0.0.1:0",
            Surfaces {
                health: Arc::clone(&s.health),
                txlist: Arc::clone(&s.txlist),
                checkpoints: Arc::clone(&s.checkpoints),
                vitals: Arc::clone(&s.vitals),
                blocks: Arc::clone(&s.blocks),
                names: Arc::clone(&s.names),
                degraded: Arc::clone(&s.degraded),
            },
        )
        .expect("bind")
    }

    fn server_with(page: &str) -> (ExplorerServer, Arc<RwLock<String>>) {
        let s = surfaces(page);
        (start(&s), s.health)
    }

    fn server_with_txlist(
        page: &str,
        view: TxListView,
    ) -> (ExplorerServer, Arc<RwLock<String>>, Arc<Mutex<Arc<TxListView>>>) {
        let s = surfaces(page);
        *s.txlist.lock().unwrap() = Arc::new(view);
        (start(&s), Arc::clone(&s.health), s.txlist)
    }

    /// A view shaped like the live chain: transaction blocks at 4913 and 5398,
    /// thousands of empty heights around them.
    fn live_shaped_view() -> TxListView {
        TxListView {
            blocks: vec![
                txlist::BlockTxs {
                    height: 4913,
                    txs: vec![txlist::TxFacts {
                        txid: [0x5a; 32],
                        wire_bytes: 151_392,
                        fee: 1_000_000,
                        nullifiers: 2,
                        commitments: 2,
                    }],
                },
                txlist::BlockTxs {
                    height: 5398,
                    txs: vec![txlist::TxFacts {
                        txid: [0x77; 32],
                        wire_bytes: 151_392,
                        fee: 1_000_000,
                        nullifiers: 2,
                        commitments: 2,
                    }],
                },
            ],
            tip_height: 6000,
            tip_hash: Some([0xfe; 32]),
        }
    }

    fn body_of(resp: &str) -> &str {
        resp.split("\r\n\r\n").nth(1).expect("a response body")
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

    // ---- the loud swallow + degraded healthz (lab #486 stage-1 hardening) ------

    /// 🔴 [`publish`] writes THROUGH a poisoned lock and reports it: the old
    /// `if let Ok` swallow darked the projection forever with no log line; now
    /// the poison is survived AND surfaced. The panicking writer here is a
    /// stand-in for any writer panic in process history.
    #[test]
    fn publish_writes_through_a_poisoned_lock_and_reports_it() {
        let slot = Arc::new(RwLock::new("before".to_string()));
        assert!(!publish(&slot, "healthy".to_string()), "a healthy lock reports no poison");
        assert_eq!(*slot.read().unwrap(), "healthy");

        let poisoner = Arc::clone(&slot);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.write().unwrap();
            panic!("a writer dies while holding the lock");
        })
        .join();
        assert!(slot.write().is_err(), "the lock is genuinely poisoned");

        assert!(publish(&slot, "after".to_string()), "poison is REPORTED, not swallowed");
        let served = slot.read().map(|p| p.clone()).unwrap_or_else(|e| e.into_inner().clone());
        assert_eq!(served, "after", "…and the projection is NOT dark: readers see the new body");
    }

    /// Once the degraded flag is set, `/healthz` stops attesting health: 503
    /// with a body that names the condition — never `ok` from a process that
    /// has eaten a panic in its serving path. The JSON routes keep serving.
    #[test]
    fn healthz_reports_degraded_after_a_poison_observation() {
        let s = surfaces("{\"v\":1}");
        let server = start(&s);
        assert!(get(server.addr(), "/healthz").starts_with("HTTP/1.1 200"));

        s.degraded.store(true, Ordering::Relaxed);
        let resp = get(server.addr(), "/healthz");
        assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
        assert!(resp.contains("degraded"), "{resp}");
        assert!(resp.contains("poisoned lock"), "the body names the condition: {resp}");
        let health = get(server.addr(), HEALTH_PATH);
        assert!(health.starts_with("HTTP/1.1 200"), "the documents still serve: {health}");
        server.shutdown();
    }

    /// 🔴 Every response this listener emits carries `Cache-Control: no-store`
    /// — the JSON documents, the refusals, `/healthz`, all of it. The lab #486
    /// stage-0 live finding: a CDN default-cached `health.json` for 71 minutes
    /// because nothing at the source said not to.
    #[test]
    fn every_response_carries_cache_control_no_store() {
        let s = surfaces("{\"v\":1}");
        let server = start(&s);
        let addr = server.addr();
        for probe in [
            HEALTH_PATH,
            "/v1/txlist?from=0&to=10",
            "/v1/txlist",             // 400
            CHECKPOINTS_PATH,
            VITALS_PATH,
            "/v1/blocks?from=0&to=10",
            "/v1/names/events?from=0&to=10",
            "/healthz",
            "/v1/tx/abc",             // 404
        ] {
            let resp = get(addr, probe);
            assert!(resp.contains("Cache-Control: no-store"), "{probe}: {resp}");
        }
        let post = exchange(
            addr,
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        assert!(post.contains("Cache-Control: no-store"), "the 405 too: {post}");
        server.shutdown();
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

    // ---- the transaction-existence route (issue #326) ------------------------

    #[test]
    fn the_txlist_route_serves_the_document_over_a_real_socket() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let addr = server.addr();

        let resp = get(addr, "/v1/txlist?from=4900&to=5400");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("application/json"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON off the wire");
        assert_eq!(v["v"], txlist::TXLIST_VERSION);
        assert_eq!(v["tip_height"], 6000);
        assert_eq!(v["range"]["covered_to"], 5400);
        let heights: Vec<u64> = v["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["height"].as_u64().unwrap())
            .collect();
        assert_eq!(heights, vec![4913, 5398]);
        assert_eq!(
            v["boundary"], txlist::BOUNDARY_SENTENCE,
            "D3 reaches the reader with the data, not beside it"
        );
        server.shutdown();
    }

    /// The run loop's swap reaches readers here too — the same property the
    /// pre-serialized projection has, over a snapshot that is encoded per request.
    #[test]
    fn a_snapshot_swap_reaches_txlist_readers() {
        let (server, _page, list) = server_with_txlist("{}", TxListView::default());
        let addr = server.addr();
        let before: serde_json::Value =
            serde_json::from_str(body_of(&get(addr, "/v1/txlist?from=0&to=10"))).unwrap();
        assert_eq!(before["blocks"].as_array().unwrap().len(), 0);

        *list.lock().unwrap() = Arc::new(live_shaped_view());
        let after: serde_json::Value =
            serde_json::from_str(body_of(&get(addr, "/v1/txlist?from=4900&to=5400"))).unwrap();
        assert_eq!(after["blocks"].as_array().unwrap().len(), 2);
        server.shutdown();
    }

    /// 🔴 D2, test-locked as a **shape**: every by-id form of this route is a 404,
    /// and the body says why rather than reading as an unbuilt feature.
    #[test]
    fn every_by_id_form_of_the_txlist_route_is_a_404_and_the_body_states_d2() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let addr = server.addr();
        let txid = "5a".repeat(32);
        for probe in [
            format!("/v1/txlist/{txid}"),
            format!("/v1/tx/{txid}"),
            format!("/v1/txlist/tx/{txid}"),
            format!("/v1/txlist/by-id/{txid}"),
            format!("/tx/{txid}"),
        ] {
            let resp = get(addr, &probe);
            assert!(resp.starts_with("HTTP/1.1 404"), "{probe}: {resp}");
            let v: serde_json::Value =
                serde_json::from_str(body_of(&resp)).expect("the 404 body is JSON");
            assert_eq!(v["refusal"], "not_found", "{probe}");
            let detail = v["detail"].as_str().expect("detail");
            assert!(
                detail.contains("bulk-only") && detail.contains("deliberately NO lookup"),
                "{probe}: the 404 must say the list exists AND that by-id does not: {detail}"
            );
        }

        // A txid smuggled in as a query parameter is not a route either: the
        // handler reads `from`/`to` and nothing else, so this is a bad-bounds 400
        // and never a filtered answer.
        let resp = get(addr, &format!("/v1/txlist?txid={txid}"));
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(!resp.contains(&txid[..8]), "the id is not echoed back: {resp}");
        server.shutdown();
    }

    /// Bad bounds are a named 400 and **never an empty success** — an empty list
    /// is the meaningful answer "no transactions in the covered range".
    #[test]
    fn bad_bounds_are_a_named_refusal_and_never_an_empty_list() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let addr = server.addr();
        for probe in [
            "/v1/txlist",
            "/v1/txlist?from=0",
            "/v1/txlist?to=10",
            "/v1/txlist?from=abc&to=10",
            "/v1/txlist?from=0&to=-1",
            "/v1/txlist?from=10&to=9",
        ] {
            let resp = get(addr, probe);
            assert!(resp.starts_with("HTTP/1.1 400"), "{probe}: {resp}");
            let v: serde_json::Value =
                serde_json::from_str(body_of(&resp)).expect("the 400 body is JSON");
            assert_eq!(v["refusal"], "bad_bounds", "{probe}");
            assert!(v.get("blocks").is_none(), "{probe} answers no list at all");
        }
        server.shutdown();
    }

    /// A `to` above the tip is **not** a refusal: it is answered, clamped, with the
    /// tip and the covered range stated. A client asking "everything up to now"
    /// should not have to know "now" first.
    #[test]
    fn a_to_above_the_tip_is_answered_and_clamped_rather_than_refused() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let resp = get(server.addr(), "/v1/txlist?from=0&to=99999999");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).unwrap();
        assert_eq!(v["tip_height"], 6000);
        assert_eq!(
            v["range"]["covered_to"],
            txlist::MAX_TXLIST_HEIGHTS - 1,
            "the scan bound binds first, and the page says how far it looked"
        );
        server.shutdown();
    }

    /// The trailing-slash form is the same route, not a by-id probe.
    #[test]
    fn the_trailing_slash_form_is_the_same_route() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let resp = get(server.addr(), "/v1/txlist/?from=0&to=10");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        server.shutdown();
    }

    #[test]
    fn the_txlist_route_is_read_only_like_every_other() {
        let (server, _page, _list) = server_with_txlist("{}", live_shaped_view());
        let resp = exchange(
            server.addr(),
            "POST /v1/txlist HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
        assert!(resp.contains("Allow: GET"), "{resp}");
        server.shutdown();
    }

    // ---- the blocks route (lab #486 items 1 + 3) --------------------------------

    #[test]
    fn the_blocks_route_serves_the_document_over_a_real_socket() {
        let s = surfaces("{}");
        *s.blocks.lock().unwrap() = Arc::new(crate::blocks::BlocksView {
            blocks: vec![crate::blocks::BlockFacts {
                height: 42,
                block_hash: [0xe0; 32],
                timestamp: 1_787_039_600,
                difficulty: 2_837,
                body_commitment: [0xab; 32],
                txs: 0,
                coinbase: 4_979_012_345,
            }],
            tip_height: 42,
            tip_hash: Some([0xfe; 32]),
        });
        let server = start(&s);
        let resp = get(server.addr(), "/v1/blocks?from=42&to=42");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON off the wire");
        assert_eq!(v["v"], crate::blocks::BLOCKS_VERSION);
        assert_eq!(v["blocks"][0]["difficulty"], 2_837);
        assert_eq!(v["range"]["covered_to"], 42);
        server.shutdown();
    }

    /// D2 extends to this route: no by-height path, no by-hash path, and bad
    /// bounds are the named refusal.
    #[test]
    fn the_blocks_route_has_no_by_height_form_and_names_its_refusals() {
        let s = surfaces("{}");
        let server = start(&s);
        for probe in ["/v1/blocks/42", "/v1/block/42", "/v1/blocks/by-hash/aabb"] {
            let resp = get(server.addr(), probe);
            assert!(resp.starts_with("HTTP/1.1 404"), "{probe}: {resp}");
        }
        for probe in ["/v1/blocks", "/v1/blocks?from=9&to=3"] {
            let resp = get(server.addr(), probe);
            assert!(resp.starts_with("HTTP/1.1 400"), "{probe}: {resp}");
            let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON");
            assert_eq!(v["refusal"], "bad_bounds", "{probe}");
        }
        server.shutdown();
    }

    // ---- the name-event feed route (lab #486 scope item 6) --------------------

    fn feed_view() -> crate::names::NameEventsView {
        crate::names::NameEventsView {
            events: vec![crate::names::NameEvent {
                height: 19_012,
                kind: crate::names::EventKind::Commit { commit: [0x9a; 32] },
            }],
            tip_height: 19_100,
            tip_hash: Some([0xfe; 32]),
            name_boundary: qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT,
        }
    }

    #[test]
    fn the_names_events_route_serves_the_document_over_a_real_socket() {
        let s = surfaces("{}");
        *s.names.lock().unwrap() = Arc::new(feed_view());
        let server = start(&s);
        let resp = get(server.addr(), "/v1/names/events?from=19000&to=19100");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON off the wire");
        assert_eq!(v["v"], crate::names::NAMES_VERSION);
        assert_eq!(v["events"][0]["kind"], "commit");
        assert!(v.get("boundary_height").is_some(), "the dark-ship field rides every page");
        server.shutdown();
    }

    /// 🔴 Resolve-by-name is refused BY NAME (D2, the node's `/v1/names`
    /// precedent) — never a silently unfiltered answer, and never an echo of the
    /// asked-about name.
    #[test]
    fn a_name_query_parameter_is_refused_by_name_and_not_echoed() {
        let s = surfaces("{}");
        *s.names.lock().unwrap() = Arc::new(feed_view());
        let server = start(&s);
        for probe in [
            "/v1/names/events?name=larry",
            "/v1/names/events?from=0&to=10&name=larry",
        ] {
            let resp = get(server.addr(), probe);
            assert!(resp.starts_with("HTTP/1.1 400"), "{probe}: {resp}");
            let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON");
            assert_eq!(v["refusal"], "no_resolve_by_name", "{probe}");
            assert!(!resp.contains("larry"), "the name is not echoed back: {resp}");
        }
        // And no by-name PATH exists either — 404 by shape, like every by-id form.
        let resp = get(server.addr(), "/v1/names/larry");
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        server.shutdown();
    }

    // ---- the finality ticker route (lab #486 scope item 2) ---------------------

    /// The checkpoints route serves the pre-serialized document, the default is
    /// the honest empty state (parseable, versioned, empty list — never a blank),
    /// and the run loop's swap reaches readers — the health.json seam, verbatim.
    #[test]
    fn the_checkpoints_route_serves_and_a_swap_is_visible() {
        let s = surfaces("{}");
        let server = start(&s);
        let resp = get(server.addr(), CHECKPOINTS_PATH);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("application/json"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON off the wire");
        assert_eq!(v["v"], crate::checkpoints::CHECKPOINTS_VERSION);
        assert!(v["history_from_height"].is_null(), "fresh: no history, and it says so");
        assert_eq!(v["checkpoints"].as_array().unwrap().len(), 0);

        *s.checkpoints.write().unwrap() = crate::checkpoints::document(
            &crate::checkpoints::view_of_tail(Some(16), None, &[]),
        );
        let after: serde_json::Value =
            serde_json::from_str(body_of(&get(server.addr(), CHECKPOINTS_PATH))).unwrap();
        assert_eq!(after["history_from_height"], 16, "the run loop's swap reaches readers");
        server.shutdown();
    }

    /// Parameterless means parameterless: a query string is ignored (the document
    /// has no range to bind), and no by-height or by-fid form exists — D2's shape
    /// rule, same as every other route here.
    #[test]
    fn the_checkpoints_route_has_no_by_id_form() {
        let s = surfaces("{}");
        let server = start(&s);
        for probe in ["/v1/checkpoints/15320", "/v1/checkpoint/15320", "/v1/checkpoints/by-fid/ab"]
        {
            let resp = get(server.addr(), probe);
            assert!(resp.starts_with("HTTP/1.1 404"), "{probe}: {resp}");
        }
        server.shutdown();
    }

    // ---- the vitals route (lab #486 scope item 4) ------------------------------

    /// The vitals route serves the pre-serialized ring document, the default is
    /// the honest empty state, and the run loop's swap reaches readers.
    #[test]
    fn the_vitals_route_serves_and_a_swap_is_visible() {
        let s = surfaces("{}");
        let server = start(&s);
        let resp = get(server.addr(), VITALS_PATH);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("application/json"), "{resp}");
        let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON off the wire");
        assert_eq!(v["v"], crate::vitals::VITALS_VERSION);
        assert!(v["since"].is_null(), "fresh: nothing sampled, and it says so");
        assert_eq!(v["samples"].as_array().unwrap().len(), 0);

        let mut ring = crate::vitals::VitalsRing::new();
        assert!(ring.maybe_push(crate::vitals::Sample {
            t: 1_787_000_000,
            peers: 5,
            mempool: 0,
            tip_height: 15_761,
            stall_depth: 0,
        }));
        *s.vitals.write().unwrap() = ring.document();
        let after: serde_json::Value =
            serde_json::from_str(body_of(&get(server.addr(), VITALS_PATH))).unwrap();
        assert_eq!(after["since"], 1_787_000_000u64, "the run loop's swap reaches readers");
        assert_eq!(after["samples"][0]["peers"], 5);
        server.shutdown();
    }

    #[test]
    fn names_events_bad_bounds_are_a_named_refusal() {
        let s = surfaces("{}");
        let server = start(&s);
        for probe in ["/v1/names/events", "/v1/names/events?from=5", "/v1/names/events?from=9&to=3"] {
            let resp = get(server.addr(), probe);
            assert!(resp.starts_with("HTTP/1.1 400"), "{probe}: {resp}");
            let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("JSON");
            assert_eq!(v["refusal"], "bad_bounds", "{probe}");
        }
        server.shutdown();
    }
}
