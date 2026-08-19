//! `qumbra-explorer` — the public chain-health page (issue #235).
//!
//! ```text
//! qumbra-explorer check --config FILE   validate the whole deployment, bind nothing
//! qumbra-explorer run   --config FILE   keyless observer node + the JSON projection
//! ```
//!
//! Since issue #281 this binary serves **no page**: `GET /v1/health.json` and
//! `/healthz`, nothing else. The page is `qumbra-explorer-web`, static files served
//! by svc0's Caddy from a file root beside these two routes.
//!
//! CLI glue only; the testable logic is in the library, the same posture as
//! `qumbra-node`'s and `qumbra-faucet`'s `main.rs`.

use std::error::Error;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use qlab_devnet::pow::RandomXPow;
use qlab_node::round::ObsClock;
use qlab_p2p::adapter::MiningClock;

use qumbra_explorer::blocks::{self, BlocksView};
use qumbra_explorer::checkpoints;
use qumbra_explorer::config::ExplorerConfig;
use qumbra_explorer::http::{self, ExplorerServer, Surfaces};
use qumbra_explorer::json;
use qumbra_explorer::metrics_server::MetricsServer;
use qumbra_explorer::names::{self, NameEventsView};
use qumbra_explorer::telemetry::Telemetry;
use qumbra_explorer::txlist::{self, TxListView};
use qumbra_explorer::vitals;
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::select_verifier;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // 🔴 Telemetry is initialised for EVERY subcommand, not just `run` — the
    // faucet's rule, for the faucet's reason: "no OTEL_EXPORTER_OTLP_ENDPOINT ⇒
    // no exporter, no noise" is only checkable from outside if a cheap
    // invocation exercises the same initialisation path `run` does.
    // `tests/otel_disabled.rs` drives the no-args usage path for exactly that.
    // The cost when export is off is one tracer provider with no span processor.
    let telemetry = Telemetry::init();
    let code = match dispatch(&args, &telemetry) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-explorer error: {e}");
            ExitCode::FAILURE
        }
    };
    // Flush before exit: a batch exporter dropped without a shutdown loses what
    // it was holding, and the spans most worth having are from the run that just
    // ended.
    telemetry.shutdown();
    code
}

fn dispatch(args: &[String], telemetry: &Telemetry) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("run") => run(&args[1..], telemetry),
        Some("-h") | Some("--help") | None => {
            usage();
            Ok(())
        }
        Some(other) => {
            usage();
            Err(format!("unknown command `{other}`").into())
        }
    }
}

fn usage() {
    eprintln!(
        "qumbra-explorer — the public chain-health page (issue #235)\n\n\
         USAGE:\n  \
         qumbra-explorer check --config FILE   validate the deployment; bind nothing\n  \
         qumbra-explorer run   --config FILE   run the keyless observer node + the page\n"
    );
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Load both configs with every refusal applied in the same order for `check`
/// and `run` — the faucet's `load` discipline.
fn load(cfg_path: &str) -> Result<(ExplorerConfig, NodeConfig, GenesisFile), Box<dyn Error>> {
    let cfg = ExplorerConfig::load(cfg_path)?;
    let node = NodeConfig::load(&cfg.node_config)?;
    cfg.check_observer(&node)?;
    let genesis = GenesisFile::load(&node.genesis_file)?;
    Ok((cfg, node, genesis))
}

fn check(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("check requires --config FILE")?;
    let (cfg, node, genesis) = load(cfg_path)?;
    println!("qumbra-explorer check: OK");
    println!("  api listen:     {}", cfg.listen_addr);
    println!("  node listen:    {}", node.listen_addr);
    println!("  dial peers:     {}", node.dial_peers.len());
    println!("  genesis file hash: {}", genesis.hash_hex());
    println!("  network:        {} (banner label source — served, never hardcoded)", genesis.network);
    println!("  committee keys: 0 (keyless — enforced)");
    println!("  mining:         false (enforced)");
    println!(
        "  extra listeners: telemetry_addr refused outright; metrics loopback-only \
         (§6.2, OTel-baton ruling)"
    );
    println!(
        "  metrics:        {}",
        cfg.metrics_addr
            .as_deref()
            .unwrap_or("not served (set metrics_addr — loopback only)")
    );
    println!(
        "  routes:         {} + {}?from=&to= + {}?from=&to= + {}?from=&to= + {} + {} \
         + /healthz (no page, no write path)",
        http::HEALTH_PATH,
        http::TXLIST_PATH,
        http::BLOCKS_PATH,
        http::NAMES_EVENTS_PATH,
        http::CHECKPOINTS_PATH,
        http::VITALS_PATH
    );
    println!("  tx lookup:      none — bulk list only, matched client-side (D2)");
    println!("  name lookup:    none — event feed is range-only, resolve refused by name (D2)");
    Ok(())
}

/// The loud half of the poisoned-lock contract (`http::publish` docs): log the
/// observation ONCE — the flag latches, so a poisoned lock republished every
/// tick does not flood the log — and leave /healthz answering `degraded` for
/// the rest of the process's life. The lock is written through, so the route
/// keeps serving fresh documents; what is lost is this process's claim to
/// unqualified health, because some writer panicked to get here.
fn note_poisoned(route: &str, degraded: &AtomicBool) {
    if !degraded.swap(true, Ordering::Relaxed) {
        eprintln!(
            "🔴 {route}: a poisoned page lock was observed and written through — a writer \
             panicked at some point in this process's history. The document keeps serving; \
             /healthz now reports 503 degraded. (This line prints once.)"
        );
    }
}

fn run(args: &[String], telemetry: &Telemetry) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("run requires --config FILE")?;
    let (cfg, node_cfg, genesis) = load(cfg_path)?;

    let (verifier, verifier_log) = select_verifier(has_flag(args, "--rehearsal-verifier"));
    let mut node = RunningNode::start(&node_cfg, &genesis, RandomXPow::new(), verifier)?;
    // The same two clock opt-ins every binary takes: real wall-clock header
    // timestamps for LWMA, and a wall-clock observation clock for diagnostics.
    node.set_mining_clock(MiningClock::WallClock);
    node.set_obs_clock(ObsClock::WallClock);

    // Serialize once before binding, so the first request served is never blank —
    // the faucet's rule, kept across the split.
    let genesis_hash = genesis.hash_hex();
    let page = Arc::new(RwLock::new(json::health(
        &node.telemetry(),
        &genesis_hash,
        cfg.refresh_secs,
        &genesis.network,
    )));

    // And project the transaction-existence view once for the same reason: the
    // first `/v1/txlist` read must be answered from the chain this process
    // actually opened, not from an empty view that would read as "no transactions"
    // (the same rule `start_discovery_endpoint` states for `/v1/compact`).
    let txlist_view = Arc::new(Mutex::new(Arc::new(TxListView::default())));
    txlist::refresh_shared(&txlist_view, node.state().chain());

    // The per-height block facts (ticker + charts), projected once pre-bind for
    // the same first-read rule.
    let blocks_view = Arc::new(Mutex::new(Arc::new(BlocksView::default())));
    blocks::refresh_shared(&blocks_view, node.state().chain());

    // The name-event feed, projected once pre-bind for the same first-read rule.
    // Chain-derived from the persisted riders, so it BACKFILLS: an explorer
    // rolled after the 19,008 boundary still serves every event from the
    // boundary's first block (lab #486 stage-0 §4).
    let names_view = Arc::new(Mutex::new(Arc::new(NameEventsView::default())));
    names::refresh_shared(&names_view, node.state().chain());

    // The finality ticker, pre-serialized once pre-bind for the same first-read
    // rule — a fresh or just-restored tracker serves its honest (possibly empty)
    // history rather than a blank (lab #486 item 2).
    let mut cp_last: Option<checkpoints::Fingerprint> = None;
    let cp_first = checkpoints::refreshed_document(&mut cp_last, node.p2p().node().finality())
        .expect("first render: no fingerprint seen yet");
    let checkpoints_page = Arc::new(RwLock::new(cp_first));

    // The vitals ring (lab #486 item 4) — the run loop is its only writer, so
    // the ring itself is unshared; readers see the pre-serialized document. It
    // starts honestly empty (`since: null`) and fills at the sampling cadence.
    let mut vitals_ring = vitals::VitalsRing::new();
    let vitals_page = Arc::new(RwLock::new(vitals_ring.document()));

    // Latched by the loud-publish path below; served by /healthz as a 503.
    let degraded = Arc::new(AtomicBool::new(false));

    // A failure to bind is FATAL, same rule as the faucet's listener.
    let metrics = telemetry.metrics();
    let server = ExplorerServer::start_with_telemetry(
        &cfg.listen_addr,
        Surfaces {
            health: Arc::clone(&page),
            txlist: Arc::clone(&txlist_view),
            checkpoints: Arc::clone(&checkpoints_page),
            vitals: Arc::clone(&vitals_page),
            blocks: Arc::clone(&blocks_view),
            names: Arc::clone(&names_view),
            degraded: Arc::clone(&degraded),
        },
        Arc::clone(&metrics),
    )?;

    // The scrape endpoint (§C.1 piece 3), off unless `metrics_addr` is set. A
    // non-loopback value was already refused at load, so this bind cannot be
    // the first place an operator hears about it; a bind failure is fatal, same
    // rule as the listener above.
    let metrics_server = match cfg.metrics_addr.as_deref() {
        Some(addr) => Some(MetricsServer::start(addr, Arc::clone(&metrics))?),
        None => None,
    };

    println!("qumbra-explorer running");
    println!("  projection:     http://{}{}", server.addr(), http::HEALTH_PATH);
    println!(
        "  tx existence:   http://{}{}?from=&to=  (bulk only — no lookup by txid, by design)",
        server.addr(),
        http::TXLIST_PATH
    );
    println!(
        "  blocks:         http://{}{}?from=&to=  (ticker + charts; range-only)",
        server.addr(),
        http::BLOCKS_PATH
    );
    println!(
        "  name events:    http://{}{}?from=&to=  (range-only — no resolve-by-name, by design)",
        server.addr(),
        http::NAMES_EVENTS_PATH
    );
    println!(
        "  checkpoints:    http://{}{}  (finality ticker; history is process-lifetime \
         and the document says where it begins)",
        server.addr(),
        http::CHECKPOINTS_PATH
    );
    println!(
        "  vitals:         http://{}{}  (peers/mempool over 24 h, sampled every {} s)",
        server.addr(),
        http::VITALS_PATH,
        vitals::SAMPLE_SECS
    );
    println!("  page:           served separately (qumbra-explorer-web) — no / here");
    match &metrics_server {
        Some(m) => println!("  metrics:        http://{}/metrics (loopback only)", m.addr()),
        None => println!("  metrics:        not served (set metrics_addr in the config to enable)"),
    }
    println!("  {}", telemetry.posture_line());
    println!("  node listen:    {}", node.listen_addr());
    println!("  node data dir:  {}", node_cfg.data_dir.display());
    println!("  genesis file hash: {genesis_hash}");
    println!("  committee keys: 0 (keyless — §6.2 decision 1)");
    println!("  mining:         false (observer)");
    println!("  {verifier_log}");
    if !server.addr().ip().is_loopback() {
        println!(
            "  ⚠️  the page is bound off-loopback. It holds no key and takes no input, \
             but put TLS and rate limiting in front before announcing the URL."
        );
    }
    println!("(Ctrl-C / SIGTERM to shut down — the node's snapshot is flushed on exit)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&shutdown);
    // ctrlc with the `termination` feature: SIGINT + SIGTERM + SIGHUP (issue #145).
    ctrlc::set_handler(move || sig.store(true, Ordering::SeqCst))?;

    // Re-serialize when the snapshot's cheap fingerprint moves, and at least once per
    // refresh interval so age/regime keep pace with chain time even on a quiet net.
    // The fingerprint rule lives in the library (`json::fingerprint`) because it IS a
    // rule — this file is CLI glue, and a rule kept here could not be tested. It now
    // includes head #3, which the pre-#281 tuple omitted.
    let refresh = Duration::from_secs(cfg.refresh_secs.max(1));
    let mut last_render = Instant::now();
    let mut last_seen: Option<json::Fingerprint> = None;
    node.run_until_with(&shutdown, |n| {
        let t = n.telemetry();
        let seen = json::fingerprint(&t);
        if last_seen != Some(seen) || last_render.elapsed() >= refresh {
            let body = json::health(&t, &genesis_hash, cfg.refresh_secs, &genesis.network);
            // 🔴 The loud swallow (lab #486 stage-1 scope): `publish` writes
            // THROUGH a poisoned lock — the projection never darks — and a
            // poison observation is logged once and latched into /healthz's
            // degraded answer. The `if let Ok` this replaces could dark the
            // page forever with no log line while /healthz kept saying ok.
            if http::publish(&page, body) {
                note_poisoned(http::HEALTH_PATH, &degraded);
            }
            last_seen = Some(seen);
            last_render = Instant::now();
        }
        // Keyed on the chain's own tip hash inside `refresh_shared`, so an
        // unchanged chain costs one comparison and no copy. Deliberately NOT on
        // `refresh_secs`: that knob is the reader's poll cadence, and holding a
        // known-stale transaction list back for it would be a second staleness
        // rule nobody asked for.
        txlist::refresh_shared(&txlist_view, n.state().chain());
        blocks::refresh_shared(&blocks_view, n.state().chain());
        names::refresh_shared(&names_view, n.state().chain());
        // The finality ticker re-serializes only when the record moved — the
        // decision rule lives in the library (`checkpoints::refreshed_document`)
        // for the same testability reason as `json::fingerprint`.
        if let Some(doc) = checkpoints::refreshed_document(&mut cp_last, n.p2p().node().finality())
        {
            if http::publish(&checkpoints_page, doc) {
                note_poisoned(http::CHECKPOINTS_PATH, &degraded);
            }
        }
        // One vitals sample per cadence interval (the rule lives in the
        // library; this is the one place the wall clock is read — a clock the
        // OS cannot answer samples nothing rather than fabricating a t).
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            if vitals_ring.maybe_push(vitals::sample_of(now.as_secs(), &t))
                && http::publish(&vitals_page, vitals_ring.document())
            {
                note_poisoned(http::VITALS_PATH, &degraded);
            }
        }
    });

    server.shutdown();
    if let Some(m) = metrics_server {
        m.shutdown();
    }
    println!("shutdown complete");
    Ok(())
}
