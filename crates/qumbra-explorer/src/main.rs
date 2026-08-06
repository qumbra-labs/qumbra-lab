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
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use qlab_devnet::pow::RandomXPow;
use qlab_node::round::ObsClock;
use qlab_p2p::adapter::MiningClock;

use qumbra_explorer::config::ExplorerConfig;
use qumbra_explorer::http::{self, ExplorerServer};
use qumbra_explorer::json;
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::select_verifier;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-explorer error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("run") => run(&args[1..]),
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
    println!("  committee keys: 0 (keyless — enforced)");
    println!("  mining:         false (enforced)");
    println!("  extra listeners: none (telemetry_addr/metrics_addr refused — §6.2)");
    println!("  routes:         {} + /healthz (no page, no write path)", http::HEALTH_PATH);
    Ok(())
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
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
    )));

    // A failure to bind is FATAL, same rule as the faucet's listener.
    let server = ExplorerServer::start(&cfg.listen_addr, Arc::clone(&page))?;

    println!("qumbra-explorer running");
    println!("  projection:     http://{}{}", server.addr(), http::HEALTH_PATH);
    println!("  page:           served separately (qumbra-explorer-web) — no / here");
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
            let body = json::health(&t, &genesis_hash, cfg.refresh_secs);
            if let Ok(mut p) = page.write() {
                *p = body;
            }
            last_seen = Some(seen);
            last_render = Instant::now();
        }
    });

    server.shutdown();
    println!("shutdown complete");
    Ok(())
}
