//! `qumbra-node` — the deployable full-node binary + genesis tooling (M10-T0-1).
//!
//! ```text
//!   qumbra-node genesis init [--out DIR]   build the T0 genesis file + committee
//!                                          key files; print the genesis hash
//!   qumbra-node run --config FILE          run a full node (TCP + RandomX + disk)
//!   qumbra-node audit [--out FILE]         emit the params_devnet convergence audit
//! ```
//!
//! All the testable logic lives in the library ([`qumbra_node`]); this is thin
//! CLI glue. Graceful shutdown (Ctrl-C) flushes an atomic snapshot.

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use qlab_devnet::pow::RandomXPow;
use qlab_p2p::adapter::MiningClock;

use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::params_audit;
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-node error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("genesis") => match args.get(1).map(String::as_str) {
            Some("init") => genesis_init(&args[2..]),
            _ => {
                usage();
                Err("expected `genesis init`".into())
            }
        },
        Some("run") => run_node(&args[1..]),
        Some("audit") => audit(&args[1..]),
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
        "qumbra-node — Qumbra full node (M10-T0-1)\n\n\
         USAGE:\n  \
         qumbra-node genesis init [--out DIR]   build the T0 genesis file + 21 committee key files\n  \
         qumbra-node run --config FILE          run a full node (TCP + RandomX + disk persistence)\n  \
         qumbra-node audit [--out FILE]         emit the params_devnet ⟷ FROZEN v1.0 convergence audit"
    );
}

/// `--name VALUE` flag lookup.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn genesis_init(args: &[String]) -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(flag(args, "--out").unwrap_or("."));
    std::fs::create_dir_all(&out)?;

    let gf = GenesisFile::new_devnet_t0();
    let gpath = out.join("genesis.qmb");
    gf.write(&gpath)?;
    let key_dir = out.join("keys");
    let keys = gf.write_committee_key_files(&key_dir)?;

    // Self-verify: the file we just wrote must load, byte-verify, and re-hash to
    // the printed value (item 2 — genesis hash printed + asserted).
    let loaded = GenesisFile::load(&gpath)?;
    let hash = loaded.hash_hex();
    loaded.verify_startup(Some(&hash))?;

    println!("qumbra-node genesis init");
    println!("  network:        {}", gf.network);
    println!("  format version: {} (NOT frozen — [devnet-placeholder] shape)", gf.format_version);
    println!("  committee:      N={} quorum={}", gf.frozen.committee_size, gf.frozen.quorum);
    println!("  block time:     {} s (FROZEN)", gf.frozen.block_time_secs);
    println!("  consensus FRI:  {}", gf.frozen.consensus_fri);
    println!("  genesis file:   {}", gpath.display());
    println!("  key files:      {} in {}", keys.len(), key_dir.display());
    println!("  GENESIS HASH:   {hash}");
    println!("  self-verify:    OK");
    Ok(())
}

fn run_node(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("run requires --config FILE")?;
    let config = NodeConfig::load(cfg_path)?;
    let genesis = GenesisFile::load(&config.genesis_file)?;

    // Real RandomX (N3) is the default engine; the injected verifier is the
    // labelled rehearsal stand-in (real seam = qlab_consensus::verify_proof).
    let mut node = RunningNode::start(&config, &genesis, RandomXPow::new(), DevnetRehearsalVerifier)?;

    // Item 0: the binary mines on real wall-clock header timestamps (NOT the
    // deterministic 75 s counter the in-process sims/tests use), so LWMA sees real
    // variable solvetimes over the soak.
    node.set_mining_clock(MiningClock::WallClock);

    println!("qumbra-node running");
    println!("  listen:       {}", node.listen_addr());
    println!("  data dir:     {}", config.data_dir.display());
    println!("  genesis hash: {}", genesis.hash_hex());
    println!("  mining:       {}", config.mining);
    println!("  committee keys held: {}", config.committee_key_paths.len());
    println!("(Ctrl-C to shut down — snapshot is flushed on exit)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&shutdown);
    ctrlc::set_handler(move || sig.store(true, Ordering::SeqCst))?;

    node.run_until(&shutdown);
    println!("shutdown complete (snapshot flushed)");
    Ok(())
}

fn audit(args: &[String]) -> Result<(), Box<dyn Error>> {
    let md = params_audit::render_markdown();
    match flag(args, "--out") {
        Some(path) => {
            std::fs::write(path, &md)?;
            println!("audit written to {path}");
        }
        None => print!("{md}"),
    }
    Ok(())
}
