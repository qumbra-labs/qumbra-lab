//! `qumbra-sequencer` (lab #847).
//!
//! - `intake --genesis G --queue DIR --listen 127.0.0.1:P` — the always-on
//!   intake (S2): verifies wallets' claim and exit files on arrival and
//!   queues them in `DIR`. The chain (`l2_id`, claim tier, genesis hash)
//!   comes from the V6 genesis file, never from flags; `--listen` must be a
//!   loopback address (Q1).
//! - `queue --queue DIR` — the queue's items, in arrival order: id, kind,
//!   state. Nothing else (no amounts, no keys).
//! - `run --genesis G --queue DIR --state FILE --node URL --telemetry ADDR
//!   --operator ADDR --key FILE --out DIR [--max-bundles N] [--max-wait S]
//!   [--poll S]` — one on-demand posting pass (S4, Q5): plans the queued
//!   claims, proves, signs, posts to the operator listener, and records a
//!   bundle only once `/v1/wrapper` names it. Exit 0 when nothing is left to
//!   plan and nothing is in flight; 3 at a ceiling (`--max-bundles`,
//!   `--max-wait`, re-posts), naming what is left; 4 when fewer than 16 claims
//!   are plannable (fillers land in S3). Resumable: the next pass reconciles.
//! - `--version`.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use qumbra_node::genesis_v6::GenesisFileV6;
use qumbra_sequencer::intake::{hex32, Chain};
use qumbra_sequencer::pass::{self, Outcome, Pass};
use qumbra_sequencer::queue::Queue;
use qumbra_sequencer::server::{loopback, serve, Intake};
use qumbra_sequencer::state::StateLock;
use qumbra_sequencer::{key, work};

const USAGE: &str = "usage: qumbra-sequencer intake --genesis FILE --queue DIR --listen 127.0.0.1:PORT\n       \
                     qumbra-sequencer queue --queue DIR\n       \
                     qumbra-sequencer run --genesis FILE --queue DIR --state FILE --node URL --telemetry IP:PORT \
                     --operator IP:PORT --key FILE --out DIR [--max-bundles N] [--max-wait SECS] [--poll SECS]\n       \
                     qumbra-sequencer --version";

/// `--max-bundles` default: one bundle per pass.
const DEFAULT_MAX_BUNDLES: u64 = 1;
/// `--max-wait` default: two hours — a spacing floor (48 blocks ≈ 1 h) and
/// a landing, with room.
const DEFAULT_MAX_WAIT_SECS: u64 = 7200;
/// `--poll` default.
const DEFAULT_POLL_SECS: u64 = 30;

fn opt_u64(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(default),
        Some(_) => flag(args, name)?.parse().map_err(|_| format!("{name} takes a whole number")),
    }
}

fn addr(args: &[String], name: &str) -> Result<std::net::SocketAddr, String> {
    let v = flag(args, name)?;
    v.parse().map_err(|_| format!("{name} {v:?} is not an ip:port address"))
}

/// One posting pass; the exit code names how it ended.
fn run_pass(args: &[String]) -> Result<ExitCode, String> {
    let genesis = load_genesis(Path::new(&flag(args, "--genesis")?))?;
    let key = key::load(Path::new(&flag(args, "--key")?), &genesis.wrapper)?;
    let qdir = PathBuf::from(flag(args, "--queue")?);
    let state = PathBuf::from(flag(args, "--state")?);
    let cfg = Pass {
        state: state.clone(),
        out: PathBuf::from(flag(args, "--out")?),
        spacing: genesis.wrapper.wrapper_spacing_blocks,
        max_bundles: opt_u64(args, "--max-bundles", DEFAULT_MAX_BUNDLES)?,
        max_wait_secs: opt_u64(args, "--max-wait", DEFAULT_MAX_WAIT_SECS)?,
        poll_secs: opt_u64(args, "--poll", DEFAULT_POLL_SECS)?,
    };
    let node = work::HttpNode { telemetry: addr(args, "--telemetry")?, operator: addr(args, "--operator")? };
    let _qlock = Queue::lock(&qdir)?;
    let _slock = StateLock::take(&state)?;
    let mut queue = Queue::open_existing(&qdir)?;
    let mut w = work::RealWork::open(genesis, key, flag(args, "--node")?, state)?;
    match pass::run(&cfg, &mut queue, &node, &work::SystemClock, &mut w)? {
        Outcome::Drained { landed } => {
            eprintln!("SEQ done: {landed} bundle(s) landed, nothing left to plan");
            Ok(ExitCode::SUCCESS)
        }
        Outcome::Ceiling(why) => {
            eprintln!("SEQ stopped at a ceiling: {why}");
            Ok(ExitCode::from(3))
        }
        Outcome::Short { have, need } => {
            eprintln!("SEQ not plannable: {have} claims of the {need} a wrapper holds — fillers land in lab #847 S3");
            Ok(ExitCode::from(4))
        }
    }
}

fn flag(args: &[String], name: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == name).ok_or_else(|| format!("{name} is required\n{USAGE}"))?;
    args.get(i + 1).filter(|v| !v.starts_with("--")).cloned().ok_or_else(|| format!("{name} takes a value\n{USAGE}"))
}

fn load_genesis(path: &Path) -> Result<GenesisFileV6, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let g = GenesisFileV6::from_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
    g.verify_startup(None).map_err(|e| format!("{}: {e:?}", path.display()))?;
    Ok(g)
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("qumbra-sequencer {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("intake") => {
            let rest = &args[1..];
            let addr = loopback(&flag(rest, "--listen")?)?;
            let chain = Chain::of(&load_genesis(Path::new(&flag(rest, "--genesis")?))?);
            let dir = PathBuf::from(flag(rest, "--queue")?);
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            let _lock = Queue::lock(&dir)?;
            let queue = Queue::open(&dir)?;
            eprintln!("INTAKE l2_id={} claim_fee_tier={} genesis={}", chain.l2_id, chain.claim_fee_tier, hex32(&chain.genesis));
            serve(addr, Intake { chain, queue })
        }
        Some("queue") => {
            let queue = Queue::open_existing(Path::new(&flag(&args[1..], "--queue")?))?;
            for item in queue.items() {
                println!("{} {} {}", hex32(&item.id), item.kind.name(), item.state.name());
            }
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("run") {
        return run_pass(&args[1..]).unwrap_or_else(|e| {
            eprintln!("qumbra-sequencer: {e}");
            ExitCode::from(64)
        });
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-sequencer: {e}");
            ExitCode::from(64)
        }
    }
}
