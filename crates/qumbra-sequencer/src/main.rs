//! `qumbra-sequencer` (lab #847).
//!
//! - `intake --genesis G --queue DIR --listen 127.0.0.1:P` — the always-on
//!   intake (S2): verifies wallets' claim and exit files on arrival and
//!   queues them in `DIR`. The chain (`l2_id`, claim tier, genesis hash)
//!   comes from the V6 genesis file, never from flags; `--listen` must be a
//!   loopback address (Q1).
//! - `queue --queue DIR` — the queue's items, in arrival order: id, kind,
//!   state. Nothing else (no amounts, no keys).
//! - `--version`.
//!
//! The posting loop (S4) arrives as a further command; bundles are built with
//! `qlab-bench f5box` until then.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use qumbra_node::genesis_v6::GenesisFileV6;
use qumbra_sequencer::intake::{hex32, Chain};
use qumbra_sequencer::queue::Queue;
use qumbra_sequencer::server::{loopback, serve, Intake};

const USAGE: &str = "usage: qumbra-sequencer intake --genesis FILE --queue DIR --listen 127.0.0.1:PORT\n       \
                     qumbra-sequencer queue --queue DIR\n       qumbra-sequencer --version";

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
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-sequencer: {e}");
            ExitCode::from(64)
        }
    }
}
