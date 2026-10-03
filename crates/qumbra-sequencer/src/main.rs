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
//!   `--max-wait`, re-posts — a claim waiting for a finality record to cover
//!   its anchor root is such a wait), naming what is left; 4 when the plannable
//!   claims plus one filler per spendable sequencer note are fewer than 16, or
//!   no claim is plannable (S3: the sequencer fills with S self-transfers of
//!   its own notes; before it holds any — S3b seeds them — a wrapper needs 16
//!   real claims). Resumable: the next pass reconciles.
//!   `run` takes the queue directory's lock, the same one `intake` holds for
//!   its whole life — so `run` refuses while an intake serves that directory.
//!   v0 runs the pass on a copy of the queue (the box rehearsal does), or
//!   with intake stopped; sharing a live queue is not built.
//! - `seed --genesis G --key FILE --node URL --out DIR --burn BESSEL
//!   [--count N] [--scan URL] [--intake IP:PORT] [--plan] [--poll S]
//!   [--max-wait S]` — the sequencer's first L2 notes (S3b): burns from its
//!   own L1 wallet (the key file's fourth derivation, in memory only), one
//!   per L1 transaction, then the claims of those burns credited to its
//!   filler wallet, handed to the intake. `--plan` prints the shortfall, the
//!   funding and the proof budget and proves nothing. Resumable.
//! - `rehearsal-key --genesis G --out FILE` — the public rehearsal seed as a
//!   0600 key file, for a rehearsal genesis only (the S6 box run).
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
                     qumbra-sequencer seed --genesis FILE --key FILE --node URL --out DIR --burn BESSEL [--count N] \
                     [--scan URL] [--intake IP:PORT] [--plan] [--poll SECS] [--max-wait SECS]\n       \
                     qumbra-sequencer rehearsal-key --genesis FILE --out FILE\n       \
                     qumbra-sequencer --version";

/// `--max-bundles` default: one bundle per pass.
const DEFAULT_MAX_BUNDLES: u64 = 1;
/// `--max-wait` default: two hours — a spacing floor (48 blocks ≈ 1 h) and
/// a landing, with room. Every wait counts against it, a claim waiting for
/// a finality record to cover its anchor included; reaching it is exit 3.
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
    v.parse().map_err(|_| format!("{name} {v:?} is not an ip:port address")) // debug-ok: an operator-typed address
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
        Outcome::Short { have, need, why } => {
            eprintln!(
                "SEQ not plannable: {have} of the {need} members a wrapper holds (claims, plus one filler per spendable \
                 sequencer note):"
            );
            for line in why {
                eprintln!("SEQ   {line}");
            }
            Ok(ExitCode::from(4))
        }
    }
}

/// `seed --max-wait` default, per wait (a burn mined, its inputs finalized):
/// three hours — the S6 box measured ≈ 10 min of finality lag per burn.
const DEFAULT_SEED_WAIT_SECS: u64 = 10800;

/// `seed` (S3b): the sequencer's first notes.
fn run_seed(args: &[String]) -> Result<(), String> {
    let genesis = load_genesis(Path::new(&flag(args, "--genesis")?))?;
    let key = key::load(Path::new(&flag(args, "--key")?), &genesis.wrapper)?;
    let node = flag(args, "--node")?;
    let scan = if args.iter().any(|a| a == "--scan") { flag(args, "--scan")? } else { node.clone() };
    let intake = if args.iter().any(|a| a == "--intake") { Some(qumbra_sequencer::server::loopback_flag("--intake", &flag(args, "--intake")?)?) } else { None };
    let s = qumbra_sequencer::seed::Seed {
        genesis,
        key,
        node,
        scan,
        intake,
        out: PathBuf::from(flag(args, "--out")?),
        count: usize::try_from(opt_u64(args, "--count", qumbra_sequencer::seed::DEFAULT_COUNT as u64)?).map_err(|_| "--count is too large")?,
        burn: flag(args, "--burn")?.parse().map_err(|_| "--burn takes a whole number of bessel".to_string())?,
        plan: args.iter().any(|a| a == "--plan"),
        poll_secs: opt_u64(args, "--poll", DEFAULT_POLL_SECS)?,
        max_wait_secs: opt_u64(args, "--max-wait", DEFAULT_SEED_WAIT_SECS)?,
    };
    s.run()
}

fn flag(args: &[String], name: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == name).ok_or_else(|| format!("{name} is required\n{USAGE}"))?;
    args.get(i + 1).filter(|v| !v.starts_with("--")).cloned().ok_or_else(|| format!("{name} takes a value\n{USAGE}"))
}

fn load_genesis(path: &Path) -> Result<GenesisFileV6, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let g = GenesisFileV6::from_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?; // debug-ok: a genesis decode error, no key material
    g.verify_startup(None).map_err(|e| format!("{}: {e:?}", path.display()))?; // debug-ok: a genesis startup check error, no key material
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
        Some("seed") => run_seed(&args[1..]),
        Some("rehearsal-key") => {
            let rest = &args[1..];
            let genesis = load_genesis(Path::new(&flag(rest, "--genesis")?))?;
            let out = PathBuf::from(flag(rest, "--out")?);
            key::write_rehearsal(&out, &genesis.wrapper)?;
            eprintln!("wrote {} (0600): the PUBLIC rehearsal sequencer seed", out.display());
            Ok(())
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
