//! `qumbra-node` — the deployable full-node binary + genesis tooling (M10-T0-1).
//!
//! ```text
//!   qumbra-node genesis init [--out DIR] [--t2] [--launch] [--difficulty N]
//!                                          build the T0/T2 genesis file + committee
//!                                          key files; print the genesis hash.
//!                                          `--t2 --launch` is the T2 ceremony path
//!                                          (OS-random committee keys; lab #506).
//!   qumbra-node mine --dir DIR             zero-to-mining in one command (lab #475):
//!                                          wallet (backup-gated) + the built-for net's
//!                                          defaults + verified genesis + node.toml, then
//!                                          `run`. `mine --print-net` reports that net.
//!   qumbra-node run --config FILE          run a full node (TCP + RandomX + disk)
//!   qumbra-node audit [--out FILE]         emit the params_devnet convergence audit
//!   qumbra-node audit-emission --data-dir  walk a data dir's main chain and report
//!     DIR [--from H] [--to H]              every body payee total ≠ schedule height
//! ```
//!
//! All the testable logic lives in the library ([`qumbra_node`]); this is thin
//! CLI glue. Graceful shutdown (SIGINT / SIGTERM / SIGHUP) flushes an atomic
//! snapshot and the learned address book.

use std::error::Error;
use std::process::ExitCode;

use qlab_devnet::pow::RandomXPow;
use qlab_node::round::ObsClock;
use qlab_p2p::adapter::MiningClock;

use qumbra_node::audit_emission::{self, EXIT_CANNOT_RUN};
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::params_audit;
use qumbra_node::release::{HaltMarker, RELEASE};
use qumbra_node::revision::own_frozen_digest_hex;
use qumbra_node::run::RunningNode;
use qumbra_node::telemetry_server::TelemetryServer;
use qumbra_node::verifier::select_verifier;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // audit-emission carries its own exit-code contract (0 clean / 1 mismatch /
    // 2 cannot-run) and must not be folded into the binary-wide SUCCESS/FAILURE map.
    if args.first().map(String::as_str) == Some("audit-emission") {
        return cmd_audit_emission(&args[1..]);
    }
    // audit-names shares the same exit-code contract (lab #367).
    if args.first().map(String::as_str) == Some("audit-names") {
        return cmd_audit_names(&args[1..]);
    }
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            qlab_devnet::jeprintln!(ERROR, "qumbra-node error: {e}");
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
        Some("mine") => mine_cmd(&args[1..]),
        Some("check") => check_config(&args[1..]),
        Some("halt-status") => halt_status(&args[1..]),
        Some("audit") => audit(&args[1..]),
        Some("emission-pins") => emission_pins(&args[1..]),
        Some("audit-emission") | Some("audit-names") => {
            // Handled in main() for exit-code fidelity; unreachable via dispatch.
            Err("audit subcommands are dispatched from main".into())
        }
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
         qumbra-node genesis init [--out DIR] [--t2] [--launch] [--difficulty N]\n      \
                                            build the genesis file + 21 committee key files.\n      \
           --t2                             mint the v5 T2 genesis (rehearsal keys, pinned hash)\n      \
           --launch                         T2 ceremony path: committee keys from OS randomness.\n      \
                                            Requires --t2. Hash is NOT reproducible.\n      \
           --difficulty N                   launch-only; default stays the current placeholder\n  \
         qumbra-node mine --dir DIR             zero-to-mining in one command (lab #475). Finds or\n      \
                                            CREATES a wallet (its mnemonic is printed ONCE and the\n      \
                                            run waits for you to confirm), downloads + verifies\n      \
                                            genesis against the pin for the net this binary was\n      \
                                            BUILT for, writes an ordinary node.toml into DIR, then\n      \
                                            runs it.\n      \
           [--net t1|t2]                      join a net other than the one this binary was\n      \
                                            built for (`mine --print-net` says which that is)\n      \
           [--genesis-hash <64hex>]           pin THIS genesis identity — the no-rebuild path\n      \
                                            onto a net this binary predates\n      \
           [--print-net]                      print the baked network identity and exit. Binds\n      \
                                            nothing, writes nothing, needs no --dir.\n      \
           [--seeds a:1,b:2]                  override the four baked public seed addresses\n      \
           [--genesis-url URL]                override https://seed.qumbra.org/genesis.qmb\n      \
           [--rkm <64hex>]                    pay THIS key and never touch a wallet (manual path)\n      \
           [--yes-i-backed-up]                the non-interactive backup confirmation. Without a\n      \
                                            terminal and without this flag, `mine` REFUSES to\n      \
                                            create a wallet rather than creating one silently.\n      \
           [--index N]                        wallet address index the payout key derives at (0).\n      \
                                            `mine` ALLOCATES the index so this wallet's own scan\n      \
                                            covers what it mines; capped at 1024.\n      \
           [--listen ADDR]                    P2P bind address (default 0.0.0.0:9400)\n  \
         qumbra-node run --config FILE          run a full node (TCP + RandomX + disk persistence)\n      \
           [--rehearsal-verifier]               opt in to the NO-OP rehearsal tx verifier (devnet only)\n      \
           [--sample-interval-secs N]           telemetry sampling cadence (default 30; observability only)\n      \
           [--snapshot-interval-secs N]         snapshot write cadence (default 300; durability only, #359)\n  \
         qumbra-node check --config FILE        pre-flight a deployed config (genesis + keys), bind nothing\n  \
         qumbra-node halt-status [--config F]   print this binary's halt schedule + revision digest (#74),\n      \
                                            and — with --config — this data dir's snapshot height (#359)\n  \
         qumbra-node audit [--out FILE]         emit the params_devnet ⟷ FROZEN v1.0 convergence audit\n  \
         qumbra-node audit-emission --data-dir DIR [--from H] [--to H]\n      \
         qumbra-node audit-names --data-dir DIR [--from H] [--to H]\n      \
                                            walk the persisted main chain; report every height whose\n      \
                                            body.coinbase ≠ emission::coinbase(height) (lab #299 / QUM-82)\n      \
                                            exit 0 = clean, 1 = ≥1 mismatch, 2 = could not run\n  \
         qumbra-node emission-pins              print the emission-rule boundary's activation pins as\n      \
                                            pasteable Rust literals (lab #299/#303 ruling clause 3).\n      \
                                            🔴 RUN THIS ON A LINUX/glibc HOST — the pins are the\n      \
                                            HISTORICAL schedule's values and #303 measured that they\n      \
                                            differ between C libraries."
    );
}

/// Print the emission-rule boundary's activation pins (lab #299 + #303).
///
/// Pure and read-only: no data dir, no network. See
/// [`qumbra_node::emission_pins`] for why it exists as a command.
fn emission_pins(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "{}",
        qumbra_node::emission_pins::render(&qumbra_node::emission_pins::compute())
    );
    Ok(())
}

/// Read-only emission localization (lab #299 baton (a) / QUM-82).
///
/// Exit codes are the operator contract, not free-form: 0 ran-clean, 1 ran-with-
/// mismatches, 2 could-not-run (bad dir / unreadable log / interval beyond tip /
/// usage). The report always ends with a summary line so a clean chain is never silent.
fn cmd_audit_names(args: &[String]) -> ExitCode {
    let (data_dir, from, to) = match qumbra_node::audit_names::parse_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("qumbra-node audit-names: {e}");
            usage();
            return ExitCode::from(qumbra_node::audit_names::EXIT_CANNOT_RUN);
        }
    };
    match qumbra_node::audit_names::audit_names(&data_dir, from, to) {
        Ok(report) => {
            print!("{}", report.format_output());
            ExitCode::from(report.exit_code())
        }
        Err(e) => {
            eprintln!("qumbra-node audit-names: {e}");
            ExitCode::from(qumbra_node::audit_names::EXIT_CANNOT_RUN)
        }
    }
}

fn cmd_audit_emission(args: &[String]) -> ExitCode {
    let (data_dir, from, to) = match audit_emission::parse_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("qumbra-node audit-emission: {e}");
            usage();
            return ExitCode::from(EXIT_CANNOT_RUN);
        }
    };
    // `--payee <64hex>`: attribution, not audit. Parsed with the SAME function the
    // node uses for its own `miner_rkm` (`config::rkm_lanes_from_hex`), because a
    // second copy of that lane-major arithmetic is exactly the wrong-in-the-detail
    // this tool exists to settle.
    let payee = match flag(args, "--payee") {
        None => None,
        Some(hex) => match qumbra_node::config::rkm_lanes_from_hex(hex) {
            Ok(lanes) => Some(lanes),
            Err(e) => {
                eprintln!("qumbra-node audit-emission: --payee {e}");
                return ExitCode::from(EXIT_CANNOT_RUN);
            }
        },
    };
    match audit_emission::audit_emission(&data_dir, from, to, payee) {
        Ok(report) => {
            println!("{}", report.format_output());
            ExitCode::from(report.exit_code())
        }
        Err(e) => {
            eprintln!("qumbra-node audit-emission: {e}");
            ExitCode::from(EXIT_CANNOT_RUN)
        }
    }
}

/// `--name VALUE` flag lookup.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Presence-only flag lookup (`--name`).
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn genesis_init(args: &[String]) -> Result<(), Box<dyn Error>> {
    let plan = qumbra_node::genesis::GenesisInitPlan::parse(args)?;
    std::fs::create_dir_all(&plan.out)?;

    // Lab #470 stage 4b: `--t2` mints the v5-format T2 genesis; the default
    // stays the T1 file byte-for-byte.
    // Lab #506: `--t2 --launch` is the T2 ceremony path — same v5 shape, OS-random
    // committee keys. Without `--launch` the rehearsal constructors are used
    // unchanged (the pin tests are the compat lock).
    let (gf, launch_seeds) = if plan.launch {
        let (gf, seeds) = GenesisFile::new_t2_launch(plan.difficulty);
        (gf, Some(seeds))
    } else if plan.t2 {
        (GenesisFile::new_t2(), None)
    } else {
        (GenesisFile::new_devnet_t0(), None)
    };
    let gpath = plan.out.join("genesis.qmb");
    gf.write(&gpath)?;
    let key_dir = plan.out.join("keys");
    let keys = match &launch_seeds {
        Some(seeds) => gf.write_committee_key_files_from_seeds(
            &key_dir,
            seeds,
            qumbra_node::genesis::LAUNCH_KEY_NOTE,
        )?,
        None => gf.write_committee_key_files(&key_dir)?,
    };

    // Self-verify: the file we just wrote must load, byte-verify, and re-hash to
    // the printed value (item 2 — genesis hash printed + asserted).
    let loaded = GenesisFile::load(&gpath)?;
    let hash = loaded.hash_hex();
    loaded.verify_startup(Some(&hash))?;

    println!("qumbra-node genesis init");
    println!("  network:        {}", gf.network);
    println!(
        "  format version: {} (NOT frozen — [devnet-placeholder] shape)",
        gf.format_version
    );
    println!(
        "  mode:           {}",
        qumbra_node::genesis::mode_banner(plan.launch)
    );
    println!(
        "  committee:      N={} quorum={}",
        gf.frozen.committee_size, gf.frozen.quorum
    );
    println!("  block time:     {} s (FROZEN)", gf.frozen.block_time_secs);
    println!("  consensus FRI:  {}", gf.frozen.consensus_fri);
    println!("  genesis file:   {}", gpath.display());
    println!("  key files:      {} in {}", keys.len(), key_dir.display());
    println!("  GENESIS HASH:   {hash}");
    println!("  self-verify:    OK");
    Ok(())
}

/// `mine` — lab #475: prepare `DIR`, then hand the config it wrote to the
/// ORDINARY run path.
///
/// The last two lines are the whole design. Everything `mine` decided is a file
/// in `DIR` by the time `run_node` is called, and `run_node` is called with the
/// operator's own arguments still attached — so `mine --rehearsal-verifier` or
/// `mine --snapshot-interval-secs 60` reach the run path exactly as they would
/// have on `run`. There is no second node here, only a prepared directory.
fn mine_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
    use std::io::IsTerminal;

    let plan = match qumbra_node::mine::parse_mine(args)? {
        // `--print-net` answers "what net is this binary built for" and exits.
        // It binds nothing, writes nothing and reads no wallet, which is what
        // lets the release lane's artifact gate ask a freshly built binary the
        // question that lab #527 had no way to ask the shipped one.
        qumbra_node::mine::MinePlan::PrintNet(identity) => {
            print!("{}", identity.report());
            return Ok(());
        }
        qumbra_node::mine::MinePlan::Prepare(args) => *args,
    };
    // Whether there is a human to show a mnemonic to is a property of THIS
    // process's stdin, decided here and injected — `mine.rs` takes it as an
    // argument so the whole backup gate is testable without a pty.
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut input = stdin.lock();
    let mut out = std::io::stdout();
    let prepared = qumbra_node::mine::prepare(
        &plan,
        interactive,
        qumbra_node::mine::http_fetch,
        &mut input,
        &mut out,
    )?;

    let mut run_args: Vec<String> = vec![
        "--config".to_string(),
        prepared.config_path.display().to_string(),
    ];
    run_args.extend_from_slice(args);
    run_node(&run_args)
}

fn run_node(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("run requires --config FILE")?;
    // Lab #300: the entry line is the FIRST act — before config load, and so
    // before everything downstream of it. A node that spends an hour computing
    // before its banner is indistinguishable from a dead one; this line makes
    // that silence structurally impossible (ordering locked in `startup`'s
    // tests + tests/startup_entry.rs).
    let config = qumbra_node::startup::announce_then_load(&mut std::io::stdout(), cfg_path)?;
    // Lab #552(a) — THE FIRST REFUSAL, and it is first on purpose: it is a pure
    // config fact, so it costs nothing, and a node that is going to be told it
    // has nobody to pay should be told before it reads a genesis file or builds a
    // ~256 MiB RandomX cache. This used to be a WARNING at the point the payout
    // key was installed (`run.rs`, still there for the in-process rehearsal seam)
    // — but the warning is at startup and the burn is at every block, and nobody
    // rereads startup logs: T2 blocks 607/610/611 paid ~15 QMB to a placeholder
    // nobody owns. `qumbra-node check` refuses the same combination via
    // `preflight`, so the two operator surfaces agree.
    qumbra_node::run::check_miner_payout(&config)?;
    qlab_devnet::jprintln!("STARTUP loading genesis file {}", config.genesis_file.display());
    // Lab #708: dispatched by the file's leading format_version — an L1
    // genesis runs the L1 node, an Annulet genesis the sequencer net.
    let genesis_bytes = std::fs::read(&config.genesis_file)?;
    let genesis = qumbra_node::annulet_genesis::load_any(&genesis_bytes)?;
    qlab_devnet::jprintln!("STARTUP genesis file loaded");

    // Real RandomX (N3) is the default engine. The tx verifier defaults to the
    // REAL M3 verifier (qlab_consensus::verify_proof, frozen CONSENSUS_CFG);
    // `--rehearsal-verifier` opts into the NO-OP stand-in and logs loudly
    // (M10-T0-4, issue #68 — the named M11 gate, closed early).
    let rehearsal_verifier = has_flag(args, "--rehearsal-verifier");
    let (verifier, verifier_log) = select_verifier(rehearsal_verifier);
    // Lab #300: bracket every pre-banner stage that can plausibly be expensive,
    // so a stall names the stage it is in instead of presenting as silence. The
    // RandomX constructor is lazy today (the ~256 MiB cache builds at first
    // hash) — the bracket is there for when that stops being true.
    qlab_devnet::jprintln!("STARTUP RandomX engine init begin (light mode; cache builds lazily at first hash)");
    let pow = RandomXPow::new();
    qlab_devnet::jprintln!("STARTUP RandomX engine init done");

    // Lab #373 — startup is three phases now (the shape PR #372 gave the
    // faucet), and the order is load-bearing in both directions. Lab #300's
    // single node-start bracket splits around the phases (merge composition,
    // PR #439 + PR #440) so a stall still names the stage it is in:
    //
    // ① everything that can refuse, refuses — the halt gates, the genesis
    //   byte-verify + hash pin, the committee key checks. A bind BEFORE these
    //   would hold a socket this process is about to refuse to run on.
    qlab_devnet::jprintln!("STARTUP node prepare begin (halt gates, genesis byte-verify, committee keys)");
    let prepared = match &genesis {
        qumbra_node::annulet_genesis::AnyGenesis::L1(g) => RunningNode::prepare(&config, g, pow, verifier)?,
        qumbra_node::annulet_genesis::AnyGenesis::Annulet(g) => {
            // The L2 transaction verifier is B4's: until it lands, the real L1
            // verifier would refuse every L2 transaction, so an Annulet node
            // runs only with the rehearsal verifier, asked for by name.
            if !rehearsal_verifier {
                return Err("an Annulet genesis runs only with --rehearsal-verifier until the L2 \
                            transaction verifier lands (lab B4)"
                    .into());
            }
            RunningNode::prepare_annulet(&config, g, pow, verifier)?
        }
    };
    qlab_devnet::jprintln!("STARTUP node prepare done");

    // ② bind the telemetry listener. From this moment `GET /v1/ready` answers —
    //   `starting`, with the live replay position once the walk begins — so a
    //   healthy replaying host is distinguishable from a dead one for the whole
    //   of the open (node3 spent 3h34m as `UNREACHABLE-OR-SILENT` for want of
    //   this). `/v1/telemetry` 404s until the handover below. A bind AFTER the
    //   open is the defect this ordering fixes.
    let telemetry = match config.telemetry_addr.as_deref() {
        Some(addr) => {
            let srv = TelemetryServer::start(addr)?;
            qlab_devnet::jprintln!(
                "  telemetry:    http://{}{} live (starting); {} serves after the node opens",
                srv.addr(),
                qumbra_node::telemetry_server::READY_PATH,
                qumbra_node::telemetry_server::TELEMETRY_PATH,
            );
            if !srv.addr().ip().is_loopback() {
                qlab_devnet::jprintln!(WARN,
                    "  ⚠️  telemetry is bound to a non-loopback address — it must be paired with a \
                     SOURCE-RESTRICTED inbound rule to the operator's collector, not an open one."
                );
            }
            Some(srv)
        }
        None => None,
    };

    // ③ open the node — Node::open replays blocks.log, hours on a large chain —
    //   then hand the listener the live node.
    qlab_devnet::jprintln!("STARTUP node open begin (data dir open/replay, listen bind, seed dial)");
    let mut node = prepared.open()?;
    if let Some(srv) = telemetry {
        let bound = node.adopt_telemetry_server(srv);
        qlab_devnet::jprintln!("  telemetry:    http://{bound}/v1/telemetry (versioned read wire, GET only)");
    }
    qlab_devnet::jprintln!("STARTUP node open done");

    // Item 0: the binary mines on real wall-clock header timestamps (NOT the
    // deterministic 75 s counter the in-process sims/tests use), so LWMA sees real
    // variable solvetimes over the soak.
    node.set_mining_clock(MiningClock::WallClock);

    // Issue #87: the same seam for round diagnostics. "Were votes still arriving
    // when this round was cut off?" is a wall-clock question — chain time cannot
    // express it — so the binary opts in here, exactly as it does for the mining
    // clock, and the in-process sims keep their deterministic default.
    node.set_obs_clock(ObsClock::WallClock);

    // Issue #87 decision 1 — PULL. The scrape endpoint exists only where the
    // operator asked for it: no `metrics_addr`, no listener. Failure to bind is
    // fatal, because a node that believes it is observable and is not is the exact
    // failure this instrumentation exists to remove.
    if let Some(addr) = config.metrics_addr.as_deref() {
        let bound = node.start_metrics_endpoint(addr)?;
        qlab_devnet::jprintln!("  metrics:      http://{bound}/metrics (Prometheus scrape target)");
        if !bound.ip().is_loopback() {
            qlab_devnet::jprintln!(WARN,
                "  ⚠️  metrics is bound to a non-loopback address — it must be paired with a \
                 SOURCE-RESTRICTED inbound rule to the collector, not an open one."
            );
        }
    } else {
        qlab_devnet::jprintln!("  metrics:      not served (set metrics_addr in the config to enable)");
    }

    // Issue #117 — the `/v1/telemetry` read endpoint itself is bound in phase ②
    // above (lab #373) and by now handed the live node. Same rule as
    // `metrics_addr` and for the same reason: no `telemetry_addr`, no listener;
    // a failure to bind is fatal rather than a node that its operator believes
    // is readable and is not.
    if config.telemetry_addr.is_none() {
        qlab_devnet::jprintln!("  telemetry:    not served (set telemetry_addr in the config to enable)");
    }

    // Issue #188 baton 2 — `/v1/compact`, the note-discovery endpoint a recipient
    // finds its outputs on. 🔴 **The opposite default to the two above, and the
    // opposite for a reason**: `metrics` and `telemetry` are off unless asked for
    // because setting them opens a port, while this one defaults to LOOPBACK, which
    // opens nothing an off-host attacker can reach. A chain whose recipients cannot
    // find their money unless the operator opted in is `t1-discovery-serving-
    // decision.md`'s option 2a with extra steps — the chain commits discovery
    // correctly and hands it to nobody. Turning it off is an explicit
    // `discovery_addr = "off"`.
    if let Some(addr) = config.discovery_bind() {
        let bound = node.start_discovery_endpoint(addr)?;
        let view = node.discovery_view();
        qlab_devnet::jprintln!(
            "  discovery:    http://{bound}/v1/compact?from=&to= (committed note discovery, GET only)"
        );
        qlab_devnet::jprintln!(
            "                projected {} main-chain blocks, {} B of committed discovery",
            view.blocks.len(),
            view.len_bytes()
        );
        if !bound.ip().is_loopback() {
            qlab_devnet::jprintln!(WARN,
                "  ⚠️  discovery is bound to a non-loopback address — it must be paired with a \
                 SOURCE-RESTRICTED inbound rule, not an open one. The bytes are public chain \
                 data, but the listener is still an attack surface."
            );
        }
    } else {
        qlab_devnet::jprintln!(WARN,
            "  discovery:    ⚠️  NOT SERVED (discovery_addr = \"off\"). Recipients of any \
             transaction this node accepts cannot find their outputs here."
        );
    }

    // Telemetry sampling cadence — OBSERVABILITY ONLY. This changes how often a
    // TELEMETRY line is printed and nothing else: not consensus, not the halt
    // height, not any frozen value. It exists because `regime=Halting` is a real
    // but SHORT interval (tip reaches H, then the committee's vote round closes),
    // and at the 30 s default a fast vote round can open and close between two
    // samples — leaving a state the code defines with no run that has ever shown
    // it. Distinct from the halt height, which has no runtime path by design (H1).
    if let Some(v) = flag(args, "--sample-interval-secs") {
        match v.parse::<u64>() {
            Ok(secs) if secs > 0 => {
                node.set_sample_interval(std::time::Duration::from_secs(secs));
                qlab_devnet::jprintln!("  telemetry sampling: every {secs} s (observability only)");
            }
            _ => {
                return Err(
                    format!("--sample-interval-secs needs a positive integer, got `{v}`").into(),
                )
            }
        }
    }

    // Snapshot cadence (issue #359 S2) — DURABILITY ONLY. It changes how often the
    // loop writes `snapshot.bin` and nothing else: not consensus, not the halt
    // height, not any frozen value, and two nodes running different values agree on
    // everything. Tunable per host because the trade it sets — replay time bought
    // with write cost — depends on the host's disk and the chain's length, and
    // neither is a protocol fact.
    if let Some(v) = flag(args, "--snapshot-interval-secs") {
        match v.parse::<u64>() {
            Ok(secs) if secs > 0 => {
                node.set_snapshot_interval(std::time::Duration::from_secs(secs));
                qlab_devnet::jprintln!("  snapshot cadence: every {secs} s (durability only)");
            }
            _ => {
                return Err(
                    format!("--snapshot-interval-secs needs a positive integer, got `{v}`").into(),
                )
            }
        }
    }

    qlab_devnet::jprintln!("qumbra-node running");
    qlab_devnet::jprintln!("  listen:       {}", node.listen_addr());
    qlab_devnet::jprintln!("  data dir:     {}", config.data_dir.display());
    qlab_devnet::jprintln!("  {}", node.recovery_report());
    // Issue #225: before this, a snapshot that could not be honoured against its
    // own block log KILLED the process (`rewind refused: rewind target is not a
    // known block`, 19 times on a rolled T0 host, with no startup line at all).
    // It is a fall-through now, and the fall-through is always correct — so the
    // only thing left to get wrong is letting it pass unnoticed. This says, at the
    // one moment an operator is reading, that the datadir's snapshot was unusable.
    if let Some(why) = &node.recovery_report().snapshot_rejected {
        qlab_devnet::jprintln!(WARN,
            "  ⚠️  THE SNAPSHOT IN THIS DATA DIR COULD NOT BE HONOURED against its own \
             blocks.log (issue #225)."
        );
        qlab_devnet::jprintln!(WARN, "      reason: {why}");
        // Lab #408: the rejection no longer implies the genesis fold. When the
        // log proves the snapshot's tip is on the finalized main chain, its
        // state was honoured anyway and only the tail was replayed — say which
        // of the two recoveries this start actually was.
        if node.recovery_report().snapshot_height.is_some() {
            qlab_devnet::jprintln!(WARN,
                "      Degraded to a NEAR-TIP resume (lab #408): the log's own finalizations \
                 prove the"
            );
            qlab_devnet::jprintln!(WARN,
                "      snapshot's tip is on the finalized main chain, so its state was honoured \
                 and only"
            );
            qlab_devnet::jprintln!(WARN,
                "      the records past it were replayed. State is exactly what a from-genesis \
                 replay"
            );
            qlab_devnet::jprintln!(WARN,
                "      reaches. The snapshot is rewritten at the next graceful stop; if this \
                 repeats"
            );
            qlab_devnet::jprintln!(WARN, "      every start, the log is what to look at.");
        } else {
            qlab_devnet::jprintln!(WARN,
                "      Recovered by a full replay from genesis — the log is the source of truth \
                 and this"
            );
            qlab_devnet::jprintln!(WARN,
                "      state is exactly what a from-genesis replay reaches. The stale snapshot \
                 is rewritten"
            );
            qlab_devnet::jprintln!(WARN,
                "      at the next graceful stop. If this repeats every start, the log is what \
                 to look at."
            );
        }
    }
    qlab_devnet::jprintln!(
        "  genesis hash: {}",
        match &genesis {
            qumbra_node::annulet_genesis::AnyGenesis::L1(g) => g.hash_hex(),
            qumbra_node::annulet_genesis::AnyGenesis::Annulet(g) => g.hash_hex(),
        }
    );
    qlab_devnet::jprintln!("  mining:       {}", config.mining);
    qlab_devnet::jprintln!("  template_serving: {}", config.template_serving);
    qlab_devnet::jprintln!("  committee keys held: {}", config.committee_key_paths.len());
    // The rehearsal banner is the ⚠️-class abnormality the #512 amendment
    // names; the real-verifier line is nominal and carries no token.
    if rehearsal_verifier {
        qlab_devnet::jprintln!(WARN, "  {verifier_log}");
    } else {
        qlab_devnet::jprintln!("  {verifier_log}");
    }
    // H4: the revision identifier + frozen-parameter digest are logged LOUDLY at
    // every startup — that is what makes an undocumented parameter change show up
    // in every log rather than only in a review someone remembers to do.
    qlab_devnet::jprintln!("-- halt-height upgrade status (issue #74) --");
    // The banner is a multi-line string shared with the one-shot `halt-status`
    // (which stays unstamped, like all one-shot command output); here on the
    // run path each of its lines gets the journal stamp.
    for line in RELEASE
        .banner(HaltMarker::load(&config.data_dir).ok().flatten().as_ref())
        .lines()
    {
        qlab_devnet::jprintln!("{line}");
    }
    if let Some(h) = node.halt_at() {
        qlab_devnet::jprintln!(WARN, "  ⚠️  THIS RELEASE HALTS AT HEIGHT {h} — it will stop mining, stop accepting");
        qlab_devnet::jprintln!(WARN, "      blocks, and stop signing checkpoints above it. regime=Halting until the");
        qlab_devnet::jprintln!(WARN, "      boundary finalizes, then regime=Halted.");
    }
    qlab_devnet::jprintln!("{}", qumbra_node::shutdown::stop_signals_line());

    // One seam, two platform mechanisms — see `shutdown.rs` for why Windows needs
    // its own handler rather than ctrlc's (lab #478).
    let shutdown = qumbra_node::shutdown::install()?;

    let flushed = node.run_until(&shutdown);
    // Release any console handler blocked waiting for this (Windows only; a no-op
    // on unix). It goes BEFORE the print: on a window-close the console is already
    // going away, and the thing worth doing promptly is letting the OS have the
    // process back now that the snapshot is on disk.
    qumbra_node::shutdown::flush_complete();
    if flushed {
        qlab_devnet::jprintln!("shutdown complete (snapshot flushed)");
    } else {
        // Do not claim the flush when run_until already logged the failure.
        qlab_devnet::jprintln!("shutdown complete (snapshot flush failed)");
    }
    Ok(())
}

fn check_config(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("check requires --config FILE")?;
    let config = NodeConfig::load(cfg_path)?;
    let genesis = GenesisFile::load(&config.genesis_file)?;
    let pf = qumbra_node::run::preflight(&config, &genesis)?;
    // Halt-height release gates (#74), exactly as `run` would apply them: the
    // cadence-grid + revision-digest checks, and — if this data dir has already
    // halted — the resume gate. A pre-flight that skipped these would tell an
    // operator a swap is safe when startup is about to refuse it.
    let marker = HaltMarker::load(&config.data_dir)?;
    RELEASE.validate()?;
    RELEASE.check_against_marker(marker.as_ref())?;
    println!("qumbra-node check: OK ({cfg_path})");
    println!("  genesis hash: {}", pf.genesis_hash);
    println!(
        "  committee:    N={} quorum={}",
        pf.committee_size, pf.quorum
    );
    println!("  keys held:    {}", pf.keys_held);
    println!("  listen:       {}", pf.listen_addr);
    println!("  dial peers:   {}", pf.dial_peers);
    println!("  mining:       {}", pf.mining);
    // Lab #475: shown because `run`'s loud burn warning arrived too late to act
    // on — by then the node was up and the operator had stopped reading.
    //
    // Lab #552(a) removed the third arm this match used to have. `mining = true`
    // with no `miner_rkm` cannot reach here: `preflight` above returns
    // `RunError::MiningWithoutPayout` for it, so `check` REFUSES where it used to
    // print `⚠️ UNSET with mining = true`. An unset key that gets this far
    // therefore belongs to a non-mining node, and saying so is not a guess.
    match &pf.miner_rkm {
        Some(rkm) => println!("  miner_rkm:    {rkm}"),
        None => println!("  miner_rkm:    not set (this node does not mine)"),
    }
    println!("  halt plan:    {}", RELEASE.plan.describe());
    Ok(())
}

/// `halt-status` — the operator's read of this binary's upgrade schedule (#74).
/// Works with or without a `--config`; with one it also reports the node's on-disk
/// halt marker, i.e. whether this data dir has actually halted.
fn halt_status(args: &[String]) -> Result<(), Box<dyn Error>> {
    // Issue #359 S3: the data dir is kept rather than dropped, because the
    // snapshot section below reads the same directory the marker came from — and
    // both are things an operator needs *before* restarting this host.
    let (marker, data_dir) = match flag(args, "--config") {
        Some(p) => {
            let config = NodeConfig::load(p)?;
            (HaltMarker::load(&config.data_dir)?, Some(config.data_dir))
        }
        None => (None, None),
    };
    println!("qumbra-node halt-status (issue #74)");
    print!("{}", RELEASE.banner(marker.as_ref()));
    // Lab #367: the name-service boundary is a second consensus boundary this
    // binary carries — banner it beside the emission one so arming day reads
    // one command, not two.
    print!(
        "{}",
        qumbra_node::run::name_service_status_line(qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT)
    );
    // Issue #359 S3: without `--config` there is no data dir to ask, and saying
    // "none" would be a claim about a directory this invocation never named.
    match &data_dir {
        Some(dir) => print!("{}", qumbra_node::run::snapshot_status_report(dir)),
        None => println!(
            "  snapshot:     not read — pass --config to report this data dir's snapshot (#359)"
        ),
    }
    println!("  frozen digest (recomputed from THIS binary's constants):");
    println!("    {}", own_frozen_digest_hex());
    match RELEASE.validate() {
        Ok(()) => println!("  validate:     OK — this release is startable"),
        Err(e) => {
            println!("  validate:     REFUSES TO START — {e}");
            return Err(Box::new(e));
        }
    }
    if let Some(m) = &marker {
        if let Err(e) = RELEASE.check_against_marker(Some(m)) {
            println!("  resume gate:  REFUSES TO START — {e}");
            return Err(Box::new(e));
        }
        println!("  resume gate:  OK for this data dir");
        // #81: the rule domain this binary will actually run under is a property of
        // the release AND of the data dir — a routine release inherits the boundary
        // from the marker. An operator diagnosing a fork needs to see the effective
        // value, not the one this binary declares.
        match RELEASE.rule_schedule_on(Some(m)) {
            Ok(s) => match s.post_halt {
                Some(p) => println!(
                    "  rule domain:  {} above height {} ({})",
                    qumbra_node::genesis::hex_encode(&p.domain),
                    p.from_height,
                    if RELEASE.resumes_from == Some(p.from_height) {
                        "declared by this release"
                    } else {
                        "inherited from the halt marker"
                    }
                ),
                None => println!("  rule domain:  none — v1.0 rules at every height"),
            },
            Err(e) => {
                println!("  rule domain:  REFUSES TO START — {e}");
                return Err(Box::new(e));
            }
        }
    }
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
