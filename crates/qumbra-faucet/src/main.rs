//! `qumbra-faucet` — the faucet listener binary (issue #123).
//!
//! ```text
//!   qumbra-faucet keygen --out DIR      write a fresh seed + ticket secret (0600),
//!                                       print only the PUBLIC parts
//!   qumbra-faucet address --config F    print this faucet's receive address and the
//!                                       `miner_rkm` the node must be told to pay
//!   qumbra-faucet ticket --config F --id N   issue one single-use grant ticket
//!   qumbra-faucet check --config F      validate the whole deployment, bind nothing
//!   qumbra-faucet run --config F        run the node + the listener in one process
//! ```
//!
//! All the testable logic is in the library ([`qumbra_faucet`]); this is CLI glue,
//! the same posture `qumbra-node`'s `main.rs` takes.
//!
//! **Nothing here ever prints key material.** `keygen` writes the two secrets and
//! prints the address and the `rkm`, both of which are public by construction (an
//! `rkm` is what every address contains and every coinbase body carries).

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use qlab_devnet::pow::RandomXPow;
use qlab_faucet::{Faucet, FaucetConfig, FaucetLimits, TicketPolicy, TicketSecret};
use qlab_node::round::ObsClock;
use qlab_p2p::adapter::MiningClock;
use qlab_wallet::address::Diversifier;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;

use qumbra_faucet::config::FaucetServiceConfig;
use qumbra_faucet::http::FaucetServer;
use qumbra_faucet::metrics_server::MetricsServer;
use qumbra_faucet::service::{publish_starting, FaucetService};
use qumbra_faucet::telemetry::{FaucetMetrics, Telemetry};
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::select_verifier;

/// The faucet's own change/receive diversifier. Fixed rather than rotated, for the
/// reason `qlab_faucet::Faucet::new` gives: the change note is the faucet's own, and
/// a faucet is a publicly-known payer either way — every grant it makes announces it.
/// It is also the `d` the node's `miner_rkm` is derived at, so it must not move: move
/// it and the node keeps paying an address the faucet no longer watches.
fn faucet_d() -> Diversifier {
    Diversifier::default()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // 🔴 Telemetry is initialised for EVERY subcommand, not just `run`, and the
    // reason is the negative test rather than tidiness: "no `OTEL_EXPORTER_OTLP_ENDPOINT`
    // ⇒ no exporter, no noise" is only checkable from outside if some cheap
    // subcommand exercises the same initialisation path a long-running `run` does.
    // `tests/otel_disabled.rs` drives `keygen` for exactly that. The cost when
    // export is off is one tracer provider with no span processor.
    let telemetry = Telemetry::init();
    let code = match dispatch(&args, &telemetry) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            qlab_devnet::jeprintln!(ERROR, "qumbra-faucet error: {e}");
            ExitCode::FAILURE
        }
    };
    // Flush before exit: a batch exporter that is dropped without a shutdown loses
    // whatever it was holding, and the spans most worth having are the ones from
    // the run that just ended.
    telemetry.shutdown();
    code
}

fn dispatch(args: &[String], telemetry: &Telemetry) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("address") => address(&args[1..]),
        Some("ticket") => ticket(&args[1..]),
        Some("check") => check(&args[1..]),
        Some("run") => run(&args[1..], telemetry),
        Some("annulet") => annulet(&args[1..]),
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
        "qumbra-faucet — the T1 faucet listener (issue #123)\n\n\
         USAGE:\n  \
         qumbra-faucet keygen --out DIR            write faucet.seed + faucet-tickets.secret (0600)\n  \
         qumbra-faucet address --config FILE       print the receive address + the miner_rkm to pay\n  \
         qumbra-faucet ticket --config FILE --id N issue one single-use grant ticket\n  \
         qumbra-faucet check --config FILE         validate the deployment; bind nothing, mine nothing\n  \
         qumbra-faucet run --config FILE           run the keyless node + the HTTP listener\n  \
         qumbra-faucet annulet --node-config FILE [--listen ADDR]\n                                            \
         the Annulet devnet faucet: a keyless follower + genesis-stock grants (lab #716)\n"
    );
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Write a file with owner-only permissions where the platform has them.
fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Err(format!(
            "{} already exists. Refusing to overwrite key material — move it aside first.",
            path.display()
        )
        .into());
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// The `miner_rkm` string for this wallet — the node config's 64-hex, lane-major LE
/// form (`NodeConfig::miner_rkm`).
fn miner_rkm_hex(wallet: &Wallet) -> String {
    hex32(&qlab_note::hash::digest_bytes(&wallet.rkm(faucet_d())))
}

fn keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    use rand::Rng;
    let out = PathBuf::from(flag(args, "--out").unwrap_or("."));
    std::fs::create_dir_all(&out)?;

    // The OS CSPRNG directly, and a failure is fatal: a seed from a degraded source
    // is a key somebody else can derive.
    let mut entropy = [0u8; 32];
    let mut ticket = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut entropy);
    rng.fill_bytes(&mut ticket);

    let seed_path = out.join("faucet.seed");
    let ticket_path = out.join("faucet-tickets.secret");
    write_secret(&seed_path, &entropy)?;
    write_secret(&ticket_path, &ticket)?;

    let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy(entropy), 1);
    println!("qumbra-faucet keygen");
    println!("  seed:          {} (0600, NEVER printed)", seed_path.display());
    println!("  ticket secret: {} (0600, NEVER printed)", ticket_path.display());
    println!("  hd account:    1 (not 0 — account 0 is conventionally the primary wallet)");
    println!();
    println!("  Put this in the NODE's config so it pays the faucet what it mines:");
    println!("    miner_rkm = \"{}\"", miner_rkm_hex(&wallet));
    println!();
    println!("  Receive address (public):");
    println!("    {}", wallet.address(faucet_d()).encode());
    Ok(())
}

/// Load the service config, the node config, and the faucet's wallet — everything
/// `run` and `check` both need, with every refusal applied in the same order.
fn load(
    cfg_path: &str,
) -> Result<(FaucetServiceConfig, NodeConfig, Wallet, TicketSecret), Box<dyn Error>> {
    let svc = FaucetServiceConfig::load(cfg_path)?;
    svc.validate()?;
    let node = NodeConfig::load(&svc.node_config)?;
    // 🔴 §6.2 decision 1, before anything else touches a key: the faucet's node must
    // hold no committee keys.
    svc.check_keyless(&node)?;
    let seed = FaucetServiceConfig::read_secret(&svc.seed_file)?;
    let ticket_secret = FaucetServiceConfig::read_secret(&svc.ticket_secret_file)?;
    let wallet =
        Wallet::from_master_seed(&MasterSeed::from_entropy(seed), svc.hd_account());
    // …and the node must be paying THIS faucet, or the faucet would never be funded
    // and would never say why.
    svc.check_payout(&node, wallet.rkm(faucet_d()))?;
    Ok((svc, node, wallet, TicketSecret::from_bytes(ticket_secret)))
}

fn address(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("address requires --config FILE")?;
    // Deliberately does NOT run the payout check: this command exists to produce the
    // value that check needs, so refusing until it passes would be a deadlock.
    let svc = FaucetServiceConfig::load(cfg_path)?;
    svc.validate()?;
    let seed = FaucetServiceConfig::read_secret(&svc.seed_file)?;
    let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy(seed), svc.hd_account());
    println!("miner_rkm = \"{}\"", miner_rkm_hex(&wallet));
    println!("{}", wallet.address(faucet_d()).encode());
    Ok(())
}

fn ticket(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("ticket requires --config FILE")?;
    let id: u64 = flag(args, "--id").ok_or("ticket requires --id N")?.parse()?;
    let svc = FaucetServiceConfig::load(cfg_path)?;
    let secret = TicketSecret::from_bytes(FaucetServiceConfig::read_secret(&svc.ticket_secret_file)?);
    println!("{}", qlab_faucet::Ticket::issue(&secret, id).encode());
    Ok(())
}

fn check(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("check requires --config FILE")?;
    let (svc, node, wallet, _secret) = load(cfg_path)?;
    let genesis = GenesisFile::load(&node.genesis_file)?;
    let pf = qumbra_node::run::preflight(&node, &genesis)?;

    let trusted = svc.trusted_proxies()?;
    println!("qumbra-faucet check: OK ({cfg_path})");
    println!("  listen:            {}", svc.listen_addr);
    println!("  loopback:          {}", svc.binds_loopback());
    println!("  node config:       {}", svc.node_config.display());
    println!("  node genesis hash: {}", pf.genesis_hash);
    println!("  committee keys:    {} (MUST be 0 — §6.2)", pf.keys_held);
    println!("  node mining:       {}", pf.mining);
    println!("  grant value:       {} bessel", svc.grant_value());
    println!("  hd account:        {}", svc.hd_account());
    println!("  tickets required:  {}", svc.tickets_required());
    println!("  {}", trusted.posture_line());
    println!(
        "  metrics:           {}",
        svc.metrics_addr.as_deref().unwrap_or("not served (set metrics_addr — loopback only)")
    );
    println!("  miner_rkm:         {}", miner_rkm_hex(&wallet));
    if !svc.binds_loopback() {
        println!();
        println!("  ⚠️  listen_addr is NOT a loopback address. This faucet holds a HOT SPENDING");
        println!("      KEY. Binding it off-loopback must be a deliberate deployment decision");
        println!("      paired with a source-restricted inbound rule — never the default, and");
        println!("      never a side effect of copying a config (testnet-plan.md §6.2).");
    }
    Ok(())
}

fn run(args: &[String], telemetry: &Telemetry) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("run requires --config FILE")?;
    let (svc, node_cfg, wallet, ticket_secret) = load(cfg_path)?;
    let genesis = GenesisFile::load(&node_cfg.genesis_file)?;

    let rehearsal_verifier = has_flag(args, "--rehearsal-verifier");
    let (verifier, verifier_log) = select_verifier(rehearsal_verifier, genesis.form()?);

    let limits = FaucetLimits {
        ticket_policy: if svc.tickets_required() {
            TicketPolicy::Required
        } else {
            TicketPolicy::Disabled
        },
        ..FaucetLimits::default()
    };
    let faucet = Faucet::new(
        wallet.clone(),
        faucet_d(),
        ticket_secret,
        FaucetConfig {
            grant_value: svc.grant_value(),
            limits,
            hd_account: svc.hd_account(),
            ..FaucetConfig::default()
        },
    );
    let mut service = FaucetService::new(faucet, wallet, faucet_d());
    // `FaucetService::new` seeds the snapshot as `Starting`, so the first request
    // served is never a blank state and never a fabricated one (lab #365).

    // Lab #308: parse the trust set before binding so a bad CIDR refuses to
    // start rather than silently falling back to the empty (socket-only) posture.
    let trusted = svc.trusted_proxies()?;

    // 🔴 A failure to bind is FATAL. `?` and no fallback: a faucet its operator
    // believes is listening and which is not is discovered by a user who cannot get
    // funds and has no way to report it.
    //
    // 🔴 **The bind is BEFORE the node opens, and the order of everything above it
    // is load-bearing** (lab #365). `Node::open` replays `blocks.log`, which took
    // 2h33m on svc1 on 2026-08-12 and ~5 h on a snapshotless host (#359); binding
    // after it meant `faucet.qumbra.org` served a bare Cloudflare 502 for the whole
    // window, with the process healthy and the percentage sitting in its own log.
    //
    // What must NOT move above this line, because both are refusals that exist to
    // fire before this process owns a port:
    //   * `load()` — §6.2's keyless check and the payout check;
    //   * `svc.trusted_proxies()` — #308's CIDR parse.
    // Both are already done. A bind that happened before them would be a faucet
    // holding a socket it was about to refuse to run on.
    let metrics: Arc<FaucetMetrics> = telemetry.metrics();
    let server = FaucetServer::start_with_telemetry(
        &svc.listen_addr,
        service.gate(),
        service.status(),
        trusted.clone(),
        Arc::clone(&metrics),
    )?;
    qlab_devnet::jprintln!("qumbra-faucet listening on http://{}/ — opening the node…", server.addr());

    // The scrape endpoint binds here too, and for the same reason the faucet's own
    // listener does: `Node::open` replays `blocks.log` and has taken hours on a
    // snapshotless host (#359), and a scrape target that only appears after that is
    // a scrape target that is down for the whole window an operator most wants it.
    // Off unless `metrics_addr` is set; a non-loopback value was already refused at
    // load, so this bind cannot be the first place an operator hears about it.
    let metrics_server = match svc.metrics_addr.as_deref() {
        Some(addr) => {
            let m = MetricsServer::start(addr, Arc::clone(&metrics))?;
            qlab_devnet::jprintln!("  metrics:      http://{}/metrics (loopback only)", m.addr());
            Some(m)
        }
        None => {
            qlab_devnet::jprintln!("  metrics:      not served (set metrics_addr in the config to enable)");
            None
        }
    };

    // Now the expensive part, with the listener already answering `Starting`. The
    // publisher thread lives exactly as long as the open: it reads the same
    // counter #287 prints, so the page and the log cannot disagree.
    let opening = Arc::new(AtomicBool::new(true));
    let publisher = {
        let opening = Arc::clone(&opening);
        let status = service.status();
        std::thread::spawn(move || {
            while opening.load(Ordering::Relaxed) {
                publish_starting(&status, qlab_node::live_replay_position());
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        })
    };

    let node_result = RunningNode::start(&node_cfg, &genesis, RandomXPow::new(), verifier);
    opening.store(false, Ordering::Relaxed);
    let _ = publisher.join();
    let mut node = node_result?;
    // The same two clock opt-ins the node binary makes: real wall-clock header
    // timestamps so LWMA sees real solvetimes, and a wall-clock observation clock
    // for round diagnostics.
    node.set_mining_clock(MiningClock::WallClock);
    node.set_obs_clock(ObsClock::WallClock);
    if let Some(addr) = node_cfg.telemetry_addr.as_deref() {
        let bound = node.start_telemetry_endpoint(addr)?;
        qlab_devnet::jprintln!("  node telemetry: http://{bound}/v1/telemetry");
    }
    // 🔴 **The first real sample is a whole tick, not a bare render** (lab #543).
    // `refresh_status` alone publishes what the service currently holds, and before
    // any harvest pass that is `next_maturity: None` / `maturing: 0` — the values a
    // pass reports for a faucet with *no* immature coinbase. So a faucet whose entire
    // stock was inside the frozen §2 gate answered `Empty` — "out of funds … the only
    // refill is a coinbase note", i.e. **none coming** — and refused requests it would
    // have queued one iteration later, to a listener that has been serving since it
    // bound. A tick harvests and then renders, so the first thing this page publishes
    // is measured rather than defaulted.
    //
    // The Ctrl-C handler is installed **before** it, because a restart's first pass
    // re-walks the whole main chain and that is not a moment to be unkillable.
    let shutdown = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&shutdown);
    ctrlc::set_handler(move || sig.store(true, Ordering::SeqCst))?;
    let mut rng = rand::rng();
    log_serve_report(&service.tick(&mut node, &mut rng));

    qlab_devnet::jprintln!("qumbra-faucet running");
    qlab_devnet::jprintln!("  faucet:         http://{}/", server.addr());
    qlab_devnet::jprintln!("  node listen:    {}", node.listen_addr());
    qlab_devnet::jprintln!("  node data dir:  {}", node_cfg.data_dir.display());
    qlab_devnet::jprintln!("  genesis hash:   {}", genesis.hash_hex());
    qlab_devnet::jprintln!("  committee keys: 0 (keyless — §6.2 decision 1)");
    qlab_devnet::jprintln!("  mining:         {} (payout → this faucet)", node_cfg.mining);
    qlab_devnet::jprintln!("  grant:          {} bessel", svc.grant_value());
    qlab_devnet::jprintln!("  tickets:        {}", if svc.tickets_required() { "required" } else { "OPEN" });
    // Lab #308 / #296 honesty voice: name which client-id posture is active.
    qlab_devnet::jprintln!("  {}", trusted.posture_line());
    qlab_devnet::jprintln!("  {}", telemetry.posture_line());
    // The rehearsal banner is the ⚠️-class abnormality the #512 amendment
    // names; the real-verifier line is nominal and carries no token.
    if rehearsal_verifier {
        qlab_devnet::jprintln!(WARN, "  {verifier_log}");
    } else {
        qlab_devnet::jprintln!("  {verifier_log}");
    }
    if !server.addr().ip().is_loopback() {
        qlab_devnet::jprintln!(WARN,
            "  ⚠️  THE FAUCET IS BOUND OFF-LOOPBACK AND HOLDS A HOT SPENDING KEY. Pair this \
             with a source-restricted inbound rule."
        );
    }
    if !svc.tickets_required() {
        qlab_devnet::jprintln!(WARN,
            "  ⚠️  TICKETS ARE OFF. The only remaining controls are token buckets, which are an \
             anti-accident filter and not a defence: this faucet is saturable by roughly a \
             hundred distinct subnets."
        );
    }
    qlab_devnet::jprintln!(
        "  maturity: coinbase this node wins is spendable {} blocks later (FROZEN §2), so a \
         fresh net cannot serve a grant for ~{} h.",
        qlab_node::COINBASE_MATURITY_BLOCKS,
        qlab_node::COINBASE_MATURITY_BLOCKS * 75 / 3600
    );
    qlab_devnet::jprintln!("(Ctrl-C to shut down — the node's snapshot is flushed on exit)");

    // The faucet runs on the node's own loop, not a thread of its own — see
    // `RunningNode::run_until_with` for what that buys and what it costs.
    node.run_until_with(&shutdown, |n| {
        log_serve_report(&service.tick(n, &mut rng));
    });

    server.shutdown();
    if let Some(m) = metrics_server {
        m.shutdown();
    }
    qlab_devnet::jprintln!("shutdown complete");
    Ok(())
}

/// Every operator-visible line a served tick produces, in one place.
///
/// One statement rather than two (lab #543): the first sample is a tick now, and a
/// restart's first pass is exactly the one that funds hundreds of notes at once — so
/// a second copy of this block would have been the copy that drifted, and the pass
/// whose numbers matter most would have been the one nobody printed.
fn log_serve_report(report: &qumbra_faucet::service::ServeReport) {
    if report.harvest.funded > 0 {
        qlab_devnet::jprintln!(
            "FAUCET funded {} matured coinbase note(s)",
            report.harvest.funded
        );
    }
    if report.harvest.skipped_spent > 0 {
        // Lab #310: spent notes the restart walk would otherwise re-fund.
        qlab_devnet::jprintln!(
            "FAUCET harvest-skipped-spent {}",
            report.harvest.skipped_spent
        );
    }
    if let Some(receipt) = report.granted {
        // The receipt, never the recipient: a grant line in a log rotation must
        // not be a record of who asked (PR #103's redaction, same rule).
        qlab_devnet::jprintln!("FAUCET granted receipt={receipt}");
    }
    // Lab #310 / #241: one named reason per refused attempt, before any
    // gave-up line so the operator sees the fault that burned the budget.
    if let Some(reason) = &report.refusal_reason {
        qlab_devnet::jprintln!("FAUCET refuse reason={reason}");
    }
    if report.dropped_spent > 0 {
        qlab_devnet::jprintln!(
            "FAUCET dropped-spent {} (stale inventory; attempt not burned)",
            report.dropped_spent
        );
    }
    if let Some(receipt) = report.gave_up {
        match &report.refusal_reason {
            Some(reason) => qlab_devnet::jprintln!("FAUCET gave-up receipt={receipt} reason={reason}"),
            None => qlab_devnet::jprintln!("FAUCET gave-up receipt={receipt}"),
        }
    }
}

/// **The Annulet devnet faucet** (lab #716): a keyless follower in process,
/// its discovery endpoint as the faucet's served source, and one grant per
/// genesis stock note over `POST /v1/annulet/grant`.
///
/// Refuses, by name and before anything binds: an L1 genesis (that is
/// `qumbra-faucet run`), any genesis other than the devnet's (the only
/// Annulet faucet key is the devnet's **dev** key, public by construction),
/// and a node that would be the sequencer.
fn annulet(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_faucet::annulet::{serve_grants, AnnuletFaucet, Served, SpendKey};
    use qumbra_node::annulet_genesis::{devnet, load_any, AnnuletGenesisFile, AnyGenesis};
    let cfg_path = flag(args, "--node-config").ok_or("annulet requires --node-config FILE")?;
    let listen = flag(args, "--listen").unwrap_or("127.0.0.1:8090");
    let node_cfg = NodeConfig::load(cfg_path)?;
    let genesis = match load_any(&std::fs::read(&node_cfg.genesis_file)?)? {
        AnyGenesis::L1(_) => {
            return Err("the genesis is an L1 form; the Annulet faucet refuses to start on it \
                        (lab #716) — the L1 faucet is `qumbra-faucet run`"
                .into())
        }
        AnyGenesis::Annulet(g) => g,
    };
    if genesis.hash() != AnnuletGenesisFile::devnet().hash() {
        return Err("this Annulet genesis is not the devnet genesis; the Annulet faucet holds only the \
                    devnet dev key (lab #716)"
            .into());
    }
    // An Annulet net has no PoW; the engine parameter is unused on it.
    let mut node = RunningNode::start_annulet(
        &node_cfg,
        &genesis,
        qlab_devnet::pow::KeccakPow,
        qumbra_node::verifier::L2Verifier,
    )?;
    if node.is_sequencer() {
        return Err("the faucet's node would be the sequencer (a sequencer key file is in its data dir); \
                    the faucet runs a keyless follower"
            .into());
    }
    let discovery = node.start_discovery_endpoint(node_cfg.discovery_bind().unwrap_or("127.0.0.1:0"))?;
    node.refresh_discovery();
    node.refresh_leaves();
    node.refresh_registry();
    let key = SpendKey { sk: devnet::FAUCET_SK, d: devnet::FAUCET_D };
    let change = qlab_note::kem::generate_keypair(&mut rand::rng());
    let faucet = AnnuletFaucet::start(
        Served { addr: discovery },
        genesis.form()?,
        key,
        change.ek,
        genesis.params.fee_tier_s,
    )?;
    let stock = faucet.stock_left();
    let bound = serve_grants(listen, Arc::new(std::sync::Mutex::new(faucet)))?;
    qlab_devnet::jprintln!("qumbra-faucet annulet running (lab #716)");
    qlab_devnet::jprintln!("  grants:         http://{bound}{}", qumbra_faucet::annulet::GRANT_PATH);
    qlab_devnet::jprintln!("  stock:          {stock} genesis note(s) unspent");
    qlab_devnet::jprintln!("  node listen:    {}", node.listen_addr());
    qlab_devnet::jprintln!("  node discovery: http://{discovery}/");
    qlab_devnet::jprintln!("  genesis hash:   {}", genesis.hash_hex());
    qlab_devnet::jprintln!(WARN, "  ⚠️  DEV KEY: the faucet key is the devnet's published dev key. No tickets, no rate limit.");
    let shutdown = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&shutdown);
    ctrlc::set_handler(move || sig.store(true, Ordering::SeqCst))?;
    node.run_until(&shutdown);
    qlab_devnet::jprintln!("shutdown complete");
    Ok(())
}
