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
use qumbra_faucet::service::{publish_starting, FaucetService};
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
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-faucet error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("address") => address(&args[1..]),
        Some("ticket") => ticket(&args[1..]),
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
        "qumbra-faucet — the T1 faucet listener (issue #123)\n\n\
         USAGE:\n  \
         qumbra-faucet keygen --out DIR            write faucet.seed + faucet-tickets.secret (0600)\n  \
         qumbra-faucet address --config FILE       print the receive address + the miner_rkm to pay\n  \
         qumbra-faucet ticket --config FILE --id N issue one single-use grant ticket\n  \
         qumbra-faucet check --config FILE         validate the deployment; bind nothing, mine nothing\n  \
         qumbra-faucet run --config FILE           run the keyless node + the HTTP listener\n"
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

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_path = flag(args, "--config").ok_or("run requires --config FILE")?;
    let (svc, node_cfg, wallet, ticket_secret) = load(cfg_path)?;
    let genesis = GenesisFile::load(&node_cfg.genesis_file)?;

    let (verifier, verifier_log) = select_verifier(has_flag(args, "--rehearsal-verifier"));

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
    let server = FaucetServer::start_with_trusted_proxies(
        &svc.listen_addr,
        service.gate(),
        service.status(),
        trusted.clone(),
    )?;
    println!("qumbra-faucet listening on http://{}/ — opening the node…", server.addr());

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
        println!("  node telemetry: http://{bound}/v1/telemetry");
    }
    // First real sample: from here the snapshot is node-derived and `chain` stops
    // being `None`.
    service.refresh_status(&node);

    println!("qumbra-faucet running");
    println!("  faucet:         http://{}/", server.addr());
    println!("  node listen:    {}", node.listen_addr());
    println!("  node data dir:  {}", node_cfg.data_dir.display());
    println!("  genesis hash:   {}", genesis.hash_hex());
    println!("  committee keys: 0 (keyless — §6.2 decision 1)");
    println!("  mining:         {} (payout → this faucet)", node_cfg.mining);
    println!("  grant:          {} bessel", svc.grant_value());
    println!("  tickets:        {}", if svc.tickets_required() { "required" } else { "OPEN" });
    // Lab #308 / #296 honesty voice: name which client-id posture is active.
    println!("  {}", trusted.posture_line());
    println!("  {verifier_log}");
    if !server.addr().ip().is_loopback() {
        println!(
            "  ⚠️  THE FAUCET IS BOUND OFF-LOOPBACK AND HOLDS A HOT SPENDING KEY. Pair this \
             with a source-restricted inbound rule."
        );
    }
    if !svc.tickets_required() {
        println!(
            "  ⚠️  TICKETS ARE OFF. The only remaining controls are token buckets, which are an \
             anti-accident filter and not a defence: this faucet is saturable by roughly a \
             hundred distinct subnets."
        );
    }
    println!(
        "  maturity: coinbase this node wins is spendable {} blocks later (FROZEN §2), so a \
         fresh net cannot serve a grant for ~{} h.",
        qlab_node::COINBASE_MATURITY_BLOCKS,
        qlab_node::COINBASE_MATURITY_BLOCKS * 75 / 3600
    );
    println!("(Ctrl-C to shut down — the node's snapshot is flushed on exit)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&shutdown);
    ctrlc::set_handler(move || sig.store(true, Ordering::SeqCst))?;

    // The faucet runs on the node's own loop, not a thread of its own — see
    // `RunningNode::run_until_with` for what that buys and what it costs.
    let mut rng = rand::rng();
    node.run_until_with(&shutdown, |n| {
        let report = service.tick(n, &mut rng);
        if report.harvest.funded > 0 {
            println!(
                "FAUCET funded {} matured coinbase note(s)",
                report.harvest.funded
            );
        }
        if report.harvest.skipped_spent > 0 {
            // Lab #310: spent notes the restart walk would otherwise re-fund.
            println!(
                "FAUCET harvest-skipped-spent {}",
                report.harvest.skipped_spent
            );
        }
        if let Some(receipt) = report.granted {
            // The receipt, never the recipient: a grant line in a log rotation must
            // not be a record of who asked (PR #103's redaction, same rule).
            println!("FAUCET granted receipt={receipt}");
        }
        // Lab #310 / #241: one named reason per refused attempt, before any
        // gave-up line so the operator sees the fault that burned the budget.
        if let Some(reason) = &report.refusal_reason {
            println!("FAUCET refuse reason={reason}");
        }
        if report.dropped_spent > 0 {
            println!(
                "FAUCET dropped-spent {} (stale inventory; attempt not burned)",
                report.dropped_spent
            );
        }
        if let Some(receipt) = report.gave_up {
            match &report.refusal_reason {
                Some(reason) => println!("FAUCET gave-up receipt={receipt} reason={reason}"),
                None => println!("FAUCET gave-up receipt={receipt}"),
            }
        }
    });

    server.shutdown();
    println!("shutdown complete");
    Ok(())
}
