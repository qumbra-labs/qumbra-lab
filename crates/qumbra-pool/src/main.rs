//! `qumbra-pool` — CLI glue. Testable logic lives in the library.

use std::error::Error;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qumbra_pool::config::PoolConfig;
use qumbra_pool::endpoint::serve;
use qumbra_pool::{assemble_coinbase, Accounts, ConnGuard, JobOutbox, NodeRpcClient,
    PplnsWindow, Pool, TemplateWatch, WatchAction};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            qlab_devnet::jeprintln!(ERROR, "qumbra-pool error: {e}");
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
        "qumbra-pool — the T2 pool listener (lab #482 stage 1)\n\n\
         USAGE:\n  \
         qumbra-pool check --config FILE   validate config; bind nothing\n  \
         qumbra-pool run --config FILE     listen for stratum TCP\n\n\
         v4-compat: a v4 template refuses stock-xmrig login by name\n  \
         (#356 UNCLEAN). Share-PoW: qlab_pow::RandomXHasher. PPLNS + N=1 payee list.\n"
    );
    // lab #605: the process that chooses the payee says which build it is. On the
    // same line shape the node and the wallet use, so one archive reads as one
    // vocabulary.
    eprintln!("build rev: {}", qumbra_pool::build_rev_line());
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn check(args: &[String]) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(flag(args, "--config").ok_or("missing --config FILE")?);
    let cfg = PoolConfig::load(&path)?;
    cfg.ensure_service_ready()?;
    println!("qumbra-pool check: ok");
    println!("  listen:            {}", cfg.listen_addr);
    println!("  share_difficulty:  {}", cfg.share_difficulty);
    println!("  payout_rkm:        configured (non-zero)");
    if let Some(url) = &cfg.node_rpc {
        println!("  node_rpc:          {url}");
        println!("  poll_ms:           {}", cfg.poll_interval_ms());
        println!(
            "  stall:             {} failed polls / {}ms without a good template",
            cfg.stall_poll_failures(),
            cfg.stall_age_ms()
        );
        println!(
            "  disconnect:        {}ms without a good template",
            cfg.disconnect_after_ms()
        );
        println!(
            "  listen guards:     {} conn / {} per-ip / {} B line / {}ms request / {}ms first-line",
            cfg.max_connections(),
            cfg.max_connections_per_ip(),
            cfg.max_line_bytes(),
            cfg.request_timeout_ms_resolved(),
            cfg.connection_timeout_ms_resolved()
        );
        println!("  template:          live (GET /v1/mine/template)");
    } else {
        let form = cfg.form()?;
        let template = cfg.into_template()?;
        println!("  form:              {form:?}");
        println!(
            "  stock-xmrig:       {}",
            if template.serves_stock_xmrig() {
                "yes (v5)"
            } else {
                "no — login will refuse v4-net-unclean-for-stock-xmrig"
            }
        );
        println!("  height:            {}", template.header.height);
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(flag(args, "--config").ok_or("missing --config FILE")?);
    let cfg = PoolConfig::load(&path)?;
    cfg.ensure_service_ready()?;
    let listen = cfg.listen_addr.clone();
    let share_difficulty = cfg.share_difficulty;
    let payout_rkm = cfg.payout_rkm_lanes()?;
    #[cfg(feature = "randomx")]
    let hasher: Box<dyn qumbra_pool::ShareHasher> =
        Box::new(qumbra_pool::RandomXShareHasher::new());
    #[cfg(not(feature = "randomx"))]
    {
        return Err(
            "qumbra-pool run requires feature `randomx` (default ON) — rebuild the binary".into(),
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop2.store(true, Ordering::SeqCst);
    })?;

    let outbox = Arc::new(JobOutbox::new());
    let guard = Arc::new(ConnGuard::new(cfg.listen_limits()));
    #[cfg(feature = "randomx")]
    let pool = if let Some(url) = cfg.node_rpc.clone() {
        // Learn only form/height, then make the first template request with an
        // explicit pool-owned payee list. No payee-free template shim exists.
        let context = NodeRpcClient::parse(&url)?.fetch_context()?;
        let initial_payees = assemble_coinbase(
            context.form,
            context.height,
            &PplnsWindow::default(),
            &Accounts::default(),
            payout_rkm,
        )?.payees();
        let live = qumbra_pool::NodeRpcTemplateSource::connect(&url, &initial_payees)?;
        let client = live.client();
        let initial = live.snapshot();
        let form = initial.form;
        let pool = Arc::new(Pool::new_with_hasher(
            share_difficulty,
            Box::new(qumbra_pool::HeldTemplateSource::new(initial)),
            hasher,
            payout_rkm,
        )?);
        pool.set_submitter(Arc::new(client));
        pool.set_outbox(Arc::clone(&outbox));
        let poll = Duration::from_millis(cfg.poll_interval_ms());
        let stall_failures = cfg.stall_poll_failures();
        let stall_age = Duration::from_millis(cfg.stall_age_ms());
        let disconnect_after = Duration::from_millis(cfg.disconnect_after_ms());
        let watch = Arc::new(TemplateWatch::new(
            stall_failures,
            stall_age,
            disconnect_after,
        ));
        let pool_poll = Arc::clone(&pool);
        let stop_poll = Arc::clone(&stop);
        let watch_poll = Arc::clone(&watch);
        let outbox_poll = Arc::clone(&outbox);
        let guard_poll = Arc::clone(&guard);
        std::thread::spawn(move || {
            while !stop_poll.load(Ordering::SeqCst) {
                std::thread::sleep(poll);
                let polled = live.client().fetch_context()
                    .and_then(|context| pool_poll
                        .assemble_for(context.form, context.height)
                        .map_err(|e| e.to_string()))
                    .and_then(|coinbase| live.poll(&coinbase.payees()));
                match polled {
                    Ok(changed) => {
                        let recovering = pool_poll.is_unavailable();
                        watch_poll.record_ok();
                        if changed || recovering {
                            let t = live.snapshot();
                            match pool_poll
                                .replace_template(Box::new(qumbra_pool::HeldTemplateSource::new(t)))
                            {
                                Ok(jobs) => {
                                    let snap = watch_poll.snapshot();
                                    let why = if recovering {
                                        "recovered"
                                    } else {
                                        "tip changed"
                                    };
                                    qlab_devnet::jprintln!(
                                        "pool template: {why}; pushed {} job(s); poll_failures={} consecutive={} last_good_s={} jobs_pushed={} {}",
                                        jobs.len(),
                                        snap.template_poll_failures,
                                        snap.consecutive_failures,
                                        snap.seconds_since_last_good_template,
                                        outbox_poll.jobs_pushed(),
                                        guard_poll.snapshot().journal_fields()
                                    );
                                }
                                Err(e) => {
                                    qlab_devnet::jeprintln!(WARN, "pool template re-issue: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(action) = watch_poll.record_err() {
                            let action_name = match &action {
                                WatchAction::Suspend(_) => "suspend",
                                WatchAction::Disconnect(_) => "disconnect",
                            };
                            let reason = action.reason().to_owned();
                            pool_poll.apply_watch_action(action);
                            let snap = watch_poll.snapshot();
                            qlab_devnet::jeprintln!(
                                WARN,
                                "pool template poll: {e}; action={action_name}; {reason}; poll_failures={} consecutive={} last_good_s={} jobs_pushed={} {}",
                                snap.template_poll_failures,
                                snap.consecutive_failures,
                                snap.seconds_since_last_good_template,
                                outbox_poll.jobs_pushed(),
                                guard_poll.snapshot().journal_fields()
                            );
                        } else {
                            let snap = watch_poll.snapshot();
                            qlab_devnet::jeprintln!(
                                WARN,
                                "pool template poll: {e}; poll_failures={} consecutive={} last_good_s={} jobs_pushed={} {}",
                                snap.template_poll_failures,
                                snap.consecutive_failures,
                                snap.seconds_since_last_good_template,
                                outbox_poll.jobs_pushed(),
                                guard_poll.snapshot().journal_fields()
                            );
                        }
                    }
                }
            }
        });
        qlab_devnet::jprintln!(
            "  node_rpc: {url}  poll_ms={} stall={}/{}ms disconnect={}ms",
            cfg.poll_interval_ms(),
            cfg.stall_poll_failures(),
            cfg.stall_age_ms(),
            cfg.disconnect_after_ms()
        );
        qlab_devnet::jprintln!("  form: {form:?} (from live node)");
        pool
    } else {
        let source = cfg.template_source()?;
        let form = cfg.form()?;
        qlab_devnet::jprintln!("  form: {form:?} (static [template])");
        Arc::new(Pool::new_with_hasher(
            share_difficulty,
            Box::new(source),
            hasher,
            payout_rkm,
        )?)
    };
    let listener = TcpListener::bind(&listen)?;
    let bound = listener.local_addr()?;
    qlab_devnet::jprintln!("qumbra-pool listening on {bound}  share_diff={share_difficulty}");
    if !pool.current_template().serves_stock_xmrig() {
        qlab_devnet::jprintln!(
            WARN,
            "  ⚠️  v4 template: stock-xmrig login will be refused (#356 UNCLEAN)"
        );
    }
    qlab_devnet::jprintln!("  share-PoW: qlab_pow::RandomXHasher + #490 strict <");
    qlab_devnet::jprintln!(
        "  pplns window: {} shares [devnet-placeholder]",
        qumbra_pool::PPLNS_WINDOW_SHARES
    );
    qlab_devnet::jprintln!(
        "  listen guards: {} conn / {} per-ip / {} B line / {}ms request / {}ms first-line",
        cfg.max_connections(),
        cfg.max_connections_per_ip(),
        cfg.max_line_bytes(),
        cfg.request_timeout_ms_resolved(),
        cfg.connection_timeout_ms_resolved()
    );

    serve(listener, pool, stop, outbox, guard)?;
    qlab_devnet::jprintln!("qumbra-pool stopped");
    Ok(())
}
