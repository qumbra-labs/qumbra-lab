//! `qumbra-pool` — CLI glue. Testable logic lives in the library.

use std::error::Error;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use qumbra_pool::config::PoolConfig;
use qumbra_pool::endpoint::serve;
use qumbra_pool::Pool;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-pool error: {e}");
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
    let form = cfg.form()?;
    let template = cfg.into_template()?;
    println!("qumbra-pool check: ok");
    println!("  listen:            {}", cfg.listen_addr);
    println!("  share_difficulty:  {}", cfg.share_difficulty);
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
    Ok(())
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(flag(args, "--config").ok_or("missing --config FILE")?);
    let cfg = PoolConfig::load(&path)?;
    let form = cfg.form()?;
    let listen = cfg.listen_addr.clone();
    let share_difficulty = cfg.share_difficulty;
    let source = cfg.template_source()?;
    #[cfg(feature = "randomx")]
    let hasher: Box<dyn qumbra_pool::ShareHasher> =
        Box::new(qumbra_pool::RandomXShareHasher::new());
    #[cfg(not(feature = "randomx"))]
    {
        return Err(
            "qumbra-pool run requires feature `randomx` (default ON) — rebuild the binary".into(),
        );
    }
    #[cfg(feature = "randomx")]
    let pool = Arc::new(Pool::new_with_hasher(
        share_difficulty,
        Box::new(source),
        hasher,
        [9, 0, 0, 0],
    )?);
    let listener = TcpListener::bind(&listen)?;
    let bound = listener.local_addr()?;
    println!("qumbra-pool listening on {bound}  form={form:?}  share_diff={share_difficulty}");
    if !pool.current_template().serves_stock_xmrig() {
        println!("  ⚠️  v4 template: stock-xmrig login will be refused (#356 UNCLEAN)");
    }
    println!("  share-PoW: qlab_pow::RandomXHasher + #490 strict <");
    println!(
        "  pplns window: {} shares [devnet-placeholder]",
        qumbra_pool::PPLNS_WINDOW_SHARES
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop2.store(true, Ordering::SeqCst);
    })?;
    serve(listener, pool, stop)?;
    println!("qumbra-pool stopped");
    Ok(())
}
