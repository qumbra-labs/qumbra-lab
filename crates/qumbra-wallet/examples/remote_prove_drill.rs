//! **The remote-prove drill** (lab #937 cut-over, M4): drives a format-34
//! prover service through the real ingress from an operator's machine with
//! the wallet's own remote-prove client (`send_annulet_remote`) — the CLI has
//! no remote-prove command, and this is not one: it is a drill.
//!
//! A **rehearsal** chain's genesis is in no release build's pins, so the
//! drill can register a fixture pin for it (`--pin-payee`, `--pin-max`) —
//! hence the `fixture-pins` feature, which no release build has. A genesis
//! that IS in `prover_pins::PINS` uses its compiled-in pin, and a
//! `--pin-payee` for it is refused.
//!
//!   cargo run --release -p qumbra-wallet --features fixture-pins --example remote_prove_drill -- <command> …
//!
//! Commands (every line it prints is `PASS`, `FAIL`, `INFO` or `TIME`; exit
//! 1 on any FAIL):
//!   check --prover URL --genesis-hash HEX [--pin-payee ADDR --pin-max S,P]
//!       /v2/annulet/info (raw bytes admitted against the pin; format 34),
//!       /v2/annulet/quota → 404 quota-not-served, /healthz's status.
//!   send  --prover URL --url NODE --genesis-hash HEX --dir WALLET --asset N
//!         --amount V --to V2ADDR [--pin-payee ADDR --pin-max S,P] [--busy-probe]
//!       one remote-proved send: the plan and the admitted price, each step's
//!       service events with times (upload → accepted → proving → submitted),
//!       the transaction ids. `--busy-probe`: once step 1's job is live, POST
//!       its recorded bundle again from this machine → expect 429 ip-busy.
//!
//! What it cannot reach (host-side, through the coordinator's driver): the
//! paid ledger's line count, a direct call without the ingress header (400
//! client-ip-unknown), and `import-openings` (the CLI's own command).

use std::time::{Duration, Instant};

use qumbra_wallet::annulet_send::{send_annulet_remote, RemoteHooks, WalletEndpoint};
use qumbra_wallet::remote_prover::{self, Event, HttpProver, ProverTransport, RECORD_DIR};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn need<'a>(args: &'a [String], name: &str) -> &'a str {
    flag(args, name).unwrap_or_else(|| {
        eprintln!("{name} is required");
        std::process::exit(2)
    })
}

struct Report {
    failed: bool,
}

impl Report {
    fn pass(&mut self, what: &str) {
        println!("PASS {what}");
    }
    fn fail(&mut self, what: &str) {
        println!("FAIL {what}");
        self.failed = true;
    }
    fn check(&mut self, ok: bool, what: &str) {
        if ok {
            self.pass(what)
        } else {
            self.fail(what)
        }
    }
}

fn genesis_of(args: &[String]) -> [u8; 32] {
    qumbra_wallet::annulet::parse_genesis_hash(need(args, "--genesis-hash")).unwrap_or_else(|e| {
        eprintln!("--genesis-hash: {e}");
        std::process::exit(2)
    })
}

/// The pin for `genesis`: compiled in, or (a rehearsal chain only) a fixture
/// pin from `--pin-payee` / `--pin-max S,P`.
fn pin(args: &[String], genesis: &[u8; 32]) {
    let compiled = qumbra_wallet::prover_pins::PINS.iter().any(|(g, ..)| g == genesis);
    match (flag(args, "--pin-payee"), compiled) {
        (Some(_), true) => {
            eprintln!("this genesis is pinned in this build: --pin-payee is refused (the drill uses the compiled-in pin)");
            std::process::exit(2)
        }
        (Some(payee), false) => {
            let (s, p) = need(args, "--pin-max")
                .split_once(',')
                .and_then(|(s, p)| Some((s.parse().ok()?, p.parse().ok()?)))
                .unwrap_or_else(|| {
                    eprintln!("--pin-max S,P (whole fee units)");
                    std::process::exit(2)
                });
            qumbra_wallet::prover_pins::pin_fixture(
                *genesis,
                qumbra_wallet::prover_pins::ProverPin {
                    payee: payee.to_string(),
                    max_price: qumbra_wallet::annulet_plan::ProverPrice { s, p },
                },
            );
            println!("INFO fixture pin registered for this genesis: max S {s} / P {p}");
        }
        (None, _) => {}
    }
}

fn check(args: &[String]) -> bool {
    let mut r = Report { failed: false };
    let genesis = genesis_of(args);
    pin(args, &genesis);
    let mut t = HttpProver { base: need(args, "--prover").to_string() };
    match remote_prover::info(&mut t) {
        Ok(bytes) => {
            println!("INFO /v2/annulet/info {} B: {}", bytes.len(), String::from_utf8_lossy(&bytes));
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            r.check(v.get("genesis_format").and_then(|f| f.as_u64()) == Some(34), "/info: genesis_format 34");
            match qumbra_wallet::prover_pins::admit(&bytes, &genesis) {
                Ok(p) => r.pass(&format!("/info admitted on the pin: price S {} / P {}, payee {}", p.price.s, p.price.p, p.payee.short().encode())),
                Err(e) => r.fail(&format!("/info refused by the pin: {e}")),
            }
        }
        Err(e) => r.fail(&format!("/v2/annulet/info: {e}")),
    }
    match t.call("GET", "/v2/annulet/quota", None, remote_prover::MAX_VIEW_BYTES) {
        Ok((status, body)) => {
            let code = remote_prover::error_code(&body);
            r.check(status == 404 && code == "quota-not-served", &format!("/v2/annulet/quota → {status} {code} (want 404 quota-not-served)"));
        }
        Err(e) => r.fail(&format!("/v2/annulet/quota: {e}")),
    }
    match t.call("GET", "/healthz", None, remote_prover::MAX_VIEW_BYTES) {
        Ok((status, body)) => println!(
            "INFO /healthz → {status} {} (503 nullifiers-catching-up / -stale until the follow is ready)",
            remote_prover::error_code(&body)
        ),
        Err(e) => r.fail(&format!("/healthz: {e}")),
    }
    !r.failed
}

fn send(args: &[String]) -> bool {
    let mut r = Report { failed: false };
    let genesis = genesis_of(args);
    pin(args, &genesis);
    let base = need(args, "--prover").to_string();
    let dir = std::path::PathBuf::from(need(args, "--dir"));
    let w = WalletDir::open(&dir).unwrap_or_else(|e| {
        eprintln!("--dir: {e}");
        std::process::exit(2)
    });
    let asset: u16 = need(args, "--asset").parse().expect("--asset N");
    let amount: u64 = need(args, "--amount").parse().expect("--amount V");
    let to = qlab_wallet::address::Address::decode_any(need(args, "--to")).expect("--to: an address");
    let busy_probe = args.iter().any(|a| a == "--busy-probe");
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    let mut t = HttpProver { base: base.clone() };
    let started = Instant::now();
    let mut marks: Vec<(usize, String, Duration)> = Vec::new();
    let mut probed = None;
    let mut events = |step: usize, e: Event| {
        let at = started.elapsed();
        match &e {
            Event::Uploading { attempt } => marks.push((step, format!("upload #{attempt}"), at)),
            Event::NotNow { status, code, wait } => println!("INFO step {} not now: {status} {code}, again in {}s", step + 1, wait.as_secs()),
            Event::Accepted { state, .. } | Event::State { state, .. } => {
                marks.push((step, format!("{state:?}").to_lowercase(), at));
                if busy_probe && step == 0 && probed.is_none() && !state.terminal() {
                    probed = Some(busy(&dir, &base));
                }
            }
        }
    };
    let result = send_annulet_remote(
        &w,
        WalletEndpoint { url: need(args, "--url").to_string() },
        asset,
        amount,
        &to,
        u64::MAX,
        genesis,
        &[],
        Duration::from_secs(600),
        RemoteHooks {
            transport: &mut t,
            sleep: &mut std::thread::sleep,
            events: &mut events,
            // The drill states each step's kernel review before it is signed
            // and signs only a review that renders.
            review: &mut |i, r| match r.render() {
                Ok(text) => {
                    for line in text.lines() {
                        println!("REVIEW step {} {line}", i + 1);
                    }
                    true
                }
                Err(why) => {
                    println!("FAIL step {} review refused: {why}", i + 1);
                    false
                }
            },
            list: None,
        },
        &mut |plan, p| {
            println!(
                "INFO plan: {} transaction(s), network fees {}, prover fees {} at S {} / P {}",
                plan.steps.len(),
                plan.total_fee(),
                plan.prover_fees(),
                p.price.s,
                p.price.p
            );
            true
        },
        &mut rng,
    );
    for (step, what, at) in &marks {
        println!("TIME step {} {what} at {:.1}s", step + 1, at.as_secs_f64());
    }
    match result {
        Ok(report) => {
            for (i, id) in report.tx_ids.iter().enumerate() {
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                println!("INFO step {} submitted by the service: tx {hex}", i + 1);
            }
            r.pass(&format!("send: {} step(s) submitted in {:.1}s", report.tx_ids.len(), started.elapsed().as_secs_f64()));
        }
        Err(e) => r.fail(&format!("send: {e}")),
    }
    if busy_probe {
        match probed {
            Some(Ok((429, code))) if code == "ip-busy" => r.pass("a second job from this IP while step 1's is live → 429 ip-busy"),
            Some(Ok((status, code))) => r.fail(&format!("the second job from this IP → {status} {code} (want 429 ip-busy)")),
            Some(Err(e)) => r.fail(&format!("the busy probe: {e}")),
            None => r.fail("the busy probe never ran (step 1's job was never seen live)"),
        }
    }
    !r.failed
}

/// The newest recorded bundle, POSTed again from this machine while its job
/// is live: `(status, code)`.
fn busy(dir: &std::path::Path, base: &str) -> Result<(u16, String), String> {
    let newest = std::fs::read_dir(dir.join(RECORD_DIR))
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "bundle"))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .ok_or("no recorded bundle")?;
    let bytes = std::fs::read(newest.path()).map_err(|e| e.to_string())?;
    let mut t = HttpProver { base: base.to_string() };
    let (status, body) = t.call("POST", "/v2/annulet/jobs", Some(&bytes), remote_prover::MAX_VIEW_BYTES)?;
    Ok((status, if status < 300 { "accepted".into() } else { remote_prover::error_code(&body) }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ok = match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("send") => send(&args[1..]),
        _ => {
            eprintln!("usage: remote_prove_drill check|send … (see the file's header)");
            std::process::exit(2)
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
