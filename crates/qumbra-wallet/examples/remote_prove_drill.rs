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
//!       The service's fee checks (M4 checklist 7), a rehearsal genesis only:
//!       `--lie-payee V2ADDR` rewrites /info's payee to V2ADDR and pins it,
//!       so output 3 pays V2ADDR → expect 402 prover-fee-missing;
//!       `--lie-price S,P` rewrites /info's price (below the service's) →
//!       expect 402 prover-fee-short. Either spends the step's leaves.
//!
//! Lab #966, measurement only: a send also prints where its time before the
//! first upload went — `TIME scan|build <route>: calls, bytes, fetch, wallet`
//! per route class (`wallet` is the wallet's own time on that route's answers,
//! up to its next request), then `TIME plan at`, `TIME step N review at`, and
//! the existing `TIME step N upload #1 at`. Nothing the send does changes.
//!
//! What it cannot reach (host-side, through the coordinator's driver): the
//! paid ledger's line count, a direct call without the ingress header (400
//! client-ip-unknown), and `import-openings` (the CLI's own command).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use qlab_l2spend::Endpoint;
use qumbra_wallet::annulet_send::{send_annulet_remote, RemoteHooks, WalletEndpoint};
use qumbra_wallet::remote_prover::{self, Event, HttpProver, ProverTransport, RECORD_DIR};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A value-taking flag. Present without a value (last on the line, or followed by another `--flag`)
/// is refused, never read as absent: a bare `--lie-payee` would otherwise be an honest send.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == name)?;
    match args.get(i + 1) {
        Some(v) if !v.starts_with("--") => Some(v.as_str()),
        _ => {
            eprintln!("{name} needs a value");
            std::process::exit(2)
        }
    }
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
/// pin from `--pin-payee` / `--pin-max S,P` — or, for the fee-check drill,
/// the lied payee (`--lie-payee`, which takes `--pin-payee`'s place).
fn pin(args: &[String], genesis: &[u8; 32]) {
    let compiled = qumbra_wallet::prover_pins::PINS.iter().any(|(g, ..)| g == genesis);
    let lying = flag(args, "--lie-payee").is_some() || flag(args, "--lie-price").is_some();
    if lying && compiled {
        eprintln!("this genesis is pinned in this build: --lie-payee / --lie-price are refused (a rehearsal genesis only)");
        std::process::exit(2)
    }
    if flag(args, "--lie-payee").is_some() && flag(args, "--pin-payee").is_some() {
        eprintln!("--lie-payee pins the lied payee itself: drop --pin-payee");
        std::process::exit(2)
    }
    match (flag(args, "--pin-payee").or(flag(args, "--lie-payee")), compiled) {
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
    if args.iter().any(|a| a == "--lie-payee" || a == "--lie-price") {
        eprintln!("--lie-payee / --lie-price are send-only");
        std::process::exit(2)
    }
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
    let lie_payee = flag(args, "--lie-payee").map(str::to_string);
    let lie_price = flag(args, "--lie-price").map(|v| {
        v.split_once(',').and_then(|(s, p)| Some((s.parse::<u64>().ok()?, p.parse::<u64>().ok()?))).unwrap_or_else(|| {
            eprintln!("--lie-price S,P (whole fee units)");
            std::process::exit(2)
        })
    });
    let expect = match (&lie_payee, lie_price) {
        (Some(_), Some(_)) => {
            eprintln!("one lie at a time: --lie-payee or --lie-price");
            std::process::exit(2)
        }
        (Some(_), None) => Some("HTTP 402 prover-fee-missing"),
        (None, Some(_)) => Some("HTTP 402 prover-fee-short"),
        (None, None) => None,
    };
    if expect.is_some() && busy_probe {
        eprintln!("--busy-probe needs an honest send");
        std::process::exit(2)
    }
    let mut t = Lying { inner: HttpProver { base: base.clone() }, payee: lie_payee, price: lie_price };
    let started = Instant::now();
    let timing = Rc::new(Timing::default());
    let phases: RefCell<Vec<(String, Duration)>> = RefCell::new(Vec::new());
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
        Timed { inner: WalletEndpoint { url: need(args, "--url").to_string() }, timing: Rc::clone(&timing) },
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
                    timing.close();
                    phases.borrow_mut().push((format!("step {} review", i + 1), started.elapsed()));
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
            timing.close();
            timing.planned.set(true);
            phases.borrow_mut().push(("plan".to_string(), started.elapsed()));
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
    timing.close();
    timing.print();
    for (what, at) in phases.borrow().iter() {
        println!("TIME {what} at {:.1}s", at.as_secs_f64());
    }
    for (step, what, at) in &marks {
        println!("TIME step {} {what} at {:.1}s", step + 1, at.as_secs_f64());
    }
    match (result, expect) {
        (Ok(report), None) => {
            for (i, id) in report.tx_ids.iter().enumerate() {
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                println!("INFO step {} submitted by the service: tx {hex}", i + 1);
            }
            r.pass(&format!("send: {} step(s) submitted in {:.1}s", report.tx_ids.len(), started.elapsed().as_secs_f64()));
        }
        (Err(e), None) => r.fail(&format!("send: {e}")),
        (Err(e), Some(want)) => {
            let e = e.to_string();
            r.check(e.contains(want), &format!("the service refused the lying bundle: {e} (want {want})"));
        }
        (Ok(_), Some(want)) => r.fail(&format!("the service SUBMITTED a bundle that should have been refused ({want})")),
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

/// Lab #966: the node endpoint with a stopwatch — per route class, how many
/// reads, how many bytes, the time waiting for each answer, and the wallet's
/// time on it (from the answer to the next request, or to the next mark).
/// Only times; every byte passes through unchanged.
struct Timed {
    inner: WalletEndpoint,
    timing: Rc<Timing>,
}

#[derive(Default)]
struct Timing {
    /// `false` until the plan is shown: reads before it are the scan's,
    /// reads after it the build's (registry, tree paths, splits).
    planned: Cell<bool>,
    /// The route class whose answer the wallet is working on, and since when.
    open: RefCell<Option<(String, Instant)>>,
    /// (phase, route class) → (calls, bytes, fetch, wallet).
    by: RefCell<BTreeMap<(&'static str, String), RouteTime>>,
}

/// calls, bytes, fetch, wallet.
type RouteTime = (u32, u64, Duration, Duration);

impl Timing {
    /// `/v1/block/123/tx/4/full?x=1` → `/v1/block/N/tx/N/full`: a class, not a URL.
    fn class(path: &str) -> String {
        let path = path.split('?').next().unwrap_or(path);
        let mut out = String::new();
        let mut digits = false;
        for c in path.chars() {
            if c.is_ascii_digit() {
                if !digits {
                    out.push('N');
                }
                digits = true;
            } else {
                digits = false;
                out.push(c);
            }
        }
        out
    }

    fn phase(&self) -> &'static str {
        if self.planned.get() { "build" } else { "scan" }
    }

    /// End the wallet's time on the last answer, now.
    fn close(&self) {
        if let Some((class, since)) = self.open.borrow_mut().take() {
            let key = (self.phase(), class);
            self.by.borrow_mut().entry(key).or_default().3 += since.elapsed();
        }
    }

    fn print(&self) {
        let mut totals: BTreeMap<&'static str, (Duration, Duration)> = BTreeMap::new();
        for ((phase, class), (calls, bytes, fetch, wallet)) in self.by.borrow().iter() {
            println!(
                "TIME {phase} {class}: {calls} call(s), {bytes} B, fetch {:.1}s, wallet {:.1}s",
                fetch.as_secs_f64(),
                wallet.as_secs_f64()
            );
            let t = totals.entry(phase).or_default();
            t.0 += *fetch;
            t.1 += *wallet;
        }
        for (phase, (fetch, wallet)) in totals {
            println!("TIME {phase} total: fetch {:.1}s, wallet {:.1}s", fetch.as_secs_f64(), wallet.as_secs_f64());
        }
    }
}

impl Endpoint for Timed {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.timing.close();
        let class = Timing::class(path);
        let asked = Instant::now();
        let got = self.inner.get(path);
        let fetch = asked.elapsed();
        {
            let mut by = self.timing.by.borrow_mut();
            let e = by.entry((self.timing.phase(), class.clone())).or_default();
            e.0 += 1;
            e.1 += got.as_ref().map_or(0, |b| b.len() as u64);
            e.2 += fetch;
        }
        *self.timing.open.borrow_mut() = Some((class, Instant::now()));
        got
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        self.timing.close();
        self.inner.post(path, body)
    }
}

/// The fee-check drill's transport: `/v2/annulet/info` with its payee and/or
/// price rewritten (the service's own answer otherwise), everything else
/// passed through untouched.
struct Lying {
    inner: HttpProver,
    payee: Option<String>,
    price: Option<(u64, u64)>,
}

impl ProverTransport for Lying {
    fn call(&mut self, method: &str, path: &str, body: Option<&[u8]>, max_bytes: usize) -> Result<(u16, Vec<u8>), String> {
        let (status, bytes) = self.inner.call(method, path, body, max_bytes)?;
        if (method, path, status) != ("GET", "/v2/annulet/info", 200) || (self.payee.is_none() && self.price.is_none()) {
            return Ok((status, bytes));
        }
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "the service's /info is not JSON".to_string())?;
        let o = v.as_object_mut().ok_or_else(|| "the service's /info is not a JSON object".to_string())?;
        if let Some(p) = &self.payee {
            o.insert("payee".into(), serde_json::Value::String(p.clone()));
        }
        if let Some((s, p)) = self.price {
            o.insert("price".into(), serde_json::json!({ "S": s, "P": p }));
        }
        println!("INFO lying /info: {v}");
        Ok((status, v.to_string().into_bytes()))
    }
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
