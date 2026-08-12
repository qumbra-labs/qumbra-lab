//! `qumbra-wallet` — CLI glue only; the testable logic is in the library
//! (`store`, `view`), the same posture as every other binary here.

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_wallet::store::{seed_from_phrase, reveal_mnemonic, WalletDir};
use qumbra_wallet::view;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qumbra-wallet error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("restore") => restore(&args[1..]),
        Some("address") => address(&args[1..]),
        Some("contact") => contact(&args[1..]),
        Some("backup") => backup(&args[1..]),
        Some("scan") => scan(&args[1..]),
        Some("history") => history(&args[1..]),
        Some("miner-rkm") => miner_rkm(&args[1..]),
        Some("send") => send(&args[1..]),
        Some("names") => names(&args[1..]),
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

/// `names` — the wallet's name layer (lab #367): sync/resolve/pin/register/renew.
/// Registration is a resumable two-step (commit → reveal) driven by repeated
/// invocations against the persisted `names-reg.v1` state; the salt is written
/// BEFORE any tx posts.
fn names(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::names::*;
    let sub = args.first().map(String::as_str);
    match sub {
        Some("sync") => {
            let dir = dir_of(&args[1..])?;
            let url = flag(&args[1..], "--url").ok_or("names sync requires --url")?;
            let tip: u64 =
                flag(&args[1..], "--to").ok_or("names sync requires --to HEIGHT")?.parse()?;
            let mut reg = WalletRegistry::load(&dir)?.unwrap_or_default();
            let before = reg.synced_to;
            qumbra_wallet::names::sync_names(&mut reg, tip, |path| {
                qumbra_wallet::net::http_get(url, path).map_err(|e| e.to_string())
            })
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
            reg.save(&dir)?;
            println!(
                "names: synced {} → {}; {} registration(s) known",
                before,
                reg.synced_to,
                reg.len()
            );
            Ok(())
        }
        Some("resolve") => {
            let name = args.get(1).ok_or("names resolve NAME --tip H")?;
            let dir = dir_of(&args[2..])?;
            let tip: u64 = flag(&args[2..], "--tip").ok_or("names resolve requires --tip")?.parse()?;
            let reg = WalletRegistry::load(&dir)?
                .ok_or("no synced name registry — run `names sync` first")?;
            match reg.resolve(name, tip) {
                Resolution::Active(e) => {
                    let a = qlab_wallet::address::Address::from_raw_bytes(&e.address)
                        .ok_or("entry does not decode")?;
                    let pins = Pins::load(&dir)?;
                    let pin = match pins.check(name, &e.address) {
                        PinVerdict::Match => "pinned ✓".to_string(),
                        PinVerdict::FirstUse { .. } => "NOT pinned — verify out of band".to_string(),
                        PinVerdict::Rebind { pinned, .. } => {
                            format!("🔴 REBIND (you pinned {pinned})")
                        }
                    };
                    println!(
                        "{name} → {}\n  fingerprint {}  [{pin}]\n  registered {}  expires {}",
                        a.encode(),
                        a.short().encode(),
                        e.registered,
                        e.expiry
                    );
                }
                Resolution::Expiring { entry, reopens_at } => {
                    let a = qlab_wallet::address::Address::from_raw_bytes(&entry.address)
                        .ok_or("entry does not decode")?;
                    println!(
                        "{name} → {} (⚠ in grace; re-registrable at {reopens_at})",
                        a.short().encode()
                    );
                }
                Resolution::Unknown => println!("{name}: not registered (as of height {tip})"),
            }
            Ok(())
        }
        Some("pin") => {
            let name = args.get(1).ok_or("names pin NAME FINGERPRINT")?;
            let fp = args.get(2).ok_or("names pin NAME FINGERPRINT")?;
            let dir = dir_of(&args[3..])?;
            let mut pins = Pins::load(&dir)?;
            if let Some(old) = pins.get(name) {
                eprintln!("replacing pin {old} → {fp} (out-of-band re-confirmation is on you)");
            }
            pins.pin(name, fp);
            pins.save(&dir)?;
            println!("pinned {name} → {fp}");
            Ok(())
        }
        Some("register") => names_register(&args[1..]),
        Some("renew") => {
            // Renewal: one ordinary self-send carrying the renew op — any
            // payer may renew any name (N4).
            let name = args.get(1).ok_or("names renew NAME --url … --node … --scan-to H")?;
            let op = qumbra_wallet::names::renewal_op(name)?;
            names_self_send(&args[2..], &op, &format!("renew {name}"))
        }
        _ => Err("names subcommands: sync | resolve | pin | register | renew".into()),
    }
}

/// Drive one step of the resumable registration.
fn names_register(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::names::*;
    let name = args.first().ok_or(
        "names register NAME --dir … --url … --node … --scan-to H [--committed-at H]",
    )?;
    let bare = name.strip_suffix(".qmb").unwrap_or(name);
    let dir = dir_of(&args[1..])?;

    // Record an observed commit height (the operator reads it off the explorer
    // or their node) — pure state transition, no network.
    if let Some(h) = flag(&args[1..], "--committed-at") {
        let mut st = RegisterState::load(&dir)?.ok_or("no registration in flight")?;
        if st.name != bare {
            return Err(format!("in-flight registration is for {}, not {bare}", st.name).into());
        }
        st.committed_at = Some(h.parse()?);
        st.save(&dir)?;
        println!("recorded commit height {h}; re-run `names register {bare} …` once the window opens (~10 min)");
        return Ok(());
    }

    let st = match RegisterState::load(&dir)? {
        Some(st) if st.name == bare => st,
        Some(st) => return Err(format!("a registration for {} is already in flight", st.name).into()),
        None => {
            let mut wallet = qumbra_wallet::store::WalletDir::open(&dir)?;
            qumbra_wallet::names::prepare_registration(&mut wallet, bare)?
        }
    };

    let scan_to: u64 = flag(&args[1..], "--scan-to")
        .ok_or("names register requires --scan-to HEIGHT")?
        .parse()?;
    match st.step(scan_to) {
        RegisterStep::NeedsCommit => {
            let mut st = st;
            st.commit_attempted = true;
            st.save(&dir)?;
            let op = st.commit_op();
            names_self_send(&args[1..], &op, &format!("commit for {bare} (relay fee only)"))?;
            println!(
                "commit posted. Once mined at height H: `names register {bare} --committed-at H --dir …`"
            );
            Ok(())
        }
        RegisterStep::WaitForWindow { at } => {
            Err(format!("the reveal window opens at height {at} (~10 min after the commit); re-run then").into())
        }
        RegisterStep::RevealNow { closes } => {
            let op = st.reveal_op();
            let fee = qlab_devnet::names::name_fee_for(&op);
            eprintln!("revealing {bare} (window closes at {closes}); name fee {fee} bessel, BURNED");
            names_self_send(&args[1..], &op, &format!("reveal for {bare}"))?;
            RegisterState::clear(&dir)?;
            println!("reveal posted — once mined, {bare}.qmb is yours for 365 epochs. Pin your own fingerprint for your records.");
            Ok(())
        }
        RegisterStep::WindowClosed => {
            RegisterState::clear(&dir)?;
            Err("the reveal window closed unrevealed — the commit is dead and its salt will not \
                 be reused. Start over: `names register` (a fresh salt costs one more relay fee)."
                .into())
        }
    }
}

/// A minimal self-send carrying `op` — the vehicle both registration steps and
/// renewals ride (brief §1: name ops ride the ordinary transaction).
fn names_self_send(
    args: &[String],
    op: &qlab_devnet::names::NameOp,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::spend::{execute, SendRequest, SendStep};
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("requires --url")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let scan_to: u64 = flag(args, "--scan-to").ok_or("requires --scan-to HEIGHT")?.parse()?;
    let no_submit = has_flag(args, "--no-submit");

    // Self-send: the recipient is this wallet's own next address; amount 0 —
    // the whole value moves through change minus fees.
    let w = qumbra_wallet::store::WalletDir::open(&dir)?;
    let self_addr = w.wallet().address_at_index(0);
    let mut sink = |step: SendStep| {
        if let SendStep::Built { fee, prove_secs, .. } = step {
            eprintln!("{label}: proved in {prove_secs:.2}s, declared fee {fee} bessel");
        }
    };
    let req = SendRequest {
        dir: &dir,
        url,
        node_url,
        recipient: &self_addr,
        contact_name: None,
        amount: 0,
        scan_to,
        no_submit,
        name_op: Some(op),
    };
    execute(&req, &mut sink).map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
    Ok(())
}

fn usage() {
    eprintln!(
        "qumbra-wallet — the end-user wallet CLI (issue #243)\n\n\
         USAGE:\n  \
         qumbra-wallet keygen  --dir DIR                 new seed (0600) + address 0; prints NO key material\n  \
         qumbra-wallet restore --dir DIR                 seed from a Qumbra mnemonic on STDIN\n  \
         qumbra-wallet address --dir DIR [--new|--index N]  show or allocate diversified addresses\n  \
                            [--uri] [--amount-qmb DECIMAL] [--label TEXT] [--qr] [--qr-svg FILE]\n\
                            --uri prints a qumbra: payment URI for the selected address (index 0\n\
                            unless --new/--index picked one); --amount-qmb (whole-coin QMB) and\n\
                            --label fold into it; --qr renders it as a terminal QR, --qr-svg\n\
                            writes it as an SVG file. The qs1… fingerprint is always printed\n\
                            beside a URI/QR: a QR that merely scans is NOT a verified address —\n\
                            confirm the fingerprint with the payee out of band\n  \
         qumbra-wallet contact add NAME QADDR --dir DIR  save a full address under a local name\n  \
         qumbra-wallet contact list --dir DIR            show NAME → qs1… (short)\n  \
         qumbra-wallet contact remove NAME --dir DIR     remove a local contact\n  \
         qumbra-wallet backup  --dir DIR --reveal        print the mnemonic (explicitly, once)\n  \
         qumbra-wallet scan    --dir DIR --url URL --to N [--from N]  balance via light-client scan\n  \
         qumbra-wallet names sync --dir DIR --url URL --to HEIGHT   bulk-sync the name registry (D2)\n  \
         qumbra-wallet names resolve NAME --dir DIR --tip HEIGHT    resolve LOCALLY + pin status\n  \
         qumbra-wallet names pin NAME FINGERPRINT --dir DIR         pin an out-of-band-confirmed qs1…\n  \
         qumbra-wallet names register NAME --dir DIR --url URL --node URL --scan-to N\n\
                            resumable commit → reveal (re-run to advance; salt persisted first;\n\
                            record the mined commit with --committed-at H). Name fee is BURNED\n  \
         qumbra-wallet names renew NAME --dir DIR --url URL --node URL --scan-to N  anyone may renew\n  \
         qumbra-wallet history --dir DIR --url URL --to N [--from N]  this wallet's own ledger:\n\
                            every note received, every note spent, and the sends reconstructed\n\
                            from them. Chain-derived throughout; the recipient of a past send is\n\
                            shown only where this wallet dir holds a local `sends.v1` record, and\n\
                            is labeled as such (a restored wallet never has one)\n  \
         qumbra-wallet miner-rkm --dir DIR [--index N]   the miner_rkm for a node config (coinbase payee)\n  \
         qumbra-wallet send --dir DIR --url URL --node URL --scan-to N\n  \
                            (--to ADDR-or-qumbra:URI-or-NAME.qmb | --to-contact NAME) [--amount BESSEL]\n  \
                            --to NAME.qmb resolves LOCALLY against the synced registry (D2)\n\
                            behind the pin gate: first use and any rebind refuse until the\n\
                            fingerprint is confirmed out of band and pinned (`names pin`)\n  \
                            [--out FILE] [--no-submit]\n  \
                            --to also takes a qumbra: payment URI; its amount= prefills the\n\
                            send amount (in that case --amount may be omitted; if both are\n\
                            given and disagree, the send refuses — no silent preference).\n\
                            A URI's label/memo are shown for display only, never transmitted\n  \
                            scan → sync the commitment tree → build + PROVE (real STARK,\n  \
                            ~3 s / ~12 GB) → POST /v1/tx, printing the node's typed outcome\n\n\
         --url  is the compact/scan endpoint (cbserver or a node's discovery server):\n\
                /v1/compact, /v1/block/../full, and /v1/nullifiers (the spent-note\n\
                subtraction — without it no balance is quotable)\n\
         --node is the node's discovery server: /v1/tree/leaves, /v1/anchors, POST /v1/tx\n\
                (defaults to --url when omitted — one host usually serves both)\n\n\
         Both URLs accept http://host:PORT (port required, plaintext) and\n\
         https://host[:port] (TLS, port defaults to 443, roots are the compiled-in\n\
         Mozilla set). There is no fallback from https to http: a TLS failure is\n\
         reported, never downgraded.\n\n\
         Nothing here runs a node: every endpoint above is somebody else's.\n"
    );
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}


fn dir_of(args: &[String]) -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(flag(args, "--dir").ok_or("--dir DIR is required")?))
}

fn keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    use rand::Rng;
    let dir = dir_of(args)?;
    // The OS CSPRNG directly; a failure is fatal — a seed from a degraded
    // source is a key somebody else can derive (the faucet's rule, kept).
    let mut entropy = [0u8; ENTROPY_LEN];
    rand::rng().fill_bytes(&mut entropy);
    let w = WalletDir::create(&dir, MasterSeed::from_entropy(entropy))?;
    let addr = w.wallet().address_at_index(0);
    println!("qumbra-wallet keygen");
    println!("  seed:    {} (0600 — NEVER printed; back it up with `backup --reveal`)", dir.join(qumbra_wallet::store::SEED_FILE).display());
    println!("  address [0]:");
    println!("    {}", addr.encode());
    println!("    short: {}", addr.short().encode());
    Ok(())
}

fn restore(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    eprintln!("paste the Qumbra mnemonic, then EOF (Ctrl-D):");
    // Stdin, never argv: argv is visible to `ps` and shell history.
    let seed = seed_from_phrase(&mut std::io::stdin().lock())?;
    let w = WalletDir::create(&dir, seed)?;
    let addr = w.wallet().address_at_index(0);
    println!("restored. address [0]: {}", addr.encode());
    println!(
        "note: only index 0 is re-allocated; if you had more addresses, re-allocate with \
         `address --new` — funds are index-derived and unaffected."
    );
    Ok(())
}

fn address(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    let mut w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    // Any payment-request flag puts the command in URI mode (lab #342); the
    // render flags imply --uri because the QR IS the URI.
    let amount_qmb = flag(args, "--amount-qmb");
    let label = flag(args, "--label");
    let qr = has_flag(args, "--qr");
    let qr_svg = flag(args, "--qr-svg");
    let uri_mode =
        has_flag(args, "--uri") || qr || qr_svg.is_some() || amount_qmb.is_some() || label.is_some();

    // A payment request is for exactly one address: --new/--index pick it,
    // otherwise URI mode falls back to the wallet's canonical index 0.
    let picked = if has_flag(args, "--new") {
        Some(w.allocate_next()?)
    } else if let Some(n) = flag(args, "--index") {
        Some(n.parse::<u64>()?)
    } else if uri_mode {
        Some(0)
    } else {
        None
    };

    let Some(idx) = picked else {
        for idx in &w.allocated {
            println!("[{idx}] {}", wallet.address_at_index(*idx).encode());
        }
        return Ok(());
    };

    let addr = wallet.address_at_index(idx);
    let known = if w.allocated.contains(&idx) { "" } else { " (NOT in this wallet's allocated set — valid, but scans here won't cover it until allocated)" };
    println!("address [{idx}]{known}:");
    println!("  {}", addr.encode());
    println!("  short: {}", addr.short().encode());

    if !uri_mode {
        return Ok(());
    }

    let amount_bessel = match amount_qmb {
        Some(s) => Some(
            qlab_wallet::uri::qmb_to_bessel(s)
                .map_err(|why| format!("--amount-qmb `{s}`: {why}"))?,
        ),
        None => None,
    };
    let uri = qlab_wallet::uri::encode(&addr, amount_bessel, label, None);
    let fp = addr.short().encode();
    // The fingerprint travels beside EVERY URI/QR display (contact list's
    // discipline, name-service D3): a QR that merely scans is the phishing
    // surface — only the qs1… confirmed out of band makes it a verified one.
    println!("payment URI [fingerprint {fp}]:");
    println!("  {uri}");
    if qr {
        let rendered = qumbra_wallet::qr::render_unicode(&uri)?;
        println!("QR of the URI above [fingerprint {fp}] — confirm the fingerprint with the payer's screen, not the scan:");
        print!("{rendered}");
    }
    if let Some(file) = qr_svg {
        let svg = qumbra_wallet::qr::render_svg(&uri)?;
        std::fs::write(file, svg)?;
        println!("QR SVG → {file} [fingerprint {fp}]");
    }
    Ok(())
}

fn contact(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::contacts::ContactBook;

    let dir = dir_of(args)?;
    // A contact book belongs to a wallet dir, not merely an arbitrary path.
    WalletDir::open(&dir)?;
    match args.first().map(String::as_str) {
        Some("add") => {
            let name = args.get(1).ok_or("contact add requires NAME")?;
            let address = args.get(2).ok_or("contact add requires a full qaddr1… ADDRESS")?;
            let saved = ContactBook::add(&dir, name, address)?;
            println!("{} → {} (short)", saved.name, saved.short());
            println!(
                "confirm this fingerprint with the payee out of band — a saved name is not a \
                 verified one"
            );
            Ok(())
        }
        Some("list") => {
            for saved in ContactBook::load(&dir)?.entries() {
                println!("{} → {} (short)", saved.name, saved.short());
            }
            Ok(())
        }
        Some("remove") => {
            let name = args.get(1).ok_or("contact remove requires NAME")?;
            ContactBook::remove(&dir, name)?;
            println!("removed contact `{name}`");
            Ok(())
        }
        Some(other) => {
            Err(format!("unknown contact command `{other}` (use add, list, or remove)").into())
        }
        None => Err("contact requires add, list, or remove".into()),
    }
}

/// The `miner_rkm` a node config needs so its coinbase pays THIS wallet
/// (issue #246 join-docs gap): `hex(lane-major-LE(digest(rkm)))`, byte-for-byte
/// the form `NodeConfig::miner_rkm_lanes` parses and the faucet's keygen
/// prints. Position: derived at an ALLOCATED index's diversifier (default 0) —
/// the identity this wallet already displays — not the faucet's fixed default
/// diversifier, which is that binary's own convention.
fn miner_rkm(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    let w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    let idx: u64 = flag(args, "--index").unwrap_or("0").parse()?;
    if !w.allocated.contains(&idx) {
        eprintln!(
            "note: index {idx} is not in this wallet's allocated set — the rkm is valid, but \
             allocate it (`address --new`) so scans cover the coinbase identity."
        );
    }
    let d = wallet.diversifier_at_index(idx);
    let bytes = qlab_note::hash::digest_bytes(&wallet.rkm(d));
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("Put this in the NODE's config so it pays this wallet what it mines:");
    println!("  miner_rkm = \"{hex}\"");
    // Deliberately no copied number: the maturity constant lives in
    // qlab_node::COINBASE_MATURITY_BLOCKS (frozen §2), and a second copy here
    // is a WRONG-IN-THE-DETAIL waiting to happen.
    println!(
        "(coinbase paid to it belongs to address [{idx}]; it matures per frozen §2 — \
         COINBASE_MATURITY_BLOCKS in qlab-node — before it is spendable)"
    );
    Ok(())
}

/// The whole send path, wired (issue #276): scan → sync the local commitment
/// tree → select a finalized anchor → build + PROVE → `POST /v1/tx`, printing
/// the node's typed outcome verbatim.
///
/// Refuses on partial scan coverage — spending on incomplete knowledge risks
/// double-claimed nullifiers (#244's discipline, untouched).
fn send(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::spend::{execute, SendError, SendRequest, SendStep};

    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("send requires --url (compact/scan endpoint)")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let scan_to: u64 = flag(args, "--scan-to").ok_or("send requires --scan-to HEIGHT")?.parse()?;
    let to = flag(args, "--to");
    let to_contact = flag(args, "--to-contact");
    let amount_flag: Option<u64> =
        flag(args, "--amount").map(|a| a.parse::<u64>()).transpose()?;
    let out = flag(args, "--out");
    let no_submit = has_flag(args, "--no-submit");

    // Filled only when --to is a qumbra: payment URI (lab #342).
    let mut uri_amount: Option<u64> = None;
    let (recipient, contact_name) = match (to, to_contact) {
        (Some(_), Some(_)) => {
            return Err("send requires exactly one of --to ADDRESS or --to-contact NAME; both were provided".into())
        }
        (None, None) => {
            return Err("send requires exactly one of --to ADDRESS or --to-contact NAME".into())
        }
        // Lab #367: `NAME.qmb` resolves LOCALLY against the synced registry
        // (D2 — no server is ever asked about one name) behind the N6 pin
        // gate: first use and any rebind REFUSE until the fingerprint is
        // confirmed out of band and pinned via `names pin`.
        (Some(target), None) if target.ends_with(".qmb") => {
            let reg = qumbra_wallet::names::WalletRegistry::load(&dir)?
                .ok_or("no synced name registry — run `qumbra-wallet names sync` first")?;
            let entry = match reg.resolve(target, scan_to) {
                qumbra_wallet::names::Resolution::Active(e) => e,
                qumbra_wallet::names::Resolution::Expiring { entry, reopens_at } => {
                    eprintln!(
                        "⚠ {target} is past expiry, inside its grace window (re-registrable at \
                         height {reopens_at}) — its holder should renew"
                    );
                    entry
                }
                qumbra_wallet::names::Resolution::Unknown => {
                    return Err(format!(
                        "{target} is not registered as of height {scan_to} (registry synced to \
                         {}). If it was registered recently, `names sync` further.",
                        reg.synced_to
                    )
                    .into())
                }
            };
            let pins = qumbra_wallet::names::Pins::load(&dir)?;
            match pins.check(target, &entry.address) {
                qumbra_wallet::names::PinVerdict::Match => {}
                qumbra_wallet::names::PinVerdict::FirstUse { fingerprint } => {
                    return Err(format!(
                        "first payment to {target}: verify the fingerprint {fingerprint} with \
                         the payee OUT OF BAND (a name that resolves is not a name that is \
                         verified — D3), then pin it:\n  qumbra-wallet names pin {target} \
                         {fingerprint} --dir …\nand re-run this send."
                    )
                    .into())
                }
                qumbra_wallet::names::PinVerdict::Rebind { pinned, resolved } => {
                    return Err(format!(
                        "🔴 REBIND ALARM: {target} now resolves to {resolved}, but you confirmed \
                         {pinned}. This is either the name lapsing and being re-registered \
                         (possibly by someone else!) or a records divergence. Do NOT pay until \
                         you re-confirm the NEW fingerprint out of band; then: qumbra-wallet \
                         names pin {target} {resolved} --dir …"
                    )
                    .into())
                }
            }
            let address = qlab_wallet::address::Address::from_raw_bytes(&entry.address)
                .ok_or("registry entry does not decode as an address — re-sync the registry")?;
            eprintln!(
                "{target} → {} (pinned ✓; registered at {}, expires {})",
                address.short().encode(),
                entry.registered,
                entry.expiry
            );
            (address, Some(target.to_string()))
        }
        // A bech32m address never contains `:`, so a colon means a URI — and
        // routing it through the URI parser gives a scheme-shaped mistake
        // (`bitcoin:…`) a typed refusal instead of "not a valid qaddr1…".
        (Some(target), None) if target.contains(':') => {
            let req = qlab_wallet::uri::parse(target)?;
            eprintln!(
                "URI → {} — verify this fingerprint with the payee out of band; a URI that \
                 merely parses is not a verified address",
                req.address.short().encode()
            );
            // label/memo are DISPLAY ONLY: there is no memo on the wire from
            // this wallet, and this send transmits neither (wallet-interop §1
            // + the lab #342 ruling — no invented transmit path).
            if let Some(l) = &req.label {
                eprintln!("URI label (display only, NOT transmitted): {l}");
            }
            if let Some(m) = &req.memo {
                eprintln!(
                    "URI memo (display only, NOT transmitted; {} bytes): {}",
                    m.len(),
                    String::from_utf8_lossy(m)
                );
            }
            uri_amount = req.amount_bessel;
            (req.address, None)
        }
        (Some(address), None) => (
            qlab_wallet::address::Address::decode(address)
                .ok_or("`--to` is not a valid qaddr1… address or qumbra: URI")?,
            None,
        ),
        (None, Some(name)) => (
            qumbra_wallet::contacts::ContactBook::load(&dir)?.resolve(name)?,
            Some(name.to_string()),
        ),
    };
    let amount = resolve_send_amount(uri_amount, amount_flag)?;

    // The sink. Progress belongs on stderr so a piped stdout stays the result;
    // the flow itself is `qumbra_wallet::spend`, shared with every other surface.
    let mut sink = |step: SendStep| match step {
        SendStep::Resolved { recipient_short, contact } => {
            if let Some(name) = contact {
                eprintln!("→ {name} ({recipient_short})");
            }
        }
        SendStep::Selected { skipped_spent, .. } if skipped_spent > 0 => eprintln!(
            "note: {skipped_spent} already-spent note(s) skipped by input selection (their \
             nullifiers are on the chain)"
        ),
        SendStep::Selected { .. } => {}
        SendStep::Tree {
            held, fetched, anchor_count, anchor_root, node_tip, finalized, anchor_behind,
        } => {
            eprintln!(
                "tree: {held} leaves held ({fetched} new); anchor at {anchor_count} leaves, root \
                 {anchor_root} (node tip {node_tip}, finalized {})",
                finalized.map(|h| h.to_string()).unwrap_or_else(|| "none".into())
            );
            if anchor_behind > 0 {
                eprintln!(
                    "  (the anchor is {anchor_behind} leaves behind what this node served — a \
                     witness must be built against a FINALIZED root, so this is normal, not a lag)"
                );
            }
        }
        SendStep::Proving => eprintln!("proving (real STARK — this takes seconds and gigabytes)…"),
        SendStep::Built { amount, fee, change, prove_secs, used_dummy } => println!(
            "built: {amount} bessel, fee {fee}, change {change} — proved in {prove_secs:.2} s{}",
            if used_dummy { " (single real note + dummy slot)" } else { "" }
        ),
        SendStep::Recorded => eprintln!(
            "note: the recipient was recorded locally in {} (0600). It is NOT on the chain and a \
             restore from your mnemonic will not bring it back.",
            qumbra_wallet::sends::SENDS_FILE
        ),
        SendStep::Warning(w) => eprintln!("warning: {w}"),
        SendStep::Submitting => {}
        SendStep::Answered { status, body } => println!("node [{status}]: {body}"),
    };

    let req = SendRequest {
        dir: &dir,
        url,
        node_url,
        recipient: &recipient,
        contact_name: contact_name.as_deref(),
        amount,
        scan_to,
        no_submit,
        name_op: None,
    };

    // A proof that cost gigabytes should not be lost to a failed socket — so the
    // bytes are written on EVERY path that has them, success or not.
    let keep = |bytes: &[u8]| -> Result<(), Box<dyn Error>> {
        if let Some(path) = out {
            std::fs::write(path, bytes)?;
            println!("wire: {} bytes → {path}", bytes.len());
        }
        Ok(())
    };

    match execute(&req, &mut sink) {
        Ok(o) => {
            keep(&o.wire_bytes)?;
            if o.answer.is_none() {
                println!("not submitted (--no-submit).");
                if out.is_none() {
                    eprintln!(
                        "warning: --no-submit without --out discarded this proof — nothing was \
                         written and nothing was sent."
                    );
                }
                eprintln!(
                    "note: no {} record was written — this send was not submitted, and the local \
                     record exists to name the recipient of a send that is actually on its way.",
                    qumbra_wallet::sends::SENDS_FILE
                );
            }
            Ok(())
        }
        Err(SendError::Refused(why)) => Err(why.into()),
        Err(SendError::Incomplete { why, wire_bytes }) => {
            keep(&wire_bytes)?;
            Err(format!(
                "{why}{}",
                match out {
                    Some(p) => format!(" They are saved at {p}."),
                    None => " Re-run with --out FILE to keep them next time.".to_string(),
                }
            )
            .into())
        }
        Err(SendError::Answered { class, body, wire_bytes, .. }) => {
            keep(&wire_bytes)?;
            use qumbra_wallet::net::SubmitClass;
            Err(match class {
                SubmitClass::Unavailable => format!(
                    "the node did not judge this transaction — that is its state, not your \
                     transaction's. Retry{}; the transaction itself is unchanged.",
                    match out {
                        Some(p) => format!(" with the saved bytes at {p}"),
                        None => String::new(),
                    }
                ),
                _ => format!("the node refused this transaction: {body}"),
            }
            .into())
        }
    }
}

fn backup(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    let w = WalletDir::open(&dir)?;
    if !has_flag(args, "--reveal") {
        return Err("backup prints your mnemonic — key material. Re-run with --reveal, on a \
                    screen nobody is watching and a terminal that does not log."
            .into());
    }
    eprintln!("⚠️  THIS PHRASE IS YOUR WALLET. Anyone who reads it can spend everything.");
    println!("{}", reveal_mnemonic(&w));
    Ok(())
}


/// `history` — this wallet's own chronological ledger (the wallet-side
/// transaction view). Same two streams as `scan`, same honesty vocabulary; what
/// is new is that the events are named rather than summed, and that the one
/// field the chain can never carry — **who a send paid** — is joined in from the
/// wallet dir's local `sends.v1` when there is one, and labeled every time.
fn history(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    let url = flag(args, "--url")
        .ok_or("history requires --url http://host:port or --url https://host[:port]")?;
    let to: u64 = flag(args, "--to")
        .ok_or("history requires --to HEIGHT (explicit: a ledger is a claim about a range)")?
        .parse()?;
    let from: u64 = flag(args, "--from").unwrap_or("0").parse()?;

    let w = WalletDir::open(&dir)?;
    let report = qumbra_wallet::history::report(&dir, &w, url, from, to);
    // stderr, so a piped ledger stays a ledger — but never dropped: each note
    // names a reason a `recipient:` line below reads `not recorded`.
    for note in &report.notes {
        eprintln!("note: {note}");
    }
    print!("{}", report.text);
    Ok(())
}

/// `scan` — the balance report, and since lab issue #314 it is a **two-stream**
/// report: the outputs off `/v1/compact`, then this wallet's own spends
/// subtracted against `/v1/nullifiers`.
///
/// The nullifier stream is fetched **after** every scan, deliberately: the chain
/// only grows, so a node that advanced mid-scan gives the second fetch MORE
/// coverage than the outputs need, never less. Fetching it first would turn an
/// ordinary block arrival into a spurious `UNAVAILABLE`.
fn scan(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    let url = flag(args, "--url")
        .ok_or("scan requires --url http://host:port or --url https://host[:port]")?;
    let to: u64 = flag(args, "--to")
        .ok_or("scan requires --to HEIGHT (explicit: a balance is a claim about a range)")?
        .parse()?;
    let from: u64 = flag(args, "--from").unwrap_or("0").parse()?;

    let w = WalletDir::open(&dir)?;
    let (scans, coverage) = qumbra_wallet::scan::scan_report(&w, url, from, to);
    print!("{}", view::render(&scans, (from, to), url, &coverage));
    Ok(())
}

/// The amount a send actually uses, from the URI's `amount=` and/or `--amount`
/// (both bessel). A disagreement is a hard error — silently preferring either
/// one is exactly the confusion the URI amount exists to prevent (lab #342).
fn resolve_send_amount(
    uri_bessel: Option<u64>,
    flag_bessel: Option<u64>,
) -> Result<u64, String> {
    use qlab_wallet::uri::bessel_to_qmb;
    match (uri_bessel, flag_bessel) {
        (Some(u), Some(f)) if u != f => Err(format!(
            "the URI requests {u} bessel ({} QMB) but --amount says {f} bessel ({} QMB) — \
             refusing to choose; drop --amount to honor the URI, or drop the URI amount",
            bessel_to_qmb(u),
            bessel_to_qmb(f),
        )),
        (Some(u), _) => Ok(u),
        (None, Some(f)) => Ok(f),
        (None, None) => {
            Err("send requires --amount BESSEL (or a qumbra: URI carrying amount=)".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_send_amount;

    #[test]
    fn send_amount_resolution() {
        // URI prefills; an explicit flag alone works; agreement is fine.
        assert_eq!(resolve_send_amount(Some(150_000_000), None), Ok(150_000_000));
        assert_eq!(resolve_send_amount(None, Some(42)), Ok(42));
        assert_eq!(resolve_send_amount(Some(42), Some(42)), Ok(42));
        // No amount from anywhere is a refusal.
        assert!(resolve_send_amount(None, None).is_err());
        // Disagreement is a HARD error naming both values, not a preference.
        let err = resolve_send_amount(Some(150_000_000), Some(42)).unwrap_err();
        assert!(err.contains("150000000") && err.contains("42"), "{err}");
        assert!(err.contains("1.5") && err.contains("0.00000042"), "both in QMB: {err}");
    }
}
