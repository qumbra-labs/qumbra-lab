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
        "qumbra-wallet — the end-user wallet CLI (issue #243)\n\n\
         USAGE:\n  \
         qumbra-wallet keygen  --dir DIR                 new seed (0600) + address 0; prints NO key material\n  \
         qumbra-wallet restore --dir DIR                 seed from a Qumbra mnemonic on STDIN\n  \
         qumbra-wallet address --dir DIR [--new|--index N]  show or allocate diversified addresses\n  \
         qumbra-wallet contact add NAME QADDR --dir DIR  save a full address under a local name\n  \
         qumbra-wallet contact list --dir DIR            show NAME → qs1… (short)\n  \
         qumbra-wallet contact remove NAME --dir DIR     remove a local contact\n  \
         qumbra-wallet backup  --dir DIR --reveal        print the mnemonic (explicitly, once)\n  \
         qumbra-wallet scan    --dir DIR --url URL --to N [--from N]  balance via light-client scan\n  \
         qumbra-wallet history --dir DIR --url URL --to N [--from N]  this wallet's own ledger:\n\
                            every note received, every note spent, and the sends reconstructed\n\
                            from them. Chain-derived throughout; the recipient of a past send is\n\
                            shown only where this wallet dir holds a local `sends.v1` record, and\n\
                            is labeled as such (a restored wallet never has one)\n  \
         qumbra-wallet miner-rkm --dir DIR [--index N]   the miner_rkm for a node config (coinbase payee)\n  \
         qumbra-wallet send --dir DIR --url URL --node URL --scan-to N\n  \
                            (--to ADDR | --to-contact NAME) --amount BESSEL\n  \
                            [--out FILE] [--no-submit]\n  \
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
    if has_flag(args, "--new") {
        let idx = w.allocate_next()?;
        let addr = wallet.address_at_index(idx);
        println!("address [{idx}]:");
        println!("  {}", addr.encode());
        println!("  short: {}", addr.short().encode());
    } else if let Some(n) = flag(args, "--index") {
        let idx: u64 = n.parse()?;
        let addr = wallet.address_at_index(idx);
        let known = if w.allocated.contains(&idx) { "" } else { " (NOT in this wallet's allocated set — valid, but scans here won't cover it until allocated)" };
        println!("address [{idx}]{known}:");
        println!("  {}", addr.encode());
    } else {
        for idx in &w.allocated {
            println!("[{idx}] {}", wallet.address_at_index(*idx).encode());
        }
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
    let amount: u64 = flag(args, "--amount").ok_or("send requires --amount BESSEL")?.parse()?;
    let out = flag(args, "--out");
    let no_submit = has_flag(args, "--no-submit");

    let (recipient, contact_name) = match (to, to_contact) {
        (Some(_), Some(_)) => {
            return Err("send requires exactly one of --to ADDRESS or --to-contact NAME; both were provided".into())
        }
        (None, None) => {
            return Err("send requires exactly one of --to ADDRESS or --to-contact NAME".into())
        }
        (Some(address), None) => (
            qlab_wallet::address::Address::decode(address)
                .ok_or("`--to` is not a valid qaddr1… address")?,
            None,
        ),
        (None, Some(name)) => (
            qumbra_wallet::contacts::ContactBook::load(&dir)?.resolve(name)?,
            Some(name.to_string()),
        ),
    };

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
