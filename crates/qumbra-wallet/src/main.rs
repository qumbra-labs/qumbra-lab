//! `qumbra-wallet` — CLI glue only; the testable logic is in the library
//! (`store`, `view`), the same posture as every other binary here.

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_wallet::store::{seed_from_phrase, reveal_mnemonic, WalletDir};
use qumbra_wallet::view::{self, DivScan};

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
        Some("backup") => backup(&args[1..]),
        Some("scan") => scan(&args[1..]),
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
         qumbra-wallet backup  --dir DIR --reveal        print the mnemonic (explicitly, once)\n  \
         qumbra-wallet scan    --dir DIR --url URL --to N [--from N]  balance via light-client scan\n  \
         qumbra-wallet miner-rkm --dir DIR [--index N]   the miner_rkm for a node config (coinbase payee)\n  \
         qumbra-wallet send --dir DIR --url URL --scan-to N --to ADDR --amount BESSEL --out FILE\n  \
                            build + PROVE a spend (real STARK, ~2 s / ~12 GB); writes wire bytes,\n  \
                            does NOT submit (no public submission surface exists — by decision)\n\n\
         There is deliberately no `send` yet: it is gated on the dummy-input mechanism\n\
         (lab #219) and the T1 mint. Nothing here runs a node.\n"
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

/// Written, not accepted (the mint is its acceptance): scan → select → prove →
/// encrypt → write the canonical wire bytes. Refuses on partial scan coverage
/// — spending on incomplete knowledge risks double-claimed nullifiers.
fn send(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig};
    use qumbra_wallet::send::{os_rng, Spendable};

    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("send requires --url (cbserver)")?;
    let scan_to: u64 = flag(args, "--scan-to").ok_or("send requires --scan-to HEIGHT")?.parse()?;
    let to = flag(args, "--to").ok_or("send requires --to ADDRESS")?;
    let amount: u64 = flag(args, "--amount").ok_or("send requires --amount BESSEL")?.parse()?;
    let out = flag(args, "--out").ok_or("send requires --out FILE")?;

    let recipient = qlab_wallet::address::Address::decode(to)
        .ok_or("`--to` is not a valid qaddr1… address")?;

    let w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    let mut rng = os_rng();

    // Gather spendables — and REFUSE on any non-Complete verdict: a spend
    // built on partial knowledge can double-claim a nullifier.
    let mut spendables: Vec<Spendable> = Vec::new();
    for &idx in &w.allocated {
        let d = wallet.diversifier_at_index(idx);
        let kp = wallet.diversified_keypair(&d);
        let outcome = light_client_scan(url, &kp.dk, 0, scan_to, ScanConfig::default(), &mut rng)
            .map_err(|e| format!("scan never started for index {idx}: {e}"))?;
        match outcome.completeness() {
            Completeness::Complete | Completeness::Shadowed { .. } => {}
            other => {
                return Err(format!(
                    "index {idx} scanned {other:?} — refusing to build a spend on partial                      knowledge (a double-claimed nullifier could be among the unread outputs)"
                )
                .into())
            }
        }
        for ln in &outcome.notes {
            spendables.push(Spendable {
                div_index: idx,
                value: ln.detected.note.value,
                rho: ln.detected.note.rho,
                rseed: ln.detected.note.rseed,
            });
        }
    }

    // 🔴 The tree. A light client cannot yet RECONSTRUCT the commitment tree
    // from the compact stream on a real chain (coinbase leaves append at
    // maturity and are not compact entries) — the named gap this subcommand
    // carries until a tree-sync surface exists. Acceptance rides the mint.
    return Err(format!(
        "send is WRITTEN but cannot complete against a remote endpoint yet: the commitment          tree (witness source) is not reconstructible from the compact stream — coinbase          leaves are not compact entries. {} spendable note(s) were found and the prover path          is real (see `send::build_send` and its test); the tree-sync surface is the named          open piece, tracked with the submission seam. Nothing was written to {out}.",
        spendables.len()
    )
    .into())
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

fn scan(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qlab_cbserver::client::{light_client_scan, ScanConfig};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("scan requires --url http://host:port")?;
    let to: u64 = flag(args, "--to")
        .ok_or("scan requires --to HEIGHT (explicit: a balance is a claim about a range)")?
        .parse()?;
    let from: u64 = flag(args, "--from").unwrap_or("0").parse()?;

    let w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    // Seed the decoy rng from the OS CSPRNG (StdRng has no direct from-OS
    // constructor at this rand pin; the 32-byte seed carries the entropy).
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    let mut rng = StdRng::from_seed(seed_bytes);
    let mut scans = Vec::new();
    for &idx in &w.allocated {
        let d = wallet.diversifier_at_index(idx);
        let kp = wallet.diversified_keypair(&d);
        let short = wallet.address_at_index(idx).short().encode();
        // `Err` here means the scan NEVER STARTED for this key (compact fetch or
        // decode failed) — render the named cannot-know verdict rather than
        // aborting the whole report or, worse, printing a zero.
        match light_client_scan(url, &kp.dk, from, to, ScanConfig::default(), &mut rng) {
            Ok(outcome) => scans.push(DivScan::from_outcome(idx, short, &outcome)),
            Err(e) => scans.push(DivScan {
                index: idx,
                address_short: short,
                completeness: qlab_cbserver::client::Completeness::Complete,
                spendable_bessel: 0,
                shadowed_bessel: 0,
                never_started: Some(e.to_string()),
            }),
        }
    }
    print!("{}", view::render(&scans, (from, to), url));
    Ok(())
}
