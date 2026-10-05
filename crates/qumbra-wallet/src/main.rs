//! `qumbra-wallet` — CLI glue only; the testable logic is in the library
//! (`store`, `view`), the same posture as every other binary here.

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

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
        Some("deposit") => deposit(&args[1..]),
        Some("exit") => exit_v6_cmd(&args[1..]),
        Some("names") => names(&args[1..]),
        Some("issuer") => issuer(&args[1..]),
        Some("ivk") => ivk(&args[1..]),
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
    names_register_with(
        args,
        names_observe_reveal,
        names_self_send_preserving,
        names_repost_wire,
    )
}

fn names_register_with<Observe, Send, Repost>(
    args: &[String],
    mut observe: Observe,
    mut send: Send,
    mut repost: Repost,
) -> Result<(), Box<dyn Error>>
where
    Observe: FnMut(
        &[String],
        &qumbra_wallet::names::RegisterState,
        u64,
    ) -> Result<Option<u64>, Box<dyn Error>>,
    Send: FnMut(
        &[String],
        &qlab_devnet::names::NameOp,
        &str,
        &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), Box<dyn Error>>,
    Repost: FnMut(&[String], &[u8], &str) -> Result<(), Box<dyn Error>>,
{
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

    let mut st = match RegisterState::load(&dir)? {
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
    if st.reveal_tx.is_some() && st.revealed_at.is_none() {
        if let Some(at) = observe(&args[1..], &st, scan_to)? {
            st.revealed_at = Some(at);
            st.save(&dir)?;
        }
    }
    match st.step(scan_to) {
        RegisterStep::NeedsCommit => {
            st.commit_attempted = true;
            st.save(&dir)?;
            let op = st.commit_op();
            send(
                &args[1..],
                &op,
                &format!("commit for {bare} (relay fee only)"),
                &mut |_| Ok(()),
            )?;
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
            if let Some(wire) = st.reveal_tx.as_deref() {
                eprintln!(
                    "re-posting the saved reveal for {bare} byte-identically (window closes at \
                     {closes}); name fee {fee} bessel, BURNED"
                );
                repost(&args[1..], wire, &format!("reveal for {bare}"))?;
            } else {
                eprintln!(
                    "revealing {bare} (window closes at {closes}); name fee {fee} bessel, BURNED"
                );
                let mut preserve = |wire: &[u8]| {
                    st.reveal_tx = Some(wire.to_vec());
                    st.save(&dir).map_err(|e| e.to_string())
                };
                send(
                    &args[1..],
                    &op,
                    &format!("reveal for {bare}"),
                    &mut preserve,
                )?;
            }
            if has_flag(&args[1..], "--no-submit") {
                println!(
                    "reveal prepared but NOT submitted — exact retry bytes and salt retained. \
                     Re-run without --no-submit before height {closes}."
                );
            } else {
                println!(
                    "reveal posted, not yet confirmed — retry bytes and salt retained until chain \
                     inclusion or height {closes}. Re-run `names register {bare} …` to check and \
                     re-post the exact transaction."
                );
            }
            Ok(())
        }
        RegisterStep::RevealConfirmed { at } => {
            RegisterState::clear(&dir)?;
            println!(
                "reveal confirmed at height {at} — {bare}.qmb is yours for 365 epochs; \
                 registration retry state cleared. Pin your own fingerprint for your records."
            );
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

/// Sync the chain's committed name riders and identify this exact record only
/// when it landed inside this commit's reveal window.
fn names_observe_reveal(
    args: &[String],
    state: &qumbra_wallet::names::RegisterState,
    scan_to: u64,
) -> Result<Option<u64>, Box<dyn Error>> {
    use qumbra_wallet::names::{sync_names, WalletRegistry};
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("names register requires --url")?;
    let mut registry = WalletRegistry::load(&dir)?.unwrap_or_default();
    sync_names(&mut registry, scan_to, |path| {
        qumbra_wallet::net::http_get(url, path).map_err(|e| e.to_string())
    })
    .map_err(|e| -> Box<dyn Error> { e.into() })?;
    registry.save(&dir)?;
    Ok(registry.observed_reveal_height(state))
}

/// A minimal self-send carrying `op` — the vehicle both registration steps and
/// renewals ride (brief §1: name ops ride the ordinary transaction).
fn names_self_send(
    args: &[String],
    op: &qlab_devnet::names::NameOp,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    names_self_send_wire(args, op, label).map(|_| ())
}

fn names_self_send_preserving(
    args: &[String],
    op: &qlab_devnet::names::NameOp,
    label: &str,
    before_submit: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), Box<dyn Error>> {
    names_self_send_wire_before(args, op, label, before_submit).map(|_| ())
}

fn names_self_send_wire(
    args: &[String],
    op: &qlab_devnet::names::NameOp,
    label: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    names_self_send_wire_before(args, op, label, &mut |_| Ok(()))
}

fn names_self_send_wire_before(
    args: &[String],
    op: &qlab_devnet::names::NameOp,
    label: &str,
    before_submit: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use qumbra_wallet::spend::{execute_with_pre_submit, SendRequest, SendStep};
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
        form: genesis_form_of(args)?,
    };
    let outcome = execute_with_pre_submit(&req, &mut sink, before_submit)
        .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
    Ok(outcome.wire_bytes)
}

/// Retry the exact canonical bytes retained before the first reveal POST. No
/// proving or wallet reconstruction is reachable on this path.
fn names_repost_wire(
    args: &[String],
    wire: &[u8],
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::net::SubmitClass;
    use qumbra_wallet::spend::submit;
    if has_flag(args, "--no-submit") {
        eprintln!("not submitted (--no-submit); the saved reveal transaction remains retryable");
        return Ok(());
    }
    let url = flag(args, "--url").ok_or("requires --url")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let answer = submit(node_url, wire, &mut |_| {})
        .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
    match answer.class() {
        SubmitClass::Accepted | SubmitClass::Duplicate => Ok(()),
        _ => Err(answer.body.into()),
    }
}

fn usage() {
    // The build-provenance line (lab #437) sits in the header rather than behind a
    // `--version` subcommand: a downloaded tarball carries no OCI label, and the
    // first thing a stranger runs on an unfamiliar binary is `--help`.
    eprintln!("build rev: {}", qumbra_wallet::build_rev_line());
    // Beside the build rev, and for the same reason it is there: so the artifact
    // can be ASKED rather than assumed. The release gate greps this line back out
    // of the built binary — a stamp nothing reads back is a stamp that can
    // silently fail to apply, which is precisely how #581 shipped (lab #581).
    eprintln!(
        "built for net: {}",
        BUILT_FOR_NET.unwrap_or("unstamped — --net decides, defaulting to t1")
    );
    eprintln!(
        "qumbra-wallet — the end-user wallet CLI (issue #243)\n\n\
         USAGE:\n  \
         qumbra-wallet keygen  --dir DIR                 new seed + address 0; prints NO key material\n  \
                            (the seed file's actual protection is printed by `keygen` — it is\n  \
                            0600 on unix and an inherited ACL on Windows, lab #478)\n  \
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
                            record the mined commit with --committed-at H; an unconfirmed reveal\n\
                            re-posts its saved exact bytes and clears only when chain-observed).\n\
                            Name fee is BURNED\n  \
         qumbra-wallet names renew NAME --dir DIR --url URL --node URL --scan-to N  anyone may renew\n  \
         qumbra-wallet history --dir DIR --url URL --to N [--from N]  this wallet's own ledger:\n\
                            every note received, every note spent, and the sends reconstructed\n\
                            from them. Chain-derived throughout; the recipient of a past send is\n\
                            shown only where this wallet dir holds a local `sends.v1` record, and\n\
                            is labeled as such (a restored wallet never has one). With\n\
                            --net annulet: per asset, each block this wallet spent in read as\n\
                            the net of what left and what came back (lab #831) — never a\n\
                            recipient, never an amount and a fee told apart\n  \
         qumbra-wallet deposit --dir DIR --url URL [--node URL] --scan-to N --net t2\n\
                            --l2-id N --genesis-hash HEX64 --amount BESSEL [--out FILE] [--no-submit]\n\
                            an L1 → L2 deposit (lab #831): the L1 burn to the L2's burn address,\n\
                            sealed to THIS wallet so it can be claimed and recovered. Refused unless\n\
                            the node's /v1/l2 confirms both --l2-id and --genesis-hash; `scan` then\n\
                            shows it as a pending deposit, never as balance. `send` never burns\n  \
         qumbra-wallet deposit claim --dir DIR --url URL [--node URL] --scan-to N --net t2\n\
                            --l2-id N --genesis-hash HEX64 [--deposit K] [--anchor-count N]\n\
                            (--out FILE | --plan-only)\n\
                            prove the claim of a pending deposit (about 3.17 GiB, local only) and\n\
                            write it for the sequencer — the file reveals the deposit amount. The\n\
                            claim opens at the newest valid anchor unless --anchor-count picks\n\
                            another served root; it is taken once a wrapper absorbs that root\n  \
         qumbra-wallet exit --net v6 --dir DIR --url URL [--node URL] --scan-to N --l2-id N --genesis-hash HEX64\n\
                            --exit-to ADDR [--amount V] (--out FILE | --plan-only) [--submit --intake IP:PORT]\n\
                            exit one claim credit WHOLE from the V6 L2 to an L1 address (the P lane, about\n\
                            30 GiB, local only), anchored to the last landed bundle after checking the\n\
                            node's L2 index against that bundle's own stated roots; --submit hands the\n\
                            file to the sequencer's intake, which HOLDS exits until it plans them (R3b)\n  \
         qumbra-wallet miner-rkm --dir DIR [--index N]   the miner_rkm for a node config (coinbase payee)\n  \
         qumbra-wallet ivk export --dir DIR [--i-understand-this-is-a-viewing-key]\n  \
                            the incoming viewing key as hex on stdout, for a scan-only host; writes\n\
                            nothing; refuses a terminal without the flag. An incoming viewing key\n\
                            reads EVERY incoming note to this wallet, across all its addresses, past\n\
                            and future; it cannot spend and cannot see spends\n  \
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
                /v1/compact, /v1/block/../full, /v1/nullifiers (the spent-note\n\
                subtraction — without it no balance is quotable) and /v1/coinbase\n\
                (what this wallet's rkm MINED — a node that does not serve it makes\n\
                the balance transactions-only, and the report says so)\n\
         --node is the node's discovery server: /v1/tree/leaves, /v1/anchors, POST /v1/tx\n\
                (defaults to --url when omitted — one host usually serves both)\n\
         --net  annulet (scan, send and history, lab #718/#720/#831) — the Annulet L2 net: it reads\n\
                /v1/genesis/notes first and REFUSES an endpoint that does not serve\n\
                an Annulet chain; balances are per asset (asset 0 = fee units, not\n\
                QMB); no coinbase. `send --net annulet --asset N --amount V --to ADDR`\n\
                pays an exact-tariff asset-0 fee note (split off a larger one first\n\
                when there is none); when no one note of the asset covers the\n\
                amount it merges notes first (3x2, one exact fee note each) and\n\
                prints the whole plan with its total fee before proving anything\n\
                (--plan-only stops there). Only the verified-header record is\n\
                written to the wallet dir. A policy asset's sender passes the issuer's\n\
                published freeze list with --freeze-list FILE (a frozen address is\n\
                refused before anything is proved). `issuer keygen|freeze|allow|mint|\n\
                redeem|register|update --asset N` are the issuer's verbs (lab #722,\n\
                #730; the secret stays in this wallet dir's issuer.v1). `register\n\
                --mode cloaked|hybrid|regulated` writes a new asset into an empty\n\
                registry slot, `update` changes a held leaf (--freeze-list,\n\
                --allow-list, --mode, --redeem-open|--redeem-closed, --rotate-key),\n\
                and `freeze add|remove --publish` puts the new root on chain; each\n\
                write pays one asset-0 note (change back) and returns a 0-value seed\n\
                note of the asset, which a first mint rides on. `send --net annulet --exit-to\n\
                L1-ADDR --amount V --out FILE` builds and proves an exit (lab #831): one\n\
                asset-0 note redeemed on L2 and paid on L1 to the address, shape P,\n\
                32 GiB class, proved here only; it is WRITTEN, never submitted — an\n\
                Annulet net refuses an exit, and a V6 sequencer bundles it. --genesis-hash HEX64 pins the chain:\n\
                REQUIRED for every --net annulet command: `scan`/`history` verify the\n\
                genesis file, every seal and each note's block against it (lab #850)\n\
                and print no figure otherwise; `send`, the exit and the issuer verbs\n\
                plan only from that verified scan (lab #869)\n\
         --net  t1|t2 — WHICH NET these endpoints serve. Defaults to the net this\n\
                build was CUT for when it carries the release lane\'s stamp, and to\n\
                t1 only for an unstamped build; the flag overrides either. A\n\
                coinbase note\'s derivation is genesis-form dependent, so a wallet\n\
                that MINED on T2 and derives under T1 reconstructs commitments\n\
                that are in no tree: `scan` reports a mined balance and `send`\n\
                then refuses at the witness lookup (lab #566). Accepted by\n\
                scan/send/history and by `names register`/`renew`. No effect on a\n\
                wallet that only receives — transaction outputs are not\n\
                form-dependent. Every command that uses it prints the net it\n\
                chose AND where that came from, so a default is never silent\n\n\
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

/// `--net t1|t2` → the genesis form the chain's coinbase notes are keyed under
/// (lab #566).
///
/// ## Why this flag exists, and what it is NOT
///
/// A coinbase note's ρ and rseed are form-dependent: v5 derives them under a
/// `:v2` domain carrying the payee index, so **the same block yields a different
/// commitment on T1 and T2.** A holder that derives under the wrong form gets a
/// commitment that is in no tree — the note reads as spendable and then refuses
/// at the witness lookup. That is lab #566, confirmed on a T2 mining wallet
/// holding 131 matured notes it could not move.
///
/// `qumbra-node mine` resolves the same question through a [`NetProfile`] table
/// (`--genesis-hash > --net > QUMBRA_GENESIS_HASH > BUILT_FOR_NET`, lab #527).
/// **This is deliberately less than that**: the wallet is nodeless, loads no
/// genesis file, and nothing it fetches — `/v1/coinbase`, `/v1/nullifiers`,
/// `/v1/tree/leaves`, `/v1/anchors` — carries a format version, so there is
/// nothing here for a profile to verify the flag against.
///
/// 🔴 **The durable fix is still owed and is still a stop point**: the served
/// wire carries no genesis format version, so nothing this wallet fetches can
/// *verify* the answer. That is asked on lab #566. What keeps the interim safe
/// rather than merely small is that a wrong answer cannot produce a bad proof —
/// the tree disagrees, and `sync`/`send` refuse and name this flag when they do.
///
/// ## Where the default comes from (lab #581)
///
/// The flag used to default to `t1` unconditionally, and that was a footgun with
/// a measurement behind it: on `t2-2026.08.21-1`, the first release in which a
/// miner *can* spend what they mined, the default invocation still could not.
/// A T2 miner who omitted the flag got #566's refusal on a build that had fixed
/// #566.
///
/// The release lane already knows the answer. It stamps `QUMBRA_NET` into
/// `qumbra-node` — that is what `qumbra-node mine --print-net` reports — and
/// until #581 it stamped **nothing** into the `qumbra-wallet` shipped in the same
/// tarball, so the flag was a second, hand-maintained copy of a fact the release
/// already held, defaulting to the retired net. Resolution order is now:
///
/// 1. **`--net` on the command line** — always wins, including over a stamp, so a
///    T2-stamped binary can still read a T1 endpoint.
/// 2. **[`BUILT_FOR_NET`]**, stamped by the release lane for the net this
///    artifact was cut for.
/// 3. **`t1`** for an unstamped build — a plain `cargo build`, where no lane has
///    an opinion. Unchanged from before, so no developer's command moves.
///
/// A stamp this wallet cannot name is a **release-lane defect, not user error**,
/// and says so: it refuses rather than falling through to a default, because
/// falling through is exactly how a T2 artifact would quietly behave as T1.
///
/// [`NetProfile`]: https://github.com/qumbra-labs/qumbra-lab/blob/main/crates/qumbra-node/src/mine.rs
fn genesis_form_of(args: &[String]) -> Result<qlab_devnet::forms::GenesisForm, Box<dyn Error>> {
    let (form, source) = resolve_net(flag(args, "--net"), BUILT_FOR_NET)?;
    // On stderr, so it never lands in output something is parsing. A default that
    // nobody can see is the failure mode this whole block exists to end: say what
    // was chosen and who chose it, every time.
    eprintln!("net: {} ({})", net_name(form), source.describe());
    Ok(form)
}

/// The flag spelling of a form, for the line above — not `Debug`, which would
/// print `V4`/`V5` and make the user translate.
fn net_name(form: qlab_devnet::forms::GenesisForm) -> &'static str {
    use qlab_devnet::forms::GenesisForm;
    match form {
        GenesisForm::V4 => "t1",
        GenesisForm::V5 => "t2",
        // `resolve_net` never yields it today (the wallet's send path is L1;
        // the L2 note layer is C1/C2) — named, not guessed, if it ever does.
        GenesisForm::Annulet => "annulet",
    }
}

/// The net this artifact was cut for, stamped by the release lane
/// (`.github/workflows/release-binaries.yml`) via `QUMBRA_NET` — the same
/// variable, from the same preflight output, that stamps `qumbra-node`.
///
/// `None` for any build the lane did not produce.
pub const BUILT_FOR_NET: Option<&str> = option_env!("QUMBRA_NET");

/// What decided the net, so a surface can say so instead of leaving the user to
/// infer it. A silent default is how [`genesis_form_of`]'s footgun stayed
/// invisible for a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetSource {
    /// `--net` was given explicitly.
    Flag,
    /// Taken from [`BUILT_FOR_NET`].
    Stamp,
    /// Neither — an unstamped build with no flag.
    Fallback,
}

impl NetSource {
    /// The phrase that goes after the net name on a human-facing line.
    fn describe(self) -> &'static str {
        match self {
            NetSource::Flag => "from --net",
            NetSource::Stamp => "stamped into this build by the release lane",
            NetSource::Fallback => "default for an unstamped build — pass --net to be explicit",
        }
    }
}

/// The whole decision, as a pure function of the two inputs, so it can be tested
/// without a build stamp: `option_env!` is fixed at compile time and a test
/// cannot vary it.
fn resolve_net(
    flag: Option<&str>,
    stamped: Option<&str>,
) -> Result<(qlab_devnet::forms::GenesisForm, NetSource), Box<dyn Error>> {
    use qlab_devnet::forms::GenesisForm;

    let (net, source) = match (flag, stamped) {
        (Some(n), _) => (n, NetSource::Flag),
        (None, Some(n)) => (n, NetSource::Stamp),
        (None, None) => ("t1", NetSource::Fallback),
    };

    match net {
        "t1" => Ok((GenesisForm::V4, source)),
        "t2" => Ok((GenesisForm::V5, source)),
        // Lab #718: the Annulet net is `scan`'s alone for now — `scan` takes
        // it before this function is reached. Every other command here is an
        // L1 flow (send, history, names), and the L2 send path is C2's.
        "annulet" if matches!(source, NetSource::Flag) => Err(
            "--net annulet is accepted by `scan` and `send` only (lab #718/#720): history and names \
             are L1 flows here"
                .into(),
        ),
        other => Err(match source {
            NetSource::Stamp => format!(
                "this build is stamped for net {other}, which this wallet cannot name (it knows: \
                 t1, t2). That is a release-lane defect, not something you did — the binary and \
                 the wallet were built from trees that disagree about which nets exist. Refusing \
                 rather than falling back to a default, because falling back is how a T2 artifact \
                 would quietly behave as T1"
            ),
            _ => format!(
                "--net {other} is not a net this wallet knows (it knows: t1, t2). The net decides \
                 how a mined coinbase note is derived, so guessing it would produce notes with no \
                 leaf in any tree — refusing rather than picking one"
            ),
        }
        .into()),
    }
}


fn dir_of(args: &[String]) -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(flag(args, "--dir").ok_or("--dir DIR is required")?))
}

fn keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir_of(args)?;
    // Entropy → seed → seed file is the library's job since lab #475
    // (`create_from_os_entropy_gated`), so this binary and `qumbra-node mine`
    // mint a wallet by the same code rather than by two copies of it. The gate
    // is what `mine` uses for its backup confirmation; keygen prints no key
    // material, so it has nothing to confirm and always proceeds.
    let w = match qumbra_wallet::store::create_from_os_entropy_gated(&dir, |_mnemonic| true)? {
        qumbra_wallet::store::GatedCreate::Created(w) => w,
        qumbra_wallet::store::GatedCreate::Refused => {
            unreachable!("keygen's gate always accepts")
        }
    };
    let addr = w.wallet().address_at_index(0);
    println!("qumbra-wallet keygen");
    // The protection phrase is platform-derived (lab #478): this line said "0600"
    // unconditionally, which is a false claim on Windows — there is no chmod there
    // and the seed file inherits the folder's ACL instead.
    println!(
        "  seed:    {} ({} — NEVER printed; back it up with `backup --reveal`)",
        dir.join(qumbra_wallet::store::SEED_FILE).display(),
        qumbra_wallet::store::secret_file_protection(),
    );
    println!("  address [0]:");
    println!("    {}", addr.encode());
    println!("    short: {}", addr.short().encode());
    if let Some(note) = qumbra_wallet::store::secret_file_protection_note(&dir) {
        println!("{note}");
    }
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
    // Same seed file, same gap — a restore writes it too (lab #478).
    if let Some(note) = qumbra_wallet::store::secret_file_protection_note(&dir) {
        println!("{note}");
    }
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
    // Lab #896 G: a Candidate A net's addresses (version 2) bind the active
    // generation's auth_root, read from the journal. No journal yet means a
    // restored or new-to-Candidate-A wallet: `migrate` sets it up first, so a
    // restored wallet never hands out a generation it may have used.
    let v2_root = if has_flag(args, "--candidate-a") {
        let journal = qumbra_wallet::auth_journal::AuthJournal::load(&dir)?.ok_or(
            "this wallet has no auth journal yet: run `qumbra-wallet migrate --net annulet --scan-url URL \
             --genesis-hash HEX` once on the Candidate A net (a restored wallet must not resume a generation)",
        )?;
        Some(journal.active().auth_root)
    } else {
        None
    };
    let addr_at = |i: u64| match &v2_root {
        Some(root) => wallet.address_candidate_a_at_index(i, root),
        None => wallet.address_at_index(i),
    };

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
            println!("[{idx}] {}", addr_at(*idx).encode());
        }
        return Ok(());
    };

    let addr = addr_at(idx);
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
/// The flag that lets `ivk export` print to a terminal (lab #821).
const IVK_ACK: &str = "--i-understand-this-is-a-viewing-key";

/// What an exported incoming viewing key is (lab #821) — said in the help and
/// on every export.
const IVK_DATA_CLASS: &str = "an incoming viewing key reads EVERY incoming note to this wallet, across \
all its addresses, past and future; it cannot spend and cannot see spends";

/// `ivk export --dir DIR` (lab #821): the wallet's incoming viewing key as hex
/// (`qlab_wallet::viewing::Ivk::to_bytes`) on stdout, for a host that only
/// scans (the Annulet gateway). Writes nothing anywhere; refuses a terminal
/// unless told otherwise, so the key goes where a pipe sends it rather than
/// into a scrollback.
fn ivk(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("export") => {
            let rest = &args[1..];
            let dir = dir_of(rest)?;
            use std::io::IsTerminal;
            ivk_export_gate(std::io::stdout().is_terminal(), has_flag(rest, IVK_ACK))?;
            let w = WalletDir::open(&dir)?;
            let hex: String = w.wallet().ivk().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("incoming viewing key of {} — {IVK_DATA_CLASS}", dir.display());
            println!("{hex}");
            Ok(())
        }
        _ => Err(format!("usage: qumbra-wallet ivk export --dir DIR [{IVK_ACK}]").into()),
    }
}

/// Whether `ivk export` may print: never to a terminal without the flag.
fn ivk_export_gate(stdout_is_terminal: bool, acknowledged: bool) -> Result<(), String> {
    if stdout_is_terminal && !acknowledged {
        return Err(format!(
            "refusing to print an incoming viewing key to a terminal: {IVK_DATA_CLASS}. Pipe it to \
             where it is going (e.g. `| ssh host 'cat > ivk.hex'`), or pass {IVK_ACK}"
        ));
    }
    Ok(())
}

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
    // The derivation itself lives in the library (lab #475): `qumbra-node mine`
    // needs this exact value and a payout key must not have two expressions.
    let hex = qumbra_wallet::store::miner_rkm_hex(&wallet, idx);
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

    // Lab #720: the Annulet send — its own flow, before any L1 file is read.
    if flag(args, "--net") == Some("annulet") {
        return send_annulet_cmd(args);
    }

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
    // Lab #896 G (QG1): URIs, contacts and the directory carry either
    // address version; this L1 send pays only version 1. A Candidate A
    // address here would make a note nobody can spend — refused by name.
    recipient.require_version(qlab_wallet::address::ADDRESS_VERSION)?;
    // Lab #831 W3 (Q2): only `deposit` burns, and only sealed to this wallet's
    // own key — the burn address of the L2 this chain bridges (as the node
    // names it) reaching `send` (pasted, a contact, a URI, a name) is refused
    // whatever key it carries.
    let bridged = qumbra_wallet::deposit::fetch_l2(node_url).map(|a| a.l2_ids()).unwrap_or_default();
    if let Some(l2_id) = qlab_ledger::deposits::burn_l2_id(&recipient.rkm_lanes(), &bridged) {
        return Err(format!(
            "the recipient is L2 {l2_id}'s burn address: paying it is a deposit, and `send` never burns. Use \
             `qumbra-wallet deposit`, which seals the deposit to this wallet so it can be claimed and recovered"
        )
        .into());
    }

    send_resolved(args, &dir, url, node_url, scan_to, out, no_submit, recipient, contact_name, amount)
}

/// `deposit` (lab #831 W3a): an L1 → L2 deposit — the L1 burn, sealed to
/// this wallet. Before anything is scanned or proved, the node's `/v1/l2`
/// must confirm BOTH pinned facts (`--l2-id`, `--genesis-hash`; ruling on
/// Q-W3-1: both mandatory, no warning mode); then the ordinary send flow pays
/// [`qumbra_wallet::deposit::burn_address`].
fn deposit(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.first().map(String::as_str) == Some("claim") {
        return deposit_claim(&args[1..]);
    }
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("deposit requires --url (compact/scan endpoint)")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let scan_to: u64 = flag(args, "--scan-to").ok_or("deposit requires --scan-to HEIGHT")?.parse()?;
    let amount: u64 = flag(args, "--amount").ok_or("deposit requires --amount BESSEL")?.parse()?;
    let l2_id: u64 = flag(args, "--l2-id")
        .ok_or("deposit requires --l2-id N: the L2 you mean to deposit to, which the chain must confirm")?
        .parse()?;
    let genesis = flag(args, "--genesis-hash")
        .ok_or("deposit requires --genesis-hash HEX64: the chain you mean to burn on, which the node must confirm")?;
    let genesis = qumbra_wallet::annulet::parse_genesis_hash(genesis)?;
    for refused in ["--to", "--to-contact"] {
        if flag(args, refused).is_some() {
            return Err(format!("{refused} does not apply to a deposit: its payee is the L2's burn address, sealed to this wallet").into());
        }
    }
    if flag(args, "--net") == Some("t1") || (flag(args, "--net").is_none() && BUILT_FOR_NET.is_none_or(|n| n == "t1")) {
        return Err("T1 bridges no L2 and never will: a burn there is lost. Pass --net t2 against a V6 node".into());
    }
    let out = flag(args, "--out");
    let no_submit = has_flag(args, "--no-submit");
    // The net, resolved before the gate prints anything: `--net annulet`, an
    // unknown net or a bad stamp is refused here, never after "confirmed".
    genesis_form_of(args)?;

    // The gate, before anything else: an irreversible burn into a chain the
    // user did not name, or an L2 it does not bridge, is never built.
    let answer = qumbra_wallet::deposit::fetch_l2(node_url).map_err(|e| {
        format!("the node did not say which L2 its chain bridges ({e}); refusing to burn without that answer")
    })?;
    let route = qumbra_wallet::deposit::check_bridge(&answer, l2_id, &genesis)?;
    let w = WalletDir::open(&dir)?;
    let burn = qumbra_wallet::deposit::burn_address(&w.wallet(), l2_id);
    println!(
        "deposit: {amount} bessel to L2 {l2_id} on genesis {} — confirmed by the node's /v1/l2 (claim fee tier {}, \
         wrapper params {})",
        route.genesis.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        route.claim_fee_tier,
        route.wrapper_params.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!(
        "  the burn is sealed to this wallet: its scan shows it as a pending deposit until it is claimed on L2 \
         (`qumbra-wallet scan`); it is never L1 balance again"
    );
    drop(w);
    send_resolved(args, &dir, url, node_url, scan_to, out, no_submit, burn, Some(format!("deposit to L2 {l2_id}")), amount)
}

/// `deposit claim` (lab #831 W3b): the claim of one of this wallet's pending
/// deposits — proved here (the claim lane, ≈ 3.17 GiB, local only) and
/// written to `--out` for the sequencer; never submitted (W4).
///
/// The same two-fact gate as `deposit` (`/v1/l2` must confirm `--l2-id` and
/// `--genesis-hash`), and the chain's claim tier from that same answer. The
/// claim opens the burn under a caller-chosen anchor — the newest finalized
/// one the node serves by default, `--anchor-count N` to pick another served
/// root — and is taken by a wrapper only once one absorbs that root. Its
/// blinds come from this wallet and the burn alone
/// (`Wallet::claim_blinds`), so a claim bound to a root no wrapper absorbs
/// costs a re-prove at another anchor, never a lost deposit; and a wallet
/// restored from its mnemonic rebuilds it from a rescan.
fn deposit_claim(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::net::{HttpAnchorSource, HttpLeafSource};
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("deposit claim requires --url (compact/scan endpoint)")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let scan_to: u64 = flag(args, "--scan-to").ok_or("deposit claim requires --scan-to HEIGHT")?.parse()?;
    let l2_id: u64 = flag(args, "--l2-id").ok_or("deposit claim requires --l2-id N, which the chain must confirm")?.parse()?;
    let genesis = flag(args, "--genesis-hash")
        .ok_or("deposit claim requires --genesis-hash HEX64, which the node must confirm")?;
    let genesis = qumbra_wallet::annulet::parse_genesis_hash(genesis)?;
    if flag(args, "--net") == Some("t1") || (flag(args, "--net").is_none() && BUILT_FOR_NET.is_none_or(|n| n == "t1")) {
        return Err("T1 bridges no L2: there is nothing to claim. Pass --net t2 against a V6 node".into());
    }
    let form = genesis_form_of(args)?;
    let plan_only = has_flag(args, "--plan-only");
    let out = flag(args, "--out").map(std::path::Path::new);
    match out {
        Some(path) => refuse_out_path(path)?,
        None if !plan_only => return Err("deposit claim writes the proven claim to --out FILE (or pass --plan-only)".into()),
        None => {}
    }
    let pick: Option<usize> = flag(args, "--deposit").map(str::parse).transpose()?;
    let anchor_pick: Option<u64> = flag(args, "--anchor-count").map(str::parse).transpose()?;

    // The gate, and the chain's claim tier from the same answer.
    let answer = qumbra_wallet::deposit::fetch_l2(node_url).map_err(|e| {
        format!("the node did not say which L2 its chain bridges ({e}); refusing to build a claim without that answer")
    })?;
    let route = qumbra_wallet::deposit::check_bridge(&answer, l2_id, &genesis)?;

    // This wallet's pending deposits to that L2, as its own scan sets them aside.
    let w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    let gathered = qumbra_wallet::scan::gather(&w, url, 0, scan_to, form);
    let mut pending: Vec<qlab_ledger::deposits::SetAside> = gathered
        .set_aside
        .into_iter()
        .filter(|s| s.kind == qlab_ledger::deposits::SetAsideKind::PendingDeposit { l2_id })
        .collect();
    pending.sort_by_key(|s| (s.height, s.tx_index, s.cm));
    if pending.is_empty() {
        return Err(format!("no pending deposit to L2 {l2_id} in heights 0..={scan_to}").into());
    }
    // Every burn is listed, claimed or not: whether a claim landed is L2
    // state (its cnf in the wrapper's tree), which nothing this wallet reads
    // serves yet — a second claim of one burn is refused there, not here.
    println!("pending deposits to L2 {l2_id} (claimed ones included — the L1 cannot say which were claimed on L2):");
    for (k, s) in pending.iter().enumerate() {
        println!("  deposit [{k}]: {} bessel at height {} (tx {}, address [{}])", s.note.value, s.height, s.tx_index, s.div_index);
    }
    let chosen = match (pick, pending.len()) {
        (Some(k), n) if k < n => &pending[k],
        (Some(k), n) => return Err(format!("--deposit {k}: there are {n} pending deposit(s)").into()),
        (None, 1) => &pending[0],
        (None, n) => return Err(format!("{n} pending deposits: pick one with --deposit K (listed above)").into()),
    };

    // The L1 tree and the anchor: the newest the node serves, or a chosen one
    // that is also a served root.
    let (synced, newest) = qumbra_wallet::sync::sync_and_select(&dir, &HttpLeafSource::new(node_url), &HttpAnchorSource::new(node_url))?;
    let anchor_count = match anchor_pick {
        None => newest.count,
        Some(n) => {
            let served = HttpAnchorSource::new(node_url);
            let set = qumbra_wallet::sync::AnchorSource::anchors(&served)?;
            if n > synced.count || !set.roots.contains(&qlab_note::hash::digest_bytes(&synced.tree.root_at(n))) {
                return Err(format!("--anchor-count {n}: the root at that count is not one the node serves as a valid anchor").into());
            }
            n
        }
    };
    let anchor_root = qlab_note::hash::digest_bytes(&synced.tree.root_at(anchor_count));

    let note = qlab_air::claim::BurnNote {
        value: chosen.note.value,
        rkm: qlab_ledger::deposits::burn_rkm(l2_id),
        rho: chosen.note.rho,
        rseed: chosen.note.rseed,
    };
    let cm = qlab_air::claim::l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
    let (r_v, rseed) = wallet.claim_blinds(&cm);
    let credit = qlab_air::claim::ClaimCredit { rkm: wallet.rkm(wallet.diversifier_at_index(0)), rseed };
    let fee = route.claim_fee_tier;
    let inst = qlab_l2spend::claim_instance(&synced.tree, anchor_count, &note, l2_id, &r_v, &credit, fee)?;

    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!(
        "plan: claim {} bessel burned to L2 {l2_id}: {} credited on L2 to this wallet's address 0, claim fee {fee} \
         (the chain's tier)",
        note.value,
        note.value - fee
    );
    println!(
        "  anchor: root {} at {anchor_count} leaves{} — the claim is taken only once a wrapper absorbs this root; \
         one that is never absorbed costs a re-prove at another anchor (--anchor-count), never the deposit",
        hex(&anchor_root),
        if anchor_pick.is_none() {
            format!(", the newest valid anchor (node finalized height {})", newest.finalized_height.map_or("none".into(), |h| h.to_string()))
        } else {
            String::new()
        }
    );
    println!("  prove:  the claim lane, about 3.17 GiB, on this machine only");
    println!(
        "  privacy: the file reveals the deposit amount to whoever holds it — it is for the sequencer only"
    );
    if plan_only {
        println!("--plan-only: nothing proved or written");
        return Ok(());
    }
    let proof = qlab_l2spend::prove_claim(&inst);
    let out = out.expect("checked above");
    write_new_atomically(out, &qlab_l2spend::encode_claim_artifact(&genesis, l2_id, &inst.pvs, &proof, note.value, &r_v))?;
    println!(
        "wrote {}: the proven claim (version {} of the claim file, bound to this chain's genesis and its claim tier)",
        out.display(),
        qlab_l2spend::CLAIM_ARTIFACT_VERSION
    );
    Ok(())
}

/// `exit --net v6` (lab #860 R3): one claim credit of this wallet, exited
/// whole from a V6 chain's L2 to an L1 address. The gate is W3a's (`/v1/l2`
/// must confirm `--l2-id` and `--genesis-hash`); the anchor and its check are
/// [`qumbra_wallet::exit_v6::plan`]'s, all before the proof (self-consistency
/// of the node's index and bundle — L1 inclusion is R3c); the file binds
/// the V6 genesis. `--submit` POSTs it to the sequencer's intake, which holds
/// exits until the sequencer plans them (R3b).
fn exit_v6_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::exit_v6::{self, EXIT_FEE_V6};
    match flag(args, "--net") {
        Some("v6") => {}
        Some(other) => {
            return Err(format!("`exit` is the V6 exit (--net v6); --net {other} is refused here — an Annulet exit is `send --net annulet --exit-to`").into())
        }
        None => return Err("`exit` requires --net v6 (the V6 bridge's exit; an Annulet exit is `send --net annulet --exit-to`)".into()),
    }
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("exit requires --url (compact/scan endpoint)")?;
    let node_url = flag(args, "--node").unwrap_or(url);
    let scan_to: u64 = flag(args, "--scan-to").ok_or("exit requires --scan-to HEIGHT")?.parse()?;
    let l2_id: u64 = flag(args, "--l2-id").ok_or("exit requires --l2-id N, which the chain must confirm")?.parse()?;
    let genesis = flag(args, "--genesis-hash").ok_or("exit requires --genesis-hash HEX64, which the node must confirm")?;
    let genesis = qumbra_wallet::annulet::parse_genesis_hash(genesis)?;
    let to = flag(args, "--exit-to").ok_or("exit requires --exit-to ADDR (the L1 address the exit pays)")?;
    let to = qlab_wallet::address::Address::decode(to).ok_or("--exit-to is not a wallet address (the L1 recipient)")?;
    let amount: Option<u64> = flag(args, "--amount").map(str::parse).transpose()?;
    let plan_only = has_flag(args, "--plan-only");
    let out = flag(args, "--out").map(std::path::Path::new);
    match out {
        Some(path) => refuse_out_path(path)?,
        None if !plan_only => return Err("exit writes the proven exit to --out FILE (or pass --plan-only)".into()),
        None => {}
    }
    let submit = has_flag(args, "--submit");
    if submit && plan_only {
        return Err("--submit with --plan-only: a plan proves and writes nothing, so there is nothing to hand over".into());
    }
    let intake = match (submit, flag(args, "--intake")) {
        (true, Some(a)) => Some(a.parse::<std::net::SocketAddr>().map_err(|_| format!("--intake {a} is not an ip:port address"))?),
        (true, None) => return Err("--submit requires --intake IP:PORT (the sequencer's intake, loopback or a tunnel to it)".into()),
        (false, Some(_)) => return Err("--intake without --submit: pass --submit to hand the file over".into()),
        (false, None) => None,
    };

    // The gate (W3a's rule): the node must bridge exactly this L2 on exactly
    // this genesis; the claim tier comes from the same answer.
    let answer = qumbra_wallet::deposit::fetch_l2(node_url)
        .map_err(|e| format!("the node did not say which L2 its chain bridges ({e}); refusing to build an exit"))?;
    let route = qumbra_wallet::deposit::check_bridge(&answer, l2_id, &genesis)?;
    let w = WalletDir::open(&dir)?;
    let wallet = w.wallet();
    let gathered = qumbra_wallet::scan::gather(&w, url, 0, scan_to, qlab_devnet::forms::GenesisForm::V5);
    let served = qlab_l2spend::Served::v6(qumbra_wallet::annulet_send::WalletEndpoint { url: node_url.to_string() });
    let mut rng = rand::rng();
    let change_to = qumbra_wallet::annulet_send::me(&w);
    let plan = exit_v6::plan(&served, &wallet, &gathered.set_aside, l2_id, route.claim_fee_tier, to.rkm_lanes(), &change_to, amount, &mut rng)?;
    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!(
        "plan: exit {} bessel — the whole credit of the claim of the deposit at height {} — to L1 {}, fee {EXIT_FEE_V6}",
        plan.credit.note.value, plan.credit.height, to.short().encode()
    );
    println!(
        "  anchor: bundle {} at height {}, its stated C over {} leaves — the served leaves and the asset-0 registry opening fold to its stated roots",
        hex(&plan.anchor_id),
        plan.anchor_height,
        plan.c_next
    );
    println!(
        "  trust: the L2 index is checked against that bundle, but the anchor bundle's L1 inclusion is NOT verified by \
         this wallet — a lying node can waste a proof, never funds; nullifier completeness is NOT verified (lab #853): \
         a credit already spent would be refused by the chain, not here"
    );
    println!("  prove:  the P lane, about 30 GiB, on this machine only");
    println!("  HELD:   the sequencer holds exits until it plans them (lab #860 R3b) — this exit will not land before that");
    if plan_only {
        println!("--plan-only: nothing proved or written");
        return Ok(());
    }
    let built = qlab_l2spend::prove_exit(&plan.ei, EXIT_FEE_V6, &change_to, &mut rng);
    let bytes = qlab_l2spend::encode_exit_artifact(&genesis, &built.tx);
    let out = out.expect("checked above");
    write_new_atomically(out, &bytes)?;
    println!("wrote {}: the proven exit (exit file version {}, bound to this chain's genesis)", out.display(), qlab_l2spend::EXIT_ARTIFACT_VERSION);
    if let Some(addr) = intake {
        let (status, body) = qumbra_wallet::net::http_post_bytes(&format!("http://{addr}"), "/v1/intake", &bytes)
            .map_err(|e| format!("POST /v1/intake did not complete ({e}); the file stays at {}", out.display()))?;
        match qumbra_wallet::exit_v6::intake_verdict(status, &body) {
            Ok(line) => println!("{line}"),
            Err(why) => return Err(format!("{why}; the file stays at {}", out.display()).into()),
        }
    }
    Ok(())
}

/// The send after its recipient and amount are settled — shared by `send` and
/// `deposit` (lab #831 W3a), so a deposit is the same flow, the same proof,
/// the same keep-the-bytes discipline, never a second copy of it.
#[allow(clippy::too_many_arguments)]
fn send_resolved(
    args: &[String],
    dir: &std::path::Path,
    url: &str,
    node_url: &str,
    scan_to: u64,
    out: Option<&str>,
    no_submit: bool,
    recipient: qlab_wallet::address::Address,
    contact_name: Option<String>,
    amount: u64,
) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::spend::{execute, SendError, SendRequest, SendStep};

    // The sink. Progress belongs on stderr so a piped stdout stays the result;
    // the flow itself is `qumbra_wallet::spend`, shared with every other surface.
    let mut sink = |step: SendStep| match step {
        SendStep::Resolved { recipient_short, contact } => {
            if let Some(name) = contact {
                eprintln!("→ {name} ({recipient_short})");
            }
        }
        // 🔴 Loud by decision (lab #424): the send proceeds, and the one thing a
        // user must not do is conclude they spent from a complete view.
        SendStep::CoinbaseUnavailable { why } => eprintln!("🔴 {why}"),
        SendStep::Selected { skipped_spent, mined, .. } => {
            if skipped_spent > 0 {
                eprintln!(
                    "note: {skipped_spent} already-spent note(s) skipped by input selection \
                     (their nullifiers are on the chain)"
                );
            }
            if mined > 0 {
                eprintln!(
                    "note: {mined} matured coinbase note(s) this wallet mined are among the \
                     candidate inputs"
                );
            }
        }
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
        dir,
        url,
        node_url,
        recipient: &recipient,
        contact_name: contact_name.as_deref(),
        amount,
        scan_to,
        no_submit,
        name_op: None,
        form: genesis_form_of(args)?,
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
    // Lab #831 W1: the Annulet ledger — its own flow, before any L1 net is resolved.
    if flag(args, "--net") == Some("annulet") {
        return history_annulet_cmd(args, &w, url, from, to);
    }
    let report = qumbra_wallet::ledger_run::report(&dir, &w, url, from, to, genesis_form_of(args)?);
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
    // Lab #718: the Annulet net's scan — its form verified against the
    // endpoint's own genesis, optionally pinned; the L1 path below unchanged.
    if flag(args, "--net") == Some("annulet") {
        return scan_annulet_cmd(args, &w, url, from, to);
    }
    let report = qumbra_wallet::scan::scan_report(&w, url, from, to, genesis_form_of(args)?);
    print!(
        "{}",
        view::render_with_exits(
            &report.scans,
            (from, to),
            url,
            &report.spent,
            report.coinbase.as_ref(),
            &report.coinbase_coverage,
            report.exits.as_ref(),
            &report.exit_coverage,
        )
    );
    // Lab #831 W3: what the scan set aside, beside — never inside — the figures.
    print!("{}", qlab_ledger::deposits::render(&report.set_aside));
    Ok(())
}

/// `issuer …` (lab #722): an Annulet asset issuer's verbs. The issuer secret
/// lives in the wallet dir's `issuer.v1` (never in a node); the freeze list
/// is a published file of key hashes.
fn issuer(args: &[String]) -> Result<(), Box<dyn Error>> {
    use qumbra_wallet::issuer::{freeze_update, lanes_hex, read_key_list, write_key_list, IssuerFile};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let asset = || -> Result<u16, Box<dyn Error>> {
        Ok(flag(args, "--asset").ok_or("issuer requires --asset N")?.parse().map_err(|_| "--asset must be below 65536")?)
    };
    let list = |path: &str| -> Result<Vec<[u64; 4]>, Box<dyn Error>> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(read_key_list(&t)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    };
    let allow_list = |path: &str| -> Result<Vec<[u64; 4]>, Box<dyn Error>> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(qumbra_wallet::issuer::read_allow_list(&t)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    };
    // A registry write (lab #730): the session's inputs, and the policy flags.
    type WriteCtx = (WalletDir, qumbra_wallet::annulet_send::WalletEndpoint, u64, Option<[u8; 32]>, StdRng);
    let write_ctx = || -> Result<WriteCtx, Box<dyn Error>> {
        let dir = dir_of(args)?;
        let url = flag(args, "--url").ok_or("a registry write requires --url")?;
        let scan_to: u64 = flag(args, "--scan-to").ok_or("requires --scan-to HEIGHT")?.parse()?;
        let pin = Some(required_pin(args, "issuer registry write")?);
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Ok((WalletDir::open(&dir)?, qumbra_wallet::annulet_send::WalletEndpoint { url: url.to_string() }, scan_to, pin, StdRng::from_seed(seed)))
    };
    let policy = || -> Result<qumbra_wallet::issuer::LeafPolicy, Box<dyn Error>> {
        let mode = match flag(args, "--mode") {
            Some(m) => Some(qumbra_wallet::issuer::parse_mode(m).ok_or("--mode is cloaked, hybrid or regulated")?),
            None => None,
        };
        let redeem_open = match (has_flag(args, "--redeem-open"), has_flag(args, "--redeem-closed")) {
            (true, true) => return Err("--redeem-open and --redeem-closed contradict".into()),
            (true, false) => Some(true),
            (false, true) => Some(false),
            (false, false) => None,
        };
        Ok(qumbra_wallet::issuer::LeafPolicy {
            mode,
            freeze_keys: flag(args, "--freeze-list").map(list).transpose()?,
            allow_creds: flag(args, "--allow-list").map(allow_list).transpose()?,
            redeem_open,
        })
    };
    let report_write = |verb: &str, r: &qumbra_wallet::issuer::RegistryReport| {
        println!(
            "{verb} asset {} ({} leaf); registry root now {}",
            r.leaf.asset,
            ["cloaked", "hybrid", "regulated"].get(r.leaf.mode as usize).unwrap_or(&"?"),
            r.new_root.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        println!("issuer_key = {}", lanes_hex(&r.leaf.issuer_key));
        println!(
            "change {} fee units back; seed: a 0-value note of asset {} (a first mint rides on it)",
            r.change.value, r.seed.asset
        );
        println!("(every pooled spend bound to the old root is evicted: holders re-read the leaf and re-prove)");
    };
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let dir = dir_of(args)?;
            let mut isk = [0u64; 4];
            for l in isk.iter_mut() {
                *l = rand::rng().next_u64();
            }
            IssuerFile::add(&dir, asset()?, isk)?;
            println!("issuer_key = {}  (the registry leaf's issuer key)", lanes_hex(&qlab_air::l2p::issuer_key_of(&isk)));
            Ok(())
        }
        Some("freeze") => {
            let path = flag(args, "--list").ok_or("issuer freeze requires --list FILE (the published list)")?;
            let keys = list(path)?;
            let (keys, root) = match args.get(1).map(String::as_str) {
                Some(verb @ ("add" | "remove")) => {
                    let addr = flag(args, "--address").ok_or("issuer freeze add/remove requires --address ADDR")?;
                    let addr = qlab_wallet::address::Address::decode(addr).ok_or("--address is not a wallet address")?;
                    let (keys, root) = freeze_update(&keys, &addr, verb == "add");
                    std::fs::write(path, write_key_list(&keys))?;
                    (keys, root)
                }
                Some("root") => {
                    let t = qlab_air::l2p::CanonicalFreezeTree::from_keys(&keys);
                    (t.keys, t.root)
                }
                _ => return Err("issuer freeze add|remove|root".into()),
            };
            println!("freeze list: {} key(s); root {}", keys.len(), lanes_hex(&root));
            if has_flag(args, "--publish") {
                let (w, endpoint, scan_to, pin, mut rng) = write_ctx()?;
                let p = qumbra_wallet::issuer::LeafPolicy { freeze_keys: Some(keys), ..Default::default() };
                let r = qumbra_wallet::issuer::issuer_update(&w, endpoint, asset()?, &p, false, scan_to, pin, &mut rng)?;
                report_write("published the freeze root of", &r);
            } else {
                println!("(local until published: `issuer freeze … --publish --asset N --url … --scan-to …`)");
            }
            Ok(())
        }
        Some("allow") => {
            let path = flag(args, "--list").ok_or("issuer allow requires --list FILE (the published list)")?;
            let creds = allow_list(path)?;
            let (creds, root) = match args.get(1).map(String::as_str) {
                Some(verb @ ("add" | "remove")) => {
                    let addr = flag(args, "--address").ok_or("issuer allow add/remove requires --address ADDR")?;
                    let addr = qlab_wallet::address::Address::decode(addr).ok_or("--address is not a wallet address")?;
                    let (creds, root) = qumbra_wallet::issuer::allow_update(&creds, &addr, verb == "add");
                    std::fs::write(path, qumbra_wallet::issuer::write_allow_list(&creds))?;
                    (creds, root)
                }
                Some("root") => {
                    let t = qlab_air::l2p::CanonicalAllowTree::from_creds(&creds);
                    (t.creds, t.root)
                }
                _ => return Err("issuer allow add|remove|root".into()),
            };
            println!("allow list: {} credential(s); root {}", creds.len(), lanes_hex(&root));
            if has_flag(args, "--publish") {
                let (w, endpoint, scan_to, pin, mut rng) = write_ctx()?;
                let p = qumbra_wallet::issuer::LeafPolicy { allow_creds: Some(creds), ..Default::default() };
                let r = qumbra_wallet::issuer::issuer_update(&w, endpoint, asset()?, &p, false, scan_to, pin, &mut rng)?;
                report_write("published the allow root of", &r);
            }
            Ok(())
        }
        Some("register") => {
            let (w, endpoint, scan_to, pin, mut rng) = write_ctx()?;
            let r = qumbra_wallet::issuer::issuer_register(&w, endpoint, asset()?, &policy()?, scan_to, pin, &mut rng)?;
            report_write("registered", &r);
            Ok(())
        }
        Some("update") => {
            let (w, endpoint, scan_to, pin, mut rng) = write_ctx()?;
            let rotate = has_flag(args, "--rotate-key");
            let r = qumbra_wallet::issuer::issuer_update(&w, endpoint, asset()?, &policy()?, rotate, scan_to, pin, &mut rng)?;
            report_write("updated", &r);
            if rotate {
                println!("(the new issuer secret is pending in issuer.v1 and becomes the one in force once the chain shows it)");
            }
            Ok(())
        }
        Some(verb @ ("mint" | "redeem")) => {
            let dir = dir_of(args)?;
            let url = flag(args, "--url").ok_or("issuer mint/redeem requires --url")?;
            let scan_to: u64 = flag(args, "--scan-to").ok_or("requires --scan-to HEIGHT")?.parse()?;
            let amount: u64 = flag(args, "--amount").ok_or("requires --amount")?.parse()?;
            let pin = Some(required_pin(args, "issuer mint/redeem")?);
            let keys = match flag(args, "--freeze-list") {
                Some(p) => list(p)?,
                None => Vec::new(),
            };
            let w = WalletDir::open(&dir)?;
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            let mut rng = StdRng::from_seed(seed);
            let endpoint = qumbra_wallet::annulet_send::WalletEndpoint { url: url.to_string() };
            let wait = std::time::Duration::from_secs(120);
            let report = if verb == "mint" {
                let to = flag(args, "--to").ok_or("issuer mint requires --to ADDRESS")?;
                let to = qlab_wallet::address::Address::decode(to).ok_or("--to is not a wallet address")?;
                qumbra_wallet::issuer::issuer_mint(&w, endpoint, asset()?, amount, &to, &keys, scan_to, pin, wait, &mut rng)?
            } else {
                qumbra_wallet::issuer::redeem(&w, endpoint, asset()?, amount, &keys, scan_to, pin, wait, &mut rng)?
            };
            println!("{verb}ed {amount} of asset {} (shape P, vPublic {}{amount})", asset()?, if verb == "mint" { "+" } else { "-" });
            if let Some(n) = report.split_fee_note {
                println!("fee-split first: made an exact-tariff fee note of {}", n.value);
            }
            if verb == "mint" {
                if report.rearmed {
                    println!("re-armed: this wallet still holds a note of asset {} for the next mint", asset()?);
                } else {
                    println!(
                        "NOT re-armed: this wallet holds no note of asset {} now — the next mint needs one; \
                         a registry update (`issuer update`) seeds a 0-value note",
                        asset()?
                    );
                }
            }
            Ok(())
        }
        _ => Err("issuer keygen|freeze|allow|mint|redeem|register|update (lab #722, #730)".into()),
    }
}

/// `send --net annulet` (lab #720; A4): scan, plan (fee-splits, merges, the
/// payment), print the plan before anything is proved, prove, submit — or
/// stop after the plan with `--plan-only`. Writes nothing to the wallet dir.
fn send_annulet_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    // Lab #831 W2: an exit is its own flow — one P transaction, written out.
    if flag(args, "--exit-to").is_some() {
        return exit_annulet_cmd(args);
    }
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("send --net annulet requires --url (the node's discovery server)")?;
    let scan_to: u64 = flag(args, "--scan-to").ok_or("send requires --scan-to HEIGHT")?.parse()?;
    let asset: u16 = flag(args, "--asset")
        .ok_or("send --net annulet requires --asset N (0 is the fee unit)")?
        .parse()
        .map_err(|_| "--asset must be a registry index below 65536")?;
    let amount: u64 = flag(args, "--amount").ok_or("send requires --amount")?.parse()?;
    let to = flag(args, "--to").ok_or("send --net annulet requires --to ADDRESS")?;
    // Either version (lab #896 G): `send_annulet` checks it against the net.
    let to = qlab_wallet::address::Address::decode_any(to).ok_or("--to is not a wallet address")?;
    let pin = Some(required_pin(args, "send --net annulet")?);
    // Lab #722: the asset issuer's published freeze-key list, when it has one.
    let freeze_keys = match flag(args, "--freeze-list") {
        Some(path) => qumbra_wallet::issuer::read_key_list(&std::fs::read_to_string(path)?)?,
        None => Vec::new(),
    };
    let w = WalletDir::open(&dir)?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    eprintln!(
        "net: annulet (from --net; verifying genesis bytes against --genesis-hash, the seal chain and each note's block)"
    );
    let endpoint = qumbra_wallet::annulet_send::WalletEndpoint { url: url.to_string() };
    let plan_only = args.iter().any(|a| a == "--plan-only");
    // A4 (design #283 Q5): the whole plan, with its total fee, before any proof.
    let mut on_plan = |plan: &qumbra_wallet::annulet_send::SendPlan| {
        print!("{plan}");
        !plan_only
    };
    let report = match qumbra_wallet::annulet_send::send_annulet(
        &w,
        endpoint,
        asset,
        amount,
        &to,
        scan_to,
        pin,
        &freeze_keys,
        std::time::Duration::from_secs(120),
        &mut on_plan,
        &mut rng,
    ) {
        Err(qumbra_wallet::annulet_send::SendRefusal::PlanDeclined) if plan_only => {
            println!("--plan-only: nothing proved or submitted");
            return Ok(());
        }
        other => other?,
    };
    if let Some(fee) = report.split_fee_note {
        println!("fee-split: made an exact-tariff fee note of {} (asset 0) first", fee.value);
    }
    println!(
        "sent {amount} of asset {asset} (shape {:?}) after {} merge(s); change {} back to this wallet; fee {} in all",
        report.shape,
        report.plan.merges(),
        report.outputs[1].value,
        report.plan.total_fee()
    );
    Ok(())
}

/// `--genesis-hash`, required (lab #869 (a)): every Annulet write — send,
/// exit, registry write, mint/redeem — opens its session on the verified scan,
/// which needs the chain named by its genesis hash. The same rule `deposit`
/// and `scan`/`history --net annulet` already follow.
fn required_pin(args: &[String], verb: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let hex = flag(args, "--genesis-hash").ok_or_else(|| {
        format!(
            "{verb} requires --genesis-hash HEX64: an Annulet write starts from a scan verified against the chain it \
             names (lab #869)"
        )
    })?;
    Ok(qumbra_wallet::annulet::parse_genesis_hash(hex)?)
}

/// `scan --net annulet` (lab #718): verify the endpoint serves an Annulet
/// chain (and the pinned genesis, when `--genesis-hash` is given), scan at the
/// L2 width, and report per asset.
fn scan_annulet_cmd(args: &[String], w: &WalletDir, url: &str, from: u64, to: u64) -> Result<(), Box<dyn Error>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let pin = flag(args, "--genesis-hash").map(qumbra_wallet::annulet::parse_genesis_hash).transpose()?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let (report, range, trust) = annulet_report(w, &mut fetch, from, to, pin, &mut rng)?;
    print!("{}", qumbra_wallet::annulet::render(&report, url, range));
    println!("{trust}");
    Ok(())
}

/// The Annulet scan both `scan` and `history` read (lab #850 AD1): the
/// **verified** scan — genesis by its bytes, every seal from genesis to the
/// verified tip, each note's block recomputed — and the range ends at the
/// verified tip. `--genesis-hash` is required (the #850 ruling, as W3a ruled
/// for `deposit`): the CLI never prints an Annulet figure from an unverified
/// scan.
fn annulet_report<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut rand::rngs::StdRng,
) -> Result<(qumbra_wallet::annulet::AnnuletReport, (u64, u64), String), Box<dyn Error>>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let Some(pin) = pin else {
        return Err("--net annulet needs --genesis-hash: an Annulet figure is printed only from a scan \
                    verified against the chain it names (lab #850)"
            .into());
    };
    eprintln!("net: annulet (from --net; verifying genesis bytes, the seal chain and each note's block)");
    let v = qumbra_wallet::annulet_verify::scan_annulet_verified(w, fetch, from, to, Some(pin), rng)?;
    let (bodies, bytes) = v.body_cost();
    let tip = v.chain().tip();
    let freshness = match v.stated_tip() {
        Some(stated) if stated > tip => format!(
            " The endpoint states tip {stated}: the verified chain is {} header(s) behind it.",
            stated - tip
        ),
        Some(_) => String::new(),
        None => " The endpoint did not state its tip.".to_string(),
    };
    let trust = format!(
        "trust:    outputs VERIFIED — genesis file hashed to the pin; seals verified 1..={tip}; {bodies} block \
         body(ies) ({bytes} B) recomputed for the notes found.{freshness}\n\
         spends:   NOT VERIFIED — the subtracted spends are the endpoint's list; a withheld spend leaves a \
         spent note in the figure, so a balance can be OVERSTATED (lab #853)."
    );
    let cache = match v.cache() {
        qumbra_wallet::annulet_verify::ChainCache::Unused => "headers: verified from genesis (no record yet)".to_string(),
        qumbra_wallet::annulet_verify::ChainCache::Resumed { anchor, recorded } if anchor < recorded => format!(
            "headers: this wallet's verified record holds {recorded}; this endpoint serves only up to {anchor}, \
             re-checked there — the verified tip is {anchor}"
        ),
        qumbra_wallet::annulet_verify::ChainCache::Resumed { anchor, .. } => {
            format!("headers: resumed from this wallet's verified record at height {anchor}, re-checked against the endpoint")
        }
        qumbra_wallet::annulet_verify::ChainCache::Discarded(why) => {
            format!("headers: RECORD DISCARDED — {why}; re-verified from genesis")
        }
    };
    let cache = match v.cache_write() {
        Some(why) => format!("{cache}; the record was not written: {why}"),
        None => cache,
    };
    let trust = format!("{trust}\ncache:    {cache}");
    let range = v.range();
    let report = qumbra_wallet::annulet_verify::into_report(v);
    Ok((report, range, trust))
}

/// `history --net annulet` (lab #831 W1): the same verified scan as
/// `scan --net annulet`, read as a ledger.
fn history_annulet_cmd(args: &[String], w: &WalletDir, url: &str, from: u64, to: u64) -> Result<(), Box<dyn Error>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    // Refused rather than ignored: a ledger reads one endpoint, and a flag that
    // looks like it chose a second one must not be silently dropped.
    if flag(args, "--node").is_some() {
        return Err("history --net annulet reads only --url (the scan endpoint); --node is not used — drop it".into());
    }
    let pin = flag(args, "--genesis-hash").map(qumbra_wallet::annulet::parse_genesis_hash).transpose()?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let (report, range, trust) = annulet_report(w, &mut fetch, from, to, pin, &mut rng)?;
    let ledger = qumbra_wallet::annulet::history(&report, range);
    print!("{}", qlab_ledger::l2history::render(&ledger, url));
    println!("{trust}");
    Ok(())
}

/// `send --net annulet --exit-to ADDR --amount V --out FILE` (lab #831 W2):
/// the exit's plan, then the proven P transaction written to `--out` — never
/// submitted. An Annulet net refuses an exit by name (it has no bridge); a
/// V6 bundle is a sequencer's to assemble (W4, after sequencer-v0).
fn exit_annulet_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let dir = dir_of(args)?;
    let url = flag(args, "--url").ok_or("an exit requires --url (the L2 endpoint it is built against)")?;
    let scan_to: u64 = flag(args, "--scan-to").ok_or("an exit requires --scan-to HEIGHT")?.parse()?;
    let amount: u64 = flag(args, "--amount").ok_or("an exit requires --amount (of asset 0)")?.parse()?;
    if flag(args, "--asset").is_some_and(|a| a != "0") {
        return Err("only asset 0 exits to L1 (the exit is an asset-0 redeem); drop --asset or pass 0".into());
    }
    // Every flag a send reads and an exit does not, refused by name rather
    // than ignored: `--to`/`--to-contact` (the recipient is --exit-to),
    // `--freeze-list` (asset 0 has none), `--node` (one endpoint), and
    // `--no-submit` (an exit is never submitted).
    for refused in ["--to", "--to-contact", "--freeze-list", "--node"] {
        if flag(args, refused).is_some() {
            return Err(format!("{refused} does not apply to an exit (the L1 recipient is --exit-to; one --url endpoint; asset 0 has no freeze list)").into());
        }
    }
    if args.iter().any(|a| a == "--no-submit") {
        return Err("--no-submit does not apply to an exit: an exit is never submitted, only written with --out".into());
    }
    let plan_only = args.iter().any(|a| a == "--plan-only");
    let out = flag(args, "--out").map(std::path::Path::new);
    match out {
        None if !plan_only => {
            return Err("an exit is never submitted from here: an Annulet net refuses one by name (it has no bridge), and a \
                        V6 bundle is assembled by a sequencer (lab #831 W4). Pass --out FILE to write the proven \
                        transaction, or --plan-only"
                .into())
        }
        // Before anything is read or proved: a 30 GiB proof must never be
        // lost to a path that cannot take it, nor overwrite a file.
        Some(path) => refuse_out_path(path)?,
        None => {}
    }
    let to = flag(args, "--exit-to").expect("routed here on --exit-to");
    let to = qlab_wallet::address::Address::decode(to).ok_or("--exit-to is not a wallet address (the L1 recipient)")?;
    let pin = Some(required_pin(args, "exit")?);
    let w = WalletDir::open(&dir)?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    eprintln!(
        "net: annulet (from --net; verifying genesis bytes against --genesis-hash, the seal chain and each note's block)"
    );
    let endpoint = qumbra_wallet::annulet_send::WalletEndpoint { url: url.to_string() };
    let mut on_plan = |plan: &qumbra_wallet::annulet_send::ExitPlan| {
        print!("{plan}");
        !plan_only
    };
    let (plan, built, genesis) = match qumbra_wallet::annulet_send::exit_annulet(&w, endpoint, amount, &to, scan_to, pin, &mut on_plan, &mut rng) {
        Err(qumbra_wallet::annulet_send::SendRefusal::PlanDeclined) if plan_only => {
            println!("--plan-only: nothing proved or written");
            return Ok(());
        }
        other => other?,
    };
    let out = out.expect("checked above");
    write_new_atomically(out, &qlab_l2spend::encode_exit_artifact(&genesis, &built.tx))?;
    println!(
        "wrote {}: the proven exit of {} (fee {}, change {} back) — version {} of the exit file, bound to this chain's \
         genesis; it is paid on L1 only once a V6 bundle carries it",
        out.display(),
        plan.value,
        plan.fee,
        plan.change,
        qlab_l2spend::EXIT_ARTIFACT_VERSION
    );
    Ok(())
}

/// `--out` checked before anything is read or proved (lab #831 W2 X1): a
/// proof must never be lost to a path that cannot take it, nor overwrite a
/// file.
fn refuse_out_path(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Err(format!("--out {}: the file exists; refusing to overwrite it", path.display()).into());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    if !parent.is_dir() {
        return Err(format!("--out {}: the directory {} does not exist", path.display(), parent.display()).into());
    }
    Ok(())
}

/// Write `bytes` to `path`, which must not exist: into a sibling temporary
/// created with `create_new`, synced, then hard-linked to `path` (which fails
/// rather than replace a file that appeared meanwhile) and the temporary
/// removed. A failure after the write names the temporary that still holds
/// the bytes, so nothing proved is lost to a path error.
fn write_new_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    if let Err(e) = std::fs::hard_link(&tmp, path) {
        return Err(format!("{} could not be created ({e}); the proven exit is kept in {}", path.display(), tmp.display()).into());
    }
    std::fs::remove_file(&tmp)?;
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
    use super::{names_register_with, resolve_net, resolve_send_amount, NetSource};

    /// Lab #821: `ivk export` never prints to a terminal without the flag,
    /// and the refusal names the data class and the flag.
    #[test]
    fn ivk_export_refuses_a_terminal_without_the_flag() {
        use super::{ivk_export_gate, IVK_ACK};
        assert!(ivk_export_gate(false, false).is_ok(), "a pipe needs no flag");
        assert!(ivk_export_gate(true, true).is_ok(), "the flag admits a terminal");
        let why = ivk_export_gate(true, false).unwrap_err();
        assert!(why.contains(IVK_ACK) && why.contains("cannot spend"), "{why}");
    }
    use qlab_devnet::body::{TxEntry, TxPublic};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::forms::GenesisForm;
    use qlab_devnet::names::{
        encode_rider, NameRecord, COMMIT_MAX_AGE, COMMIT_MIN_AGE, L1_ADDRESS_LEN,
        RECORD_KIND_L1_ADDRESS,
    };
    use qumbra_wallet::names::RegisterState;
    use std::cell::{Cell, RefCell};

    #[test]
    fn unconfirmed_reveal_is_retained_and_reposted_byte_identically() {
        let dir = std::env::temp_dir().join(format!("qw-i625-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = RegisterState::new(
            "alice",
            NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xA5; L1_ADDRESS_LEN],
            },
            [0x62; 32],
        );
        state.commit_attempted = true;
        state.committed_at = Some(9_000);
        state.save(&dir).unwrap();

        let args = vec![
            "alice".to_string(),
            "--dir".to_string(),
            dir.display().to_string(),
            "--scan-to".to_string(),
            (9_000 + COMMIT_MIN_AGE).to_string(),
        ];
        let submitted = RefCell::new(Vec::new());
        let builds = Cell::new(0u8);
        let mut observe = |_: &[String], _: &RegisterState, _: u64| Ok(None);
        let mut build_and_submit = |
            _: &[String],
            op: &qlab_devnet::names::NameOp,
            _: &str,
            preserve: &mut dyn FnMut(&[u8]) -> Result<(), String>,
        | {
            // Model the real builder's randomized proof: rebuilding the same
            // reveal deliberately changes the canonical wire. The retry path
            // must retain and resubmit the FIRST bytes, not merely reconstruct
            // the same rider from the saved salt and record.
            let build = builds.get();
            builds.set(build + 1);
            let tx = TxEntry { auth: qlab_devnet::annulet::L2_AUTH_ABSENT.to_vec(), l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(),
                proof: vec![build],
                public: TxPublic {
                    anchor: [0x11; 32],
                    nullifiers: vec![[0x21; 32], [0x22; 32]],
                    commitments: vec![[0x31; 32], [0x32; 32]],
                    bucket: ArityBucket::TwoByTwo,
                    fee: qlab_devnet::names::name_fee_for(op),
                },
                discovery: vec![0x41],
                rider: encode_rider(Some(op)),
            };
            let wire = qlab_p2p::codec::encode_tx(&tx);
            preserve(&wire)?;
            submitted.borrow_mut().push(wire);
            Ok(())
        };
        let mut repost = |_: &[String], wire: &[u8], _: &str| {
            submitted.borrow_mut().push(wire.to_vec());
            Ok(())
        };

        names_register_with(&args, &mut observe, &mut build_and_submit, &mut repost).unwrap();
        let retained = RegisterState::load(&dir).unwrap().expect(
            "an accepted POST is not chain confirmation; the salt and retry state must remain",
        );
        assert_eq!(retained.salt, state.salt);
        assert_eq!(retained.record, state.record);
        assert!(retained.reveal_tx.is_some(), "the exact first wire is durable");

        names_register_with(&args, &mut observe, &mut build_and_submit, &mut repost).unwrap();
        let submitted = submitted.borrow();
        assert_eq!(submitted.len(), 2, "the unconfirmed reveal is posted again");
        assert_eq!(builds.get(), 1, "retry must not rebuild a randomized proof");
        assert_eq!(
            submitted[0], submitted[1],
            "retry must submit the exact first transaction, not rebuild randomized bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_observed_reveal_clears_without_reposting() {
        let dir = std::env::temp_dir().join(format!("qw-i625-confirm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = RegisterState::new(
            "alice",
            NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xA6; L1_ADDRESS_LEN],
            },
            [0x63; 32],
        );
        state.commit_attempted = true;
        state.committed_at = Some(10_000);
        state.reveal_tx = Some(vec![0x51, 0x36, 0x32]);
        state.save(&dir).unwrap();
        let confirmed = 10_000 + COMMIT_MIN_AGE;
        let args = vec![
            "alice".to_string(),
            "--dir".to_string(),
            dir.display().to_string(),
            "--scan-to".to_string(),
            confirmed.to_string(),
        ];

        names_register_with(
            &args,
            |_, _, _| Ok(Some(confirmed)),
            |_, _, _, _| panic!("a confirmed reveal must not build"),
            |_, _, _| panic!("a confirmed reveal must not re-post"),
        )
        .unwrap();
        assert_eq!(RegisterState::load(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn window_closing_still_clears_and_refuses_salt_reuse() {
        let dir = std::env::temp_dir().join(format!("qw-i625-closed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = RegisterState::new(
            "alice",
            NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xA7; L1_ADDRESS_LEN],
            },
            [0x64; 32],
        );
        state.commit_attempted = true;
        state.committed_at = Some(11_000);
        state.reveal_tx = Some(vec![0x51, 0x36, 0x33]);
        state.save(&dir).unwrap();
        let args = vec![
            "alice".to_string(),
            "--dir".to_string(),
            dir.display().to_string(),
            "--scan-to".to_string(),
            (11_000 + COMMIT_MAX_AGE + 1).to_string(),
        ];

        let err = names_register_with(
            &args,
            |_, _, _| Ok(None),
            |_, _, _, _| panic!("a closed window must not build"),
            |_, _, _| panic!("a closed window must not re-post"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("salt will not be reused"), "{err}");
        assert_eq!(RegisterState::load(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn net_resolution_precedence() {
        // The flag wins over everything, including a stamp that disagrees — a
        // T2-stamped wallet must still be able to read a T1 endpoint.
        assert_eq!(resolve_net(Some("t1"), Some("t2")).unwrap(), (GenesisForm::V4, NetSource::Flag));
        assert_eq!(resolve_net(Some("t2"), Some("t1")).unwrap(), (GenesisForm::V5, NetSource::Flag));

        // No flag: the stamp decides. THIS is lab #581 — before it, both of these
        // resolved to V4 and a T2 miner's own release derived under T1.
        assert_eq!(resolve_net(None, Some("t2")).unwrap(), (GenesisForm::V5, NetSource::Stamp));
        assert_eq!(resolve_net(None, Some("t1")).unwrap(), (GenesisForm::V4, NetSource::Stamp));

        // Unstamped and unasked — a plain `cargo build`. Unchanged from before
        // #581, so no developer's existing command moves.
        assert_eq!(resolve_net(None, None).unwrap(), (GenesisForm::V4, NetSource::Fallback));
    }

    /// Lab #718/#720: `--net annulet` belongs to `scan` and `send`; every other
    /// command here is an L1 flow and refuses it by name.
    #[test]
    fn net_annulet_outside_scan_is_refused_by_name() {
        let err = resolve_net(Some("annulet"), None).unwrap_err().to_string();
        assert!(err.contains("accepted by `scan` and `send` only"), "{err}");
    }

    #[test]
    fn an_unknown_net_refuses_and_says_whose_fault_it_is() {
        // From the user: it is their flag, and the message names the flag.
        let err = resolve_net(Some("t3"), None).unwrap_err().to_string();
        assert!(err.contains("--net t3"), "{err}");
        assert!(err.contains("t1, t2"), "{err}");

        // From the lane: NOT user error, and it must not fall through to t1 —
        // falling through is exactly how a T2 artifact would behave as T1.
        let err = resolve_net(None, Some("t3")).unwrap_err().to_string();
        assert!(err.contains("release-lane defect"), "{err}");
        assert!(err.contains("not something you did"), "{err}");
    }

    #[test]
    fn every_source_describes_itself_distinctly() {
        // The line printed on every command is the only thing standing between a
        // user and a silent default, so the three cases must not read alike.
        let all = [NetSource::Flag, NetSource::Stamp, NetSource::Fallback];
        for (i, a) in all.iter().enumerate() {
            assert!(!a.describe().is_empty());
            for b in &all[i + 1..] {
                assert_ne!(a.describe(), b.describe());
            }
        }
    }

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
