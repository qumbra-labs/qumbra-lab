//! **Candidate A spend fixtures for a shell's harness** (lab #924 PR 3, the
//! 4b kernel).
//!
//! The extension runs `qmb_auth_*` / `qmb_spend_v2_*` / `qmb_intent_*` from
//! JavaScript over its wasm build. This example RECORDS the native run of the
//! same calls — the scan that yields the basis, the spend's served reads,
//! the take, the intent, the review, the signature — against qumbra-wallet's
//! fixture `Endpoint` on a format-33 genesis, every path the kernel asked in
//! order with its exact answer. ML-DSA signing is deterministic and every
//! random input is host-given, so the harness, replaying the transcripts
//! through its wasm build with the same inputs, must reproduce **the same
//! intent, review and bundle bytes**.
//!
//! **Every seed here is the FIXTURE's** — wallet entropy `[0x4B; 32]`, the
//! payee's `[0x4C; 32]`, the sequencer seed, the scan rng, the spend seed and
//! the dummy entropy — public test bytes, never a real wallet's and never to
//! be used for one.
//!
//! Output (refused if `<out>` exists, unless `--force`):
//!   <out>/manifest.json            lab rev, the inputs, the cases
//!   <out>/<case>/case.json         the request, both transcripts, the files
//!   <out>/<case>/scan/NNN.bin      the scan's answers, transcript order
//!   <out>/<case>/spend/NNN.bin     the spend's answers, transcript order
//!   <out>/<case>/journal_before.txt, journal_after.txt   auth.v1 text
//!   <out>/<case>/intent.bin, review.txt, bundle.bin      the kernel's output
//!   <out>/<case>/list.json, list.sig  the asset list the scan was given (a
//!                                  case with one; signed with the TEST list
//!                                  key — `test-support`, dev-only)
//!   <out>/<case>/auth/NNN.bin      the open-time check's bodies (PR 3b)
//!   <out>/<auth case>/             first / restore / stale-check / revive /
//!                                  rotated cases: journal_in.txt,
//!                                  journal_out.txt, case.json (status,
//!                                  refusal, the basis summary, wall ms),
//!                                  summary.json (each journal through
//!                                  qmb_auth_journal_summary, PR 3f); the
//!                                  scan names the journal's generations
//!                                  (restore and first: the probe 0..8)
//!   <out>/check_stale/then_restore/  the restore the STALE status asks for
//!   <out>/rotated_receive/         the rotated journal on a chain paying its
//!                                  generation-1 address; only_g0/ holds the
//!                                  same wallet's scan naming [0] alone, and
//!                                  case.json's scan_only_g0 its basis (which
//!                                  must miss that note)
//!   <out>/SHA256SUMS               every file above, `sha256sum -c` form
//!
//! Run (a named local run, no prove):
//!   cargo run -p qumbra-ffi --example annulet_spend_fixtures -- <out> --lab-rev <commit> [--force]

#[path = "../../qumbra-wallet/tests/common/mod.rs"]
mod common;

use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;

use common::*;
use qlab_devnet::body::BlockBody;
use qumbra_ffi::annulet::{qmb_annulet_free, qmb_annulet_new_v2, qmb_annulet_step, qmb_annulet_supply, qmb_annulet_supply_err, qmb_annulet_take_basis};
use qumbra_ffi::spend_v2::{
    qmb_auth_check_finish, qmb_auth_check_free, qmb_auth_check_new, qmb_auth_check_step, qmb_auth_check_supply,
    qmb_auth_check_supply_err, qmb_auth_first_new, qmb_auth_open_next, qmb_auth_restore_new, qmb_spend_basis_free,
    qmb_auth_journal_summary, qmb_spend_basis_summary, AuthHandle, SpendBasis,
    qmb_auth_free, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_v2_free, qmb_spend_v2_intent,
    qmb_spend_v2_new, qmb_spend_v2_step, qmb_spend_v2_supply, qmb_spend_v2_supply_err,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal, GenState, Generation};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

const SEED: u8 = 0x4B;
const PAYEE: u8 = 0x4C;
const RNG: [u8; 32] = [0x59; 32];
const SPEND_SEED: [u8; 32] = [0x5A; 32];
const DUMMIES: [u8; 64] = [0x5B; 64];
const VALID_FOR: u64 = 96;
/// The generations a restore or first scans: it has no journal to name them.
const PROBE: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

unsafe fn take_str(p: *mut c_char) -> String {
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    qmb_string_free(p);
    s
}

/// Answer `path` from `ep`, recording it as transcript entry `n` in `dir`.
fn answer(dir: &Path, n: usize, ep: &Endpoint, path: &str) -> (Value, Result<Vec<u8>, String>) {
    match ep.fetch(path) {
        Ok(body) => {
            let file = format!("{n:03}.bin");
            std::fs::write(dir.join(&file), &body).unwrap();
            (json!({ "path": path, "ok": true, "file": file, "len": body.len() }), Ok(body))
        }
        Err(why) => (json!({ "path": path, "ok": false, "error": why }), Err(why)),
    }
}

/// The fixture chain: the payer's v2 address 0 holds 1,000,000 USDT-test
/// (Hybrid), 50 and 2 fee units at genesis and 5 more at height 1.
fn chain(extra: Option<qlab_devnet::body::TxEntry>) -> (Endpoint, String, String) {
    let w = wallet_dir("spend_fixtures", SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let mut rng = StdRng::seed_from_u64(0x4B);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let file = genesis_v2(&a2, vec![note_to(&a2, 50, 0, 30), note_to(&a2, 2, 0, 40)]);
    let mut bodies = vec![body];
    if let Some(tx) = extra {
        bodies.push(BlockBody { txs: vec![tx], ..BlockBody::default() });
    }
    let ep = Endpoint::new(file, &bodies, None, Lie::None);
    let _ = std::fs::remove_dir_all(&w.dir);
    let p = wallet_dir("spend_fixtures_payee", PAYEE);
    let pw = p.wallet();
    let payee = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0)).encode();
    let _ = std::fs::remove_dir_all(&p.dir);
    (ep, payee, AuthJournal::fresh(root).to_text())
}

/// PR 3h: a payment of 7 fee units to the fixture wallet's GENERATION-1
/// address 0 — an address only `qmb_auth_open_next` hands out
/// (`qmb_wallet_address_v2(w, 0, 1)`).
fn g1_payment() -> qlab_devnet::body::TxEntry {
    let w = wallet_dir("spend_fixtures_g1", SEED);
    let wallet = w.wallet();
    let g1 = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 1));
    let _ = std::fs::remove_dir_all(&w.dir);
    let mut rng = StdRng::seed_from_u64(0x61);
    pay_tx(&g1, &[note_to(&g1, 7, 0, 60)], 0x40, &mut rng)
}

/// The fixture wallet's two-generation journal: generation 0 (cursor 0) in
/// `g0`, generation 1 active and fresh.
fn journal_of(g0: GenState) -> String {
    let w = wallet_dir("spend_fixtures_journal", SEED);
    let wallet = w.wallet();
    let gens = vec![
        Generation { g: 0, next: 0, auth_root: generation_root(&wallet, 0), state: g0 },
        Generation { g: 1, next: 0, auth_root: generation_root(&wallet, 1), state: GenState::Active },
    ];
    let _ = std::fs::remove_dir_all(&w.dir);
    AuthJournal::from_generations(gens).unwrap().to_text()
}

/// (bytes, signature) of a TEST-signed list naming USDT-test on `genesis`
/// under the genesis issuer key.
fn list_for(genesis: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let issuer = hex(&qlab_node::annulet_genesis::h32(&[9, 9, 9, 9]));
    let bytes = format!(
        r#"{{"v":1,"network":"annulet-ad1","genesis":"{}","testnet":true,"assets":[{{"id":1,"issuer_key":"{issuer}","name":"Tether USD (test)","ticker":"tUSDT","decimals":6}}]}}"#,
        hex(genesis)
    )
    .into_bytes();
    let sig = qumbra_wallet::asset_view::test_list_key::sign(&bytes);
    (bytes, sig)
}

/// The verified scan through the ABI, recorded into `dir/scan`: its basis.
unsafe fn scan_basis(
    dir: &Path,
    w: *mut qumbra_ffi::WalletState,
    ep: &Endpoint,
    list: Option<&(Vec<u8>, Vec<u8>)>,
    gens: &[u32],
) -> (*mut SpendBasis, Vec<Value>) {
    std::fs::create_dir_all(dir.join("scan")).unwrap();
    let endpoint = CString::new("fixture").unwrap();
    let pin = ep.file.hash();
    let indices = [0u64, 1];
    let null = ptr::null();
    let mut err: *mut c_char = ptr::null_mut();
    let key = qumbra_wallet::asset_view::test_list_key::encoded();
    let (lp, ll, sp, sl, kp, kl) = match list {
        Some((b, s)) => {
            std::fs::write(dir.join("list.json"), b).unwrap();
            std::fs::write(dir.join("list.sig"), s).unwrap();
            (b.as_ptr(), b.len(), s.as_ptr(), s.len(), key.as_ptr(), key.len())
        }
        None => (null, 0, null, 0, null, 0),
    };
    let s = qmb_annulet_new_v2(
        w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, lp, ll, sp, sl, kp,
        kl, ptr::null(), gens.as_ptr(), gens.len(), &mut err,
    );
    assert!(!s.is_null());
    let mut scan = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_annulet_step(s, &mut out) {
            1 => {
                let (entry, a) = answer(&dir.join("scan"), scan.len(), ep, &take_str(out));
                scan.push(entry);
                match a {
                    Ok(b) => qmb_annulet_supply(s, b.as_ptr(), b.len()),
                    Err(e) => qmb_annulet_supply_err(s, CString::new(e).unwrap().as_ptr()),
                }
            }
            0 => break,
            other => panic!("scan step {other}"),
        }
    }
    let basis = qmb_annulet_take_basis(s);
    qmb_annulet_free(s);
    assert!(!basis.is_null());
    (basis, scan)
}

/// Which open the auth phase runs.
enum Open<'a> {
    /// The journal and the generation to open.
    Check(&'a str, u32),
    First,
    Restore,
}

/// What the auth phase returned.
struct Opened {
    a: Option<*mut AuthHandle>,
    journal: Option<String>,
    status: i32,
    refusal: Option<String>,
    transcript: Vec<Value>,
    millis: u128,
}

/// The open-time check (or first / restore) through the ABI, its bodies
/// recorded into `dir/auth`.
unsafe fn auth_phase(dir: &Path, w: *mut qumbra_ffi::WalletState, ep: &Endpoint, basis: *const SpendBasis, open: Open) -> Opened {
    std::fs::create_dir_all(dir.join("auth")).unwrap();
    let started = std::time::Instant::now();
    let mut err: *mut c_char = ptr::null_mut();
    let c = match open {
        Open::Check(journal, g) => {
            let j = CString::new(journal).unwrap();
            qmb_auth_check_new(w, j.as_ptr(), basis, g, &mut err)
        }
        Open::First => qmb_auth_first_new(w, basis, &mut err),
        Open::Restore => qmb_auth_restore_new(w, basis, &mut err),
    };
    assert!(!c.is_null(), "{}", take_str(err));
    let mut transcript = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_auth_check_step(c, &mut out) {
            1 => {
                let (entry, ans) = answer(&dir.join("auth"), transcript.len(), ep, &take_str(out));
                transcript.push(entry);
                match ans {
                    Ok(b) => qmb_auth_check_supply(c, b.as_ptr(), b.len()),
                    Err(e) => qmb_auth_check_supply_err(c, CString::new(e).unwrap().as_ptr()),
                }
            }
            0 => break,
            other => panic!("check step {other}: {}", take_str(out)),
        }
    }
    let (mut jout, mut status) = (ptr::null_mut(), -1i32);
    let a = qmb_auth_check_finish(w, c, &mut jout, &mut status, &mut err);
    qmb_auth_check_free(c);
    let journal = (!jout.is_null()).then(|| take_str(jout));
    let refusal = (a.is_null() && !err.is_null()).then(|| take_str(err));
    Opened { a: (!a.is_null()).then_some(a), journal, status, refusal, transcript, millis: started.elapsed().as_millis() }
}

/// An open-only case (lab #924 PR 3b, the extension's e2e): `open` on `ep`,
/// recorded into `dir`.
unsafe fn auth_case(dir: &Path, ep: &Endpoint, open: Open, journal_in: Option<&str>) -> Value {
    std::fs::create_dir_all(dir).unwrap();
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    // The host scans every generation its journal names; with none, the probe.
    let gens: Vec<u32> = match journal_in {
        Some(j) => AuthJournal::from_text(j).unwrap().generations().iter().map(|g| g.g).collect(),
        None => PROBE.to_vec(),
    };
    let (basis, scan) = scan_basis(dir, w, ep, None, &gens);
    let summary: Value = serde_json::from_str(&take_str(qmb_spend_basis_summary(basis))).unwrap();
    let o = auth_phase(dir, w, ep, basis, open);
    qmb_spend_basis_free(basis);
    if let Some(a) = o.a {
        qmb_auth_free(a);
    }
    qmb_wallet_free(w);
    if let Some(j) = journal_in {
        std::fs::write(dir.join("journal_in.txt"), j).unwrap();
    }
    if let Some(j) = &o.journal {
        std::fs::write(dir.join("journal_out.txt"), j).unwrap();
    }
    // PR 3f: what the shell shows and scans — each journal through qmb_auth_journal_summary.
    let summarize = |text: &str| {
        let t = CString::new(text).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let out = qmb_auth_journal_summary(t.as_ptr(), &mut err);
        assert!(!out.is_null(), "{}", take_str(err));
        serde_json::from_str::<Value>(&take_str(out)).unwrap()
    };
    let journals = json!({
        "journal_in": journal_in.map(summarize),
        "journal_out": o.journal.as_deref().map(summarize),
    });
    std::fs::write(dir.join("summary.json"), serde_json::to_vec_pretty(&journals).unwrap()).unwrap();
    json!({
        "journal_in": journal_in.map(|_| "journal_in.txt"),
        "journal_out": o.journal.as_ref().map(|_| "journal_out.txt"),
        "summary": "summary.json",
        "status": o.status,
        "keys": o.a.is_some(),
        "refusal": o.refusal,
        "scan_generations": gens,
        "basis": summary,
        "scan": scan,
        "auth": o.transcript,
        "wall_ms_native": o.millis,
    })
}

/// One whole spend through the ABI, recorded into `dir`.
unsafe fn case(
    dir: &Path,
    ep: &Endpoint,
    payee: &str,
    journal: &str,
    asset: u16,
    amount: u64,
    list: Option<&(Vec<u8>, Vec<u8>)>,
) -> Value {
    std::fs::create_dir_all(dir.join("spend")).unwrap();
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let mut err: *mut c_char = ptr::null_mut();
    let (basis, scan) = scan_basis(dir, w, ep, list, &[0]);
    // The keys: the open-time check of the account's journal.
    let opened = auth_phase(dir, w, ep, basis, Open::Check(journal, 0));
    let a = opened.a.expect("the fresh journal opens");
    let checked = opened.journal.clone().expect("a checked journal");
    let to = CString::new(payee).unwrap();
    let sp = qmb_spend_v2_new(basis, to.as_ptr(), asset, amount, VALID_FOR, SPEND_SEED.as_ptr(), DUMMIES.as_ptr(), &mut err);
    assert!(!sp.is_null(), "{}", take_str(err));
    let mut spend = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_spend_v2_step(a, sp, &mut out) {
            1 => {
                let (entry, ans) = answer(&dir.join("spend"), spend.len(), ep, &take_str(out));
                spend.push(entry);
                match ans {
                    Ok(b) => qmb_spend_v2_supply(sp, b.as_ptr(), b.len()),
                    Err(e) => qmb_spend_v2_supply_err(sp, CString::new(e).unwrap().as_ptr()),
                }
            }
            0 => break,
            other => panic!("spend step {other}: {}", take_str(out)),
        }
    }
    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(qmb_auth_take(a, sp, &mut out), 0);
    let after = take_str(out);
    let mut len = 0usize;
    let ip = qmb_spend_v2_intent(sp, &mut len);
    let intent = std::slice::from_raw_parts(ip, len).to_vec();
    qmb_dealloc(ip, len);
    let review = take_str(qmb_intent_review(sp, intent.as_ptr(), intent.len(), &mut err));
    let after_c = CString::new(after.clone()).unwrap();
    let mut blen = 0usize;
    let bp = qmb_intent_sign(a, sp, intent.as_ptr(), intent.len(), after_c.as_ptr(), &mut blen, &mut err);
    assert!(!bp.is_null(), "{}", take_str(err));
    let bundle = std::slice::from_raw_parts(bp, blen).to_vec();
    qmb_dealloc(bp, blen);
    qmb_spend_v2_free(sp);
    qmb_auth_free(a);
    qmb_wallet_free(w);

    std::fs::write(dir.join("journal_before.txt"), journal).unwrap();
    std::fs::write(dir.join("journal_checked.txt"), &checked).unwrap();
    std::fs::write(dir.join("journal_after.txt"), &after).unwrap();
    std::fs::write(dir.join("intent.bin"), &intent).unwrap();
    std::fs::write(dir.join("review.txt"), &review).unwrap();
    std::fs::write(dir.join("bundle.bin"), &bundle).unwrap();
    json!({
        "request": { "to": payee, "asset": asset, "amount": amount.to_string(), "valid_for": VALID_FOR },
        "list": list.map(|_| json!({ "bytes": "list.json", "sig": "list.sig" })),
        "scan": scan,
        "auth": opened.transcript,
        "auth_status": opened.status,
        "spend": spend,
        "files": {
            "journal_before": "journal_before.txt", "journal_checked": "journal_checked.txt", "journal_after": "journal_after.txt",
            "intent": "intent.bin", "review": "review.txt", "bundle": "bundle.bin",
        },
        "intent_len": intent.len(),
        "bundle_len": bundle.len(),
    })
}

/// `--force` removes `<out>`: never `/`, the home directory, the working
/// directory or one of its ancestors, and only a directory this example
/// wrote (it holds `manifest.json`).
fn guarded_remove(out: &Path) {
    let abs = std::fs::canonicalize(out).expect("canonical <out>");
    let cwd = std::fs::canonicalize(".").expect("canonical cwd");
    let home = std::env::var_os("HOME").map(PathBuf::from).and_then(|h| std::fs::canonicalize(h).ok());
    assert!(abs.parent().is_some(), "refusing to remove {}", abs.display());
    assert!(!cwd.starts_with(&abs), "refusing to remove {} (the working directory or an ancestor)", abs.display());
    assert!(home.as_deref() != Some(abs.as_path()), "refusing to remove the home directory");
    assert!(abs.join("manifest.json").is_file(), "refusing to remove {}: not a fixtures directory", abs.display());
    std::fs::remove_dir_all(&abs).unwrap();
}

/// `sha256sum -c` lines for every file under `root`, sorted.
fn sha256sums(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();
    files
        .iter()
        .map(|p| {
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            format!("{}  {rel}\n", hex(&Sha256::digest(std::fs::read(p).unwrap())))
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = PathBuf::from(args.first().expect("usage: <out> --lab-rev <commit> [--force]"));
    let rev = args.iter().position(|a| a == "--lab-rev").and_then(|i| args.get(i + 1)).expect("--lab-rev <commit>");
    if out.exists() {
        assert!(args.iter().any(|a| a == "--force"), "{} exists (use --force)", out.display());
        guarded_remove(&out);
    }
    std::fs::create_dir_all(&out).unwrap();
    let (ep, payee, journal) = chain(None);
    let mut cases = serde_json::Map::new();
    let usdt_list = list_for(&ep.file.hash());
    for (name, asset, amount, list) in [("s_asset0", 0u16, 10u64, None), ("p_usdt", USDT as u16, 1_000, Some(&usdt_list))] {
        let dir = out.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let c = unsafe { case(&dir, &ep, &payee, &journal, asset, amount, list) };
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<10} {} scan + {} spend reads → bundle {} B", c["scan"].as_array().unwrap().len(), c["spend"].as_array().unwrap().len(), c["bundle_len"]);
        cases.insert(name.into(), json!(name));
    }
    // PR 3b's open cases. The spent chain: s_asset0's bundle landed at height 2
    // (its transaction, a placeholder proof — the fixture chain seals
    // without verifying).
    let mut landed = qlab_l2spend::bundle::ProvingBundle::decode(&std::fs::read(out.join("s_asset0/bundle.bin")).unwrap())
        .unwrap()
        .tx()
        .clone();
    landed.proof = vec![0xAB; 64];
    let (spent, _, _) = chain(Some(landed));
    // retired_revive: generation 0 retired while it still holds the
    // chain's notes, generation 1 active → check(0) revives it (F9).
    let retired = journal_of(GenState::Retired);
    // rotated_balance: open_next on the fresh journal (generation 0 becomes
    // sweep-only behind a gate, 1 active) while 0 holds every note.
    let rotated = unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let scratch = out.join("rotated_balance/open_next");
        let (b, _) = scan_basis(&scratch, w, &ep, None, &[0]);
        let j = CString::new(journal.as_str()).unwrap();
        let mut o: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_open_next(w, j.as_ptr(), b, &mut o), 0, "{}", take_str(o));
        qmb_spend_basis_free(b);
        qmb_wallet_free(w);
        std::fs::remove_dir_all(&scratch).unwrap();
        take_str(o)
    };
    // rotated_receive (PR 3h): the same rotated journal on a chain where a
    // note lands at height 2 on generation 1's address. A scan that names
    // every journal generation ([0, 1]) owns it; one that names only [0]
    // does not — the balance a shell loses by scanning too few generations.
    let (received, _, _) = chain(Some(g1_payment()));
    for (name, chain_ep, open, journal_in) in [
        ("first_unspent", &ep, Open::First, None),
        ("restore_spent", &spent, Open::Restore, None),
        ("check_stale", &spent, Open::Check(&journal, 0), Some(journal.as_str())),
        ("first_spent", &spent, Open::First, None),
        ("retired_revive", &ep, Open::Check(&retired, 0), Some(retired.as_str())),
        ("rotated_balance", &ep, Open::Check(&rotated, 0), Some(rotated.as_str())),
        ("rotated_receive", &received, Open::Check(&rotated, 0), Some(rotated.as_str())),
    ] {
        let dir = out.join(name);
        let mut c = unsafe { auth_case(&dir, chain_ep, open, journal_in) };
        if name == "check_stale" {
            // What STALE asks of the host: persist journal_out, tell the
            // user, run the restore.
            let then = unsafe { auth_case(&dir.join("then_restore"), chain_ep, Open::Restore, None) };
            println!("  then_restore status {} keys {} {} ms", then["status"], then["keys"], then["wall_ms_native"]);
            c["then_restore"] = then;
        }
        if name == "rotated_balance" || name == "rotated_receive" {
            c["journal_in_made_by"] = json!("qmb_auth_open_next on the fresh journal, basis scanned at [0] on the unspent chain");
        }
        if name == "rotated_receive" {
            // The same wallet's scan naming generation 0 alone, recorded into
            // `only_g0/`: its basis must miss the generation-1 note.
            let only_g0 = unsafe {
                let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
                let (b, scan) = scan_basis(&dir.join("only_g0"), w, chain_ep, None, &[0]);
                let basis: Value = serde_json::from_str(&take_str(qmb_spend_basis_summary(b))).unwrap();
                qmb_spend_basis_free(b);
                qmb_wallet_free(w);
                json!({ "scan_generations": [0], "basis": basis, "scan": scan })
            };
            let g1_notes = |basis: &Value| {
                basis["owned"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|n| n["generation"] == json!(1) && n["value"] == json!("7"))
                    .count()
            };
            assert_eq!(g1_notes(&c["basis"]), 1, "the [0, 1] scan owns the generation-1 note: {}", c["basis"]);
            assert_eq!(g1_notes(&only_g0["basis"]), 0, "the [0] scan does not: {}", only_g0["basis"]);
            println!("  rotated_receive: g1 note owned by the [0,1] scan, not by the [0] scan");
            c["scan_only_g0"] = only_g0;
        }
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<14} status {} keys {} {} ms{}", c["status"], c["keys"], c["wall_ms_native"], c["refusal"].as_str().map(|r| format!(" — {r}")).unwrap_or_default());
        cases.insert(name.into(), json!(name));
    }
    // (v) first_fresh refused on the three outside doors, for the fixture seed.
    // (vi) a seed born here: first_fresh's journal == first's for the same
    // seed on a chain with no block. Its entropy is drawn by the kernel, so
    // this case differs run to run: the harness checks the equality, not
    // bytes; the drawn entropy is written (a throwaway, never funded).
    unsafe {
        let dir = out.join("first_fresh");
        std::fs::create_dir_all(&dir).unwrap();
        let fixture_seed = [SEED; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let h0 = qmb_wallet_from_entropy(fixture_seed.as_ptr());
        let phrase = take_str(qumbra_ffi::qmb_wallet_reveal_mnemonic(h0));
        qmb_wallet_free(h0);
        let outside = [
            ("from_entropy", qmb_wallet_from_entropy(fixture_seed.as_ptr())),
            ("from_parts", qumbra_ffi::qmb_wallet_from_parts(qlab_wallet::seed::SEED_VERSION, fixture_seed.as_ptr(), &mut err)),
            ("restore", qumbra_ffi::qmb_wallet_restore(CString::new(phrase).unwrap().as_ptr(), &mut err)),
        ];
        let mut refused = serde_json::Map::new();
        for (door, h) in outside {
            let mut jout: *mut c_char = ptr::null_mut();
            let rc = qumbra_ffi::spend_v2::qmb_auth_first_fresh(h, &mut jout);
            refused.insert(door.into(), json!({ "rc": rc, "refusal": take_str(jout) }));
            qmb_wallet_free(h);
        }
        let born = qumbra_ffi::qmb_wallet_new_fresh();
        let mut jout: *mut c_char = ptr::null_mut();
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, &mut jout), 0);
        let fresh = take_str(jout);
        let mut entropy = [0u8; 32];
        qumbra_ffi::qmb_wallet_seed_entropy(born, entropy.as_mut_ptr());
        let w = qmb_wallet_from_entropy(entropy.as_ptr());
        let p = wallet_dir("spend_fixtures_holder", PAYEE);
        let holder = p.wallet().address_candidate_a_at_index(0, &generation_root(&p.wallet(), 0));
        let _ = std::fs::remove_dir_all(&p.dir);
        let empty = Endpoint::new(genesis_v2(&holder, Vec::new()), &[], None, Lie::None);
        let (basis, _) = scan_basis(&dir, w, &empty, None, &PROBE);
        let o = auth_phase(&dir, w, &empty, basis, Open::First);
        qmb_spend_basis_free(basis);
        if let Some(a) = o.a {
            qmb_auth_free(a);
        }
        let first = o.journal.clone().unwrap_or_default();
        std::fs::write(dir.join("journal_first_fresh.txt"), &fresh).unwrap();
        std::fs::write(dir.join("journal_first_empty_chain.txt"), &first).unwrap();
        let c = json!({
            "outside_doors_refused": refused,
            "born_entropy_throwaway": hex(&entropy),
            "first_fresh_equals_first_on_empty_chain": fresh == first,
            "first_status": o.status,
        });
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("first_fresh    equal {} · outside doors refused {}", fresh == first, refused.values().all(|v| v["rc"] == -1));
        qmb_wallet_free(w);
        qmb_wallet_free(born);
        cases.insert("first_fresh".into(), json!("first_fresh (varies run to run: entropy drawn by the kernel)"));
    }
    // The seeds below are PUBLIC TEST CONSTANTS of this fixture, written so the
    // harness can replay the run — never a real wallet's, never to fund one.
    let manifest = json!({
        "what": "lab #924 PR 3/3b — Candidate A spend and open fixtures, recorded from the real ABI (scan → basis → checked open → spend → take → intent → review → sign; first / restore / stale-check then restore / retired revive / rotated balance / rotated receive) on a format-33 genesis. FIXTURE seeds only.",
        "lab_rev": rev,
        "wallet_entropy": hex(&[SEED; 32]),
        "payee_entropy": hex(&[PAYEE; 32]),
        "pin": hex(&ep.file.hash()),
        "scan_rng": hex(&RNG),
        "spend_seed": hex(&SPEND_SEED),
        "dummy_entropy": hex(&DUMMIES),
        "indices": [0, 1],
        "list_key": hex(&qumbra_wallet::asset_view::test_list_key::encoded()),
        "cases": cases,
    });
    std::fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let sums = sha256sums(&out);
    std::fs::write(out.join("SHA256SUMS"), sums).unwrap();
}
