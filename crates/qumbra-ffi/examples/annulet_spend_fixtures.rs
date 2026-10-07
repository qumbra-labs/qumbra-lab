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
    qmb_auth_free, qmb_auth_open, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_v2_free, qmb_spend_v2_intent,
    qmb_spend_v2_new, qmb_spend_v2_step, qmb_spend_v2_supply, qmb_spend_v2_supply_err,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

const SEED: u8 = 0x4B;
const PAYEE: u8 = 0x4C;
const RNG: [u8; 32] = [0x59; 32];
const SPEND_SEED: [u8; 32] = [0x5A; 32];
const DUMMIES: [u8; 64] = [0x5B; 64];
const VALID_FOR: u64 = 96;

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
fn chain() -> (Endpoint, String, String) {
    let w = wallet_dir("spend_fixtures", SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let mut rng = StdRng::seed_from_u64(0x4B);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let file = genesis_v2(&a2, vec![note_to(&a2, 50, 0, 30), note_to(&a2, 2, 0, 40)]);
    let ep = Endpoint::new(file, &[body], None, Lie::None);
    let _ = std::fs::remove_dir_all(&w.dir);
    let p = wallet_dir("spend_fixtures_payee", PAYEE);
    let pw = p.wallet();
    let payee = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0)).encode();
    let _ = std::fs::remove_dir_all(&p.dir);
    (ep, payee, AuthJournal::fresh(root).to_text())
}

/// One whole spend through the ABI, recorded into `dir`.
unsafe fn case(dir: &Path, ep: &Endpoint, payee: &str, journal: &str, asset: u16, amount: u64) -> Value {
    for sub in ["scan", "spend"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    // The scan → the basis.
    let endpoint = CString::new("fixture").unwrap();
    let pin = ep.file.hash();
    let indices = [0u64, 1];
    let null = ptr::null();
    let mut err: *mut c_char = ptr::null_mut();
    let s = qmb_annulet_new_v2(
        w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, null, 0, null, 0,
        null, 0, ptr::null(), ptr::null(), 0, &mut err,
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

    // The keys, the spend, its reads.
    let j = CString::new(journal).unwrap();
    let a = qmb_auth_open(w, j.as_ptr(), &mut err);
    assert!(!a.is_null());
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
    std::fs::write(dir.join("journal_after.txt"), &after).unwrap();
    std::fs::write(dir.join("intent.bin"), &intent).unwrap();
    std::fs::write(dir.join("review.txt"), &review).unwrap();
    std::fs::write(dir.join("bundle.bin"), &bundle).unwrap();
    json!({
        "request": { "to": payee, "asset": asset, "amount": amount.to_string(), "valid_for": VALID_FOR },
        "scan": scan,
        "spend": spend,
        "files": {
            "journal_before": "journal_before.txt", "journal_after": "journal_after.txt",
            "intent": "intent.bin", "review": "review.txt", "bundle": "bundle.bin",
        },
        "intent_len": intent.len(),
        "bundle_len": bundle.len(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = PathBuf::from(args.first().expect("usage: <out> --lab-rev <commit> [--force]"));
    let rev = args.iter().position(|a| a == "--lab-rev").and_then(|i| args.get(i + 1)).expect("--lab-rev <commit>");
    if out.exists() {
        assert!(args.iter().any(|a| a == "--force"), "{} exists (use --force)", out.display());
        std::fs::remove_dir_all(&out).unwrap();
    }
    std::fs::create_dir_all(&out).unwrap();
    let (ep, payee, journal) = chain();
    let mut cases = serde_json::Map::new();
    for (name, asset, amount) in [("s_asset0", 0u16, 10u64), ("p_usdt", USDT as u16, 1_000)] {
        let dir = out.join(name);
        let c = unsafe { case(&dir, &ep, &payee, &journal, asset, amount) };
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<10} {} scan + {} spend reads → bundle {} B", c["scan"].as_array().unwrap().len(), c["spend"].as_array().unwrap().len(), c["bundle_len"]);
        cases.insert(name.into(), json!(name));
    }
    let manifest = json!({
        "what": "lab #924 PR 3 — Candidate A spend fixtures, recorded from the real ABI (scan → basis → auth → spend → take → intent → review → sign) on a format-33 genesis. FIXTURE seeds only.",
        "lab_rev": rev,
        "wallet_entropy": hex(&[SEED; 32]),
        "payee_entropy": hex(&[PAYEE; 32]),
        "pin": hex(&ep.file.hash()),
        "scan_rng": hex(&RNG),
        "spend_seed": hex(&SPEND_SEED),
        "dummy_entropy": hex(&DUMMIES),
        "indices": [0, 1],
        "cases": cases,
    });
    std::fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}
