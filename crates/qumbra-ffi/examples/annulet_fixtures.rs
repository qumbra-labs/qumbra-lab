//! **Annulet fixture transcripts for a shell's harness** (lab #858 WA3a).
//!
//! The browser extension pumps `qmb_annulet_*` from JavaScript; its harness
//! needs a node that answers exactly as the kernel's own lying-endpoint
//! fixture does. This example RECORDS that, rather than precomputing routes:
//! for each case it runs the real ABI pump (the same calls a host makes, the
//! same as `tests/annulet_abi.rs`'s `abi()`) against qumbra-wallet's fixture
//! `Endpoint`, and writes every path the driver asked, in order, with its
//! exact answer — an error as an error, never as a file. Beside each
//! transcript it writes what the kernel's own encoder produced
//! (`view_json` / `refusal_json` through the ABI), so the harness compares
//! against the kernel and holds no hand-written expectations.
//!
//! **Every seed here is the FIXTURE's** — wallet entropy `[seed; 32]`, the
//! sequencer seed, the rng seed — public test bytes, never a real wallet's
//! and never to be used for one. The list is signed with the TEST list key
//! (`test-support`, a dev-dependency only: this example never reaches the
//! wasm build or a release).
//!
//! Output (refused if `<out>` exists, unless `--force`):
//!   <out>/manifest.json         lab rev, rng seed, endpoint label, list
//!                               commit, the TEST list key (hex), the cases
//!   <out>/<case>/case.json      wallet entropy + indices, pin, list choice,
//!                               the transcript, the expected result, the
//!                               record in/out file names
//!   <out>/<case>/NNN.bin        answer bodies, numbered by transcript order
//!   <out>/<case>/record_in.bin  the record fed to qmb_annulet_new (if any)
//!   <out>/<case>/record_out.bin the record qmb_annulet_take_record returned
//!   <out>/lists/*.json|*.sig    the signed lists the cases use
//!
//! Run (a named local run on the ad_goldens rule):
//!   cargo run -p qumbra-ffi --example annulet_fixtures -- <out> --lab-rev <commit> [--force]
//! Nothing recomputes an example: regenerate by hand when the kernel's ABI,
//! its encoder or the fixture changes; the manifest's `--lab-rev` is what the
//! harness compares against. (The prefilter's `cargo check --workspace
//! --all-targets` compiles this file, so it cannot rot silently.)

#[path = "../../qumbra-wallet/tests/common/mod.rs"]
mod common;

use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};

use common::*;
use qlab_devnet::body::BlockBody;
use qumbra_ffi::annulet::{
    qmb_annulet_free, qmb_annulet_new, qmb_annulet_step, qmb_annulet_supply, qmb_annulet_supply_err,
    qmb_annulet_take_record, qmb_annulet_take_view,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy};
use qumbra_wallet::asset_view::test_list_key;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

/// The rng seed every case is pumped with; the harness passes the same one.
const RNG: [u8; 32] = [0x58; 32];
const ENDPOINT: &str = "fixture";
const COMMIT: &str = "fixture-list";

/// A signed list: (bytes, signature).
type Signed = (Vec<u8>, Vec<u8>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// (bytes, signature) of a TEST-signed list naming USDT on `genesis`.
fn list_for(genesis: &[u8; 32]) -> Signed {
    let issuer = hex(&qlab_node::annulet_genesis::h32(&[9, 9, 9, 9]));
    let bytes = format!(
        r#"{{"v":1,"network":"annulet-ad1","genesis":"{}","testnet":true,"assets":[{{"id":1,"issuer_key":"{issuer}","name":"Tether USD (test)","ticker":"tUSDT","decimals":6}}]}}"#,
        hex(genesis)
    )
    .into_bytes();
    let sig = test_list_key::sign(&bytes);
    (bytes, sig)
}

unsafe fn take_str(p: *mut c_char) -> String {
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    qmb_string_free(p);
    s
}

struct Recorded {
    transcript: Vec<Value>,
    expect: Value,
    record: Option<Vec<u8>>,
}

/// One scan through the ABI, pumped like a host, recording every Need and
/// its answer into `dir`.
fn pump(dir: &Path, seed: u8, ep: &Endpoint, list: Option<&Signed>, record: Option<&[u8]>) -> Recorded {
    let key = test_list_key::encoded();
    unsafe {
        let w = qmb_wallet_from_entropy([seed; 32].as_ptr());
        let endpoint = CString::new(ENDPOINT).unwrap();
        let commit = CString::new(COMMIT).unwrap();
        let pin = ep.file.hash();
        let indices = [0u64, 1];
        let (lp, ll, sp, sl, kp, kl) = match list {
            Some((b, s)) => (b.as_ptr(), b.len(), s.as_ptr(), s.len(), key.as_ptr(), key.len()),
            None => (std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0),
        };
        let (rp, rl) = record.map_or((std::ptr::null(), 0), |r| (r.as_ptr(), r.len()));
        let mut err: *mut c_char = std::ptr::null_mut();
        let s = qmb_annulet_new(
            w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), rp, rl, lp, ll, sp, sl,
            kp, kl, commit.as_ptr(), &mut err,
        );
        assert!(!s.is_null(), "qmb_annulet_new refused: {}", if err.is_null() { "NULL".into() } else { take_str(err) });
        let mut transcript = Vec::new();
        let expect = loop {
            let mut out: *mut c_char = std::ptr::null_mut();
            match qmb_annulet_step(s, &mut out) {
                1 => {
                    let path = take_str(out);
                    let n = transcript.len();
                    match ep.fetch(&path) {
                        Ok(body) => {
                            let file = format!("{n:03}.bin");
                            std::fs::write(dir.join(&file), &body).unwrap();
                            qmb_annulet_supply(s, body.as_ptr(), body.len());
                            transcript.push(json!({ "path": path, "ok": true, "file": file, "len": body.len() }));
                        }
                        Err(why) => {
                            let status: u16 = why.split_whitespace().next().and_then(|c| c.parse().ok()).unwrap_or(500);
                            let c = CString::new(why.clone()).unwrap();
                            qmb_annulet_supply_err(s, c.as_ptr());
                            transcript.push(json!({ "path": path, "ok": false, "status": status, "error": why }));
                        }
                    }
                }
                0 => break json!({ "view": serde_json::from_str::<Value>(&take_str(qmb_annulet_take_view(s))).unwrap() }),
                -2 => break json!({ "refusal": serde_json::from_str::<Value>(&take_str(out)).unwrap() }),
                other => panic!("step returned {other}"),
            }
        };
        let mut len = 0usize;
        let p = qmb_annulet_take_record(s, &mut len);
        let record = (!p.is_null()).then(|| {
            let r = std::slice::from_raw_parts(p, len).to_vec();
            qmb_dealloc(p, len);
            r
        });
        qmb_annulet_free(s);
        qmb_wallet_free(w);
        Recorded { transcript, expect, record }
    }
}

struct Case<'a> {
    name: &'a str,
    seed: u8,
    ep: &'a Endpoint,
    /// "none", "listed" or "other_network" — and the list file it names.
    list: (&'a str, Option<(&'a Signed, &'a str)>),
    record_in: Option<Vec<u8>>,
}

fn write_case(out: &Path, c: &Case) -> Option<Vec<u8>> {
    let dir = out.join(c.name);
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(r) = &c.record_in {
        std::fs::write(dir.join("record_in.bin"), r).unwrap();
    }
    let rec = pump(&dir, c.seed, c.ep, c.list.1.map(|(l, _)| l), c.record_in.as_deref());
    if let Some(r) = &rec.record {
        std::fs::write(dir.join("record_out.bin"), r).unwrap();
    }
    let case = json!({
        "case": c.name,
        "wallet": { "entropy": hex(&[c.seed; 32]), "seedVersion": "from_entropy", "indices": [0, 1] },
        "pin": hex(&c.ep.file.hash()),
        "list": c.list.0,
        "listFile": c.list.1.map(|(_, f)| f),
        "recordIn": c.record_in.as_ref().map(|_| "record_in.bin"),
        "recordOut": rec.record.as_ref().map(|_| "record_out.bin"),
        "transcript": rec.transcript,
        "expect": rec.expect,
    });
    std::fs::write(dir.join("case.json"), serde_json::to_string_pretty(&case).unwrap()).unwrap();
    println!("{:<16} {} Needs → {}", c.name, case["transcript"].as_array().unwrap().len(),
        if rec.expect.get("refusal").is_some() { format!("refusal {}", rec.expect["refusal"]["refusal"]) } else { "view".into() });
    rec.record
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = PathBuf::from(args.first().expect("usage: annulet_fixtures <out> --lab-rev <commit> [--force]"));
    let lab_rev = args.iter().position(|a| a == "--lab-rev").and_then(|i| args.get(i + 1)).expect("--lab-rev <commit> is required");
    if out.exists() {
        if !args.iter().any(|a| a == "--force") {
            eprintln!("{} exists — refusing to overwrite (pass --force)", out.display());
            std::process::exit(2);
        }
        std::fs::remove_dir_all(&out).unwrap();
    }
    std::fs::create_dir_all(out.join("lists")).unwrap();

    // honest / listed / other_network / no_nullifiers: seed 0xA1, three bodies.
    const A: u8 = 0xA1;
    let wa = wallet_dir("wa3a_a", A);
    let mut rng = StdRng::seed_from_u64(A as u64);
    let a0 = wa.wallet().address_at_index(0);
    let mut honest_bodies = bodies(&wa, &mut rng);
    honest_bodies.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 1, USDT, 60)], 0x60, &mut rng)], ..BlockBody::default() });
    honest_bodies.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 2, USDT, 61)], 0x61, &mut rng)], ..BlockBody::default() });
    let file_a = genesis(&a0);
    let honest3 = Endpoint::new(file_a.clone(), &honest_bodies[..3], None, Lie::None);
    let listed = list_for(&file_a.hash());
    let other = list_for(&[0x0E; 32]);
    for (name, l) in [("listed", &listed), ("other_network", &other)] {
        std::fs::write(out.join("lists").join(format!("{name}.json")), &l.0).unwrap();
        std::fs::write(out.join("lists").join(format!("{name}.sig")), &l.1).unwrap();
    }
    let no_nf = Endpoint::new(file_a.clone(), &honest_bodies[..3], None, Lie::NoNullifiers);

    // The five lies (and registry_leaf, which is not a refusal): seed 0xB1.
    const B: u8 = 0xB1;
    let wb = wallet_dir("wa3a_b", B);
    let mut rng = StdRng::seed_from_u64(B as u64);
    let b0 = wb.wallet().address_at_index(0);
    let file_b = genesis(&b0);
    let hb = bodies(&wb, &mut rng);
    let mut forged_note = hb.clone();
    forged_note[1].txs.push(pay_tx(&b0, &[note_to(&b0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let mut forged_group = hb.clone();
    forged_group[1].txs[0] = pay_tx(&b0, &[note_to(&b0, 1_000_000, USDT, 98)], 0x40, &mut rng);
    let lies = [
        ("genesis_bytes", Endpoint::new(file_b.clone(), &hb, None, Lie::GenesisBytes)),
        ("bad_seal", Endpoint::new(file_b.clone(), &hb, None, Lie::BadSeal)),
        ("forged_note", Endpoint::new(file_b.clone(), &hb, Some(&forged_note), Lie::ForgedNote)),
        ("forged_group", Endpoint::new(file_b.clone(), &hb, Some(&forged_group), Lie::ForgedGroup)),
        ("registry_leaf", Endpoint::new(file_b.clone(), &hb, None, Lie::RegistryLeaf)),
    ];
    let listed_b = list_for(&file_b.hash());
    std::fs::write(out.join("lists").join("listed_b.json"), &listed_b.0).unwrap();
    std::fs::write(out.join("lists").join("listed_b.sig"), &listed_b.1).unwrap();

    let mut names = Vec::new();
    let mut run = |c: Case| {
        names.push(c.name.to_string());
        write_case(&out, &c)
    };
    run(Case { name: "honest", seed: A, ep: &honest3, list: ("none", None), record_in: None });
    run(Case { name: "listed", seed: A, ep: &honest3, list: ("listed", Some((&listed, "lists/listed"))), record_in: None });
    run(Case { name: "other_network", seed: A, ep: &honest3, list: ("other_network", Some((&other, "lists/other_network"))), record_in: None });
    run(Case { name: "no_nullifiers", seed: A, ep: &no_nf, list: ("none", None), record_in: None });
    for (name, ep) in &lies {
        run(Case { name, seed: B, ep, list: ("listed", Some((&listed_b, "lists/listed_b"))), record_in: None });
    }

    // The record: scan 1 on three bodies, scan 2 on five fed scan 1's record,
    // and scan 2 again fed a tampered copy (a cache, never trust: it only
    // costs a re-verify — a longer fetch sequence).
    const C: u8 = 0xC1;
    let wc = wallet_dir("wa3a_c", C);
    let mut rng = StdRng::seed_from_u64(C as u64);
    let c0 = wc.wallet().address_at_index(0);
    let mut cb = bodies(&wc, &mut rng);
    cb.push(BlockBody { txs: vec![pay_tx(&c0, &[note_to(&c0, 1, USDT, 60)], 0x60, &mut rng)], ..BlockBody::default() });
    cb.push(BlockBody { txs: vec![pay_tx(&c0, &[note_to(&c0, 2, USDT, 61)], 0x61, &mut rng)], ..BlockBody::default() });
    let file_c = genesis(&c0);
    let ep3 = Endpoint::new(file_c.clone(), &cb[..3], None, Lie::None);
    let ep5 = Endpoint::new(file_c.clone(), &cb, None, Lie::None);
    let first = run(Case { name: "record_first", seed: C, ep: &ep3, list: ("none", None), record_in: None }).expect("a first scan records");
    run(Case { name: "record_resume", seed: C, ep: &ep5, list: ("none", None), record_in: Some(first.clone()) });
    let mut tampered = first.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    run(Case { name: "record_tampered", seed: C, ep: &ep5, list: ("none", None), record_in: Some(tampered) });

    for w in [wa, wb, wc] {
        let _ = std::fs::remove_dir_all(&w.dir);
    }
    let manifest = json!({
        "what": "lab #858 WA3a — Annulet fixture transcripts, recorded from the real ABI pump. FIXTURE seeds only.",
        "labRev": lab_rev,
        "rngSeed": hex(&RNG),
        "endpointLabel": ENDPOINT,
        "listSourceCommit": COMMIT,
        "testListKey": hex(&test_list_key::encoded()),
        "cases": names,
    });
    std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    println!("wrote {} cases to {}", manifest["cases"].as_array().unwrap().len(), out.display());
}
