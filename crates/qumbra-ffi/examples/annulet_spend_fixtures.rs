//! **Candidate A spend fixtures for a shell's harness** (lab #924 PR 3, the
//! 4b kernel).
//!
//! The extension runs `qmb_auth_*` / `qmb_spend_v2_*` / `qmb_intent_*` from
//! JavaScript over its wasm build. This example RECORDS the native run of the
//! same calls — the scan that yields the basis, the spend's served reads,
//! the take, the intent, the review, the signature — against qumbra-wallet's
//! fixture `Endpoint` on a format-33 genesis (and, for the v3_* cases, on
//! format-34 genesis files), every path the kernel asked in
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
//!   <out>/<case>/landed.json       lab #935 (extension #95 §3):
//!                                  qmb_auth_check_take_landed after a finish
//!                                  that returned a journal (`[]` when none) —
//!                                  every auth case and every spend case's
//!                                  check; case.json `landed` names it (null
//!                                  when the finish gave no journal)
//!   case.json `page`               the qmb_auth_check_set_page size the open
//!                                  ran with: 0 = one body per NEED, as before
//!   <out>/<auth case>/             first / restore / stale-check / revive /
//!                                  rotated cases: journal_in.txt,
//!                                  journal_out.txt, case.json (status,
//!                                  refusal, the basis summary, wall ms),
//!                                  summary.json (each journal through
//!                                  qmb_auth_journal_summary, PR 3f); the
//!                                  scan names the journal's generations
//!                                  (restore and first: the probe 0..8)
//!   <out>/check_stale/then_restore/  the restore the STALE status asks for
//!   <out>/restore_spent_paged/, restore_spent_paged1/, check_stale_paged/
//!                                  lab #936 (extension #95 §3): restore_spent
//!                                  and check_stale walked in pages of 256, 1
//!                                  and 256 bodies (/v1/bodies) — asserted to
//!                                  reach the unpaged case's journal_out,
//!                                  status, keys and landed.json
//!   <out>/restore_spent/landed_expected.json  the matching pair, asserted
//!                                  here and written for the harness to
//!                                  compare the kernel's answer against:
//!                                  keccak256(s_asset0/intent.bin) and the
//!                                  tx_id of the transaction landed at height 2
//!   <out>/rotated_receive/         the rotated journal on a chain paying its
//!                                  generation-1 address; only_g0/ holds the
//!                                  same wallet's scan naming [0] alone, and
//!                                  case.json's scan_only_g0 its basis (which
//!                                  must miss that note)
//!   <out>/v3_*/                    lab #937 cut-over (D-C6): format-34 spends
//!                                  that pay a fixture prover, each on its own
//!                                  chain (case.json `genesis`): v3_s_asset0,
//!                                  v3_p_usdt, v3_fee_bank, v3_split (step 1 of
//!                                  2). Each one's shape, output 3 and review
//!                                  lines are asserted, not only named.
//!   <out>/v3_*/info.json           the /info bytes the kernel admits before the
//!                                  first step: an admit-equivalent SUBSET of a
//!                                  format-34 service's answer (no shapes,
//!                                  d_auth, slot_secs, …), not its bytes
//!   <out>/v3_s_asset0_landed/      v3_s_asset0's transaction landed at
//!                                  height 1 of the same genesis, and a check
//!                                  of its journal_after.txt there: CHECKED,
//!                                  one landed spend, landed_expected.json as
//!                                  restore_spent's (extension #95 §3 (d))
//!   <out>/v3_not_pinned/           the same on a net with no pin: the
//!                                  NotPinned refusal a release kernel replays
//!   manifest.json `prover_pin`     what the harness kernel registers per v3_*
//!                                  genesis (qmb_harness_pin_fixture)
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
    qmb_auth_check_finish, qmb_auth_check_free, qmb_auth_check_new, qmb_auth_check_set_page, qmb_auth_check_step,
    qmb_auth_check_supply, qmb_auth_check_supply_err, qmb_auth_check_take_landed, qmb_auth_first_new, qmb_auth_open_next, qmb_auth_restore_new, qmb_spend_basis_free,
    qmb_auth_journal_summary, qmb_spend_basis_summary, AuthHandle, SpendBasis,
    qmb_auth_free, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_v2_free, qmb_spend_v2_intent,
    qmb_spend_v2_new, qmb_spend_v2_prover, qmb_spend_v2_step, qmb_spend_v2_supply, qmb_spend_v2_supply_err,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal, GenState, Generation};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

const SEED: u8 = 0x4B;
const PAYEE: u8 = 0x4C;
/// Lab #937 cut-over (D-C6): the fixture prover's payee wallet.
const PROVER: u8 = 0x4D;
/// The fixture prover's pinned maximum and its advertised price (D-C2's
/// shape: the maximum S 2 / P 4, the price S 1 / P 2).
const PIN_MAX: (u64, u64) = (2, 4);
const PRICE: (u64, u64) = (1, 2);
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
/// (`qmb_wallet_address_v2(w, 0, 1, 1, ptr::null())`).
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

/// Lab #937 cut-over (D-C6): the fixture prover's payee — a third
/// wallet's version-2 address 0.
fn prover_address() -> qlab_wallet::address::Address {
    let p = wallet_dir("spend_fixtures_prover", PROVER);
    let pw = p.wallet();
    let a = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0));
    let _ = std::fs::remove_dir_all(&p.dir);
    a
}

/// A **format-34** fixture chain: the payer's v2 address 0 holds the genesis
/// 1,000,000 USDT-test and `notes(a2)`; `extra`, when given, is the one
/// transaction of block 1 (no blocks after genesis otherwise). With
/// `pin`, this net's prover is pinned in this process's fixture registry —
/// what the harness kernel's `qmb_harness_pin_fixture` does from the
/// manifest's `prover_pin`.
fn chain_v3(
    tag: &str,
    notes: impl Fn(&qlab_wallet::address::Address) -> Vec<qlab_note::l2note::L2Note>,
    pin: bool,
    extra: Option<qlab_devnet::body::TxEntry>,
) -> (Endpoint, String, String) {
    let w = wallet_dir(tag, SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let file = genesis_v3(&a2, notes(&a2));
    assert_eq!(file.format_version, 34);
    if pin {
        qumbra_wallet::prover_pins::pin_fixture(
            file.hash(),
            qumbra_wallet::prover_pins::ProverPin {
                payee: prover_address().encode(),
                max_price: qumbra_wallet::annulet_plan::ProverPrice { s: PIN_MAX.0, p: PIN_MAX.1 },
            },
        );
    }
    let bodies: Vec<BlockBody> = extra.into_iter().map(|tx| BlockBody { txs: vec![tx], ..BlockBody::default() }).collect();
    let ep = Endpoint::new(file, &bodies, None, Lie::None);
    let _ = std::fs::remove_dir_all(&w.dir);
    let p = wallet_dir(&format!("{tag}_payee"), PAYEE);
    let pw = p.wallet();
    let payee = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0)).encode();
    let _ = std::fs::remove_dir_all(&p.dir);
    (ep, payee, AuthJournal::fresh(root).to_text())
}

/// The prover service's `/v2/annulet/info` for `ep`'s net, as a format-34
/// service answers it (the fields `prover_pins::admit` reads, and the rest).
fn prover_info(ep: &Endpoint) -> Vec<u8> {
    json!({
        "protocol_version": 1,
        "genesis_format": 34,
        "genesis_hash": hex(&ep.file.hash()),
        "fee_asset": 0,
        "price": { "S": PRICE.0, "P": PRICE.1 },
        "payee": prover_address().encode(),
        "recommended_valid_for_blocks": VALID_FOR,
    })
    .to_string()
    .into_bytes()
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
        w, endpoint.as_ptr(), pin.as_ptr(), 1, 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, lp, ll, sp, sl, kp,
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
    /// `qmb_auth_check_take_landed`'s JSON, when the finish gave a journal.
    landed: Option<String>,
    transcript: Vec<Value>,
    millis: u128,
}

/// The open-time check (or first / restore) through the ABI, its bodies
/// recorded into `dir/auth`. `page > 0` walks in pages of that many bodies
/// (`qmb_auth_check_set_page`, lab #936); 0 is one body per NEED.
unsafe fn auth_phase(
    dir: &Path,
    w: *mut qumbra_ffi::WalletState,
    ep: &Endpoint,
    basis: *const SpendBasis,
    open: Open,
    page: u32,
) -> Opened {
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
    if page > 0 {
        assert_eq!(qmb_auth_check_set_page(c, page, &mut err), 0, "set_page({page}): {}", take_str(err));
    }
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
    let journal = (!jout.is_null()).then(|| take_str(jout));
    let refusal = (a.is_null() && !err.is_null()).then(|| take_str(err));
    // Lab #935: read before the free, after a finish that gave a journal.
    let landed = journal.as_ref().map(|_| {
        let mut lerr: *mut c_char = ptr::null_mut();
        let l = qmb_auth_check_take_landed(c, &mut lerr);
        assert!(!l.is_null(), "take_landed: {}", take_str(lerr));
        take_str(l)
    });
    qmb_auth_check_free(c);
    Opened {
        a: (!a.is_null()).then_some(a),
        journal,
        status,
        refusal,
        landed,
        transcript,
        millis: started.elapsed().as_millis(),
    }
}

/// An open-only case (lab #924 PR 3b, the extension's e2e): `open` on `ep`,
/// recorded into `dir`.
unsafe fn auth_case(dir: &Path, ep: &Endpoint, open: Open, journal_in: Option<&str>, page: u32) -> Value {
    std::fs::create_dir_all(dir).unwrap();
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    // The host scans every generation its journal names; with none, the probe.
    let gens: Vec<u32> = match journal_in {
        Some(j) => AuthJournal::from_text(j).unwrap().generations().iter().map(|g| g.g).collect(),
        None => PROBE.to_vec(),
    };
    let (basis, scan) = scan_basis(dir, w, ep, None, &gens);
    let summary: Value = serde_json::from_str(&take_str(qmb_spend_basis_summary(basis))).unwrap();
    let o = auth_phase(dir, w, ep, basis, open, page);
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
    if let Some(l) = &o.landed {
        std::fs::write(dir.join("landed.json"), l).unwrap();
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
        "landed": o.landed.as_ref().map(|_| "landed.json"),
        "page": page,
        "scan_generations": gens,
        "basis": summary,
        "scan": scan,
        "auth": o.transcript,
        "wall_ms_native": o.millis,
    })
}

/// One whole spend through the ABI, recorded into `dir`.
#[allow(clippy::too_many_arguments)]
unsafe fn case(
    dir: &Path,
    ep: &Endpoint,
    payee: &str,
    journal: &str,
    asset: u16,
    amount: u64,
    list: Option<&(Vec<u8>, Vec<u8>)>,
    prover: Option<&[u8]>,
) -> Value {
    std::fs::create_dir_all(dir.join("spend")).unwrap();
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let mut err: *mut c_char = ptr::null_mut();
    let (basis, scan) = scan_basis(dir, w, ep, list, &[0]);
    // The keys: the open-time check of the account's journal.
    let opened = auth_phase(dir, w, ep, basis, Open::Check(journal, 0), 0);
    let a = opened.a.expect("the fresh journal opens");
    let checked = opened.journal.clone().expect("a checked journal");
    let to = CString::new(payee).unwrap();
    let sp = qmb_spend_v2_new(basis, to.as_ptr(), asset, amount, VALID_FOR, SPEND_SEED.as_ptr(), DUMMIES.as_ptr(), &mut err);
    assert!(!sp.is_null(), "{}", take_str(err));
    // Lab #937 cut-over (D-C6): a format-34 spend pays its prover — the
    // service's /info bytes, as the host fetched them, before the first step.
    if let Some(info) = prover {
        std::fs::write(dir.join("info.json"), info).unwrap();
        assert_eq!(qmb_spend_v2_prover(sp, info.as_ptr(), info.len(), &mut err), 0, "{}", take_str(err));
    }
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
    std::fs::write(dir.join("landed.json"), opened.landed.as_deref().expect("a finish with a journal")).unwrap();
    std::fs::write(dir.join("journal_after.txt"), &after).unwrap();
    std::fs::write(dir.join("intent.bin"), &intent).unwrap();
    std::fs::write(dir.join("review.txt"), &review).unwrap();
    std::fs::write(dir.join("bundle.bin"), &bundle).unwrap();
    json!({
        "request": { "to": payee, "asset": asset, "amount": amount.to_string(), "valid_for": VALID_FOR },
        "list": list.map(|_| json!({ "bytes": "list.json", "sig": "list.sig" })),
        "genesis": hex(&ep.file.hash()),
        "prover": prover.map(|_| json!({ "info": "info.json" })),
        "scan": scan,
        "auth": opened.transcript,
        "auth_status": opened.status,
        "landed": "landed.json",
        "page": 0,
        "spend": spend,
        "files": {
            "journal_before": "journal_before.txt", "journal_checked": "journal_checked.txt", "journal_after": "journal_after.txt",
            "intent": "intent.bin", "review": "review.txt", "bundle": "bundle.bin",
        },
        "intent_len": intent.len(),
        "bundle_len": bundle.len(),
    })
}

/// Lab #935 (extension #95 §3): the matching pair. `dir/landed.json` must
/// hold exactly one spend, whose intent digest is keccak256 of
/// `<intent_case>/intent.bin` (the bytes the device signed) and whose tx_id is
/// `tx`'s (the transaction the chain carries). Asserted here, then written as
/// `landed_expected.json` so a harness compares the kernel's answer to these
/// values rather than recomputing both sides in one place.
fn landed_expected(dir: &Path, intent_case: &str, tx: &qlab_devnet::body::TxEntry) -> Value {
    let landed: Value = serde_json::from_slice(&std::fs::read(dir.join("landed.json")).unwrap()).unwrap();
    let intent = std::fs::read(dir.join("..").join(intent_case).join("intent.bin")).unwrap();
    let want = json!({
        "intent_digest": hex(&qlab_remote_auth::keccak256(&[&intent])),
        "tx_id": hex(&qlab_p2p::codec::tx_id(tx)),
        "intent_file": format!("../{intent_case}/intent.bin"),
    });
    let spends = landed.as_array().expect("landed.json is a list");
    assert_eq!(spends.len(), 1, "{}: exactly one landed spend: {landed}", dir.display());
    assert_eq!(spends[0]["intent_digest"], want["intent_digest"], "{}: the intent digest", dir.display());
    assert_eq!(spends[0]["tx_id"], want["tx_id"], "{}: the transaction id", dir.display());
    std::fs::write(dir.join("landed_expected.json"), serde_json::to_vec_pretty(&want).unwrap()).unwrap();
    want
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
        let c = unsafe { case(&dir, &ep, &payee, &journal, asset, amount, list, None) };
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
    let landed_tx = landed.clone();
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
        let mut c = unsafe { auth_case(&dir, chain_ep, open, journal_in, 0) };
        if name == "check_stale" {
            // What STALE asks of the host: persist journal_out, tell the
            // user, run the restore.
            let then = unsafe { auth_case(&dir.join("then_restore"), chain_ep, Open::Restore, None, 0) };
            println!("  then_restore status {} keys {} {} ms", then["status"], then["keys"], then["wall_ms_native"]);
            c["then_restore"] = then;
        }
        if name == "restore_spent" {
            let want = landed_expected(&dir, "s_asset0", &landed_tx);
            println!("  restore_spent landed: intent {} tx {}", want["intent_digest"], want["tx_id"]);
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
    // Lab #936 (extension #95 §3 (b)): the same opens walked in pages — the
    // NEEDs are asserted path by path, and the outcome must be the unpaged
    // case's to the byte.
    for (name, base, open, journal_in, page, needs) in [
        ("restore_spent_paged", "restore_spent", Open::Restore, None, 256u32, &["/v1/bodies?from=1&to=2"][..]),
        (
            "restore_spent_paged1",
            "restore_spent",
            Open::Restore,
            None,
            1,
            &["/v1/bodies?from=1&to=1", "/v1/bodies?from=2&to=2"][..],
        ),
        ("check_stale_paged", "check_stale", Open::Check(&journal, 0), Some(journal.as_str()), 256, &["/v1/bodies?from=1&to=2"][..]),
    ] {
        let dir = out.join(name);
        let c = unsafe { auth_case(&dir, &spent, open, journal_in, page) };
        let asked: Vec<&str> = c["auth"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
        assert_eq!(asked, needs, "{name}: the page NEEDs");
        let base_case: Value = serde_json::from_slice(&std::fs::read(out.join(base).join("case.json")).unwrap()).unwrap();
        for k in ["status", "keys"] {
            assert_eq!(c[k], base_case[k], "{name}: {k} as {base}'s");
        }
        for f in ["journal_out.txt", "landed.json"] {
            let read = |d: &str| std::fs::read(out.join(d).join(f)).unwrap_or_else(|e| panic!("{d}/{f}: {e}"));
            assert_eq!(read(name), read(base), "{name}: {f} as {base}'s");
        }
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<14} status {} keys {} page {page}: {} → {base}'s journal and landed {} ms", c["status"], c["keys"], asked.join(", "), c["wall_ms_native"]);
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
            let rc = qumbra_ffi::spend_v2::qmb_auth_first_fresh(h, 1, ptr::null(), &mut jout);
            refused.insert(door.into(), json!({ "rc": rc, "refusal": take_str(jout) }));
            qmb_wallet_free(h);
        }
        let born = qumbra_ffi::qmb_wallet_new_fresh();
        let mut jout: *mut c_char = ptr::null_mut();
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 1, ptr::null(), &mut jout), 0);
        let fresh = take_str(jout);
        let mut entropy = [0u8; 32];
        qumbra_ffi::qmb_wallet_seed_entropy(born, entropy.as_mut_ptr());
        let w = qmb_wallet_from_entropy(entropy.as_ptr());
        let p = wallet_dir("spend_fixtures_holder", PAYEE);
        let holder = p.wallet().address_candidate_a_at_index(0, &generation_root(&p.wallet(), 0));
        let _ = std::fs::remove_dir_all(&p.dir);
        let empty = Endpoint::new(genesis_v2(&holder, Vec::new()), &[], None, Lie::None);
        let (basis, _) = scan_basis(&dir, w, &empty, None, &PROBE);
        let o = auth_phase(&dir, w, &empty, basis, Open::First, 0);
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
    // Lab #937 cut-over (D-C6): format-34 spends that pay the fixture prover.
    // Each case is its own chain (its own genesis, in case.json); the harness
    // kernel registers the manifest's `prover_pin` for each before replaying.
    let mut v3_genesis = Vec::new();
    use qlab_devnet::annulet::L2ShapeTag;
    for (name, notes, asset, amount, shape, want, what) in [
        ("v3_s_asset0", vec![(50u64, 0u64, 30u64)], 0u16, 10u64, L2ShapeTag::S, "step 1 of 1: the payment", "S: one asset-0 note pays 10 + the S tier + the S price"),
        ("v3_p_usdt", vec![(4, 0, 40)], USDT as u16, 1_000, L2ShapeTag::P, "step 1 of 1: the payment", "P: the asset-0 row's exact note is the P tier + the P price"),
        ("v3_fee_bank", vec![(500, USDT, 60), (4, 0, 40)], USDT as u16, 1_000_200, L2ShapeTag::P, "step 1 of 1: the payment", "P: two USDT notes and the exact fee note in slot 3; output 3 rides the fee bank"),
        ("v3_split", vec![(50, 0, 30)], USDT as u16, 1_000, L2ShapeTag::S, "step 1 of 2: a fee-split", "step 1 of 2: a fee split, paying its own S price"),
    ] {
        let dir = out.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let (cep, cpayee, cjournal) =
            chain_v3(&format!("spend_fixtures_{name}"), |a| notes.iter().map(|&(v, asset, k)| note_to(a, v, asset, k)).collect(), true, None);
        let info = prover_info(&cep);
        let mut c = unsafe { case(&dir, &cep, &cpayee, &cjournal, asset, amount, None, Some(&info)) };
        // What was recorded is the shape this case names — asserted on the
        // bundle and the review, never only stated.
        let b = qlab_l2spend::bundle::ProvingBundle::decode(&std::fs::read(dir.join("bundle.bin")).unwrap()).unwrap();
        let review = std::fs::read_to_string(dir.join("review.txt")).unwrap();
        assert_eq!(b.shape(), shape, "{name}: the bundle's shape");
        assert!(review.contains(want), "{name}: {review}");
        let price = if shape == L2ShapeTag::S { PRICE.0 } else { PRICE.1 };
        let wit = b.witness();
        assert_eq!(wit.outputs.len(), 3, "{name}: three outputs");
        let o3 = &wit.outputs[2];
        assert_eq!((o3.value, o3.asset, o3.rkm), (price, 0, prover_address().rkm_lanes()), "{name}: output 3 pays the prover");
        assert!(review.contains(&format!("prover fee: {price} fee unit")), "{name}: {review}");
        if name == "v3_fee_bank" {
            assert_eq!([wit.inputs[0].asset, wit.inputs[1].asset], [USDT, USDT], "{name}: no asset-0 row");
            match &wit.fee_slot {
                qlab_air::l2::FeeSlotV2::Exact { input, .. } => {
                    assert_eq!(input.value, 2 + PRICE.1, "{name}: slot 3 is the P tier + the P price")
                }
                qlab_air::l2::FeeSlotV2::Dummy { .. } => panic!("{name}: slot 3 is the exact fee note"),
            }
        }
        if name == "v3_split" {
            assert!(review.contains("this plan from here: 2 transactions"), "{name}: {review}");
        }
        c["what"] = json!(what);
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<14} {} scan + {} spend reads → bundle {} B (pays its prover)", c["scan"].as_array().unwrap().len(), c["spend"].as_array().unwrap().len(), c["bundle_len"]);
        v3_genesis.push(json!({ "case": name, "genesis": hex(&cep.file.hash()) }));
        cases.insert(name.into(), json!(name));
    }
    // Extension #95 §3 (d): v3_s_asset0's own transaction landed at height 1
    // of the same genesis (same wallet, same notes — asserted by hash), and a
    // check of the journal that spend left: the chain the popup scans after
    // the recorded send, and the landed spend it settles by.
    unsafe {
        let name = "v3_s_asset0_landed";
        let dir = out.join(name);
        let mut tx = qlab_l2spend::bundle::ProvingBundle::decode(&std::fs::read(out.join("v3_s_asset0/bundle.bin")).unwrap())
            .unwrap()
            .tx()
            .clone();
        tx.proof = vec![0xAB; 64];
        let (cep, _, _) = chain_v3("spend_fixtures_v3_s_asset0_landed", |a| vec![note_to(a, 50, 0, 30)], true, Some(tx.clone()));
        let genesis = hex(&cep.file.hash());
        assert_eq!(json!(genesis), v3_genesis[0]["genesis"], "{name}: v3_s_asset0's genesis");
        let after = std::fs::read_to_string(out.join("v3_s_asset0/journal_after.txt")).unwrap();
        let mut c = auth_case(&dir, &cep, Open::Check(&after, 0), Some(&after), 0);
        assert!(
            c["scan"].as_array().unwrap().iter().any(|e| e["path"] == json!("/v1/block/1/body")),
            "{name}: the scan reads the landed body: {}",
            c["scan"]
        );
        assert_eq!((c["status"].clone(), c["keys"].clone()), (json!(0), json!(true)), "{name}: CHECKED, keys given: {}", c["refusal"]);
        let want = landed_expected(&dir, "v3_s_asset0", &tx);
        c["genesis"] = json!(genesis);
        c["what"] = json!("v3_s_asset0's transaction landed at height 1 of its genesis; a check of its journal_after there");
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<14} status {} keys {}: landed intent {} tx {}", c["status"], c["keys"], want["intent_digest"], want["tx_id"]);
        v3_genesis.push(json!({ "case": name, "genesis": genesis }));
        cases.insert(name.into(), json!(name));
    }
    // What a RELEASE kernel replays: a format-34 net with no pin — the
    // prover's /info is refused by name (`NotPinned`), before any step.
    unsafe {
        let name = "v3_not_pinned";
        let dir = out.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let (cep, cpayee, _) = chain_v3("spend_fixtures_v3_not_pinned", |a| vec![note_to(a, 51, 0, 31)], false, None);
        let info = prover_info(&cep);
        std::fs::write(dir.join("info.json"), &info).unwrap();
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let (basis, scan) = scan_basis(&dir, w, &cep, None, &[0]);
        let to = CString::new(cpayee.as_str()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let sp = qmb_spend_v2_new(basis, to.as_ptr(), 0, 10, VALID_FOR, SPEND_SEED.as_ptr(), DUMMIES.as_ptr(), &mut err);
        assert!(!sp.is_null(), "{}", take_str(err));
        assert_eq!(qmb_spend_v2_prover(sp, info.as_ptr(), info.len(), &mut err), -1, "no pin: refused");
        let refusal = take_str(err);
        assert!(refusal.contains("no prover is pinned for this network"), "{refusal}");
        qmb_spend_v2_free(sp);
        qmb_wallet_free(w);
        let c = json!({
            "what": "a format-34 net with no prover pin: what a release kernel refuses (NotPinned), before any step",
            "genesis": hex(&cep.file.hash()),
            "request": { "to": cpayee, "asset": 0, "amount": "10", "valid_for": VALID_FOR },
            "scan": scan,
            "prover": { "info": "info.json" },
            "prover_refusal": refusal,
        });
        std::fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        println!("{name:<14} refused: {}", c["prover_refusal"]);
        cases.insert(name.into(), json!(name));
    }
    // The seeds below are PUBLIC TEST CONSTANTS of this fixture, written so the
    // harness can replay the run — never a real wallet's, never to fund one.
    let manifest = json!({
        "what": "lab #924 PR 3/3b — Candidate A spend and open fixtures, recorded from the real ABI (scan → basis → checked open → spend → take → intent → review → sign; first / restore / stale-check then restore / retired revive / rotated balance / rotated receive) on a format-33 genesis; and (lab #937 cut-over, D-C6) format-34 spends that pay a fixture prover (v3_*), each on its own chain, plus the NotPinned refusal a release kernel replays; and (lab #935/#936, extension #95 §3) each open's landed spends (landed.json), the paged walks, and the matching pair asserted in landed_expected.json. FIXTURE seeds only.",
        "lab_rev": rev,
        "wallet_entropy": hex(&[SEED; 32]),
        "payee_entropy": hex(&[PAYEE; 32]),
        "pin": hex(&ep.file.hash()),
        "scan_rng": hex(&RNG),
        "spend_seed": hex(&SPEND_SEED),
        "dummy_entropy": hex(&DUMMIES),
        "indices": [0, 1],
        "list_key": hex(&qumbra_wallet::asset_view::test_list_key::encoded()),
        "prover_pin": {
            "what": "register for each v3_* genesis below with qmb_harness_pin_fixture (the harness kernel only) before replaying it; v3_not_pinned is replayed WITHOUT it",
            "payee": prover_address().encode(),
            "max_s": PIN_MAX.0,
            "max_p": PIN_MAX.1,
            "genesis": v3_genesis,
        },
        "prover_price": { "S": PRICE.0, "P": PRICE.1 },
        "cases": cases,
    });
    std::fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let sums = sha256sums(&out);
    std::fs::write(out.join("SHA256SUMS"), sums).unwrap();
}
