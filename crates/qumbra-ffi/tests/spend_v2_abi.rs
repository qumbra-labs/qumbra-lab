//! **Candidate A spends over the C ABI** (lab #924 PR 3, the 4b kernel):
//! scan → basis → open the keys → pump the served reads → take → intent →
//! review → sign, over a format-33 fixture chain, and the bundle the kernel
//! exports is one the prover's own lock (`ProvingBundle::check`) accepts.
//!
//! (a) an S payment of asset 0 (one note paying its own fee) and (b) a P
//!     payment of the Hybrid USDT-test (its note plus an exact fee note),
//!     each to another wallet's version-2 address;
//! (c) persist-before-sign: a journal that does not show the take is refused,
//!     and the handle is then spent — one take, one sign;
//! (d) the review is of the pending intent's bytes only;
//! (e) a failed served read before the take, and a plan that cannot be made,
//!     consume no leaf; take is refused before READY;
//! (f) a journal of another seed, a v1 recipient, a zero validity — refused
//!     by name at open/new.
//!
//! Fixture seeds only; nothing proves.

#[path = "../../qumbra-wallet/tests/common/mod.rs"]
mod common;

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use common::*;
use qlab_devnet::annulet::{AuthContext, L2ShapeTag};
use qlab_devnet::body::BlockBody;
use qlab_l2spend::bundle::ProvingBundle;
use qumbra_ffi::annulet::{qmb_annulet_free, qmb_annulet_new_v2, qmb_annulet_step, qmb_annulet_supply, qmb_annulet_supply_err, qmb_annulet_take_basis};
use qumbra_ffi::spend_v2::{
    qmb_auth_journal_summary,
    qmb_auth_journal_advances,
    qmb_auth_check_finish, qmb_auth_check_free, qmb_auth_check_new, qmb_auth_check_step, qmb_auth_check_supply,
    qmb_auth_check_set_page, qmb_auth_check_supply_err, qmb_auth_check_take_landed, qmb_auth_free, qmb_auth_journal, qmb_auth_open_next, qmb_auth_restore_new, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_basis_free,
    qmb_spend_v2_free, qmb_spend_v2_intent, qmb_spend_v2_new, qmb_spend_v2_prover, qmb_spend_v2_refusal, qmb_spend_v2_step,
    qmb_spend_v2_supply,
    qmb_spend_v2_supply_err, AuthHandle, CheckHandle, SpendBasis, SpendHandle, QMB_AUTH_CHECKED, QMB_AUTH_JOURNAL_STALE,
    QMB_AUTH_RESTORED, QMB_AUTH_SWEEP_WAITING,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy, WalletState};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal};
use rand::rngs::StdRng;
use rand::SeedableRng;

const SEED: u8 = 0x4B;
const PAYEE: u8 = 0x4C;
const RNG: [u8; 32] = [0x59; 32];
const SPEND_SEED: [u8; 32] = [0x5A; 32];
const DUMMIES: [u8; 64] = [0x5B; 64];

unsafe fn take_str(p: *mut c_char) -> String {
    assert!(!p.is_null(), "NULL string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    qmb_string_free(p);
    s
}

unsafe fn take_bytes(p: *mut u8, len: usize) -> Vec<u8> {
    assert!(!p.is_null(), "NULL bytes");
    let v = std::slice::from_raw_parts(p, len).to_vec();
    qmb_dealloc(p, len);
    v
}

struct Fixture {
    _dir: WalletDirGuard,
    ep: Endpoint,
    payee: String,
    fresh: String,
}

struct WalletDirGuard(qumbra_wallet::store::WalletDir);
impl Drop for WalletDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0.dir);
    }
}

/// A format-33 chain: the genesis pays the v2 address 0 (generation 0)
/// 1,000,000 USDT-test (Hybrid: shape P), 50 fee units and an exact P-tier
/// fee note (2); height 1 pays it 5 more fee units.
fn chain(tag: &str) -> Fixture {
    chain_lying(tag, Lie::None)
}

/// [`chain`] served by an endpoint that tells `lie`.
fn chain_lying(tag: &str, lie: Lie) -> Fixture {
    chain_full(tag, lie, Vec::new(), false)
}

/// The fixture chain with `extra` blocks after height 1; with `forge_last`
/// the endpoint serves the last block's body as an empty one under its real
/// header (the bodies route lies; the scan's routes see no note of ours).
fn chain_full(tag: &str, lie: Lie, extra: Vec<BlockBody>, forge_last: bool) -> Fixture {
    chain_built(tag, lie, extra, forge_last, false)
}

/// [`chain_full`]; with `g1_note` the genesis also pays 30 fee units to the
/// wallet's generation-1 address 0 (an address only `open_next` hands out).
fn chain_built(tag: &str, lie: Lie, extra: Vec<BlockBody>, forge_last: bool, g1_note: bool) -> Fixture {
    let w = wallet_dir(tag, SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let mut rng = StdRng::seed_from_u64(0x4B);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let mut genesis_notes = vec![note_to(&a2, 50, 0, 30), note_to(&a2, 2, 0, 40)];
    if g1_note {
        let g1 = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 1));
        genesis_notes.push(note_to(&g1, 30, 0, 50));
    }
    let file = genesis_v2(&a2, genesis_notes);
    let mut honest = vec![body];
    honest.extend(extra);
    let ep = if forge_last {
        let mut forged = honest.clone();
        *forged.last_mut().unwrap() = BlockBody::default();
        Endpoint::new(file, &honest, Some(&forged), Lie::ForgedNote)
    } else {
        Endpoint::new(file, &honest, None, lie)
    };
    let payee = wallet_dir(&format!("{tag}_payee"), PAYEE);
    let pw = payee.wallet();
    let to = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0)).encode();
    let _ = std::fs::remove_dir_all(&payee.dir);
    Fixture { _dir: WalletDirGuard(w), ep, payee: to, fresh: AuthJournal::fresh(root).to_text() }
}

/// The verified scan through the ABI, then its basis.
unsafe fn basis(w: *mut WalletState, ep: &Endpoint) -> *mut SpendBasis {
    basis_with(w, ep, None)
}

/// A TEST-signed asset list for `genesis` naming `asset` with `issuer` lanes.
fn list(genesis: &[u8; 32], asset: u16, issuer: [u64; 4]) -> (Vec<u8>, Vec<u8>) {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let bytes = format!(
        r#"{{"v":1,"network":"annulet-ad1","genesis":"{}","testnet":true,"assets":[{{"id":{asset},"issuer_key":"{}","name":"Tether USD (test)","ticker":"tUSDT","decimals":6}}]}}"#,
        hex(genesis),
        hex(&qlab_node::annulet_genesis::h32(&issuer))
    )
    .into_bytes();
    let sig = qumbra_wallet::asset_view::test_list_key::sign(&bytes);
    (bytes, sig)
}

/// [`basis`] with the scan given `list` (bytes, signature) under the TEST key.
unsafe fn basis_with(w: *mut WalletState, ep: &Endpoint, list: Option<&(Vec<u8>, Vec<u8>)>) -> *mut SpendBasis {
    basis_full(w, ep, list, &[])
}

/// Every probe generation — what a restore or a first scans.
const PROBE: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

/// [`basis`] scanning `gens` (empty: the default `[0]`).
unsafe fn basis_g(w: *mut WalletState, ep: &Endpoint, gens: &[u32]) -> *mut SpendBasis {
    basis_full(w, ep, None, gens)
}

unsafe fn basis_full(w: *mut WalletState, ep: &Endpoint, list: Option<&(Vec<u8>, Vec<u8>)>, gens: &[u32]) -> *mut SpendBasis {
    basis_d(w, ep, list, gens, 1)
}

/// [`basis_full`] on authorization derivation `d` (lab #971).
unsafe fn basis_d(w: *mut WalletState, ep: &Endpoint, list: Option<&(Vec<u8>, Vec<u8>)>, gens: &[u32], d: u8) -> *mut SpendBasis {
    let key = qumbra_wallet::asset_view::test_list_key::encoded();
    let (lp, ll, sp, sl, kp, kl) = match list {
        Some((b, s)) => (b.as_ptr(), b.len(), s.as_ptr(), s.len(), key.as_ptr(), key.len()),
        None => (ptr::null(), 0, ptr::null(), 0, ptr::null(), 0),
    };
    let endpoint = CString::new("fixture").unwrap();
    let pin = ep.file.hash();
    let indices = [0u64, 1];
    let null = ptr::null();
    let mut err: *mut c_char = ptr::null_mut();
    let s = qmb_annulet_new_v2(
        w, endpoint.as_ptr(), pin.as_ptr(), d, 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, lp, ll, sp, sl,
        kp, kl, ptr::null(), if gens.is_empty() { ptr::null() } else { gens.as_ptr() }, gens.len(), &mut err,
    );
    assert!(!s.is_null(), "{}", if err.is_null() { String::new() } else { take_str(err) });
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_annulet_step(s, &mut out) {
            1 => {
                let path = take_str(out);
                match ep.fetch(&path) {
                    Ok(body) => qmb_annulet_supply(s, body.as_ptr(), body.len()),
                    Err(why) => qmb_annulet_supply_err(s, CString::new(why).unwrap().as_ptr()),
                }
            }
            0 => break,
            other => panic!("scan step {other}: {}", if out.is_null() { String::new() } else { take_str(out) }),
        }
    }
    let b = qmb_annulet_take_basis(s);
    assert!(!b.is_null(), "a verified scan with an index has a basis");
    assert!(qmb_annulet_take_basis(s).is_null(), "once");
    qmb_annulet_free(s);
    b
}

/// What a checked open returned.
struct Opened {
    a: *mut AuthHandle,
    journal: String,
    status: i32,
    /// The body paths the check asked for, in order.
    paths: Vec<String>,
    /// Lab #935: `qmb_auth_check_take_landed` after the finish.
    landed: String,
}

/// Pump a check (or restore) handle over `ep`'s bodies and finish it.
unsafe fn finish_check(w: *mut WalletState, c: *mut CheckHandle, ep: &Endpoint, fail_at: Option<u64>) -> Result<Opened, String> {
    let mut paths = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_auth_check_step(c, &mut out) {
            1 => {
                let path = take_str(out);
                paths.push(path.clone());
                // A per-block NEED names its height; a page NEED (lab #936) does not.
                let h: Option<u64> = path.split('/').nth(3).and_then(|s| s.parse().ok());
                if fail_at.is_some() && fail_at == h {
                    qmb_auth_check_supply_err(c, CString::new("connection reset").unwrap().as_ptr());
                    continue;
                }
                let body = ep.fetch(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
                qmb_auth_check_supply(c, body.as_ptr(), body.len());
            }
            0 => break,
            -2 => {
                let why = take_str(out);
                qmb_auth_check_free(c);
                return Err(why);
            }
            other => panic!("check step {other}"),
        }
    }
    let (mut jout, mut status, mut err) = (ptr::null_mut(), -1i32, ptr::null_mut());
    let a = qmb_auth_check_finish(w, c, &mut jout, &mut status, &mut err);
    let landed = if a.is_null() {
        String::new()
    } else {
        let mut why: *mut c_char = ptr::null_mut();
        let l = qmb_auth_check_take_landed(c, &mut why);
        assert!(!l.is_null(), "a finished check lists its landed spends: {}", take_str(why));
        take_str(l)
    };
    qmb_auth_check_free(c);
    let journal = if jout.is_null() { String::new() } else { take_str(jout) };
    if a.is_null() {
        return Err(format!("{} [status {status}] {journal}", take_str(err)));
    }
    Ok(Opened { a, journal, status, paths, landed })
}

/// The checked open of `journal`'s generation `g` over `ep`'s verified chain.
unsafe fn open_g(w: *mut WalletState, ep: &Endpoint, journal: &str, g: u32) -> Result<Opened, String> {
    // The host scans every generation of the journal (the header's rule).
    let gens: Vec<u32> = AuthJournal::from_text(journal).map(|j| j.generations().iter().map(|r| r.g).collect()).unwrap_or_default();
    let b = basis_g(w, ep, &gens);
    let j = CString::new(journal).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let c = qmb_auth_check_new(w, j.as_ptr(), b, g, &mut err);
    qmb_spend_basis_free(b);
    if c.is_null() {
        return Err(take_str(err));
    }
    finish_check(w, c, ep, None)
}

/// The checked open of `journal`'s generation 0 (the fixtures' active one).
unsafe fn auth(w: *mut WalletState, ep: &Endpoint, journal: &str) -> Result<*mut AuthHandle, String> {
    open_g(w, ep, journal, 0).map(|o| o.a)
}

unsafe fn spend(b: *mut SpendBasis, to: &str, asset: u16, amount: u64, valid_for: u64) -> Result<*mut SpendHandle, String> {
    let to = CString::new(to).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let s = qmb_spend_v2_new(b, to.as_ptr(), asset, amount, valid_for, SPEND_SEED.as_ptr(), DUMMIES.as_ptr(), &mut err);
    if s.is_null() {
        Err(take_str(err))
    } else {
        Ok(s)
    }
}

/// Pump to READY (`Ok`) or REFUSED (`Err` why), answering from `ep`; the
/// first `fail` NEEDs are answered with a transport failure instead.
unsafe fn pump(a: *const AuthHandle, s: *mut SpendHandle, ep: &Endpoint, mut fail: usize) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_spend_v2_step(a, s, &mut out) {
            1 => {
                let path = take_str(out);
                paths.push(path.clone());
                if fail > 0 {
                    fail -= 1;
                    qmb_spend_v2_supply_err(s, CString::new("connection reset").unwrap().as_ptr());
                    continue;
                }
                let body = ep.fetch(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
                qmb_spend_v2_supply(s, body.as_ptr(), body.len());
            }
            0 => return Ok(paths),
            -2 => return Err(take_str(out)),
            other => panic!("step returned {other}"),
        }
    }
}

unsafe fn take(a: *mut AuthHandle, s: *mut SpendHandle) -> Result<String, String> {
    let mut out: *mut c_char = ptr::null_mut();
    match qmb_auth_take(a, s, &mut out) {
        0 => Ok(take_str(out)),
        _ => Err(take_str(out)),
    }
}

unsafe fn intent(s: *const SpendHandle) -> Vec<u8> {
    let mut len = 0usize;
    take_bytes(qmb_spend_v2_intent(s, &mut len), len)
}

unsafe fn review(s: *const SpendHandle, intent: &[u8]) -> Result<String, String> {
    let mut err: *mut c_char = ptr::null_mut();
    let r = qmb_intent_review(s, intent.as_ptr(), intent.len(), &mut err);
    if r.is_null() {
        Err(take_str(err))
    } else {
        Ok(take_str(r))
    }
}

unsafe fn sign(a: *const AuthHandle, s: *mut SpendHandle, intent: &[u8], journal: &str) -> Result<Vec<u8>, String> {
    let j = CString::new(journal).unwrap();
    let mut len = 0usize;
    let mut err: *mut c_char = ptr::null_mut();
    let b = qmb_intent_sign(a, s, intent.as_ptr(), intent.len(), j.as_ptr(), &mut len, &mut err);
    if b.is_null() {
        Err(take_str(err))
    } else {
        Ok(take_bytes(b, len))
    }
}

fn next_of(journal: &str) -> u32 {
    AuthJournal::from_text(journal).unwrap().get(0).unwrap().next
}

/// One whole spend; the bundle and the review.
unsafe fn send(f: &Fixture, asset: u16, amount: u64, slots: u32, shape: L2ShapeTag) -> (ProvingBundle, String) {
    send_with(f, asset, amount, slots, shape, None)
}

unsafe fn send_with(
    f: &Fixture,
    asset: u16,
    amount: u64,
    slots: u32,
    shape: L2ShapeTag,
    list: Option<&(Vec<u8>, Vec<u8>)>,
) -> (ProvingBundle, String) {
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let a = auth(w, &f.ep, &f.fresh).unwrap();
    let s = spend(basis_with(w, &f.ep, list), &f.payee, asset, amount, 96).unwrap();
    let paths = pump(a, s, &f.ep, 0).expect("READY");
    assert!(paths.iter().any(|p| p == "/v1/annulet/params"), "{paths:?}");
    assert!(paths.iter().any(|p| p.starts_with("/v1/tree/leaves")), "{paths:?}");
    assert_eq!(next_of(&take_str(qmb_auth_journal(a))), 0, "nothing taken while pumping");
    let journal = take(a, s).expect("the take");
    assert_eq!(next_of(&journal), slots, "one leaf per real slot");
    let i = intent(s);
    let text = review(s, &i).expect("the review");
    let bundle = sign(a, s, &i, &journal).expect("signed with the persisted journal");
    let b = ProvingBundle::decode(&bundle).expect("the export is a bundle");
    assert_eq!(b.shape(), shape);
    b.check(&AuthContext::candidate_a(f.ep.file.hash())).expect("the prover's own lock accepts it");
    assert!(b.tx().proof.is_empty(), "the kernel never proves");
    qmb_spend_v2_free(s);
    qmb_auth_free(a);
    qmb_wallet_free(w);
    (b, text)
}

#[test]
fn a_an_s_payment_of_asset_0_is_a_bundle_the_prover_accepts() {
    let f = chain("sv2_a");
    let (b, text) = unsafe { send(&f, 0, 10, 1, L2ShapeTag::S) };
    assert_eq!(b.tx().public.fee, 1, "the S tier");
    let short = qlab_wallet::address::Address::decode_any(&f.payee).unwrap().short().encode();
    assert!(text.contains("step 1 of 1: the payment"), "{text}");
    assert!(text.contains(&format!("to {short}")), "{text}");
    assert!(text.contains("returns to this wallet"), "{text}");
    assert!(text.contains("send 10 fee units to "), "{text}");
    assert!(text.contains("39 fee units returns to this wallet"), "{text}");
    assert!(text.contains("fee: 1 fee unit\n") && text.contains("valid until block "), "{text}");
    assert!(text.starts_with("asset list: none — every asset is unlisted; amounts in base units\n"), "{text}");
    assert!(!text.contains("leaf") && !text.contains("anchor"), "{text}");
}

#[test]
fn b_a_p_payment_of_the_hybrid_asset_takes_its_note_and_an_exact_fee_note() {
    let f = chain("sv2_b");
    let (b, text) = unsafe { send(&f, USDT as u16, 1_000, 2, L2ShapeTag::P) };
    assert_eq!(b.tx().public.fee, 2, "the P tier");
    assert!(text.contains("send 1,000 base units of QIA #1 (no list for this network) to "), "{text}");
    assert!(text.contains("999,000 base units of QIA #1 (no list for this network) returns to this wallet"), "{text}");
    assert!(text.contains("fee: 2 fee units"), "{text}");
}

#[test]
fn c_the_signature_needs_the_take_on_disk_and_happens_once() {
    let f = chain("sv2_c");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &f.fresh).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).unwrap();
        let journal = take(a, s).unwrap();
        assert!(take(a, s).unwrap_err().contains("not READY"), "one take");
        let i = intent(s);
        // The journal as it stood before the take: refused, and the handle is spent.
        let stale = sign(a, s, &i, &f.fresh).unwrap_err();
        assert!(stale.contains("does not show this take"), "{stale}");
        let again = sign(a, s, &i, &journal).unwrap_err();
        assert!(again.contains("once already"), "{again}");
        assert!(qmb_spend_v2_intent(s, &mut 0usize).is_null(), "the intent is gone with the handle");
        assert!(take_str(qmb_spend_v2_refusal(s)).contains("once already"));
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

#[test]
fn d_the_review_is_of_the_pending_intent_only() {
    let f = chain("sv2_d");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &f.fresh).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).unwrap();
        let journal = take(a, s).unwrap();
        let mut i = intent(s);
        let last = i.len() - 1;
        i[last] ^= 1;
        assert!(review(s, &i).unwrap_err().contains("not the bytes"));
        assert!(sign(a, s, &i, &journal).unwrap_err().contains("not the bytes"));
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

#[test]
fn e_nothing_is_taken_until_every_read_is_in() {
    let f = chain("sv2_e");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &f.fresh).unwrap();
        // A failed read: refused by name, no leaf taken, and take refused.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let why = pump(a, s, &f.ep, 1).unwrap_err();
        assert!(why.contains("connection reset"), "{why}");
        assert!(take(a, s).unwrap_err().contains("not READY"));
        qmb_spend_v2_free(s);
        // A plan that cannot be made: more asset 0 than the wallet holds.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 1_000, 96).unwrap();
        let why = pump(a, s, &f.ep, 0).unwrap_err();
        assert!(why.contains("no single spendable note of asset 0"), "{why}");
        qmb_spend_v2_free(s);
        assert_eq!(next_of(&take_str(qmb_auth_journal(a))), 0, "no leaf consumed");
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

#[test]
fn f_another_seed_s_journal_a_v1_recipient_and_a_zero_validity_are_refused() {
    let f = chain("sv2_f");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let other = qmb_wallet_from_entropy([PAYEE; 32].as_ptr());
        let foreign = auth(other, &f.ep, &f.fresh).unwrap_err();
        assert!(foreign.contains("not this wallet's tree"), "{foreign}");
        qmb_wallet_free(other);
        let payee_v1 = wallet_dir("sv2_f_v1", PAYEE);
        let v1 = payee_v1.wallet().address_at_index(0).encode();
        let _ = std::fs::remove_dir_all(&payee_v1.dir);
        assert!(spend(basis(w, &f.ep), &v1, 0, 10, 96).unwrap_err().contains("version"));
        assert!(spend(basis(w, &f.ep), &f.payee, 0, 10, 0).unwrap_err().contains("valid_for 0"));
        let b = basis(w, &f.ep);
        qmb_spend_basis_free(b);
        qmb_wallet_free(w);
    }
}

/// A journal of generation 0 standing at `next`.
fn journal_at(f: &Fixture, next: u32) -> String {
    let mut j = AuthJournal::from_text(&f.fresh).unwrap();
    j.advance_mem(0, next).unwrap();
    j.to_text()
}

#[test]
fn g_the_signature_refuses_another_tree_s_journal_and_a_bad_call_still_spends() {
    let f = chain("sv2_g");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &f.fresh).unwrap();
        // Another wallet's journal, its cursor well past this take: the root decides.
        let other = wallet_dir("sv2_g_other", PAYEE);
        let mut foreign = AuthJournal::fresh(generation_root(&other.wallet(), 0));
        let _ = std::fs::remove_dir_all(&other.dir);
        foreign.advance_mem(0, 100).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        assert!(take(a, s).unwrap_err().contains("not READY"), "no take while pumping");
        pump(a, s, &f.ep, 0).unwrap();
        let journal = take(a, s).unwrap();
        // A stray answer after READY is ignored: the prepared spend survives.
        qmb_spend_v2_supply(s, b"x".as_ptr(), 1);
        qmb_spend_v2_supply_err(s, CString::new("late").unwrap().as_ptr());
        let i = intent(s);
        assert!(review(s, &i).is_ok(), "still prepared");
        let why = sign(a, s, &i, &foreign.to_text()).unwrap_err();
        assert!(why.contains("does not show this take"), "{why}");
        assert!(sign(a, s, &i, &journal).unwrap_err().contains("once already"));
        qmb_spend_v2_free(s);

        // Refused for its bytes: spent all the same.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).unwrap();
        let journal = take(a, s).unwrap();
        let i = intent(s);
        assert!(sign(a, s, &i[1..], &journal).unwrap_err().contains("not the bytes"));
        assert!(sign(a, s, &i, &journal).unwrap_err().contains("once already"));
        qmb_spend_v2_free(s);

        // A NULL argument: spent all the same.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).unwrap();
        let journal = take(a, s).unwrap();
        let i = intent(s);
        let j = CString::new(journal.clone()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let mut len = 0usize;
        assert!(qmb_intent_sign(a, s, ptr::null(), 0, j.as_ptr(), &mut len, &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        assert!(sign(a, s, &i, &journal).unwrap_err().contains("once already"));
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

/// F1: the budget is judged before the take. At exactly the floor the spend
/// goes through (its own leaves do not count against it after the take);
/// one leaf less is refused before anything is taken.
#[test]
fn h_the_budget_boundary_is_judged_before_the_take() {
    let f = chain("sv2_h");
    // Four spendable notes in generation 0: floor = 4 + 2; one leaf needed.
    let at_floor = 4096 - (1 + 4 + 2);
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &journal_at(&f, at_floor)).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).expect("exactly at the floor: READY");
        let journal = take(a, s).unwrap();
        assert_eq!(next_of(&journal), at_floor + 1);
        let i = intent(s);
        sign(a, s, &i, &journal).expect("the take's own leaf does not refuse it");
        qmb_spend_v2_free(s);
        qmb_auth_free(a);

        let below = journal_at(&f, at_floor + 1);
        let a = auth(w, &f.ep, &below).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let why = pump(a, s, &f.ep, 0).unwrap_err();
        assert!(why.contains("below the 6 needed to sweep"), "{why}");
        assert_eq!(next_of(&take_str(qmb_auth_journal(a))), at_floor + 1, "no leaf consumed");
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

#[test]
fn i_every_export_answers_null_by_name_or_as_a_no_op() {
    unsafe {
        let mut err: *mut c_char = ptr::null_mut();
        let j = CString::new("x").unwrap();
        assert!(qmb_auth_check_new(ptr::null(), j.as_ptr(), ptr::null(), 0, &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        assert!(qmb_auth_restore_new(ptr::null(), ptr::null(), &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_check_step(ptr::null_mut(), &mut out), -1);
        qmb_auth_check_supply(ptr::null_mut(), ptr::null(), 0);
        qmb_auth_check_supply_err(ptr::null_mut(), ptr::null());
        let mut st = 0i32;
        assert!(qmb_auth_check_finish(ptr::null(), ptr::null_mut(), &mut out, &mut st, &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        qmb_auth_check_free(ptr::null_mut());
        assert_eq!(qmb_auth_open_next(ptr::null(), j.as_ptr(), ptr::null(), &mut out), -1);
        assert!(qmb_auth_journal(ptr::null()).is_null());
        qmb_auth_free(ptr::null_mut());
        let to = CString::new("x").unwrap();
        assert!(qmb_spend_v2_new(ptr::null_mut(), to.as_ptr(), 0, 1, 1, SPEND_SEED.as_ptr(), DUMMIES.as_ptr(), &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_spend_v2_step(ptr::null(), ptr::null_mut(), &mut out), -1);
        qmb_spend_v2_supply(ptr::null_mut(), ptr::null(), 0);
        qmb_spend_v2_supply_err(ptr::null_mut(), ptr::null());
        assert_eq!(qmb_auth_take(ptr::null_mut(), ptr::null_mut(), &mut out), -1);
        assert!(qmb_spend_v2_intent(ptr::null(), &mut 0usize).is_null());
        assert!(qmb_spend_v2_refusal(ptr::null()).is_null());
        assert!(qmb_intent_review(ptr::null(), ptr::null(), 0, &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        assert!(qmb_intent_sign(ptr::null(), ptr::null_mut(), ptr::null(), 0, ptr::null(), &mut 0usize, &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        qmb_spend_v2_free(ptr::null_mut());
        qmb_spend_basis_free(ptr::null_mut());
    }
}

/// Lab #924 PR 3c: the review names an asset only from the verified list,
/// and only while its leaf (bound to the verified tip) carries the listed
/// issuer key; otherwise the raw base units, saying why.
#[test]
fn j_the_review_names_the_asset_from_the_verified_list_only() {
    let f = chain("sv2_j");
    let genesis = f.ep.file.hash();
    unsafe {
        // Listed, issuer as on chain: name, ticker and decimals.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&genesis, USDT as u16, [9; 4])));
        assert!(text.starts_with("asset list: annulet-ad1 "), "{text}");
        assert!(text.contains("— a test network: test money"), "{text}");
        assert!(text.contains("send 0.001000 tUSDT (Tether USD (test)) to "), "{text}");
        assert!(text.contains("0.999000 tUSDT (Tether USD (test)) returns to this wallet"), "{text}");
        assert!(text.contains("fee: 2 fee units"), "{text}");
        // Listed under another issuer key: the name is withheld.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&genesis, USDT as u16, [8; 4])));
        assert!(text.contains("send 1,000 base units of QIA #1 (listed as tUSDT, but its issuer key changed: name withheld)"), "{text}");
        // The list does not carry asset 1: not on list <short id>.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&genesis, 7, [9; 4])));
        assert!(text.contains("send 1,000 base units of QIA #1 (not on list "), "{text}");
        // A list for another network: ignored.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&[0x11; 32], USDT as u16, [9; 4])));
        assert!(text.starts_with("asset list: for another network (11111111), ignored"), "{text}");
        assert!(text.contains("(no list for this network)"), "{text}");
    }
    // An endpoint that serves the listed issuer key on a registry path that
    // does not fold to its root: the name is withheld, and the review says
    // why — a lie told apart from data not yet served.
    let lying = chain_lying("sv2_j_lie", Lie::RegistryBadPath);
    let genesis = lying.ep.file.hash();
    let w = unsafe { qmb_wallet_from_entropy([SEED; 32].as_ptr()) };
    unsafe {
        let a = auth(w, &lying.ep, &lying.fresh).unwrap();
        let s = spend(basis_with(w, &lying.ep, Some(&list(&genesis, USDT as u16, [9; 4]))), &lying.payee, USDT as u16, 1_000, 96)
            .unwrap();
        pump(a, s, &lying.ep, 0).expect("READY: the opening decodes");
        take(a, s).unwrap();
        let text = review(s, &intent(s)).unwrap();
        assert!(!text.contains("tUSDT ("), "no name: {text}");
        assert!(
            text.contains("(listed as tUSDT; its issuer could not be confirmed: the endpoint's registry path does not fold to its root; name withheld)"),
            "{text}"
        );
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
}

// ------------------------------------------------------------ PR 3b

/// One signed S spend of 10 fee units from a fresh journal on `f`, as the
/// block transaction it would land as (a placeholder proof: the fixture
/// chain seals without verifying), and the journal the take wrote.
unsafe fn landed_spend(f: &Fixture) -> (qlab_devnet::body::TxEntry, String) {
    let (tx, journal, _) = landed_spend_recorded(f);
    (tx, journal)
}

/// Lab #935: what the spend's own parties hold for it, recorded as it is
/// made — the id the prover service returns for the transaction it submits
/// (`qlab_p2p::codec::tx_id`, the service's own call) and the digest of the
/// intent bytes the device signed.
#[derive(Clone)]
struct SpendRecord {
    tx_id: [u8; 32],
    intent_digest: [u8; 32],
    /// Lab #989: the signed bundle as a remote send records it.
    bundle: Vec<u8>,
}

/// [`landed_spend`] with its [`SpendRecord`].
unsafe fn landed_spend_recorded(f: &Fixture) -> (qlab_devnet::body::TxEntry, String, SpendRecord) {
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let a = auth(w, &f.ep, &f.fresh).unwrap();
    let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
    pump(a, s, &f.ep, 0).unwrap();
    let journal = take(a, s).unwrap();
    let i = intent(s);
    let bundle = sign(a, s, &i, &journal).unwrap();
    let mut tx = ProvingBundle::decode(&bundle).unwrap().tx().clone();
    tx.proof = vec![0xAB; 64];
    let record = SpendRecord { tx_id: qlab_p2p::codec::tx_id(&tx), intent_digest: qlab_remote_auth::keccak256(&[&i]), bundle };
    qmb_spend_v2_free(s);
    qmb_auth_free(a);
    qmb_wallet_free(w);
    (tx, journal, record)
}

/// The fixture chain on which our spend landed at height 2 — built once.
fn spent_chain() -> &'static (Fixture, String) {
    &spent_chain_recorded().0
}

/// [`spent_chain`] with the spend's [`SpendRecord`].
fn spent_chain_recorded() -> &'static ((Fixture, String), SpendRecord) {
    static F: std::sync::OnceLock<((Fixture, String), SpendRecord)> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let f = chain("sv2_spent_src");
        let (tx, journal, record) = unsafe { landed_spend_recorded(&f) };
        let landed = chain_full("sv2_spent", Lie::None, vec![BlockBody { txs: vec![tx], ..BlockBody::default() }], false);
        ((landed, journal), record)
    })
}

fn genesis_hex(f: &Fixture) -> String {
    f.ep.file.hash().iter().map(|b| format!("{b:02x}")).collect()
}

/// The journal that saw the take is checked, pumping only the blocks after
/// its `checked_to`; one checked past the tip is walked from height 1; a
/// journal older than the landed leaf is STALE — no keys, its cursor raised
/// and returned to persist — and a restore then takes over.
#[test]
fn k_the_open_check_finds_a_journal_older_than_the_chain() {
    let (f, persisted) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        // The take's journal was checked on the source chain through height 1.
        assert!(persisted.contains(&format!("checked 0 {}:1", genesis_hex(f))), "{persisted}");
        let ok = open_g(w, &f.ep, persisted, 0).unwrap();
        assert_eq!(ok.paths, vec!["/v1/block/2/body".to_string()], "only what is past checked_to");
        assert_eq!(ok.status, QMB_AUTH_CHECKED);
        assert!(ok.journal.contains(&format!("checked 0 {}:2", genesis_hex(f))), "{}", ok.journal);
        assert_eq!(next_of(&ok.journal), 1);
        qmb_auth_free(ok.a);
        // Checked past the verified tip (an edited backup): walked from 1.
        let beyond = persisted.replace(&format!("{}:1", genesis_hex(f)), &format!("{}:99", genesis_hex(f)));
        let again = open_g(w, &f.ep, &beyond, 0).unwrap();
        assert_eq!(again.paths.first().map(String::as_str), Some("/v1/block/1/body"));
        qmb_auth_free(again.a);

        let stale = open_g(w, &f.ep, &f.fresh, 0).err().unwrap();
        assert!(stale.contains(&format!("[status {QMB_AUTH_JOURNAL_STALE}]")), "{stale}");
        assert!(stale.contains("then run qmb_auth_restore_new"), "{stale}");
        let returned = stale.split_once("] ").unwrap().1;
        let j = AuthJournal::from_text(returned).unwrap();
        assert_eq!((j.active().g, j.get(0).unwrap().next), (0, 1), "raised, not rotated: {returned}");
        // Then the restore: generation 0 sweep-only, generation 1 active.
        let r = first_or_restore(w, &f.ep, true).unwrap();
        assert_eq!(r.status, QMB_AUTH_RESTORED);
        assert_eq!(AuthJournal::from_text(&r.journal).unwrap().active().g, 1);
        qmb_auth_free(r.a);
        qmb_wallet_free(w);
    }
}

/// Restore: the spent seed — generation 0 sweep-only above its landed leaf,
/// generation 1 active; every generation checked to the tip.
#[test]
fn l_restore_never_resumes_a_used_generation() {
    let (f, _) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis_g(w, &f.ep, &PROBE);
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_restore_new(w, b, &mut err);
        qmb_spend_basis_free(b);
        let r = finish_check(w, c, &f.ep, None).unwrap();
        assert_eq!(r.status, QMB_AUTH_RESTORED);
        let j = AuthJournal::from_text(&r.journal).unwrap();
        assert_eq!((j.active().g, j.get(0).unwrap().next), (1, 1), "{}", r.journal);
        assert!(r.journal.contains(&format!("checked 1 {}:2", genesis_hex(f))), "{}", r.journal);
        qmb_auth_free(r.a);
        qmb_wallet_free(w);
    }
}

// ------------------------------------------------------------ lab #935

/// `qmb_auth_check_take_landed`'s JSON as `(height, tx_id, intent_digest,
/// leaves)` rows.
fn landed_rows(json: &str) -> Vec<(u64, String, String, u64)> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}"));
    v.as_array()
        .unwrap_or_else(|| panic!("not an array: {json}"))
        .iter()
        .map(|r| {
            (
                r["height"].as_u64().unwrap(),
                r["tx_id"].as_str().unwrap().to_string(),
                r["intent_digest"].as_str().unwrap().to_string(),
                r["leaves"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The landed send names the id the prover service returned for it and the
/// digest its device signed — both RECORDED when the spend was made
/// (`SpendRecord`), here found again from the bound body alone.
#[test]
fn a_landed_spend_names_the_provers_tx_id_and_the_signed_intents_digest() {
    let ((f, persisted), record) = spent_chain_recorded();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let ok = open_g(w, &f.ep, persisted, 0).unwrap();
        assert_eq!(landed_rows(&ok.landed), vec![(2, hex32(&record.tx_id), hex32(&record.intent_digest), 1)], "{}", ok.landed);
        qmb_auth_free(ok.a);
        qmb_wallet_free(w);
    }
}

/// A check lists what landed since its journal's checked height: the take's
/// journal (checked through 1) lists the height-2 spend; the journal that
/// check returns (checked through 2) lists nothing.
#[test]
fn a_check_lists_only_spends_since_its_checked_height() {
    let ((f, persisted), record) = spent_chain_recorded();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let first = open_g(w, &f.ep, persisted, 0).unwrap();
        let rows = landed_rows(&first.landed);
        assert_eq!(rows.iter().map(|r| (r.0, r.1.clone())).collect::<Vec<_>>(), vec![(2, hex32(&record.tx_id))]);
        qmb_auth_free(first.a);
        let again = open_g(w, &f.ep, &first.journal, 0).unwrap();
        assert!(again.paths.is_empty(), "nothing past checked_to: {:?}", again.paths);
        assert_eq!(again.landed, "[]");
        qmb_auth_free(again.a);
        // A seed with no spend on its chain lists none.
        let quiet = chain("sv2_landed_quiet");
        let none = open_g(w, &quiet.ep, &quiet.fresh, 0).unwrap();
        assert_eq!(none.landed, "[]");
        qmb_auth_free(none.a);
        qmb_wallet_free(w);
    }
}

/// A restore lists the key's whole history on this net: the one spend on
/// the spent chain, recorded ids and all; both generations' spends on the
/// two-generation chain, in height order, one leaf each, distinct.
#[test]
fn a_restore_lists_the_keys_whole_history_on_this_net() {
    let ((f, _), record) = spent_chain_recorded();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let r = first_or_restore(w, &f.ep, true).unwrap();
        assert_eq!(r.status, QMB_AUTH_RESTORED);
        assert_eq!(landed_rows(&r.landed), vec![(2, hex32(&record.tx_id), hex32(&record.intent_digest), 1)]);
        qmb_auth_free(r.a);
        let two = two_gen_chain();
        let r = first_or_restore(w, &two.ep, true).unwrap();
        let rows = landed_rows(&r.landed);
        assert_eq!(rows.iter().map(|r| (r.0, r.3)).collect::<Vec<_>>(), vec![(2, 1), (3, 1)], "{}", r.landed);
        assert_ne!(rows[0].1, rows[1].1, "two transactions");
        assert_ne!(rows[0].2, rows[1].2, "two intents");
        qmb_auth_free(r.a);
        qmb_wallet_free(w);
    }
}

/// The list is read after the finish returned a journal; before, NULL and
/// why, by name — and NULL for a NULL handle.
#[test]
fn qmb_auth_check_take_landed_refuses_before_finish() {
    let (f, _) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis_g(w, &f.ep, &PROBE);
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_restore_new(w, b, &mut err);
        qmb_spend_basis_free(b);
        assert!(!c.is_null(), "{}", take_str(err));
        let mut why: *mut c_char = ptr::null_mut();
        assert!(qmb_auth_check_take_landed(c, &mut why).is_null());
        assert!(take_str(why).contains("after the check finished with a journal"));
        // Finished, it lists (finish_check takes it, asserting non-NULL).
        let r = finish_check(w, c, &f.ep, None).unwrap();
        assert_eq!(landed_rows(&r.landed).len(), 1);
        qmb_auth_free(r.a);
        // A check refused at a body never finishes with a journal: refused.
        let b = basis_g(w, &f.ep, &PROBE);
        let c = qmb_auth_restore_new(w, b, &mut err);
        qmb_spend_basis_free(b);
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_check_step(c, &mut out), 1);
        let _ = take_str(out);
        qumbra_ffi::spend_v2::qmb_auth_check_supply_err(c, CString::new("connection reset").unwrap().as_ptr());
        let (mut jout, mut status) = (ptr::null_mut(), -1i32);
        assert!(qmb_auth_check_finish(w, c, &mut jout, &mut status, &mut err).is_null());
        let _ = take_str(err);
        assert!(qmb_auth_check_take_landed(c, &mut why).is_null());
        assert!(take_str(why).contains("after the check finished with a journal"));
        qmb_auth_check_free(c);
        assert!(qmb_auth_check_take_landed(ptr::null(), &mut why).is_null());
        assert_eq!(take_str(why), "NULL argument");
        qmb_wallet_free(w);
    }
}

/// A body the check needs is not optional: unreachable → refused by name;
/// a body that does not bind to its verified header → refused by name.
#[test]
fn m_a_missing_or_lying_body_refuses_the_open() {
    let f = chain("sv2_m");
    // Block 2 carries a payment to the payee; the endpoint serves it empty
    // under its real header — the commitment cannot match.
    let lying = {
        let payee = wallet_dir("sv2_m_lie_payee", PAYEE);
        let pw = payee.wallet();
        let to = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0));
        let _ = std::fs::remove_dir_all(&payee.dir);
        let mut rng = StdRng::seed_from_u64(0x4D);
        let paid = BlockBody { txs: vec![pay_tx(&to, &[note_to(&to, 3, 0, 60)], 0x60, &mut rng)], ..BlockBody::default() };
        chain_full("sv2_m_lie", Lie::None, vec![paid], true)
    };
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis(w, &f.ep);
        let j = CString::new(f.fresh.clone()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_check_new(w, j.as_ptr(), b, 0, &mut err);
        qmb_spend_basis_free(b);
        let why = finish_check(w, c, &f.ep, Some(1)).err().unwrap();
        assert!(why.contains("block 1's body is unavailable: connection reset"), "{why}");
        let why = open_g(w, &lying.ep, &lying.fresh, 0).err().unwrap();
        assert!(why.contains("block 2's body is not the one its verified header commits to"), "{why}");
        qmb_wallet_free(w);
    }
}

/// Migrate: open-next makes generation 0 sweep-only behind a gate on this
/// net; opening it to sweep before the gate waits (no keys, journal back).
/// Past its gate a sweep pays only the active generation's own address.
#[test]
fn n_open_next_then_the_sweep_gate_and_its_target() {
    let f = chain("sv2_n");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis(w, &f.ep);
        let j = CString::new(f.fresh.clone()).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_open_next(w, j.as_ptr(), b, &mut out), 0);
        qmb_spend_basis_free(b);
        let migrated = take_str(out);
        let mj = AuthJournal::from_text(&migrated).unwrap();
        assert_eq!(mj.active().g, 1);
        let waiting = open_g(w, &f.ep, &migrated, 0).err().unwrap();
        assert!(waiting.contains(&format!("[status {QMB_AUTH_SWEEP_WAITING}]")), "{waiting}");

        // The gate passed: generation 0 sweep-only with its gate at height 0.
        let g0 = mj.get(0).unwrap().clone();
        let g1 = mj.get(1).unwrap().clone();
        let gate = qumbra_wallet::auth_journal::SweepGate { genesis: f.ep.file.hash(), not_before_height: 0 };
        let open_gate = AuthJournal::from_generations(vec![
            qumbra_wallet::auth_journal::Generation { state: qumbra_wallet::auth_journal::GenState::Sweep { gates: vec![gate] }, ..g0 },
            g1,
        ])
        .unwrap()
        .to_text();
        let sweep = open_g(w, &f.ep, &open_gate, 0).unwrap();
        assert_eq!(sweep.status, QMB_AUTH_CHECKED);
        // To anyone else: refused.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let why = pump(sweep.a, s, &f.ep, 0).unwrap_err();
        assert!(why.contains("sweep-only"), "{why}");
        qmb_spend_v2_free(s);
        // To this wallet's active generation: a bundle the prover accepts.
        let active = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 1, 1, ptr::null()));
        let s = spend(basis(w, &f.ep), &active, 0, 10, 96).unwrap();
        pump(sweep.a, s, &f.ep, 0).expect("READY");
        let journal = take(sweep.a, s).unwrap();
        let i = intent(s);
        let bundle = sign(sweep.a, s, &i, &journal).unwrap();
        ProvingBundle::decode(&bundle).unwrap().check(&AuthContext::candidate_a(f.ep.file.hash())).unwrap();
        qmb_spend_v2_free(s);
        qmb_auth_free(sweep.a);
        qmb_wallet_free(w);
    }
}

/// Run `first` (or restore) on `ep` for handle `w`.
unsafe fn first_or_restore(w: *mut WalletState, ep: &Endpoint, restore: bool) -> Result<Opened, String> {
    let b = basis_g(w, ep, &PROBE);
    let mut err: *mut c_char = ptr::null_mut();
    let c = if restore { qmb_auth_restore_new(w, b, &mut err) } else { qumbra_ffi::spend_v2::qmb_auth_first_new(w, b, &mut err) };
    qmb_spend_basis_free(b);
    assert!(!c.is_null(), "{}", take_str(err));
    finish_check(w, c, ep, None)
}

/// `first`: generation 0 fresh on a seed that received but never signed —
/// its notes spendable at once; refused by name on a seed that signed.
#[test]
fn o_first_gives_a_never_signed_seed_generation_0() {
    let f = chain("sv2_o");
    let (spent, _) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let first = first_or_restore(w, &f.ep, false).unwrap();
        assert_eq!(first.status, qumbra_ffi::spend_v2::QMB_AUTH_FIRST);
        let j = AuthJournal::from_text(&first.journal).unwrap();
        assert_eq!((j.active().g, j.active().next, j.generations().len()), (0, 0, 1), "{}", first.journal);
        // Its notes are spendable now: a payment goes through to READY.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(first.a, s, &f.ep, 0).expect("READY at once, no sweep wait");
        qmb_spend_v2_free(s);
        qmb_auth_free(first.a);
        let why = first_or_restore(w, &spent.ep, false).err().unwrap();
        assert!(why.contains("this seed has signed") && why.contains("use restore"), "{why}");
        qmb_wallet_free(w);
    }
}

/// `first_fresh`: only a handle whose seed this kernel drew; the journal is
/// the one `first` writes for the same seed on a chain with no block.
#[test]
fn p_first_fresh_is_only_for_a_seed_born_here() {
    unsafe {
        let born = qumbra_ffi::qmb_wallet_new_fresh();
        assert!(!born.is_null());
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 1, ptr::null(), &mut out), 0);
        let fresh = take_str(out);
        assert_eq!(next_of(&fresh), 0);
        assert!(fresh.starts_with("qumbra-wallet auth v1\n"), "{fresh}");
        // Once: the mark is consumed.
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 1, ptr::null(), &mut out), -1);
        assert!(take_str(out).contains("use qmb_auth_first_new or qmb_auth_restore_new"));

        // The same seed through the three outside doors: refused by name.
        let mut entropy = [0u8; 32];
        qumbra_ffi::qmb_wallet_seed_entropy(born, entropy.as_mut_ptr());
        let version = qumbra_ffi::qmb_wallet_seed_version(born);
        let phrase = take_str(qumbra_ffi::qmb_wallet_reveal_mnemonic(born));
        let mut err: *mut c_char = ptr::null_mut();
        let outside = [
            qmb_wallet_from_entropy(entropy.as_ptr()),
            qumbra_ffi::qmb_wallet_from_parts(version, entropy.as_ptr(), &mut err),
            qumbra_ffi::qmb_wallet_restore(CString::new(phrase).unwrap().as_ptr(), &mut err),
        ];
        for h in outside {
            assert!(!h.is_null());
            assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(h, 1, ptr::null(), &mut out), -1);
            let why = take_str(out);
            assert!(why.contains("use qmb_auth_first_new or qmb_auth_restore_new"), "{why}");
        }
        // `first` for the same seed on a chain with no block: the same text.
        let w = outside[0];
        let other = wallet_dir("sv2_p_holder", PAYEE);
        let holder = other.wallet().address_candidate_a_at_index(0, &generation_root(&other.wallet(), 0));
        let _ = std::fs::remove_dir_all(&other.dir);
        let empty = Endpoint::new(genesis_v2(&holder, Vec::new()), &[], None, Lie::None);
        let first = first_or_restore(w, &empty, false).unwrap();
        assert_eq!(first.journal, fresh, "first_fresh == first on an empty chain");
        qmb_auth_free(first.a);
        for h in outside {
            qmb_wallet_free(h);
        }
        qmb_wallet_free(born);
    }
}

/// The header's `#define QMB_AUTH_*` and `spend_v2.rs`'s `pub const
/// QMB_AUTH_*: i32` are one set with one set of values, both directions —
/// a status that drifts is a shell reading REPLACED as CHECKED.
#[test]
fn q_the_header_pins_the_open_statuses() {
    let header = include_str!("../include/qumbra_ffi.h");
    let src = include_str!("../src/spend_v2.rs");
    let from_header: std::collections::BTreeSet<(String, i32)> = header
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("#define QMB_AUTH_")?;
            let (name, v) = rest.split_once(' ')?;
            Some((name.to_string(), v.trim().parse().ok()?))
        })
        .collect();
    let from_src: std::collections::BTreeSet<(String, i32)> = src
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("pub const QMB_AUTH_")?;
            let (name, tail) = rest.split_once(": i32 = ")?;
            Some((name.to_string(), tail.trim_end_matches(';').trim().parse().ok()?))
        })
        .collect();
    assert_eq!(from_header.len(), 6, "{from_header:?}");
    assert_eq!(from_header, from_src);
    assert_eq!(QMB_AUTH_CHECKED, 0);
    assert_eq!(QMB_AUTH_RESTORED, 3);
    // PR 3d's ABI door over `advances_from` (its rules: qlab-remote-auth's
    // `a_journal_only_advances`): 1 / 0 / -1, NULL-safe.
    let before = AuthJournal::fresh([1, 2, 3, 4]);
    let mut after = before.clone();
    after.advance_mem(0, 3).unwrap();
    let (b, a) = (CString::new(before.to_text()).unwrap(), CString::new(after.to_text()).unwrap());
    let junk = CString::new("not a journal").unwrap();
    unsafe {
        let mut why: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_journal_advances(b.as_ptr(), b.as_ptr(), &mut why), 1);
        assert!(why.is_null());
        assert_eq!(qmb_auth_journal_advances(b.as_ptr(), a.as_ptr(), &mut why), 1);
        assert_eq!(qmb_auth_journal_advances(a.as_ptr(), b.as_ptr(), &mut why), 0);
        assert!(take_str(why).contains("cursor moves back"));
        assert_eq!(qmb_auth_journal_advances(ptr::null(), a.as_ptr(), &mut why), -1);
        assert!(take_str(why).contains("stored journal is NULL"));
        assert_eq!(qmb_auth_journal_advances(a.as_ptr(), junk.as_ptr(), &mut why), -1);
        assert!(take_str(why).contains("new journal does not parse"));
        assert_eq!(qmb_auth_journal_advances(a.as_ptr(), b.as_ptr(), ptr::null_mut()), 0, "out_why may be NULL");
        let huge = CString::new(before.to_text() + &"#".repeat(64 * 1024)).unwrap();
        assert_eq!(qmb_auth_journal_advances(b.as_ptr(), huge.as_ptr(), &mut why), -1);
        assert!(take_str(why).contains("the new journal is"), "bounded before parsing");
    }
}

/// Lab #971's ABI door over `restore_across`: the #971 counterexample by
/// text (net A fresh, net B with generation 0's leaves landed) merges to
/// generation 1 above B's cursor, and every refusal is by name. Records
/// only: no chain, no tree, no handle.
#[test]
fn q_restore_across_merges_restored_texts_and_refuses_by_name() {
    use qumbra_ffi::spend_v2::qmb_auth_restore_across;
    use qumbra_wallet::auth_journal::{GenState, Generation};
    let root = |g: u32| [0x5eed, u64::from(g), 7, 9];
    let a = AuthJournal::fresh(root(0));
    let b = AuthJournal::from_generations(vec![
        Generation { g: 0, next: 3, auth_root: root(0), state: GenState::Retired },
        Generation { g: 1, next: 0, auth_root: root(1), state: GenState::Active },
    ])
    .unwrap();
    let other = AuthJournal::fresh([1, 2, 3, 4]);
    let text = |j: &AuthJournal| CString::new(j.to_text()).unwrap();
    let (ta, tb, tother) = (text(&a), text(&b), text(&other));
    let junk = CString::new("not a journal").unwrap();
    unsafe {
        let mut out: *mut c_char = ptr::null_mut();
        let both = [ta.as_ptr(), tb.as_ptr()];
        assert_eq!(qmb_auth_restore_across(both.as_ptr(), 2, &mut out), 0);
        let merged = AuthJournal::from_text(&take_str(out)).unwrap();
        assert_eq!((merged.active().g, merged.active().next), (1, 0));
        assert_eq!(merged.get(0).unwrap().next, 3);
        assert_eq!(merged.to_text(), qumbra_wallet::auth_check::restore_across(&[a.clone(), b.clone()]).unwrap().to_text());

        let one = [tb.as_ptr()];
        assert_eq!(qmb_auth_restore_across(one.as_ptr(), 1, &mut out), 0);
        assert_eq!(take_str(out), b.to_text(), "one journal comes back unchanged");

        assert_eq!(qmb_auth_restore_across(both.as_ptr(), 0, &mut out), -1);
        assert!(take_str(out).contains("at least one net's restored journal"));
        assert_eq!(qmb_auth_restore_across(ptr::null(), 2, &mut out), -1);
        assert!(take_str(out).contains("at least one net's restored journal"));
        let many = [ta.as_ptr(); 17];
        assert_eq!(qmb_auth_restore_across(many.as_ptr(), 17, &mut out), -1);
        assert!(take_str(out).contains("over the 16"));
        let with_null = [ta.as_ptr(), ptr::null()];
        assert_eq!(qmb_auth_restore_across(with_null.as_ptr(), 2, &mut out), -1);
        assert!(take_str(out).contains("journal 1 is NULL"));
        let with_junk = [ta.as_ptr(), junk.as_ptr()];
        assert_eq!(qmb_auth_restore_across(with_junk.as_ptr(), 2, &mut out), -1);
        assert!(take_str(out).contains("journal 1 does not parse"));
        let two_keys = [ta.as_ptr(), tother.as_ptr()];
        assert_eq!(qmb_auth_restore_across(two_keys.as_ptr(), 2, &mut out), -1);
        assert!(take_str(out).contains("generation 0 different authorization roots"));
        assert_eq!(qmb_auth_restore_across(both.as_ptr(), 2, ptr::null_mut()), -1, "out_journal NULL");
    }
}

/// Lab #971 through the ABI: a scan on authorization derivation 2 leaves a
/// basis the `qmb_auth_*` calls derive from — restore and first write an
/// `auth v3` journal naming the scan's genesis; that journal is refused on a
/// derivation-1 basis and by `qmb_auth_restore_across`, and a derivation-1
/// journal on the derivation-2 basis; `qmb_auth_first_fresh` takes the net
/// (refusing a bad one before consuming the mark); a scan with an unknown
/// derivation, or one other than the build's pin for the genesis, is
/// refused by name before any read.
#[test]
fn v_a_derivation_2_basis_writes_and_opens_only_its_nets_journal() {
    let f = chain("sv2_v");
    let pin = f.ep.file.hash();
    let pin_hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
    let v3_head = format!("qumbra-wallet auth v3\nderivation 2 {pin_hex}\n");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        // Restore on the derivation-2 basis: the v1 notes of this fixture are
        // not this net's keys, so generation 0 fresh — of derivation 2.
        let b2 = basis_d(w, &f.ep, None, &PROBE, 2);
        let summary = take_str(qumbra_ffi::spend_v2::qmb_spend_basis_summary(b2));
        assert!(summary.contains(r#""auth_derivation":2"#), "{summary}");
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_restore_new(w, b2, &mut err);
        assert!(!c.is_null(), "{}", take_str(err));
        let restored = finish_check(w, c, &f.ep, None).unwrap();
        assert_eq!(restored.status, qumbra_ffi::spend_v2::QMB_AUTH_RESTORED);
        assert!(restored.journal.starts_with(&v3_head), "{}", restored.journal);
        let j = AuthJournal::from_text(&restored.journal).unwrap();
        assert_ne!(j.active().auth_root, generation_root(&f._dir.0.wallet(), 0), "not the derivation-1 root");
        qmb_auth_free(restored.a);
        let c = qumbra_ffi::spend_v2::qmb_auth_first_new(w, b2, &mut err);
        assert!(!c.is_null(), "{}", take_str(err));
        let first = finish_check(w, c, &f.ep, None).unwrap();
        assert_eq!(first.journal, restored.journal, "first and restore agree on a seed with nothing here");
        qmb_auth_free(first.a);

        // The v3 journal reopens on its own basis, and on no other kind.
        let opened = open_on(w, b2, &f.ep, &restored.journal, 0).unwrap();
        qmb_auth_free(opened);
        let b1 = basis_g(w, &f.ep, &PROBE);
        let why = open_on(w, b1, &f.ep, &restored.journal, 0).unwrap_err();
        assert!(why.contains("derivation 2 (genesis") && why.contains("this net is derivation 1"), "{why}");
        let why = open_on(w, b2, &f.ep, &f.fresh, 0).unwrap_err();
        assert!(why.contains("a derivation 1 journal") && why.contains("this net is derivation 2"), "{why}");
        qmb_spend_basis_free(b1);
        qmb_spend_basis_free(b2);

        // restore_across: a derivation-2 journal by name.
        let t = CString::new(restored.journal.clone()).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_restore_across([t.as_ptr()].as_ptr(), 1, &mut out), -1);
        assert!(take_str(out).contains("is one net's: restore it from that net alone"));

        // A scan with an unknown derivation, or against the build's pin.
        for (pin, d, why) in [
            (pin, 3u8, "authorization derivation 3"),
            (qumbra_wallet::prover_pins::PINS[0].0, 2, "derives authorization v1 (its pin), not v2"),
        ] {
            let endpoint = CString::new("fixture").unwrap();
            let mut err: *mut c_char = ptr::null_mut();
            let s = qmb_annulet_new_v2(
                w, endpoint.as_ptr(), pin.as_ptr(), d, 0, u64::MAX, ptr::null(), 0, RNG.as_ptr(), ptr::null(), 0,
                ptr::null(), 0, ptr::null(), 0, ptr::null(), 0, ptr::null(), ptr::null(), 0, &mut err,
            );
            assert!(s.is_null());
            let e = take_str(err);
            assert!(e.contains(why), "{e}");
        }
        qmb_wallet_free(w);

        // first_fresh on a net: derivation 2 names the genesis; a bad net is
        // refused before the once-only mark is consumed.
        let born = qumbra_ffi::qmb_wallet_new_fresh();
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 2, ptr::null(), &mut out), -1);
        assert!(take_str(out).contains("needs the net's genesis hash"));
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 3, pin.as_ptr(), &mut out), -1);
        assert!(take_str(out).contains("authorization derivation 3"));
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, 2, pin.as_ptr(), &mut out), 0, "the mark was kept");
        let fresh = take_str(out);
        assert!(fresh.starts_with(&v3_head), "{fresh}");
        qmb_wallet_free(born);
    }
}

/// [`open_g`] on a given basis (not consumed): the open-time check, pumped.
unsafe fn open_on(w: *mut WalletState, b: *mut SpendBasis, ep: &Endpoint, journal: &str, g: u32) -> Result<*mut AuthHandle, String> {
    let text = CString::new(journal).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let c = qmb_auth_check_new(w, text.as_ptr(), b, g, &mut err);
    if c.is_null() {
        return Err(take_str(err));
    }
    finish_check(w, c, ep, None).map(|o| o.a)
}

/// A chain on which BOTH generations signed: generation 0 at height 2, then
/// (after `open_next`) generation 1 at height 3 — the lost-device case a
/// stale journal hides. Built once.
fn two_gen_chain() -> &'static Fixture {
    static F: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
    F.get_or_init(|| unsafe {
        let src = chain_built("sv2_two_src", Lie::None, Vec::new(), false, true);
        let (tx_a, j_a) = landed_spend(&src);
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis_g(w, &src.ep, &[0]);
        let j = CString::new(j_a).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_open_next(w, j.as_ptr(), b, &mut out), 0);
        qmb_spend_basis_free(b);
        let j_b = take_str(out);
        let g1 = open_g(w, &src.ep, &j_b, 1).unwrap();
        let s = spend(basis_g(w, &src.ep, &[0, 1]), &src.payee, 0, 10, 96).unwrap();
        pump(g1.a, s, &src.ep, 0).unwrap();
        let journal = take(g1.a, s).unwrap();
        let i = intent(s);
        let mut tx_b = ProvingBundle::decode(&sign(g1.a, s, &i, &journal).unwrap()).unwrap().tx().clone();
        tx_b.proof = vec![0xAB; 64];
        qmb_spend_v2_free(s);
        qmb_auth_free(g1.a);
        qmb_wallet_free(w);
        let body = |tx| BlockBody { txs: vec![tx], ..BlockBody::default() };
        chain_built("sv2_two", Lie::None, vec![body(tx_a), body(tx_b)], false, true)
    })
}

/// F8: both generations used. A stale generation-0 journal is STALE (no
/// keys); the restore walks every probe generation: generation 0 and 1
/// sweep-only above their landed leaves, generation 2 active. `first` is
/// refused.
#[test]
fn r_a_stale_journal_hides_a_later_generation_the_restore_finds() {
    let f = two_gen_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let stale = open_g(w, &f.ep, &f.fresh, 0).err().unwrap();
        assert!(stale.contains(&format!("[status {QMB_AUTH_JOURNAL_STALE}]")), "{stale}");
        let r = first_or_restore(w, &f.ep, true).unwrap();
        assert_eq!(r.status, QMB_AUTH_RESTORED);
        let j = AuthJournal::from_text(&r.journal).unwrap();
        assert_eq!(j.active().g, 2, "{}", r.journal);
        for g in [0, 1] {
            let rec = j.get(g).unwrap();
            assert_eq!(rec.next, 1, "generation {g} above its landed leaf: {}", r.journal);
            assert!(!matches!(rec.state, qumbra_wallet::auth_journal::GenState::Active), "{}", r.journal);
        }
        qmb_auth_free(r.a);
        let why = first_or_restore(w, &f.ep, false).err().unwrap();
        assert!(why.contains("use restore"), "{why}");
        qmb_wallet_free(w);
    }
}

/// F7: a note at generation 1 (an address only `open_next` makes) means a
/// journal existed — `first` is refused even with nothing landed.
#[test]
fn s_first_refuses_a_seed_that_opened_a_later_generation() {
    let f = chain_built("sv2_s", Lie::None, Vec::new(), false, true);
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let why = first_or_restore(w, &f.ep, false).err().unwrap();
        assert!(why.contains("this seed opened generation 1") && why.contains("use restore"), "{why}");
        qmb_wallet_free(w);
    }
}

/// F9: a generation never dies for receiving. A retired generation that
/// holds a note is revived — sweep-only with a NEW gate, SWEEP_WAITING, the
/// journal returned; a retired one holding nothing is refused. A sweep-only
/// generation may not pay its own (non-active) address either.
#[test]
fn t_a_retired_generation_that_receives_is_revived() {
    let f = chain("sv2_t");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let g0 = AuthJournal::from_text(&f.fresh).unwrap().get(0).unwrap().clone();
        let g1 = qumbra_wallet::auth_journal::Generation {
            g: 1,
            next: 0,
            auth_root: generation_root(&wallet_dir("sv2_t_root", SEED).wallet(), 1),
            state: qumbra_wallet::auth_journal::GenState::Active,
        };
        use qumbra_wallet::auth_journal::{GenState, Generation};
        let retired = AuthJournal::from_generations(vec![Generation { state: GenState::Retired, ..g0.clone() }, g1.clone()]).unwrap().to_text();
        let waiting = open_g(w, &f.ep, &retired, 0).err().unwrap();
        assert!(waiting.contains(&format!("[status {QMB_AUTH_SWEEP_WAITING}]")), "{waiting}");
        let revived = AuthJournal::from_text(waiting.split_once("] ").unwrap().1).unwrap();
        match &revived.get(0).unwrap().state {
            GenState::Sweep { gates } => assert!(gates[0].not_before_height > 1152, "a new gate: {gates:?}"),
            other => panic!("revived as {other:?}"),
        }
        // Nothing held at generation 1: a retired 1 is refused.
        let empty_retired = AuthJournal::from_generations(vec![g0.clone(), Generation { state: GenState::Retired, ..g1.clone() }]).unwrap().to_text();
        let why = open_g(w, &f.ep, &empty_retired, 1).err().unwrap();
        assert!(why.contains("retired and holds nothing"), "{why}");
        // Past its gate, the sweep may not pay its own generation-0 address.
        let gate = qumbra_wallet::auth_journal::SweepGate { genesis: f.ep.file.hash(), not_before_height: 0 };
        let open_gate = AuthJournal::from_generations(vec![Generation { state: GenState::Sweep { gates: vec![gate] }, ..g0 }, g1])
            .unwrap()
            .to_text();
        let sweep = open_g(w, &f.ep, &open_gate, 0).unwrap();
        let own_g0 = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 0, 1, ptr::null()));
        let s = spend(basis_g(w, &f.ep, &[0, 1]), &own_g0, 0, 10, 96).unwrap();
        assert!(pump(sweep.a, s, &f.ep, 0).unwrap_err().contains("sweep-only"));
        qmb_spend_v2_free(s);
        // ... and pays the active generation's address.
        let active = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 1, 1, ptr::null()));
        let s = spend(basis_g(w, &f.ep, &[0, 1]), &active, 0, 10, 96).unwrap();
        pump(sweep.a, s, &f.ep, 0).unwrap();
        qmb_spend_v2_free(s);
        qmb_auth_free(sweep.a);
        qmb_wallet_free(w);
    }
}

/// Lab #924 PR 3f: the journal summary over the recorded fixture journals
/// (`annulet_spend_fixtures` at c132d3f3: check_stale's restore, retired_revive's
/// input), a gate on a second net, and the refusals.
#[test]
fn u_the_journal_summary_lists_every_generation_with_its_nets() {
    let net = "4a996d02f37c60090c564da79ddf122d3c17775f503ae7e91e60fc9a27a1c4fd";
    let other = "ab".repeat(32);
    let (r0, r1) = (
        "f3a6dd683c0d8cc9c632e80624194fffd723c58b31bce5b94af9e28ca5eeaadf",
        "f59195087db98c32df51d80a5dfcdd1ddf66e6448edb1a9d4623600207811479",
    );
    let summary = |text: &str| unsafe {
        let t = CString::new(text).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let out = qmb_auth_journal_summary(t.as_ptr(), &mut err);
        if out.is_null() {
            Err(take_str(err))
        } else {
            assert!(err.is_null());
            Ok(serde_json::from_str::<serde_json::Value>(&take_str(out)).unwrap())
        }
    };
    let restored = format!(
        "qumbra-wallet auth v2\n0 1 {r0} sweep {net}:1154,{other}:5\n1 0 {r1} active\nchecked 0 {net}:2\nchecked 1 {net}:2\n"
    );
    assert_eq!(
        summary(&restored).unwrap(),
        serde_json::json!({
            "active": 1,
            "generations": [
                {
                    "g": 0, "state": "sweep", "next": 1,
                    "checked": [{"genesis": net, "height": 2}],
                    "gates": [{"genesis": net, "not_before_height": 1154}, {"genesis": other, "not_before_height": 5}],
                },
                {
                    "g": 1, "state": "active", "next": 0,
                    "checked": [{"genesis": net, "height": 2}],
                    "gates": [],
                },
            ],
        })
    );
    let retired = summary(&format!("qumbra-wallet auth v1\n0 0 {r0} retired\n1 0 {r1} active\n")).unwrap();
    assert_eq!(retired["active"], 1);
    assert_eq!(retired["generations"][0]["state"], "retired");
    assert_eq!(retired["generations"][0]["gates"], serde_json::json!([]));
    assert_eq!(retired["generations"][0]["checked"], serde_json::json!([]));
    assert!(!summary(&restored).unwrap().to_string().contains(r0), "no roots");

    assert!(summary("not a journal").unwrap_err().contains("does not parse"));
    assert!(summary(&(restored.clone() + &"#".repeat(64 * 1024))).unwrap_err().contains("the journal is"));
    unsafe {
        let mut err: *mut c_char = ptr::null_mut();
        assert!(qmb_auth_journal_summary(ptr::null(), &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
        assert!(qmb_auth_journal_summary(ptr::null(), ptr::null_mut()).is_null(), "err_out may be NULL");
    }
}

// ------------------------------------------------------------ format 34 (lab #937 PR D)

const PROVER: u8 = 0x4D;

/// The prover's pinned payee for the fixture nets: a third wallet's
/// version-2 address.
fn prover_address() -> qlab_wallet::address::Address {
    let p = wallet_dir("sv3_prover", PROVER);
    let pw = p.wallet();
    let a = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0));
    let _ = std::fs::remove_dir_all(&p.dir);
    a
}

/// A **format-34** chain (no blocks after genesis): the genesis pays the
/// wallet's v2 address 0 the holder's 1,000,000 USDT-test and `notes(a2)`.
/// With `pin`, this net's prover is pinned (fixture pins): the payee
/// [`prover_address`], at most S 1 / P 2 fee units per transaction.
fn chain_v3(tag: &str, notes: impl Fn(&qlab_wallet::address::Address) -> Vec<qlab_note::l2note::L2Note>, pin: bool) -> Fixture {
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
                max_price: qumbra_wallet::annulet_plan::ProverPrice { s: 1, p: 2 },
            },
        );
    }
    let ep = Endpoint::new(file, &[], None, Lie::None);
    let payee = wallet_dir(&format!("{tag}_payee"), PAYEE);
    let pw = payee.wallet();
    let to = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0)).encode();
    let _ = std::fs::remove_dir_all(&payee.dir);
    Fixture { _dir: WalletDirGuard(w), ep, payee: to, fresh: AuthJournal::fresh(root).to_text() }
}

/// The prover service's `/v2/annulet/info` for `f`'s net.
fn info(f: &Fixture, s: u64, p: u64, payee: &str) -> Vec<u8> {
    let hex: String = f.ep.file.hash().iter().map(|b| format!("{b:02x}")).collect();
    format!(r#"{{"protocol_version":2,"genesis_hash":"{hex}","fee_asset":0,"price":{{"S":{s},"P":{p}}},"payee":"{payee}"}}"#)
        .into_bytes()
}

unsafe fn set_prover(s: *mut SpendHandle, info: &[u8]) -> Result<(), String> {
    let mut err: *mut c_char = ptr::null_mut();
    match qmb_spend_v2_prover(s, info.as_ptr(), info.len(), &mut err) {
        0 => {
            assert!(err.is_null());
            Ok(())
        }
        -1 => Err(take_str(err)),
        other => panic!("qmb_spend_v2_prover returned {other}"),
    }
}

/// One whole format-34 spend paying the prover at the advertised S 1 / P 2.
unsafe fn send_v3(f: &Fixture, asset: u16, amount: u64, slots: u32, shape: L2ShapeTag) -> (ProvingBundle, String) {
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let a = auth(w, &f.ep, &f.fresh).unwrap();
    let s = spend(basis(w, &f.ep), &f.payee, asset, amount, 96).unwrap();
    set_prover(s, &info(f, 1, 2, &prover_address().encode())).expect("the pinned prover");
    pump(a, s, &f.ep, 0).expect("READY");
    let journal = take(a, s).expect("the take");
    assert_eq!(next_of(&journal), slots, "one leaf per real slot");
    let i = intent(s);
    let text = review(s, &i).expect("the review");
    let bundle = sign(a, s, &i, &journal).expect("signed with the persisted journal");
    let b = ProvingBundle::decode(&bundle).expect("the export is a bundle");
    assert_eq!(b.shape(), shape);
    b.check(&AuthContext::candidate_a_v3(f.ep.file.hash())).expect("the prover's own lock accepts it on format 34");
    assert!(b.tx().proof.is_empty(), "the kernel never proves");
    qmb_spend_v2_free(s);
    qmb_auth_free(a);
    qmb_wallet_free(w);
    (b, text)
}

/// Output 3 of `b` pays the pinned prover `value` of asset 0.
fn pays_the_prover(b: &ProvingBundle, value: u64) {
    let w = b.witness();
    assert_eq!(w.outputs.len(), 3, "a format-34 spend has three outputs");
    let o = &w.outputs[2];
    assert_eq!((o.value, o.asset, o.rkm), (value, 0, prover_address().rkm_lanes()), "output 3 is the prover's fee");
}

/// Lab #937 PR D: an asset-0 payment on format 34 — one note pays the
/// amount, the S fee and the prover's S price (10 + 1 + 1 of 50; 38 back);
/// output 3 pays the pinned prover 1. One transaction: no total line.
#[test]
fn v3_a_an_asset_0_payment_pays_its_prover() {
    let f = chain_v3("sv3_a", |a| vec![note_to(a, 50, 0, 30)], true);
    let (b, text) = unsafe { send_v3(&f, 0, 10, 1, L2ShapeTag::S) };
    assert_eq!(b.tx().public.fee, 1, "the S tier");
    pays_the_prover(&b, 1);
    let short = prover_address().short().encode();
    assert!(text.contains("send 10 fee units to "), "{text}");
    assert!(text.contains("38 fee units returns to this wallet"), "{text}");
    assert!(text.contains(&format!("fee: 1 fee unit\nprover fee: 1 fee unit to {short}\nvalid until block ")), "{text}");
    assert!(!text.contains("this plan from here"), "one transaction, no total line: {text}");
}

/// A P payment of the Hybrid asset beside an exact asset-0 note of the P
/// tier **plus** the P price (2 + 2 = 4): output 3 (2 fee units to the
/// prover) sits on the asset-0 row.
#[test]
fn v3_b_a_p_payment_pays_its_prover_from_the_asset_0_row() {
    let f = chain_v3("sv3_b", |a| vec![note_to(a, 4, 0, 40)], true);
    let (b, text) = unsafe { send_v3(&f, USDT as u16, 1_000, 2, L2ShapeTag::P) };
    assert_eq!(b.tx().public.fee, 2, "the P tier");
    pays_the_prover(&b, 2);
    assert!(text.contains("999,000 base units of QIA #1 (no list for this network) returns to this wallet"), "{text}");
    assert!(text.contains("fee: 2 fee units\nprover fee: 2 fee units to "), "{text}");
}

/// A plan of two transactions: no exact 4 is held, so step 1 splits the 50
/// (4 for the payment + 1 S fee + 1 S price; 44 back) and step 2 pays. The
/// review of step 1 states its own prover fee and the plan from here,
/// summed per step at the price fixed for the handle — verbatim.
#[test]
fn v3_c_a_multi_step_plan_states_its_total_from_here() {
    let f = chain_v3("sv3_c", |a| vec![note_to(a, 50, 0, 30)], true);
    let (b, text) = unsafe { send_v3(&f, USDT as u16, 1_000, 1, L2ShapeTag::S) };
    pays_the_prover(&b, 1);
    let w = b.witness();
    assert_eq!((w.outputs[0].value, w.outputs[1].value), (4, 44), "the split: the exact 4 and the rest");
    assert!(text.contains("step 1 of 2: a fee-split"), "{text}");
    assert!(
        text.contains("prover fee: 1 fee unit to ")
            && text.contains("\nthis plan from here: 2 transactions; network fees 3 + prover fees 3 = 6 fee units\n"),
        "{text}"
    );
}

/// Two notes of the Hybrid asset and the exact 4 in slot 3: no balance row
/// is asset 0, so output 3 rides the fee bank (`o3f`, lab #937 A′) — the
/// slot-3 note pays the P tier and the P price.
#[test]
fn v3_d_a_two_note_payment_pays_its_prover_through_the_fee_bank() {
    let f = chain_v3("sv3_d", |a| vec![note_to(a, 500, USDT, 60), note_to(a, 4, 0, 40)], true);
    let (b, text) = unsafe { send_v3(&f, USDT as u16, 1_000_200, 3, L2ShapeTag::P) };
    pays_the_prover(&b, 2);
    let w = b.witness();
    assert_eq!([w.inputs[0].asset, w.inputs[1].asset], [USDT, USDT], "no asset-0 row");
    match &w.fee_slot {
        qlab_air::l2::FeeSlotV2::Exact { input, .. } => assert_eq!(input.value, 4, "the P tier plus the P price"),
        qlab_air::l2::FeeSlotV2::Dummy { .. } => panic!("slot 3 is the exact fee note"),
    }
    assert!(text.contains("prover fee: 2 fee units to "), "{text}");
}

/// The refusals, by name: a format-34 spend with no prover set; a payee
/// that is not the pin; a price over the pinned maximum; a net with no pin;
/// a second set (the price is fixed for the handle); a set after the first
/// step; and a prover on a format-33 net (no third output).
#[test]
fn v3_e_the_prover_is_set_once_on_its_pin_or_refused_by_name() {
    let f = chain_v3("sv3_e", |a| vec![note_to(a, 50, 0, 30)], true);
    let pinned = prover_address().encode();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.ep, &f.fresh).unwrap();
        // No prover: refused by the attempt once the params and registry
        // reads are in — before the take, so no leaf is consumed.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let why = pump(a, s, &f.ep, 0).expect_err("refused");
        assert!(why.contains("set the prover with qmb_spend_v2_prover first"), "{why}");
        qmb_spend_v2_free(s);
        // Payee, price, twice.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let other = qlab_wallet::address::Address::decode_any(&f.payee).unwrap().encode();
        let why = set_prover(s, &info(&f, 1, 2, &other)).expect_err("another payee");
        assert!(why.contains("not this network's pinned payee"), "{why}");
        let why = set_prover(s, &info(&f, 2, 2, &pinned)).expect_err("over the maximum");
        assert!(why.contains("asks 2 fee unit(s) for shape S, above this wallet's maximum of 1"), "{why}");
        set_prover(s, &info(&f, 1, 1, &pinned)).expect("at or below the maximum");
        let why = set_prover(s, &info(&f, 1, 2, &pinned)).expect_err("twice");
        assert!(why.contains("already set: its price is fixed"), "{why}");
        qmb_spend_v2_free(s);
        // After the first step.
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_spend_v2_step(a, s, &mut out), 1, "the first step asks for the params");
        qmb_string_free(out);
        let why = set_prover(s, &info(&f, 1, 2, &pinned)).expect_err("after a step");
        assert!(why.contains("before the first step"), "{why}");
        qmb_spend_v2_free(s);
        qmb_auth_free(a);
        qmb_wallet_free(w);
    }
    // A format-34 net with no pin.
    let g = chain_v3("sv3_e_unpinned", |a| vec![note_to(a, 51, 0, 31)], false);
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let s = spend(basis(w, &g.ep), &g.payee, 0, 10, 96).unwrap();
        let why = set_prover(s, &info(&g, 1, 2, &pinned)).expect_err("no pin");
        assert!(why.contains("no prover is pinned for this network"), "{why}");
        qmb_spend_v2_free(s);
        qmb_wallet_free(w);
    }
    // Format 33.
    let h = chain("sv3_e_33");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let s = spend(basis(w, &h.ep), &h.payee, 0, 10, 96).unwrap();
        let why = set_prover(s, &info(&h, 1, 2, &pinned)).expect_err("format 33");
        assert!(why.contains("this net is not format 34"), "{why}");
        qmb_spend_v2_free(s);
        qmb_wallet_free(w);
    }
}

/// Lab #937 PR D (ruling §3): the test prover pins never reach a release
/// build — `cargo tree` of qumbra-ffi's normal and build edges (what
/// `cargo build -p qumbra-ffi --release` resolves; dev edges excluded) names
/// neither `fixture-pins` nor `test-support` (the TEST list signer).
#[test]
fn w_no_test_feature_is_in_the_release_feature_tree() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let tree = |edges: &str| {
        let out = std::process::Command::new(&cargo)
            .args(["tree", "--offline", "--manifest-path", manifest, "-p", "qumbra-ffi", "-e", edges, "--prefix", "none"])
            .output()
            .expect("run cargo tree");
        assert!(out.status.success(), "cargo tree failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("utf-8")
    };
    let release = tree("normal,build,features");
    assert!(release.contains("qumbra-wallet feature \"verify\""), "the probe reads the feature tree: {release}");
    for test_only in ["\"fixture-pins\"", "\"test-support\"", "\"harness-pins\""] {
        assert!(!release.contains(test_only), "{test_only} is in qumbra-ffi's release feature tree");
    }
    // The probe can see them: through the dev edges, both are there.
    let with_dev = tree("normal,build,dev,features");
    assert!(with_dev.contains("\"fixture-pins\"") && with_dev.contains("\"test-support\""), "the dev tree names them");
}

/// Lab #936: a restore (`paged = Some(n)`: `qmb_auth_check_set_page(n)` first).
unsafe fn restore_paged(w: *mut WalletState, ep: &Endpoint, paged: Option<u32>) -> Result<Opened, String> {
    let b = basis_g(w, ep, &PROBE);
    let mut err: *mut c_char = ptr::null_mut();
    let c = qmb_auth_restore_new(w, b, &mut err);
    qmb_spend_basis_free(b);
    assert!(!c.is_null(), "{}", take_str(err));
    if let Some(n) = paged {
        assert_eq!(qmb_auth_check_set_page(c, n, &mut err), 0, "{}", if err.is_null() { String::new() } else { take_str(err) });
    }
    finish_check(w, c, ep, None)
}

/// **Lab #936**: paging is opt-in and changes only how bodies are asked
/// for — the same restore, the same journal and verdict, the bodies read as
/// `/v1/bodies` pages; an open check reads its pages from past `checked_to`.
#[test]
fn x_a_paged_check_reaches_the_per_block_verdict() {
    let (f, persisted) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let one = restore_paged(w, &f.ep, None).unwrap();
        assert_eq!(one.paths, vec!["/v1/block/1/body".to_string(), "/v1/block/2/body".to_string()], "the default is unchanged");
        let paged = restore_paged(w, &f.ep, Some(256)).unwrap();
        assert_eq!(paged.paths, vec!["/v1/bodies?from=1&to=2".to_string()], "one page to the verified tip");
        assert_eq!((paged.status, &paged.journal), (one.status, &one.journal), "the same verdict and journal");
        let ones = restore_paged(w, &f.ep, Some(1)).unwrap();
        assert_eq!(ones.paths, vec!["/v1/bodies?from=1&to=1".to_string(), "/v1/bodies?from=2&to=2".to_string()]);
        assert_eq!((ones.status, &ones.journal), (one.status, &one.journal));
        for o in [one, paged, ones] {
            qmb_auth_free(o.a);
        }
        // An open check pages from past its checked_to, as it walks one at a time.
        let gens: Vec<u32> = AuthJournal::from_text(persisted).unwrap().generations().iter().map(|r| r.g).collect();
        let b = basis_g(w, &f.ep, &gens);
        let j = CString::new(persisted.as_str()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_check_new(w, j.as_ptr(), b, 0, &mut err);
        qmb_spend_basis_free(b);
        assert_eq!(qmb_auth_check_set_page(c, 256, ptr::null_mut()), 0);
        let ok = finish_check(w, c, &f.ep, None).unwrap();
        assert_eq!(ok.paths, vec!["/v1/bodies?from=2&to=2".to_string()]);
        assert_eq!(ok.status, QMB_AUTH_CHECKED);
        qmb_auth_free(ok.a);
        qmb_wallet_free(w);
    }
}

/// **Lab #936**: a body in a page that does not bind to its verified header
/// refuses the check at that height, by the per-block check's own words; the
/// page size is bounded and fixed before the first step.
#[test]
fn y_a_paged_check_refuses_a_lying_body_and_the_page_is_bounded() {
    let lying = {
        let payee = wallet_dir("sv2_y_lie_payee", PAYEE);
        let pw = payee.wallet();
        let to = pw.address_candidate_a_at_index(0, &generation_root(&pw, 0));
        let _ = std::fs::remove_dir_all(&payee.dir);
        let mut rng = StdRng::seed_from_u64(0x59);
        let paid = BlockBody { txs: vec![pay_tx(&to, &[note_to(&to, 3, 0, 60)], 0x60, &mut rng)], ..BlockBody::default() };
        chain_full("sv2_y_lie", Lie::None, vec![paid], true)
    };
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let why = restore_paged(w, &lying.ep, Some(256)).err().unwrap();
        assert!(why.contains("block 2's body is not the one its verified header commits to"), "{why}");

        let b = basis_g(w, &lying.ep, &PROBE);
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_restore_new(w, b, &mut err);
        qmb_spend_basis_free(b);
        assert_eq!(qmb_auth_check_set_page(c, 257, &mut err), -1);
        assert!(take_str(err).contains("exceeds 256"));
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_check_step(c, &mut out), 1);
        let _ = take_str(out);
        assert_eq!(qmb_auth_check_set_page(c, 8, &mut err), -1, "fixed once a step is taken");
        assert!(take_str(err).contains("before the first step"));
        assert_eq!(qmb_auth_check_set_page(ptr::null_mut(), 8, ptr::null_mut()), -1, "NULL-safe");
        qumbra_ffi::spend_v2::qmb_auth_check_free(c);
        qmb_wallet_free(w);
    }
}

/// **Lab #936**: a page shorter than asked is taken for what it holds and
/// the next NEED asks on from there; an empty page is the body missing —
/// refused by name, never read as "nothing landed".
#[test]
fn z_a_short_page_continues_and_an_empty_page_refuses() {
    let (f, _) = spent_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis_g(w, &f.ep, &PROBE);
        let mut err: *mut c_char = ptr::null_mut();
        let c = qmb_auth_restore_new(w, b, &mut err);
        qmb_spend_basis_free(b);
        assert_eq!(qmb_auth_check_set_page(c, 256, ptr::null_mut()), 0);
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_auth_check_step(c, &mut out), 1);
        assert_eq!(take_str(out), "/v1/bodies?from=1&to=2");
        // The endpoint answers with height 1 only.
        let short = f.ep.fetch("/v1/bodies?from=1&to=1").unwrap();
        qmb_auth_check_supply(c, short.as_ptr(), short.len());
        assert_eq!(qmb_auth_check_step(c, &mut out), 1);
        assert_eq!(take_str(out), "/v1/bodies?from=2&to=2", "asked on from past what the page held");
        // Then with nothing at all.
        let empty = qlab_p2p::served::encode_bodies_page(f.ep.wire, 2, &[]);
        qmb_auth_check_supply(c, empty.as_ptr(), empty.len());
        assert_eq!(qmb_auth_check_step(c, &mut out), -2);
        let why = take_str(out);
        assert!(why.contains("block 2's body is unavailable: the endpoint served an empty page"), "{why}");
        qumbra_ffi::spend_v2::qmb_auth_check_free(c);
        qmb_wallet_free(w);
    }
}

// ------------------------------------------------------------ lab #989

/// The spent chain's check, once: its `take_landed` JSON (the height-2
/// spend) and the checked height the journal it returned names.
fn settle_inputs() -> &'static (String, u64) {
    static S: std::sync::OnceLock<(String, u64)> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let (f, persisted) = spent_chain();
        unsafe {
            let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
            let ok = open_g(w, &f.ep, persisted, 0).unwrap();
            assert!(ok.journal.contains(&format!("checked 0 {}:2", genesis_hex(f))), "{}", ok.journal);
            qmb_auth_free(ok.a);
            qmb_wallet_free(w);
            (ok.landed, 2)
        }
    })
}

/// [`settle_inputs`]' JSON as the kernel's `LandedSpend`s.
fn landed_spends() -> Vec<qumbra_wallet::auth_check::LandedSpend> {
    let unhex = |s: &str| -> [u8; 32] {
        let v: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    };
    landed_rows(&settle_inputs().0)
        .into_iter()
        .map(|(height, tx, intent, leaves)| qumbra_wallet::auth_check::LandedSpend {
            height,
            tx_id: unhex(&tx),
            intent_digest: unhex(&intent),
            leaves: leaves as u32,
        })
        .collect()
}

/// The landed bundle's key (its transaction's first nullifier), and the
/// validity height its section signs.
fn bundle_key_and_validity(bundle: &[u8]) -> ([u8; 32], u64) {
    use qlab_devnet::annulet::{auth_shape, L2Surface};
    let b = ProvingBundle::decode(bundle).unwrap();
    let tx = b.tx();
    let shape = L2Surface::decode(&tx.l2).unwrap().unwrap().shape;
    let section = qlab_remote_auth::annulet::AnnuletAuthSection::decode(auth_shape(shape), &tx.auth).unwrap();
    (tx.public.nullifiers[0], section.valid_until_height)
}

/// A temporary wallet directory holding `records` in `remote.v1`, each
/// `(key, bundle, outcome line or none)` — written as a send writes them.
struct Records(std::path::PathBuf);

impl Records {
    fn new(tag: &str, records: &[([u8; 32], &[u8], Option<&str>)]) -> Records {
        let dir = std::env::temp_dir().join(format!("qmb-989-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (key, bundle, outcome) in records {
            qumbra_wallet::remote_prover::record(&dir, key, bundle).unwrap();
            if let Some(line) = outcome {
                std::fs::write(dir.join("remote.v1").join(format!("{}.outcome", hex32(key))), format!("{line}\n")).unwrap();
            }
        }
        Records(dir)
    }

    fn outcome(&self, key: &[u8; 32]) -> Option<String> {
        std::fs::read_to_string(self.0.join("remote.v1").join(format!("{}.outcome", hex32(key)))).ok()
    }

    fn settle(&self, landed: &[qumbra_wallet::auth_check::LandedSpend], checked_to: u64) -> qumbra_wallet::remote_prover::SettleReport {
        let f = &spent_chain().0;
        qumbra_wallet::remote_prover::settle(&self.0, f.ep.wire.l2_auth, &f.ep.file.hash(), landed, checked_to).unwrap()
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// t1: a `submitted` record whose bundle is the landed height-2
/// transaction's settles `landed 2 <tx_id>`, the id the chain's
/// (`qlab_p2p::codec::tx_id` of that transaction), found by its intent.
#[test]
fn t1_a_submitted_record_whose_bundle_landed_settles_landed() {
    let (_, record) = spent_chain_recorded();
    let (key, _) = bundle_key_and_validity(&record.bundle);
    let r = Records::new("t1", &[(key, &record.bundle, Some(&format!("submitted {}", hex32(&record.tx_id))))]);
    let report = r.settle(&landed_spends(), settle_inputs().1);
    let line = format!("landed 2 {}", hex32(&record.tx_id));
    assert_eq!(report.lines, vec![(key, line.clone())]);
    assert_eq!(report.landed, vec![(key, 2, record.tx_id)]);
    assert!(report.expired.is_empty() && report.undecodable.is_empty(), "{report:?}");
    assert_eq!(r.outcome(&key), Some(format!("{line}\n")));
    assert_eq!(
        qumbra_wallet::remote_prover::intent_digest_of_bundle(&record.bundle, spent_chain().0.ep.wire.l2_auth, &spent_chain().0.ep.file.hash()),
        Ok(record.intent_digest),
        "the bundle's rebuild is the digest the device signed"
    );
    // Settled once: a second pass leaves it.
    assert_eq!(r.settle(&landed_spends(), settle_inputs().1), Default::default());
}

/// t2: the record said `submitted <another id>`: the chain's id is the
/// record's, the prover's kept as what it said.
#[test]
fn t2_a_prover_tx_id_the_chain_does_not_carry_is_kept_as_what_it_said() {
    let (_, record) = spent_chain_recorded();
    let (key, _) = bundle_key_and_validity(&record.bundle);
    let wrong = hex32(&[0xee; 32]);
    let r = Records::new("t2", &[(key, &record.bundle, Some(&format!("submitted {wrong}")))]);
    let report = r.settle(&landed_spends(), settle_inputs().1);
    let line = format!("landed 2 {} prover-said {wrong}", hex32(&record.tx_id));
    assert_eq!(report.lines, vec![(key, line.clone())]);
    assert_eq!(r.outcome(&key), Some(format!("{line}\n")));
}

/// t3: an `in-flight` record that did not land expires once every block
/// that could carry it is walked — `valid_until < checked_to` — and is left
/// while the last such block is not.
#[test]
fn t3_an_unlanded_record_expires_only_past_its_validity() {
    let (_, record) = spent_chain_recorded();
    let (key, v) = bundle_key_and_validity(&record.bundle);
    let r = Records::new("t3", &[(key, &record.bundle, Some("in-flight intent-in-flight"))]);
    assert_eq!(r.settle(&[], v), Default::default(), "checked_to == valid_until: the chain has not said");
    assert_eq!(r.outcome(&key).as_deref(), Some("in-flight intent-in-flight\n"));
    let report = r.settle(&[], v + 1);
    assert_eq!(report.lines, vec![(key, format!("expired {v} unlanded-through {}", v + 1))]);
    assert_eq!(report.expired, vec![(key, v)]);
    assert_eq!(r.outcome(&key), Some(format!("expired {v} unlanded-through {}\n", v + 1)));
    // No outcome at all (the upload's answer unknown) is open too.
    let none = Records::new("t3n", &[(key, &record.bundle, None)]);
    assert_eq!(none.settle(&[], v + 1).expired, vec![(key, v)]);
}

/// t4 (L3): a landed spend of this key's leaves under ANOTHER intent is
/// another send — it does not confirm this record, whatever the key, and
/// neither does the prover's tx_id.
#[test]
fn t4_matching_is_by_intent_digest_only() {
    let (_, record) = spent_chain_recorded();
    let (key, v) = bundle_key_and_validity(&record.bundle);
    let r = Records::new("t4", &[(key, &record.bundle, Some(&format!("submitted {}", hex32(&record.tx_id))))]);
    let mut other = landed_spends();
    assert_eq!(other.len(), 1);
    other[0].intent_digest[0] ^= 1;
    assert_eq!(r.settle(&other, settle_inputs().1), Default::default(), "same key and tx_id, another intent");
    assert_eq!(r.outcome(&key), Some(format!("submitted {}\n", hex32(&record.tx_id))));
    // And it still expires on its own validity, not by the other send.
    assert_eq!(r.settle(&other, v + 1).expired, vec![(key, v)]);
}

/// t5: a record that ended (`failed 400 …`) is not reopened, nor its bundle
/// read — an unreadable one is not reported.
#[test]
fn t5_an_ended_record_is_left_untouched() {
    let (_, record) = spent_chain_recorded();
    let (key, _) = bundle_key_and_validity(&record.bundle);
    let r = Records::new("t5", &[(key, &record.bundle, Some("failed 400 bad-bundle")), ([0x77; 32], b"junk", Some("failed 0 refused"))]);
    assert_eq!(r.settle(&landed_spends(), settle_inputs().1), Default::default());
    assert_eq!(r.outcome(&key).as_deref(), Some("failed 400 bad-bundle\n"));
}

/// t6: an open record whose bundle does not decode is reported by key and
/// why; the others are settled in the same pass.
#[test]
fn t6_an_undecodable_bundle_is_reported_and_the_rest_settled() {
    let (_, record) = spent_chain_recorded();
    let (key, _) = bundle_key_and_validity(&record.bundle);
    let junk = [0x01; 32];
    let r = Records::new("t6", &[(junk, b"not a bundle", Some("in-flight nullifier-in-flight")), (key, &record.bundle, None)]);
    let report = r.settle(&landed_spends(), settle_inputs().1);
    assert_eq!(report.undecodable.len(), 1, "{report:?}");
    assert_eq!(report.undecodable[0].0, junk);
    assert!(report.undecodable[0].1.contains("does not decode"), "{}", report.undecodable[0].1);
    assert_eq!(report.lines, vec![(key, format!("landed 2 {}", hex32(&record.tx_id)))]);
    assert_eq!(r.outcome(&junk).as_deref(), Some("in-flight nullifier-in-flight\n"), "reported, not rewritten");
}

/// t7 (L2): `landed` is a definitive end, as `expired` and a 4xx `failed`
/// are; `submitted` and `in-flight` are not.
#[test]
fn t7_landed_is_a_definitive_end() {
    use qumbra_wallet::remote_prover::ended_definitively;
    assert!(ended_definitively("landed 2 aa"));
    assert!(ended_definitively("landed 2 aa prover-said bb\n"));
    assert!(ended_definitively("expired 5 unlanded-through 6"));
    assert!(!ended_definitively("submitted aa"));
    assert!(!ended_definitively("in-flight intent-in-flight"));
}

/// `qmb_remote_settle`'s JSON, pinned: the caller's records and
/// `qmb_auth_check_take_landed`'s own output in, the report out — and each
/// malformed argument refused by name.
#[test]
fn qmb_remote_settle_answers_the_pinned_json_over_the_callers_records() {
    use qumbra_ffi::spend_v2::qmb_remote_settle;
    let (f, _) = spent_chain();
    let (_, record) = spent_chain_recorded();
    let (key, v) = bundle_key_and_validity(&record.bundle);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let records = serde_json::json!([
        {"key": hex32(&key), "bundle": hex(&record.bundle), "outcome": format!("submitted {}", hex32(&record.tx_id))},
        {"key": hex32(&[0x01; 32]), "bundle": hex(b"not a bundle"), "outcome": null},
        {"key": hex32(&[0x02; 32]), "bundle": hex(b"junk"), "outcome": "failed 400 x"},
    ])
    .to_string();
    let (landed, checked_to) = settle_inputs();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let b = basis(w, &f.ep);
        let call = |records: &str, landed: &str, checked_to: u64| -> Result<serde_json::Value, String> {
            let (r, l) = (CString::new(records).unwrap(), CString::new(landed).unwrap());
            let mut err: *mut c_char = ptr::null_mut();
            let out = qmb_remote_settle(b, r.as_ptr(), l.as_ptr(), checked_to, &mut err);
            if out.is_null() {
                Err(take_str(err))
            } else {
                assert!(err.is_null());
                Ok(serde_json::from_str(&take_str(out)).unwrap())
            }
        };
        let got = call(&records, landed, *checked_to).unwrap();
        let undecodable = got["undecodable"].as_array().unwrap();
        assert_eq!(undecodable.len(), 1, "{got}");
        assert_eq!(undecodable[0]["key"], hex32(&[0x01; 32]));
        let want = serde_json::json!({
            "lines": [{"key": hex32(&key), "outcome": format!("landed 2 {}", hex32(&record.tx_id))}],
            "landed": [{"key": hex32(&key), "height": 2, "tx_id": hex32(&record.tx_id)}],
            "expired": [],
            "undecodable": [{"key": hex32(&[0x01; 32]), "why": undecodable[0]["why"].clone()}],
        });
        assert_eq!(got, want);
        // Not landed, past its validity: expired.
        let got = call(&records, "[]", v + 1).unwrap();
        assert_eq!(got["expired"], serde_json::json!([{"key": hex32(&key), "valid_until": v}]));
        assert_eq!(got["lines"][0]["outcome"], format!("expired {v} unlanded-through {}", v + 1));
        // Refusals, by name.
        assert!(call("{}", "[]", 2).unwrap_err().contains("records_json is not a JSON array"));
        assert!(call(r#"[{"key":"AB","bundle":"00","outcome":null}]"#, "[]", 2).unwrap_err().contains("records[0].key is not 64 lowercase hex"));
        assert!(call(r#"[{"key":"0000000000000000000000000000000000000000000000000000000000000000","bundle":"zz","outcome":null}]"#, "[]", 2)
            .unwrap_err()
            .contains("records[0].bundle is not hex"));
        assert!(call("[]", r#"[{"height":2}]"#, 2).unwrap_err().contains("landed[0].tx_id is not a string"));
        let mut err: *mut c_char = ptr::null_mut();
        let empty = CString::new("[]").unwrap();
        assert!(qmb_remote_settle(ptr::null(), empty.as_ptr(), empty.as_ptr(), 2, &mut err).is_null());
        assert_eq!(take_str(err), "NULL argument");
        assert!(qmb_remote_settle(b, ptr::null(), empty.as_ptr(), 2, &mut err).is_null());
        assert!(take_str(err).contains("records_json is NULL"));
        qmb_spend_basis_free(b);
        qmb_wallet_free(w);
    }
}
