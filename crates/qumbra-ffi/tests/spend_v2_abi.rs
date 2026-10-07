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
    qmb_auth_free, qmb_auth_journal, qmb_auth_open, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_basis_free,
    qmb_spend_v2_free, qmb_spend_v2_intent, qmb_spend_v2_new, qmb_spend_v2_refusal, qmb_spend_v2_step, qmb_spend_v2_supply,
    qmb_spend_v2_supply_err, AuthHandle, SpendBasis, SpendHandle,
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
    let w = wallet_dir(tag, SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let mut rng = StdRng::seed_from_u64(0x4B);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let file = genesis_v2(&a2, vec![note_to(&a2, 50, 0, 30), note_to(&a2, 2, 0, 40)]);
    let ep = Endpoint::new(file, &[body], None, Lie::None);
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
        w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, lp, ll, sp, sl,
        kp, kl, ptr::null(), ptr::null(), 0, &mut err,
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

unsafe fn auth(w: *const WalletState, journal: &str) -> Result<*mut AuthHandle, String> {
    let j = CString::new(journal).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let a = qmb_auth_open(w, j.as_ptr(), &mut err);
    if a.is_null() {
        Err(take_str(err))
    } else {
        Ok(a)
    }
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
    let a = auth(w, &f.fresh).unwrap();
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
    assert!(text.contains("fee: 1 fee units") && text.contains("valid until block "), "{text}");
    assert!(text.starts_with("asset list: none"), "{text}");
    assert!(!text.contains("leaf") && !text.contains("anchor"), "{text}");
}

#[test]
fn b_a_p_payment_of_the_hybrid_asset_takes_its_note_and_an_exact_fee_note() {
    let f = chain("sv2_b");
    let (b, text) = unsafe { send(&f, USDT as u16, 1_000, 2, L2ShapeTag::P) };
    assert_eq!(b.tx().public.fee, 2, "the P tier");
    assert!(text.contains("send 1,000 base units of asset 1 (no list for this network) to "), "{text}");
    assert!(text.contains("999,000 base units of asset 1 (no list for this network) returns to this wallet"), "{text}");
    assert!(text.contains("fee: 2 fee units"), "{text}");
}

#[test]
fn c_the_signature_needs_the_take_on_disk_and_happens_once() {
    let f = chain("sv2_c");
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let a = auth(w, &f.fresh).unwrap();
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
        let a = auth(w, &f.fresh).unwrap();
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
        let a = auth(w, &f.fresh).unwrap();
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
        let foreign = auth(other, &f.fresh).unwrap_err();
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
        let a = auth(w, &f.fresh).unwrap();
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
        let a = auth(w, &journal_at(&f, at_floor)).unwrap();
        let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
        pump(a, s, &f.ep, 0).expect("exactly at the floor: READY");
        let journal = take(a, s).unwrap();
        assert_eq!(next_of(&journal), at_floor + 1);
        let i = intent(s);
        sign(a, s, &i, &journal).expect("the take's own leaf does not refuse it");
        qmb_spend_v2_free(s);
        qmb_auth_free(a);

        let below = journal_at(&f, at_floor + 1);
        let a = auth(w, &below).unwrap();
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
        assert!(qmb_auth_open(ptr::null(), j.as_ptr(), &mut err).is_null());
        assert!(take_str(err).contains("NULL"));
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
        assert!(text.contains("send 1,000 base units of asset 1 (listed as tUSDT, but its issuer key changed: name withheld)"), "{text}");
        // The list does not carry asset 1: not on list <short id>.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&genesis, 7, [9; 4])));
        assert!(text.contains("send 1,000 base units of asset 1 (not on list "), "{text}");
        // A list for another network: ignored.
        let (_, text) = send_with(&f, USDT as u16, 1_000, 2, L2ShapeTag::P, Some(&list(&[0x11; 32], USDT as u16, [9; 4])));
        assert!(text.starts_with("asset list: for another network (11111111), ignored"), "{text}");
        assert!(text.contains("(no list for this network)"), "{text}");
    }
}
