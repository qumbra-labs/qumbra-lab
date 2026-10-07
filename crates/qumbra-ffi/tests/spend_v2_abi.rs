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
    qmb_auth_journal_advances,
    qmb_auth_check_finish, qmb_auth_check_free, qmb_auth_check_new, qmb_auth_check_step, qmb_auth_check_supply,
    qmb_auth_check_supply_err, qmb_auth_free, qmb_auth_journal, qmb_auth_open_next, qmb_auth_restore_new, qmb_auth_take, qmb_intent_review, qmb_intent_sign, qmb_spend_basis_free,
    qmb_spend_v2_free, qmb_spend_v2_intent, qmb_spend_v2_new, qmb_spend_v2_refusal, qmb_spend_v2_step, qmb_spend_v2_supply,
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
                let h: u64 = path.split('/').nth(3).unwrap().parse().unwrap();
                if fail_at == Some(h) {
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
    qmb_auth_check_free(c);
    let journal = if jout.is_null() { String::new() } else { take_str(jout) };
    if a.is_null() {
        return Err(format!("{} [status {status}] {journal}", take_str(err)));
    }
    Ok(Opened { a, journal, status, paths })
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
    let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
    let a = auth(w, &f.ep, &f.fresh).unwrap();
    let s = spend(basis(w, &f.ep), &f.payee, 0, 10, 96).unwrap();
    pump(a, s, &f.ep, 0).unwrap();
    let journal = take(a, s).unwrap();
    let i = intent(s);
    let bundle = sign(a, s, &i, &journal).unwrap();
    let mut tx = ProvingBundle::decode(&bundle).unwrap().tx().clone();
    tx.proof = vec![0xAB; 64];
    qmb_spend_v2_free(s);
    qmb_auth_free(a);
    qmb_wallet_free(w);
    (tx, journal)
}

/// The fixture chain on which our spend landed at height 2 — built once.
fn spent_chain() -> &'static (Fixture, String) {
    static F: std::sync::OnceLock<(Fixture, String)> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let f = chain("sv2_spent_src");
        let (tx, journal) = unsafe { landed_spend(&f) };
        let landed = chain_full("sv2_spent", Lie::None, vec![BlockBody { txs: vec![tx], ..BlockBody::default() }], false);
        (landed, journal)
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
        let active = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 1));
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
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, &mut out), 0);
        let fresh = take_str(out);
        assert_eq!(next_of(&fresh), 0);
        assert!(fresh.starts_with("qumbra-wallet auth v1\n"), "{fresh}");
        // Once: the mark is consumed.
        assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(born, &mut out), -1);
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
            assert_eq!(qumbra_ffi::spend_v2::qmb_auth_first_fresh(h, &mut out), -1);
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
        let own_g0 = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 0));
        let s = spend(basis_g(w, &f.ep, &[0, 1]), &own_g0, 0, 10, 96).unwrap();
        assert!(pump(sweep.a, s, &f.ep, 0).unwrap_err().contains("sweep-only"));
        qmb_spend_v2_free(s);
        // ... and pays the active generation's address.
        let active = take_str(qumbra_ffi::qmb_wallet_address_v2(w, 0, 1));
        let s = spend(basis_g(w, &f.ep, &[0, 1]), &active, 0, 10, 96).unwrap();
        pump(sweep.a, s, &f.ep, 0).unwrap();
        qmb_spend_v2_free(s);
        qmb_auth_free(sweep.a);
        qmb_wallet_free(w);
    }
}
