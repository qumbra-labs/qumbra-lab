//! **Candidate A receive-only over the C ABI** (lab #896; extension #68 D2).
//!
//! (a) `qmb_wallet_address_v2` / `_short` are the wallet's version-2 address
//!     over generation `g`'s authorization root — the derivation seam G's
//!     wallet and the faucet use — and differ from the v1 address and from
//!     another generation's;
//! (b) `qmb_address_parse_any` names the version of a v1 and a v2 address,
//!     returns the canonical and short forms, and refuses a non-address by
//!     name;
//! (c) `qmb_annulet_new_v2` over a **format-33** fixture chain: a genesis note
//!     and a block note paid to the v2 address are found with the default
//!     generations (`[0]`), and not with generation 1 alone;
//! (d) the generation list: the bound (8) is accepted, one more, NULL with a
//!     count and a generation listed twice are refused by name.
//!
//! One wallet handle per test, so its root cache holds: each generation's
//! tree (4,096 ML-DSA-44 keys) is built once.
//!
//! Fixture seeds only; nothing proves.

#[path = "../../qumbra-wallet/tests/common/mod.rs"]
mod common;

use std::ffi::{c_char, CStr, CString};

use common::*;
use qlab_devnet::body::BlockBody;
use qumbra_ffi::annulet::{
    qmb_annulet_free, qmb_annulet_new, qmb_annulet_new_v2, qmb_annulet_step, qmb_annulet_supply,
    qmb_annulet_supply_err, qmb_annulet_take_view, MAX_ANNULET_GENERATIONS,
};
use qumbra_ffi::{
    qmb_address_parse_any, qmb_string_free, qmb_wallet_address, qmb_wallet_address_v2, qmb_wallet_address_v2_short,
    qmb_wallet_free, qmb_wallet_from_entropy,
};
use qumbra_wallet::auth_journal::generation_root;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

const RNG: [u8; 32] = [0x58; 32];
const SEED: u8 = 0xD2;

unsafe fn take_str(p: *mut c_char) -> String {
    assert!(!p.is_null(), "NULL string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    qmb_string_free(p);
    s
}

#[test]
fn a_the_v2_address_is_the_wallets_over_the_generation_root() {
    let w = wallet_dir("v2abi_a", SEED);
    let wallet = w.wallet();
    unsafe {
        let h = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        for (index, g) in [(0u64, 0u32), (1, 0), (0, 1)] {
            let want = wallet.address_candidate_a_at_index(index, &generation_root(&wallet, g));
            assert_eq!(want.version, qlab_wallet::address::ADDRESS_VERSION_CANDIDATE_A);
            assert_eq!(take_str(qmb_wallet_address_v2(h, index, g)), want.encode(), "index {index}, generation {g}");
            assert_eq!(take_str(qmb_wallet_address_v2_short(h, index, g)), want.short().encode());
        }
        let v1 = take_str(qmb_wallet_address(h, 0));
        let v2g0 = take_str(qmb_wallet_address_v2(h, 0, 0));
        let v2g1 = take_str(qmb_wallet_address_v2(h, 0, 1));
        assert_ne!(v1, v2g0, "not the v1 address");
        assert_ne!(v2g0, v2g1, "each generation binds its own root");
        // The cache: a second call answers the same.
        assert_eq!(take_str(qmb_wallet_address_v2(h, 0, 0)), v2g0);
        assert!(qmb_wallet_address_v2(std::ptr::null(), 0, 0).is_null());
        qmb_wallet_free(h);
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn b_parse_any_names_the_version_and_refuses_a_non_address() {
    let w = wallet_dir("v2abi_b", SEED);
    let wallet = w.wallet();
    let v1 = wallet.address_at_index(0);
    let v2 = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0));
    unsafe {
        for (addr, version) in [(&v1, 1u64), (&v2, 2)] {
            let s = CString::new(addr.encode()).unwrap();
            let mut err: *mut c_char = std::ptr::null_mut();
            let v: Value = serde_json::from_str(&take_str(qmb_address_parse_any(s.as_ptr(), &mut err))).unwrap();
            assert!(err.is_null());
            assert_eq!(v["version"], version);
            assert_eq!(v["canonical"], addr.encode());
            assert_eq!(v["short"], addr.short().encode());
        }
        for bad in ["not an address".to_string(), v1.short().encode()] {
            let s = CString::new(bad.clone()).unwrap();
            let mut err: *mut c_char = std::ptr::null_mut();
            assert!(qmb_address_parse_any(s.as_ptr(), &mut err).is_null(), "{bad} is refused");
            assert!(take_str(err).contains("not a Qumbra address"), "{bad}: by name");
        }
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

thread_local! {
    /// Every path `scan` was asked for, in order (lab #937: what the kernel
    /// fetched before it refused).
    static ASKED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// One scan of handle `w` through `qmb_annulet_new_v2` (`gens` = Some) or the
/// old `qmb_annulet_new` (`gens` = None); the view or the refusal.
unsafe fn scan(w: *mut qumbra_ffi::WalletState, ep: &Endpoint, gens: Option<&[u32]>) -> Result<Value, Value> {
    {
        let endpoint = CString::new("fixture").unwrap();
        let pin = ep.file.hash();
        let indices = [0u64, 1];
        let null = std::ptr::null();
        let mut err: *mut c_char = std::ptr::null_mut();
        let s = match gens {
            Some(g) => qmb_annulet_new_v2(
                w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, null, 0,
                null, 0, null, 0, std::ptr::null(), if g.is_empty() { std::ptr::null() } else { g.as_ptr() }, g.len(),
                &mut err,
            ),
            None => qmb_annulet_new(
                w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), null, 0, null, 0,
                null, 0, null, 0, std::ptr::null(), &mut err,
            ),
        };
        assert!(!s.is_null(), "new refused: {}", if err.is_null() { "NULL".into() } else { take_str(err) });
        let out = loop {
            let mut out: *mut c_char = std::ptr::null_mut();
            match qmb_annulet_step(s, &mut out) {
                1 => {
                    let path = take_str(out);
                    ASKED.with(|a| a.borrow_mut().push(path.clone()));
                    match ep.fetch(&path) {
                        Ok(body) => qmb_annulet_supply(s, body.as_ptr(), body.len()),
                        Err(why) => {
                            let why = CString::new(why).unwrap();
                            qmb_annulet_supply_err(s, why.as_ptr());
                        }
                    }
                }
                0 => break Ok(serde_json::from_str(&take_str(qmb_annulet_take_view(s))).unwrap()),
                -2 => break Err(serde_json::from_str(&take_str(out)).unwrap()),
                other => panic!("step returned {other}"),
            }
        };
        qmb_annulet_free(s);
        out
    }
}

fn spendable(view: &Value, asset: u64) -> Option<String> {
    view["balances"]["rows"]
        .as_array()?
        .iter()
        .find(|r| r["asset"] == asset)
        .and_then(|r| r["spendable"]["baseUnits"].as_str().map(str::to_string))
}

/// The format-33 fixture: the genesis pays 1,000,000 USDT-test to the v2
/// address 0 (generation 0); height 1 pays it 5 fee units.
fn v2_chain() -> (WalletDirGuard, Endpoint) {
    let w = wallet_dir("v2abi_c", SEED);
    let wallet = w.wallet();
    let a2 = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0));
    let mut rng = StdRng::seed_from_u64(0xD2);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let file = genesis_v2(&a2, Vec::new());
    assert_eq!(file.format_version, qlab_devnet::forms::ANNULET_AUTH_GENESIS_FORMAT_VERSION, "a format-33 genesis");
    let ep = Endpoint::new(file, &[body], None, Lie::None);
    (WalletDirGuard(w), ep)
}

struct WalletDirGuard(qumbra_wallet::store::WalletDir);
impl Drop for WalletDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0.dir);
    }
}

#[test]
fn c_a_format_33_scan_finds_the_v2_notes_under_generation_0() {
    let (_w, ep) = v2_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let view = scan(w, &ep, Some(&[])).expect("the format-33 chain verifies");
        assert_eq!(spendable(&view, USDT).as_deref(), Some("1000000"), "the genesis note: {view}");
        assert_eq!(spendable(&view, 0).as_deref(), Some("5"), "the block note: {view}");
        assert_eq!(scan(w, &ep, Some(&[0])).unwrap(), view, "[0] is the default");
        // Generation 1 alone owns none of them.
        let other = scan(w, &ep, Some(&[1])).expect("still verifies");
        assert_eq!(spendable(&other, USDT), None, "{other}");
        assert_eq!(spendable(&other, 0), None, "{other}");
        qmb_wallet_free(w);
    }
}

#[test]
fn d_the_generation_list_is_bounded_by_name() {
    let (_w, ep) = v2_chain();
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let endpoint = CString::new("fixture").unwrap();
        let pin = ep.file.hash();
        let (nu8, nu64) = (std::ptr::null::<u8>(), std::ptr::null::<u64>());
        let too_many: Vec<u32> = (0..=MAX_ANNULET_GENERATIONS as u32).collect();
        let twice = [0u32, 0];
        for (p, n, why) in [
            (too_many.as_ptr(), too_many.len(), "generations: at most"),
            (std::ptr::null(), 3, "generations: at most"),
            (std::ptr::null(), 1, "generations: at most"),
            (twice.as_ptr(), 2, "generation 0 is listed twice"),
        ] {
            let mut err: *mut c_char = std::ptr::null_mut();
            let s = qmb_annulet_new_v2(
                w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, nu64, 0, RNG.as_ptr(), nu8, 0, nu8, 0, nu8, 0,
                nu8, 0, std::ptr::null(), p, n, &mut err,
            );
            assert!(s.is_null(), "{n} generations refused");
            let e = take_str(err);
            assert!(e.contains(why), "by name: {e}");
        }
        // The bound itself is accepted, and the scan completes.
        let bound: Vec<u32> = (0..MAX_ANNULET_GENERATIONS as u32).collect();
        assert_eq!(bound.len(), 8);
        let view = scan(w, &ep, Some(&bound)).expect("eight generations scan");
        assert_eq!(spendable(&view, USDT).as_deref(), Some("1000000"), "generation 0 is among them");
        qmb_wallet_free(w);
    }
}

/// Lab #937 PR C: the kernel refuses a format-34 net **by name** after its
/// verified scan — `format_not_supported`, until PR D carries the
/// three-output path into the kernel (the wallet CLI already builds it). The
/// same holder's format-33 chain still scans.
#[test]
fn e_a_format_34_net_is_refused_by_the_kernel_until_pr_d() {
    let w = wallet_dir("v2abi_e34", SEED);
    let wallet = w.wallet();
    let a2 = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0));
    let v2 = genesis_v2(&a2, Vec::new());
    let v3 = qlab_node::annulet_genesis::AnnuletGenesisFile::assemble_with_auth(
        "annulet-ad1-v3",
        v2.params,
        SEQ_SEED,
        v2.registry_genesis.clone(),
        v2.genesis_notes.clone(),
        0,
        qlab_devnet::forms::L2AuthForm::CandidateAV3,
    );
    assert_eq!(v3.format_version, 34);
    let ep = Endpoint::new(v3, &[], None, Lie::None);
    let _guard = WalletDirGuard(w);
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        ASKED.with(|a| a.borrow_mut().clear());
        let refusal = scan(w, &ep, Some(&[])).expect_err("the kernel refuses format 34");
        assert_eq!(refusal["refusal"], "format_not_supported", "{refusal}");
        assert!(refusal["message"].as_str().unwrap().contains("lab #937 PR D"), "{refusal}");
        // Review F3: refused right after the genesis verifies — nothing of
        // the chain was asked for.
        assert_eq!(ASKED.with(|a| a.borrow().clone()), vec!["/genesis.qmb".to_string()]);
        qmb_wallet_free(w);
    }
}
