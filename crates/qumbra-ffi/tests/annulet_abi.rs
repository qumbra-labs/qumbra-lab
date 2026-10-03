//! **WA2's done-when** (lab #858): the `qmb_annulet_*` ABI is the kernel's
//! verified asset scan, and its JSON is the macOS bridge's.
//!
//! (a) over the AD1 fixture, the ABI pump gives exactly what the macOS
//!     bridge's synchronous path gives — `view_json(asset_view(
//!     scan_annulet_verified(…)))` — with the same fetch sequence (driver
//!     Needs, then leaf Needs in `held_assets` order) and the same record;
//! (b) each of AD1's five lies: a named refusal (or, for the forged registry
//!     leaf, a row that names its leaf problem), equal to the kernel's;
//! (c) the record round-trips through the host: a second scan fed the first's
//!     record re-checks the recorded tip and reads only what is new; a
//!     tampered record costs a full re-verify, never a refusal;
//! (d) the list: a bad signature or a partial triple is refused at `_new`
//!     by name; another network's list labels nothing;
//! (e) misuse: an answer out of turn is `driver_misuse`; a step after DONE
//!     is -1; the view crosses once;
//! (f) key sets: the refusal JSON, and every list/balances state of the view,
//!     carry exactly the macOS bridge's keys.
//!
//! The golden is the macOS XCTest decode literal — `qumbra-wallet-macos`
//! `Tests/QumbraWalletMacTests/BridgeModelTests.swift` @ e050024,
//! `assetViewJSON(spendsVerified:)`, copied below with `"false"`.

#[path = "../../qumbra-wallet/tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, CStr, CString};

use common::*;
use qlab_devnet::body::BlockBody;
use qumbra_ffi::annulet::{
    qmb_annulet_free, qmb_annulet_new, qmb_annulet_step, qmb_annulet_supply, qmb_annulet_supply_err,
    qmb_annulet_take_record, qmb_annulet_take_view, refusal_json, refusal_key, view_json,
};
use qumbra_ffi::{qmb_dealloc, qmb_string_free, qmb_wallet_free, qmb_wallet_from_entropy};
use qumbra_wallet::annulet_verify::{chain_cache_path, scan_annulet_verified, VerifyRefusal};
use qumbra_wallet::asset_view::{
    asset_view, render_amount, test_list_key, verify_asset_list, Amount, AssetLabel, AssetList, AssetMode, AssetRow,
    AssetView, Balances, FreezeStatus, ListStatus,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

const RNG: [u8; 32] = [0x58; 32];
const ENDPOINT: &str = "fixture";
const COMMIT: &str = "2f466c8";

/// A signed list: (bytes, signature, key encoding).
type Signed = (Vec<u8>, Vec<u8>, Vec<u8>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn list_for(genesis: &[u8; 32]) -> Signed {
    let issuer = hex(&qlab_node::annulet_genesis::h32(&[9, 9, 9, 9]));
    let bytes = format!(
        r#"{{"v":1,"network":"annulet-ad1","genesis":"{}","testnet":true,"assets":[{{"id":1,"issuer_key":"{issuer}","name":"Tether USD (test)","ticker":"tUSDT","decimals":6}}]}}"#,
        hex(genesis)
    )
    .into_bytes();
    let sig = test_list_key::sign(&bytes);
    (bytes, sig, test_list_key::encoded())
}

struct Abi {
    result: Result<Value, Value>,
    paths: Vec<String>,
    record: Option<Vec<u8>>,
}

unsafe fn take_str(p: *mut c_char) -> String {
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    qmb_string_free(p);
    s
}

/// One scan through the ABI, pumped like a host: `fetch` answers each Need.
fn abi(seed: u8, ep: &Endpoint, list: Option<&Signed>, record: Option<&[u8]>) -> Abi {
    unsafe {
        let w = qmb_wallet_from_entropy([seed; 32].as_ptr());
        let endpoint = CString::new(ENDPOINT).unwrap();
        let commit = CString::new(COMMIT).unwrap();
        let pin = ep.file.hash();
        let indices = [0u64, 1];
        let (lp, ll, sp, sl, kp, kl) = match list {
            Some((b, s, k)) => (b.as_ptr(), b.len(), s.as_ptr(), s.len(), k.as_ptr(), k.len()),
            None => (std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0),
        };
        let (rp, rl) = record.map_or((std::ptr::null(), 0), |r| (r.as_ptr(), r.len()));
        let mut err: *mut c_char = std::ptr::null_mut();
        let s = qmb_annulet_new(
            w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, indices.as_ptr(), 2, RNG.as_ptr(), rp, rl, lp, ll, sp, sl,
            kp, kl, commit.as_ptr(), &mut err,
        );
        assert!(!s.is_null(), "qmb_annulet_new refused: {}", if err.is_null() { "NULL".into() } else { take_str(err) });
        let mut paths = Vec::new();
        let result = loop {
            let mut out: *mut c_char = std::ptr::null_mut();
            match qmb_annulet_step(s, &mut out) {
                1 => {
                    let path = take_str(out);
                    match ep.fetch(&path) {
                        Ok(body) => qmb_annulet_supply(s, body.as_ptr(), body.len()),
                        Err(why) => {
                            let why = CString::new(why).unwrap();
                            qmb_annulet_supply_err(s, why.as_ptr());
                        }
                    }
                    paths.push(path);
                }
                0 => {
                    let view = take_str(qmb_annulet_take_view(s));
                    assert!(qmb_annulet_take_view(s).is_null(), "the view crosses once");
                    break Ok(serde_json::from_str(&view).unwrap());
                }
                -2 => break Err(serde_json::from_str(&take_str(out)).unwrap()),
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
        Abi { result, paths, record }
    }
}

/// The macOS bridge's synchronous path, over the same fixture and rng: the
/// verified scan, then `asset_view`'s leaves, encoded by the shared encoder.
fn bridge(tag: &str, seed: u8, ep: &Endpoint, list: Option<&Signed>, record: Option<&[u8]>) -> Abi {
    let w = wallet_dir(tag, seed);
    let pin = ep.file.hash();
    if let Some(r) = record {
        std::fs::write(chain_cache_path(&w, &pin), r).unwrap();
    }
    let list: Option<AssetList> = list.map(|(b, s, _)| verify_asset_list(b, s, &test_list_key::verifying()).unwrap());
    let mut paths = Vec::new();
    let mut fetch = |p: &str| {
        paths.push(p.to_string());
        ep.fetch(p)
    };
    let mut rng = StdRng::from_seed(RNG);
    let (result, record) = match scan_annulet_verified(&w, &mut fetch, 0, u64::MAX, Some(pin), &mut rng) {
        Err(e) => (Err(refusal_json(&e)), None),
        Ok(v) => {
            let view = asset_view(&w, &v, list.as_ref(), &BTreeMap::new(), &mut fetch);
            let record = v.record_to_write().map(|_| std::fs::read(chain_cache_path(&w, &pin)).unwrap());
            (Ok(view_json(ENDPOINT, &view, v.body_cost(), Some(COMMIT))), record)
        }
    };
    let _ = std::fs::remove_dir_all(&w.dir);
    Abi { result, paths, record }
}

fn assert_same(tag: &str, a: &Abi, b: &Abi) {
    assert_eq!(a.result, b.result, "{tag}: the result");
    assert_eq!(a.paths, b.paths, "{tag}: the fetch sequence");
    assert_eq!(a.record, b.record, "{tag}: the record");
}

fn honest(seed: u8, n: usize) -> (Endpoint, Vec<BlockBody>) {
    let w = wallet_dir(&format!("abi_bodies_{seed:x}"), seed);
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let a0 = w.wallet().address_at_index(0);
    let mut b = bodies(&w, &mut rng);
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 1, USDT, 60)], 0x60, &mut rng)], ..BlockBody::default() });
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 2, USDT, 61)], 0x61, &mut rng)], ..BlockBody::default() });
    let ep = Endpoint::new(genesis(&a0), &b[..n], None, Lie::None);
    let _ = std::fs::remove_dir_all(&w.dir);
    (ep, b)
}

#[test]
fn a_the_abi_is_the_bridges_path_byte_for_key() {
    const SEED: u8 = 0xA1;
    let (ep, _) = honest(SEED, 3);
    let list = list_for(&ep.file.hash());
    for (tag, l) in [("listed", Some(&list)), ("no_list", None)] {
        let a = abi(SEED, &ep, l, None);
        assert_same(tag, &a, &bridge(&format!("abi_a_{tag}"), SEED, &ep, l, None));
        let v = a.result.as_ref().expect("an honest endpoint");
        assert_eq!(v["spendsVerified"], Value::Bool(false));
        assert_eq!(v["verifiedTip"], 3);
        assert!(a.record.is_some(), "{tag}: a first verification is recorded");
        let rows = v["balances"]["rows"].as_array().unwrap();
        let usdt = rows.iter().find(|r| r["asset"] == USDT).unwrap();
        match tag {
            "listed" => {
                assert_eq!(usdt["label"]["kind"], "listed");
                assert_eq!(usdt["spendable"]["display"], "1.000407");
                assert_eq!(v["listSourceCommit"], COMMIT);
            }
            _ => {
                assert_eq!(usdt["label"]["kind"], "unlisted");
                assert_eq!(v["listSourceCommit"], Value::Null);
            }
        }
        // The leaf Need comes after every driver Need.
        let leaf_at = a.paths.iter().position(|p| p == "/v1/registry/1").expect("USDT's leaf asked");
        assert_eq!(leaf_at, a.paths.len() - 1, "{tag}: leaves last: {:?}", a.paths);
    }
}

#[test]
fn b_each_of_ad1s_five_lies_is_named_across_the_abi() {
    const SEED: u8 = 0xB1;
    let w = wallet_dir("abi_b", SEED);
    let mut rng = StdRng::seed_from_u64(0xB1);
    let a0 = w.wallet().address_at_index(0);
    let file = genesis(&a0);
    let honest = bodies(&w, &mut rng);
    let mut forged_note = honest.clone();
    forged_note[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let mut forged_group = honest.clone();
    forged_group[1].txs[0] = pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 98)], 0x40, &mut rng);
    let list = list_for(&file.hash());
    type Case<'a> = (&'a str, Lie, Option<&'a [BlockBody]>, Option<&'a str>);
    let cases: Vec<Case> = vec![
        ("genesis_bytes", Lie::GenesisBytes, None, Some("genesis_mismatch")),
        ("bad_seal", Lie::BadSeal, None, Some("header_invalid")),
        ("forged_note", Lie::ForgedNote, Some(&forged_note), Some("body_commitment_mismatch")),
        ("forged_group", Lie::ForgedGroup, Some(&forged_group), Some("forged_note")),
        ("registry_leaf", Lie::RegistryLeaf, None, None),
    ];
    for (tag, lie, forged, key) in cases {
        let ep = Endpoint::new(file.clone(), &honest, forged, lie);
        let a = abi(SEED, &ep, Some(&list), None);
        assert_same(tag, &a, &bridge(&format!("abi_b_{tag}"), SEED, &ep, Some(&list), None));
        match key {
            Some(key) => {
                let r = a.result.as_ref().expect_err(tag);
                assert_eq!(r["refusal"], key, "{tag}");
                assert!(a.record.is_none(), "{tag}: a refused scan records nothing");
            }
            None => {
                // The chain is honest; the forged leaf confirms nothing.
                let v = a.result.as_ref().expect(tag);
                let usdt = v["balances"]["rows"].as_array().unwrap().iter().find(|r| r["asset"] == USDT).unwrap().clone();
                assert_eq!(usdt["label"]["kind"], "unconfirmed", "{tag}");
                assert!(usdt["leafProblem"].as_str().unwrap().contains("NotAtVerifiedTip"), "{usdt}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn c_the_record_round_trips_through_the_host() {
    const SEED: u8 = 0xC1;
    let (ep3, b) = honest(SEED, 3);
    let ep5 = Endpoint::new(ep3.file.clone(), &b, None, Lie::None);
    let first = abi(SEED, &ep3, None, None);
    let record = first.record.clone().expect("recorded");
    assert_eq!(record.len(), 41 + 3 * 153);

    let second = abi(SEED, &ep5, None, Some(&record));
    assert_same("resume", &second, &bridge("abi_c_resume", SEED, &ep5, None, Some(&record)));
    let headers: Vec<&str> = second.paths.iter().filter(|p| p.starts_with("/v1/headers")).map(String::as_str).collect();
    assert_eq!(headers, vec!["/v1/headers?from=3&to=3", "/v1/headers?from=4&to=259"], "only what is new");
    assert_eq!(second.result.as_ref().unwrap()["verifiedTip"], 5);
    assert_eq!(second.record.as_ref().map(Vec::len), Some(41 + 5 * 153));

    // A tampered record is a cache miss, never a refusal.
    let mut tampered = record.clone();
    tampered[41 + 40] ^= 1;
    let third = abi(SEED, &ep3, None, Some(&tampered));
    assert_same("tampered", &third, &bridge("abi_c_tampered", SEED, &ep3, None, Some(&tampered)));
    assert!(third.result.is_ok());
    assert!(third.paths.iter().any(|p| p == "/v1/headers?from=1&to=256"), "re-verified from genesis");
    assert_eq!(third.record, Some(record), "the discarded record is rewritten");
}

#[test]
fn d_a_list_is_verified_at_new_and_labels_only_its_network() {
    const SEED: u8 = 0xD1;
    let (ep, _) = honest(SEED, 3);
    let (bytes, sig, key) = list_for(&ep.file.hash());
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let endpoint = CString::new(ENDPOINT).unwrap();
        let pin = ep.file.hash();
        let idx = [0u64, 1];
        let new = |b: &[u8], s: Option<&[u8]>, k: &[u8]| {
            let mut err: *mut c_char = std::ptr::null_mut();
            let (sp, sl) = s.map_or((std::ptr::null(), 0), |s| (s.as_ptr(), s.len()));
            let h = qmb_annulet_new(
                w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, idx.as_ptr(), 2, RNG.as_ptr(), std::ptr::null(), 0,
                b.as_ptr(), b.len(), sp, sl, k.as_ptr(), k.len(), std::ptr::null(), &mut err,
            );
            let err = (!err.is_null()).then(|| take_str(err));
            if !h.is_null() {
                qmb_annulet_free(h);
            }
            (h.is_null(), err)
        };
        let mut bad = sig.clone();
        bad[0] ^= 1;
        let (null, err) = new(&bytes, Some(&bad), &key);
        assert!(null);
        assert!(err.unwrap().starts_with("the asset list is refused: "));
        let (null, err) = new(&bytes, None, &key);
        assert!(null);
        assert!(err.unwrap().contains("all three or none"));
        let (null, err) = new(&bytes, Some(&sig), &key[..100]);
        assert!(null);
        assert_eq!(err.unwrap(), "the asset-list key does not decode");
        qmb_wallet_free(w);
    }
    let other = list_for(&[7; 32]);
    let a = abi(SEED, &ep, Some(&other), None);
    assert_same("other_network", &a, &bridge("abi_d_other", SEED, &ep, Some(&other), None));
    let v = a.result.unwrap();
    assert_eq!(v["list"]["state"], "other_network");
    assert_eq!(v["list"]["listGenesis"], hex(&[7; 32]));
    assert_eq!(v["listSourceCommit"], Value::Null, "a commit is named only for a list that labels the view");
}

#[test]
fn e_misuse_is_a_host_bug_by_name() {
    const SEED: u8 = 0xE1;
    let (ep, _) = honest(SEED, 3);
    unsafe {
        let w = qmb_wallet_from_entropy([SEED; 32].as_ptr());
        let endpoint = CString::new(ENDPOINT).unwrap();
        let pin = ep.file.hash();
        let idx = [0u64, 1];
        let mk = || {
            let null = std::ptr::null();
            qmb_annulet_new(
                w, endpoint.as_ptr(), pin.as_ptr(), 0, u64::MAX, idx.as_ptr(), 2, RNG.as_ptr(), null, 0, null, 0, null, 0,
                null, 0, std::ptr::null(), std::ptr::null_mut(),
            )
        };
        // An answer before any Need.
        let s = mk();
        qmb_annulet_supply(s, [1u8].as_ptr(), 1);
        let mut out: *mut c_char = std::ptr::null_mut();
        assert_eq!(qmb_annulet_step(s, &mut out), -2);
        let r: Value = serde_json::from_str(&take_str(out)).unwrap();
        assert_eq!(r["refusal"], "driver_misuse");
        assert_eq!(qmb_annulet_step(s, &mut out), -2, "a refusal is terminal and repeats");
        qmb_string_free(out);
        qmb_annulet_free(s);

        // A step after DONE; an answer after DONE.
        let s = mk();
        loop {
            let mut out: *mut c_char = std::ptr::null_mut();
            match qmb_annulet_step(s, &mut out) {
                1 => {
                    let body = ep.fetch(&take_str(out)).unwrap();
                    qmb_annulet_supply(s, body.as_ptr(), body.len());
                }
                0 => break,
                other => panic!("{other}"),
            }
        }
        let mut out: *mut c_char = std::ptr::null_mut();
        assert_eq!(qmb_annulet_step(s, &mut out), -1, "a step after DONE");
        assert!(!qmb_annulet_take_view(s).is_null());
        qmb_annulet_supply(s, [1u8].as_ptr(), 1);
        assert!(qmb_annulet_take_view(s).is_null(), "the view crossed once");
        assert_eq!(qmb_annulet_step(s, &mut out), -1);
        qmb_annulet_free(s);
        qmb_wallet_free(w);
    }
}

/// The macOS XCTest decode literal (see the module doc), with `"false"`.
const SWIFT_GOLDEN: &str = r#"
        {"endpoint":"http://node","genesisHash":"abababababababababababababababababababababababababababababababab","verifiedTip":270,
         "statedTip":272,"headersBehind":2,"bodiesRecomputed":3,"bodyBytes":900000,"spendsVerified":false,
         "list":{"state":"no_list"},"listSourceCommit":null,
         "balances":{"state":"figures","rows":[{"asset":1001,"label":{"kind":"unlisted"},"mode":"cloaked",
           "modeRaw":null,"spendable":{"baseUnits":"340282366920938463463374607431768211455",
           "display":"340,282,366,920,938,463,463,374,607,431,768,211,455","unit":"base units of asset #1001"},
           "spendableNotes":2,"testnet":true,"freeze":"no_freeze_list","leafProblem":null}]}}
"#;

fn golden_view(list: ListStatus, balances: Balances) -> AssetView {
    AssetView { genesis_hash: [0xab; 32], verified_tip: 270, stated_tip: Some(272), spends_verified: false, list, balances }
}

fn golden_row() -> AssetRow {
    AssetRow {
        asset: 1001,
        label: AssetLabel::Unlisted,
        mode: AssetMode::Cloaked,
        spendable: Amount {
            base_units: u128::MAX,
            display: render_amount(u128::MAX, 0),
            unit: "base units of asset #1001".into(),
        },
        spendable_notes: 2,
        testnet: true,
        freeze: FreezeStatus::NoFreezeList,
        leaf_problem: None,
    }
}

#[test]
fn f_the_shared_encoder_is_the_swift_golden() {
    let golden: Value = serde_json::from_str(SWIFT_GOLDEN).unwrap();
    let ours = view_json(
        "http://node",
        &golden_view(ListStatus::NoList, Balances::Figures(vec![golden_row()])),
        (3, 900_000),
        Some("ignored: no list labels the view"),
    );
    assert_eq!(ours, golden);
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn set(ks: &[&str]) -> BTreeSet<String> {
    ks.iter().map(|k| k.to_string()).collect()
}

/// (f) Every state the golden does not cover carries exactly the bridge's
/// keys (`qumbra-wallet-macos` `rust/src/assets.rs` @ e050024: the serde
/// shapes of `ListStatusView`, `BalancesView`, `AssetLabelView`).
#[test]
fn f_every_view_state_and_the_refusal_carry_the_bridges_keys() {
    let golden: Value = serde_json::from_str(SWIFT_GOLDEN).unwrap();
    let top = keys(&golden);
    let row_keys = keys(&golden["balances"]["rows"][0]);
    let lists = [
        (ListStatus::NoList, set(&["state"])),
        (ListStatus::Listed { network: "n".into(), digest: [1; 32], signer: [2; 32] }, set(&["state", "network", "digest", "signer"])),
        (ListStatus::OtherNetwork { list_genesis: [3; 32] }, set(&["state", "listGenesis"])),
    ];
    let balances = [
        (Balances::Unavailable { why: "w".into() }, set(&["state", "reason"])),
        (Balances::Figures(vec![golden_row()]), set(&["state", "rows"])),
    ];
    for (list, list_keys) in &lists {
        for (bal, bal_keys) in &balances {
            let v = view_json("e", &golden_view(list.clone(), bal.clone()), (0, 0), Some("c"));
            assert_eq!(keys(&v), top, "top level");
            assert_eq!(keys(&v["list"]), *list_keys, "{list:?}");
            assert_eq!(keys(&v["balances"]), *bal_keys, "{bal:?}");
            if let Some(rows) = v["balances"]["rows"].as_array() {
                assert_eq!(keys(&rows[0]), row_keys);
            }
        }
    }
    let labels = [
        (AssetLabel::FeeUnit, "fee_unit", set(&["kind"])),
        (AssetLabel::Listed { name: "n".into(), ticker: "t".into() }, "listed", set(&["kind", "name", "ticker"])),
        (AssetLabel::IssuerChanged { listed_ticker: "t".into() }, "issuer_changed", set(&["kind", "listedTicker"])),
        (AssetLabel::Unconfirmed { listed_ticker: "t".into() }, "unconfirmed", set(&["kind", "listedTicker"])),
        (AssetLabel::Unlisted, "unlisted", set(&["kind"])),
    ];
    for (label, kind, label_keys) in labels {
        let mut row = golden_row();
        row.label = label;
        let v = view_json("e", &golden_view(ListStatus::NoList, Balances::Figures(vec![row])), (0, 0), None);
        let l = &v["balances"]["rows"][0]["label"];
        assert_eq!(l["kind"], kind);
        assert_eq!(keys(l), label_keys, "{kind}");
    }
    let r = refusal_json(&VerifyRefusal::NoPin);
    assert_eq!(keys(&r), set(&["refusal", "message"]));
}

/// Q2's condition: every refusal's machine key, pinned. The match is
/// exhaustive, so a new variant does not compile here until its key is
/// pinned too.
#[test]
fn every_refusal_has_its_pinned_key() {
    use VerifyRefusal::*;
    let s = String::new;
    let all = [
        NoPin,
        GenesisUnavailable { why: s() },
        GenesisTooLarge { got: 0 },
        GenesisMismatch { pinned: [0; 32], fetched: [0; 32] },
        GenesisInvalid { why: s() },
        HeadersUnavailable { from: 0, why: s() },
        HeadersMalformed { from: 0, why: s() },
        HeaderGap { want: 0, got: 0 },
        HeaderFork { height: 0 },
        HeaderInvalid { height: 0, why: s() },
        BodyUnavailable { height: 0, why: s() },
        BodyMalformed { height: 0, why: s() },
        BodyHeaderMismatch { height: 0 },
        BodyCommitmentMismatch { height: 0 },
        ForgedNote { height: 0, tx_index: 0, why: s() },
        ForgedGenesisNote { cm: [0; 32] },
        RegistryUnavailable { asset: 0, why: s() },
        RegistryWrongAsset { want: 0, got: 0 },
        RegistryHeightUnverified { height: 0, tip: 0 },
        RegistryRootMismatch { height: 0 },
        RegistryPathMismatch { asset: 0 },
        ChainCacheInvalid { why: s() },
        CachedTipForked { height: 0 },
        DriverMisuse { why: s() },
    ];
    let mut seen = BTreeSet::new();
    for r in &all {
        let pinned = match r {
            NoPin => "no_pin",
            GenesisUnavailable { .. } => "genesis_unavailable",
            GenesisTooLarge { .. } => "genesis_too_large",
            GenesisMismatch { .. } => "genesis_mismatch",
            GenesisInvalid { .. } => "genesis_invalid",
            HeadersUnavailable { .. } => "headers_unavailable",
            HeadersMalformed { .. } => "headers_malformed",
            HeaderGap { .. } => "header_gap",
            HeaderFork { .. } => "header_fork",
            HeaderInvalid { .. } => "header_invalid",
            BodyUnavailable { .. } => "body_unavailable",
            BodyMalformed { .. } => "body_malformed",
            BodyHeaderMismatch { .. } => "body_header_mismatch",
            BodyCommitmentMismatch { .. } => "body_commitment_mismatch",
            ForgedNote { .. } => "forged_note",
            ForgedGenesisNote { .. } => "forged_genesis_note",
            RegistryUnavailable { .. } => "registry_unavailable",
            RegistryWrongAsset { .. } => "registry_wrong_asset",
            RegistryHeightUnverified { .. } => "registry_height_unverified",
            RegistryRootMismatch { .. } => "registry_root_mismatch",
            RegistryPathMismatch { .. } => "registry_path_mismatch",
            ChainCacheInvalid { .. } => "chain_cache_invalid",
            CachedTipForked { .. } => "cached_tip_forked",
            DriverMisuse { .. } => "driver_misuse",
        };
        assert_eq!(refusal_key(r), pinned);
        assert!(seen.insert(pinned), "{pinned} twice");
    }
    assert_eq!(seen.len(), 24, "every variant listed once");
}

/// Condition 2: the TEST list signer is reachable only through this crate's
/// dev-dependency. The `[dependencies]` entry for `qumbra-wallet` — the one a
/// release or wasm build resolves — must not name `test-support`, and the
/// workspace resolver must be "2" (which keeps dev-dependency features out of
/// a non-test build).
#[test]
fn the_test_list_key_is_not_reachable_from_a_release_build() {
    let manifest = include_str!("../Cargo.toml");
    let deps = manifest.split("[dependencies]").nth(1).unwrap().split("\n[").next().unwrap();
    let wallet = deps.lines().find(|l| l.starts_with("qumbra-wallet")).expect("the dependency");
    assert!(!wallet.contains("test-support"), "{wallet}");
    let workspace = include_str!("../../../Cargo.toml");
    assert!(workspace.contains("resolver = \"2\""), "the workspace resolver keeps dev features out of release builds");
}
