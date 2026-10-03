//! **AD2's done-when** (lab #850): the signed asset list verifies or is
//! refused by name, and the view model renders each case the design names —
//! listed, unlisted, issuer changed (D2), testnet, UNAVAILABLE, frozen — from
//! a **verified** scan only, carrying `spends_verified = false` (lab #853).
//!
//! Lists are signed with the TEST list key (`asset_view::test_list_key`),
//! never a production key. Fixture-only: the endpoint is the shared lying
//! fixture (`common`), nothing proves.

mod common;

use std::collections::BTreeMap;

use common::*;
use qlab_air::l2p::CanonicalFreezeTree;
use qumbra_wallet::asset_view::{
    asset_view, render_amount, test_list_key, verify_asset_list, AssetLabel, AssetList, AssetMode, AssetRow,
    AssetView, Balances, FreezeStatus, ListKey, ListRefusal, ListStatus, ASSET_LIST_DOMAIN,
};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const REG: u16 = 2;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn lanes_hex(l: [u64; 4]) -> String {
    hex(&qlab_node::annulet_genesis::h32(&l))
}

/// A list for `genesis` naming USDT-test with `issuer`.
fn list_json(genesis: &[u8; 32], issuer: [u64; 4]) -> Vec<u8> {
    format!(
        r#"{{"v":1,"network":"annulet-ad1","genesis":"{}","assets":[{{"id":1,"issuer_key":"{}","name":"Tether USD (test)","ticker":"tUSDT","decimals":6,"testnet":true}}]}}"#,
        hex(genesis),
        lanes_hex(issuer)
    )
    .into_bytes()
}

fn signed(bytes: &[u8]) -> AssetList {
    verify_asset_list(bytes, &test_list_key::sign(bytes), &test_list_key::verifying()).expect("a test-signed list")
}

/// A wallet holding fee units, USDT-test and (when `regulated`) 50 of a
/// Regulated asset whose freeze list names address 0.
fn setup(tag: &str, seed: u8, regulated: bool, lie: Lie) -> (WalletDir, Endpoint) {
    let w = wallet_dir(tag, seed);
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let a0 = w.wallet().address_at_index(0);
    let rkm0 = w.wallet().rkm(w.wallet().diversifier_at_index(0));
    let (extra, notes) = if regulated {
        let leaf = qlab_air::l2::RegistryLeaf {
            asset: u64::from(REG),
            issuer_key: [5, 5, 5, 5],
            mode: qlab_air::l2::MODE_REGULATED,
            freeze_root: CanonicalFreezeTree::from_keys(&[rkm0]).root,
            allow_root: [0; 4],
            flags: 0,
        };
        (vec![leaf], vec![note_to(&a0, 50, u64::from(REG), 11)])
    } else {
        (Vec::new(), Vec::new())
    };
    let file = genesis_with(&a0, extra, notes);
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, lie);
    (w, ep)
}

fn view(w: &WalletDir, ep: &Endpoint, list: Option<&AssetList>, freeze: &BTreeMap<u16, Vec<[u64; 4]>>) -> AssetView {
    let pin = ep.file.hash();
    let v = run(w, ep, Some(pin)).expect("the endpoint's chain verifies");
    let mut fetch = |p: &str| ep.fetch(p);
    asset_view(w, &v, list, freeze, &mut fetch)
}

fn rows(v: &AssetView) -> &[AssetRow] {
    match &v.balances {
        Balances::Figures(rows) => rows,
        Balances::Unavailable { why } => panic!("expected figures, got UNAVAILABLE: {why}"),
    }
}

fn row(v: &AssetView, asset: u16) -> &AssetRow {
    rows(v).iter().find(|r| r.asset == asset).expect("a row for the asset")
}

#[test]
fn the_test_list_key_is_derived_and_pinned() {
    let k = test_list_key::verifying();
    assert_eq!(hex(&k.fingerprint()), test_list_key::ASSET_LIST_TEST_KEY_FINGERPRINT);
    assert_eq!(ASSET_LIST_DOMAIN, b"qumbra:asset-list:v1\0");
}

#[test]
fn a_list_verifies_only_under_its_key_and_only_unchanged() {
    let bytes = list_json(&[7; 32], [9, 9, 9, 9]);
    let sig = test_list_key::sign(&bytes);
    let list = verify_asset_list(&bytes, &sig, &test_list_key::verifying()).expect("verifies");
    assert_eq!(list.genesis, [7; 32]);
    assert_eq!(list.assets[&1].ticker, "tUSDT");
    assert_eq!(list.assets[&1].decimals, 6);
    assert!(list.assets[&1].testnet);
    assert_eq!(list.signer, test_list_key::verifying().fingerprint());

    let mut tampered = bytes.clone();
    let at = tampered.len() - 10;
    tampered[at] ^= 1;
    assert_eq!(verify_asset_list(&tampered, &sig, &test_list_key::verifying()).err(), Some(ListRefusal::BadSignature));

    // Another key: signature valid for its signer, refused under the list key.
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey};
    let other = SigningKey::<MlDsa65>::from_seed(&[0x33; 32].into());
    let mut msg = ASSET_LIST_DOMAIN.to_vec();
    msg.extend_from_slice(&bytes);
    let sig2: ml_dsa::Signature<MlDsa65> = other.sign(&msg);
    assert_eq!(
        verify_asset_list(&bytes, sig2.encode().as_slice(), &test_list_key::verifying()).err(),
        Some(ListRefusal::BadSignature)
    );
    let other_key = ListKey::from_encoded(other.verifying_key().encode().as_slice()).unwrap();
    assert!(verify_asset_list(&bytes, sig2.encode().as_slice(), &other_key).is_ok(), "valid under its own key");
    assert_eq!(verify_asset_list(&bytes, b"short", &test_list_key::verifying()).err(), Some(ListRefusal::BadSignature));
}

#[test]
fn a_malformed_list_is_refused_by_name() {
    let g = hex(&[7; 32]);
    let k = lanes_hex([9, 9, 9, 9]);
    let entry = |extra: &str| {
        format!(r#"{{"id":1,"issuer_key":"{k}","name":"N","ticker":"T","decimals":6,"testnet":false{extra}}}"#)
    };
    let cases: Vec<(String, &str)> = vec![
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[],"extra":1}}"#), "unknown key `extra`"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[{}]}}"#, entry(r#","url":"x""#)), "unknown key `url`"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[{}]}}"#, entry("").replace(r#""id":1"#, r#""id":0"#)), "asset 0"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[{},{}]}}"#, entry(""), entry("")), "strictly ascending"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[{}]}}"#, entry("").replace(r#""ticker":"T""#, r#""ticker":"T T""#)), "`ticker`"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{g}","assets":[{}]}}"#, entry("").replace(r#""decimals":6"#, r#""decimals":19"#)), "`decimals`"),
        (format!(r#"{{"v":1,"network":"n","genesis":"{}","assets":[]}}"#, g.to_uppercase()), "lowercase hex"),
    ];
    for (json, want) in cases {
        let b = json.into_bytes();
        match verify_asset_list(&b, &test_list_key::sign(&b), &test_list_key::verifying()).err() {
            Some(ListRefusal::Malformed { why }) => assert!(why.contains(want), "{want:?} not in {why:?}"),
            other => panic!("expected Malformed({want}), got {other:?}"),
        }
    }
    let v2 = format!(r#"{{"v":2,"network":"n","genesis":"{g}","assets":[]}}"#).into_bytes();
    assert_eq!(
        verify_asset_list(&v2, &test_list_key::sign(&v2), &test_list_key::verifying()).err(),
        Some(ListRefusal::UnknownVersion { got: 2 })
    );
}

#[test]
fn a_listed_testnet_asset_renders_by_name_in_its_decimals() {
    let (w, ep) = setup("listed", 0x61, false, Lie::None);
    let list = signed(&list_json(&ep.file.hash(), [9, 9, 9, 9]));
    let v = view(&w, &ep, Some(&list), &BTreeMap::new());
    assert_eq!(v.genesis_hash, ep.file.hash());
    assert_eq!((v.verified_tip, v.stated_tip), (3, Some(3)));
    assert!(!v.spends_verified, "lab #853 reaches the view model");
    assert_eq!(
        v.list,
        ListStatus::Listed { network: "annulet-ad1".into(), digest: list.digest, signer: test_list_key::verifying().fingerprint() }
    );
    let usdt = row(&v, USDT as u16);
    assert_eq!(usdt.label, AssetLabel::Listed { name: "Tether USD (test)".into(), ticker: "tUSDT".into() });
    assert_eq!(usdt.spendable.base_units, 1_000_407);
    assert_eq!(usdt.spendable.display, "1.000407");
    assert_eq!(usdt.spendable.unit, "tUSDT");
    assert!(usdt.testnet);
    assert_eq!(usdt.mode, AssetMode::Hybrid);
    assert_eq!(usdt.freeze, FreezeStatus::NoFreezeList);
    assert_eq!(usdt.leaf_problem, None);
    let fee = row(&v, 0);
    assert_eq!(fee.label, AssetLabel::FeeUnit);
    assert_eq!((fee.spendable.display.as_str(), fee.spendable.unit.as_str()), ("5", "fee units"));
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn an_issuer_the_list_does_not_pin_withholds_the_name_and_keeps_the_balance() {
    let (w, ep) = setup("issuer", 0x62, false, Lie::None);
    let list = signed(&list_json(&ep.file.hash(), [1, 1, 1, 1]));
    let v = view(&w, &ep, Some(&list), &BTreeMap::new());
    let usdt = row(&v, USDT as u16);
    assert_eq!(usdt.label, AssetLabel::IssuerChanged { listed_ticker: "tUSDT".into() });
    assert_eq!(usdt.spendable.display, "1,000,407", "raw base units: decimals are not trusted for this issuer");
    assert_eq!(usdt.spendable.unit, "base units of asset #1");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn without_this_networks_list_every_asset_is_unlisted() {
    let (w, ep) = setup("unlisted", 0x63, false, Lie::None);
    let v = view(&w, &ep, None, &BTreeMap::new());
    assert_eq!(v.list, ListStatus::NoList);
    assert_eq!(row(&v, USDT as u16).label, AssetLabel::Unlisted);
    assert_eq!(row(&v, USDT as u16).spendable.unit, "base units of asset #1");
    assert!(!row(&v, USDT as u16).testnet);

    let other = signed(&list_json(&[0xEE; 32], [9, 9, 9, 9]));
    let v = view(&w, &ep, Some(&other), &BTreeMap::new());
    assert_eq!(v.list, ListStatus::OtherNetwork { list_genesis: [0xEE; 32] });
    assert_eq!(row(&v, USDT as u16).label, AssetLabel::Unlisted, "another chain's list names nothing here");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_regulated_assets_freeze_list_is_checked_only_against_its_own_root() {
    let (w, ep) = setup("frozen", 0x64, true, Lie::None);
    let rkm0 = w.wallet().rkm(w.wallet().diversifier_at_index(0));
    let none = BTreeMap::new();
    let v = view(&w, &ep, None, &none);
    let reg = row(&v, REG);
    assert_eq!(reg.mode, AssetMode::Regulated);
    assert_eq!(reg.freeze, FreezeStatus::NotChecked, "a freeze root and no list: not checked, never 'not frozen'");

    let mut lists = BTreeMap::new();
    lists.insert(REG, vec![rkm0]);
    assert_eq!(row(&view(&w, &ep, None, &lists), REG).freeze, FreezeStatus::Frozen);

    lists.insert(REG, vec![[3, 3, 3, 3]]);
    assert_eq!(
        row(&view(&w, &ep, None, &lists), REG).freeze,
        FreezeStatus::NotChecked,
        "a list whose root is not the leaf's is not the list in force"
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn without_the_spends_there_is_no_figure_never_a_zero() {
    let (w, ep) = setup("unavailable", 0x65, false, Lie::NoNullifiers);
    let v = view(&w, &ep, None, &BTreeMap::new());
    assert!(matches!(v.balances, Balances::Unavailable { .. }), "{:?}", v.balances);
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_leaf_not_at_the_verified_tip_confirms_nothing() {
    let (w, ep) = setup("leaf", 0x66, false, Lie::RegistryLeaf);
    let list = signed(&list_json(&ep.file.hash(), [9, 9, 9, 9]));
    let v = view(&w, &ep, Some(&list), &BTreeMap::new());
    let usdt = row(&v, USDT as u16);
    assert_eq!(usdt.label, AssetLabel::Unconfirmed { listed_ticker: "tUSDT".into() });
    assert_eq!(usdt.mode, AssetMode::Unknown);
    assert_eq!(usdt.freeze, FreezeStatus::Unknown);
    assert_eq!(usdt.leaf_problem.as_deref(), Some("NotAtVerifiedTip"));
    assert_eq!(usdt.spendable.base_units, 1_000_407, "the balance stays: it is bound to the chain on its own");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn amounts_are_exact_integers_rendered_without_floats() {
    assert_eq!(render_amount(1_000_407, 6), "1.000407");
    assert_eq!(render_amount(123_456_789_000_000, 6), "123,456,789.000000");
    assert_eq!(render_amount(5, 0), "5");
}
