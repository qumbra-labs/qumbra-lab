//! **The verified scan with explicit authorization generations** (lab #896;
//! macOS #60 D2 — the Rust-API twin of `qmb_annulet_new_v2`).
//!
//! (a) On a **format-33** fixture chain, `scan_annulet_verified_with_generations`
//!     finds the genesis note and a block note paid to the wallet's v2
//!     generation-0 address under `[(0, root0)]`, and none under `[(1, root1)]`;
//!     the verified scan reports the net as Candidate A.
//! (b) On the v1 fixture chain, the old `scan_annulet_verified` and the new one
//!     with an empty list give the same figures, the same range and the same
//!     body cost; the net reads as v1.
//!
//! Fixture seeds only; nothing proves.

mod common;

use common::*;
use qlab_devnet::body::BlockBody;
use qlab_devnet::forms::L2AuthForm;
use qumbra_wallet::annulet_verify::{scan_annulet_verified, scan_annulet_verified_with_generations};
use qumbra_wallet::auth_journal::generation_root;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn a_the_generations_scan_finds_the_v2_notes_under_generation_0_only() {
    const SEED: u8 = 0x60;
    let w = wallet_dir("v2scan_a", SEED);
    let wallet = w.wallet();
    let (root0, root1) = (generation_root(&wallet, 0), generation_root(&wallet, 1));
    let a2 = wallet.address_candidate_a_at_index(0, &root0);
    let mut rng = StdRng::seed_from_u64(0x60);
    let body = BlockBody { txs: vec![pay_tx(&a2, &[note_to(&a2, 5, 0, 20)], 0x30, &mut rng)], ..BlockBody::default() };
    let file = genesis_v2(&a2, Vec::new());
    assert_eq!(file.format_version, qlab_devnet::forms::ANNULET_AUTH_GENESIS_FORMAT_VERSION);
    let pin = file.hash();
    let ep = Endpoint::new(file, &[body], None, Lie::None);
    let mut fetch = |p: &str| ep.fetch(p);

    let v = scan_annulet_verified_with_generations(&w, &mut fetch, 0, u64::MAX, Some(pin), &[(0, root0)], &mut rng)
        .expect("the format-33 chain verifies");
    assert_eq!(v.l2_auth(), L2AuthForm::CandidateA, "format 33 reads as Candidate A");
    assert_eq!(v.l2_auth(), v.chain().genesis.l2_auth);
    let index = v.report().index.clone().expect("both halves known");
    assert_eq!(index.balances(), vec![(0, 5), (USDT as u16, 1_000_000)], "the genesis note and the block note");

    let w1 = wallet_dir("v2scan_a1", SEED);
    let other = scan_annulet_verified_with_generations(&w1, &mut fetch, 0, u64::MAX, Some(pin), &[(1, root1)], &mut rng)
        .expect("still verifies");
    let index = other.report().index.clone().expect("both halves known");
    assert!(index.balances().is_empty(), "generation 1 owns none of them: {:?}", index.balances());
    for d in [w.dir, w1.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn b_on_a_v1_net_the_empty_list_is_the_old_scan() {
    const SEED: u8 = 0x61;
    let (w_old, w_new) = (wallet_dir("v2scan_b_old", SEED), wallet_dir("v2scan_b_new", SEED));
    let mut rng = StdRng::seed_from_u64(0x61);
    let file = genesis(&w_old.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w_old, &mut rng), None, Lie::None);
    let mut fetch = |p: &str| ep.fetch(p);

    let old = scan_annulet_verified(&w_old, &mut fetch, 0, u64::MAX, Some(pin), &mut StdRng::seed_from_u64(7))
        .expect("the v1 chain verifies");
    let new = scan_annulet_verified_with_generations(&w_new, &mut fetch, 0, u64::MAX, Some(pin), &[], &mut StdRng::seed_from_u64(7))
        .expect("the v1 chain verifies");
    assert_eq!(old.l2_auth(), L2AuthForm::None, "format 32 reads as v1");
    assert_eq!(new.l2_auth(), L2AuthForm::None);
    assert_eq!(old.report().index.clone().unwrap().balances(), new.report().index.clone().unwrap().balances());
    assert_eq!(old.report().index.clone().unwrap().balances(), vec![(0, 5), (USDT as u16, 1_000_407)]);
    assert_eq!((old.range(), old.body_cost()), (new.range(), new.body_cost()));
    assert_eq!(old.chain().tip(), new.chain().tip());
    for d in [w_old.dir, w_new.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Lab #937 PR C: a format-34 genesis (three-output S/P) **verifies** in
/// the wallet — its CLI scans and builds format 34 now — and names its axis;
/// the kernel (`qumbra-ffi`) still refuses it by name until PR D
/// (`VerifyRefusal::FormatNotSupported`, raised by the kernel after its scan).
#[test]
fn z_a_format_34_genesis_verifies_in_the_wallet() {
    use qumbra_wallet::annulet_verify::genesis_from_bytes;
    let w = wallet_dir("v2scan_z34", 0x61);
    let wallet = w.wallet();
    let holder = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0));
    let v2 = genesis_v2(&holder, Vec::new());
    let v3 = qlab_node::annulet_genesis::AnnuletGenesisFile::assemble_with_auth(
        "annulet-ad1-v3",
        v2.params,
        SEQ_SEED,
        v2.registry_genesis.clone(),
        v2.genesis_notes.clone(),
        0,
        L2AuthForm::CandidateAV3,
    );
    assert_eq!(v3.format_version, 34);
    let g = genesis_from_bytes(v3.hash(), &v3.to_bytes()).expect("format 34 verifies in the wallet");
    assert_eq!(g.l2_auth, L2AuthForm::CandidateAV3);
    assert_eq!(g.wire(), qlab_p2p::compact::WireForm::ANNULET_AUTH_V3);
    assert!(genesis_from_bytes(v2.hash(), &v2.to_bytes()).is_ok(), "format 33 still verifies");
}
