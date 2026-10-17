//! Lab #942: **`migrate` carries the issuer's seed** into the active
//! generation, on a format-34 test genesis (`L2AuthForm::CandidateAV3`) over
//! the three-node harness.
//!
//! Two issuers, each with a journal whose generation 0 is sweep-only (gate
//! passed on this net) and generation 1 active:
//! - `U` issues asset 8. Its generation 0 holds only the asset's zero-value
//!   seed, and its active generation holds nothing. `migrate` cannot fund
//!   the carry and says so by name (`carry_unfunded`, S + the S tariff).
//!   Generation 0 stays sweep-only and nothing is proved.
//! - `W` issues asset 7. Its generation 0 holds only the seed; its active
//!   generation holds 10 of asset 0. The first `migrate` pre-funds
//!   generation 0 from the active one (an S of exactly the tariff) and is
//!   given no time to see it in the served tree, so it stops there,
//!   `SplitNotIncluded`. The pre-fund lands anyway. The second `migrate`
//!   finds it in generation 0 and carries through (i):
//!   `[seed, pre-fund] → [0 of 7, 0 of 7]` to the active generation. A third
//!   `migrate` retires generation 0 and moves nothing.
//!
//! Throughout, asset 0 drops by exactly the two fees, and the net's
//! nullifier count rises by three per transaction, with nothing extra: no
//! note is spent twice. **Two S v3 proves** (the pre-fund and the carry).

use std::time::Duration;

use qlab_air::l2::RegistryLeaf;
use qlab_air::l2p::issuer_key_of;
use qlab_devnet::forms::L2AuthForm;
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{SendRefusal, WalletEndpoint};
use qumbra_wallet::annulet_v2::migrate;
use qumbra_wallet::auth_journal::{generation_root, AuthJournal, GenState, Generation, SweepGate};
use qumbra_wallet::issuer::IssuerFile;
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ASSET: u16 = 7;
const OTHER: u16 = 8;
const ISK_W: [u64; 4] = [0x942_0001, 0x942_0002, 0x942_0003, 0x942_0004];
const ISK_U: [u64; 4] = [0x942_0011, 0x942_0012, 0x942_0013, 0x942_0014];

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_942_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

/// A note to `w`'s generation-`g` v2 address 0.
fn to_gen(w: &WalletDir, g: u32, value: u64, asset: u16, k: u64) -> L2Note {
    let wallet = w.wallet();
    let rkm = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, g)).rkm_lanes();
    L2Note { value, asset: u64::from(asset), rkm, rho: [k, k + 1, k + 2, k + 3], rseed: [k + 4; 4] }
}

/// A Cloaked leaf (shape S) whose issuer key is `isk`'s.
fn issued(asset: u16, isk: &[u64; 4]) -> RegistryLeaf {
    RegistryLeaf { issuer_key: issuer_key_of(isk), ..RegistryLeaf::cloaked(u64::from(asset)) }
}

/// Generation 0 sweep-only with its gate passed on `genesis`, generation 1
/// active.
fn journal_0_sweep_1_active(w: &WalletDir, genesis: [u8; 32]) {
    let wallet = w.wallet();
    let gens = vec![
        Generation {
            g: 0,
            next: 0,
            auth_root: generation_root(&wallet, 0),
            state: GenState::Sweep { gates: vec![SweepGate { genesis, not_before_height: 0 }] },
        },
        Generation { g: 1, next: 0, auth_root: generation_root(&wallet, 1), state: GenState::Active },
    ];
    AuthJournal::from_generations(gens).unwrap().save(&w.dir).unwrap();
}

/// The verified scan's index.
fn index(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32]) -> qlab_ledger::assets::AssetIndex {
    let mut rng = StdRng::seed_from_u64(0x942);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let v = qumbra_wallet::annulet_verify::scan_annulet_verified(w, &mut fetch, 0, tip, Some(hash), &mut rng)
        .expect("the pinned format-34 chain verifies");
    v.report().index.clone().expect("both halves known")
}

fn values(index: &qlab_ledger::assets::AssetIndex, asset: u16) -> Vec<u64> {
    let mut v: Vec<u64> = index.spendable(asset).iter().map(|n| n.note.value).collect();
    v.sort_unstable();
    v
}

#[test]
fn migrate_carries_an_issuer_seed_and_completes_a_carry_whose_pre_fund_landed() {
    let (w, u) = (wallet("w", 0x61), wallet("u", 0x62));
    IssuerFile::add(&w.dir, ASSET, ISK_W).unwrap();
    IssuerFile::add(&u.dir, OTHER, ISK_U).unwrap();
    let tier_s = devnet::FEE_TIER_S;
    let params = AnnuletParams {
        fee_tier_s: tier_s,
        fee_tier_p: devnet::FEE_TIER_P,
        fee_tier_r: devnet::FEE_TIER_R,
        slot_secs: 10,
        max_empty_slots: 6,
    };
    let notes = [
        to_gen(&w, 0, 0, ASSET, 10), // W's seed, in its sweep-only generation
        to_gen(&w, 1, 10, 0, 20),    // W's active funds
        to_gen(&u, 0, 0, OTHER, 30), // U's seed; U's active generation holds nothing
    ];
    let g = AnnuletGenesisFile::assemble_with_auth(
        "annulet-942-test",
        params,
        devnet::SEQUENCER_SEED,
        vec![
            RegistryLeafRecord::asset_zero(),
            RegistryLeafRecord::of(&issued(ASSET, &ISK_W)),
            RegistryLeafRecord::of(&issued(OTHER, &ISK_U)),
        ],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
        L2AuthForm::CandidateAV3,
    );
    assert_eq!((g.format_version, g.l2_auth().unwrap()), (34, L2AuthForm::CandidateAV3));
    let hash = g.hash();
    for d in [&w, &u] {
        journal_0_sweep_1_active(d, hash);
    }
    let net = Net::start(&g, "g942");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let ep = || WalletEndpoint { url: urls[1].clone() };
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(942);
    let v = net.settle_spends(0, "genesis");

    // U: nothing in the active generation pays the carry. Reported by name;
    // generation 0 stays sweep-only; nothing is proved or submitted.
    let r = migrate(&u, ep(), v[1].state_tip, Some(hash), false, wait, &mut rng).expect("U's migrate");
    assert_eq!(r.carry_unfunded, vec![(0, OTHER, tier_s + tier_s)], "S + the S tariff, named");
    assert!(r.carried.is_empty() && r.retired.is_empty() && r.swept.is_empty(), "{r:?}");
    let j = AuthJournal::load(&u.dir).unwrap().unwrap();
    assert!(matches!(j.get(0).unwrap().state, GenState::Sweep { .. }), "U's generation 0 stays sweep-only");
    let v = net.settle_spends(0, "U: nothing moved");

    // W, first run: the pre-fund is submitted, and the run is given no time
    // to see it in the served tree — it stops there, before the carry.
    let first = migrate(&w, ep(), v[1].state_tip, Some(hash), false, Duration::ZERO, &mut rng);
    assert!(matches!(first, Err(SendRefusal::SplitNotIncluded { .. })), "{:?}", first.map(|_| ()));
    let v = net.settle_spends(3, "the pre-fund lands anyway");
    let idx = index(&w, &urls[1], v[1].state_tip, hash);
    assert_eq!(values(&idx.only_generation(0), 0), vec![tier_s], "generation 0 holds exactly the tariff");
    assert_eq!(values(&idx.only_generation(1), 0), vec![10 - 2 * tier_s], "the active change: 10 − tariff − S");

    // W, second run: (i) from the pre-fund — the carry, one S.
    let r = migrate(&w, ep(), v[1].state_tip, Some(hash), false, wait, &mut rng).expect("W's second migrate");
    assert_eq!(r.carried, vec![(0, ASSET)]);
    assert_eq!(r.swept, vec![(0, 1)], "one transaction: the carry, no split");
    assert!(r.carry_unfunded.is_empty() && r.carry_next.is_empty() && r.retired.is_empty(), "{r:?}");
    assert!(r.asset0_left.is_empty(), "the pre-fund was its only asset-0 note, and the fee took it");
    let v = net.settle_spends(6, "the carry");
    let idx = index(&w, &urls[1], v[1].state_tip, hash);
    let base = idx.only_generation(1).mint_base(ASSET).cloned().expect("a mint base of asset 7 in the active generation");
    assert_eq!((base.note.value, base.generation), (0, Some(1)));
    let old = idx.only_generation(0);
    assert!(old.mint_base(ASSET).is_none() && old.spendable(0).is_empty(), "generation 0 holds nothing now");
    assert_eq!(values(&idx, 0), vec![10 - 2 * tier_s], "asset 0 dropped by exactly the two fees");

    // W, third run: nothing left to carry or sweep — generation 0 retires,
    // nothing is proved, and the nullifier count does not move.
    let r = migrate(&w, ep(), v[1].state_tip, Some(hash), false, wait, &mut rng).expect("W's third migrate");
    assert_eq!(r.retired, vec![0]);
    assert!(r.carried.is_empty() && r.swept.is_empty(), "{r:?}");
    let j = AuthJournal::load(&w.dir).unwrap().unwrap();
    assert_eq!(j.get(0).unwrap().state, GenState::Retired);
    net.settle_spends(6, "nothing spent twice");

    for d in [&w.dir, &u.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
