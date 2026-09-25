//! **A4's merge through the node** (design #283):
//! the wallet's own `plan_send` and `send_annulet` against B6's three-node
//! harness under the real `L2Verifier`, over a test genesis.
//!
//! Genesis for `W`: ten 10s of `USDT-m` (asset 2, Hybrid, empty freeze tree),
//! three 10s of `CLK` (asset 3, Cloaked), and asset-0 fee notes — two exact
//! P-tariff 2s, one 5 (= 2 + 2 + the S tier: one split, two fee notes), and
//! two exact S-tariff 1s.
//!
//! 1. **"10 × 10 → pay 50"** in `USDT-m` to `T`, through a follower. The plan:
//!    one fee-split (S, `d3 = 1`), three merges (P3, `d3 = 0`), one payment
//!    of two notes (P3, `d3 = 0`) — five transactions in three rounds, fee
//!    1 + 4 × 2 = 9. Outstanding `USDT-m` stays 100: a merge issues nothing.
//! 2. **"3 × 10 → pay 25"** in `CLK`: one merge (S3, `d3 = 0`), one payment
//!    of two notes (S3, `d3 = 0`), the held 1s paying — fee 2.
//! 3. `T` holds 50 and 25; `W` holds 50, 5 and no asset 0.
//!
//! 3 S + 4 P proves.

use std::time::Duration;

use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{issuer_key_of, CanonicalFreezeTree};
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::devnet_harness::{Net, View};
use qumbra_node::annulet_genesis::{AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet::scan_annulet;
use qumbra_wallet::annulet_send::{send_annulet, SendPlan, WalletEndpoint};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const USDT_M: u16 = 2;
const CLK: u16 = 3;

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_a4_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

fn rkm0(w: &WalletDir) -> [u64; 4] {
    w.wallet().address_at_index(0).rkm_lanes()
}

fn note(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: rkm0(w), rho: [0xA4, k, 1, 2], rseed: [0xA4, k, 3, 4] }
}

fn supply(v: &View, asset: u16) -> i128 {
    v.supplies.iter().find(|(a, _)| *a == asset).map(|(_, s)| *s).unwrap_or(0)
}

/// `w`'s spendable value of `asset` at `tip` (0 when it holds none).
fn balance(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32], asset: u16) -> u128 {
    let mut rng = StdRng::seed_from_u64(0xA4);
    let mut fetch = qumbra_wallet::net::scan_fetch(url);
    let report = scan_annulet(w, &mut fetch, 0, tip, Some(hash), &mut rng).expect("an Annulet endpoint with the pinned genesis");
    let balances = report.index.expect("both halves known").balances();
    balances.iter().find(|(a, _)| *a == asset).map(|(_, v)| *v).unwrap_or(0)
}

#[test]
fn ten_notes_of_ten_pay_fifty_through_the_node_after_three_merges() {
    let (w, t) = (wallet("w", 0x41), wallet("t", 0x42));
    let usdt_m = RegistryLeaf {
        asset: u64::from(USDT_M),
        issuer_key: issuer_key_of(&[0xA4; 4]),
        mode: MODE_HYBRID,
        freeze_root: CanonicalFreezeTree::empty().root,
        allow_root: [0; 4],
        flags: 0,
    };
    let mut notes: Vec<L2Note> = (0..10).map(|k| note(&w, 10, u64::from(USDT_M), k)).collect();
    notes.extend((0..3).map(|k| note(&w, 10, u64::from(CLK), 20 + k)));
    notes.extend([note(&w, 2, 0, 30), note(&w, 2, 0, 31), note(&w, 5, 0, 32), note(&w, 1, 0, 33), note(&w, 1, 0, 34)]);
    let g = AnnuletGenesisFile::assemble(
        "annulet-a4-merge-test",
        AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 4, slot_secs: 10, max_empty_slots: 6 },
        qumbra_node::annulet_genesis::devnet::SEQUENCER_SEED,
        vec![
            RegistryLeafRecord::asset_zero(),
            RegistryLeafRecord::of(&usdt_m),
            RegistryLeafRecord::of(&RegistryLeaf::cloaked(u64::from(CLK))),
        ],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
    );
    let hash = g.hash();
    let net = Net::start(&g, "a4");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(283);
    let v = net.settle_spends(0, "genesis");
    assert_eq!(supply(&v[0], USDT_M), 100, "genesis issuance: W's ten 10s");
    let t_addr = t.wallet().address_at_index(0);

    // 1. Ten 10s → pay 50 (P), through follower 1.
    let mut shown: Option<SendPlan> = None;
    let report = send_annulet(
        &w,
        WalletEndpoint { url: urls[1].clone() },
        USDT_M,
        50,
        &t_addr,
        v[1].state_tip,
        Some(hash),
        &[],
        wait,
        &mut |plan: &SendPlan| {
            eprintln!("{plan}");
            shown = Some(plan.clone());
            true
        },
        &mut rng,
    )
    .expect("10 × 10 → 50: split, merges, pay");
    let plan = shown.expect("the plan is shown before proving");
    assert_eq!(plan, report.plan, "the plan run is the plan shown");
    assert_eq!((plan.splits(), plan.merges(), plan.steps.len(), plan.rounds()), (1, 3, 5, 3), "{plan}");
    assert_eq!(plan.total_fee(), 1 + 4 * 2, "{plan}");
    assert_eq!(plan.steps[0].outputs, [2, 2], "the 5 splits into two exact P notes");
    assert_eq!(report.outputs[0].value, 50);
    // Five transactions × three nullifiers each (A4).
    let v = net.settle_spends(15, "10 × 10 → 50");
    assert!(v.iter().all(|x| supply(x, USDT_M) == 100), "a merge issues nothing: {v:?}");

    // 2. Three 10s of the Cloaked asset → pay 25 (S3 merge + S3 pay).
    let report = send_annulet(
        &w,
        WalletEndpoint { url: urls[2].clone() },
        CLK,
        25,
        &t_addr,
        v[2].state_tip,
        Some(hash),
        &[],
        wait,
        &mut |plan: &SendPlan| {
            eprintln!("{plan}");
            true
        },
        &mut rng,
    )
    .expect("3 × 10 → 25: merge, pay");
    assert_eq!((report.plan.splits(), report.plan.merges(), report.plan.rounds()), (0, 1, 2), "{}", report.plan);
    assert_eq!(report.plan.total_fee(), 2, "{}", report.plan);
    let v = net.settle_spends(21, "3 × 10 → 25");

    // 3. Final balances, each read through a different node.
    assert_eq!(balance(&t, &urls[2], v[2].state_tip, hash, USDT_M), 50);
    assert_eq!(balance(&t, &urls[0], v[0].state_tip, hash, CLK), 25);
    assert_eq!(balance(&w, &urls[1], v[1].state_tip, hash, USDT_M), 50, "five 10s untouched, the merges' 0 notes");
    assert_eq!(balance(&w, &urls[1], v[1].state_tip, hash, CLK), 5);
    assert_eq!(balance(&w, &urls[1], v[1].state_tip, hash, 0), 0, "11 of asset 0 in, 11 paid in fees");
    for d in [&w.dir, &t.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
