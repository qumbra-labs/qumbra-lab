//! Lab #937 PR C: **a format-34 send end to end** — the three-output twin of
//! `annulet_auth_send`'s Candidate A send. A format-34 genesis
//! (`L2AuthForm::CandidateAV3`) pays wallet `W`'s generation-0 v2 address two
//! asset-7 notes (60, 50) and one exact S-tariff fee note; `W` sends 100 of
//! asset 7 to `T` through a follower. The plan is the format-33 one (one S,
//! both asset-7 notes, the fee note in slot 3 — the **TwoAndFee** layout,
//! no asset-0 balance row); the builder adds the third output — a
//! zero-value note to `W`'s change address, of asset 7 because no row is
//! asset 0 (`zero_third_asset`; beside an asset-0 row it is asset 0) — the bundle's
//! lock runs under the format-34 context, the proof is a **v3** S proof, and
//! three nodes running the **real `L2VerifierV3`** admit, seal and apply it.
//! **One S v3 prove.**

use std::time::Duration;

use qlab_air::l2::RegistryLeaf;
use qlab_devnet::forms::L2AuthForm;
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{send_annulet, SendPlan, WalletEndpoint};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ASSET: u16 = 7;

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_937_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

/// A note to `w`'s generation-0 v2 address 0.
fn to_w(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    let wallet = w.wallet();
    let rkm = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0)).rkm_lanes();
    L2Note { value, asset, rkm, rho: [k, k + 1, k + 2, k + 3], rseed: [k + 4; 4] }
}

fn balances(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32]) -> Vec<(u16, u128)> {
    let mut rng = StdRng::seed_from_u64(0x937);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let v = qumbra_wallet::annulet_verify::scan_annulet_verified(w, &mut fetch, 0, tip, Some(hash), &mut rng)
        .expect("the pinned format-34 chain verifies");
    v.report().index.as_ref().expect("both halves known").balances()
}

#[test]
fn a_format_34_send_carries_three_outputs_and_is_sealed_by_the_v3_verifier() {
    let w = wallet("w", 0x51);
    let t = wallet("t", 0x52);
    for d in [&w, &t] {
        AuthJournal::fresh(generation_root(&d.wallet(), 0)).save(&d.dir).unwrap();
    }
    let tier_s = devnet::FEE_TIER_S;
    let params = AnnuletParams {
        fee_tier_s: tier_s,
        fee_tier_p: devnet::FEE_TIER_P,
        fee_tier_r: devnet::FEE_TIER_R,
        slot_secs: 10,
        max_empty_slots: 6,
    };
    let notes = [to_w(&w, 60, ASSET as u64, 10), to_w(&w, 50, ASSET as u64, 20), to_w(&w, tier_s, 0, 30)];
    let g = AnnuletGenesisFile::assemble_with_auth(
        "annulet-937-test",
        params,
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero(), RegistryLeafRecord::of(&RegistryLeaf::cloaked(ASSET as u64))],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
        L2AuthForm::CandidateAV3,
    );
    assert_eq!((g.format_version, g.l2_auth().unwrap()), (34, L2AuthForm::CandidateAV3));
    let hash = g.hash();
    let net = Net::start(&g, "g937");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    assert_eq!(balances(&w, &urls[1], 0, hash), vec![(0, tier_s as u128), (ASSET, 110)]);

    let mut rng = StdRng::seed_from_u64(937);
    let t_addr = t.wallet().address_candidate_a_at_index(0, &generation_root(&t.wallet(), 0));
    let report = send_annulet(
        &w,
        WalletEndpoint { url: urls[1].clone() },
        ASSET,
        100,
        &t_addr,
        0,
        Some(hash),
        &[],
        Duration::from_secs(60),
        &mut |plan: &SendPlan| {
            eprintln!("{plan}");
            true
        },
        &mut rng,
    )
    .expect("the format-34 send: one S v3, both notes, the exact fee note, a zero-value third output");
    assert_eq!(report.plan.steps.len(), 1, "one transaction: {}", report.plan);
    assert_eq!(report.plan.steps[0].third, None, "the planner leaves the third output to the builder");
    assert_eq!((report.outputs[0].value, report.outputs[1].value), (100, 10));
    let v = net.settle_spends(3, "the format-34 send");

    // W's own verified scan finds the zero-value third output beside its
    // change: the three-output transaction landed, and the wallet scans it.
    let mut scan_rng = StdRng::seed_from_u64(0x9370);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(&urls[1]);
    let scanned =
        qumbra_wallet::annulet_verify::scan_annulet_verified(&w, &mut fetch, 0, v[1].state_tip, Some(hash), &mut scan_rng)
            .expect("the pinned format-34 chain verifies");
    let index = scanned.report().index.as_ref().expect("both halves known");
    let values: Vec<u64> = index.spendable(ASSET).iter().map(|n| n.note.value).collect();
    assert_eq!(values, vec![10], "only the change is spendable");
    // The zero-value third output is seen, not spendable: it went to the
    // change address and is held apart from every spendable row.
    // TwoAndFee (A₁ = A₂ = 7, the fee in slot 3): no asset-0 row, so the
    // zero-value third output is asset 7 (`zero_third_asset(7, 7)`).
    assert_eq!(qumbra_wallet::annulet_v2::zero_third_asset(ASSET as u64, ASSET as u64), ASSET as u64);
    assert_eq!(index.zero.len(), 1, "one zero-value note: the third output");
    let zero: Vec<_> = index.zero.iter().filter(|n| n.note.asset == ASSET as u64).collect();
    assert_eq!(zero.len(), 1, "the third output is seen, asset 7");
    assert_eq!(zero[0].note.value, 0);
    assert_eq!(zero[0].note.rkm, report.outputs[1].rkm, "the third output went to the change address");
    assert_ne!(zero[0].note.commitment(), report.outputs[1].commitment(), "the third output is its own note");

    // T finds 100; W's change is 10 — the zero-value third output adds nothing.
    assert_eq!(balances(&t, &urls[2], v[2].state_tip, hash), vec![(ASSET, 100)]);
    assert_eq!(balances(&w, &urls[1], v[1].state_tip, hash), vec![(0, 0), (ASSET, 10)]);
}
