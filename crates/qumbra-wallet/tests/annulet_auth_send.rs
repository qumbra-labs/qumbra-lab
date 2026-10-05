//! Lab #896 seam G: **a Candidate A send end to end** — the integration lock
//! seam F could not have: a **real v2 proof**, the wallet's **real ML-DSA
//! signatures** over the intent the node rebuilds, the node's **real
//! `L2VerifierV2`** and `check_auth`, admission through `POST /v1/tx` on a
//! follower, and the block **sealed** and applied on three nodes.
//!
//! A format-33 test genesis (`assemble_with_auth`, `L2AuthForm::CandidateA`)
//! registers a Cloaked asset 7 and pays wallet `W`'s generation-0 v2 address
//! two asset-7 notes (60, 50) and one exact S-tariff asset-0 fee note — no
//! faucet. `W` (a fresh journal at generation 0) sends 100 of asset 7 to `T`'s
//! v2 address through a follower: no single note covers it, so the plan is one
//! S with both asset-7 notes and the fee note in slot 3 (`FeeIn::Exact`, the
//! v2 builder path E4's round trips leave to here). **One S prove.**
//!
//! Then the served Candidate A body is read back: the transaction's own auth
//! section gives the landed leaves, and `landed_next` over them is the cursor
//! position `W`'s journal recorded — the input of a restore's sweep floor,
//! checked against a real body. Two no-prove locks ride along: a version-1
//! recipient on this net is refused by name before any planning, and
//! `migrate --open-next` afterwards opens generation 1 and leaves generation
//! 0 waiting on this net until tip + 1,152.
use std::time::Duration;

use qlab_air::l2::RegistryLeaf;
use qlab_devnet::forms::L2AuthForm;
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{open_session, send_annulet, SendPlan, SendRefusal, WalletEndpoint};
use qumbra_wallet::annulet_v2::{landed_next, landed_slots, migrate};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ASSET: u16 = 7;

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_g_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

/// A note to `w`'s generation-0 v2 address 0.
fn to_w(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    let wallet = w.wallet();
    let rkm = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, 0)).rkm_lanes();
    L2Note { value, asset, rkm, rho: [k, k + 1, k + 2, k + 3], rseed: [k + 4; 4] }
}

/// The verified scan's per-asset balances (a Candidate A scan: owned under
/// the journal's generations).
fn balances(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32]) -> Vec<(u16, u128)> {
    let mut rng = StdRng::seed_from_u64(0x896);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let v = qumbra_wallet::annulet_verify::scan_annulet_verified(w, &mut fetch, 0, tip, Some(hash), &mut rng)
        .expect("the pinned format-33 chain verifies");
    v.report().index.as_ref().expect("both halves known").balances()
}

#[test]
fn a_candidate_a_send_is_proved_signed_admitted_and_sealed() {
    let w = wallet("w", 0x41);
    let t = wallet("t", 0x42);
    // Fresh wallets: generation 0 active (what `migrate` sets up for a wallet
    // with no notes yet).
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
        "annulet-g-test",
        params,
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero(), RegistryLeafRecord::of(&RegistryLeaf::cloaked(ASSET as u64))],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
        L2AuthForm::CandidateA,
    );
    assert_eq!(g.l2_auth().unwrap(), L2AuthForm::CandidateA, "format 33");
    let hash = g.hash();
    let net = Net::start(&g, "g896");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    assert_eq!(balances(&w, &urls[1], 0, hash), vec![(0, tier_s as u128), (ASSET, 110)]);

    // A version-1 recipient on this format-33 net is refused by name, before
    // anything is planned or proved.
    let mut rng = StdRng::seed_from_u64(896);
    let refused = send_annulet(
        &w,
        WalletEndpoint { url: urls[1].clone() },
        ASSET,
        100,
        &t.wallet().address_at_index(0),
        0,
        Some(hash),
        &[],
        Duration::from_secs(60),
        &mut |_: &SendPlan| panic!("no plan for a v1 recipient"),
        &mut rng,
    );
    assert!(
        matches!(&refused, Err(SendRefusal::Auth(why)) if why.contains("version 1") && why.contains("new address")),
        "{:?}",
        refused.err().map(|e| e.to_string())
    );

    // W sends 100 of asset 7 to T's v2 address through follower 1.
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
    .expect("the Candidate A send: one S, both notes and the exact fee note");
    assert_eq!(report.plan.steps.len(), 1, "one transaction: {}", report.plan);
    assert_eq!((report.plan.splits(), report.plan.merges()), (0, 0));
    assert_eq!((report.outputs[0].value, report.outputs[1].value), (100, 10));
    let v = net.settle_spends(3, "the Candidate A send");

    // The journal took exactly the three real slots, persisted.
    let journal = AuthJournal::load(&w.dir).unwrap().expect("W's journal");
    assert_eq!(journal.active().g, 0);
    assert_eq!(journal.get(0).unwrap().next, 3, "two asset-7 inputs and the fee note");

    // T finds 100 under its own generation 0; W's change is 10.
    assert_eq!(balances(&t, &urls[2], v[2].state_tip, hash), vec![(ASSET, 100)]);
    assert_eq!(balances(&w, &urls[1], v[1].state_tip, hash), vec![(0, 0), (ASSET, 10)]);

    // The served Candidate A body — bound to the verified header — carries
    // the transaction's auth section: its real leaves give back the journal's
    // position.
    let session = open_session(&w, WalletEndpoint { url: urls[1].clone() }, v[1].state_tip, Some(hash), &mut rng)
        .expect("a verified session");
    let wallet = w.wallet();
    let root0 = generation_root(&wallet, 0);
    let spent: Vec<_> = notes
        .iter()
        .map(|n| {
            let owned = qlab_ledger::assets::OwnedL2Note::from_genesis_v2(&wallet, 0, qumbra_node::annulet_genesis::h32(&n.commitment()), *n, &[(0, root0)])
                .expect("W's genesis note");
            (owned, v[1].state_tip)
        })
        .collect();
    let slots = landed_slots(&session, &wallet, &spent).expect("the landed body reads back, verified");
    assert_eq!(slots.len(), 3, "one S: three slots");
    assert_eq!(landed_next(&wallet, 0, &slots), 3, "the restore floor is the journal's position");

    // `migrate --open-next` on this net: generation 1 opens, generation 0
    // (holding the change) waits until tip + 1,152 — nothing is proved.
    let tip = v[1].state_tip;
    let report = migrate(
        &w,
        WalletEndpoint { url: urls[1].clone() },
        tip,
        Some(hash),
        true,
        Duration::from_secs(60),
        &mut rng,
    )
    .expect("migrate --open-next");
    assert_eq!(report.active, 1);
    // The gate is an upper bound on the real tip at this moment: the
    // harness may have sealed empty slot blocks since `tip` was read.
    assert_eq!(report.waiting.len(), 1, "{:?}", report.waiting);
    assert_eq!(report.waiting[0].0, 0);
    assert!(report.waiting[0].1 >= tip + qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS, "{:?}", report.waiting);
    assert!(report.swept.is_empty() && report.retired.is_empty());
    let journal = AuthJournal::load(&w.dir).unwrap().unwrap();
    assert_eq!(journal.active().g, 1);
    assert_eq!(journal.get(0).unwrap().next, 3, "generation 0 consumed nothing more");

    for d in [&w.dir, &t.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
