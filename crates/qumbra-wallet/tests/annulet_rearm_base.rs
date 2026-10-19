//! Gateway issue #197 Q2: **an issuer re-arms an asset's mint base in the
//! next generation before `open_next`**, so its first mint after the
//! rollover does not wait for the old generation's sweep gate. On a
//! format-34 test genesis (`L2AuthForm::CandidateAV3`) over the three-node
//! harness.
//!
//! A Candidate A mint spends a note of the asset from the **active**
//! generation (`AssetIndex::mint_base`). After `migrate --open-next` every
//! base sits in the now sweep-only generation, which moves only once its gate
//! (tip + 1,152) passes. The re-arm is a **zero-amount mint** to the next
//! generation's address 0 ([`next_generation_address`]): `VPublic::mint(0)`
//! is `VPublic::NONE`, so the P row carries no issuance term; it spends the
//! base and an exact P fee note and outputs `[0 of A → next generation,
//! base → this generation]`. Nothing new in the circuit or the builder: this
//! test is what shows the P circuit, the node's verifier and admission accept
//! it.
//!
//! - `W` issues Hybrid asset 7. Its generation 0 (active) holds the asset's
//!   zero-value base and an exact P fee note; its generation 1 address holds
//!   an exact P fee note (the pre-fund, issue #197 step 2). `W` re-arms (one
//!   P), runs `migrate --open-next` (no prove; generation 0's gate is in the
//!   future), and mints 5 to `T` from generation 1 at once (one P). The
//!   address the re-arm paid is the one `open_next` made active.
//! - `U` issues asset 8 with the same holdings and skips the re-arm: after
//!   `open_next` its mint is refused `NoIssuerNote` before anything is
//!   proved — the stall the re-arm removes.
//!
//! **Two P v3 proves** (the re-arm, the mint).

use std::time::Duration;

use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{issuer_key_of, CanonicalFreezeTree};
use qlab_devnet::forms::L2AuthForm;
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::devnet_harness::{Net, View};
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{SendRefusal, WalletEndpoint};
use qumbra_wallet::annulet_v2::{migrate, next_generation_address};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal, GenState, Generation};
use qumbra_wallet::issuer::{prepare_mint, IsskSource};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ASSET: u16 = 7;
const OTHER: u16 = 8;
const ISK_W: [u64; 4] = [0x197_0001, 0x197_0002, 0x197_0003, 0x197_0004];
const ISK_U: [u64; 4] = [0x197_0011, 0x197_0012, 0x197_0013, 0x197_0014];

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_g197_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

/// A note to `w`'s generation-`g` v2 address 0.
fn to_gen(w: &WalletDir, g: u32, value: u64, asset: u16, k: u64) -> L2Note {
    let wallet = w.wallet();
    let rkm = wallet.address_candidate_a_at_index(0, &generation_root(&wallet, g)).rkm_lanes();
    L2Note { value, asset: u64::from(asset), rkm, rho: [k, k + 1, k + 2, k + 3], rseed: [k + 4; 4] }
}

/// A Hybrid leaf (shape P, an empty canonical freeze tree) whose issuer key
/// is `isk`'s — the gateway's assets' mode.
fn hybrid(asset: u16, isk: &[u64; 4]) -> RegistryLeaf {
    RegistryLeaf {
        issuer_key: issuer_key_of(isk),
        mode: MODE_HYBRID,
        freeze_root: CanonicalFreezeTree::empty().root,
        ..RegistryLeaf::cloaked(u64::from(asset))
    }
}

/// A fresh journal: generation 0 active.
fn journal_0_active(w: &WalletDir) {
    let wallet = w.wallet();
    let gens = vec![Generation { g: 0, next: 0, auth_root: generation_root(&wallet, 0), state: GenState::Active }];
    AuthJournal::from_generations(gens).unwrap().save(&w.dir).unwrap();
}

/// The verified scan's index.
fn index(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32]) -> qlab_ledger::assets::AssetIndex {
    let mut rng = StdRng::seed_from_u64(0x197);
    let mut fetch = qumbra_wallet::net::verified_scan_fetch(url);
    let v = qumbra_wallet::annulet_verify::scan_annulet_verified(w, &mut fetch, 0, tip, Some(hash), &mut rng)
        .expect("the pinned format-34 chain verifies");
    v.report().index.clone().expect("both halves known")
}

fn supply(v: &View, asset: u16) -> i128 {
    v.supplies.iter().find(|(a, _)| *a == asset).map(|(_, s)| *s).unwrap_or(0)
}

#[test]
fn a_zero_amount_mint_re_arms_the_base_in_the_next_generation_before_open_next() {
    let (w, u, t) = (wallet("w", 0x71), wallet("u", 0x72), wallet("t", 0x73));
    let tier_p = devnet::FEE_TIER_P;
    let params = AnnuletParams {
        fee_tier_s: devnet::FEE_TIER_S,
        fee_tier_p: tier_p,
        fee_tier_r: devnet::FEE_TIER_R,
        slot_secs: 10,
        max_empty_slots: 6,
    };
    let notes = [
        to_gen(&w, 0, 0, ASSET, 10),  // W's base, in its active generation
        to_gen(&w, 0, tier_p, 0, 20), // the re-arm's fee
        to_gen(&w, 1, tier_p, 0, 30), // the pre-fund: the first mint's fee
        to_gen(&u, 0, 0, OTHER, 40),
        to_gen(&u, 1, tier_p, 0, 50),
    ];
    let g = AnnuletGenesisFile::assemble_with_auth(
        "annulet-g197-test",
        params,
        devnet::SEQUENCER_SEED,
        vec![
            RegistryLeafRecord::asset_zero(),
            RegistryLeafRecord::of(&hybrid(ASSET, &ISK_W)),
            RegistryLeafRecord::of(&hybrid(OTHER, &ISK_U)),
        ],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
        L2AuthForm::CandidateAV3,
    );
    assert_eq!((g.format_version, g.l2_auth().unwrap()), (34, L2AuthForm::CandidateAV3));
    let hash = g.hash();
    for d in [&w, &u, &t] {
        journal_0_active(d);
    }
    let net = Net::start(&g, "g197");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let ep = || WalletEndpoint { url: urls[1].clone() };
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(197);
    let v = net.settle_spends(0, "genesis");
    let t_addr = t.wallet().address_candidate_a_at_index(0, &generation_root(&t.wallet(), 0));

    // U: open_next without a re-arm — the mint has no base in generation 1
    // and is refused before anything is proved.
    let r = migrate(&u, ep(), v[1].state_tip, Some(hash), true, wait, &mut rng).expect("U opens generation 1");
    assert_eq!(r.active, 1);
    let stalled = prepare_mint(&u, ep(), OTHER, 5, &t_addr, &[], IsskSource::Given(ISK_U), v[1].state_tip, Some(hash), wait, &mut rng);
    assert!(
        matches!(stalled, Err(SendRefusal::NoIssuerNote { asset: OTHER })),
        "without a re-arm the base waits behind generation 0's gate: {:?}",
        stalled.err()
    );
    let v = net.settle_spends(0, "U proved nothing");

    // W: the next generation's address, read before it is opened.
    let (next_g, next_addr) = next_generation_address(&w).expect("W has a journal");
    assert_eq!(next_g, 1);

    // The re-arm: a zero-amount mint to that address — one P.
    let rearm = prepare_mint(&w, ep(), ASSET, 0, &next_addr, &[], IsskSource::Given(ISK_W), v[1].state_tip, Some(hash), wait, &mut rng)
        .expect("a zero-amount mint is built and proved")
        .submit()
        .expect("the node admits it");
    assert_eq!(rearm.outputs[0].value, 0);
    assert_eq!(rearm.outputs[0].rkm, next_addr.rkm_lanes(), "the zero note goes to the next generation's address 0");
    assert!(rearm.rearmed, "generation 0 keeps its own base too");
    let v = net.settle_spends(3, "the re-arm");
    assert_eq!(supply(&v[1], ASSET), 0, "a zero-amount mint issues nothing");
    let idx = index(&w, &urls[1], v[1].state_tip, hash);
    assert!(idx.only_generation(1).mint_base(ASSET).is_none(), "generation 1 is not in the journal yet");

    // open_next: no prove; generation 0's gate is tip + 1,152.
    let r = migrate(&w, ep(), v[1].state_tip, Some(hash), true, wait, &mut rng).expect("W opens generation 1");
    assert_eq!(r.active, 1);
    assert!(r.swept.is_empty() && r.carried.is_empty(), "{r:?}");
    let j = AuthJournal::load(&w.dir).unwrap().unwrap();
    assert!(matches!(j.get(0).unwrap().state, GenState::Sweep { .. }));
    let wallet = w.wallet();
    assert_eq!(
        wallet.address_candidate_a_at_index(0, &j.active().auth_root).rkm_lanes(),
        next_addr.rkm_lanes(),
        "the address the re-arm paid is the one open_next made active"
    );
    let v = net.settle_spends(3, "open_next moved nothing");
    let idx = index(&w, &urls[1], v[1].state_tip, hash);
    let base = idx.only_generation(1).mint_base(ASSET).cloned().expect("the re-armed base, now in the active generation");
    assert_eq!((base.note.value, base.generation), (0, Some(1)));

    // The first mint after the rollover, at once — one P, on generation 1's
    // base and its pre-funded fee note.
    let mint = prepare_mint(&w, ep(), ASSET, 5, &t_addr, &[], IsskSource::Given(ISK_W), v[1].state_tip, Some(hash), wait, &mut rng)
        .expect("the mint rides the re-armed base")
        .submit()
        .expect("the node admits it");
    assert_eq!(mint.outputs[0].value, 5);
    assert!(mint.rearmed);
    let v = net.settle_spends(6, "the mint");
    assert_eq!(supply(&v[1], ASSET), 5);
    let idx = index(&w, &urls[1], v[1].state_tip, hash);
    assert_eq!(
        idx.only_generation(1).mint_base(ASSET).map(|n| n.note.value),
        Some(0),
        "the mint returned the base to generation 1"
    );
    assert!(idx.only_generation(1).spendable(0).is_empty(), "the pre-fund paid the mint's fee");

    for d in [&w.dir, &u.dir, &t.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
