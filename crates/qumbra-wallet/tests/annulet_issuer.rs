//! **C3's done-when** (lab #722): the issuer verbs on B6's three-node
//! harness, over a C3 **test** genesis (a fixture, not the devnet pin), with
//! B4's outstanding supply checked on all three nodes at every step.
//!
//! The genesis carries `USDT-c3` (asset 2, Hybrid, redeem closed) whose
//! issuer key is a test `isk` and whose **freeze tree is canonical and
//! genesis-static, holding one holder `F`'s key** — registry updates (a new
//! root) need A2/C4, so a freeze in force today is one the genesis carries.
//! Genesis notes: a 0-value `USDT-c3` note for the issuer to mint on (P3), fee
//! notes of the P tariff, and `F`'s own `USDT-c3`.
//!
//! 1. **mint**: the issuer mints 1,000 to holder `H` (P, vPublic +1,000, AISS).
//!    Supply 1,000.
//! 2. **transfer**: `H` sends 400 to the issuer with C2's send, through a
//!    follower, the published freeze list in hand. Supply unchanged.
//! 3. **frozen**: `F`'s send is refused by the wallet **before proving**; a
//!    spend `F` hand-forges against the pre-freeze (empty) leaf proves, and is
//!    **refused by the node**. Nothing changes on chain.
//! 4. **redeem**: the issuer redeems 150 (P, vPublic −150). Supply 850.
//!
//! 4 P proves (≈ 80 s).

use std::time::Duration;

use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{dummy_allow_witness, freeze_key_of, issuer_key_of, CanonicalFreezeTree, L2PolicyInput, VPublic};
use qlab_l2spend::{prove_p_with_policies, Out, Recipient, SpendError};
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::annulet::served;
use qumbra_faucet::devnet_harness::{Net, View};
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{send_annulet, SendRefusal, WalletEndpoint};
use qumbra_wallet::issuer::{issuer_mint, redeem, IssuerFile};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ASSET: u16 = 2;
const ISK: [u64; 4] = [0xC315_0001, 0xC315_0002, 0xC315_0003, 0xC315_0004];

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_c3_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

fn rkm0(w: &WalletDir) -> [u64; 4] {
    w.wallet().address_at_index(0).rkm_lanes()
}

fn note(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: rkm0(w), rho: [0xC3, k, 1, 2], rseed: [0xC3, k, 3, 4] }
}

fn supply(v: &View) -> i128 {
    v.supplies.iter().find(|(a, _)| *a == ASSET).map(|(_, s)| *s).unwrap_or(0)
}

#[test]
fn mint_transfer_frozen_refused_redeem_with_the_supply_ledger_matching() {
    let (issuer, h, f) = (wallet("issuer", 0x31), wallet("h", 0x32), wallet("f", 0x33));
    IssuerFile::add(&issuer.dir, ASSET, ISK).unwrap();

    // The C3 test genesis.
    let freeze = CanonicalFreezeTree::from_rkms(&[rkm0(&f)]);
    let usdt_c3 = RegistryLeaf {
        asset: u64::from(ASSET),
        issuer_key: issuer_key_of(&ISK),
        mode: MODE_HYBRID,
        freeze_root: freeze.root,
        allow_root: [0; 4],
        flags: 0,
    };
    let notes = [
        note(&issuer, 0, u64::from(ASSET), 1), // P3: the note a mint rides
        note(&issuer, 2, 0, 2),
        note(&issuer, 2, 0, 3),
        note(&h, 2, 0, 4),
        note(&f, 50, u64::from(ASSET), 5),
        note(&f, 2, 0, 6),
    ];
    let g = AnnuletGenesisFile::assemble(
        "annulet-c3-test",
        AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, slot_secs: 10, max_empty_slots: 6 },
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero(), RegistryLeafRecord::of(&usdt_c3)],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
    );
    let hash = g.hash();
    let net = Net::start(&g, "c3");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let keys = freeze.keys.clone(); // the issuer's published list
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(722);
    let v = net.settle_spends(0, "genesis");
    assert_eq!(supply(&v[0]), 0, "genesis notes are not public issuance");

    // 1. Mint 1,000 to H.
    let to_h = h.wallet().address_at_index(0);
    issuer_mint(&issuer, WalletEndpoint { url: urls[0].clone() }, ASSET, 1_000, &to_h, &keys, v[0].state_tip, Some(hash), wait, &mut rng)
        .expect("the issuer mints");
    let v = net.settle_spends(2, "the mint");
    assert!(v.iter().all(|x| supply(x) == 1_000), "supply = minted, on all three: {v:?}");

    // 2. H sends 400 to the issuer (C2's send, through follower 1).
    let to_issuer = issuer.wallet().address_at_index(0);
    send_annulet(&h, WalletEndpoint { url: urls[1].clone() }, ASSET, 400, &to_issuer, v[1].state_tip, Some(hash), &keys, wait, &mut rng)
        .expect("an unfrozen holder transfers");
    let v = net.settle_spends(4, "the transfer");
    assert!(v.iter().all(|x| supply(x) == 1_000), "a transfer issues nothing: {v:?}");

    // 3a. F is frozen: its wallet refuses before proving.
    let refused = send_annulet(&f, WalletEndpoint { url: urls[2].clone() }, ASSET, 10, &to_h, v[2].state_tip, Some(hash), &keys, wait, &mut rng);
    assert!(
        matches!(refused, Err(SendRefusal::Spend(SpendError::Frozen { asset: 2 }))),
        "the frozen holder is refused by its own wallet: {:?}",
        refused.err()
    );
    // 3b. F hand-forges a spend against the PRE-freeze leaf (an empty freeze
    //     tree): it proves, under a registry root no node holds — refused.
    let seq = served(net.served[0]);
    let real = seq.registry(u64::from(ASSET)).unwrap();
    let forged_leaf = RegistryLeaf { freeze_root: CanonicalFreezeTree::empty().root, ..real.leaf };
    let forged_root = real.witness.fold_root(&forged_leaf.hash());
    let zero = seq.registry(0).unwrap();
    let fw = f.wallet();
    let spend = |n: &L2Note| {
        let d = fw.diversifier_at_index(0);
        let l1 = fw.spend_input(n.value, n.rho, n.rseed, d);
        qlab_air::l2::L2TxInput { sk: l1.sk, value: n.value, asset: n.asset, rho: n.rho, rseed: n.rseed, d: l1.d }
    };
    let (usdt_in, fee_in) = (spend(&notes[4]), spend(&notes[5]));
    let empty = CanonicalFreezeTree::empty();
    let policy = [
        L2PolicyInput {
            leaf: forged_leaf,
            reg_witness: real.witness,
            freeze: empty.opening_for(&rkm0(&f)).unwrap(),
            allow: dummy_allow_witness(),
            isk: [0; 4],
        },
        L2PolicyInput {
            leaf: zero.leaf,
            reg_witness: zero.witness,
            freeze: empty.opening_for(&rkm0(&f)).unwrap(),
            allow: dummy_allow_witness(),
            isk: [0; 4],
        },
    ];
    let me_f = Recipient { rkm: rkm0(&f), ek: fw.address_at_index(0).encapsulation_key().unwrap() };
    let h_r = Recipient { rkm: rkm0(&h), ek: to_h.encapsulation_key().unwrap() };
    let forged = prove_p_with_policies(
        &seq.commitment_tree().unwrap(),
        [&usdt_in, &fee_in],
        &[Out { to: h_r, value: 50, asset: u64::from(ASSET) }, Out { to: me_f, value: 0, asset: 0 }],
        2,
        policy,
        forged_root,
        [VPublic::NONE; 2],
        &mut rng,
    )
    .expect("the forged instance proves: the AIR checks paths, the node checks roots");
    let verdict = seq.submit(&forged.tx);
    assert!(matches!(verdict, Err(SpendError::Refused(_))), "the node refuses a spend under a stale leaf: {verdict:?}");
    assert_eq!(freeze_key_of(&rkm0(&f)), keys[0], "the published list is F's key");
    std::thread::sleep(Duration::from_secs(2));
    let v = net.settle_spends(4, "nothing moved");
    assert!(v.iter().all(|x| supply(x) == 1_000));

    // 4. The issuer redeems 150 from the 400 it received.
    redeem(&issuer, WalletEndpoint { url: urls[0].clone() }, ASSET, 150, &keys, v[0].state_tip, Some(hash), wait, &mut rng)
        .expect("the issuer redeems");
    let v = net.settle_spends(6, "the redeem");
    assert!(v.iter().all(|x| supply(x) == 850), "supply = minted − redeemed, on all three: {v:?}");

    for d in [&issuer.dir, &h.dir, &f.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
