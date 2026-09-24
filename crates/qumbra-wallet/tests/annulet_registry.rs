//! **C4a's done-when** (lab #730): registry transactions from the wallet's
//! issuer verbs, on B6's three-node harness over a C4a **test** genesis.
//!
//! The genesis registers `USDT-c4` (asset 2, Hybrid, an empty canonical freeze
//! tree) to the issuer's test `isk`; holder `F` holds 50 of it; the issuer and
//! `H` hold asset-0 notes of 10 (a registry write pays the R tariff 4 and gets
//! change back).
//!
//! 1. **register Cloaked**: the issuer registers asset 11 (Cloaked); its
//!    secret is in `issuer.v1` and the served leaf carries its key.
//! 2. **register Regulated**: the issuer registers asset 12 with `H` on its
//!    allow list; the served allow root is the list's canonical root.
//! 3. **the slot race**: `H` registers asset 13, then the issuer tries the
//!    same slot — the loser is told by name (`SlotTaken` if `H`'s write has
//!    landed, `RegistryRaced` if it is still pooled), and the slot is `H`'s.
//! 4. **a freeze published at runtime**: the issuer adds `F` to asset 2's
//!    freeze list and publishes the root. `F`'s wallet then refuses its send
//!    with the new list (`Frozen`) and with the old one (`FreezeListStale`).
//! 5. **key rotation**: asset 2's issuer key moves to a fresh secret, pending
//!    in `issuer.v1` until the chain shows it.
//! 6. **mode change**: Hybrid → Regulated (an allow list added), proved with
//!    the rotated secret, which is promoted; the freeze root is kept.
//!
//! After every write the three nodes agree (tip, tree, nullifiers, supplies,
//! registry root), and no write issues supply. 6 R proves (plus one proved
//! race loser when `H`'s write is still pooled).

use std::time::Duration;

use qlab_air::l2::{RegistryLeaf, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED};
use qlab_air::l2p::{cred_of, freeze_key_of, issuer_key_of, CanonicalAllowTree, CanonicalFreezeTree};
use qlab_l2spend::SpendError;
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::annulet::served;
use qumbra_faucet::devnet_harness::{Net, View};
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{send_annulet, SendRefusal, WalletEndpoint};
use qumbra_wallet::issuer::{issuer_register, issuer_update, IssuerFile, LeafPolicy};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const USDT: u16 = 2;
const ISK: [u64; 4] = [0xC4A5_0001, 0xC4A5_0002, 0xC4A5_0003, 0xC4A5_0004];

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_c4a_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

fn rkm0(w: &WalletDir) -> [u64; 4] {
    w.wallet().address_at_index(0).rkm_lanes()
}

fn note(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: rkm0(w), rho: [0xC4A, k, 1, 2], rseed: [0xC4A, k, 3, 4] }
}

fn agree(v: &[View; 3]) -> [u8; 32] {
    assert!(v.iter().all(|x| x.registry_root == v[0].registry_root), "{v:?}");
    v[0].registry_root
}

fn no_supply(v: &[View; 3], asset: u16) {
    assert!(v.iter().all(|x| x.supplies.iter().all(|(a, s)| *a != asset || *s == 0)), "asset {asset}: {v:?}");
}

#[test]
fn register_update_freeze_rotate_and_change_mode_at_runtime() {
    let (issuer, h, f) = (wallet("issuer", 0x41), wallet("h", 0x42), wallet("f", 0x43));
    IssuerFile::add(&issuer.dir, USDT, ISK).unwrap();

    let usdt = RegistryLeaf {
        asset: u64::from(USDT),
        issuer_key: issuer_key_of(&ISK),
        mode: MODE_HYBRID,
        freeze_root: CanonicalFreezeTree::empty().root,
        allow_root: [0; 4],
        flags: 0,
    };
    let notes = [
        note(&issuer, 10, 0, 1),
        note(&issuer, 10, 0, 2),
        note(&issuer, 10, 0, 3),
        note(&h, 10, 0, 4),
        note(&f, 50, u64::from(USDT), 5),
        note(&f, 2, 0, 6),
    ];
    let g = AnnuletGenesisFile::assemble(
        "annulet-c4a-test",
        AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 4, slot_secs: 10, max_empty_slots: 6 },
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero(), RegistryLeafRecord::of(&usdt)],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
    );
    let pin = Some(g.hash());
    let net = Net::start(&g, "c4a");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let at = |i: usize| WalletEndpoint { url: urls[i].clone() };
    let follower = served(net.served[2]);
    let mut rng = StdRng::seed_from_u64(730);
    let v = net.settle_spends(0, "genesis");
    let genesis_root = agree(&v);

    // 1. Register asset 11, Cloaked.
    let cloaked = LeafPolicy { mode: Some(MODE_CLOAKED), ..Default::default() };
    let r = issuer_register(&issuer, at(0), 11, &cloaked, v[0].state_tip, pin, &mut rng).expect("registers asset 11");
    let v = net.settle_spends(1, "register 11");
    assert_eq!(agree(&v), r.new_root);
    assert_ne!(r.new_root, genesis_root);
    let leaf11 = follower.registry(11).unwrap().leaf;
    assert_eq!(leaf11, r.leaf);
    assert_eq!((leaf11.mode, leaf11.freeze_root, leaf11.allow_root, leaf11.flags), (MODE_CLOAKED, [0; 4], [0; 4], 0));
    let isk11 = IssuerFile::load(&issuer.dir).unwrap().unwrap().isk(11).expect("the secret was written before submission");
    assert_eq!(issuer_key_of(&isk11), leaf11.issuer_key);
    assert_eq!((r.seed.asset, r.seed.value, r.change.value), (11, 0, 6), "the seed of asset 11; change 10 − 4");
    no_supply(&v, 11);

    // 2. Register asset 12, Regulated, H on its allow list.
    let allow = vec![cred_of(&rkm0(&h))];
    let regulated = LeafPolicy { mode: Some(MODE_REGULATED), allow_creds: Some(allow.clone()), ..Default::default() };
    let r = issuer_register(&issuer, at(1), 12, &regulated, v[1].state_tip, pin, &mut rng).expect("registers asset 12");
    let v = net.settle_spends(2, "register 12");
    assert_eq!(agree(&v), r.new_root);
    let leaf12 = follower.registry(12).unwrap().leaf;
    assert_eq!((leaf12.mode, leaf12.allow_root), (MODE_REGULATED, CanonicalAllowTree::from_creds(&allow).root));
    assert_eq!(leaf12.freeze_root, CanonicalFreezeTree::empty().root);

    // 3. The slot race on 13: H first, then the issuer — the loser is named.
    let hybrid = LeafPolicy { mode: Some(MODE_HYBRID), ..Default::default() };
    let won = issuer_register(&h, at(0), 13, &hybrid, v[0].state_tip, pin, &mut rng).expect("H registers asset 13");
    let lost = issuer_register(&issuer, at(0), 13, &hybrid, v[0].state_tip, pin, &mut rng);
    let branch = match &lost {
        Err(SendRefusal::SlotTaken { asset: 13 }) => "SlotTaken (H's write had landed)",
        Err(SendRefusal::RegistryRaced(_)) => "RegistryRaced (H's write was still pooled)",
        other => panic!("the second registration of slot 13 must be refused by name: {:?}", other.as_ref().err()),
    };
    // Written to the stderr HANDLE, not through `eprintln!`: libtest captures
    // the print macros of a passing test, and the lane log is where this is
    // read (lab #730: which race branch ran).
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "C4a slot race on asset 13: the loser got {branch}");
    }
    let v = net.settle_spends(3, "the race");
    assert_eq!(agree(&v), won.new_root);
    assert_eq!(follower.registry(13).unwrap().leaf.issuer_key, won.leaf.issuer_key, "the slot is H's");

    // 4. A freeze published at runtime: F onto asset 2's list.
    let keys = vec![freeze_key_of(&rkm0(&f))];
    let freeze = LeafPolicy { freeze_keys: Some(keys.clone()), ..Default::default() };
    let r = issuer_update(&issuer, at(2), USDT, &freeze, false, v[2].state_tip, pin, &mut rng).expect("publishes the freeze root");
    let v = net.settle_spends(4, "the freeze");
    assert_eq!(agree(&v), r.new_root);
    assert_eq!(follower.registry(u64::from(USDT)).unwrap().leaf.freeze_root, CanonicalFreezeTree::from_keys(&keys).root);
    let to_h = h.wallet().address_at_index(0);
    let wait = Duration::from_secs(60);
    let refused = send_annulet(&f, at(1), USDT, 10, &to_h, v[1].state_tip, pin, &keys, wait, &mut rng);
    assert!(matches!(refused, Err(SendRefusal::Spend(SpendError::Frozen { asset: 2 }))), "{:?}", refused.err());
    let stale = send_annulet(&f, at(1), USDT, 10, &to_h, v[1].state_tip, pin, &[], wait, &mut rng);
    assert!(
        matches!(stale, Err(SendRefusal::Spend(SpendError::FreezeListStale { asset: 2 }))),
        "the pre-freeze list no longer rebuilds the served root: {:?}",
        stale.err()
    );

    // 5. Rotate asset 2's issuer key.
    let r = issuer_update(&issuer, at(0), USDT, &LeafPolicy::default(), true, v[0].state_tip, pin, &mut rng).expect("rotates");
    let v = net.settle_spends(5, "the rotation");
    assert_eq!(agree(&v), r.new_root);
    let file = IssuerFile::load(&issuer.dir).unwrap().unwrap();
    let next = *file.next.get(&USDT).expect("the new secret is pending until used");
    assert_eq!(file.isk(USDT), Some(ISK));
    assert_eq!(follower.registry(u64::from(USDT)).unwrap().leaf.issuer_key, issuer_key_of(&next));

    // 6. Hybrid → Regulated, proved with the rotated secret (promoted).
    let to_regulated = LeafPolicy { mode: Some(MODE_REGULATED), allow_creds: Some(allow.clone()), ..Default::default() };
    let r = issuer_update(&issuer, at(1), USDT, &to_regulated, false, v[1].state_tip, pin, &mut rng).expect("changes mode");
    let v = net.settle_spends(6, "the mode change");
    assert_eq!(agree(&v), r.new_root);
    let leaf2 = follower.registry(u64::from(USDT)).unwrap().leaf;
    assert_eq!((leaf2.mode, leaf2.allow_root), (MODE_REGULATED, CanonicalAllowTree::from_creds(&allow).root));
    assert_eq!(leaf2.freeze_root, CanonicalFreezeTree::from_keys(&keys).root, "the freeze root is kept");
    let file = IssuerFile::load(&issuer.dir).unwrap().unwrap();
    assert_eq!((file.isk(USDT), file.next.get(&USDT)), (Some(next), None), "the rotation was promoted");
    // Registry writes issue nothing: asset 2's supply is F's genesis 50.
    assert!(v.iter().all(|x| x.supplies.iter().any(|(a, s)| *a == USDT && *s == 50)), "{v:?}");

    for d in [&issuer.dir, &h.dir, &f.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// **C4b's done-when** (lab #730): an asset registered at runtime is minted on
/// its R seed and then moves between two holders — with the node's supply and
/// the explorer's `/v1/attest` document (the explorer's own code, over each
/// node) agreeing after every step.
///
/// 1. The issuer registers asset 21 (Hybrid, an empty freeze tree); the seed
///    is its only note of the asset. Outstanding 0.
/// 2. **The issuer mints 1,000 to `H` on the seed** (P, vPublic +1,000). The
///    mint re-arms: the issuer holds a note of 21 again (the seed's 0 back).
/// 3. **`H` sends 400 to `K`** (P, vPublic 0) — two non-issuer wallets.
///
/// 1 R + 2 P proves.
#[test]
fn a_runtime_asset_is_minted_on_its_seed_and_moves_between_holders() {
    const NEW: u16 = 21;
    let (issuer, h, k) = (wallet("mint-issuer", 0x51), wallet("mint-h", 0x52), wallet("mint-k", 0x53));
    let notes = [note(&issuer, 10, 0, 11), note(&issuer, 2, 0, 12), note(&h, 2, 0, 13)];
    let g = AnnuletGenesisFile::assemble(
        "annulet-c4b-test",
        AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 4, slot_secs: 10, max_empty_slots: 6 },
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero()],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
    );
    let issuance = qlab_node::asset_supply::genesis_issuance(&g.notes()).unwrap();
    let probe: qumbra_faucet::devnet_harness::Probe =
        std::sync::Arc::new(move |n: &qlab_node::MemNode| qumbra_explorer::attest::attest_document(n, &issuance));
    let net = Net::start_probed(&g, "c4b", Some(probe));
    net.wait_connected();
    let pin = Some(g.hash());
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let at = |i: usize| WalletEndpoint { url: urls[i].clone() };
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(7301);
    // Every node's /v1/attest agrees with that node, and all three state the
    // same outstanding figure for `NEW`.
    let attested = |what: &str| -> Vec<serde_json::Value> {
        let docs: Vec<serde_json::Value> = net.probes().iter().map(|d| serde_json::from_str(d).expect("/v1/attest is JSON")).collect();
        for (i, d) in docs.iter().enumerate() {
            assert_eq!(d["node_agrees"], true, "{what}: node {i}'s /v1/attest disagrees with it: {}", d["node_divergences"]);
        }
        docs
    };
    let outstanding = |d: &serde_json::Value| -> String {
        d["assets"].as_array().unwrap().iter().find(|r| r["asset"] == NEW).map_or("0".into(), |r| r["outstanding"].as_str().unwrap().to_string())
    };
    let supply = |v: &View| v.supplies.iter().find(|(a, _)| *a == NEW).map_or(0, |(_, s)| *s);
    let v = net.settle_spends(0, "genesis");
    attested("genesis");

    // 1. Register 21 at runtime; its seed is the issuer's only note of it.
    let hybrid = LeafPolicy { mode: Some(MODE_HYBRID), ..Default::default() };
    let reg = issuer_register(&issuer, at(0), NEW, &hybrid, v[0].state_tip, pin, &mut rng).expect("registers 21");
    assert_eq!((reg.seed.asset, reg.seed.value), (u64::from(NEW), 0));
    let v = net.settle_spends(1, "register 21");
    let docs = attested("register 21");
    assert!(v.iter().all(|x| supply(x) == 0) && docs.iter().all(|d| outstanding(d) == "0"), "{v:?}");

    // 2. The issuer mints 1,000 to H — on the seed.
    let to_h = h.wallet().address_at_index(0);
    let mint = qumbra_wallet::issuer::issuer_mint(&issuer, at(1), NEW, 1_000, &to_h, &[], v[1].state_tip, pin, wait, &mut rng)
        .expect("the issuer mints on the R seed");
    assert!(mint.split_fee_note.is_none(), "the genesis fee note was exact");
    assert!(mint.rearmed, "the mint returns the seed's row to the issuer: re-armed");
    assert_eq!((mint.outputs[1].asset, mint.outputs[1].value), (u64::from(NEW), 0));
    let v = net.settle_spends(3, "the mint");
    let docs = attested("the mint");
    assert!(v.iter().all(|x| supply(x) == 1_000), "{v:?}");
    assert!(docs.iter().all(|d| outstanding(d) == "1000"), "/v1/attest states 1,000 on every node");

    // 3. H sends 400 to K: a P spend of the new asset between non-issuers.
    let to_k = k.wallet().address_at_index(0);
    send_annulet(&h, at(2), NEW, 400, &to_k, v[2].state_tip, pin, &[], wait, &mut rng).expect("H pays K in asset 21");
    let v = net.settle_spends(5, "H → K");
    let docs = attested("H → K");
    assert!(v.iter().all(|x| supply(x) == 1_000) && docs.iter().all(|d| outstanding(d) == "1000"), "a transfer issues nothing");
    let ks = qumbra_wallet::annulet_send::open_session(&k, at(1), v[1].state_tip, pin, &mut rng).expect("K scans");
    let held: Vec<u64> = ks.index.spendable(NEW).iter().map(|n| n.note.value).collect();
    assert_eq!(held, vec![400], "K holds the 400 of asset 21");

    for d in [&issuer.dir, &h.dir, &k.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
