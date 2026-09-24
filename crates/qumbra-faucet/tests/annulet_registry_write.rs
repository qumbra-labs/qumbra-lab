//! **B3b's done-when** (lab #728 Q9): a registry write, end to end, on the
//! devnet harness — a sequencer and two followers over TCP loopback running
//! the real [`L2Verifier`](qumbra_node::verifier::L2Verifier).
//!
//! 1. **Register** a new asset into an empty slot (shape R, permissionless):
//!    the slot's opening is read from `/v1/registry/slot/{asset}`, the fee is
//!    paid from one devnet stock note, the change returns to the payer.
//! 2. **Update** it (shape R): rotate the issuer key, proving the current
//!    one, with the opening read from a *follower*.
//!
//! After each write all three nodes agree on the tip, the commitment root,
//! the nullifiers, the supplies **and the registry root**, which is the root
//! the write declared; a follower serves the new leaf; the payer detects both
//! change notes **and both seeds** (A3, lab #731: every write mints a 0-value
//! note of the written asset to the writer — the note a first mint rides on);
//! a replayed write is refused. 2 real R proves (≈ 3.5 GB each).

use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{issuer_key_of, CanonicalFreezeTree};
use qlab_note::hash::digest_bytes;
use qumbra_faucet::annulet::{served, OwnedNote, Recipient, SpendKey};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile};
use rand::SeedableRng;

/// The slot the test registers — empty in the devnet genesis.
const ASSET: u64 = 9;
const ISK: [u64; 4] = [0x9A55_0001, 0x9A55_0002, 0x9A55_0003, 0x9A55_0004];
const ISK_NEXT: [u64; 4] = [0x9A55_0011, 0x9A55_0012, 0x9A55_0013, 0x9A55_0014];

#[test]
fn a_registry_write_registers_then_updates_and_converges_on_three_nodes() {
    let g = AnnuletGenesisFile::devnet();
    let net = Net::start(&g, "b3b");
    let seq = served(net.served[0]);
    let follower = served(net.served[2]);
    let mut rng = rand::rngs::StdRng::seed_from_u64(728);
    let tier_r = g.params.fee_tier_r;
    assert_eq!(tier_r, devnet::FEE_TIER_R);
    net.settle_spends(0, "genesis");
    net.wait_connected();
    let genesis_root = net.views()[0].registry_root;

    // The payer spends devnet stock notes with the dev faucet key (the
    // faucet itself is not running here); change comes back to it.
    let payer = SpendKey { sk: devnet::FAUCET_SK, d: devnet::FAUCET_D };
    let kem = qlab_note::kem::generate_keypair(&mut rng);
    let change = Recipient { rkm: payer.rkm(), ek: kem.ek.clone() };

    // 1. Register asset 9 into its empty slot.
    let empty = follower.registry_slot(ASSET).expect("the slot route answers an empty slot");
    assert!(empty.leaf.is_none(), "slot {ASSET} is empty in the devnet genesis");
    assert_eq!(digest_bytes(&empty.root), genesis_root);
    let leaf = RegistryLeaf {
        asset: ASSET,
        issuer_key: issuer_key_of(&ISK),
        mode: MODE_HYBRID,
        freeze_root: CanonicalFreezeTree::empty().root,
        allow_root: [0; 4],
        flags: 0,
    };
    let fee_in = OwnedNote { note: devnet::stock_note(0), key: payer }.input();
    let reg = qlab_l2spend::build_r(&seq, &fee_in, &change, tier_r, leaf, [0; 4], &mut rng)
        .expect("the registration builds and proves");
    seq.submit(&reg.tx).expect("the registration is admitted");
    let v = net.settle_spends(1, "the registration");
    assert_ne!(reg.new_root, genesis_root);
    assert!(v.iter().all(|x| x.registry_root == reg.new_root), "the write's declared root, on all three: {v:?}");
    let held = follower.registry_slot(ASSET).unwrap();
    assert_eq!((held.leaf, digest_bytes(&held.root)), (Some(leaf), reg.new_root), "a follower serves the new leaf");
    assert_eq!(follower.registry(ASSET).expect("/v1/registry/{asset} answers now").leaf, leaf);

    // 2. Update it: rotate the issuer key, proving the current one; the
    //    opening comes from a follower.
    let updated = RegistryLeaf { issuer_key: issuer_key_of(&ISK_NEXT), ..leaf };
    let fee_in = OwnedNote { note: devnet::stock_note(1), key: payer }.input();
    let upd = qlab_l2spend::build_r(&follower, &fee_in, &change, tier_r, updated, ISK, &mut rng)
        .expect("the update builds and proves");
    seq.submit(&upd.tx).expect("the update is admitted");
    let v = net.settle_spends(2, "the update");
    assert!(v.iter().all(|x| x.registry_root == upd.new_root), "{v:?}");
    let held = served(net.served[1]).registry_slot(ASSET).unwrap();
    assert_eq!((held.leaf, digest_bytes(&held.root)), (Some(updated), upd.new_root), "follower 1 serves the update");

    // The payer finds both change notes and both seeds through a follower.
    let mine = follower.detect(&kem.dk, 1, v[2].state_tip).expect("the follower serves discovery");
    assert!(mine.contains(&reg.output) && mine.contains(&upd.output), "{mine:?}");
    assert_eq!((reg.output.value, reg.output.asset), (devnet::STOCK_NOTE_VALUE - tier_r, 0));
    assert!(mine.contains(&reg.seed) && mine.contains(&upd.seed), "the registrant holds both seeds: {mine:?}");
    for seed in [reg.seed, upd.seed] {
        assert_eq!((seed.value, seed.asset, seed.rkm), (0, ASSET, payer.rkm()), "a 0-value note of asset 9 to the writer");
    }
    assert_eq!(mine.iter().filter(|n| n.asset == ASSET).count(), 2, "exactly the two seeds of asset 9");
    // The seeds issue nothing: asset 9 has no outstanding supply.
    assert!(v.iter().all(|x| x.supplies.iter().all(|(a, s)| *a != ASSET as u16 || *s == 0)), "{v:?}");

    // A replayed write is refused: its fee note is spent and its root is gone.
    assert!(seq.submit(&upd.tx).is_err());
}
