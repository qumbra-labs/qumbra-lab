//! **B6's done-when** (lab #716): the Annulet devnet journey, end to end, on
//! three real nodes over TCP loopback running the real [`L2Verifier`].
//!
//! On the devnet genesis ([`AnnuletGenesisFile::devnet`]) a sequencer and two
//! followers (the followers dial the sequencer; production is the key file's):
//!
//! 1. The Annulet faucet refuses an L1 form by name, then reads its 16 stock
//!    notes from `/v1/genesis/notes`.
//! 2. **Two grants (shape S):** one to the `USDT-test` holder (its fee note),
//!    one to a freshly generated recipient.
//! 3. **The holder sends `USDT-test` (shape P, vPublic = 0)** to the recipient,
//!    paying the P fee with its grant.
//! 4. **The recipient detects** both of its notes through a *follower's*
//!    `/v1/compact` + `/full`, and **spends** the `USDT-test` note back to the
//!    holder (shape P), paying with its grant — witnesses read from the
//!    follower.
//!
//! Every transaction is submitted over `POST /v1/tx` and every block reaches
//! both followers, which apply it under the same verifier: at the end the
//! three nodes agree on the tip, the commitment root and the nullifier set.
//! 2 S + 2 P real proves (≈ 60 s on the lane).

use std::time::Instant;

use qlab_devnet::forms::GenesisForm;
use qlab_note::l2note::L2Note;
use qumbra_faucet::annulet::{served, AnnuletError, AnnuletFaucet, OwnedNote, Out, Recipient, SpendError, SpendKey};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile};
use rand::{Rng, SeedableRng};

#[test]
fn the_annulet_devnet_journey_grant_send_detect_spend_across_three_nodes() {
    let g = AnnuletGenesisFile::devnet();
    let net = Net::start(&g, "b6");
    let seq = served(net.served[0]);
    let follower = served(net.served[2]);
    let mut rng = rand::rngs::StdRng::seed_from_u64(716);
    let tier_p = g.params.fee_tier_p;
    assert_eq!((g.params.fee_tier_s, tier_p), (devnet::FEE_TIER_S, devnet::FEE_TIER_P));

    // Keys: the faucet's and the holder's are the devnet genesis's; the
    // recipient's are generated here.
    let faucet_key = SpendKey { sk: devnet::FAUCET_SK, d: devnet::FAUCET_D };
    let holder_key = SpendKey { sk: devnet::HOLDER_SK, d: devnet::HOLDER_D };
    let user_key = SpendKey { sk: [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()], d: [7, 1] };
    let faucet_kem = qlab_note::kem::generate_keypair(&mut rng);
    let holder_kem = qlab_note::kem::generate_keypair(&mut rng);
    let user_kem = qlab_note::kem::generate_keypair(&mut rng);
    let holder = Recipient { rkm: holder_key.rkm(), ek: holder_kem.ek.clone() };
    let user = Recipient { rkm: user_key.rkm(), ek: user_kem.ek.clone() };
    assert_eq!(holder.rkm, devnet::rkm(devnet::HOLDER_SK, devnet::HOLDER_D));

    // 1. The faucet refuses an L1 form by name, and reads its stock.
    for l1 in [GenesisForm::V4, GenesisForm::V5] {
        let refused = AnnuletFaucet::start(served(net.served[0]), l1, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S);
        assert!(matches!(refused, Err(AnnuletError::NotAnnulet)), "{l1:?}");
    }
    let mut faucet =
        AnnuletFaucet::start(served(net.served[0]), GenesisForm::Annulet, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S)
            .expect("the Annulet faucet starts on an Annulet node");
    assert_eq!(faucet.stock_left() as u64, devnet::STOCK_NOTES);
    net.settle_spends(0, "genesis");
    // Both followers are connected to the sequencer before anything is sealed.
    net.wait_connected();

    // 2. Two grants (shape S): the holder's fee note, the recipient's.
    let t = Instant::now();
    let holder_fee = faucet.grant(&holder, &mut rng).expect("grant 1 (to the holder) is admitted");
    net.settle_spends(2, "grant 1");
    let user_fee = faucet.grant(&user, &mut rng).expect("grant 2 (to the recipient) is admitted");
    net.settle_spends(4, "grant 2");
    eprintln!("B6 journey: 2 S grants sealed and applied on 3 nodes in {:?}", t.elapsed());
    assert_eq!(faucet.stock_left() as u64, devnet::STOCK_NOTES - 2);
    // A restarted faucet (a fresh start against a follower) skips both
    // granted notes by their on-chain nullifiers.
    let restarted =
        AnnuletFaucet::start(served(net.served[2]), GenesisForm::Annulet, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S)
            .expect("restarts");
    assert_eq!(restarted.stock_left() as u64, devnet::STOCK_NOTES - 2);
    for n in [holder_fee, user_fee] {
        assert_eq!((n.value, n.asset), (devnet::GRANT_VALUE, 0));
    }

    // 3. The holder sends USDT-test to the recipient (shape P, vPublic = 0).
    //    The policy inputs come from the served registry openings alone, with
    //    isk = 0: a transfer proves no issuer action (lab #720).
    let t = Instant::now();
    let holder_usdt = OwnedNote { note: devnet::holder_usdt_note(), key: holder_key }.input();
    let holder_fee = OwnedNote { note: holder_fee, key: holder_key }.input();
    let outs = [
        Out { to: user.clone(), value: devnet::HOLDER_USDT_VALUE, asset: devnet::USDT_TEST_ASSET },
        Out { to: holder.clone(), value: devnet::GRANT_VALUE - tier_p, asset: 0 },
    ];
    let send = qlab_l2spend::build_p(&seq, [&holder_usdt, &holder_fee], &outs, tier_p, &mut rng)
        .expect("the holder's P send builds and proves");
    seq.submit(&send.tx).expect("the holder's P send is admitted");
    let v = net.settle_spends(6, "the holder's send");
    eprintln!("B6 journey: holder → recipient USDT-test (P) sealed and applied in {:?}", t.elapsed());

    // 4. The recipient detects its two notes through a FOLLOWER's served
    //    surfaces, and nothing else.
    let mut mine: Vec<L2Note> = follower.detect(&user_kem.dk, 1, v[2].state_tip).expect("the follower serves discovery");
    mine.sort_by_key(|n| n.asset);
    assert_eq!(mine.len(), 2, "the recipient finds exactly its grant and its USDT-test");
    assert_eq!(mine[0], user_fee);
    assert_eq!(mine[1], send.outputs[0]);
    assert_eq!((mine[1].asset, mine[1].value), (devnet::USDT_TEST_ASSET, devnet::HOLDER_USDT_VALUE));
    let stranger = qlab_note::kem::generate_keypair(&mut rng);
    assert!(follower.detect(&stranger.dk, 1, v[2].state_tip).unwrap().is_empty());

    // …and spends the USDT-test note back to the holder (shape P), its
    // witnesses and registry openings read from the follower.
    let t = Instant::now();
    let user_usdt = OwnedNote { note: mine[1], key: user_key }.input();
    let user_fee = OwnedNote { note: mine[0], key: user_key }.input();
    let outs = [
        Out { to: holder.clone(), value: mine[1].value, asset: devnet::USDT_TEST_ASSET },
        Out { to: user.clone(), value: mine[0].value - tier_p, asset: 0 },
    ];
    let back = qlab_l2spend::build_p(&follower, [&user_usdt, &user_fee], &outs, tier_p, &mut rng)
        .expect("the recipient's P spend builds and proves");
    seq.submit(&back.tx).expect("the recipient's P spend is admitted");
    let v = net.settle_spends(8, "the recipient's spend");
    eprintln!("B6 journey: recipient → holder USDT-test (P) sealed and applied in {:?}", t.elapsed());

    // A spent note stays spent: the recipient's spend again is refused.
    let again = seq.submit(&back.tx);
    assert!(matches!(again, Err(SpendError::Refused(_))), "{again:?}");

    // The three nodes agree: tip, commitment root, and the four spends'
    // eight nullifiers (a real and a dummy per S grant, two real per P).
    assert!(v.iter().all(|x| x.root == v[0].root && x.state_tip == v[0].state_tip), "{v:?}");
    assert_eq!(v[0].nullifiers, 8, "{v:?}");
    let holder_back = served(net.served[1]).detect(&holder_kem.dk, 1, v[1].state_tip).unwrap();
    assert!(holder_back.contains(&back.outputs[0]), "the holder finds its USDT-test back on follower 1");
}
