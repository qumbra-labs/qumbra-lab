//! **C2's done-when** (lab #720): the wallet's real `scan --net annulet` and
//! `send --net annulet` code paths — its own http transport, its own scan,
//! plan, fee-split and prove — against B6's three-node harness (a sequencer
//! and two followers over TCP loopback under the real `L2Verifier`), not a
//! hand-modelled endpoint.
//!
//! 1. The devnet faucet key spends two genesis stock notes in one S: 3 to an
//!    ordinary wallet `W`, and 2 (a P-tariff fee note) to the devnet holder.
//! 2. The holder sends `W` its `USDT-test` (P, vPublic = 0).
//! 3. `W` scans through a follower: `[(0, 3), (1, 1_000_000)]`.
//! 4. `W` sends 250,000 `USDT-test` to a third wallet `T` **through a
//!    follower**. It holds no exact P-tariff fee note, so it **fee-splits**
//!    its 3 into a 2 plus change (S) first, waits for the split to land, and
//!    then sends (P).
//! 5. `T` scans through the other follower and finds 250,000; `W` rescans to
//!    750,000 of `USDT-test`.
//!
//! The wallet dir is left **byte-identical**: the L1 files `tree-leaves.v1`
//! and `sends.v1` are untouched and nothing is added. 2 S + 2 P real proves.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use qlab_l2spend::{build_p, build_s, Out, Recipient};
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::annulet::{served, OwnedNote, SpendKey};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile};
use qumbra_wallet::annulet::scan_annulet;
use qumbra_wallet::annulet_send::{send_annulet, Plan, WalletEndpoint};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_c2_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

fn recipient(w: &WalletDir) -> Recipient {
    let a = w.wallet().address_at_index(0);
    Recipient { rkm: a.rkm_lanes(), ek: a.encapsulation_key().unwrap() }
}

/// Every file in the wallet dir with its bytes.
fn snapshot(w: &WalletDir) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(&w.dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap())
        })
        .collect()
}

fn balances(w: &WalletDir, url: &str, tip: u64, hash: [u8; 32]) -> Vec<(u16, u128)> {
    let mut rng = StdRng::seed_from_u64(0xC2);
    let mut fetch = qumbra_wallet::net::scan_fetch(url);
    let report = scan_annulet(w, &mut fetch, 0, tip, Some(hash), &mut rng).expect("an Annulet endpoint with the pinned genesis");
    report.index.expect("both halves known").balances()
}

#[test]
fn an_ordinary_wallet_fee_splits_and_sends_usdt_test_through_a_follower() {
    let g = AnnuletGenesisFile::devnet();
    let hash = g.hash();
    let net = Net::start(&g, "c2");
    net.wait_connected();
    let urls: Vec<String> = net.served.iter().map(|a| format!("http://{a}")).collect();
    let seq = served(net.served[0]);
    let mut rng = StdRng::seed_from_u64(720);
    let (tier_s, tier_p) = (g.params.fee_tier_s, g.params.fee_tier_p);

    let w = wallet("w", 0x21);
    let t = wallet("t", 0x22);
    let holder_key = SpendKey { sk: devnet::HOLDER_SK, d: devnet::HOLDER_D };
    let holder_kem = qlab_note::kem::generate_keypair(&mut rng);
    let holder = Recipient { rkm: holder_key.rkm(), ek: holder_kem.ek.clone() };

    // 1. Two stock notes (3 + 3) in one S: 3 to W, 2 to the holder, fee 1.
    let faucet_key = SpendKey { sk: devnet::FAUCET_SK, d: devnet::FAUCET_D };
    let stock = [0u64, 1].map(|i| OwnedNote { note: devnet::stock_note(i), key: faucet_key }.input());
    let fund = build_s(
        &seq,
        &[&stock[0], &stock[1]],
        &[Out { to: recipient(&w), value: 3, asset: 0 }, Out { to: holder.clone(), value: tier_p, asset: 0 }],
        tier_s,
        &mut rng,
    )
    .expect("the two-stock-note S builds and proves");
    assert_eq!(2 * devnet::STOCK_NOTE_VALUE, 3 + tier_p + tier_s);
    seq.submit(&fund.tx).expect("admitted");
    net.settle_spends(2, "the funding S");

    // 2. The holder sends W its USDT-test (P), paying with its 2.
    let usdt = OwnedNote { note: devnet::holder_usdt_note(), key: holder_key }.input();
    let fee = OwnedNote { note: fund.outputs[1], key: holder_key }.input();
    let to_w = build_p(
        &seq,
        [&usdt, &fee],
        &[
            Out { to: recipient(&w), value: devnet::HOLDER_USDT_VALUE, asset: devnet::USDT_TEST_ASSET },
            Out { to: holder, value: 0, asset: 0 },
        ],
        tier_p,
        &mut rng,
    )
    .expect("the holder's P builds and proves");
    seq.submit(&to_w.tx).expect("admitted");
    let v = net.settle_spends(4, "the holder's P");

    // 3. W scans through follower 1 — the real wallet scan over its own transport.
    assert_eq!(balances(&w, &urls[1], v[1].state_tip, hash), vec![(0, 3), (1, devnet::HOLDER_USDT_VALUE as u128)]);

    // 4. W sends 250,000 USDT-test to T through follower 1: split first, then P.
    std::fs::write(w.dir.join("tree-leaves.v1"), b"an L1 wallet's tree cache").unwrap();
    std::fs::write(w.dir.join("sends.v1"), b"an L1 wallet's send record").unwrap();
    let before = snapshot(&w);
    let started = Instant::now();
    let t_addr = t.wallet().address_at_index(0);
    let report = send_annulet(
        &w,
        WalletEndpoint { url: urls[1].clone() },
        devnet::USDT_TEST_ASSET as u16,
        250_000,
        &t_addr,
        v[1].state_tip,
        Some(hash),
        Duration::from_secs(60),
        &mut rng,
    )
    .expect("the wallet's send: fee-split, then P");
    assert!(matches!(report.plan, Plan::SplitFirst { .. }), "no exact P-tariff note: {:?}", report.plan);
    assert_eq!(report.split_fee_note.map(|n: L2Note| (n.value, n.asset)), Some((tier_p, 0)));
    assert_eq!(report.outputs[0].value, 250_000);
    assert_eq!(report.outputs[1].value, devnet::HOLDER_USDT_VALUE - 250_000);
    let v = net.settle_spends(8, "the split and the send");
    eprintln!("C2: W's fee-split (S) + send (P), sealed and applied on 3 nodes in {:?}", started.elapsed());
    assert_eq!(snapshot(&w), before, "send --net annulet leaves the wallet dir byte-identical (P8)");

    // 5. T finds it through follower 2; W rescans.
    assert_eq!(balances(&t, &urls[2], v[2].state_tip, hash), vec![(1, 250_000)]);
    let after = balances(&w, &urls[1], v[1].state_tip, hash);
    assert_eq!(after, vec![(0, 0), (1, (devnet::HOLDER_USDT_VALUE - 250_000) as u128)], "the split's change is a 0 note");
    for d in [&w.dir, &t.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
