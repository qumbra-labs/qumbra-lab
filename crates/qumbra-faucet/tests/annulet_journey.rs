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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState as _;
use qlab_note::l2note::L2Note;
use qumbra_faucet::annulet::{
    build_p_send, AnnuletError, AnnuletFaucet, OwnedNote, Recipient, Served, SpendKey,
};
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};
use qumbra_node::config::NodeConfig;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::L2Verifier;
use rand::{Rng, SeedableRng};

type Node = RunningNode<KeccakPow, L2Verifier>;

fn config(base: &std::path::Path, g: &AnnuletGenesisFile, dial: Option<&str>) -> NodeConfig {
    NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: dial.map(|a| vec![a.to_string()]).unwrap_or_default(),
        advertise_addr: None,
        genesis_file: base.join("genesis.qmb"),
        committee_key_paths: vec![],
        mining: false,
        expected_genesis_hash: Some(g.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: None,
        template_serving: false,
    }
}

fn data_dir(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("qmb_b6_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("data")).unwrap();
    base
}

/// What the driver thread publishes each pass, per node (producer first).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct View {
    header_tip: u64,
    state_tip: u64,
    root: [u8; 32],
    nullifiers: usize,
    ready_peers: usize,
}

/// The three nodes, owned by one driver thread that runs each one's real
/// loop step and seals whenever the producer's pool is non-empty (the slot
/// rule's non-empty arm, without waiting out the 10-s slot).
struct Net {
    served: [SocketAddr; 3],
    views: Arc<Mutex<[View; 3]>>,
    stop: Arc<AtomicBool>,
    driver: Option<std::thread::JoinHandle<()>>,
    bases: Vec<std::path::PathBuf>,
}

impl Net {
    fn start(g: &AnnuletGenesisFile) -> Self {
        let bases: Vec<_> = ["seq", "f1", "f2"].iter().map(|t| data_dir(t)).collect();
        let kf = SequencerKeyFile {
            seed_hex: devnet::SEQUENCER_SEED.iter().map(|b| format!("{b:02x}")).collect(),
            note: "devnet sequencer key (test)".into(),
        };
        std::fs::write(bases[0].join("data").join(SEQUENCER_KEY_FILE), kf.to_toml()).unwrap();
        let views = Arc::new(Mutex::new([View::default(); 3]));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (g2, bases2, views2, stop2) = (g.clone(), bases.clone(), views.clone(), stop.clone());
        let driver = std::thread::spawn(move || {
            let producer: Node =
                RunningNode::start_annulet(&config(&bases2[0], &g2, None), &g2, KeccakPow, L2Verifier).expect("producer");
            assert!(producer.is_sequencer());
            let dial = producer.listen_addr().to_string();
            let mut nodes = vec![producer];
            for base in &bases2[1..] {
                let f: Node = RunningNode::start_annulet(&config(base, &g2, Some(&dial)), &g2, KeccakPow, L2Verifier)
                    .expect("follower");
                assert!(!f.is_sequencer());
                nodes.push(f);
            }
            let served: Vec<SocketAddr> =
                nodes.iter_mut().map(|n| n.start_discovery_endpoint("127.0.0.1:0").expect("discovery binds")).collect();
            tx.send([served[0], served[1], served[2]]).unwrap();
            // Seal on the wall clock, never below the parent: the loop's own
            // slot step also seals (an empty block every 6 slots) at wall time.
            let wall = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let mut ts = g2.genesis_header.timestamp;
            let mut last = [View::default(); 3];
            while !stop2.load(Ordering::Acquire) {
                for n in nodes.iter_mut() {
                    n.one_iteration(&mut |_| {});
                }
                if !nodes[0].p2p().node().mempool().is_empty() {
                    ts = (ts + 1).max(wall());
                    nodes[0].seal_block_now(ts).expect("the producer seals");
                }
                let mut now = [View::default(); 3];
                for (i, n) in nodes.iter_mut().enumerate() {
                    let s = n.p2p().node().state();
                    now[i] = View {
                        header_tip: n.tip_height(),
                        state_tip: s.tip_height(),
                        root: s.commitment_root(),
                        nullifiers: s.nullifier_count(),
                        ready_peers: n.p2p().peers().ready_peers().len(),
                    };
                    // Serve the new tip at once rather than on the 5-s cadence.
                    if now[i] != last[i] {
                        n.refresh_discovery();
                        n.refresh_leaves();
                        n.refresh_anchors();
                        n.refresh_registry();
                    }
                }
                last = now;
                *views2.lock().unwrap() = now;
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let served = rx.recv_timeout(Duration::from_secs(60)).expect("the three nodes start");
        Net { served, views, stop, driver: Some(driver), bases }
    }

    fn views(&self) -> [View; 3] {
        *self.views.lock().unwrap()
    }

    /// Wait until every node has applied exactly `nullifiers` spends and all
    /// three agree. **Keyed on the spends, not the tip** (the first full lane
    /// run): the producer's slot rule also seals EMPTY blocks, so "the tip
    /// moved" is not evidence that a submitted transaction was included.
    fn settle_spends(&self, nullifiers: usize, what: &str) -> [View; 3] {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let v = self.views();
            let agree = v.iter().all(|x| (x.header_tip, x.state_tip, x.root, x.nullifiers) == (v[0].header_tip, v[0].state_tip, v[0].root, v[0].nullifiers));
            if v[0].nullifiers == nullifiers && agree {
                return v;
            }
            assert!(Instant::now() < deadline, "{what}: the net did not settle at {nullifiers} nullifiers: {v:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(d) = self.driver.take() {
            let _ = d.join();
        }
        for b in &self.bases {
            let _ = std::fs::remove_dir_all(b);
        }
    }
}

#[test]
fn the_annulet_devnet_journey_grant_send_detect_spend_across_three_nodes() {
    let g = AnnuletGenesisFile::devnet();
    let net = Net::start(&g);
    let seq = Served { addr: net.served[0] };
    let follower = Served { addr: net.served[2] };
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
        let refused = AnnuletFaucet::start(seq, l1, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S);
        assert!(matches!(refused, Err(AnnuletError::NotAnnulet)), "{l1:?}");
    }
    let mut faucet =
        AnnuletFaucet::start(seq, GenesisForm::Annulet, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S)
            .expect("the Annulet faucet starts on an Annulet node");
    assert_eq!(faucet.stock_left() as u64, devnet::STOCK_NOTES);
    net.settle_spends(0, "genesis");
    // Both followers are connected to the sequencer before anything is sealed.
    let deadline = Instant::now() + Duration::from_secs(30);
    while net.views()[0].ready_peers < 2 {
        assert!(Instant::now() < deadline, "the followers did not connect: {:?}", net.views());
        std::thread::sleep(Duration::from_millis(20));
    }

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
        AnnuletFaucet::start(follower, GenesisForm::Annulet, faucet_key, faucet_kem.ek.clone(), devnet::FEE_TIER_S)
            .expect("restarts");
    assert_eq!(restarted.stock_left() as u64, devnet::STOCK_NOTES - 2);
    for n in [holder_fee, user_fee] {
        assert_eq!((n.value, n.asset), (devnet::GRANT_VALUE, 0));
    }

    // 3. The holder sends USDT-test to the recipient (shape P, vPublic = 0).
    let usdt = devnet::usdt_test_policy();
    let asset0 = qlab_air::l2p::PolicyAsset::cloaked(0);
    let t = Instant::now();
    let holder_usdt = OwnedNote { note: devnet::holder_usdt_note(), key: holder_key };
    let holder_fee = OwnedNote { note: holder_fee, key: holder_key };
    let send = build_p_send(&seq, [&holder_usdt, &holder_fee], [&usdt, &asset0], &user, &holder, tier_p, &mut rng)
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
    let user_usdt = OwnedNote { note: mine[1], key: user_key };
    let user_fee = OwnedNote { note: mine[0], key: user_key };
    let back = build_p_send(&follower, [&user_usdt, &user_fee], [&usdt, &asset0], &holder, &user, tier_p, &mut rng)
        .expect("the recipient's P spend builds and proves");
    seq.submit(&back.tx).expect("the recipient's P spend is admitted");
    let v = net.settle_spends(8, "the recipient's spend");
    eprintln!("B6 journey: recipient → holder USDT-test (P) sealed and applied in {:?}", t.elapsed());

    // A spent note stays spent: the recipient's spend again is refused.
    let again = seq.submit(&back.tx);
    assert!(matches!(again, Err(AnnuletError::Refused(_))), "{again:?}");

    // The three nodes agree: tip, commitment root, and the four spends'
    // eight nullifiers (a real and a dummy per S grant, two real per P).
    assert!(v.iter().all(|x| x.root == v[0].root && x.state_tip == v[0].state_tip), "{v:?}");
    assert_eq!(v[0].nullifiers, 8, "{v:?}");
    let holder_back = Served { addr: net.served[1] }.detect(&holder_kem.dk, 1, v[1].state_tip).unwrap();
    assert!(holder_back.contains(&back.outputs[0]), "the holder finds its USDT-test back on follower 1");
}
