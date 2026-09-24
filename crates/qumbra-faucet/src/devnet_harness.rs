//! **The Annulet devnet harness** (B6's, promoted in C2 — lab #720): a
//! sequencer and two followers on real TCP loopback, running the real
//! `L2Verifier`, driven by one thread that runs each node's loop step and
//! seals whenever the producer's pool is non-empty. Test support: the faucet's
//! journey and the wallet's send test run on the same three nodes.
#![doc(hidden)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState as _;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};
use qumbra_node::config::NodeConfig;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::L2Verifier;

pub type Node = RunningNode<KeccakPow, L2Verifier>;

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

fn data_dir(net: &str, tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("qmb_{net}_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("data")).unwrap();
    base
}

/// What the driver thread publishes each pass, per node (producer first).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub header_tip: u64,
    pub state_tip: u64,
    pub root: [u8; 32],
    pub nullifiers: usize,
    pub ready_peers: usize,
}

/// The three nodes, owned by one driver thread that runs each one's real
/// loop step and seals whenever the producer's pool is non-empty (the slot
/// rule's non-empty arm, without waiting out the 10-s slot).
pub struct Net {
    /// The discovery endpoints: the sequencer, follower 1, follower 2.
    pub served: [SocketAddr; 3],
    views: Arc<Mutex<[View; 3]>>,
    stop: Arc<AtomicBool>,
    driver: Option<std::thread::JoinHandle<()>>,
    bases: Vec<std::path::PathBuf>,
}

impl Net {
    /// Start the three nodes on `g`; `name` keeps concurrent harnesses' data
    /// dirs apart.
    pub fn start(g: &AnnuletGenesisFile, name: &str) -> Self {
        let bases: Vec<_> = ["seq", "f1", "f2"].iter().map(|t| data_dir(name, t)).collect();
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

    pub fn views(&self) -> [View; 3] {
        *self.views.lock().unwrap()
    }

    /// Wait until every node has applied exactly `nullifiers` spends and all
    /// three agree. **Keyed on the spends, not the tip** (the first full lane
    /// run): the producer's slot rule also seals EMPTY blocks, so "the tip
    /// moved" is not evidence that a submitted transaction was included.
    pub fn settle_spends(&self, nullifiers: usize, what: &str) -> [View; 3] {
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

impl Net {
    /// Wait until both followers are connected to the sequencer.
    pub fn wait_connected(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.views()[0].ready_peers < 2 {
            assert!(Instant::now() < deadline, "the followers did not connect: {:?}", self.views());
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
