//! **Issue #371 S5 — the joiner drill: a stranger's node syncs this net.**
//!
//! T1 Gate A's exit criterion, in-suite: a fresh node with an **empty data
//! dir** joins a running multi-node net already carrying a multi-thousand-block
//! chain, over the **real TCP transport**, and reaches `slag=0` — applied tip,
//! fork-choice tip and the servers' tip all the same block — inside the test
//! budget. While it syncs it refuses to mine (#130/#106 duty refusal, S7), and
//! what it applied survives a process restart (the bodies went through the
//! durable store, not a cache).
//!
//! **The mutation check is a standing test, not a one-off** (#84's law: a drill
//! must detect the gap it drills). `stall_without_historical_serving` runs the
//! same topology with the servers' body serving switched to the pre-#182
//! header-only wire — today's deployed behaviour per the task book — and
//! asserts the joiner gets the whole header chain and applies NOTHING: `slag`
//! pinned at the chain length, asks outstanding, nobody scored. If historical
//! serving regresses, `joins_a_running_net_from_an_empty_data_dir` fails; if
//! someone deletes the serving path's degrade honesty, the stall test fails.
//!
//! Scale: S7 of #369 applies — drill scale stays small enough for minutes, not
//! hours. 2,500 blocks ≈ the shape of the live chain (~9 k) at 28 % scale; the
//! measured rate is printed as a `JOINER_DRILL` line for #370 A4 (S6).

use std::time::{Duration, Instant};

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::sync::SyncPhase;
use qlab_p2p::transport::{TcpTransport, Transport};
use qlab_p2p::P2pNode;

#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<TcpTransport, Adapter>;

/// Fast blocks and trivial PoW: a 2,500-block chain is seconds of Keccak, and
/// the drill measures the transfer pipeline, not the hash function.
fn easy_sim() -> SimConfig {
    SimConfig {
        block_time_secs: 2,
        genesis_difficulty: 8,
        mine_nonce_budget: 5_000_000,
        ..SimConfig::default()
    }
}

fn committee() -> CommitteeState {
    let (committee, _v) = devnet_committee(7);
    CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT)
}

fn adapter() -> Adapter {
    NodeAdapter::new(committee(), KeccakPow, MarkerVerifier, easy_sim())
}

/// A fresh, empty data dir for the joiner — the clean-room condition.
fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "qlab-i371-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Mine `n` blocks on one adapter and apply the identical chain to the others —
/// a running net whose every node holds every body in its applied store.
fn seeded_servers(n: usize) -> Vec<Adapter> {
    let mut a0 = adapter();
    let mut chain: Vec<(BlockHeader, BlockBody)> = Vec::with_capacity(n);
    for _ in 0..n {
        let (h, b) = a0.mine_block().expect("mine");
        assert_eq!(a0.ingest_block(h, b.clone()), IngestOutcome::Accepted);
        chain.push((h, b));
    }
    let mut servers = vec![a0];
    for _ in 0..2 {
        let mut s = adapter();
        for (h, b) in &chain {
            assert_eq!(s.ingest_block(*h, b.clone()), IngestOutcome::Accepted);
        }
        servers.push(s);
    }
    servers
}

/// Wire three servers and the joiner over real sockets; the joiner dials all
/// three (a joiner knows only seed addresses — nobody dials a stranger).
fn wire(servers: Vec<Adapter>, joiner: Adapter) -> (Vec<Node>, Node) {
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for (i, a) in servers.into_iter().enumerate() {
        let t = TcpTransport::bind("127.0.0.1:0").unwrap();
        addrs.push(t.local_addr().to_string());
        nodes.push(P2pNode::new(t, a, [(i as u8) + 1; 32]));
    }
    let tj = TcpTransport::bind("127.0.0.1:0").unwrap();
    let mut joiner = P2pNode::new(tj, joiner, [9u8; 32]);
    for addr in addrs {
        let pid = joiner.transport().connect(&addr).unwrap();
        joiner.add_peer(pid, Some(addr));
    }
    (nodes, joiner)
}

const CHAIN_LEN: u64 = 2_500;

/// 🔴 **THE DRILL** — empty data dir → running 3-node net → `slag=0` at the
/// servers' tip, refusing duties the whole way down, durable at the end.
#[test]
fn joins_a_running_net_from_an_empty_data_dir() {
    let servers = seeded_servers(CHAIN_LEN as usize);
    let tip_hash = servers[0].tip_hash();
    let dir = temp_dir("joiner");
    let joiner_state =
        Adapter::open(&dir, committee(), KeccakPow, MarkerVerifier, easy_sim()).expect("open");
    assert_eq!(joiner_state.tip_height(), 0, "the data dir really is empty");
    let (mut servers, mut joiner) = wire(servers, joiner_state);

    // Budget: minutes, not hours (#369 S7's scale rule). Measured 117 s in
    // release on an otherwise-idle rig (JOINER_DRILL line, 2026-08-12), so 300 s
    // is ~2.5× the observed cost — margin for a loaded rig, not slack for a
    // regression: the pre-#371-S2 window collapse would not converge in any
    // budget a suite could carry, and the stall mutation is its own test.
    let budget = Duration::from_secs(300);
    let start = Instant::now();
    let mut refused_while_syncing = false;
    let converged = loop {
        let now_ms = start.elapsed().as_millis() as u64;
        for s in servers.iter_mut() {
            s.tick(now_ms);
        }
        joiner.tick(now_ms);

        // S7 — the duty refusal, asserted mid-catch-up exactly once: a node
        // whose applied view is stale must not mine (#130), and the #200
        // exemption must not be what lets this drill pass.
        if !refused_while_syncing && joiner.node().state_lag().is_lagging() {
            assert!(!joiner.node().state_tip_mine_ready(), "the #200 exemption is not armed");
            assert!(joiner.node_mut().mine_block().is_none(), "a syncing joiner refuses to mine");
            assert!(joiner.node().lag_refusals("mine") >= 1, "and the refusal is attributed");
            refused_while_syncing = true;
        }

        let lag = joiner.node().state_lag();
        if lag.blocks() == 0 && lag.state_tip == CHAIN_LEN {
            break true;
        }
        if start.elapsed() > budget {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let elapsed = start.elapsed();

    assert!(
        converged,
        "the joiner did not reach the tip inside {budget:?}: slag={} stip={} tip={}",
        joiner.node().state_lag().blocks(),
        joiner.node().state_lag().state_tip,
        joiner.node().tip_height(),
    );
    assert!(refused_while_syncing, "the drill must have observed the syncing state");
    assert_eq!(joiner.node().tip_hash(), tip_hash, "the same block, not merely the same height");
    assert_eq!(*joiner.sync_phase(), SyncPhase::Synced);
    assert_eq!(joiner.body_requests(), 0, "and it has stopped asking");
    // An honest catch-up never trips the S3 serve budgets (S1's bound: the
    // response fits what #91's inbound budget assumes).
    for s in &servers {
        assert_eq!(s.rate_stats().throttled_body_serve, 0, "honest serving was never throttled");
    }
    // Nobody scored anybody: serving history and asking for it are both honest.
    for p in joiner.peers().all_peers() {
        assert_eq!(joiner.peers().get(p).expect("peer").score, 0);
    }

    // S6 — the measured join rate at drill scale, with its basis on the line.
    let rate_blk_min = (CHAIN_LEN as f64) / (elapsed.as_secs_f64() / 60.0);
    println!(
        "JOINER_DRILL blocks={CHAIN_LEN} elapsed_s={:.2} rate_blk_min={rate_blk_min:.0} \
         transport=tcp-loopback peers=3 bodies=coinbase-only pow=keccak-diff8",
        elapsed.as_secs_f64()
    );

    // Durability: reopen the same data dir — the applied chain is on disk, so a
    // restarted joiner resumes at the tip instead of starting the drill over.
    for s in servers.iter() {
        s.transport().shutdown();
    }
    joiner.transport().shutdown();
    drop(joiner);
    let reopened =
        Adapter::open(&dir, committee(), KeccakPow, MarkerVerifier, easy_sim()).expect("reopen");
    assert_eq!(reopened.tip_height(), CHAIN_LEN, "the join survives a restart");
    assert_eq!(reopened.tip_hash(), tip_hash);
    std::fs::remove_dir_all(&dir).ok();
}

/// 🔴 **THE MUTATION** — the same net with historical body serving disabled
/// (the pre-#182 wire, today's deployed behaviour per the task book) must
/// reproduce today's stall: the joiner holds the whole header chain and applies
/// nothing, asks outstanding, nobody banned. This is the drill detecting the
/// gap it drills — if serving's absence stopped causing the stall, this test
/// failing is the news.
#[test]
fn stall_without_historical_serving() {
    const STALL_CHAIN: u64 = 400; // the stall is scale-independent; keep it quick
    let dir = temp_dir("stalled");
    let joiner_state =
        Adapter::open(&dir, committee(), KeccakPow, MarkerVerifier, easy_sim()).expect("open");
    let (mut servers, mut joiner) = wire(seeded_servers(STALL_CHAIN as usize), joiner_state);
    for s in servers.iter_mut() {
        s.set_serve_historical_bodies(false);
    }

    // Pump until the header chain is fully across, then a further grace window
    // long enough for several re-ask rounds — the state tip must not move.
    let start = Instant::now();
    let headers_across = loop {
        let now_ms = start.elapsed().as_millis() as u64;
        for s in servers.iter_mut() {
            s.tick(now_ms);
        }
        joiner.tick(now_ms);
        if joiner.node().tip_height() == STALL_CHAIN {
            break true;
        }
        if start.elapsed() > Duration::from_secs(30) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(headers_across, "header-first sync still works without body serving");

    let grace = Instant::now();
    while grace.elapsed() < Duration::from_secs(2) {
        let now_ms = start.elapsed().as_millis() as u64;
        for s in servers.iter_mut() {
            s.tick(now_ms);
        }
        joiner.tick(now_ms);
        std::thread::sleep(Duration::from_millis(1));
    }

    // Today's stall, exactly as the fleet prints it: slag pinned at the whole
    // chain, asks outstanding, and the state tip at genesis.
    assert_eq!(joiner.node().state_lag().state_tip, 0, "nothing applied — the stall");
    assert_eq!(joiner.node().state_lag().blocks(), STALL_CHAIN, "slag pinned at the chain length");
    assert!(joiner.body_requests() > 0, "still asking — the asks are answered header-only");
    assert!(joiner.node_mut().mine_block().is_none(), "and duties stay refused (S7)");
    // The stall bans nobody in either direction (#134's law): honest headers
    // are not a fault, and asking is not a fault.
    for p in joiner.peers().all_peers() {
        assert_eq!(joiner.peers().get(p).expect("peer").score, 0);
        assert!(!joiner.peers().is_banned(p));
    }
    for s in &servers {
        for p in s.peers().all_peers() {
            assert_eq!(s.peers().get(p).expect("peer").score, 0);
        }
    }

    for s in servers.iter() {
        s.transport().shutdown();
    }
    joiner.transport().shutdown();
    std::fs::remove_dir_all(&dir).ok();
}
