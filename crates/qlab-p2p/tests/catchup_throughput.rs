//! **Lab #427 — catch-up body-fetch throughput: the ~1.3 blk/s serializer,
//! reproduced and fixed.**
//!
//! ## The mechanism these tests lock out
//!
//! The live evidence (the #445 macOS joiner log, `logs/macos-miner-437.log` on
//! the operator rig, RECOVERY→catch-up span): applied-tip progress came in
//! bursts of ~96 blocks — exactly [`qlab_p2p::node::MAX_BODIES_IN_FLIGHT_CATCHUP`]
//! — separated by 30–120 s of nothing, with the ask set collapsed to a residue
//! (`bask=19@1135` against `slag=12611`) and ~2.6 wire answers per block over
//! the whole 13,7xx-block span. Two requester-side defects compose into that:
//!
//! 1. **The ask set was anchored to the applied tip** — `missing_body_hashes`
//!    scanned `window` HEIGHTS above the fork point, not `window` MISSING
//!    bodies, so once most of the span was buffered the pipeline could fetch
//!    nothing new until the low residue landed.
//! 2. **An honest decline cost as much as silence** — a peer answering
//!    `GetData(Block)` header-only ("I hold the header, not the body", #199) or
//!    `NotFound` left the ask parked on it until the 15 s
//!    [`qlab_p2p::node::BODY_REQUEST_TIMEOUT_MS`], and the re-ask rotation was
//!    free to land on a non-possessing peer again.
//!
//! Together: rate ≈ window ÷ (E[rounds] × 15 s) ≈ 96 ÷ 74 s ≈ **1.3 blk/s**,
//! independent of CPU (both the 2-vCPU t4g and the M-class laptop measured it)
//! and of RTT (0.1–0.2 s is noise against the 15 s rungs). The clock was the
//! timeout, not the machine.
//!
//! The fix is requester-side only: the ask set slides to the first `window`
//! missing bodies (bounded by the pending buffer's own admission arithmetic),
//! and a decline releases the in-flight slot for an immediate re-ask on a peer
//! that has not declined — with the full-decline case left exactly on the old
//! timeout pacing (`stall_without_historical_serving` still passes unmodified).

use std::sync::Arc;
use std::time::{Duration, Instant};

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, IngestOutcome};
use qlab_p2p::node::BODY_REQUEST_TIMEOUT_MS;
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport, TcpTransport};
use qlab_p2p::P2pNode;

#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type InProcNode = P2pNode<InProcTransport, Adapter>;
type TcpNode = P2pNode<TcpTransport, Adapter>;

/// Fast blocks and trivial PoW — these tests measure the transfer pipeline, not
/// the hash function (the joiner drill's own justification).
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

/// Mine `n` blocks on a throwaway proposer; every server in a test ingests the
/// same chain so each holds every body in its applied store.
fn mined_chain(n: usize) -> Vec<(BlockHeader, BlockBody)> {
    let mut proposer = adapter();
    (0..n)
        .map(|_| {
            let (h, b) = proposer.mine_block().expect("mine");
            assert_eq!(proposer.ingest_block(h, b.clone()), IngestOutcome::Accepted);
            (h, b)
        })
        .collect()
}

const SIM_TICK_MS: u64 = 10;

/// Drive nodes for `rounds` ticks on a shared monotone sim clock from `base_ms`;
/// returns the clock it stopped at. The logical clock is the point: it lets a
/// test assert "this happened WITHOUT the 15 s timeout elapsing".
fn run(nodes: &mut [&mut InProcNode], rounds: u64, base_ms: u64) -> u64 {
    let mut now = base_ms;
    for _ in 0..rounds {
        now += SIM_TICK_MS;
        for n in nodes.iter_mut() {
            n.tick(now);
        }
    }
    now
}

fn slag(node: &InProcNode) -> u64 {
    node.node().state_lag().blocks()
}

// ---------------------------------------------------------------------------
// The decline re-route (F1), deterministically
// ---------------------------------------------------------------------------

/// 🔴 **A header-only decline is answered by re-asking a DIFFERENT peer on the
/// next tick — not by waiting out the 15 s timeout.** One peer holds only
/// headers (every restarted node, every joiner), one holds the bodies. Blind
/// rotation parks ~half the window on the header-only peer each rung; before
/// #427 each of those asks burned a full timeout, which is the live net's
/// measured 2.6 rounds × 15 s per block. The whole catch-up here must complete
/// in sim-time well under ONE timeout.
#[test]
fn a_declined_ask_re_routes_to_another_peer_without_waiting_out_the_timeout() {
    let blocks = mined_chain(40);

    let hub = InProcHub::new();
    let mut header_only =
        P2pNode::new(InProcTransport::new(PeerId(3), Arc::clone(&hub)), adapter(), [3; 32]);
    for (h, _) in &blocks {
        assert_eq!(header_only.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    let mut server =
        P2pNode::new(InProcTransport::new(PeerId(5), Arc::clone(&hub)), adapter(), [5; 32]);
    for (h, b) in &blocks {
        assert_eq!(server.node_mut().ingest_block(*h, b.clone()), IngestOutcome::Accepted);
    }
    let mut asker =
        P2pNode::new(InProcTransport::new(PeerId(4), Arc::clone(&hub)), adapter(), [4; 32]);
    for (h, _) in &blocks {
        assert_eq!(asker.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    hub.link(PeerId(3), PeerId(4));
    hub.link(PeerId(5), PeerId(4));
    header_only.add_peer(PeerId(4), None);
    server.add_peer(PeerId(4), None);
    asker.add_peer(PeerId(3), None);
    asker.add_peer(PeerId(5), None);

    // 400 ticks × 10 ms = 4,000 ms of sim time: less than a third of ONE
    // BODY_REQUEST_TIMEOUT_MS rung. Convergence inside it is only possible if a
    // decline releases the slot for an immediate re-ask.
    let stopped_at = run(&mut [&mut header_only, &mut server, &mut asker], 400, 0);
    assert!(stopped_at < BODY_REQUEST_TIMEOUT_MS / 3, "the budget itself stayed sub-timeout");

    assert_eq!(slag(&asker), 0, "caught up without a single timeout rung");
    assert_eq!(
        asker.node().state_lag().state_tip,
        40,
        "the whole chain applied while the timeout never elapsed"
    );
    // The decline was honest and cost the decliner nothing (#134's law).
    assert_eq!(asker.peers().get(PeerId(3)).expect("peer").score, 0);
    assert!(!asker.peers().is_banned(PeerId(3)));
}

/// **When EVERY ready peer has declined, the retry stays timeout-paced** — the
/// pre-#427 behaviour, kept on purpose: this is the genuinely-unobtainable case
/// (#200's exemption feeds off it), and an immediate-retry loop here would be a
/// tick-rate re-ask storm at the only peers who already said no.
#[test]
fn when_every_ready_peer_has_declined_the_retry_stays_timeout_paced() {
    let blocks = mined_chain(20);

    let hub = InProcHub::new();
    let mut a = P2pNode::new(InProcTransport::new(PeerId(3), Arc::clone(&hub)), adapter(), [3; 32]);
    let mut b = P2pNode::new(InProcTransport::new(PeerId(6), Arc::clone(&hub)), adapter(), [6; 32]);
    for (h, _) in &blocks {
        assert_eq!(a.node_mut().ingest_header(*h), IngestOutcome::Accepted);
        assert_eq!(b.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    let mut asker =
        P2pNode::new(InProcTransport::new(PeerId(4), Arc::clone(&hub)), adapter(), [4; 32]);
    for (h, _) in &blocks {
        assert_eq!(asker.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    hub.link(PeerId(3), PeerId(4));
    hub.link(PeerId(6), PeerId(4));
    a.add_peer(PeerId(4), None);
    b.add_peer(PeerId(4), None);
    asker.add_peer(PeerId(3), None);
    asker.add_peer(PeerId(6), None);

    // Both peers decline everything. After the one consult-each-peer cascade the
    // asks must PARK: still outstanding, nothing applied, and — the bound this
    // test exists for — no unbounded re-ask churn inside the timeout window.
    run(&mut [&mut a, &mut b, &mut asker], 500, 0); // 5,000 ms sim — inside one rung
    assert_eq!(slag(&asker), 20, "nothing could be served, so nothing was applied");
    assert!(asker.body_requests() > 0, "the asks are parked, not abandoned");
    let parked = asker.body_requests();

    // Inside the same rung nothing changes — the park is real.
    run(&mut [&mut a, &mut b, &mut asker], 500, 5_000);
    assert_eq!(asker.body_requests(), parked, "no churn inside the timeout window");

    // Past the rung the ladder re-asks (and the peers decline again) — the ask
    // set neither leaks nor gives up.
    run(&mut [&mut a, &mut b, &mut asker], 200, BODY_REQUEST_TIMEOUT_MS + 1_000);
    assert!(asker.body_requests() > 0, "the ladder keeps climbing after the rung");
    assert_eq!(asker.peers().get(PeerId(3)).expect("peer").score, 0, "declining stays unscored");
}

// ---------------------------------------------------------------------------
// The drill: a mixed-serving fleet over real TCP (the #427 shape end to end)
// ---------------------------------------------------------------------------

/// Wire `servers` and a fresh joiner over real sockets; the joiner dials all of
/// them (a joiner knows only seed addresses).
fn wire_tcp(servers: Vec<Adapter>) -> (Vec<TcpNode>, TcpNode) {
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for (i, a) in servers.into_iter().enumerate() {
        let t = TcpTransport::bind("127.0.0.1:0").unwrap();
        addrs.push(t.local_addr().to_string());
        nodes.push(P2pNode::new(t, a, [(i as u8) + 1; 32]));
    }
    let tj = TcpTransport::bind("127.0.0.1:0").unwrap();
    let mut joiner = P2pNode::new(tj, adapter(), [9u8; 32]);
    for addr in addrs {
        let pid = joiner.transport().connect(&addr).unwrap();
        joiner.add_peer(pid, Some(addr));
    }
    (nodes, joiner)
}

/// 🔴 **THE #427 DRILL — the live fleet's shape: 4 peers, only 2 possess the
/// bodies.** A fresh joiner syncs a 400-block chain over real TCP against a
/// fleet where half the peers answer `GetData(Block)` header-only (a restarted
/// node's honest answer — #135: `P2pNode::blocks` is not persisted; #199:
/// possession-based serving). Before #427 this topology is the measured
/// ~1.3 blk/s ladder — 400 blocks would need ~5 minutes of 15 s rungs and this
/// budget CANNOT hold; after it, a decline re-routes within a round trip and the
/// window slides ahead, so wall-clock is loopback-bounded.
#[test]
fn a_joiner_against_a_half_serving_fleet_is_not_paced_by_the_timeout_ladder() {
    const CHAIN: u64 = 400;
    let blocks = mined_chain(CHAIN as usize);
    let mut servers: Vec<Adapter> = Vec::new();
    for _ in 0..4 {
        let mut s = adapter();
        for (h, b) in &blocks {
            assert_eq!(s.ingest_block(*h, b.clone()), IngestOutcome::Accepted);
        }
        servers.push(s);
    }
    let (mut servers, mut joiner) = wire_tcp(servers);
    // Half the fleet serves headers only — the drill's mutation switch, used
    // here as the live condition rather than the negative control.
    servers[0].set_serve_historical_bodies(false);
    servers[1].set_serve_historical_bodies(false);

    let budget = Duration::from_secs(120);
    let start = Instant::now();
    let converged = loop {
        let now_ms = start.elapsed().as_millis() as u64;
        for s in servers.iter_mut() {
            s.tick(now_ms);
        }
        joiner.tick(now_ms);
        let lag = joiner.node().state_lag();
        if lag.blocks() == 0 && lag.state_tip == CHAIN {
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
        "mixed-serving catch-up fell back onto the timeout ladder: stip={} slag={} after {elapsed:?}",
        joiner.node().state_lag().state_tip,
        joiner.node().state_lag().blocks(),
    );
    // The hard bound: the pre-#427 mechanism needs ≥ ceil(400/96) − 1 ≈ 3 full
    // 15 s rungs even with a PERFECT rotation (every window has a residue parked
    // on a non-serving peer), and measured live it needed ~2.6 rungs per BLOCK.
    // 30 s of wall-clock is unreachable on the old code and lax for the new.
    assert!(
        elapsed < Duration::from_secs(30),
        "convergence took {elapsed:?} — timeout rungs are back in the pipeline"
    );
    // Declining peers are honest peers (#134): nobody was scored in either direction.
    for pid in joiner.peers().all_peers() {
        assert_eq!(joiner.peers().get(pid).expect("peer").score, 0);
        assert!(!joiner.peers().is_banned(pid));
    }
    for s in &servers {
        for pid in s.peers().all_peers() {
            assert_eq!(s.peers().get(pid).expect("peer").score, 0);
        }
    }

    let rate = CHAIN as f64 / elapsed.as_secs_f64();
    println!(
        "CATCHUP_DRILL blocks={CHAIN} elapsed_s={:.2} rate_blk_s={rate:.1} \
         transport=tcp-loopback peers=4 serving=2 bodies=coinbase-only pow=keccak-diff8",
        elapsed.as_secs_f64()
    );

    for s in servers.iter() {
        s.transport().shutdown();
    }
    joiner.transport().shutdown();
}

/// **The measurement variant** (ignored in the suite; run explicitly for the
/// #427 before/after table). Same topology as the drill, no convergence
/// assertion, a long budget, and a `CATCHUP_MEASURE` line per 25-block stride so
/// the burst-vs-ladder shape is visible, not just the average.
///
/// ```sh
/// cargo test -p qlab-p2p --release --test catchup_throughput -- --ignored --nocapture
/// ```
#[test]
#[ignore = "measurement harness — run explicitly with --ignored --nocapture"]
fn measure_mixed_serving_catchup_rate() {
    const CHAIN: u64 = 400;
    let blocks = mined_chain(CHAIN as usize);
    let mut servers: Vec<Adapter> = Vec::new();
    for _ in 0..4 {
        let mut s = adapter();
        for (h, b) in &blocks {
            assert_eq!(s.ingest_block(*h, b.clone()), IngestOutcome::Accepted);
        }
        servers.push(s);
    }
    let (mut servers, mut joiner) = wire_tcp(servers);
    servers[0].set_serve_historical_bodies(false);
    servers[1].set_serve_historical_bodies(false);

    let budget = Duration::from_secs(600);
    let start = Instant::now();
    let mut last_stride = 0u64;
    loop {
        let now_ms = start.elapsed().as_millis() as u64;
        for s in servers.iter_mut() {
            s.tick(now_ms);
        }
        joiner.tick(now_ms);
        let stip = joiner.node().state_lag().state_tip;
        if stip / 25 > last_stride {
            last_stride = stip / 25;
            println!(
                "CATCHUP_MEASURE stip={stip} elapsed_s={:.2} breq={}",
                start.elapsed().as_secs_f64(),
                joiner.body_requests()
            );
        }
        if (joiner.node().state_lag().blocks() == 0 && stip == CHAIN)
            || start.elapsed() > budget
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let elapsed = start.elapsed();
    let applied = joiner.node().state_lag().state_tip;
    println!(
        "CATCHUP_MEASURE_FINAL blocks_applied={applied}/{CHAIN} elapsed_s={:.2} rate_blk_s={:.2} \
         transport=tcp-loopback peers=4 serving=2 bodies=coinbase-only pow=keccak-diff8",
        elapsed.as_secs_f64(),
        applied as f64 / elapsed.as_secs_f64()
    );
    for s in servers.iter() {
        s.transport().shutdown();
    }
    joiner.transport().shutdown();
}
