//! **QUM-115 (lab #412) — the body-fetch pipeline a catch-up actually needs.**
//!
//! Checkpoint sync cleared the header wall; what it uncovered was the fetch
//! side. A joiner holding 12,400 headers and no bodies applied ~0.3 blocks/s,
//! and the reason was not bandwidth, not CPU and not the peers:
//!
//! **This node was dropping the answers it had asked for.** `crate::ratelimit`
//! sits ahead of decode by #91's decision 2 and cannot know a frame is an answer
//! to our own ask, so a body over the frame budget is dropped silently and
//! unscored — indistinguishable, from the requester's side, from a peer that
//! never replied. The ask then stands for the whole `BODY_REQUEST_TIMEOUT_MS`,
//! and with the window already full there is nothing else the node may ask for.
//! The pipeline stops dead for 15 s at a time.
//!
//! Two properties are locked here, and each is a different half of the fix:
//!
//! - **pacing** — asks never exceed what this node's own inbound budget will
//!   admit, so no answer to our own ask is ever thrown away
//!   (`a_catch_up_never_drops_the_answers_it_asked_for` is the standing guard —
//!   see its own note on why the chain length is part of the test);
//! - **width** — a node thousands of blocks behind opens
//!   `MAX_BODIES_IN_FLIGHT_CATCHUP`, and a node near the tip still opens
//!   `MAX_BODIES_IN_FLIGHT`, because the steady constant's own arithmetic is
//!   about the 75 s block rate and does not transfer to a replay.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{decode_inv, InvKind};
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::node::{
    BODY_ASK_FRAME_HEADROOM, CATCHUP_LAG_BLOCKS, MAX_BODIES_IN_FLIGHT,
    MAX_BODIES_IN_FLIGHT_CATCHUP, MAX_BODIES_PER_GETDATA,
};
use qlab_p2p::peer::PeerId;
use qlab_p2p::ratelimit::RateLimits;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Frame, MsgType};
use qlab_p2p::P2pNode;

#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

fn easy_sim() -> SimConfig {
    SimConfig {
        block_time_secs: 2,
        genesis_difficulty: 8,
        mine_nonce_budget: 5_000_000,
        ..SimConfig::default()
    }
}

fn adapter() -> Adapter {
    let (committee, _v) = devnet_committee(7);
    NodeAdapter::new(
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    )
}

/// The same monotone sim clock the #130 (c) tests use, so the inbound buckets
/// refill on simulated time and a run does not depend on machine speed.
const SIM_TICK_MS: u64 = 10;

fn pair() -> (Node, Node, Arc<InProcHub>) {
    let hub = InProcHub::new();
    let a = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let b = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    (a, b, hub)
}

fn mine_chain(server: &mut Node, n: usize) -> Vec<(BlockHeader, BlockBody)> {
    (0..n)
        .map(|_| {
            let (h, body) = server.node_mut().mine_block().expect("mine");
            assert_eq!(server.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
            (h, body)
        })
        .collect()
}

/// Fork choice at the tip, the state machine at height 1 — the joiner's shape.
fn lagging_at_one(node: &mut Node, blocks: &[(BlockHeader, BlockBody)]) {
    assert_eq!(
        node.node_mut().ingest_block(blocks[0].0, blocks[0].1.clone()),
        IngestOutcome::Accepted
    );
    for (h, _) in &blocks[1..] {
        assert_eq!(node.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    assert_eq!(node.node().state_lag().state_tip, 1);
}

/// Handshake to `Ready` and stop, with the server ticked once so it never
/// answers the batch the requester sends on reaching `Ready`. The asks are then
/// still outstanding and countable.
fn handshake_only(server: &mut Node, behind: &mut Node) {
    server.tick(SIM_TICK_MS);
    behind.tick(SIM_TICK_MS);
}

/// A lag of more than [`CATCHUP_LAG_BLOCKS`] opens the catch-up window; the
/// steady window is what a node near the tip still gets.
///
/// Both directions in one test on purpose: the constant is a threshold, and a
/// threshold asserted on one side only is half a test.
#[test]
fn the_window_widens_for_a_catch_up_and_stays_narrow_near_the_tip() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 200);
    lagging_at_one(&mut behind, &blocks);
    assert!(
        behind.node().state_lag().blocks() > CATCHUP_LAG_BLOCKS,
        "the premise: this node is catching up, not keeping up"
    );
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    handshake_only(&mut server, &mut behind);
    assert_eq!(
        behind.body_requests(),
        MAX_BODIES_IN_FLIGHT_CATCHUP,
        "a catch-up opens the wide window, not the steady 16"
    );

    // The other side of the threshold: 40 blocks of chain is a lag of 39, and
    // that node is keeping up — 16 is the right number and it is unchanged.
    let (mut server, mut near, _hub) = pair();
    let blocks = mine_chain(&mut server, 40);
    lagging_at_one(&mut near, &blocks);
    assert!(near.node().state_lag().blocks() <= CATCHUP_LAG_BLOCKS);
    server.add_peer(PeerId(2), None);
    near.add_peer(PeerId(1), None);
    handshake_only(&mut server, &mut near);
    assert_eq!(
        near.body_requests(),
        MAX_BODIES_IN_FLIGHT,
        "near the tip the steady window is untouched"
    );
}

/// A catch-up-width batch reaches the peer as several `GetData` messages, none
/// of them over [`MAX_BODIES_PER_GETDATA`].
///
/// This is what keeps the serve-side cap honest. That constant answers items
/// past it **header-only**, so a single 128-item inv would come back as 16
/// bodies and 112 headers — 112 asks that look answered on the wire, are not,
/// and each burns a 15 s re-ask. Splitting is why the wider window is safe
/// against a peer running an image that predates it.
#[test]
fn a_catch_up_batch_is_split_into_serve_sized_getdata_messages() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 200);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    handshake_only(&mut server, &mut behind);

    // Read the frames off the server's transport instead of ticking it, so what
    // is asserted is what went on the wire rather than what the server made of it.
    let mut items = 0usize;
    let mut messages = 0usize;
    for (_, frame) in server.transport().poll() {
        let Ok(Frame::Known(env)) = Frame::decode(&frame) else { continue };
        if env.msg_type != MsgType::GetData {
            continue;
        }
        let inv = decode_inv(&env.payload).expect("our own inv decodes");
        let blocks_asked = inv.items.iter().filter(|i| i.kind == InvKind::Block).count();
        if blocks_asked == 0 {
            continue;
        }
        assert!(
            blocks_asked <= MAX_BODIES_PER_GETDATA,
            "no message over the serve-side cap: {blocks_asked} items"
        );
        items += blocks_asked;
        messages += 1;
    }
    assert_eq!(items, MAX_BODIES_IN_FLIGHT_CATCHUP, "the whole window did go out");
    assert!(messages > 1, "and it took more than one message to carry it");
}

/// 🔴 **The defect, as a property: the requester never asks for more than its
/// own inbound limiter will admit.**
///
/// Driven through a deliberately tiny frame budget so the bound is exact and
/// does not depend on timing: with the burst spent down, the asks outstanding
/// are what is left after [`BODY_ASK_FRAME_HEADROOM`] — never the full window,
/// and never more than the node can receive.
#[test]
fn asks_are_capped_by_this_nodes_own_inbound_frame_budget() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 200);
    lagging_at_one(&mut behind, &blocks);
    // A burst of 40 frames and no refill: the arithmetic below is then a fact
    // about the budget rather than about how fast this machine ran the test.
    behind.set_rate_limits(RateLimits {
        msg_burst: 40,
        msg_refill_per_sec: 0,
        ..RateLimits::default()
    });
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    handshake_only(&mut server, &mut behind);

    let asked = behind.body_requests();
    assert!(asked > 0, "it did ask — otherwise the bound below is vacuous");
    assert!(
        (asked as u64) <= 40 - BODY_ASK_FRAME_HEADROOM,
        "asked for {asked} bodies against a 40-frame budget with {BODY_ASK_FRAME_HEADROOM} \
         held back — the window is {MAX_BODIES_IN_FLIGHT_CATCHUP}, and taking it here is \
         exactly the over-ask that gets thrown away at the limiter"
    );
}

/// 🔴 **THE GUARD — a catch-up never drops the answers it asked for.**
///
/// The whole defect in one number. Run the real requester against a real server
/// until the state machine reaches the tip, and assert the joiner's own limiter
/// threw away **nothing**.
///
/// **The chain length is load-bearing and 200 was not enough.** The budget is
/// `MSG_BURST` (256) plus `MSG_REFILL_PER_SEC` on the sim clock (0.64 frames per
/// 10 ms tick), so a run whose whole body traffic fits inside the burst cannot
/// throttle however carelessly it asks — mutation-checked: with the pacing
/// removed, 200 blocks still passed and 600 fails on this assertion. 600 bodies
/// against a 256-frame burst is the smallest scale at which the defect is
/// reachable, which is what makes this a guard rather than a decoration.
///
/// Nobody is scored in either direction — asking is not a fault and serving is
/// not a fault (#134's law), and a throttle is this node's limit, not a peer's.
#[test]
fn a_catch_up_never_drops_the_answers_it_asked_for() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 600);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);

    let mut now = 0u64;
    let mut converged = false;
    for _ in 0..4_000 {
        now += SIM_TICK_MS;
        server.tick(now);
        behind.tick(now);
        if behind.node().state_lag().blocks() == 0 {
            converged = true;
            break;
        }
    }
    assert!(converged, "the state machine reached the tip: slag={}", behind.node().state_lag().blocks());
    assert_eq!(behind.node().state_lag().state_tip, 600);
    assert_eq!(
        behind.rate_stats().throttled_frames,
        0,
        "a node that asks for no more than it can receive throws none of it away"
    );
    assert_eq!(behind.body_requests(), 0, "and it has stopped asking");
    for p in behind.peers().all_peers() {
        assert_eq!(behind.peers().get(p).expect("peer").score, 0);
    }
    for p in server.peers().all_peers() {
        assert_eq!(server.peers().get(p).expect("peer").score, 0);
    }
}
