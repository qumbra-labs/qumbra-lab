//! **Issue #200 — a body can become unobtainable net-wide.**
//!
//! `#198` / PR #199 made serving key on possession. That cannot recover a net
//! where **no host ever applied** the contested block: possession-based serving
//! has no possessor. The archive check on #197 established exactly that for
//! height 1058 on the live T0 net.
//!
//! This baton is the second line: after N cadences of lagging with an
//! outstanding, unserved body request, a node concludes the body is unobtainable
//! and mines on its **verified state tip**, producing a sibling that fork choice
//! resolves.
//!
//! 🔴 The duty gate stays. A node that is lagging **and being served** must still
//! refuse — that is the whole distinction, and the negative half is locked here
//! (and re-asserted against the #198 test that already carries it).

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

const NET: usize = 4;
const SIM_TICK_MS: u64 = 10;

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

fn adapter(rkm: u64) -> Adapter {
    let (committee, _v) = devnet_committee(7);
    let mut a = NodeAdapter::new(
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    );
    a.set_miner_rkm([rkm; 4]);
    a
}

fn mine_on(a: &mut Adapter) -> (BlockHeader, BlockBody) {
    let (h, b) = a.mine_block().expect("mine");
    assert_eq!(a.ingest_block(h, b.clone()), IngestOutcome::Accepted);
    (h, b)
}

fn slag(node: &Node) -> u64 {
    node.node().state_lag().blocks()
}

/// Advance every node to `now_ms` (and every intermediate tick so body-request
/// re-asks fire on their 15 s ladder). Returns the last `now` used.
fn drive(net: &mut [Node], hub: &InProcHub, from_ms: u64, to_ms: u64) -> u64 {
    let _ = hub;
    let mut now = from_ms;
    while now < to_ms {
        now = (now + SIM_TICK_MS).min(to_ms);
        for n in net.iter_mut() {
            n.tick(now);
        }
    }
    now
}

/// Fully mesh four nodes on an in-process hub.
fn mesh(hub: &InProcHub, net: &mut [Node]) {
    for i in 0..net.len() {
        for j in 0..net.len() {
            if i != j {
                hub.link(PeerId(i as u64 + 1), PeerId(j as u64 + 1));
            }
        }
    }
    for i in 0..net.len() {
        for j in 0..net.len() {
            if i != j {
                net[i].add_peer(PeerId(j as u64 + 1), None);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. ACCEPTANCE — the #197 shape with no possessor, and the net resumes
// ---------------------------------------------------------------------------

/// **Every node holds a header whose body exists nowhere, and the net resumes
/// by producing a sibling — not by the body arriving.**
///
/// Construction:
/// 1. Off-net, mine `L1` (the unobtainable body). Discard the factory.
/// 2. All four nodes ingest `L1`'s **header only**. Nobody ever holds the body.
/// 3. All four sit at `slag=1`, `mine_block() = None`, and after linking they
///    issue body requests that nobody can answer.
/// 4. Drive time past the unobtainable threshold. The exemption arms.
/// 5. Nodes mine on their state tip (genesis), produce a competing height-1
///    branch, and extend it until fork choice adopts it.
///
/// **Mutation-check target:** with the exemption disabled (or the threshold
/// never reached), 600 mine rounds produce zero blocks — the #199 negative
/// shape. This test starts from that standstill and ends with blocks.
#[test]
fn i200_no_possessor_the_net_resumes_by_mining_on_the_state_tip() {
    // The unobtainable body — mined off-net so no node on the hub can source it.
    let mut factory = adapter(0x11);
    let (lh1, _lb1) = mine_on(&mut factory);
    let l1 = lh1.header_hash();
    drop(factory);

    let hub = InProcHub::new();
    let mut net: Vec<Node> = (0..NET)
        .map(|i| {
            let id = PeerId(i as u64 + 1);
            P2pNode::new(
                InProcTransport::new(id, Arc::clone(&hub)),
                adapter(0xC0 + i as u64),
                [i as u8 + 1; 32],
            )
        })
        .collect();

    // Every node holds the header; nobody has the body. This is the #197 fact
    // the archive established: 1058 appears only as tip=/diff=, never applied.
    for n in net.iter_mut() {
        assert_eq!(n.node_mut().ingest_header(lh1), IngestOutcome::Accepted);
        assert_eq!(n.node().chain().tip_height(), 1);
        assert_eq!(n.node().state_lag().state_tip, 0);
        assert_eq!(slag(n), 1);
        assert!(n.node().held_body(&l1).is_none(), "no possessor anywhere");
        assert!(
            n.node_mut().mine_block().is_none(),
            "the duty gate refuses — the halt is correct"
        );
        assert!(!n.node().state_tip_mine_ready(), "exemption not yet armed");
    }

    mesh(&hub, &mut net);

    // ---- the standstill, before the threshold --------------------------------
    // Drive long enough for body requests to issue, but short of the threshold.
    // At block_time=2, threshold = 2 × 8 × 2 × 1000 = 32_000 ms.
    let threshold = net[0].node().unobtainable_threshold_ms();
    assert_eq!(threshold, 32_000, "easy_sim arithmetic: 2 cadences × 8 × 2 s");
    let mut now = 0u64;
    now = drive(&mut net, &hub, now, threshold / 2);

    for (i, n) in net.iter_mut().enumerate() {
        assert!(
            n.body_requests() > 0,
            "node{i}: must be asking — the exemption keys on an outstanding breq"
        );
        assert_eq!(slag(n), 1, "node{i}: still lagging");
        assert!(
            !n.node().state_tip_mine_ready(),
            "node{i}: half a threshold is not exhaustion"
        );
        assert!(
            n.node_mut().mine_block().is_none(),
            "node{i}: still refused before exhaustion"
        );
    }

    // ---- cross the threshold -------------------------------------------------
    now = drive(&mut net, &hub, now, threshold + SIM_TICK_MS);

    // Re-tick once more so any node whose asks rolled over mid-window re-arms.
    now = drive(&mut net, &hub, now, now + BODY_REQUEST_TIMEOUT_MS + SIM_TICK_MS);
    let armed = net.iter().filter(|n| n.node().state_tip_mine_ready()).count();
    assert!(
        armed > 0,
        "at least one node must arm the exemption after {threshold} ms of unserved asks"
    );

    // ---- the net resumes by mining siblings on the state tip -----------------
    let frozen_tip = 1u64;
    let mut produced = 0u32;
    let mut first_producer = None;
    // Need enough blocks for a competing branch to out-work the incumbent
    // (equal-work keeps the unobtainable L1 as tip until height 2 on the sibling
    // branch carries strictly more cumulative work).
    for round in 0..800u32 {
        now += SIM_TICK_MS;
        for n in net.iter_mut() {
            n.tick(now);
        }
        let miner = round as usize % NET;
        if let Some((h, b)) = net[miner].node_mut().mine_block() {
            // Under the exemption the parent must be the state tip, never L1.
            assert_ne!(
                h.prev, l1,
                "round {round}: mined on the unobtainable header — the exemption \
                 must never extend a tip this node cannot verify"
            );
            let (coinbase, rkm) = b.single_payee_parts().expect("current-cap body");
            net[miner].announce_block(h, b.txs, coinbase, rkm, 0);
            produced += 1;
            first_producer.get_or_insert(miner);
        }
        if produced >= 4 {
            break;
        }
    }
    // Settle delivery.
    for _ in 0..200u32 {
        now += SIM_TICK_MS;
        for n in net.iter_mut() {
            n.tick(now);
        }
    }

    assert!(
        first_producer.is_some(),
        "no node ever cleared the gate — the #199 negative shape, and this test \
         must not reproduce it"
    );
    assert!(
        produced >= 2,
        "only {produced} blocks produced — a single equal-work sibling cannot \
         displace the incumbent tip; the branch must extend"
    );

    // The unobtainable body never arrived. Recovery is by sibling, not by serve.
    for (i, n) in net.iter().enumerate() {
        assert!(
            n.node().held_body(&l1).is_none(),
            "node{i}: L1's body still exists nowhere — recovery must not depend on it"
        );
    }

    // At least one node's fork-choice tip advanced past the frozen height, and
    // its state machine is caught up on a chain it can actually verify.
    let advanced = net
        .iter()
        .filter(|n| n.node().chain().tip_height() > frozen_tip)
        .count();
    assert!(
        advanced > 0,
        "no node's tip advanced past the frozen height — the net did not resume"
    );
    let caught_up = net.iter().filter(|n| slag(n) == 0).count();
    assert!(
        caught_up > 0,
        "no node reached slag=0 — mining on the state tip did not close the gap"
    );
    // The exemption counter moved on whoever produced under it.
    let mines: u64 = net.iter().map(|n| n.node().state_tip_mines()).sum();
    assert!(
        mines > 0,
        "qumbra_state_tip_mines_total stayed at 0 — the exemption path was not taken"
    );
}

// Re-export so the test can name the body-request ladder without a private path.
use qlab_p2p::node::BODY_REQUEST_TIMEOUT_MS;

// ---------------------------------------------------------------------------
// 2. THE GATE SURVIVES — lagging and being served still refuses
// ---------------------------------------------------------------------------

/// **A lagging node that is being served must still refuse.**
///
/// This is the half the task book names as non-optional, and it is the one that
/// says what the exemption is *not*. The server holds every body; the lagging
/// node receives them over the wire; the refusal holds for the whole catch-up
/// and only lifts when `slag` reaches zero — even if wall time past the
/// unobtainable threshold elapses while bodies are in flight.
///
/// Cross-check: `possession_serving::the_duty_gate_still_refuses_to_mine_while_lagging_and_receiving`
/// is the #198 form of the same assertion (short of the threshold). This one
/// deliberately runs **past** the threshold so a widened exemption would fail it.
#[test]
fn i200_lagging_and_being_served_still_refuses_past_the_threshold() {
    let mut factory = adapter(0xF0);
    let chain: Vec<(BlockHeader, BlockBody)> = (0..4).map(|_| mine_on(&mut factory)).collect();

    let hub = InProcHub::new();
    let mut server =
        P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(0xF0), [1; 32]);
    let mut behind =
        P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(0xB1), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);

    // Server holds every body; behind holds every HEADER only — slag=4.
    for (h, b) in &chain {
        assert_eq!(server.node_mut().ingest_block(*h, b.clone()), IngestOutcome::Accepted);
        assert_eq!(behind.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    assert_eq!(slag(&behind), 4);

    let threshold = behind.node().unobtainable_threshold_ms();
    let mut refused_while_receiving = 0u32;
    let mut cleared_at = None;
    let mut now = 0u64;
    // Drive well past the threshold. If the exemption widened into the rule, a
    // lagging-and-receiving node would arm and mine a sibling of a body it is
    // about to be served — exactly the invalid-chain risk the gate exists to stop.
    let budget = threshold * 3;
    while now < budget {
        now += SIM_TICK_MS;
        server.tick(now);
        let frames = behind.tick(now);
        if slag(&behind) > 0 {
            assert!(
                !behind.node().state_tip_mine_ready(),
                "at {now} ms (threshold {threshold}): exemption armed while being served"
            );
            assert!(
                behind.node_mut().mine_block().is_none(),
                "at {now} ms: lagging by {} and mined anyway",
                slag(&behind)
            );
            if frames > 0 {
                refused_while_receiving += 1;
            }
        } else if cleared_at.is_none() {
            cleared_at = Some(now);
        }
    }
    assert!(
        refused_while_receiving > 0,
        "the refusal was never exercised on a tick that delivered frames"
    );
    assert!(
        cleared_at.is_some(),
        "the lag never cleared — the server should have served every body"
    );
    assert_eq!(slag(&behind), 0);
    assert!(
        !behind.node().state_tip_mine_ready(),
        "caught up ⇒ the exemption is disarmed"
    );
    assert!(
        behind.node_mut().mine_block().is_some(),
        "caught up ⇒ the duty is allowed on the fork-choice tip"
    );
    assert_eq!(
        behind.node().state_tip_mines(),
        0,
        "a node that was being served must not have mined under the exemption"
    );
}

// ---------------------------------------------------------------------------
// 3. MUTATION SHAPE — without crossing the threshold, zero blocks
// ---------------------------------------------------------------------------

/// **The negative the #199 report modelled:** from the no-possessor standstill,
/// if the exemption never arms, 600 mine rounds produce nothing.
///
/// This is not a separate code path — it is the pre-threshold half of the
/// acceptance test, stated so a future change that mines on state tip the
/// moment `slag>0` fails a named assertion rather than silently "improving"
/// recovery at the cost of the safety rule.
#[test]
fn i200_before_exhaustion_the_no_possessor_standstill_produces_nothing() {
    let mut factory = adapter(0x11);
    let (lh1, _) = mine_on(&mut factory);
    drop(factory);

    let hub = InProcHub::new();
    let mut net: Vec<Node> = (0..NET)
        .map(|i| {
            P2pNode::new(
                InProcTransport::new(PeerId(i as u64 + 1), Arc::clone(&hub)),
                adapter(0xD0 + i as u64),
                [i as u8 + 1; 32],
            )
        })
        .collect();
    for n in net.iter_mut() {
        assert_eq!(n.node_mut().ingest_header(lh1), IngestOutcome::Accepted);
    }
    mesh(&hub, &mut net);

    let threshold = net[0].node().unobtainable_threshold_ms();
    // Stay strictly below half the threshold for the whole run.
    let mut produced = 0u32;
    for round in 0..600u32 {
        // Keep now well below the threshold even across 600 rounds.
        let now = (round as u64 + 1) * SIM_TICK_MS;
        assert!(now < threshold / 2, "test clock drifted into the exemption window");
        for n in net.iter_mut() {
            n.tick(now);
        }
        let miner = round as usize % NET;
        if net[miner].node_mut().mine_block().is_some() {
            produced += 1;
        }
    }
    assert_eq!(
        produced, 0,
        "600 rounds below the threshold produced {produced} blocks — the duty \
         gate is no longer holding"
    );
    for n in &net {
        assert!(!n.node().state_tip_mine_ready());
        assert_eq!(n.node().state_tip_mines(), 0);
    }
}

// ---------------------------------------------------------------------------
// 4. UNIT — the threshold is cadence × block_time, not a bare second count
// ---------------------------------------------------------------------------

#[test]
fn i200_threshold_is_n_cadences_of_network_time() {
    let a = adapter(0x01);
    let n = qlab_p2p::adapter::UNOBTAINABLE_BODY_CADENCES;
    let cadence = qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS;
    let bt = easy_sim().block_time_secs;
    assert_eq!(n, 2, "the number the PR body argues for");
    assert_eq!(
        a.unobtainable_threshold_ms(),
        n * cadence * bt * 1_000,
        "threshold = N × CHECKPOINT_CADENCE_BLOCKS × block_time_secs × 1000"
    );
}
