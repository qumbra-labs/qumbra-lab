//! **Issue #229 — the ask set is observable, and the three layers read
//! differently.**
//!
//! The live reading these tests exist to make decidable: `stip` frozen at 2693, a
//! header chain at 2714, `slag=21`, and `breq=1–2` against an expected ask set of
//! ten to fifteen. Three layers produce that number and they have different fixes:
//!
//! - **(a)** the ask set is wrong or empty;
//! - **(b)** the asks are right and nobody serves them;
//! - **(c)** bodies arrive and never satisfy the rejoin gate.
//!
//! **Every test here asserts the three read DIFFERENTLY**, not merely that output
//! exists — an instrument that fires on all three is the state the issue is
//! already in.
//!
//! Nothing here is a mechanism test. `state_fork_point`, `missing_body_hashes`
//! and `rejoin_main_chain` behave exactly as they do on `main`; what is new is
//! that a node in these states says so.
//!
//! ## What is NOT reproduced here, and it is a finding
//!
//! Layer (a)'s sharpest shape — `state_fork_point()` answering `None`, which
//! makes `missing_body_hashes` fall back to the applied tip and ask for blocks
//! *above* a dead branch — **has no reachable path in this tree.** The walk at
//! `adapter.rs:1107` descends the state machine's own applied chain, and both the
//! live path and the snapshot-resume path (`resume_from_snapshot`) rebuild that
//! block store from the append-only log before anything reads it, so the `?` at
//! `:1118` has nothing to trip on. The rendering of that reading is unit-tested in
//! `bodywait.rs` (`a_missing_fork_point_prints_none_and_not_a_number`) so the line
//! is correct if it ever happens; it is not integration-tested, because
//! constructing it would mean breaking the store on purpose. See the PR body.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{encode_inv, InvItem, InvKind};
use qlab_p2p::bodywait::{AskSetObservation, BodyAnswer, BodyWaitJournal, RejoinGate};
use qlab_p2p::n1::{BlockIngest, IngestOutcome};
use qlab_p2p::node::{BODY_REQUEST_TIMEOUT_MS, MAX_BODIES_IN_FLIGHT};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Envelope, MsgType};
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

fn node(id: u64, rkm: u64, hub: &Arc<InProcHub>) -> Node {
    P2pNode::new(InProcTransport::new(PeerId(id), Arc::clone(hub)), adapter(rkm), [id as u8; 32])
}

/// Mine one block on an off-net factory adapter and apply it there.
fn mine_on(a: &mut Adapter) -> (BlockHeader, BlockBody) {
    let (h, b) = a.mine_block().expect("mine");
    assert_eq!(a.ingest_block(h, b.clone()), IngestOutcome::Accepted);
    (h, b)
}

/// The stall latch's threshold, in sim ms: `UNOBTAINABLE_BODY_CADENCES ×
/// CHECKPOINT_CADENCE_BLOCKS × block_time` = 2 × 8 × 2 s = **32 s** under
/// [`easy_sim`], against 20 minutes at the live 75 s target. The constant is
/// read off the adapter rather than restated, so a change to it cannot leave
/// these tests asserting an arithmetic nobody runs.
fn threshold_ms(n: &Node) -> u64 {
    n.node().unobtainable_threshold_ms()
}

/// Drive a set of nodes for `rounds` ticks from `base_ms`, `step_ms` apart.
fn run(nodes: &mut [&mut Node], rounds: u64, base_ms: u64, step_ms: u64) -> u64 {
    let mut now = base_ms;
    for _ in 0..rounds {
        now += step_ms;
        for n in nodes.iter_mut() {
            n.tick(now);
        }
    }
    now
}

/// The observation a mining node would report, with the in-flight count wired in
/// the way `RunningNode::emit_body_waits` wires it.
fn observe(n: &Node) -> AskSetObservation {
    n.node().ask_set_observation(n.body_requests(), true)
}

/// The lines a `RunningNode` would journal for this node right now.
fn journal(n: &Node, j: &mut BodyWaitJournal, now_ms: u64) -> Vec<String> {
    let obs = observe(n);
    let entries = n.body_ask_report(now_ms);
    j.report(&obs, &entries, now_ms, threshold_ms(n), BODY_REQUEST_TIMEOUT_MS)
}

/// The stranded shape both live scenarios start from, and it is the incident's
/// exactly: this node mined and applied its own branch, a heavier branch took
/// fork choice, and its state machine is on a chain nobody will extend.
///
/// Returns `(asker, main-branch blocks ascending)`. The asker holds every
/// main-chain **header** and no main-chain body, so
/// [`ChainView::missing_body_hashes`] has a real ask set to produce.
fn stranded_asker(hub: &Arc<InProcHub>, id: u64) -> (Node, Vec<(BlockHeader, BlockBody)>) {
    // The losing branch, mined by the asker itself so it is genuinely applied.
    let mut asker = node(id, 0xb0 + id, hub);
    let mut lost = Vec::new();
    for _ in 0..2 {
        let (h, b) = asker.node_mut().mine_block().expect("mine");
        assert_eq!(asker.node_mut().ingest_block(h, b.clone()), IngestOutcome::Accepted);
        lost.push((h, b));
    }
    // The winning branch, built off-net so no node on the hub can source it by
    // accident — three blocks against the asker's two, so fork choice moves.
    let mut fac = adapter(0x51);
    let won: Vec<(BlockHeader, BlockBody)> = (0..3).map(|_| mine_on(&mut fac)).collect();
    assert_ne!(
        lost[0].0.header_hash(),
        won[0].0.header_hash(),
        "a genuine sibling race at height 1"
    );
    for (h, _) in &won {
        asker.node_mut().ingest_header(*h);
    }
    assert!(
        asker.node().applied_tip().is_off_main_chain(),
        "the asker's applied tip is on the losing branch"
    );
    (asker, won)
}

// ---------------------------------------------------------------------------
// (b) — the asks are right and nobody serves them
// ---------------------------------------------------------------------------

/// **Layer (b): every ask is answered, and every answer is "I do not have it".**
///
/// Two peers, deliberately in the two honest positions #199 and #135 produce:
/// one holds the winning branch's **headers** and no bodies, so it answers
/// `GetData(Block)` with a bare `Header`; the other has never heard of those
/// blocks, so it answers `NotFound`. Both are correct and neither is scored, and
/// **before this line the two were indistinguishable from silence** — a
/// header-only answer looks exactly like ordinary header relay on the wire.
#[test]
fn layer_b_nobody_serves_and_every_peer_says_so_by_name() {
    let hub = InProcHub::new();
    let (mut asker, won) = stranded_asker(&hub, 1);
    // The header-holder: it knows the winning branch and holds none of its bodies.
    let mut holder = node(2, 0x22, &hub);
    for (h, _) in &won {
        holder.node_mut().ingest_header(*h);
    }
    // The stranger: it has never seen the winning branch at all.
    let stranger = node(3, 0x33, &hub);
    let mut stranger = stranger;
    let t = threshold_ms(&asker);
    // 🔴 The latch first, with nobody to ask — `stip` frozen and off-main for the
    // threshold. This is also the (a)-shaped half of the negative: a stranded node
    // with an EMPTY in-flight set is still reportable, because the predicate is
    // "off-main or asking", not "asking".
    asker.tick(0); // starts the stall clock at the first observation
    asker.tick(t + 1_000);
    let now = t + 1_000;
    assert!(observe(&asker).armed, "armed before any peer exists: {:?}", observe(&asker));
    assert_eq!(observe(&asker).in_flight, 0, "and with nothing in flight");

    hub.link(PeerId(1), PeerId(2));
    hub.link(PeerId(1), PeerId(3));
    asker.add_peer(PeerId(2), None);
    asker.add_peer(PeerId(3), None);
    holder.add_peer(PeerId(1), None);
    stranger.add_peer(PeerId(1), None);
    let now = run(&mut [&mut asker, &mut holder, &mut stranger], 30, now, 100);

    let obs = observe(&asker);
    assert!(obs.armed, "a node frozen off-main past the threshold is reportable: {obs:?}");
    assert!(obs.off_main, "{obs:?}");
    assert_eq!(obs.fork_point, Some(0), "the branches split at genesis");
    assert_eq!(obs.ask_set, 3, "three main-chain bodies missing: {obs:?}");
    assert_eq!(obs.in_flight, 3, "and all three are asked — the window is 16");
    assert_eq!(obs.pending, 0, "🔴 (b): nothing arrived");
    assert_eq!(obs.gate, RejoinGate::Missing(1), "so the rewind cannot be followed");

    let entries = asker.body_ask_report(now);
    assert_eq!(entries.len(), 3, "{entries:?}");
    let answers: Vec<BodyAnswer> =
        entries.iter().flat_map(|e| e.answers.values().copied()).collect();
    assert!(
        answers.contains(&BodyAnswer::HeaderOnly),
        "🔴 the peer that holds the header and not the body said so: {entries:?}"
    );
    assert!(
        entries.iter().all(|e| e.in_flight),
        "every ask is still outstanding — nothing was satisfied: {entries:?}"
    );
    assert!(
        !answers.contains(&BodyAnswer::Served),
        "nobody served anything, which is the whole of (b): {entries:?}"
    );
    assert!(
        entries.iter().all(|e| e.asks >= 1 && !e.asked.is_empty()),
        "and each names the peer it was asked of, so an unanswered ask is \
         attributable to a peer rather than to the net: {entries:?}"
    );

    let lines = journal(&asker, &mut BodyWaitJournal::new(), now);
    assert_eq!(lines.len(), 4, "summary + one line per outstanding ask: {lines:?}");
    assert!(lines[0].contains(" ask=3 breq=3 pend=0 "), "{}", lines[0]);
    assert!(lines[0].contains(" sfork=0 "), "{}", lines[0]);
    assert!(
        lines[1..].iter().any(|l| l.contains(":header-only")),
        "the per-peer answer is on the line an operator reads: {lines:?}"
    );
    for l in &lines {
        println!("PR-SAMPLE (b) {l}");
    }
}

// ---------------------------------------------------------------------------
// (c) — bodies arrive and the gate never passes
// ---------------------------------------------------------------------------

/// **Layer (c): the bodies are arriving, and the node is exactly as stuck.**
///
/// The serving peer can produce the winning branch's **upper** bodies and not the
/// body at `fork + 1`. That is not contrived: `P2pNode::blocks` is a relay-window
/// cache that is never persisted (#135) and `held_body` answers only for blocks
/// this node applied (#198), so a peer that saw the tail of a branch and not its
/// head is the ordinary consequence of a restart.
///
/// The reading that decides it: **`served` answers against asks that are still
/// outstanding, `pend=` climbing, and `gate=missing` anyway.** On every surface
/// that existed before this line — `slag=`, `schain=`, `breq=`, `stip=` — this
/// node is byte-identical to the (b) node above.
#[test]
fn layer_c_bodies_arrive_and_the_rejoin_gate_still_does_not_pass() {
    let hub = InProcHub::new();
    let (mut asker, won) = stranded_asker(&hub, 1);
    let mut server = node(2, 0x22, &hub);
    // The server holds every winning header…
    for (h, _) in &won {
        server.node_mut().ingest_header(*h);
    }
    // …and the bodies for heights 2 and 3 only. `announce_block` is the seam that
    // puts a body in the serving cache without requiring this node to have applied
    // it, which is precisely the state a restarted relay is in. Done before the
    // handshake, so nothing is pushed at the asker unasked.
    for (h, b) in &won[1..] {
        let (coinbase, rkm) = b.single_payee_parts().expect("current-cap body");
        server.announce_block(*h, b.txs.clone(), coinbase, rkm, 0);
    }
    let t = threshold_ms(&asker);
    asker.tick(0);
    asker.tick(t + 1_000);
    let now = t + 1_000;
    assert!(observe(&asker).armed, "the latch arms before the server appears");

    hub.link(PeerId(1), PeerId(2));
    asker.add_peer(PeerId(2), None);
    server.add_peer(PeerId(1), None);
    let now = run(&mut [&mut asker, &mut server], 30, now, 100);

    let obs = observe(&asker);
    assert!(obs.armed, "{obs:?}");
    assert_eq!(obs.fork_point, Some(0), "{obs:?}");
    assert!(obs.pending >= 2, "🔴 (c): the upper bodies ARRIVED and are held: {obs:?}");
    assert_eq!(
        obs.gate,
        RejoinGate::Missing(1),
        "🔴 …and the gate still refuses, because `fork + 1` is not among them: {obs:?}"
    );
    assert_eq!(obs.state_tip, 2, "so the applied tip has not moved: {obs:?}");

    let entries = asker.body_ask_report(now);
    let answers: Vec<BodyAnswer> =
        entries.iter().flat_map(|e| e.answers.values().copied()).collect();
    assert!(
        answers.contains(&BodyAnswer::Served),
        "🔴 the discriminator: an ask that was ANSWERED WITH A BODY and is still \
         outstanding — which is (c) and is invisible without it: {entries:?}"
    );

    let lines = journal(&asker, &mut BodyWaitJournal::new(), now);
    assert!(lines[0].contains(" gate=missing@1 "), "{}", lines[0]);
    assert!(!lines[0].contains(" pend=0 "), "bodies are held: {}", lines[0]);
    for l in &lines {
        println!("PR-SAMPLE (c) {l}");
    }
}

// ---------------------------------------------------------------------------
// The acceptance criterion itself
// ---------------------------------------------------------------------------

/// 🔴 **THE TEST THAT DECIDES THIS IS DONE.** The three layers produce three
/// visibly different summary lines, and the differences are the fields an
/// operator would act on.
///
/// (a) is represented by its two published readings — an empty ask set and a
/// `None` fork point — because the code path that produces them is not reachable
/// in this tree (see the module header). What is asserted is the property the
/// issue asks for: **a reader can tell which layer they are in from the line**.
#[test]
fn the_three_layers_do_not_print_the_same_line() {
    let hub_b = InProcHub::new();
    let (mut asker_b, won_b) = stranded_asker(&hub_b, 1);
    let mut holder = node(2, 0x22, &hub_b);
    for (h, _) in &won_b {
        holder.node_mut().ingest_header(*h);
    }
    let t = threshold_ms(&asker_b);
    asker_b.tick(0);
    asker_b.tick(t + 1_000);
    let now = t + 1_000;
    hub_b.link(PeerId(1), PeerId(2));
    asker_b.add_peer(PeerId(2), None);
    holder.add_peer(PeerId(1), None);
    run(&mut [&mut asker_b, &mut holder], 30, now, 100);

    let hub_c = InProcHub::new();
    let (mut asker_c, won_c) = stranded_asker(&hub_c, 1);
    let mut server = node(2, 0x22, &hub_c);
    for (h, _) in &won_c {
        server.node_mut().ingest_header(*h);
    }
    for (h, b) in &won_c[1..] {
        let (coinbase, rkm) = b.single_payee_parts().expect("current-cap body");
        server.announce_block(*h, b.txs.clone(), coinbase, rkm, 0);
    }
    asker_c.tick(0);
    asker_c.tick(t + 1_000);
    let now = t + 1_000;
    hub_c.link(PeerId(1), PeerId(2));
    asker_c.add_peer(PeerId(2), None);
    server.add_peer(PeerId(1), None);
    run(&mut [&mut asker_c, &mut server], 30, now, 100);

    let line_b = observe(&asker_b).to_line();
    let line_c = observe(&asker_c).to_line();
    // (a): the same node, with the two readings the requester would publish if its
    // walk had produced nothing to walk from.
    let mut a = observe(&asker_b);
    a.ask_set = 0;
    a.fork_point = None;
    a.gate = RejoinGate::NoForkPoint;
    let line_a = a.to_line();

    assert_ne!(line_a, line_b, "(a) and (b) must not read the same");
    assert_ne!(line_b, line_c, "(b) and (c) must not read the same");
    assert_ne!(line_a, line_c, "(a) and (c) must not read the same");

    // …and the differences are the FIELDS, not incidental digits.
    assert!(line_a.contains(" sfork=none ") && line_a.contains(" ask=0 "), "{line_a}");
    assert!(line_b.contains(" pend=0 ") && line_b.contains(" sfork=0 "), "{line_b}");
    assert!(!line_c.contains(" pend=0 "), "{line_c}");

    // 🔴 The thing the incident could not see: on every field that existed before
    // this line, (b) and (c) are the same node.
    let pre_229 = |n: &Node| {
        let o = observe(n);
        format!("stip={} slag={} schain={}", o.state_tip, o.lag, o.off_main)
    };
    assert_eq!(
        pre_229(&asker_b),
        pre_229(&asker_c),
        "two different bugs, one reading — which is why this baton exists"
    );
    println!("PR-SAMPLE (a) {line_a}");
    println!("PR-SAMPLE (b) {line_b}");
    println!("PR-SAMPLE (c) {line_c}");
}

// ---------------------------------------------------------------------------
// The negative
// ---------------------------------------------------------------------------

/// **A healthy node says nothing, and so does one that is merely behind.**
///
/// The second half is the one that matters. *"Six legitimate rewinds in fifteen
/// minutes is normal"* and must not become six log lines: the latch keys on `stip`
/// **frozen**, and a node that is behind and catching up moves `stip` on every
/// applied body, so the clock never reaches the threshold.
#[test]
fn a_healthy_node_and_a_node_merely_behind_emit_nothing() {
    let hub = InProcHub::new();
    let mut healthy = node(1, 0x11, &hub);
    let mut behind = node(2, 0x22, &hub);
    hub.link(PeerId(1), PeerId(2));
    healthy.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);

    // `healthy` mines the chain; `behind` takes the headers only, so it is lagging
    // with a real ask set — the state #130 (c)'s requester exists for.
    let mut chain = Vec::new();
    for _ in 0..4 {
        let (h, b) = healthy.node_mut().mine_block().expect("mine");
        assert_eq!(healthy.node_mut().ingest_block(h, b.clone()), IngestOutcome::Accepted);
        behind.node_mut().ingest_header(h);
        chain.push((h, b));
    }
    assert!(behind.node().state_lag().is_lagging(), "it is genuinely behind");
    assert!(
        !behind.node().applied_tip().is_off_main_chain(),
        "…and on the main chain, which is the whole difference from a strand"
    );

    let t = threshold_ms(&healthy);
    let mut jh = BodyWaitJournal::new();
    let mut jb = BodyWaitJournal::new();
    let mut now = 0;
    // Well past the threshold, applying one body per window — `stip` moves, so the
    // clock restarts, so nothing is ever reportable.
    for (h, b) in &chain {
        now += t;
        healthy.tick(now);
        behind.tick(now);
        assert!(journal(&healthy, &mut jh, now).is_empty(), "a healthy node is silent");
        assert!(
            journal(&behind, &mut jb, now).is_empty(),
            "and so is one that is catching up: {:?}",
            observe(&behind)
        );
        behind.node_mut().ingest_block(*h, b.clone());
    }
    assert!(!behind.node().state_lag().is_lagging(), "it caught up");
    now += t;
    behind.tick(now);
    assert!(journal(&behind, &mut jb, now).is_empty(), "and stays silent afterwards");
    assert!(
        !observe(&behind).armed && !observe(&healthy).armed,
        "neither latch ever armed"
    );
}

/// **The ask set is not `breq`, and the line says both.**
///
/// *"An ask set of 15 with 2 in flight and an ask set of 2 are the same `breq` and
/// different bugs."* This pins that the two numbers come from different places —
/// the ask set from [`ChainView::missing_body_hashes`], the in-flight count from
/// the requester's own map — so a divergence between them is legible instead of
/// being collapsed into one field.
#[test]
fn the_ask_set_and_the_in_flight_count_are_two_different_numbers() {
    let hub = InProcHub::new();
    let (asker, _won) = stranded_asker(&hub, 1);
    // No peer has been linked, so nothing has been asked…
    assert_eq!(asker.body_requests(), 0, "nothing in flight");
    let obs = observe(&asker);
    // …and the ask set is nonetheless three, because it is a property of the
    // node's own two chain views and not of who it is talking to.
    assert_eq!(obs.ask_set, 3, "the requester WANTS three bodies: {obs:?}");
    assert_eq!(obs.in_flight, 0, "and has asked for none of them");
    assert_eq!(obs.telemetry_field(), "3@0", "and `bask=` carries both facts");
    assert!(
        obs.ask_set <= MAX_BODIES_IN_FLIGHT,
        "the caliper: it saturates at the requester's own window and is not a gap size"
    );
}

/// **`NotFound` is a peer's answer, and it reads differently from a header.**
///
/// The third of layer (b)'s three readings, injected rather than staged: on a net
/// where header-first sync works, a peer that lacks a block's header does not stay
/// lacking it for long, so `dont-have` is the *transient* answer and `header-only`
/// is the steady state. That is worth knowing and it is why the answer classes are
/// three and not two — a peer that does not even have the header is a peer that
/// cannot be waited on, and one that has the header and not the body might be
/// served itself and then serve us.
///
/// Scoring is unchanged and asserted here so the observation hook cannot be
/// mistaken for a policy change: an item we ourselves put in flight is exempt from
/// `PENALTY_WELSHED_INV`, exactly as #130 (c) left it.
#[test]
fn a_not_found_answer_is_recorded_as_dont_have_and_still_scores_nothing() {
    let hub = InProcHub::new();
    let (mut asker, won) = stranded_asker(&hub, 1);
    let mut holder = node(2, 0x22, &hub);
    for (h, _) in &won {
        holder.node_mut().ingest_header(*h);
    }
    hub.link(PeerId(1), PeerId(2));
    asker.add_peer(PeerId(2), None);
    holder.add_peer(PeerId(1), None);
    // Handshake only: the holder never answers, so the asks stay outstanding for
    // the injection below.
    holder.tick(10);
    asker.tick(10);
    assert!(asker.body_requests() > 0, "asks are in flight");

    let wanted = won[0].0.header_hash();
    let frame = Envelope::new(
        MsgType::NotFound,
        encode_inv(&[InvItem { kind: InvKind::Block, id: wanted }]),
    )
    .encode();
    holder.transport().send(PeerId(1), &frame).expect("send");
    asker.tick(20);

    let entry = asker
        .body_ask_report(20)
        .into_iter()
        .find(|e| e.hash == wanted)
        .expect("the ask we injected an answer for");
    assert_eq!(
        entry.answers.get(&PeerId(2)),
        Some(&BodyAnswer::DontHave),
        "the peer said it does not hold the block at all: {entry:?}"
    );
    assert!(entry.to_line().contains("p2:dont-have"), "{}", entry.to_line());
    assert_eq!(
        asker.peers().get(PeerId(2)).expect("peer").score,
        0,
        "and recording the answer changed no scoring: an ask we originated is exempt"
    );
}
