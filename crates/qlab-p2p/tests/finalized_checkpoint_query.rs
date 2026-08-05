//! **Issue #204 — a node can ask the net what is finalized.**
//!
//! `set_finalized` has exactly one caller, inside the vote-tally path, so the only
//! way a node ever learned that a checkpoint was final was by accumulating the
//! quorum itself. The tally is deliberately not persisted and rebuilds only from
//! **re-gossip** — and gossip on this path is push-once, gated on "the local tally
//! grew". For a slot the rest of the net settled hours ago, nothing re-gossips. A
//! node that missed the window was not left holding a stale copy of a fact it once
//! knew; it was left **unable to learn a fact it never held**, because the one
//! request that could have fetched it, `GetData(InvKind::Checkpoint, id)`, needs an
//! id that only the finalize it missed would have told it.
//!
//! These tests run over the **real** `NodeAdapter`, not `StubNode`: the defect is a
//! disagreement between the finality tracker and `ChainState`'s finalized pointer,
//! and both must move for the fix to mean anything.
//!
//! Every test in the first two sections fails on `main` — on `main` nothing ever
//! sends the question, so the stranded node's `final=` never moves.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, Checkpoint, CommitteeState, Validator, Vote};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::{FinalizeRefusalReason, NodeAdapter};
use qlab_p2p::codec::{
    checkpoint_id, checkpoint_query_height, checkpoint_query_id, decode_checkpoint_msg,
    decode_inv, encode_checkpoint_msg, encode_inv, InvItem, InvKind, CHECKPOINT_QUERY_TAG,
};
use qlab_p2p::node::{
    CHECKPOINT_QUERY_INTERVAL_MS, CHECKPOINT_QUERY_LAG_BLOCKS, MAX_CHECKPOINT_QUERIES_IN_FLIGHT,
};
use qlab_p2p::ratelimit::CHECKPOINT_QUERY_SERVE_INTERVAL_MS;
use qlab_p2p::peer::BAN_THRESHOLD;
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Envelope, Frame, MsgType};
use qlab_p2p::P2pNode;

/// Only a tx marked `ok` verifies; every body these tests move is coinbase-only.
#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

/// Committee size for these tests. `devnet_committee(7)` has quorum
/// `(2·7)/3 + 1 = 5`, so "under quorum" and "at quorum" are four and five votes —
/// small enough that a hand-built adversarial frame stays readable.
const COMMITTEE_N: usize = 7;
const QUORUM: usize = 5;

fn easy_sim() -> SimConfig {
    SimConfig {
        block_time_secs: 2,
        genesis_difficulty: 8,
        mine_nonce_budget: 5_000_000,
        ..SimConfig::default()
    }
}

fn adapter(committee: &qlab_devnet::committee::Committee) -> Adapter {
    NodeAdapter::new(
        CommitteeState::new(committee.clone(), qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    )
}

const SIM_TICK_MS: u64 = 10;

/// Two nodes over one hub, sharing one committee so votes verify on both. **Not
/// yet handshaked and not yet peers** — every test here needs to control exactly
/// what crossed the wire before the link came up.
fn pair(committee: &qlab_devnet::committee::Committee) -> (Node, Node, Arc<InProcHub>) {
    let hub = InProcHub::new();
    let a =
        P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(committee), [1; 32]);
    let b =
        P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(committee), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    (a, b, hub)
}

fn link(a: &mut Node, b: &mut Node) {
    a.add_peer(PeerId(2), None);
    b.add_peer(PeerId(1), None);
}

/// Drive nodes for `rounds` ticks on a shared monotone sim clock from `base_ms`.
fn run(nodes: &mut [&mut Node], rounds: u64, base_ms: u64) -> u64 {
    let mut now = base_ms;
    for _ in 0..rounds {
        now += SIM_TICK_MS;
        for n in nodes.iter_mut() {
            n.tick(now);
        }
    }
    now
}

/// Mine `n` blocks on `miner`, applying each, and return them ascending.
fn mine_chain(miner: &mut Node, n: usize) -> Vec<(BlockHeader, BlockBody)> {
    (0..n)
        .map(|_| {
            let (h, body) = miner.node_mut().mine_block().expect("mine");
            assert_eq!(miner.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
            (h, body)
        })
        .collect()
}

/// Give `node` the headers only — fork choice reaches the tip, the state machine
/// does not move. The `slag` shape #130 named, and the shape node1 was in.
fn replay_headers_only(node: &mut Node, blocks: &[(BlockHeader, BlockBody)]) {
    for (h, _) in blocks {
        assert_eq!(node.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
}

/// Give `node` the same chain, block for block, with every body applied.
fn replay(node: &mut Node, blocks: &[(BlockHeader, BlockBody)]) {
    for (h, b) in blocks {
        assert_eq!(node.node_mut().ingest_block(*h, b.clone()), IngestOutcome::Accepted);
    }
}

/// The checkpoint for main-chain height `h` on `node`'s chain. `root` stands in for
/// the commitment root exactly as the rest of the devnet does — what matters here
/// is that `block_hash` is this node's own main-chain hash at `h`, or
/// `ChainState::set_finalized` would refuse it as unknown.
fn checkpoint_at(node: &Node, h: u64) -> Checkpoint {
    let hash = node.node().main_chain_hash_at(h).expect("a canonical hash at this height");
    Checkpoint::new(h, hash, hash)
}

fn sign(validators: &[Validator], cp: &Checkpoint, idxs: std::ops::Range<usize>) -> Vec<Vote> {
    validators[idxs].iter().map(|v| v.sign_checkpoint(cp)).collect()
}

/// `(finality tracker head, ChainState finalized height)` — the two stores the
/// incident found disagreeing. Every assertion below reads BOTH, because a fix that
/// moved only the tracker would leave `no_reorg_past_finalized_checkpoint_ever`
/// keyed on the stale one.
fn finalized(node: &Node) -> (Option<u64>, Option<u64>) {
    (node.node().finality().finalized_height(), node.node().chain().finalized_height())
}

// ---------------------------------------------------------------------------
// 1. Reachability — the question the coordinator asked to be settled first
// ---------------------------------------------------------------------------

/// 🔴 **REACHABILITY — the running-node case, with no restart in it.**
///
/// The coordinator's D1 open question: can a node that never restarts be left
/// unable to learn a finalized checkpoint? This is the answer, and it is **yes**.
///
/// The mechanism is push-once delivery with no retransmission anywhere. `absorb_votes`
/// relays a vote set onward **only if the local tally grew**, which is what
/// terminates relay — and which also means that once a set has been pushed and the
/// tally has stopped growing, nothing on this net will ever send those votes again.
/// A single frame that does not arrive (a link that dropped and re-dialled, an
/// inbound-rate-limited frame — #99 drops a throttled frame ahead of decode and does
/// not score it, so it leaves no trace at all) permanently removes that slot's
/// quorum from the receiver's reach.
///
/// Here the missing frame is modelled as the plainest possible version of itself:
/// node B is simply not connected while the votes fly. B is **never restarted**, its
/// tally is never cleared, and it is ticked far past the point where any honest
/// retransmission would have arrived. It stays behind.
///
/// **The consequence, and it is the whole severity argument:**
/// `no_reorg_past_finalized_checkpoint_ever` is enforced against B's own pointer, so
/// for as long as this lasts B would accept a reorg in a span its peer has closed.
#[test]
fn the_running_node_case_is_reachable_no_restart_required() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);

    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks);
    assert_eq!(b.node().tip_height(), 17, "B holds the whole chain");

    // A finalizes slot 8 and slot 16 while B is not connected. This is push-once
    // gossip doing exactly what it is designed to do; B is simply not there.
    for h in [8u64, 16] {
        let cp = checkpoint_at(&a, h);
        a.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    }
    assert_eq!(finalized(&a), (Some(16), Some(16)), "A finalized both slots");
    assert_eq!(finalized(&b), (None, None), "B was not there for either");

    // Now link them, and let the net run. Handshake, header and body gossip, the
    // sync state machine, the body requester — everything a running node does.
    // 400 rounds is two orders of magnitude past what the handshake and any relay
    // need, so this is convergence failing, not time running out.
    link(&mut a, &mut b);
    run(&mut [&mut a, &mut b], 400, 0);

    // On `main` this is where the test stops: B is caught up, connected, healthy,
    // and permanently eight blocks behind its peer on the one pointer that gates
    // reorgs. No restart was involved at any point.
    assert_eq!(b.node().tip_height(), 17, "B is fully caught up on chain");
    assert!(b.peers().is_ready(PeerId(1)), "B is connected and handshaked");
    assert_eq!(
        b.node().finality().count(),
        1,
        "B learned exactly one checkpoint — and only because it asked (issue #204)"
    );
    assert_eq!(
        finalized(&b),
        (Some(16), Some(16)),
        "with #204's query B recovers; without it this is (None, None) forever"
    );
}

/// The same fact stated as the property the fix rests on, with no wire in it: a
/// below-quorum tally is not a stalled tally that will finish, it is a tally that
/// has **nothing left to wait for**. `try_finalize` is never even reached.
#[test]
fn a_below_quorum_tally_has_nothing_left_to_wait_for() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks);

    // B accumulates QUORUM − 1 votes for slot 16 — the marginal signer's frame is
    // the one that never arrived — and then the net moves on.
    let cp = checkpoint_at(&b, 16);
    b.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM - 1));
    assert_eq!(finalized(&b), (None, None), "four of five is not a quorum");

    // No amount of running produces the fifth vote: nothing re-gossips a slot whose
    // tally is not growing anywhere.
    link(&mut a, &mut b);
    run(&mut [&mut a, &mut b], 200, 0);
    assert_eq!(
        finalized(&b),
        (None, None),
        "A never finalized 16 either, so there is nothing for B's query to fetch"
    );
}

// ---------------------------------------------------------------------------
// 2. The acceptance test — the incident's shape
// ---------------------------------------------------------------------------

/// 🔴 **ACCEPTANCE — a node that signed a slot, lost its tally, and whose peers
/// have moved on ends up finalized AT THAT SLOT, having verified the quorum
/// itself.**
///
/// The preserved artifact, scaled to this harness's cadence:
///
/// | node1, 2026-08-01 | node B here |
/// |---|---|
/// | `applied_height = 1057` | tip 17 |
/// | `finalized = 1048` | finalized 8 |
/// | signed slot 1056, its own vote recorded | its own vote for slot 16, in its tally and below quorum |
/// | peers finalized 1056 and moved on | A finalized 16, dropped the slot from its tally, and will never push it again |
///
/// "Moved on" is the load-bearing part and it is about **slots, not blocks**: once A
/// finalized 16 its tally dropped the slot (`VoteTally::on_finalized`), so relay —
/// which is gated on "the local tally grew" — can never fire for slot 16 again on
/// any node in the net. B's own vote is in its own tally and will sit there forever.
/// There is no retransmission to wait for; the only move left is to ask.
///
/// The two stores the incident found disagreeing are asserted **together**, because
/// `no_reorg_past_finalized_checkpoint_ever` keys on the second one.
#[test]
fn the_incident_shape_a_stranded_signer_recovers_the_slot_it_signed() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);

    // One chain, seventeen blocks — `applied_height = 1057` against slot 1056.
    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks[..]);
    assert_eq!(b.node().tip_height(), 17);

    // A finalized 8 and 16 and moved on.
    for h in [8u64, 16] {
        let cp = checkpoint_at(&a, h);
        a.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    }
    assert_eq!(finalized(&a), (Some(16), Some(16)));

    // B established slot 8 — the restored, provable, STALE point that `PR #171`'s
    // guard was never going to catch, because there is nothing wrong with it …
    let cp8 = checkpoint_at(&b, 8);
    b.announce_checkpoint(cp8, sign(&validators, &cp8, 0..QUORUM));
    // … and then signed slot 16 and got no further. One vote: its own.
    let cp16 = checkpoint_at(&b, 16);
    assert_eq!(cp16, checkpoint_at(&a, 16), "the same checkpoint its peer finalized");
    b.announce_checkpoint(cp16, sign(&validators, &cp16, 6..7));
    assert_eq!(
        finalized(&b),
        (Some(8), Some(8)),
        "signing is not finalizing — the gap #204 says is CORRECT"
    );

    link(&mut a, &mut b);
    // Past one full CHECKPOINT_QUERY_INTERVAL_MS of sim time, so the last outstanding
    // ask has expired and "it has stopped asking" below is a real observation.
    run(&mut [&mut a, &mut b], 2 + CHECKPOINT_QUERY_INTERVAL_MS / SIM_TICK_MS, 0);

    assert_eq!(
        finalized(&b),
        (Some(16), Some(16)),
        "B ends finalized at the slot it signed, on both stores"
    );
    assert_eq!(
        b.node().finality().latest().copied(),
        Some(cp16),
        "and at the same checkpoint identity its peer finalized (`fid` agrees)"
    );
    assert_eq!(b.checkpoint_queries(), 0, "and it has stopped asking");
}

/// **The answer is the highest finalized checkpoint the server holds at or below
/// the height asked for** — not its head, and not the next slot up.
///
/// Asked directly of the serving side, because on a live mesh the asker's tip does
/// not stand still: this is the rule the requester relies on, isolated from the sync
/// that would otherwise move the goalposts mid-test.
///
/// Capping at the asker's tip is what keeps the answer *usable*. A checkpoint above
/// the asker's tip is outside the tally window `(finalized, tip + TALLY_TIP_SLACK]`
/// and would be dropped as `Stale` — and the asker would not hold its block to
/// finalize against anyway.
#[test]
fn the_answer_is_the_highest_finalized_checkpoint_at_or_below_the_height_asked_for() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut server, mut asker, _hub) = pair(&committee);
    mine_chain(&mut server, 33);
    for h in [8u64, 16, 24, 32] {
        let cp = checkpoint_at(&server, h);
        server.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    }
    assert_eq!(finalized(&server), (Some(32), Some(32)));
    server.add_peer(PeerId(2), None);
    asker.add_peer(PeerId(1), None);
    server.tick(10);
    asker.tick(10);
    let _ = asker.transport().poll();

    // (asked height, expected answer height)
    for (ask, want) in [(7u64, None), (8, Some(8)), (17, Some(16)), (33, Some(32)), (99, Some(32))]
    {
        let q = encode_inv(&[InvItem { kind: InvKind::Checkpoint, id: checkpoint_query_id(ask) }]);
        asker
            .transport()
            .send(PeerId(1), &Envelope::new(MsgType::GetData, q).encode())
            .expect("send");
        // One tick per serve interval so the amplifier budget never masks a wrong answer.
        server.tick(1_000 + ask * CHECKPOINT_QUERY_SERVE_INTERVAL_MS);
        let mut got = None;
        for (_, raw) in asker.transport().poll() {
            let f = Frame::decode(&raw).expect("well-formed");
            let env = f.known().expect("a known type");
            match env.msg_type {
                MsgType::Checkpoint => {
                    got = Some(decode_checkpoint_msg(&env.payload).expect("well-formed").0.height)
                }
                MsgType::NotFound => assert!(want.is_none(), "asked {ask}, got NotFound"),
                _ => {}
            }
        }
        assert_eq!(got, want, "query at or below {ask}");
    }
}

/// And the requester names **its own tip**, so one round trip moves it as far as its
/// own chain can carry it rather than one slot at a time.
#[test]
fn the_requester_names_its_own_tip() {
    let (committee, _v) = devnet_committee(COMMITTEE_N);
    let (mut peer, mut asker, _hub) = pair(&committee);
    let blocks = mine_chain(&mut peer, 17);
    replay(&mut asker, &blocks);
    peer.add_peer(PeerId(2), None);
    asker.add_peer(PeerId(1), None);
    peer.tick(10);
    asker.tick(10); // handshake completes and the first query goes out with it

    let asked: Vec<u64> = peer
        .transport()
        .poll()
        .iter()
        .filter_map(|(_, raw)| {
            let f = Frame::decode(raw).expect("well-formed");
            let env = f.known().expect("a known type");
            (env.msg_type == MsgType::GetData).then(|| env.payload.clone())
        })
        .flat_map(|p| decode_inv(&p).expect("well-formed").items)
        .filter_map(|it| checkpoint_query_height(&it.id))
        .collect();
    assert_eq!(asked, vec![17], "one query, naming this node's own tip");
}

// ---------------------------------------------------------------------------
// 3. 🔴 The property that must not be spent: the receiver verifies, never trusts
// ---------------------------------------------------------------------------

/// Hand-build the answer a hostile peer would send, so the frame is exactly what a
/// peer controls and nothing in this node's own code shaped it.
fn inject_checkpoint_answer(from: &Node, to: PeerId, cp: &Checkpoint, votes: &[Vote]) {
    let frame = Envelope::new(MsgType::Checkpoint, encode_checkpoint_msg(cp, votes)).encode();
    from.transport().send(to, &frame).expect("send");
}

/// 🔴 **A PEER'S CLAIM ALONE MOVES NOTHING — under-quorum.**
///
/// The one outcome worse than the bug would be *"a peer told me it was finalized,
/// so it is"*. The answer to a #204 query re-enters through the same
/// `on_checkpoint` → `absorb_votes` → `ingest_checkpoint_votes` path as any gossiped
/// set, and the unchanged `try_finalize` counts distinct verified active signers
/// against quorum before anything moves. A well-formed checkpoint carrying four of
/// the five votes it needs is honest, useful evidence — it is tallied and it is not
/// penalised — and it moves **neither** finalized pointer.
#[test]
fn a_peers_answer_below_quorum_moves_neither_finalized_pointer() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut hostile, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut hostile, 17);
    replay(&mut b, &blocks);
    link(&mut hostile, &mut b);
    run(&mut [&mut hostile, &mut b], 20, 0);
    assert_eq!(finalized(&b), (None, None));

    let cp = checkpoint_at(&b, 16);
    let under: Vec<Vote> = sign(&validators, &cp, 0..QUORUM - 1);
    assert_eq!(under.len(), QUORUM - 1, "one short, and every signature genuine");
    inject_checkpoint_answer(&hostile, PeerId(2), &cp, &under);
    run(&mut [&mut b], 20, 1_000);

    assert_eq!(finalized(&b), (None, None), "the pointer did not move");
    assert!(
        b.peers().get(PeerId(1)).map_or(0, |p| p.score) > BAN_THRESHOLD,
        "and an honest below-quorum set is evidence, not misbehaviour — never scored"
    );

    // And the gate is a gate, not a wall: the fifth genuine vote finalizes it.
    inject_checkpoint_answer(&hostile, PeerId(2), &cp, &sign(&validators, &cp, QUORUM - 1..QUORUM));
    run(&mut [&mut b], 20, 2_000);
    assert_eq!(finalized(&b), (Some(16), Some(16)), "quorum, verified here, finalizes");
}

/// 🔴 **A PEER'S CLAIM ALONE MOVES NOTHING — forged.**
///
/// Quorum-many votes, every signer index in the roster, every signature valid for a
/// *different* checkpoint. Nothing moves, and the sender is charged: a set whose
/// indices resolve and whose signatures do not is a forge, which is the one
/// classification `#164`/`PR #166` kept as `Invalid`.
#[test]
fn a_peers_answer_with_forged_votes_moves_nothing_and_is_charged() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut hostile, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut hostile, 17);
    replay(&mut b, &blocks);
    link(&mut hostile, &mut b);
    run(&mut [&mut hostile, &mut b], 20, 0);

    let claimed = checkpoint_at(&b, 16);
    let elsewhere = Checkpoint::new(16, [0xEE; 32], [0xEE; 32]);
    // Real signatures over `elsewhere`, presented as votes for `claimed`.
    let forged: Vec<Vote> = sign(&validators, &elsewhere, 0..QUORUM);
    assert_eq!(forged.len(), QUORUM, "quorum-many, and every one of them a lie");

    let before = b.peers().get(PeerId(1)).map_or(0, |p| p.score);
    inject_checkpoint_answer(&hostile, PeerId(2), &claimed, &forged);
    run(&mut [&mut b], 20, 1_000);

    assert_eq!(finalized(&b), (None, None), "a forged quorum finalizes nothing");
    assert!(
        b.peers().get(PeerId(1)).map_or(0, |p| p.score) < before,
        "and the sender is charged for it"
    );
}

/// A quorum for a checkpoint whose `block_hash` is not this node's main chain at
/// that height moves the **consensus pointer** not at all. This is the case that
/// would matter if a peer ever answered off a fork, and it is asserted here because
/// `ChainState::set_finalized` — not the query — is what refuses it.
#[test]
fn a_quorum_for_a_block_this_node_does_not_hold_moves_the_consensus_pointer_nowhere() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut hostile, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut hostile, 17);
    replay(&mut b, &blocks);
    link(&mut hostile, &mut b);
    run(&mut [&mut hostile, &mut b], 20, 0);

    let off_chain = Checkpoint::new(16, [0x77; 32], [0x77; 32]);
    inject_checkpoint_answer(&hostile, PeerId(2), &off_chain, &sign(&validators, &off_chain, 0..QUORUM));
    run(&mut [&mut b], 20, 1_000);

    assert_eq!(
        b.node().chain().finalized_height(),
        None,
        "ChainState refuses a block it does not have — the reorg gate never moved"
    );
}

// ---------------------------------------------------------------------------
// 4. The wire: no new type, no new codepoint, and both mixed-version directions
// ---------------------------------------------------------------------------

/// The query rides `GetData` (0x0011) with `InvKind::Checkpoint = 3` and is answered
/// with `Checkpoint` (0x0022). No `MsgType` and no `InvKind` was allocated — which
/// is not a style preference: `#181` makes an unrecognised type
/// `PENALTY_MALFORMED` (100) against a `BAN_THRESHOLD` of −100, an instant one-frame
/// ban, and this net upgrades one host at a time.
#[test]
fn the_query_allocates_no_new_msg_type_and_no_new_inv_kind() {
    let id = checkpoint_query_id(1056);
    let frame =
        Envelope::new(MsgType::GetData, encode_inv(&[InvItem { kind: InvKind::Checkpoint, id }]))
            .encode();
    let back_frame = Frame::decode(&frame).expect("a type every deployed node knows");
    let back = back_frame.known().expect("a known type");
    assert_eq!(back.msg_type, MsgType::GetData);
    assert_eq!(back.msg_type.as_u16(), 0x0011, "no new envelope code was allocated");
    // `#181` made `decode_inv` return an `InvVec`, which also reports item kinds
    // this build does not implement (`unk=`'s second number). This query's kind is
    // one this build DOES implement, so it must arrive in `items` and leave
    // `unknown_kinds` at zero — asserted, because a query landing in the unknown
    // bucket would be silently unserved and look exactly like a peer that has
    // nothing.
    let inv = decode_inv(&back.payload).expect("well-formed");
    assert_eq!(inv.unknown_kinds, 0, "Checkpoint is a kind this build implements");
    assert_eq!(inv.items[0].kind, InvKind::Checkpoint, "kind 3, allocated in M10-T0-5");
    assert_eq!(inv.items[0].kind as u8, 3);

    // The answer is the message both sides have understood since M9.
    let cp = Checkpoint::new(1056, [1; 32], [1; 32]);
    let ans = Envelope::new(MsgType::Checkpoint, encode_checkpoint_msg(&cp, &[])).encode();
    assert_eq!(Frame::decode(&ans).expect("known").msg_type().expect("known").as_u16(), 0x0022);
}

/// The query id namespace and a real checkpoint id cannot be confused. A checkpoint
/// id is `keccak256(signing_message)`; a query id fixes its first 24 bytes to
/// [`CHECKPOINT_QUERY_TAG`], so a collision is a 2⁻¹⁹² event and the height round
/// trips exactly.
#[test]
fn a_query_id_is_never_mistaken_for_a_checkpoint_id() {
    for h in [0u64, 1, 8, 1056, u64::MAX] {
        assert_eq!(checkpoint_query_height(&checkpoint_query_id(h)), Some(h));
    }
    assert!(checkpoint_query_id(8) < checkpoint_query_id(16), "ids stay ordered by height");
    for h in [0u64, 1, 8, 1056] {
        let cp = Checkpoint::new(h, [h as u8; 32], [h as u8; 32]);
        assert_eq!(
            checkpoint_query_height(&checkpoint_id(&cp)),
            None,
            "a real checkpoint id is never read as a query"
        );
    }
    assert_eq!(CHECKPOINT_QUERY_TAG.len(), 24);
}

/// 🔴 **Mixed-version, new asks old.** A node running the current image holds no
/// checkpoint under a query id, so it answers `NotFound` — and the requester must
/// **not** score it, or a rolled host would ban every host that has not been rolled
/// yet, at `PENALTY_WELSHED_INV` a query. This is #130 (c)'s finding in a new place.
#[test]
fn a_not_found_for_our_own_query_is_never_scored() {
    let (committee, _v) = devnet_committee(COMMITTEE_N);
    let (mut old, mut new, _hub) = pair(&committee);
    // `old` holds a chain and has finalized nothing to serve — byte-identical, from
    // `new`'s side, to a peer whose image predates the query.
    let blocks = mine_chain(&mut old, 17);
    replay(&mut new, &blocks);
    link(&mut old, &mut new);

    // Long enough for many re-ask intervals: at PENALTY_WELSHED_INV = 5 a scored
    // NotFound would ban within 20 answers.
    let mut now = 0;
    for _ in 0..40 {
        now = run(&mut [&mut old, &mut new], 20, now);
    }
    assert!(
        new.peers().get(PeerId(1)).map_or(0, |p| p.score) > BAN_THRESHOLD,
        "an honest peer that has nothing to serve is never banned for saying so"
    );
    assert!(new.peers().is_ready(PeerId(1)), "and the link survives");

    // The exemption is scoped: an UNSOLICITED NotFound naming a query id we never
    // sent is still a welshed inv, and is still charged.
    let before = new.peers().get(PeerId(1)).map_or(0, |p| p.score);
    let bogus = encode_inv(&[InvItem { kind: InvKind::Checkpoint, id: checkpoint_query_id(999) }]);
    old.transport()
        .send(PeerId(2), &Envelope::new(MsgType::NotFound, bogus).encode())
        .expect("send");
    new.tick(now + 10);
    assert!(
        new.peers().get(PeerId(2)).map_or(0, |p| p.score) < before
            || new.peers().get(PeerId(1)).map_or(0, |p| p.score) < before,
        "an id we never asked for is not exempt"
    );
}

// ---------------------------------------------------------------------------
// 5. The bounds: when this node asks, how often, and the answer's amplification
// ---------------------------------------------------------------------------

/// **The comparison that is now somebody's job.** `final=` standing still while
/// `tip=` climbs was printed on every sample for hours on four hosts and read by
/// nobody. It is now a check the node itself makes, every tick — and this test locks
/// it at the boundary, in both directions: at the slot, silent; one block past it,
/// asking. One block is [`CHECKPOINT_QUERY_LAG_BLOCKS`], and it is the exact
/// distance the preserved artifact sat at (`applied_height = 1057`, slot 1056).
#[test]
fn at_the_slot_the_node_is_silent_and_one_block_past_it_it_asks() {
    let (committee, _v) = devnet_committee(COMMITTEE_N);
    let (mut peer, mut b, _hub) = pair(&committee);
    // B mines its own chain, so nothing gossiped can move its tip out from under
    // the assertions. `peer` exists only to be a ready peer to ask.
    mine_chain(&mut b, CHECKPOINT_CADENCE_BLOCKS as usize);
    peer.add_peer(PeerId(2), None);
    b.add_peer(PeerId(1), None);
    b.tick(10);
    peer.tick(10);
    b.tick(20);
    assert!(b.peers().is_ready(PeerId(1)), "there is a peer to ask");

    assert_eq!(b.node().tip_height(), CHECKPOINT_CADENCE_BLOCKS, "the tip IS the slot");
    assert_eq!(finalized(&b), (None, None), "and its votes have not converged yet");
    b.tick(1_000);
    assert_eq!(b.checkpoint_queries(), 0, "at the slot: silent, the ordinary path owns it");

    // One block further on, and the slot is still not finalized.
    mine_chain(&mut b, 1);
    assert_eq!(b.node().tip_height(), CHECKPOINT_CADENCE_BLOCKS + 1);
    b.tick(2_000);
    assert_eq!(b.checkpoint_queries(), 1, "one block past the slot, it asks");

    // Bounded in count and in time: no second ask inside the interval.
    b.tick(2_010);
    b.tick(2_020);
    assert_eq!(b.checkpoint_queries(), 1, "MAX_CHECKPOINT_QUERIES_IN_FLIGHT, and no re-ask");
    assert_eq!(MAX_CHECKPOINT_QUERIES_IN_FLIGHT, 1);
    assert_eq!(CHECKPOINT_QUERY_LAG_BLOCKS, 1);

    // …and it stops asking the moment the reason to ask is gone — the termination
    // argument is the trigger clearing, not a timer expiring.
    let cp = checkpoint_at(&b, CHECKPOINT_CADENCE_BLOCKS);
    let (_c, validators) = devnet_committee(COMMITTEE_N);
    b.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    b.tick(2_000 + CHECKPOINT_QUERY_INTERVAL_MS);
    b.tick(2_010 + CHECKPOINT_QUERY_INTERVAL_MS);
    assert_eq!(b.checkpoint_queries(), 0, "finalized: the query stops because it is done");
}

/// The amplifier gate. A ~45 B query against a whole quorum vote set is #91's shape
/// (a `GetAddr` measured 1084×), and the query is the first `GetData` on this wire
/// that can be driven **without an inv first**. Over-rate queries are dropped in
/// silence — not `NotFound`, which the receiver scores.
#[test]
fn a_query_flood_is_answered_at_most_once_per_serve_interval() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut server, mut flooder, _hub) = pair(&committee);
    let blocks = mine_chain(&mut server, 17);
    replay(&mut flooder, &blocks);
    // Both sides finalized 16, so neither has a query of its own to send and every
    // answer counted below is one the hand-built flood bought.
    let cp = checkpoint_at(&server, 16);
    server.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    flooder.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    link(&mut server, &mut flooder);
    server.tick(10);
    flooder.tick(10);
    let _ = flooder.transport().poll(); // clear the handshake

    let query =
        encode_inv(&[InvItem { kind: InvKind::Checkpoint, id: checkpoint_query_id(17) }]);
    let mut answers = 0;
    for i in 0..50u64 {
        flooder
            .transport()
            .send(PeerId(1), &Envelope::new(MsgType::GetData, query.clone()).encode())
            .expect("send");
        server.tick(100 + i); // 50 queries inside one serve interval
        answers += flooder
            .transport()
            .poll()
            .iter()
            .filter(|(_, raw)| {
                Frame::decode(raw).expect("well-formed").msg_type() == Some(MsgType::Checkpoint)
            })
            .count();
    }
    assert_eq!(answers, 1, "50 queries in one interval buy exactly one answer");
    assert_eq!(
        server.rate_stats().throttled_cp_query,
        49,
        "and the other 49 are dropped in silence, counted, and not scored"
    );
    assert!(
        server.peers().get(PeerId(2)).map_or(0, |p| p.score) > BAN_THRESHOLD,
        "asking twice is not misbehaviour"
    );

    // Past the interval, the allowance is back.
    flooder
        .transport()
        .send(PeerId(1), &Envelope::new(MsgType::GetData, query).encode())
        .expect("send");
    server.tick(100 + CHECKPOINT_QUERY_SERVE_INTERVAL_MS);
    assert_eq!(
        flooder
            .transport()
            .poll()
            .iter()
            .filter(|(_, raw)| {
                Frame::decode(raw).expect("well-formed").msg_type() == Some(MsgType::Checkpoint)
            })
            .count(),
        1,
        "one answer per interval, not one ever"
    );
}

// ---------------------------------------------------------------------------
// 6. 🔴 The second defect, from the coordinator's 2026-08-02 correction:
//    a refusal to record the finalized head durably, spelled `let _`
// ---------------------------------------------------------------------------

/// 🔴 **THE #203 SHAPE, AS RE-DIAGNOSED: head #1 advances, head #3 refuses, and
/// until now the refusal went to `let _` and nothing anywhere said so.**
///
/// Node B holds every header (fork choice is at the tip) and has applied bodies only
/// to height 8 — the `slag` shape, and the shape node1 was in when its state machine
/// did not hold the main-chain block the 1056 checkpoint names.
///
/// A quorum for slot 16 arrives. `FinalityTracker` (head #1) advances, because a
/// quorum of verified votes is all `try_finalize` needs and it is right about that.
/// The **durable** head (#3) refuses, because the block is not there. `final=` now
/// reads 16 and a restart would read 8.
///
/// Before this pass that refusal was `Ok(false)` into `let _`: not logged, not
/// counted, not on telemetry, and **not distinguishable from success**.
#[test]
fn a_durable_head_that_refuses_is_counted_journalled_and_on_the_line() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks[..8]); // bodies to 8
    replay_headers_only(&mut b, &blocks[8..]); // headers to 17
    assert_eq!(b.node().tip_height(), 17, "fork choice is at the tip");
    assert_eq!(b.node().state_lag().state_tip, 8, "the state machine is not");

    let cp16 = checkpoint_at(&b, 16);
    b.announce_checkpoint(cp16, sign(&validators, &cp16, 0..QUORUM));

    // Head #1 advanced — correctly. It saw a quorum.
    assert_eq!(b.node().finality().finalized_height(), Some(16), "the tracker head");
    // Head #3 did not. This is the divergence, and it is now VISIBLE.
    assert_eq!(
        b.node().durable_finalized_height(),
        None,
        "the durable head never advanced — a restart would read this, not 16"
    );
    assert_eq!(b.node().finalize_refused_total(), 1, "counted: fdrop=1");

    let journal = b.node_mut().drain_finalize_refusals();
    assert_eq!(journal.len(), 1, "journalled once");
    assert_eq!(journal[0].head, "state", "the DURABLE head is the one that refused");
    assert_eq!(journal[0].height, 16);
    assert_eq!(
        journal[0].why,
        FinalizeRefusalReason::NotHeld,
        "the state machine does not hold that block"
    );
    assert!(
        journal[0].to_string().starts_with("FINALIZE refused head=state h=16 cp="),
        "and it renders for the container log: {}",
        journal[0]
    );
    // Issue #241: this asserted `why=unknown` until the token was renamed. The
    // refusal is the same one, at the same instant, for the same cause — what
    // changed is that the line no longer shares a word with `mready=unknown`.
    assert!(journal[0].to_string().ends_with(" why=not-held"), "{}", journal[0]);
}

/// The retry is unchanged (#130 (a)) and the counter is a **transition** count, not
/// an attempt count. A stuck durable head is one number, not a per-tick ramp — and
/// when the bodies arrive the retry succeeds, the divergence closes, and the count
/// stays as the lossless record that it happened.
#[test]
fn a_stuck_durable_head_counts_once_and_closes_when_the_bodies_arrive() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks[..8]);
    replay_headers_only(&mut b, &blocks[8..]);
    let cp16 = checkpoint_at(&b, 16);
    b.announce_checkpoint(cp16, sign(&validators, &cp16, 0..QUORUM));
    assert_eq!(b.node().finalize_refused_total(), 1);
    assert_eq!(b.node_mut().drain_finalize_refusals().len(), 1, "journalled once, then taken");

    // Many more drains, each of which retries the refused record.
    link(&mut a, &mut b);
    run(&mut [&mut a, &mut b], 200, 0);
    assert!(
        b.node_mut().drain_finalize_refusals().is_empty(),
        "200 retries of a divergence that has not changed produce no new journal lines"
    );
    assert_eq!(
        b.node().finalize_refused_total(),
        1,
        "one divergence, not one per tick — this is the retry rate NOT being reported \
         as the defect rate"
    );

    // The bodies land, the retry succeeds, and the two heads agree again.
    for (h, body) in &blocks[8..] {
        let _ = b.node_mut().ingest_block(*h, body.clone());
    }
    run(&mut [&mut a, &mut b], 100, 2_000);
    assert_eq!(b.node().state_lag().state_tip, 17, "the state machine caught up");
    assert_eq!(
        b.node().durable_finalized_height(),
        Some(16),
        "and the durable head recorded what the tracker head already said"
    );
    assert_eq!(
        b.node().finalize_refused_total(),
        1,
        "the count is the lossless record that it happened, not a live gauge"
    );
    assert!(b.node_mut().drain_finalize_refusals().is_empty(), "nothing new to journal");
}

/// A healthy node never refuses, so `fdrop=0` means what it says. Stated because a
/// counter that is noisy in normal operation is a counter nobody will alert on.
#[test]
fn a_healthy_node_refuses_nothing() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut a, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut a, 17);
    replay(&mut b, &blocks);
    for h in [8u64, 16] {
        let cp = checkpoint_at(&a, h);
        a.announce_checkpoint(cp, sign(&validators, &cp, 0..QUORUM));
    }
    link(&mut a, &mut b);
    run(&mut [&mut a, &mut b], 300, 0);

    for n in [&a, &b] {
        assert_eq!(n.node().finalize_refused_total(), 0, "nothing refused");
        assert_eq!(
            n.node().durable_finalized_height(),
            n.node().finality().finalized_height(),
            "and the operator-facing head and the durable head agree"
        );
        assert_eq!(n.node().durable_finalized_height(), Some(16));
    }
}

/// The fork-choice head (#2) is read too. It refuses for its own reasons, and its
/// refusal is attributed to `head=chain` so an operator is never left guessing which
/// of the three heads declined.
#[test]
fn the_fork_choice_head_refusing_is_reported_as_its_own_head() {
    let (committee, validators) = devnet_committee(COMMITTEE_N);
    let (mut hostile, mut b, _hub) = pair(&committee);
    let blocks = mine_chain(&mut hostile, 17);
    replay(&mut b, &blocks);
    link(&mut hostile, &mut b);
    run(&mut [&mut hostile, &mut b], 20, 0);

    // A quorum for a block no head holds.
    let off_chain = Checkpoint::new(16, [0x77; 32], [0x77; 32]);
    inject_checkpoint_answer(&hostile, PeerId(2), &off_chain, &sign(&validators, &off_chain, 0..QUORUM));
    run(&mut [&mut b], 20, 1_000);

    let journal = b.node_mut().drain_finalize_refusals();
    let heads: Vec<&str> = journal.iter().map(|r| r.head).collect();
    assert!(heads.contains(&"chain"), "fork choice refused and said so: {heads:?}");
    assert!(heads.contains(&"state"), "so did the durable head: {heads:?}");
    assert!(
        journal.iter().all(|r| r.height == 16 && r.why == FinalizeRefusalReason::NotHeld),
        "{journal:?}"
    );
    assert_eq!(b.node().chain().finalized_height(), None, "and neither pointer moved");
    assert_eq!(b.node().durable_finalized_height(), None);
}
