//! **Issue #130 (c) — historical body transfer, over the wire.**
//!
//! Part (a) (`PR #142`) gave the state machine a way to *apply* a body it was
//! holding. It could not give it a way to *obtain* one: `GetBlockTxn` has exactly
//! one send site, in reply to a fresh `BlockAnnounce`, and it names transactions by
//! index — which a requester cannot build, because `BlockHeader` carries no
//! transaction count. So a node holding 649 headers and no bodies had no message it
//! could send, and three T0 hosts sat frozen behind exactly that.
//!
//! These tests are over the **real** `NodeAdapter` node-state (not `StubNode`),
//! because the defect is a disagreement between the two chain views and `StubNode`
//! has only one of them.
//!
//! Every test here fails on `main`: on `main` nothing ever sends a request, so the
//! lagging node's `stip` never moves.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{encode_inv, tx_id, InvItem, InvKind};
use qlab_p2p::compact::{
    encode_announce, reconstruct, short_id, BlockAnnounce, PrefilledTx, Reconstruct,
};
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::node::MAX_BODIES_IN_FLIGHT;
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Envelope, MsgType};
use qlab_p2p::P2pNode;

/// Same shape as the adapter's own test verifier: only a tx marked `ok` verifies.
/// The bodies these tests move are coinbase-only, so nothing depends on it beyond
/// the mismatched-body case, which never reaches the proof check.
#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

/// Fast blocks and trivial PoW, so a 40-block chain is milliseconds of Keccak.
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

/// Simulated milliseconds one `tick` represents — a monotone sim clock, so the
/// inbound rate limiter's buckets refill and the reproducibility of these runs does
/// not depend on how fast the machine is.
const SIM_TICK_MS: u64 = 10;

/// Two linked, handshaked nodes over one in-process hub.
fn pair() -> (Node, Node, Arc<InProcHub>) {
    let hub = InProcHub::new();
    let a = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let b = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    (a, b, hub)
}

/// Drive both nodes for `rounds` ticks on a shared monotone sim clock, starting at
/// `base_ms`. Returns the clock it stopped at.
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

/// Mine `n` blocks on `server`, applying each to its own state machine, and return
/// them ascending. The server therefore holds every body in its **applied-block
/// store**, which is the only place a historical body can come from.
fn mine_chain(server: &mut Node, n: usize) -> Vec<(BlockHeader, BlockBody)> {
    (0..n)
        .map(|_| {
            let (h, body) = server.node_mut().mine_block().expect("mine");
            assert_eq!(server.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
            (h, body)
        })
        .collect()
}

/// A node in **exactly the T0 condition**: its state machine applied block 1 and
/// nothing since, while header-first sync carried its fork-choice tip to the top of
/// the chain. `slag = tip − stip` is the number on the telemetry line.
fn lagging_at_one(node: &mut Node, blocks: &[(BlockHeader, BlockBody)]) {
    assert_eq!(
        node.node_mut().ingest_block(blocks[0].0, blocks[0].1.clone()),
        IngestOutcome::Accepted
    );
    for (h, _) in &blocks[1..] {
        assert_eq!(node.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    assert_eq!(node.node().state_lag().state_tip, 1, "the state machine is at height 1");
}

fn slag(node: &Node) -> u64 {
    node.node().state_lag().blocks()
}

/// Drive the handshake to `Ready` and stop, with the **server ticked only once** so
/// it never answers the batch the requester sends on reaching `Ready`.
///
/// Used by the scoring tests, which need the asks to still be outstanding when a
/// hand-built frame is injected. `run` would let the honest bodies land first, and
/// then there would be nothing in flight to test the scoring rules against.
fn handshake_only(server: &mut Node, behind: &mut Node) {
    server.tick(10); // Version → VerAck
    behind.tick(10); // Version + VerAck ⇒ Ready ⇒ the batch goes out
}

// ---------------------------------------------------------------------------
// The acceptance test
// ---------------------------------------------------------------------------

/// 🔴 **ACCEPTANCE 1 — the lagging node REACHES THE TIP.**
///
/// Two nodes: one at the tip with every body applied, one whose state machine is at
/// height 1 with all 40 headers already in hand. Nothing is announced to the lagging
/// node — the announces all happened before it was linked, exactly as on a net where
/// the blocks are history. The only way it can move is by asking.
///
/// Not "requests bodies": **reaches the tip**, with its applied tip equal to fork
/// choice's, block for block.
#[test]
fn a_node_at_height_one_with_the_headers_in_hand_reaches_the_tip() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 40);
    assert_eq!(server.node().tip_height(), 40);

    lagging_at_one(&mut behind, &blocks);
    assert_eq!(behind.node().tip_height(), 40, "fork choice is at the tip");
    assert_eq!(slag(&behind), 39, "and the state machine is 39 blocks behind it");

    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    // 39 blocks at MAX_BODIES_IN_FLIGHT per round trip is three request rounds; the
    // budget below is an order of magnitude over that, so a failure here is a
    // failure to converge and not a failure to be given enough time.
    run(&mut [&mut server, &mut behind], 60, 0);

    assert_eq!(slag(&behind), 0, "the state machine caught up with its own chain");
    assert_eq!(
        behind.node().state_lag().state_tip,
        40,
        "and it is at the tip, not merely closer to it"
    );
    assert_eq!(
        behind.node().stored_body(&blocks[39].0.header_hash()).is_some(),
        true,
        "the tip's body is applied and durable, not merely buffered"
    );
    assert_eq!(behind.node().tip_hash(), server.node().tip_hash(), "the same block");
    assert_eq!(behind.body_requests(), 0, "and it has stopped asking");
}

/// 🔴 **ACCEPTANCE 2 — the `slag` slope, strictly below the block rate.**
///
/// The production measurement that decided this issue is a *rate*: `slag` climbing
/// at the ceiling (one per block) forever. The recovery criterion is its mirror —
/// under continuing load, `slag` must climb **strictly slower than the block rate**.
///
/// So the server keeps mining while the lagging node catches up, and the slope is
/// measured in blocks rather than minutes (the same quantity with the wall clock
/// divided out). On `main` the answer is 1.0 exactly: every new block adds one to
/// `slag` and nothing ever subtracts. Here it is negative.
#[test]
fn the_slag_slope_is_strictly_below_the_block_rate_under_continuing_load() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 20);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    let mut now = run(&mut [&mut server, &mut behind], 4, 0); // handshake

    // One sample per mined block — the in-process equivalent of T-ops' sampler.
    let mut samples = vec![slag(&behind)];
    for _ in 0..8 {
        let (h, body) = server.node_mut().mine_block().expect("mine");
        assert_eq!(server.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
        server.announce_block(h, body.txs, body.coinbase, body.coinbase_rkm, 0);
        now = run(&mut [&mut server, &mut behind], 4, now);
        samples.push(slag(&behind));
    }

    let blocks_mined = samples.len() as i64 - 1;
    let growth = *samples.last().expect("sampled") as i64 - samples[0] as i64;
    assert!(
        (growth as f64) / (blocks_mined as f64) < 1.0,
        "slag slope {growth}/{blocks_mined} must be strictly below the block rate; \
         samples {samples:?}"
    );
    // The stronger fact the criterion does not require: it converges, it does not
    // merely climb more slowly.
    assert_eq!(samples.last().copied(), Some(0), "converged: {samples:?}");
}

// ---------------------------------------------------------------------------
// Bounds and scoring
// ---------------------------------------------------------------------------

/// **A peer that cannot serve a body is not scored for it** — bound (2), and the
/// half that would otherwise re-commit #134's mistake.
///
/// The peer here holds the headers and none of the bodies: it is every joiner, every
/// node that is itself behind, and every node running an image that never applied
/// that block. It answers each request with a header (which is what a node running
/// the *current* deployed image does too, because that is the arm this baton
/// changed). Its score must be exactly zero afterwards.
#[test]
fn a_peer_that_holds_no_bodies_answers_with_a_header_and_is_never_scored() {
    // A chain nobody in this test has the bodies of except its miner, which is not
    // in the mesh: `header_only` is handed headers alone.
    let mut miner = P2pNode::new(
        InProcTransport::new(PeerId(9), Arc::clone(&InProcHub::new())),
        adapter(),
        [9; 32],
    );
    let blocks = mine_chain(&mut miner, 20);

    let hub = InProcHub::new();
    let mut header_only =
        P2pNode::new(InProcTransport::new(PeerId(3), Arc::clone(&hub)), adapter(), [3; 32]);
    for (h, _) in &blocks {
        assert_eq!(header_only.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    let mut asker =
        P2pNode::new(InProcTransport::new(PeerId(4), Arc::clone(&hub)), adapter(), [4; 32]);
    lagging_at_one(&mut asker, &blocks);
    hub.link(PeerId(3), PeerId(4));
    header_only.add_peer(PeerId(4), None);
    asker.add_peer(PeerId(3), None);

    run(&mut [&mut header_only, &mut asker], 40, 0);

    assert!(slag(&asker) > 0, "nothing could be served, so nothing was applied");
    assert!(asker.body_requests() > 0, "and it is still asking — the ask is what is scored");
    assert_eq!(
        asker.peers().get(PeerId(3)).expect("peer").score,
        0,
        "a peer that genuinely cannot serve a body is NOT a misbehaving peer"
    );
    assert!(!asker.peers().is_banned(PeerId(3)));
    // And the other direction: asking cost the header-only peer nothing either.
    assert_eq!(header_only.peers().get(PeerId(4)).expect("peer").score, 0);
}

/// **`NotFound` for a body we asked for is not a welshed inv** — the same rule at
/// the other refusal.
///
/// `PENALTY_WELSHED_INV` was written for a `GetData` sent in reply to an `Inv`, i.e.
/// asking a peer for something it had just advertised. A historical body request is
/// not that, and charging 5 points a block over a 649-block catch-up would ban an
/// honest peer after twenty blocks.
#[test]
fn not_found_for_a_body_we_requested_is_not_a_fault_but_an_unsolicited_one_is() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 20);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    // Handshake ONLY. The server is deliberately not ticked again, so it never
    // answers the batch and the asks stay outstanding for the injections below —
    // a `run` here would let the real bodies arrive and empty the in-flight set.
    handshake_only(&mut server, &mut behind);
    assert!(behind.body_requests() > 0, "asks are in flight");

    // The server answers one of them with `NotFound` instead of a body.
    let outstanding = blocks[1].0.header_hash();
    let frame = Envelope::new(
        MsgType::NotFound,
        encode_inv(&[InvItem { kind: InvKind::Block, id: outstanding }]),
    )
    .encode();
    server.transport().send(PeerId(2), &frame).expect("send");
    behind.tick(40);
    assert_eq!(
        behind.peers().get(PeerId(1)).expect("peer").score,
        0,
        "a peer that cannot serve history we asked for is not welshing"
    );

    // An id we never asked for is still a welsh, at the unchanged penalty.
    let never_asked = [0xEE; 32];
    let frame = Envelope::new(
        MsgType::NotFound,
        encode_inv(&[InvItem { kind: InvKind::Block, id: never_asked }]),
    )
    .encode();
    server.transport().send(PeerId(2), &frame).expect("send");
    behind.tick(50);
    assert_eq!(
        behind.peers().get(PeerId(1)).expect("peer").score,
        -5,
        "the pre-existing welshed-inv penalty is unchanged for everything else"
    );
}

/// **A body that does not match the header's `tx_body_commitment` IS a peer fault** —
/// bound (2)'s other half, and the reason this path can be trusted at all.
///
/// The served body is delivered through the announce codec, so it lands in exactly
/// the seam `PR #79` closed: reconstruction succeeding is no evidence the body is the
/// header's body, and the verdict comes from `ingest_block`. This asserts that the
/// verdict is still reached, and still charged, when the body arrived because we
/// asked for it.
#[test]
fn a_served_body_that_does_not_match_the_header_commitment_is_charged_to_the_server() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 5);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);
    // Handshake only — the honest body for height 2 must NOT have arrived, or the
    // forgery below would be discarded as "already applied" rather than judged.
    handshake_only(&mut server, &mut behind);

    // The real header for height 2, with a body it did not commit to: the coinbase
    // counter is a body field, so changing it breaks the binding without touching a
    // single transaction.
    let (header, body) = blocks[1].clone();
    let forged = BlockAnnounce {
        header,
        nonce: 0,
        coinbase: body.coinbase.wrapping_add(1),
        coinbase_rkm: body.coinbase_rkm,
        short_ids: Vec::new(),
        prefilled: Vec::new(),
    };
    let frame = Envelope::new(MsgType::BlockAnnounce, encode_announce(&forged)).encode();
    server.transport().send(PeerId(2), &frame).expect("send");
    behind.tick(30);

    assert_eq!(
        behind.peers().get(PeerId(1)).expect("peer").score,
        -20,
        "a body that is not the header's body is PENALTY_INVALID_OBJECT, as it always was"
    );
    assert_eq!(behind.node().state_lag().state_tip, 1, "and nothing was applied");

    // **A refused answer does NOT free the slot for an immediate re-ask.** Clearing
    // the in-flight entry on arrival rather than on success is a busy loop: the body
    // is not applied, so the next tick asks for it again and the peer serves it
    // again, at the tick rate, forever. The timeout paces the retry instead — so
    // across many ticks inside one timeout window, nothing is re-asked.
    let before = behind.body_requests();
    for t in 1..20u64 {
        behind.tick(30 + t * 10);
    }
    assert_eq!(
        behind.body_requests(),
        before,
        "a body we refused is re-asked on the timeout ladder, not on every tick"
    );
}

/// **It terminates, and it is bounded while it runs.**
///
/// Two claims the issue asks for separately. The bound: never more than
/// `MAX_BODIES_IN_FLIGHT` outstanding, no matter how far behind. The termination:
/// once the state machine reaches the tip the ask set is empty and the node stops
/// asking — which is a property of `missing_body_hashes` (a hash leaves the set when
/// its body is applied), not of a timer.
#[test]
fn the_requester_is_bounded_while_it_runs_and_silent_once_it_converges() {
    let (mut server, mut behind, _hub) = pair();
    let blocks = mine_chain(&mut server, 40);
    lagging_at_one(&mut behind, &blocks);
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);

    let mut now = 0u64;
    let mut peak = 0usize;
    for _ in 0..60 {
        now += SIM_TICK_MS;
        server.tick(now);
        behind.tick(now);
        peak = peak.max(behind.body_requests());
    }
    assert!(peak > 0, "it did ask — otherwise the bound below is vacuous");
    assert!(
        peak <= MAX_BODIES_IN_FLIGHT,
        "never more than {MAX_BODIES_IN_FLIGHT} outstanding, peaked at {peak}"
    );
    assert_eq!(slag(&behind), 0, "converged");

    // Converged: further ticks add no asks, and add no frames either.
    let quiet_before = behind.body_requests();
    for _ in 0..20 {
        now += SIM_TICK_MS;
        server.tick(now);
        behind.tick(now);
    }
    assert_eq!(quiet_before, 0);
    assert_eq!(behind.body_requests(), 0, "a converged node does not keep asking");
}

/// **The requester unwedges a state machine stranded on a losing sibling** (the
/// #162 case whose body was never offered).
///
/// `rejoin_main_chain` will only rewind when it already holds the main-chain body at
/// `fork + 1`, and before this baton that body could only arrive by being announced
/// live. A node that missed the announcement stayed wedged forever — `schain=fork`,
/// `slag` climbing — because `GetData(Block)` answered with a header. Here the
/// requester asks for `fork + 1` by name, and the rewind follows.
#[test]
fn a_state_machine_stranded_on_a_sibling_asks_for_the_block_that_frees_it() {
    let hub = InProcHub::new();
    let mut winner =
        P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let mut loser =
        P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    winner.node_mut().set_miner_rkm([0xA1; 4]);
    loser.node_mut().set_miner_rkm([0xB2; 4]);

    // Both mine at height 1 before hearing the other, and each applies its own.
    let (wh1, wb1) = winner.node_mut().mine_block().expect("mine");
    assert_eq!(winner.node_mut().ingest_block(wh1, wb1.clone()), IngestOutcome::Accepted);
    let (lh1, lb1) = loser.node_mut().mine_block().expect("mine");
    assert_eq!(loser.node_mut().ingest_block(lh1, lb1), IngestOutcome::Accepted);
    assert_ne!(wh1.header_hash(), lh1.header_hash(), "a genuine sibling race");

    // The winner extends. The loser learns the winning branch as HEADERS ONLY —
    // it never sees wh1's body, which is the whole of the wedge.
    let mut extra = Vec::new();
    for _ in 0..3 {
        let (h, b) = winner.node_mut().mine_block().expect("mine");
        assert_eq!(winner.node_mut().ingest_block(h, b.clone()), IngestOutcome::Accepted);
        extra.push(h);
    }
    assert_eq!(loser.node_mut().ingest_header(wh1), IngestOutcome::Accepted);
    for h in &extra {
        assert_eq!(loser.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    assert!(
        loser.node().applied_tip().off_main_chain() == Some(true),
        "stranded: the applied tip is not the main-chain block at its height"
    );

    hub.link(PeerId(1), PeerId(2));
    winner.add_peer(PeerId(2), None);
    loser.add_peer(PeerId(1), None);
    run(&mut [&mut winner, &mut loser], 40, 0);

    assert_eq!(
        loser.node().applied_tip().off_main_chain(),
        Some(false),
        "it rejoined the main chain"
    );
    assert_eq!(slag(&loser), 0, "and caught up to the tip");
    assert_eq!(loser.node().state_rewinds().0, 1, "one rewind, and it was followed by progress");
}

/// **An old node's `GetData(Block)` still works against a new one.**
///
/// The other mixed-version direction. An image that predates this baton sends
/// `GetData(Block)` from exactly one place — `on_inv`, for a header it does not
/// have — and expects something back. It now gets a `BlockAnnounce`, which is a
/// message type it has understood since M9, and which carries the header it wanted
/// plus a body it can use. Nothing it does not understand crosses the wire.
#[test]
fn a_bare_getdata_for_a_block_is_answered_with_the_whole_block() {
    let (mut server, mut client, _hub) = pair();
    let blocks = mine_chain(&mut server, 3);
    server.add_peer(PeerId(2), None);
    client.add_peer(PeerId(1), None);
    run(&mut [&mut server, &mut client], 4, 0);

    // The pre-#130 (c) request, byte for byte: one inv item, kind Block.
    let target = blocks[0].0.header_hash();
    let frame = Envelope::new(
        MsgType::GetData,
        encode_inv(&[InvItem { kind: InvKind::Block, id: target }]),
    )
    .encode();
    client.transport().send(PeerId(1), &frame).expect("send");
    run(&mut [&mut server, &mut client], 4, 40);

    assert!(client.node().has_header(&target), "the header arrived, as it always did");
    assert!(
        client.node().stored_body(&target).is_some(),
        "and so did the body — this is the door #130 (c) opens"
    );
    assert_eq!(client.peers().get(PeerId(1)).expect("peer").score, 0, "nobody was scored");
}

/// **A transaction-carrying body reconstructs with an EMPTY mempool** — the
/// property that makes a historical transfer different from a live relay.
///
/// Live compact relay sends short ids and relies on the receiver already holding
/// the transactions; a node catching up on a block from a week ago holds none of
/// them, so every short-id slot would come back missing and the transfer would
/// degrade into a `GetBlockTxn` round trip per block — the very message a header
/// cannot build indexes for. A served block therefore prefills **every** slot, and
/// this pins that it reconstructs against no candidates at all.
///
/// The shape asserted here is exactly what `whole_block_announce` emits: no short
/// ids, `prefilled[i].index == i`, salt fixed at 0 (unused with no short ids, so
/// the encoding is a pure function of the block).
#[test]
fn a_whole_block_announce_reconstructs_against_an_empty_candidate_set() {
    let txs: Vec<TxEntry> = (1u8..=3)
        .map(|s| TxEntry {
            proof: vec![s; 8],
            public: TxPublic {
                anchor: [s; 32],
                nullifiers: vec![[s; 32]],
                commitments: vec![[s.wrapping_add(1); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
        })
        .collect();
    let body = BlockBody { txs: txs.clone(), coinbase: 42, coinbase_rkm: [7; 4] };
    let header = BlockHeader::child_of(&BlockHeader::genesis(1000, 0), 75, 1000, body.commitment());
    let ann = BlockAnnounce {
        header,
        nonce: 0,
        coinbase: body.coinbase,
        coinbase_rkm: body.coinbase_rkm,
        short_ids: Vec::new(),
        prefilled: txs
            .iter()
            .enumerate()
            .map(|(i, tx)| PrefilledTx { index: i as u32, tx: tx.clone() })
            .collect(),
    };

    // Round-trip the real wire, then reconstruct with NO candidates.
    let back = qlab_p2p::compact::decode_announce(&encode_announce(&ann)).expect("decode");
    assert!(back.short_ids.is_empty(), "a served block carries no short ids");
    match reconstruct(&back, &[]) {
        Reconstruct::Complete(got) => {
            assert_eq!(got.len(), 3);
            for (a, b) in got.iter().zip(&txs) {
                assert_eq!(tx_id(a), tx_id(b), "in order, byte-identical");
            }
            let rebuilt =
                BlockBody { txs: got, coinbase: back.coinbase, coinbase_rkm: back.coinbase_rkm };
            assert_eq!(
                rebuilt.commitment(),
                header.tx_body_commitment,
                "and the rebuilt body matches what the header committed to — which \
                 `BlockTxn` could never achieve, because it carries no coinbase fields"
            );
        }
        Reconstruct::Missing(m) => panic!("a fully prefilled announce must be complete: {m:?}"),
    }

    // The contrast, so the choice is not merely asserted: the LIVE relay shape for
    // the same body leaves every non-prefilled slot missing on an empty mempool.
    let live = BlockAnnounce {
        header,
        nonce: 0xABCD,
        coinbase: body.coinbase,
        coinbase_rkm: body.coinbase_rkm,
        short_ids: txs[1..].iter().map(|tx| short_id(0xABCD, &tx_id(tx))).collect(),
        prefilled: vec![PrefilledTx { index: 0, tx: txs[0].clone() }],
    };
    match reconstruct(&live, &[]) {
        Reconstruct::Missing(m) => assert_eq!(m, vec![1, 2], "short ids are useless to a joiner"),
        Reconstruct::Complete(_) => panic!("expected missing slots"),
    }
}

/// The wire shape of a served block, pinned: the existing announce codec, every
/// transaction prefilled, no short ids, and a `MsgType` that already existed.
#[test]
fn a_served_block_uses_the_existing_announce_codec_and_no_new_msg_type() {
    let ann = BlockAnnounce {
        header: BlockHeader::genesis(1000, 0),
        nonce: 0,
        coinbase: 5,
        coinbase_rkm: [9; 4],
        short_ids: Vec::new(),
        prefilled: vec![PrefilledTx {
            index: 0,
            tx: TxEntry {
                proof: b"ok".to_vec(),
                public: TxPublic {
                    anchor: [1; 32],
                    nullifiers: vec![],
                    commitments: vec![],
                    bucket: ArityBucket::TwoByTwo,
                    fee: 0,
                },
            },
        }],
    };
    let frame = Envelope::new(MsgType::BlockAnnounce, encode_announce(&ann)).encode();
    let back = Envelope::decode(&frame).expect("a type every deployed node knows");
    assert_eq!(back.msg_type, MsgType::BlockAnnounce);
    assert_eq!(back.msg_type.as_u16(), 0x0041, "no new envelope code was allocated");
}

/// **The serving cap is real, and over-asking degrades to a header rather than to a
/// refusal.**
///
/// `GetData(Block)` used to cost the server a header and can now cost it a body, so
/// the number of bodies one request may extract is bounded
/// (`MAX_BODIES_PER_GETDATA`). What matters as much as the cap is the *shape* of the
/// overflow: items past it are answered header-only — never `NotFound`, which the
/// receiving side scores at `PENALTY_WELSHED_INV`, and never silence, which would
/// look to the requester exactly like a dead peer.
#[test]
fn a_getdata_asking_for_more_bodies_than_the_cap_gets_headers_for_the_remainder() {
    use qlab_p2p::node::MAX_BODIES_PER_GETDATA;

    let (mut server, mut client, _hub) = pair();
    let over = MAX_BODIES_PER_GETDATA + 4;
    let blocks = mine_chain(&mut server, over);
    // The client is fully caught up, so its own requester asks for nothing and the
    // only `GetData` on the wire is the hand-built one below.
    for (h, b) in &blocks {
        assert_eq!(client.node_mut().ingest_block(*h, b.clone()), IngestOutcome::Accepted);
    }
    assert_eq!(slag(&client), 0);
    server.add_peer(PeerId(2), None);
    client.add_peer(PeerId(1), None);
    server.tick(10);
    client.tick(10);
    let _ = client.transport().poll(); // drop the handshake + this tick's own answers

    let items: Vec<InvItem> = blocks
        .iter()
        .map(|(h, _)| InvItem { kind: InvKind::Block, id: h.header_hash() })
        .collect();
    assert_eq!(items.len(), over);
    let frame = Envelope::new(MsgType::GetData, encode_inv(&items)).encode();
    client.transport().send(PeerId(1), &frame).expect("send");
    server.tick(20);

    let (mut bodies, mut headers, mut not_found) = (0, 0, 0);
    for (_, raw) in client.transport().poll() {
        match Envelope::decode(&raw).expect("well-formed").msg_type {
            MsgType::BlockAnnounce => bodies += 1,
            MsgType::Header => headers += 1,
            MsgType::NotFound => not_found += 1,
            _ => {}
        }
    }
    assert_eq!(bodies, MAX_BODIES_PER_GETDATA, "exactly the cap, no more");
    assert_eq!(headers, over - MAX_BODIES_PER_GETDATA, "the remainder, header-only as before");
    assert_eq!(not_found, 0, "over-asking is never answered with a scored refusal");
}
