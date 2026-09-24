//! **Annulet catch-up at scale, and out of order** (lab #716, B6 named tests
//! (b) and (c)) — the B2 leftovers the devnet exercises.
//!
//! - **(b)** A joiner catches up a sealed chain longer than two full
//!   `Headers` batches (2,000 × 3,462 B ≈ 6.9 MB each) through the **real
//!   default rate limiter**: the full batch fits `MAX_PAYLOAD` and the
//!   inbound byte burst, and the joiner reaches the tip with every body
//!   applied.
//! - **(c)** A joiner whose body answers are **lost and then reordered**
//!   (served backwards, the frontier withheld) still converges: the lost asks
//!   are **re-asked** after `BODY_REQUEST_TIMEOUT_MS`, and the chain applies
//!   to the tip.
//!
//! Proof verification is mocked by name, as in B2's wire test; the blocks
//! here are empty — the subject is headers and bodies on the wire.

use std::sync::Arc;

use qlab_devnet::annulet::{genesis_body_commitment_annulet, AnnuletHeaderFields, L2FeeTable, SequencerKey};
use qlab_devnet::body::{TxEntry, TxVerifier};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{decode_inv, encode_wire_headers, InvKind};
use qlab_p2p::compact::{encode_announce, BlockAnnounce};
use qlab_p2p::n1::ChainView;
use qlab_p2p::node::BODY_REQUEST_TIMEOUT_MS;
use qlab_p2p::peer::PeerId;
use qlab_p2p::ratelimit::BYTE_BURST;
use qlab_p2p::sync::MAX_HEADERS_PER_BATCH;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Envelope, Frame, MsgType, MAX_PAYLOAD};
use qlab_p2p::P2pNode;

#[derive(Clone)]
struct MockProofVerifier;
impl TxVerifier for MockProofVerifier {
    fn verify_tx(&self, e: &TxEntry) -> bool {
        e.proof == b"ok"
    }
}

type Node = P2pNode<InProcTransport, NodeAdapter<KeccakPow, MockProofVerifier>>;

const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2, tier_r: 4 };
const SIM_TICK_MS: u64 = 10;

fn registry() -> Vec<qlab_node::registry_store::RegistryLeaf> {
    vec![qlab_node::registry_store::RegistryLeaf::cloaked(0)]
}

fn root() -> Hash32 {
    use qlab_node::registry_store::RegistryStore as _;
    qlab_node::registry_store::MemRegistryStore::from_genesis(&registry()).unwrap().root_bytes()
}

fn genesis() -> BlockHeader {
    let ext = AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: root() };
    BlockHeader::genesis_annulet(ext, genesis_body_commitment_annulet(&[]), 0)
}

fn node(id: u64, hub: &Arc<InProcHub>, key: &SequencerKey) -> Node {
    let adapter = NodeAdapter::annulet(
        genesis(),
        &[],
        FEES,
        &registry(),
        key.verifying_key(),
        KeccakPow,
        MockProofVerifier,
        SimConfig::default(),
    );
    P2pNode::new(InProcTransport::new(PeerId(id), Arc::clone(hub)), adapter, [id as u8; 32])
}

/// Seal `n` empty blocks on the producer (each applied through its own
/// sealed ingest, as a follower would).
fn seal_chain(producer: &mut Node, key: &SequencerKey, n: u64) {
    for h in 1..=n {
        producer.node_mut().seal_next_block(key, 10 * h).expect("the producer seals");
    }
    assert_eq!(producer.node().state().tip_height(), n);
}

/// Tick every node until `done` holds, at most `max_ticks`; returns the ticks used.
fn run_until(nodes: &mut [&mut Node], now: &mut u64, max_ticks: u64, done: impl Fn(&[&mut Node]) -> bool) -> u64 {
    for t in 0..max_ticks {
        if done(nodes) {
            return t;
        }
        *now += SIM_TICK_MS;
        for n in nodes.iter_mut() {
            n.tick(*now);
        }
    }
    panic!("did not converge in {max_ticks} ticks");
}

/// 🔴 **(b)**: a joiner catches up 4,100 sealed blocks — two full 2,000-header
/// batches and a remainder — through the default limiter.
#[test]
fn a_joiner_catches_up_past_two_full_sealed_header_batches_through_the_limiter() {
    const N: u64 = 2 * MAX_HEADERS_PER_BATCH as u64 + 100;
    let key = SequencerKey::from_seed([0x5E; 32]);
    let hub = InProcHub::new();
    let mut producer = node(1, &hub, &key);
    let started = std::time::Instant::now();
    seal_chain(&mut producer, &key, N);
    eprintln!("B6 (b): sealed {N} blocks in {:?}", started.elapsed());

    // The full batch as the producer serves it: 2,000 sealed units under
    // MAX_PAYLOAD and inside one inbound byte burst.
    let units: Vec<_> = (1..=MAX_HEADERS_PER_BATCH as u64)
        .map(|h| {
            let id = producer.node().sealed_header_at(h).expect("sealed").id();
            producer.node().wire_header(&id).expect("a sealed unit")
        })
        .collect();
    let payload = encode_wire_headers(GenesisForm::Annulet, &units);
    let frame = Envelope::new(MsgType::Headers, payload.clone()).encode();
    eprintln!("B6 (b): a full sealed Headers batch is {} B (frame {} B)", payload.len(), frame.len());
    assert!(payload.len() as u64 <= MAX_PAYLOAD as u64, "the full batch fits MAX_PAYLOAD");
    assert!(frame.len() as u64 <= BYTE_BURST, "and one inbound byte burst");

    let mut joiner = node(3, &hub, &key);
    hub.link(PeerId(3), PeerId(1));
    joiner.add_peer(PeerId(1), None);
    producer.add_peer(PeerId(3), None);
    let mut now = 0;
    let started = std::time::Instant::now();
    let ticks = run_until(&mut [&mut producer, &mut joiner], &mut now, 200_000, |n| {
        n[1].node().state().tip_height() == N
    });
    eprintln!(
        "B6 (b): the joiner reached {N} in {ticks} ticks ({} sim-ms, {:?} wall); joiner limiter {:?}",
        now,
        started.elapsed(),
        joiner.rate_stats()
    );
    assert_eq!(joiner.node().tip_hash(), producer.node().tip_hash());
    assert_eq!(ChainView::finalized_height(joiner.node()), Some(N));
    assert_eq!(joiner.node().pending_seal_count(), 0);
    assert_eq!(joiner.node().sealed_header_at(N), producer.node().sealed_header_at(N));
}

/// Take every frame waiting in `node`'s inbox without processing it.
fn intercept(node: &Node) -> Vec<(PeerId, Vec<u8>)> {
    node.transport().poll()
}

/// The block ids a batch of intercepted frames asks for with `GetData`.
fn asked_blocks(frames: &[(PeerId, Vec<u8>)]) -> Vec<Hash32> {
    frames
        .iter()
        .filter_map(|(_, f)| match Frame::decode(f) {
            Ok(Frame::Known(e)) if e.msg_type == MsgType::GetData => decode_inv(&e.payload).ok(),
            _ => None,
        })
        .flat_map(|inv| inv.items.into_iter().filter(|i| i.kind == InvKind::Block).map(|i| i.id))
        .collect()
}

/// 🔴 **(c)**: the first body answers are lost; bodies then arrive backwards
/// with the frontier withheld; the joiner re-asks after the timeout and
/// converges to the tip.
#[test]
fn a_joiner_whose_bodies_are_lost_and_reordered_converges_through_the_re_ask() {
    const N: u64 = 40;
    let key = SequencerKey::from_seed([0x5E; 32]);
    let hub = InProcHub::new();
    let mut producer = node(1, &hub, &key);
    seal_chain(&mut producer, &key, N);
    let sealed: Vec<_> = (1..=N).map(|h| producer.node().sealed_header_at(h).expect("sealed")).collect();
    let id_at = |h: u64| sealed[(h - 1) as usize].id();

    // The joiner holds block 1 applied and every later header: header-first
    // sync done, bodies owed.
    let mut joiner = node(2, &hub, &key);
    let body1 = producer.node().stored_body(&id_at(1)).expect("the producer holds block 1");
    assert!(matches!(joiner.node_mut().ingest_sealed_block(&sealed[0], body1), qlab_p2p::n1::IngestOutcome::Accepted));
    for s in &sealed[1..] {
        assert!(matches!(joiner.node_mut().ingest_sealed_header(s), qlab_p2p::n1::IngestOutcome::Accepted));
    }
    assert_eq!((joiner.node().state().tip_height(), joiner.node().tip_height()), (1, N));

    hub.link(PeerId(1), PeerId(2));
    producer.add_peer(PeerId(2), None);
    joiner.add_peer(PeerId(1), None);
    // Handshake only: the joiner's first body asks go out…
    producer.tick(10);
    joiner.tick(10);
    let first = intercept(&producer);
    let asked = asked_blocks(&first);
    assert!(asked.contains(&id_at(2)), "the joiner asked for the frontier");
    // …and are LOST: the producer never sees them. What else crossed (the
    // handshake's tail) is delivered.
    for (_, f) in first.iter().filter(|(_, f)| {
        !matches!(Frame::decode(f), Ok(Frame::Known(e)) if e.msg_type == MsgType::GetData)
    }) {
        joiner.transport().send(PeerId(1), f).expect("forward");
    }

    // Bodies 17 down to 3 arrive backwards, unasked-for-in-this-order; the
    // frontier (2) is withheld. None can apply.
    let mut now = 10;
    for h in (3..=17u64).rev() {
        let s = &sealed[(h - 1) as usize];
        let body = producer.node().stored_body(&s.id()).expect("stored");
        let ann = BlockAnnounce {
            seal: Some(s.sig.clone()),
            header: s.header,
            nonce: 0,
            coinbase_payees: body.coinbase_payees.clone(),
            short_ids: Vec::new(),
            prefilled: Vec::new(),
        };
        let frame = Envelope::new(MsgType::BlockAnnounce, encode_announce(GenesisForm::Annulet, &ann)).encode();
        producer.transport().send(PeerId(2), &frame).expect("send");
        now += SIM_TICK_MS;
        joiner.tick(now);
    }
    assert_eq!(joiner.node().state().tip_height(), 1, "nothing applies while the frontier is withheld");

    // Past the re-ask interval the joiner asks for the frontier again.
    // Whatever the reordered arrivals provoked (sync kicks, fetch-ahead asks)
    // is delivered: only the first asks were lost.
    for (_, f) in intercept(&producer) {
        joiner.transport().send(PeerId(1), &f).expect("forward");
    }
    now += BODY_REQUEST_TIMEOUT_MS + SIM_TICK_MS;
    joiner.tick(now);
    let second = intercept(&producer);
    assert!(
        asked_blocks(&second).contains(&id_at(2)),
        "the lost frontier ask is re-asked after BODY_REQUEST_TIMEOUT_MS"
    );
    for (_, f) in &second {
        joiner.transport().send(PeerId(1), f).expect("forward");
    }

    // From here the wire is honest; the joiner converges to the tip.
    let ticks = run_until(&mut [&mut producer, &mut joiner], &mut now, 100_000, |n| {
        n[1].node().state().tip_height() == N
    });
    eprintln!("B6 (c): converged to {N} in {ticks} more ticks ({now} sim-ms in all)");
    assert_eq!(joiner.node().tip_hash(), producer.node().tip_hash());
    assert_eq!(joiner.node().state().commitment_root(), producer.node().state().commitment_root());
    assert_eq!(ChainView::finalized_height(joiner.node()), Some(N));
    assert_eq!(joiner.node().pending_seal_count(), 0);
}
