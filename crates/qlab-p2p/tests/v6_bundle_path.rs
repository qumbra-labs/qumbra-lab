//! **Lab #785 F5-5b — the bundle path**: the producer's one-slot pool and its
//! P2P gossip, over a test bundle rule (no proof — the real rule is the 4b
//! fixture's, end to end in `qumbra-node`).
//!
//! The test rule's bundle is `tag u8 ‖ counter u64 ‖ valid_to u64`: tag 0xFF
//! fails the "signature" (a refusal the bytes alone prove), a counter not above
//! the surface's fails the thread, and a block above `valid_to` fails on
//! spacing (both judged against this node's state).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qlab_devnet::body::{BundleContext, BundleOutcome, BundleRefusal, BundleVerifier, TxEntry, TxVerifier, WrapperSetup};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState as _;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, BundleAdmit, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::codec::{encode_inv, InvItem, InvKind};
use qlab_p2p::{Envelope, Frame, MsgType, P2pNode};

#[derive(Clone)]
struct OkVerifier;
impl TxVerifier for OkVerifier {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

struct TestRule;
fn parse(b: &[u8]) -> Result<(u8, u64, u64), BundleRefusal> {
    if b.len() != 17 {
        return Err(BundleRefusal::Codec("length".into()));
    }
    Ok((b[0], u64::from_le_bytes(b[1..9].try_into().unwrap()), u64::from_le_bytes(b[9..17].try_into().unwrap())))
}
fn counter(surface: &[u8]) -> Result<u64, BundleRefusal> {
    Ok(u64::from_le_bytes(surface.try_into().map_err(|_| BundleRefusal::SurfaceState)?))
}
impl BundleVerifier for TestRule {
    fn verify_bundle(&self, header: &BlockHeader, bundle: &[u8], ctx: &BundleContext<'_>) -> Result<BundleOutcome, BundleRefusal> {
        let (tag, _, valid_to) = parse(bundle)?;
        if tag == 0xFF {
            return Err(BundleRefusal::Signature);
        }
        if header.height > valid_to {
            return Err(BundleRefusal::Spacing { since: header.height, need: valid_to });
        }
        self.fold_bundle(ctx.surface, bundle)
    }
    fn fold_bundle(&self, surface: &[u8], bundle: &[u8]) -> Result<BundleOutcome, BundleRefusal> {
        let (_, next, _) = parse(bundle)?;
        if next <= counter(surface)? {
            return Err(BundleRefusal::Wrapper("Thread".into()));
        }
        Ok(BundleOutcome { surface: next.to_le_bytes().to_vec(), exits: vec![], d_batch: 0, e_batch: 0 })
    }
    fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, BundleRefusal> {
        Ok(parse(bundle)?.1.to_le_bytes().to_vec())
    }
}

fn bundle(tag: u8, counter: u64, valid_to: u64) -> Vec<u8> {
    let mut b = vec![tag];
    b.extend_from_slice(&counter.to_le_bytes());
    b.extend_from_slice(&valid_to.to_le_bytes());
    b
}

type Adapter = NodeAdapter<KeccakPow, OkVerifier>;

fn adapter() -> Adapter {
    adapter_with(Arc::new(TestRule))
}

fn adapter_with(rule: Arc<dyn BundleVerifier + Send + Sync>) -> Adapter {
    let (committee, _) = devnet_committee(qlab_devnet::params_devnet::FROZEN_COMMITTEE_SIZE);
    let sim = SimConfig { genesis_difficulty: 1, block_time_secs: 2, ..SimConfig::default() };
    let wrapper = WrapperSetup { rule, genesis_surface: 0u64.to_le_bytes().to_vec() };
    NodeAdapter::new_v6(CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT), KeccakPow, OkVerifier, sim, Some(wrapper))
}

/// [`TestRule`], counting every full verification it is asked for.
struct Counting(Arc<AtomicUsize>);
impl BundleVerifier for Counting {
    fn verify_bundle(&self, header: &BlockHeader, bundle: &[u8], ctx: &BundleContext<'_>) -> Result<BundleOutcome, BundleRefusal> {
        self.0.fetch_add(1, Ordering::SeqCst);
        TestRule.verify_bundle(header, bundle, ctx)
    }
    fn fold_bundle(&self, surface: &[u8], bundle: &[u8]) -> Result<BundleOutcome, BundleRefusal> {
        TestRule.fold_bundle(surface, bundle)
    }
    fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, BundleRefusal> {
        TestRule.bundle_surface(bundle)
    }
}

fn counting() -> (Adapter, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    (adapter_with(Arc::new(Counting(Arc::clone(&n)))), n)
}

fn mine_and_apply(a: &mut Adapter) -> (BlockHeader, qlab_devnet::body::BlockBody) {
    let (h, b) = a.mine_block().expect("mine");
    assert_eq!(a.ingest_block(h, b.clone()), IngestOutcome::Accepted);
    (h, b)
}

/// Apply the next block on `a`'s tip, with or without the slot's bundle.
fn apply_next(a: &mut Adapter, keep_bundle: bool) -> IngestOutcome {
    let c = a.assemble_block().expect("a candidate");
    let (mut h, mut b) = (c.header, c.body);
    if !keep_bundle {
        b.bundle.clear();
        h.tx_body_commitment = b.commitment_v6();
    }
    a.ingest_block(h, b)
}

/// The slot: first wins, the operator route replaces, refusals say who pays,
/// the template carries the held bundle, a bundle block clears it, and a held
/// bundle that no longer verifies at a new tip is dropped.
#[test]
fn the_bundle_slot_is_first_wins_and_follows_the_tip() {
    let mut a = adapter();
    let b5 = bundle(0, 5, 100);
    assert_eq!(a.admit_bundle(b5.clone(), false), BundleAdmit::Admitted(qlab_devnet::hash::keccak256(&b5)));
    assert_eq!(a.admit_bundle(bundle(0, 6, 100), false), BundleAdmit::SlotHeld, "first wins");
    let b7 = bundle(0, 7, 100);
    assert!(matches!(a.admit_bundle(b7.clone(), true), BundleAdmit::Admitted(_)), "the operator route replaces");
    assert!(matches!(a.admit_bundle(bundle(0xFF, 8, 100), true), BundleAdmit::Refused { charged: true, .. }), "a bad signature is the sender's");
    assert!(matches!(a.admit_bundle(bundle(0, 8, 0), true), BundleAdmit::Refused { charged: false, .. }), "spacing is ours to judge");
    assert!(matches!(a.admit_bundle(bundle(0, 0, 100), true), BundleAdmit::Refused { charged: false, .. }), "so is the thread");
    assert_eq!(a.held_bundle_slot().map(|h| h.bytes.clone()), Some(b7.clone()), "refusals leave the slot alone");

    // The template carries it; applying that block clears the slot.
    assert_eq!(a.assemble_block().unwrap().body.bundle, b7);
    assert_eq!(apply_next(&mut a, true), IngestOutcome::Accepted);
    assert!(a.held_bundle_slot().is_none(), "a bundle block cleared the slot");

    // Valid only at the next height: held, then dropped once the tip moves past it.
    let next = a.state().tip_height() + 1;
    assert!(matches!(a.admit_bundle(bundle(0, 9, next), false), BundleAdmit::Admitted(_)));
    assert_eq!(apply_next(&mut a, false), IngestOutcome::Accepted);
    assert!(a.held_bundle_slot().is_none(), "no longer verifies at the new tip: dropped");
}

type Node = P2pNode<InProcTransport, Adapter>;

fn run(nodes: &mut [&mut Node], rounds: u64, base_ms: u64) -> u64 {
    let mut now = base_ms;
    for _ in 0..rounds {
        now += 10;
        for n in nodes.iter_mut() {
            n.tick(now);
        }
    }
    now
}

/// Gossip: a bundle admitted on one node (the operator route) is advertised,
/// asked for, served and admitted on its peer; a second bundle from the same
/// peer inside the window is neither asked for nor admitted (first wins, and
/// one per window per peer).
#[test]
fn an_admitted_bundle_gossips_to_a_peer_once() {
    let hub = InProcHub::new();
    let mut a = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let mut b = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    let now = run(&mut [&mut a, &mut b], 20, 0);
    let first = bundle(0, 5, 100);
    assert!(matches!(a.submit_bundle(first.clone(), false), BundleAdmit::Admitted(_)));
    let now = run(&mut [&mut a, &mut b], 20, now);
    assert_eq!(b.node().held_bundle_slot().map(|h| h.bytes.clone()), Some(first.clone()), "gossiped and admitted");
    let second = bundle(0, 6, 100);
    assert!(matches!(a.submit_bundle(second, true), BundleAdmit::Admitted(_)));
    run(&mut [&mut a, &mut b], 20, now);
    assert_eq!(b.node().held_bundle_slot().map(|h| h.bytes.clone()), Some(first), "first wins on the peer");
}

// ---- F5-5b pre-review X8 ----

/// X1 (c): a bundle refused at a tip is not verified again at that tip; once
/// the tip moves it is judged afresh. One refused on its bytes alone is never
/// verified again, at any tip.
#[test]
fn a_refused_bundle_is_not_verified_twice() {
    let (mut a, n) = counting();
    let stale = bundle(0, 0, 100); // counter 0 is not above the surface's 0: the thread
    assert!(matches!(a.admit_bundle(stale.clone(), false), BundleAdmit::Refused { charged: false, .. }));
    assert_eq!(n.load(Ordering::SeqCst), 1);
    let again = a.admit_bundle(stale.clone(), false);
    assert!(matches!(&again, BundleAdmit::Refused { charged: false, reason } if reason.contains("refused before at this tip")), "{again:?}");
    assert_eq!(n.load(Ordering::SeqCst), 1, "same bytes, same tip: not re-verified");
    assert!(a.bundle_not_wanted(&qlab_devnet::hash::keccak256(&stale)), "nor asked for");

    let forged = bundle(0xFF, 9, 100);
    assert!(matches!(a.admit_bundle(forged.clone(), false), BundleAdmit::Refused { charged: true, .. }));
    assert_eq!(n.load(Ordering::SeqCst), 2);

    mine_and_apply(&mut a);
    assert!(!a.bundle_not_wanted(&qlab_devnet::hash::keccak256(&stale)), "a context refusal is about one tip");
    assert!(matches!(a.admit_bundle(stale, false), BundleAdmit::Refused { charged: false, .. }));
    assert_eq!(n.load(Ordering::SeqCst), 3, "a new tip: judged afresh");
    assert!(matches!(a.admit_bundle(forged.clone(), false), BundleAdmit::Refused { charged: true, .. }));
    assert_eq!(n.load(Ordering::SeqCst), 3, "refused on its bytes: never verified again");
    assert!(a.bundle_not_wanted(&qlab_devnet::hash::keccak256(&forged)));
}

/// X3: the bundle a main-chain block carries is not asked for again — until a
/// reorg drops that block, when the sequencer's re-post must propagate.
#[test]
fn a_bundle_lost_in_a_reorg_is_wanted_again() {
    let mut a = adapter();
    let mut b = adapter();
    b.set_miner_rkm([7; 4]);
    for _ in 0..2 {
        let (h, body) = mine_and_apply(&mut a);
        assert_eq!(b.ingest_block(h, body), IngestOutcome::Accepted);
    }
    let b5 = bundle(0, 5, 100);
    let id = qlab_devnet::hash::keccak256(&b5);
    assert!(matches!(a.admit_bundle(b5.clone(), false), BundleAdmit::Admitted(_)));
    let (h3, body3) = mine_and_apply(&mut a);
    assert_eq!(body3.bundle, b5, "a's block 3 carries it");
    assert!(a.held_bundle_slot().is_none());
    assert!(a.bundle_not_wanted(&id), "applied on the main chain: not asked for again");

    // b's branch, without the bundle, outgrows a's: 3', 4'.
    let (h3x, b3x) = mine_and_apply(&mut b);
    let (h4x, b4x) = mine_and_apply(&mut b);
    assert_ne!(h3x.header_hash_for(qlab_devnet::forms::GenesisForm::V5), h3.header_hash_for(qlab_devnet::forms::GenesisForm::V5));
    let _ = a.ingest_block(h3x, b3x.clone());
    let _ = a.ingest_block(h4x, b4x);
    let _ = a.ingest_block(h3x, b3x);
    assert_eq!(a.state().tip_hash(), b.state().tip_hash(), "a reorged onto b's branch");
    assert!(!a.bundle_not_wanted(&id), "the block that carried it is gone: wanted again");
    assert!(matches!(a.admit_bundle(b5, false), BundleAdmit::Admitted(_)), "the re-post is admitted");
}

/// X4: a block carrying a bundle whose header does not hold up is refused on
/// the header — the bundle rule never runs for it.
#[test]
fn a_forged_header_is_refused_before_the_bundle_rule() {
    let (mut a, n) = counting();
    assert!(matches!(a.admit_bundle(bundle(0, 5, 100), false), BundleAdmit::Admitted(_)));
    assert_eq!(n.load(Ordering::SeqCst), 1);
    let c = a.assemble_block().expect("a candidate");
    assert!(!c.body.bundle.is_empty());
    let mut forged = c.header;
    forged.difficulty += 1_000; // not the chain's next difficulty
    let out = a.ingest_block(forged, c.body.clone());
    assert!(matches!(out, IngestOutcome::Rejected(_)), "{out:?}");
    assert_eq!(n.load(Ordering::SeqCst), 1, "the header failed first: no bundle verification");
    assert_eq!(a.state().tip_height(), 0);
}

type Raw = InProcTransport;

/// Two nodes; `a` is ticked only by the test's choice, so its transport
/// serves as a raw peer: frames sent from it are hand-crafted, and its inbox
/// shows what `b` asked.
fn raw_pair() -> (Node, Node, u64) {
    let hub = InProcHub::new();
    let mut a = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let mut b = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    let now = run(&mut [&mut a, &mut b], 20, 0);
    let _ = a.transport().poll();
    (a, b, now)
}

fn send(from: &Raw, msg: MsgType, payload: Vec<u8>) {
    from.send(PeerId(2), &Envelope::new(msg, payload).encode()).unwrap();
}

fn advertise(from: &Raw, bytes: &[u8]) {
    send(from, MsgType::Inv, encode_inv(&[InvItem { kind: InvKind::Bundle, id: qlab_devnet::hash::keccak256(bytes) }]));
}

/// How many `GetData` frames `b` sent `a` since the last look.
fn asks(a: &Node) -> usize {
    a.transport()
        .poll()
        .iter()
        .filter(|(_, f)| matches!(Frame::decode(f), Ok(Frame::Known(e)) if e.msg_type == MsgType::GetData))
        .count()
}

fn score(b: &Node) -> i32 {
    b.peers().get(PeerId(1)).expect("a is b's peer").score
}

/// X8: an unasked Bundle frame and one whose bytes are not the asked id are
/// dropped uncharged; an ask is one at a time, and one unanswered past
/// `BUNDLE_ASK_TIMEOUT_MS` is forgotten, so the advert is asked for again.
#[test]
fn unasked_and_mismatched_bundles_are_dropped_and_an_ask_times_out() {
    let (a, mut b, mut now) = raw_pair();
    let good = bundle(0, 5, 100);
    send(a.transport(), MsgType::Bundle, good.clone());
    now += 10;
    b.tick(now);
    assert!(b.node().held_bundle_slot().is_none(), "unasked: dropped");
    assert_eq!(score(&b), 0, "and not charged");

    advertise(a.transport(), &good);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 1, "an advert is asked for");
    send(a.transport(), MsgType::Bundle, bundle(0, 6, 100));
    now += 10;
    b.tick(now);
    assert!(b.node().held_bundle_slot().is_none(), "not the asked bytes: dropped");
    assert_eq!(score(&b), 0);
    advertise(a.transport(), &good);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 0, "one ask in flight per peer");

    now += qlab_p2p::node::BUNDLE_ASK_TIMEOUT_MS + 10;
    b.tick(now);
    advertise(a.transport(), &good);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 1, "the timed-out ask is forgotten");
    send(a.transport(), MsgType::Bundle, good.clone());
    now += 10;
    b.tick(now);
    assert_eq!(b.node().held_bundle_slot().map(|h| h.bytes.clone()), Some(good));
}

/// X1 (b) / X8: any answer starts the peer's window — a refused one too — so
/// a peer is asked for at most one bundle per `BUNDLE_PEER_WINDOW_BLOCKS`.
#[test]
fn a_peer_is_asked_for_one_bundle_per_window_whatever_the_verdict() {
    let (a, mut b, mut now) = raw_pair();
    let stale = bundle(0, 0, 100);
    advertise(a.transport(), &stale);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 1);
    send(a.transport(), MsgType::Bundle, stale);
    now += 10;
    b.tick(now);
    assert!(b.node().held_bundle_slot().is_none(), "refused at b's tip");
    assert_eq!(score(&b), 0, "a context refusal is not charged");

    let good = bundle(0, 5, 1_000);
    advertise(a.transport(), &good);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 0, "inside the window: not asked");

    for _ in 0..qlab_p2p::node::BUNDLE_PEER_WINDOW_BLOCKS {
        mine_and_apply(b.node_mut());
    }
    let _ = a.transport().poll();
    advertise(a.transport(), &good);
    now += 10;
    b.tick(now);
    assert_eq!(asks(&a), 1, "the window has passed");
}
