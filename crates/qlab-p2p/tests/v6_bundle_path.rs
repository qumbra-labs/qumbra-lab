//! **Lab #785 F5-5b — the bundle path**: the producer's one-slot pool and its
//! P2P gossip, over a test bundle rule (no proof — the real rule is the 4b
//! fixture's, end to end in `qumbra-node`).
//!
//! The test rule's bundle is `tag u8 ‖ counter u64 ‖ valid_to u64`: tag 0xFF
//! fails the "signature" (a refusal the bytes alone prove), a counter not above
//! the surface's fails the thread, and a block above `valid_to` fails on
//! spacing (both judged against this node's state).

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
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

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
    let (committee, _) = devnet_committee(qlab_devnet::params_devnet::FROZEN_COMMITTEE_SIZE);
    let sim = SimConfig { genesis_difficulty: 1, block_time_secs: 2, ..SimConfig::default() };
    let wrapper = WrapperSetup { rule: Arc::new(TestRule), genesis_surface: 0u64.to_le_bytes().to_vec() };
    NodeAdapter::new_v6(CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT), KeccakPow, OkVerifier, sim, Some(wrapper))
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
