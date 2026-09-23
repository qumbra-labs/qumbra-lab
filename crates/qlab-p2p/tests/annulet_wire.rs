//! **B2b, the wire** (lab #708): Annulet nodes that meet only through
//! `P2pNode` frames on the in-process transport. A transaction a follower
//! originates reaches the producer on the Annulet tx wire; the producer seals
//! a block and relays it as a sealed `BlockAnnounce`, which the follower
//! reconstructs from its own pool and applies through the sealed ingest; a
//! late joiner syncs the sealed headers (`Headers` at the 3,462-B stride) and
//! fetches every historical body as a sealed announce. Proof verification is
//! mocked by name (B4's), as in the done-when test.

use std::sync::Arc;

use qlab_devnet::annulet::{
    genesis_body_commitment_annulet, AnnuletHeaderFields, L2FeeTable, L2ShapeTag, L2Surface, SequencerKey,
};
use qlab_devnet::body::{TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::ChainView;
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

#[derive(Clone)]
struct MockProofVerifier;
impl TxVerifier for MockProofVerifier {
    fn verify_tx(&self, e: &TxEntry) -> bool {
        e.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MockProofVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2 };
/// The test registry (asset 0, Cloaked) and its root — lab #710: every
/// header carries the root of the registry the node holds.
fn registry() -> Vec<qlab_node::registry_store::RegistryLeaf> {
    vec![qlab_node::registry_store::RegistryLeaf::cloaked(0)]
}

fn root() -> Hash32 {
    use qlab_node::registry_store::RegistryStore as _;
    qlab_node::registry_store::MemRegistryStore::from_genesis(&registry()).unwrap().root_bytes()
}
const SIM_TICK_MS: u64 = 10;

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

fn s_tx(anchor: Hash32, nf: u8) -> TxEntry {
    TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32]],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: FEES.tier_s,
        },
        discovery: vec![0x00],
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: root(), vpublic: None }.encode(),
    }
}

fn run(nodes: &mut [&mut Node], rounds: u64, now: &mut u64) {
    for _ in 0..rounds {
        *now += SIM_TICK_MS;
        for n in nodes.iter_mut() {
            n.tick(*now);
        }
    }
}

#[test]
fn annulet_nodes_relay_transactions_and_sealed_blocks_and_a_joiner_syncs_by_wire() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let hub = InProcHub::new();
    let mut producer = node(1, &hub, &key);
    let mut follower = node(2, &hub, &key);
    // A hub link only makes delivery possible; the handshake starts when each
    // side adds the other as a peer (the in-process mesh convention).
    hub.link(PeerId(1), PeerId(2));
    producer.add_peer(PeerId(2), None);
    follower.add_peer(PeerId(1), None);
    let mut now = 0u64;
    run(&mut [&mut producer, &mut follower], 20, &mut now);

    let mut carried = 0;
    for h in 1..=6u64 {
        if h % 2 == 1 {
            // The follower originates two S transactions; they cross the wire
            // (Inv → GetData → Tx on the Annulet tx wire) into the producer's pool.
            let root = follower.node().state().commitment_root();
            for k in 0..2u8 {
                follower.announce_tx_typed(s_tx(root, (h as u8) * 8 + k)).expect("the follower admits its own S tx");
            }
            run(&mut [&mut producer, &mut follower], 20, &mut now);
            assert_eq!(producer.node().mempool().len(), 2, "height {h}: both reached the producer by wire");
        }
        let (sealed, body) = producer.node_mut().seal_next_block(&key, 10 * h).expect("the producer seals");
        carried += body.txs.len();
        assert!(producer.relay_sealed_block(&sealed, &body, 0xC0FFEE + h) >= 1, "height {h}: announced");
        run(&mut [&mut producer, &mut follower], 20, &mut now);
        assert_eq!(follower.node().tip_hash(), sealed.id(), "height {h}: the follower took the sealed announce");
        assert_eq!(follower.node().state().tip_height(), h, "height {h}: and applied its body");
    }
    assert_eq!(carried, 6, "three blocks carried two S transactions each");
    for n in [&producer, &follower] {
        assert_eq!(ChainView::finalized_height(n.node()), Some(6), "final on acceptance, by wire");
        assert_eq!(n.node().state().nullifier_count(), 12);
    }
    assert_eq!(producer.node().state().commitment_root(), follower.node().state().commitment_root());

    // A late joiner: header-first sync of sealed headers, then every body
    // fetched as a sealed announce (the historical-body answer).
    let mut joiner = node(3, &hub, &key);
    hub.link(PeerId(3), PeerId(1));
    joiner.add_peer(PeerId(1), None);
    producer.add_peer(PeerId(3), None);
    run(&mut [&mut producer, &mut follower, &mut joiner], 400, &mut now);
    assert_eq!(joiner.node().tip_hash(), producer.node().tip_hash(), "the joiner synced the sealed headers");
    assert_eq!(joiner.node().state().tip_height(), 6, "and applied every historical body");
    assert_eq!(ChainView::finalized_height(joiner.node()), Some(6));
    assert_eq!(joiner.node().state().commitment_root(), producer.node().state().commitment_root());
    assert_eq!(joiner.node().pending_seal_count(), 0, "no seal is left waiting for a body");
    assert_eq!(
        joiner.node().sealed_header_at(6),
        producer.node().sealed_header_at(6),
        "and it serves the same sealed unit"
    );
}
