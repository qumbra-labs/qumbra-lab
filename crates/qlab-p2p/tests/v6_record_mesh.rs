//! **Lab #785 F5-3b-2 — the V6 network path, end to end over the real
//! `NodeAdapter`.** The merge condition for 3b-2 (the ruling on issue #785):
//! node A finalizes checkpoint 8 → A's next mined block carries the finality
//! record → node B applies it over the wire and reports `recorded_finality ==
//! Some(8)` → a transaction anchored under the record is accepted by B.
//!
//! The committee is the frozen 21 (`FROZEN_COMMITTEE_SIZE`): a record is
//! 15–21 signatures by committee₀ index, so a smaller devnet committee could
//! never produce one.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, Checkpoint, CommitteeState, Validator, Vote};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{FROZEN_COMMITTEE_SIZE, FROZEN_QUORUM};
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState as _;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
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

const SIM_TICK_MS: u64 = 10;

fn easy_sim() -> SimConfig {
    SimConfig { block_time_secs: 2, genesis_difficulty: 8, mine_nonce_budget: 5_000_000, ..SimConfig::default() }
}

fn v6_adapter(committee: &qlab_devnet::committee::Committee) -> Adapter {
    NodeAdapter::new_v6(
        CommitteeState::new(committee.clone(), qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
        None,
    )
}

fn pair(committee: &qlab_devnet::committee::Committee) -> (Node, Node, Arc<InProcHub>) {
    let hub = InProcHub::new();
    let a = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), v6_adapter(committee), [1; 32]);
    let b = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), v6_adapter(committee), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    (a, b, hub)
}

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

fn sign(validators: &[Validator], cp: &Checkpoint, n: usize) -> Vec<Vote> {
    validators[..n].iter().map(|v| v.sign_checkpoint(cp)).collect()
}

fn tx(anchor: Hash32, nf: u8) -> TxEntry {
    TxEntry::with_placeholder_discovery(
        b"ok".to_vec(),
        TxPublic {
            anchor,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(80); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    )
}

fn mine(node: &mut Node) -> (BlockHeader, BlockBody) {
    node.node_mut().mine_block().expect("mine")
}

/// 🔒 **The 3b-2 merge condition.**
#[test]
fn a_v6_record_travels_from_the_finalizing_miner_to_its_peer() {
    assert_eq!(FROZEN_COMMITTEE_SIZE, 21);
    let (committee, validators) = devnet_committee(FROZEN_COMMITTEE_SIZE);
    let (mut a, mut b, _hub) = pair(&committee);
    a.add_peer(PeerId(2), None);
    b.add_peer(PeerId(1), None);
    let mut now = run(&mut [&mut a, &mut b], 50, 0);

    // The empty-tree root: every height below the first matured coinbase.
    let root = a.node().state().commitment_root();

    // Blocks 1–8, applied on both through their ingest (each extends the tip).
    for _ in 0..8 {
        let (h, body) = mine(&mut a);
        assert!(body.finality.is_empty(), "nothing is finalized yet: no record");
        assert_eq!(a.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
        assert_eq!(b.node_mut().ingest_block(h, body), IngestOutcome::Accepted);
    }

    // A finalizes checkpoint 8 with a quorum of committee₀.
    let hash8 = a.node().main_chain_hash_at(8).expect("height 8");
    let cp8 = Checkpoint::new(8, hash8, hash8);
    a.announce_checkpoint(cp8, sign(&validators, &cp8, FROZEN_QUORUM));
    assert_eq!(a.node().finality().finalized_height(), Some(8));

    // A's next block carries the record; over the wire, B applies it.
    let (h9, body9) = mine(&mut a);
    assert!(!body9.finality.is_empty(), "the miner includes the newest record it holds");
    assert_eq!(a.announce_block_body(h9, body9, 1), IngestOutcome::Accepted);
    now = run(&mut [&mut a, &mut b], 200, now);
    assert_eq!(b.node().tip_height(), 9, "B applied the record-carrying block");
    assert_eq!(b.node().state().recorded_finality(), Some(8));
    assert_eq!(a.node().state().recorded_finality(), Some(8));

    // A tx anchored under the record: admitted on A, mined, applied by B.
    a.node_mut().submit_tx_typed(tx(root, 0x61)).expect("admitted under local finality 8");
    let (h10, body10) = mine(&mut a);
    assert_eq!(body10.txs.len(), 1, "the template keeps a tx the record rule accepts");
    assert!(body10.finality.is_empty(), "record 8 is not above CR(parent) = 8: omitted, not included");
    assert_eq!(a.announce_block_body(h10, body10, 2), IngestOutcome::Accepted);
    run(&mut [&mut a, &mut b], 300, now);
    assert_eq!(b.node().tip_height(), 10, "B applied the block spending under the record");
    assert_eq!(b.node().tip_hash(), a.node().tip_hash());
}
