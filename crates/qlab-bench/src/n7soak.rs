//! M9-N7 — full-node composition + N-node in-process soak harness.
//!
//! Composes the real node-state (`qlab_p2p::adapter::NodeAdapter` over the
//! qlab-node state machine + N4 mempool + N5 committee) with the P2P layer
//! (`qlab_p2p::P2pNode`) and PoW block production (N3) into one `FullNode`, then
//! runs N of them over a single deterministic `InProcHub` to exercise:
//!
//! - **sync-from-genesis under churn** (S1),
//! - **adversarial peers** — invalid proofs / blocks / checkpoints / evidence all
//!   rejected without crash (S2),
//! - **restart / reorg / partition** (S3),
//! - **long-run leak check** (S4).
//!
//! Determinism: a single seeded `SplitMix64` schedules churn/faults; KeccakPow is
//! the deterministic soak engine (a RandomXPow composition smoke test proves the
//! N3 engine slots in behind the same trait). The injected verifier is a marker
//! mock (`proof == b"ok"`); the seam is the exact `TxVerifier` that `m6devnet`
//! drives with the real `p3_uni_stark::verify` — the wiring is verifier-agnostic.

#![allow(dead_code)]

use std::sync::Arc;

use qlab_devnet::body::{TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState, Validator};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::BOND_AMOUNT;
use qlab_devnet::pow::KeccakPow;

use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

/// Marker verifier: a tx proof is valid iff its bytes are exactly `b"ok"`. Lets
/// the soak exercise the accept/reject paths deterministically without proving.
#[derive(Clone)]
pub struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

/// The soak node-state: real adapter over KeccakPow + the marker verifier.
pub type SoakAdapter = NodeAdapter<KeccakPow, MarkerVerifier>;
/// The composed full node: P2P + real node-state + PoW production.
pub type SoakP2p = P2pNode<InProcTransport, SoakAdapter>;

/// A soak sim-config: fast block time, low genesis difficulty (instant Keccak
/// mining), Monero-shape key schedule (unused by KeccakPow).
pub fn soak_sim() -> SimConfig {
    SimConfig { block_time_secs: 75, genesis_difficulty: 256, ..SimConfig::default() }
}

/// One composed full node in the mesh.
pub struct FullNode {
    pub p2p: SoakP2p,
    pub id: PeerId,
    /// Committee signing keys this node holds (only the designated proposer does).
    pub validators: Vec<Validator>,
}

impl FullNode {
    /// Build a full node with a fresh adapter over `committee`. `validators` is
    /// non-empty only for the checkpoint-proposing node.
    pub fn new(
        id: PeerId,
        node_id: [u8; 32],
        hub: &Arc<InProcHub>,
        committee: CommitteeState,
        validators: Vec<Validator>,
    ) -> Self {
        let transport = InProcTransport::new(id, Arc::clone(hub));
        let adapter = NodeAdapter::new(committee, KeccakPow, MarkerVerifier, soak_sim());
        FullNode { p2p: P2pNode::new(transport, adapter, node_id), id, validators }
    }

    /// One message-pump step.
    pub fn tick(&mut self) -> usize {
        self.p2p.tick()
    }

    pub fn tip_height(&self) -> u64 {
        use qlab_p2p::n1::ChainView;
        self.p2p.node().tip_height()
    }
    pub fn tip_hash(&self) -> [u8; 32] {
        use qlab_p2p::n1::ChainView;
        self.p2p.node().tip_hash()
    }
    pub fn finalized_height(&self) -> Option<u64> {
        use qlab_p2p::n1::ChainView;
        self.p2p.node().finalized_height()
    }

    /// Mine the next block over the tip and announce it (the announce path ingests
    /// + applies the body via `ingest_block`). Returns false if mining was not
    /// possible (no parent / budget exhausted).
    pub fn mine_and_announce(&mut self, nonce: u64) -> bool {
        match self.p2p.node_mut().mine_block() {
            Some((header, body)) => {
                self.p2p.announce_block(header, body.txs, body.coinbase, nonce);
                true
            }
            None => false,
        }
    }

    /// Propose + announce a fully-signed checkpoint for the main-chain block at
    /// `height` (proposer only). Returns false if this node cannot propose.
    pub fn checkpoint_and_announce(&mut self, height: u64) -> bool {
        if self.validators.is_empty() {
            return false;
        }
        let made = self.p2p.node().make_checkpoint(height, &self.validators);
        match made {
            Some((cp, votes)) => {
                self.p2p.announce_checkpoint(cp, votes);
                true
            }
            None => false,
        }
    }

    /// Locally submit a tx to the mempool + gossip it.
    pub fn announce_tx(&mut self, tx: TxEntry) {
        self.p2p.announce_tx(tx);
    }
}

/// A well-formed soak tx anchored at `anchor`, paying the posted 2×2 price, with a
/// verifier-accepted (`b"ok"`) or -rejected proof.
pub fn soak_tx(anchor: [u8; 32], nf: u8, good_proof: bool) -> TxEntry {
    TxEntry {
        proof: if good_proof { b"ok".to_vec() } else { b"bad".to_vec() },
        public: TxPublic {
            anchor,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(70); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}

/// Build a fully-connected mesh of `n` full nodes over one hub. Node 0 is the
/// checkpoint proposer (holds all committee validators). Committee size = 4
/// (quorum 3) — small and fast; the committee logic itself is unit-tested at the
/// frozen N=21 elsewhere.
pub fn mesh(n: u64) -> (Vec<FullNode>, Arc<InProcHub>) {
    let hub = InProcHub::new();
    let (committee, validators) = devnet_committee(4);
    // `Validator` (an ML-DSA signing key) is not `Clone`, so the whole set moves
    // into the proposer (node 0); other nodes verify votes with the public
    // committee. Scenarios that need proposer keys read `nodes[0].validators`.
    let mut validators = Some(validators);
    let mut nodes = Vec::new();
    for i in 0..n {
        let cstate = CommitteeState::new(committee.clone(), BOND_AMOUNT);
        let vs = if i == 0 { validators.take().unwrap() } else { Vec::new() };
        nodes.push(FullNode::new(PeerId(i + 1), [i as u8 + 1; 32], &hub, cstate, vs));
    }
    for i in 0..n {
        for j in 0..n {
            if i != j {
                hub.link(PeerId(i + 1), PeerId(j + 1));
                nodes[i as usize].p2p.add_peer(PeerId(j + 1), None);
            }
        }
    }
    (nodes, hub)
}

/// Drive a set of nodes to quiescence (no frames moved in a full round).
pub fn run(nodes: &mut [FullNode]) {
    for _ in 0..2000 {
        let mut moved = 0;
        for n in nodes.iter_mut() {
            moved += n.tick();
        }
        if moved == 0 {
            break;
        }
    }
}

/// Bench-mode entry (scenarios + report land in Task D).
pub fn run_n7soak(power: &str, _only: Option<&str>) {
    println!("# M9-N7 soak — placeholder (scenarios in Task D)");
    println!("power state: {power}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::pow::RandomXPow;
    use qlab_node::NodeState as _;
    use qlab_p2p::n1::{BlockIngest, ChainView};

    #[test]
    fn two_nodes_handshake_to_ready() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        assert!(nodes[0].p2p.peers().is_ready(PeerId(2)));
        assert!(nodes[1].p2p.peers().is_ready(PeerId(1)));
    }

    #[test]
    fn single_node_mines_applies_and_reports_new_tip() {
        let (mut nodes, _hub) = mesh(1);
        assert_eq!(nodes[0].tip_height(), 0);
        assert!(nodes[0].mine_and_announce(0xA1));
        assert_eq!(nodes[0].tip_height(), 1, "consensus tip advanced");
        assert_eq!(nodes[0].p2p.node().state().tip_height(), 1, "real state applied");
    }

    #[test]
    fn randomx_pow_composes_single_node() {
        // The N3 real PoW engine slots in behind the same trait: build an adapter
        // over RandomXPow, mine one block, and confirm the hash meets target.
        let (committee, _v) = devnet_committee(4);
        let cstate = CommitteeState::new(committee, BOND_AMOUNT);
        let mut a: NodeAdapter<RandomXPow, MarkerVerifier> =
            NodeAdapter::new(cstate, RandomXPow::new(), MarkerVerifier, soak_sim());
        // mine_block builds + validates the header under RandomX; ingest re-runs
        // validate_header (PoW under the key-block seed) before accepting.
        let (header, body) = a.mine_block().expect("randomx mines at low difficulty");
        assert_eq!(a.ingest_block(header, body), qlab_p2p::n1::IngestOutcome::Accepted);
        assert_eq!(a.chain().tip_height(), 1, "RandomX-mined block accepted into the chain");
    }
}
