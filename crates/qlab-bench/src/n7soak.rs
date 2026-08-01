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
    /// Deterministic simulation clock in milliseconds, advanced one step per
    /// [`FullNode::tick`] (issue #91). `tick` needs a clock for the inbound rate
    /// limits; feeding it a wall clock here would make this soak's byte-identical
    /// reproducibility depend on how fast the machine is, and feeding it a frozen
    /// clock would leave the buckets unable to refill. A per-node monotone counter
    /// is both deterministic and honest about elapsed time.
    sim_ms: u64,
}

/// Simulated milliseconds one `tick` represents.
const SIM_TICK_MS: u64 = 10;

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
        FullNode { p2p: P2pNode::new(transport, adapter, node_id), id, validators, sim_ms: 0 }
    }

    /// One message-pump step, advancing this node's deterministic sim clock.
    pub fn tick(&mut self) -> usize {
        self.sim_ms += SIM_TICK_MS;
        self.p2p.tick(self.sim_ms)
    }

    /// Inbound frames this node's rate limiter dropped (issue #91). Asserted to be
    /// zero across the soak: honest traffic must not be throttled, and a soak that
    /// silently discarded frames would be measuring a different network than the
    /// one it reports on.
    pub fn throttled(&self) -> u64 {
        let s = self.p2p.rate_stats();
        s.throttled_frames + s.throttled_bytes
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
                self.p2p.announce_block(header, body.txs, body.coinbase, body.coinbase_rkm, nonce);
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
    TxEntry::with_placeholder_discovery(if good_proof { b"ok".to_vec() } else { b"bad".to_vec() }, TxPublic {
            anchor,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(70); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        })
}

/// Build a fully-connected mesh of `n` full nodes over one hub. Node 0 is the
/// checkpoint proposer (holds all committee validators). Committee size = 4
/// (quorum 3) — small and fast; the committee logic itself is unit-tested at the
/// frozen N=21 elsewhere.
pub fn mesh(n: u64) -> (Vec<FullNode>, Arc<InProcHub>, qlab_devnet::committee::Committee) {
    let hub = InProcHub::new();
    let (committee, validators) = devnet_committee(4);
    let committee_out = committee.clone();
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
    (nodes, hub, committee_out)
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

// ==========================================================================
// Soak scenarios (S1–S4)
// ==========================================================================

/// Summary of a convergence-style scenario.
pub struct SoakResult {
    pub name: &'static str,
    pub nodes: usize,
    pub blocks: u64,
    pub converged: bool,
    pub finalized: Option<u64>,
    pub detail: String,
}

/// Summary of the long-run leak check.
pub struct LeakResult {
    pub rounds: u64,
    /// (round, max mempool length across nodes) samples.
    pub samples: Vec<(u64, usize)>,
    pub bounded: bool,
    pub final_tip: u64,
    /// Inbound frames the rate limiter dropped across all nodes (issue #91).
    /// **Expected zero**: the caps exist to bound a flood, and a soak in which
    /// honest traffic is being silently discarded is describing a different
    /// network from the one it reports on.
    pub throttled: u64,
}

/// The genesis (finalized) commitment root of a node — a valid tx anchor.
fn genesis_anchor(node: &FullNode) -> [u8; 32] {
    use qlab_node::NodeState as _;
    node.p2p.node().state().commitment_root()
}

/// `Some(tip)` iff every node reports the same tip hash; else `None`.
fn all_tips(nodes: &[FullNode]) -> Option<[u8; 32]> {
    let first = nodes.first()?.tip_hash();
    if nodes.iter().all(|n| n.tip_hash() == first) {
        Some(first)
    } else {
        None
    }
}

/// The honest node's recorded score for a peer (default 0 if unknown).
fn peer_score(node: &FullNode, peer: PeerId) -> i32 {
    node.p2p.peers().get(peer).map(|p| p.score).unwrap_or(0)
}

/// Finalize genesis network-wide: the proposer checkpoints height 0 and gossips
/// it, so the genesis (empty-tree) root becomes a valid anchor on every node.
fn finalize_genesis(nodes: &mut [FullNode]) {
    nodes[0].checkpoint_and_announce(0);
    run(nodes);
}

/// S1 — sync-from-genesis under churn. A 3-node mesh mines blocks while one node
/// is transiently partitioned out (churn) and later re-syncs, and a fresh late
/// joiner header-syncs from genesis. Convergence on the ChainView tip is the gate.
pub fn scenario_sync_from_genesis_under_churn(seed: u64) -> SoakResult {
    use qlab_devnet::load::rng::SplitMix64;
    use qlab_p2p::sync::SyncPhase;

    let (mut nodes, hub, committee) = mesh(3);
    run(&mut nodes);
    finalize_genesis(&mut nodes);
    let mut rng = SplitMix64::new(seed);

    // Mine 5 blocks with all three linked → full-block convergence.
    for _ in 0..5 {
        nodes[0].mine_and_announce(rng.next_u64());
        run(&mut nodes);
    }

    // Churn: node 3 flaps its links (disconnect + reconnect) between blocks. It
    // reconnects before the next block flows, so announce-flood keeps it in step.
    // (Recovering a *gap* needs the header-sync path — exercised by the late joiner
    // below — since announce-flood drops orphans; this is a recorded finding.)
    hub.unlink(PeerId(3), PeerId(1));
    hub.unlink(PeerId(3), PeerId(2));
    run(&mut nodes);
    hub.link(PeerId(3), PeerId(1));
    hub.link(PeerId(3), PeerId(2));
    for _ in 0..2 {
        nodes[0].mine_and_announce(rng.next_u64());
        run(&mut nodes);
    }

    // A fresh late joiner (node 4) header-syncs from genesis.
    let mut late = FullNode::new(
        PeerId(4),
        [4u8; 32],
        &hub,
        CommitteeState::new(committee, BOND_AMOUNT),
        Vec::new(),
    );
    for p in 1..=3u64 {
        hub.link(PeerId(4), PeerId(p));
        late.p2p.add_peer(PeerId(p), None);
        nodes[(p - 1) as usize].p2p.add_peer(PeerId(4), None);
    }
    nodes.push(late);
    run(&mut nodes);

    let tip = all_tips(&nodes);
    let synced = matches!(nodes[3].p2p.sync_phase(), SyncPhase::Synced);
    let converged = tip.is_some() && synced;
    let finalized = nodes[0].finalized_height();
    SoakResult {
        name: "sync-from-genesis under churn",
        nodes: nodes.len(),
        blocks: nodes[0].tip_height(),
        converged,
        finalized,
        detail: format!(
            "all {} nodes on one tip: {}; late joiner Synced: {synced}",
            nodes.len(),
            tip.is_some()
        ),
    }
}

/// S2 — adversarial peers. Inject an invalid tx proof, a bad header, a block whose
/// body carries an invalid proof, a sub-quorum checkpoint, and forged equivocation
/// evidence. Every one must be rejected, honest state must be untouched, and the
/// process must not crash (the function returning is that proof).
pub fn scenario_adversarial_peers() -> SoakResult {
    use qlab_devnet::ebbflow::EquivocationEvidence;
    use qlab_devnet::header::BlockHeader;
    use qlab_p2p::codec::{encode_checkpoint_msg, encode_evidence_msg, encode_header, encode_tx};
    use qlab_p2p::compact::{encode_announce, BlockAnnounce, PrefilledTx};
    use qlab_p2p::transport::Transport;
    use qlab_p2p::wire::{Envelope, MsgType};

    let (mut nodes, _hub, _c) = mesh(2);
    run(&mut nodes);
    finalize_genesis(&mut nodes);
    let anchor = genesis_anchor(&nodes[1]);

    // Helper: adversary (node 0 = PeerId 1) sends a raw frame to honest node 1
    // (PeerId 2), which then processes it.
    macro_rules! inject {
        ($mt:expr, $payload:expr) => {{
            let frame = Envelope::new($mt, $payload).encode();
            let _ = nodes[0].p2p.transport().send(PeerId(2), &frame);
            nodes[1].tick();
        }};
    }

    let mut ok = true;
    let mut notes = Vec::new();
    let base_mempool = nodes[1].p2p.node().mempool().len();
    let base_final = nodes[1].finalized_height();

    // (a) invalid tx proof.
    let score0 = peer_score(&nodes[1], PeerId(1));
    inject!(MsgType::Tx, encode_tx(&soak_tx(anchor, 1, false)));
    let a_ok = nodes[1].p2p.node().mempool().len() == base_mempool
        && peer_score(&nodes[1], PeerId(1)) < score0;
    ok &= a_ok;
    notes.push(format!("bad-tx rejected+penalized:{a_ok}"));

    // (b) bad header — unknown parent (orphan), no crash, tip unmoved.
    let orphan_parent = BlockHeader::genesis(256, 99);
    let orphan = BlockHeader::child_of(&BlockHeader::child_of(&orphan_parent, 75, 256, [8; 32]), 150, 256, [9; 32]);
    let tip_before = nodes[1].tip_hash();
    inject!(MsgType::Header, encode_header(&orphan));
    let b_ok = nodes[1].tip_hash() == tip_before;
    ok &= b_ok;
    notes.push(format!("bad-header no-op:{b_ok}"));

    // (c) block whose body carries an invalid-proof tx → not applied.
    let state_tip_before = {
        use qlab_node::NodeState as _;
        nodes[1].p2p.node().state().tip_height()
    };
    // The header must commit to the body it announces (issue #77) — otherwise the
    // binding rejects it first and this case would no longer test what it claims.
    let bad_tx = soak_tx(anchor, 3, false);
    let bad_body = qlab_devnet::body::BlockBody { txs: vec![bad_tx.clone()], coinbase: 0, coinbase_rkm: [0; 4] };
    let bad_block_header =
        BlockHeader::child_of(&BlockHeader::genesis(256, 0), 75, 256, bad_body.commitment());
    let ann = BlockAnnounce {
        header: bad_block_header,
        nonce: 0,
        coinbase: 0,
        coinbase_rkm: [0; 4],
        short_ids: Vec::new(),
        prefilled: vec![PrefilledTx { index: 0, tx: bad_tx }],
    };
    inject!(MsgType::BlockAnnounce, encode_announce(&ann));
    run(&mut nodes);
    let c_ok = {
        use qlab_node::NodeState as _;
        nodes[1].p2p.node().state().tip_height() == state_tip_before
    };
    ok &= c_ok;
    notes.push(format!("bad-block not-applied:{c_ok}"));

    // (c2) issue #77 — an HONEST header announced with an EMPTY body. Every other
    //      body rule passes trivially on an empty body, so before the binding
    //      landed this was applied to state under a valid header. Must be rejected,
    //      penalized, and never applied.
    let score_c2 = peer_score(&nodes[1], PeerId(1));
    let honest_body =
        qlab_devnet::body::BlockBody { txs: vec![soak_tx(anchor, 4, true)], coinbase: 0, coinbase_rkm: [0; 4] };
    let honest_header =
        BlockHeader::child_of(&BlockHeader::genesis(256, 0), 75, 256, honest_body.commitment());
    let ann_empty = BlockAnnounce {
        header: honest_header,
        nonce: 0,
        coinbase: 0,
        coinbase_rkm: [0; 4],
        short_ids: Vec::new(),
        prefilled: Vec::new(),
    };
    inject!(MsgType::BlockAnnounce, encode_announce(&ann_empty));
    run(&mut nodes);
    let c2_ok = {
        use qlab_node::NodeState as _;
        nodes[1].p2p.node().state().tip_height() == state_tip_before
            && {
                use qlab_p2p::n1::ChainView as _;
                !nodes[1].p2p.node().has_header(&honest_header.header_hash())
            }
            && peer_score(&nodes[1], PeerId(1)) < score_c2
    };
    ok &= c2_ok;
    notes.push(format!("empty-body-under-honest-header rejected+penalized:{c2_ok}"));

    // (d) well-formed sub-quorum checkpoint (2 of quorum-3 votes) → NOT finalized and
    //     NOT penalized. Since M10-T0-5 (task-book S5), a well-formed partial vote set
    //     is honest progress toward a quorum, not an invalid object — it enters the
    //     cross-node tally and is relayed, never scored against the sender. (Pre-#70
    //     this was penalized; that scoring bug is exactly what banned honest 6/5/5/5
    //     peers and blocked distributed finality.)
    let score_d = peer_score(&nodes[1], PeerId(1));
    let cp = qlab_devnet::committee::Checkpoint::new(1, [0x11; 32], [0x11; 32]);
    let votes: Vec<_> = nodes[0].validators[..2].iter().map(|v| v.sign_checkpoint(&cp)).collect();
    inject!(MsgType::Checkpoint, encode_checkpoint_msg(&cp, &votes));
    let d_ok = nodes[1].finalized_height() == base_final
        && peer_score(&nodes[1], PeerId(1)) == score_d;
    ok &= d_ok;
    notes.push(format!("subquorum-cp not-finalized+not-penalized:{d_ok}"));

    // (d2) FORGED checkpoint — a valid signature attributed to the wrong signer index
    //      → NOT finalized AND penalized (task-book S5: forged/unknown/dup sets stay
    //      penalized; this preserves the adversarial-checkpoint coverage).
    let score_d2 = peer_score(&nodes[1], PeerId(1));
    let cp2 = qlab_devnet::committee::Checkpoint::new(2, [0x12; 32], [0x12; 32]);
    let forged_vote = qlab_devnet::committee::Vote {
        signer: 0,
        signature: nodes[0].validators[1].sign_checkpoint(&cp2).signature,
    };
    inject!(MsgType::Checkpoint, encode_checkpoint_msg(&cp2, &[forged_vote]));
    let d2_ok = nodes[1].finalized_height() == base_final
        && peer_score(&nodes[1], PeerId(1)) < score_d2;
    ok &= d2_ok;
    notes.push(format!("forged-cp rejected+penalized:{d2_ok}"));

    // (e) forged evidence (cp_a == cp_b → not conflicting) → not applied + penalized.
    let score_e = peer_score(&nodes[1], PeerId(1));
    let cpx = qlab_devnet::committee::Checkpoint::new(5, [0x55; 32], [0x55; 32]);
    let forged = EquivocationEvidence {
        cp_a: cpx,
        vote_a: nodes[0].validators[0].sign_checkpoint(&cpx),
        cp_b: cpx,
        vote_b: nodes[0].validators[0].sign_checkpoint(&cpx),
    };
    let tomb_before = {
        use qlab_p2p::n1::CommitteeControl;
        (0..4).any(|i| nodes[1].p2p.node().is_tombstoned(i))
    };
    inject!(MsgType::Evidence, encode_evidence_msg(&forged));
    let e_ok = {
        use qlab_p2p::n1::CommitteeControl;
        let tomb_after = (0..4).any(|i| nodes[1].p2p.node().is_tombstoned(i));
        !tomb_before && !tomb_after && peer_score(&nodes[1], PeerId(1)) < score_e
    };
    ok &= e_ok;
    notes.push(format!("forged-evidence rejected+penalized:{e_ok}"));

    SoakResult {
        name: "adversarial peers",
        nodes: 2,
        blocks: nodes[1].tip_height(),
        converged: ok,
        finalized: nodes[1].finalized_height(),
        detail: notes.join(", "),
    }
}

/// S3 — reorg/partition + restart. A partition builds competing branches (distinct
/// txs make them genuinely divergent); the heavier branch wins on heal and finality
/// is never violated. Separately, the qlab-node state machine is snapshotted and
/// re-opened, and `open == replay` proves restart-safety.
pub fn scenario_restart_reorg_partition(seed: u64) -> SoakResult {
    use qlab_devnet::body::BlockBody;
    use qlab_devnet::header::BlockHeader;
    use qlab_node::{genesis_block, MemNode, NodeState as _};

    // ---- partition → genuine fork → fork-choice picks the heavier branch ----
    // Note (recorded finding): qlab-p2p propagates blocks by announce-flood, and
    // `complete_block` drops orphans without kicking sync — so two long-running
    // partitioned groups do NOT auto-reconcile on heal. Reconciliation runs through
    // the header-first sync path, which fires on a taller-peer handshake. We model
    // heal with a fresh observer that joins post-heal and adopts the heaviest chain
    // (ChainState fork-choice over synced headers). Finality safety holds throughout.
    let (mut nodes, hub, committee) = mesh(4);
    run(&mut nodes);
    finalize_genesis(&mut nodes);
    let anchor = genesis_anchor(&nodes[0]);
    let pre_tip = nodes[0].tip_hash();

    // Partition into group A {PeerId 1,2} and group B {PeerId 3,4}.
    for (a, b) in [(1u64, 3), (1, 4), (2, 3), (2, 4)] {
        hub.unlink(PeerId(a), PeerId(b));
        hub.unlink(PeerId(b), PeerId(a));
    }
    // Distinct tx per group *after* the split, so the branches genuinely diverge.
    nodes[0].announce_tx(soak_tx(anchor, 1, true));
    for _ in 0..30 {
        if nodes[0].tick() + nodes[1].tick() == 0 {
            break;
        }
    }
    nodes[2].announce_tx(soak_tx(anchor, 2, true));
    for _ in 0..30 {
        if nodes[2].tick() + nodes[3].tick() == 0 {
            break;
        }
    }
    let mut rng_seed = seed;
    // Group A (node 0) mines 3; group B (node 2) mines 2 → A is the heavier branch.
    for _ in 0..3 {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        nodes[0].mine_and_announce(rng_seed);
        for _ in 0..50 {
            if nodes[0].tick() + nodes[1].tick() == 0 {
                break;
            }
        }
    }
    let heavy_tip = nodes[0].tip_hash();
    for _ in 0..2 {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        nodes[2].mine_and_announce(rng_seed);
        for _ in 0..50 {
            if nodes[2].tick() + nodes[3].tick() == 0 {
                break;
            }
        }
    }
    let branch_b_tip = nodes[2].tip_hash();
    let genuine_fork = heavy_tip != branch_b_tip
        && heavy_tip != pre_tip
        && branch_b_tip != pre_tip
        && nodes[0].tip_height() == nodes[2].tip_height() + 1;

    // Heal: relink every pair, then a fresh observer joins and syncs the canonical
    // (heaviest) chain via header-first sync.
    for a in 1..=4u64 {
        for b in 1..=4u64 {
            if a != b {
                hub.link(PeerId(a), PeerId(b));
            }
        }
    }
    let mut observer = FullNode::new(
        PeerId(5),
        [5u8; 32],
        &hub,
        CommitteeState::new(committee, BOND_AMOUNT),
        Vec::new(),
    );
    for p in 1..=4u64 {
        hub.link(PeerId(5), PeerId(p));
        observer.p2p.add_peer(PeerId(p), None);
        nodes[(p - 1) as usize].p2p.add_peer(PeerId(5), None);
    }
    nodes.push(observer);
    run(&mut nodes);

    let observer_tip = nodes[4].tip_hash();
    let heavier_won = observer_tip == heavy_tip;
    // No reorg past finality: the four partitioned nodes keep genesis finalized,
    // and no node ever finalized a higher (conflicting) block. The fresh observer
    // may be None (it header-synced but hasn't pulled checkpoints yet).
    let originals_final = nodes[..4].iter().all(|n| n.finalized_height() == Some(0));
    let no_overreach = nodes.iter().all(|n| matches!(n.finalized_height(), None | Some(0)));
    let finality_safe = originals_final && no_overreach;
    let reorg_ok = genuine_fork && heavier_won && finality_safe;

    // ---- restart (qlab-node snapshot vs replay) ----
    let dir = std::env::temp_dir().join(format!("qlab_n7_restart_{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let genesis = genesis_block(256, 0);
    let mut disk = MemNode::open(&dir, genesis.clone()).unwrap();
    let mut parent = BlockHeader::genesis(256, 0);
    for h in 1..=3u64 {
        let body = BlockBody { txs: Vec::new(), coinbase: 0, coinbase_rkm: [0; 4] };
        let header = BlockHeader::child_of(&parent, h * 75, 256, body.commitment());
        disk.apply_block(header, body, &MarkerVerifier).unwrap();
        parent = header;
    }
    disk.save_snapshot().unwrap();
    let pre_tip = disk.tip_height();
    let pre_root = disk.commitment_root();
    let pre_nf = disk.nullifier_count();
    drop(disk);
    let reopened = MemNode::open(&dir, genesis.clone()).unwrap();
    let replayed = MemNode::replay(&dir, genesis).unwrap();
    let restart_ok = reopened.tip_height() == pre_tip
        && replayed.tip_height() == pre_tip
        && reopened.commitment_root() == pre_root
        && replayed.commitment_root() == pre_root
        && reopened.nullifier_count() == pre_nf
        && replayed.nullifier_count() == pre_nf;
    let _ = std::fs::remove_dir_all(&dir);

    SoakResult {
        name: "restart / reorg / partition",
        nodes: nodes.len(),
        blocks: nodes[0].tip_height(),
        converged: reorg_ok && restart_ok,
        finalized: nodes[0].finalized_height(),
        detail: format!(
            "genuine-fork:{genuine_fork} observer-adopted-heavier:{heavier_won} finality-safe:{finality_safe} restart(open==replay):{restart_ok}"
        ),
    }
}

/// S4 — long-run leak check. A 3-node mesh runs `blocks` rounds with steady tx
/// flow; the max mempool length across nodes is sampled and must stay bounded
/// (txs drain as they are mined), never growing with round count.
pub fn scenario_long_run_leak_check(seed: u64, blocks: u64) -> LeakResult {
    let (mut nodes, _hub, _c) = mesh(3);
    run(&mut nodes);
    finalize_genesis(&mut nodes);
    let anchor = genesis_anchor(&nodes[0]);

    const BOUND: usize = 5;
    let mut samples = Vec::new();
    let mut bounded = true;
    let mut nf: u32 = 0;
    for round in 0..blocks {
        // Steady tx flow: a fresh good tx every 20 rounds (unique nullifier).
        if round % 20 == 0 {
            nf += 1;
            nodes[0].announce_tx(soak_tx(anchor, nf as u8, true));
            run(&mut nodes);
        }
        nodes[0].mine_and_announce(seed ^ round);
        run(&mut nodes);
        if round % 50 == 0 {
            let max_mp = nodes.iter().map(|n| n.p2p.node().mempool().len()).max().unwrap_or(0);
            samples.push((round, max_mp));
            if max_mp > BOUND {
                bounded = false;
            }
        }
    }
    LeakResult {
        rounds: blocks,
        samples,
        bounded,
        final_tip: nodes[0].tip_height(),
        throttled: nodes.iter().map(|n| n.throttled()).sum(),
    }
}

/// Bench-mode entry: run all four scenarios and print the T0 soak report.
pub fn run_n7soak(power: &str, _only: Option<&str>) {
    let s1 = scenario_sync_from_genesis_under_churn(1);
    let s2 = scenario_adversarial_peers();
    let s3 = scenario_restart_reorg_partition(2);
    let s4 = scenario_long_run_leak_check(3, 1000);

    println!("# M9-N7 — integration + soak (T0 readiness)\n");
    println!("power state: {power}\n");
    println!("## Scenarios\n");
    println!("| scenario | nodes | blocks | pass | finalized | detail |");
    println!("|---|---|---|---|---|---|");
    for r in [&s1, &s2, &s3] {
        println!(
            "| {} | {} | {} | {} | {:?} | {} |",
            r.name, r.nodes, r.blocks, r.converged, r.finalized, r.detail
        );
    }
    let s4_samples = s4
        .samples
        .iter()
        .map(|(r, m)| format!("r{r}:{m}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "| long-run leak check | 3 | {} | {} | — | max-mempool samples [{}]; \
         rate-limited frames {} over {} rounds x 3 nodes |",
        s4.final_tip, s4.bounded, s4_samples, s4.throttled, s4.rounds
    );
    println!("\n## Reproduction\n");
    println!("Deterministic (KeccakPow + seeded SplitMix64). Seeds: S1=1, S3=2, S4=3 (1000 rounds).");
    println!("Re-run: `cargo run --release -p qlab-bench -- n7soak`. Assertions are the pass gate (see the `n7soak::tests`).");
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::pow::RandomXPow;
    use qlab_node::NodeState as _;
    use qlab_p2p::n1::{BlockIngest, ChainView};

    #[test]
    fn two_nodes_handshake_to_ready() {
        let (mut nodes, _hub, _committee) = mesh(2);
        run(&mut nodes);
        assert!(nodes[0].p2p.peers().is_ready(PeerId(2)));
        assert!(nodes[1].p2p.peers().is_ready(PeerId(1)));
    }

    #[test]
    fn single_node_mines_applies_and_reports_new_tip() {
        let (mut nodes, _hub, _committee) = mesh(1);
        assert_eq!(nodes[0].tip_height(), 0);
        assert!(nodes[0].mine_and_announce(0xA1));
        assert_eq!(nodes[0].tip_height(), 1, "consensus tip advanced");
        assert_eq!(nodes[0].p2p.node().state().tip_height(), 1, "real state applied");
    }

    #[test]
    fn s1_sync_under_churn() {
        let r = scenario_sync_from_genesis_under_churn(1);
        assert!(r.converged, "all nodes converge + late joiner synced: {}", r.detail);
        assert_eq!(r.finalized, Some(0), "genesis finalized network-wide");
    }

    #[test]
    fn s2_adversarial_rejected() {
        let r = scenario_adversarial_peers();
        assert!(r.converged, "every adversarial object rejected without crash: {}", r.detail);
    }

    #[test]
    fn s3_restart_reorg_partition() {
        let r = scenario_restart_reorg_partition(2);
        assert!(r.converged, "reorg converges + finality-safe + restart open==replay: {}", r.detail);
        assert_eq!(r.finalized, Some(0), "no reorg past the finalized block");
    }

    #[test]
    fn s4_leak_bounded() {
        let r = scenario_long_run_leak_check(3, 300);
        assert!(r.bounded, "mempool stays bounded across the run: {:?}", r.samples);
        assert!(r.final_tip >= 300, "the chain made progress: tip {}", r.final_tip);
        // Issue #91: the in-limit half of the acceptance bar, at integration scale.
        // 300 rounds of honest mesh traffic — mining, tx flow, checkpoint gossip —
        // must not trip a single inbound budget. If this ever fails, the limits are
        // too tight for honest traffic and it is the limits that are wrong.
        assert_eq!(r.throttled, 0, "honest soak traffic is never rate-limited");
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
