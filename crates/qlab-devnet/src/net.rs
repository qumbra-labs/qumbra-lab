//! An **in-process** multi-node local sim: N [`Node`]s, block gossip, and
//! partition/heal — enough to drive the consensus scenarios (partition/rejoin,
//! committee-minority offline, miner-only liveness) deterministically.
//!
//! **In-process vs localhost — decision (M6 mandate leaves this to the builder):**
//! this sim is in-process. Every node is a `Node` in one `Vec`; "gossip" is a
//! synchronous method call. Rationale: the devnet's job is to exercise *consensus*
//! behaviour (fork choice under partition, quorum finality, degraded mode), none
//! of which localhost TCP would test more thoroughly — it would only add an async
//! runtime, socket setup, and timing nondeterminism (flaky tests) for no extra
//! consensus coverage. It also keeps us well inside the "no networking beyond
//! localhost" hard line. Real wire transport (compact-block relay, Dandelion++,
//! consensus §7/§9) is out of devnet scope. Justified here per the mandate.
//!
//! Gossip model: `mine` on a node immediately delivers the new block to same-group
//! peers, so a partition group stays perfectly in sync. `partition` splits the
//! network into non-gossiping groups; `heal` reunites them and redelivers every
//! block (height order) so nodes converge on the heaviest finality-respecting chain.

use crate::committee::{Checkpoint, CommitteeState, Vote};
use crate::ebbflow::FinalityStatus;
use crate::header::{BlockHeader, Hash32};
use crate::node::{Node, NodeError, SimConfig};
use crate::pow::PowEngine;

/// An in-process network of `Node`s with a partition map.
pub struct Network<P: PowEngine> {
    nodes: Vec<Node<P>>,
    /// Partition group id per node — nodes gossip only within the same group.
    group: Vec<usize>,
    /// Every header ever produced (any order); replayed on `heal`.
    all_headers: Vec<BlockHeader>,
}

impl<P: PowEngine + Clone> Network<P> {
    /// Build `n` nodes, all from the same genesis/config, all in one group.
    pub fn new(n: usize, pow: P, config: SimConfig) -> Self {
        assert!(n >= 1, "need at least one node");
        let nodes = (0..n).map(|_| Node::new(pow.clone(), config)).collect();
        Self { nodes, group: vec![0; n], all_headers: Vec::new() }
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Read-only access to node `i`.
    pub fn node(&self, i: usize) -> &Node<P> {
        &self.nodes[i]
    }

    /// Node `i`'s tip hash / height / finalized height / finality regime.
    pub fn tip_of(&self, i: usize) -> Hash32 {
        self.nodes[i].tip_hash()
    }
    pub fn tip_height_of(&self, i: usize) -> u64 {
        self.nodes[i].tip_height()
    }
    pub fn finalized_height_of(&self, i: usize) -> Option<u64> {
        self.nodes[i].finalized_height()
    }
    pub fn finality_status_of(&self, i: usize) -> FinalityStatus {
        self.nodes[i].finality_status()
    }

    /// Node `i` mines a block on its tip and gossips it to same-group peers.
    pub fn mine(&mut self, i: usize, body: Hash32) -> Result<Hash32, NodeError> {
        let hash = self.nodes[i].mine_next(body)?;
        let header = *self.nodes[i].chain().header(&hash).expect("just-mined header present");
        self.all_headers.push(header);
        let g = self.group[i];
        for j in 0..self.nodes.len() {
            if j != i && self.group[j] == g {
                let _ = self.nodes[j].submit(header); // Duplicate/late errors are benign
            }
        }
        Ok(hash)
    }

    /// Split the network into non-gossiping partition groups. Each inner slice is
    /// one group; listed nodes get that group id, unlisted nodes keep their own.
    pub fn partition(&mut self, groups: &[&[usize]]) {
        for (gid, members) in groups.iter().enumerate() {
            for &m in *members {
                self.group[m] = gid + 1; // +1 to differ from the default group 0
            }
        }
    }

    /// Reunite all partitions and redeliver every block (height order → parents
    /// first) to every node, so they converge on the heaviest chain that respects
    /// each node's finalized prefix.
    pub fn heal(&mut self) {
        for g in self.group.iter_mut() {
            *g = 0;
        }
        let mut headers = self.all_headers.clone();
        headers.sort_by_key(|h| h.height);
        for h in &headers {
            for node in self.nodes.iter_mut() {
                let _ = node.submit(*h); // Duplicate on already-known blocks is benign
            }
        }
    }

    /// Deliver a finalized checkpoint + committee votes to the listed nodes.
    /// Returns each node's finalize result.
    pub fn finalize_on(
        &mut self,
        node_idxs: &[usize],
        cp: &Checkpoint,
        votes: &[Vote],
        cstate: &CommitteeState,
    ) -> Vec<Result<(), NodeError>> {
        node_idxs.iter().map(|&i| self.nodes[i].finalize(cp, votes, cstate)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{devnet_committee, CommitteeState, Vote};
    use crate::finality::FinalizeError;
    use crate::header::ZERO_HASH;
    use crate::params_devnet::BOND_AMOUNT;
    use crate::pow::KeccakPow;

    fn cfg() -> SimConfig {
        SimConfig { block_time_secs: 2, genesis_difficulty: 8, mine_nonce_budget: 5_000_000, ..SimConfig::default() }
    }

    /// Partition then rejoin: two groups diverge above a finalized point; on heal
    /// all nodes converge on the heavier branch, and none reorgs below finality.
    #[test]
    fn partition_rejoin_converges_and_respects_finality() {
        let mut net = Network::new(4, KeccakPow, cfg());
        let (committee, validators) = devnet_committee(7); // quorum 5
        let cstate = CommitteeState::new(committee, BOND_AMOUNT);

        // One group: mine to height 3; all four nodes agree.
        for _ in 0..3 {
            net.mine(0, ZERO_HASH).unwrap();
        }
        let tip3 = net.tip_of(0);
        for i in 0..4 {
            assert_eq!(net.tip_of(i), tip3);
            assert_eq!(net.tip_height_of(i), 3);
        }

        // Finalize height 2 on every node.
        let cp = net.node(0).checkpoint_at(2).unwrap();
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        for r in net.finalize_on(&[0, 1, 2, 3], &cp, &votes, &cstate) {
            r.unwrap();
        }

        // Partition {0,1} | {2,3}. Group A mines 4 blocks, group B mines 2 ⇒ A heavier.
        net.partition(&[&[0, 1], &[2, 3]]);
        for _ in 0..4 {
            net.mine(0, [0xA1; 32]).unwrap();
        }
        for _ in 0..2 {
            net.mine(2, [0xB1; 32]).unwrap();
        }
        assert_ne!(net.tip_of(0), net.tip_of(2), "groups diverged");
        assert_eq!(net.tip_height_of(0), 7);
        assert_eq!(net.tip_height_of(2), 5);

        // Heal: all converge on the heavier A branch (height 7)...
        net.heal();
        let converged = net.tip_of(0);
        for i in 0..4 {
            assert_eq!(net.tip_of(i), converged, "node {i} converges");
            assert_eq!(net.tip_height_of(i), 7);
            // ...and none reorged below the finalized height 2.
            assert_eq!(net.finalized_height_of(i), Some(2));
            assert!(net.node(i).chain().descends_from_finalized(&converged));
        }
    }

    /// Committee-minority offline: below quorum ⇒ nobody finalizes (degraded);
    /// once enough come online ⇒ finality lands on every node.
    #[test]
    fn committee_minority_offline_blocks_then_resumes_finality() {
        let mut net = Network::new(3, KeccakPow, cfg());
        let (committee, validators) = devnet_committee(7); // quorum 5
        let cstate = CommitteeState::new(committee, BOND_AMOUNT);
        for _ in 0..3 {
            net.mine(0, ZERO_HASH).unwrap();
        }
        let cp = net.node(0).checkpoint_at(2).unwrap();

        // Only 4 of 7 online (3 offline) — below the 5 quorum.
        let votes4: Vec<Vote> = validators[..4].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        for r in net.finalize_on(&[0, 1, 2], &cp, &votes4, &cstate) {
            assert_eq!(r, Err(NodeError::Finalize(FinalizeError::InsufficientQuorum { have: 4, need: 5 })));
        }
        for i in 0..3 {
            assert_eq!(net.finalized_height_of(i), None);
            assert_eq!(net.finality_status_of(i), FinalityStatus::Degraded);
        }

        // A fifth validator comes online ⇒ quorum met ⇒ finalizes everywhere.
        let votes5: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        for r in net.finalize_on(&[0, 1, 2], &cp, &votes5, &cstate) {
            r.unwrap();
        }
        for i in 0..3 {
            assert_eq!(net.finalized_height_of(i), Some(2));
        }
    }

    /// Miner-only liveness: with no committee finality at all, mining continues,
    /// every node stays in sync via gossip, and the chain keeps growing (degraded
    /// probabilistic mode) — the liveness the Ebb-and-Flow split guarantees (§4).
    #[test]
    fn miner_only_liveness_keeps_chain_growing_degraded() {
        let mut net = Network::new(3, KeccakPow, cfg());
        for round in 0..12usize {
            net.mine(round % 3, ZERO_HASH).unwrap(); // round-robin miners
        }
        let tip = net.tip_of(0);
        for i in 0..3 {
            assert_eq!(net.tip_of(i), tip, "all nodes share the tip via gossip");
            assert_eq!(net.tip_height_of(i), 12);
            assert_eq!(net.finality_status_of(i), FinalityStatus::Degraded, "no finality ⇒ degraded");
        }
    }
}
