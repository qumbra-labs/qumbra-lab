//! [`qlab_faucet::ChainView`] over the in-process node's live consensus state.
//!
//! The faucet library implements `ChainView` for `qlab_node::NodeRpc`, which is the
//! *wallet-facing RPC* composition. A node composed by `qumbra-node` has no such
//! RPC — it owns a [`MemNode`] behind the P2P adapter — so the same four facts are
//! read straight off the node state here. Same trait, same faucet code path; only
//! the source of the facts differs.
//!
//! A newtype rather than an `impl` on `&MemNode` because both the trait and the
//! type are foreign to this crate (the orphan rule), and a newtype is the honest
//! way to say "this is *our* view of someone else's node".

use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::header::Hash32;
use qlab_faucet::ChainView;
use qlab_node::{ChainStore, CommitmentStore, MemNode, NodeState};

/// A read-only [`ChainView`] over an in-process node.
///
/// Read-only is the whole point: a co-resident wallet reads consensus state and
/// writes only by submitting a transaction, which goes through the node's own
/// local-origination path and not through this.
pub struct NodeView<'a>(pub &'a MemNode);

impl NodeView<'_> {
    /// Main-chain commitment roots, **newest first**.
    ///
    /// The commitment root is not a header field — it is the root of the tree
    /// *prefix* that height's blocks had grown the tree to. So it is recomputed the
    /// same way `NodeRpc::main_chain_roots` recomputes it: accumulate each block's
    /// leaf contribution (its coinbase note since #101, plus its transactions'
    /// output commitments) and fold the tree at that prefix. Reproducing the walk
    /// rather than sharing it is a duplication, and it is called out as such in the
    /// PR — `NodeRpc`'s version is private, and a node composed by `qumbra-node`
    /// has no `NodeRpc` at all.
    fn main_chain_roots_newest_first(&self) -> Vec<Hash32> {
        let chain = self.0.chain();
        let tree = self.0.commitments().tree();
        let mut count = 0u64;
        let mut out = Vec::new();
        for hash in chain.chain().main_chain() {
            let Some(block) = chain.block(&hash) else { continue };
            if qlab_node::coinbase_note_leaf(block.header.height, &block.body()).is_some() {
                count += 1;
            }
            count += block.txs.iter().map(|t| t.commitments.len() as u64).sum::<u64>();
            out.push(qlab_note::hash::digest_bytes(&tree.root_at(count)));
        }
        out.reverse();
        out
    }
}

impl ChainView for NodeView<'_> {
    fn tip_height(&self) -> u64 {
        self.0.tip_height()
    }

    fn finalized_height(&self) -> Option<u64> {
        self.0.finalized_height()
    }

    fn is_valid_anchor(&self, root: &Hash32) -> bool {
        self.0.is_valid_anchor(root)
    }

    fn newest_anchor(&self) -> Option<Hash32> {
        // Newest-first, first hit wins — the same choice `NodeRpc::newest_anchor`
        // makes, and for the same reason the trait documents: without published
        // per-root heights, the newest root's unknown deadline is the latest of
        // those on offer.
        self.main_chain_roots_newest_first().into_iter().find(|r| self.0.is_valid_anchor(r))
    }

    fn tree(&self) -> &CommitmentTree {
        self.0.commitments().tree()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
    use qlab_devnet::header::BlockHeader;
    use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
    use qlab_node::genesis_block;

    struct NoTx;
    impl TxVerifier for NoTx {
        fn verify_tx(&self, _: &TxEntry) -> bool {
            unreachable!("fixture blocks carry no transactions")
        }
    }

    /// The cold start, at the seam the faucet reads: nothing finalized ⇒ no valid
    /// anchor, however tall the chain is.
    #[test]
    fn an_unfinalized_chain_offers_no_anchor() {
        let node = MemNode::in_memory(genesis_block(GENESIS_DIFFICULTY, 0));
        let view = NodeView(&node);
        assert_eq!(view.tip_height(), 0);
        assert_eq!(view.finalized_height(), None);
        assert!(view.newest_anchor().is_none(), "nothing finalized ⇒ no anchor");
    }

    /// A finalized tip's own commitment root is the newest valid anchor, and the
    /// leaf count recovered for it is the count the tree actually has — the two
    /// facts a witness must be cut against.
    #[test]
    fn the_newest_anchor_is_the_finalized_tip_root_and_its_prefix_resolves() {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        for height in 1..=3u64 {
            let body = BlockBody {
                txs: Vec::new(),
                coinbase: qlab_node::coinbase(height),
                coinbase_rkm: [height, 2, 3, 4],
            };
            let header =
                BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
            let hash = node.apply_block(header, body, &NoTx).expect("applies");
            node.finalize(hash).expect("finalize");
            tip = header;
        }
        let _ = tip;
        let view = NodeView(&node);
        assert_eq!(view.tip_height(), 3);
        let anchor = view.newest_anchor().expect("a finalized chain has an anchor");
        assert_eq!(
            anchor,
            node.commitment_root(),
            "the newest anchor is the live root, i.e. the finalized tip's prefix"
        );
        // One coinbase leaf per block since #101.
        assert_eq!(view.tree().len(), 3);
        assert_eq!(
            view.anchor_leaf_count(&anchor),
            Some(3),
            "the anchor pins the whole current prefix"
        );
    }
}
