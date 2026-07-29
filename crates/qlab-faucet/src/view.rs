//! What the faucet reads from a node — the narrow view, and the one thing the
//! published RPC surface cannot tell it.
//!
//! The faucet needs four facts to plan a grant: the tip height, whether a root is
//! a valid anchor *now*, the newest valid anchor, and the live commitment tree it
//! fetches membership witnesses from. [`ChainView`] is exactly those, implemented
//! for [`qlab_node::NodeRpc`] so the faucet plans against live node state without
//! reaching into node internals.
//!
//! ## The gap this trait documents (reported, not fixed — payload = stop point)
//!
//! `/v1/anchors` returns `roots` newest-first plus `tip_height`,
//! `finalized_height` and `max_age_blocks`, but **no per-root height**
//! (`qlab_node::rpc::AnchorSet`). A wallet holding a root can therefore establish
//! only "this is valid right now" — it cannot compute *when the root expires*,
//! which is precisely the fact a wallet planning a ~1.7 s proof needs. Carrying
//! `(height, root)` pairs would fix it in one field, and that is a **payload
//! change** — a stop point for this baton. So [`anchor_leaf_count`] recovers what
//! it can locally (which tree prefix the anchor is a root of, by scanning prefix
//! roots) and [`crate::grant::AnchorLease`] takes the conservative route: a short
//! self-imposed lease plus a re-check immediately before submission.
//!
//! [`anchor_leaf_count`]: ChainView::anchor_leaf_count

use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::header::Hash32;
use qlab_node::{ChainStore, CommitmentStore, NodeRpc, NodeState, NullifierStore};

/// The node facts a faucet plans a grant against.
pub trait ChainView {
    /// Fork-choice tip height.
    fn tip_height(&self) -> u64;

    /// Finalized head height, if anything is finalized.
    fn finalized_height(&self) -> Option<u64>;

    /// Whether `root` is a valid transaction anchor **right now** — finalized and
    /// within the ≤ `MAX_ANCHOR_AGE_BLOCKS` window (protocol-spec §4, frozen §7).
    fn is_valid_anchor(&self, root: &Hash32) -> bool;

    /// The newest valid anchor, or `None` if nothing is finalized yet. Newest is
    /// the right choice for a faucet even without per-root heights: whatever the
    /// unknown true deadline is, the newest root's is the latest of those on offer.
    fn newest_anchor(&self) -> Option<Hash32>;

    /// The live depth-32 commitment tree — the same tree the 2×2 bucket proves
    /// membership against.
    fn tree(&self) -> &CommitmentTree;

    /// Which leaf-count prefix of the live tree has `anchor` as its root.
    ///
    /// The anchor pins a tree *prefix*, and a witness must be cut against that
    /// prefix's leaf count or it folds to a different root. The count is not
    /// published, so it is recovered by scanning prefix roots newest-first — O(n)
    /// depth-32 folds, which is lab-scale work and is why it is a provided method
    /// rather than something a node is asked to serve.
    fn anchor_leaf_count(&self, anchor: &Hash32) -> Option<u64> {
        let tree = self.tree();
        let target = qlab_note::hash::digest_from_bytes(anchor);
        (0..=tree.len()).rev().find(|&c| tree.root_at(c) == target)
    }
}

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> ChainView for NodeRpc<C, N, T> {
    fn tip_height(&self) -> u64 {
        self.node().tip_height()
    }

    fn finalized_height(&self) -> Option<u64> {
        self.node().finalized_height()
    }

    fn is_valid_anchor(&self, root: &Hash32) -> bool {
        self.node().is_valid_anchor(root)
    }

    fn newest_anchor(&self) -> Option<Hash32> {
        // `AnchorSet::roots` is already newest-first over the main chain.
        self.anchors().roots.first().copied()
    }

    fn tree(&self) -> &CommitmentTree {
        self.node().commitments().tree()
    }
}
