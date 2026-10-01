//! Lab #785 F5-6 (1) — **the box node, read**: the L1 commitment tree, the
//! valid-anchor set and the coinbase stream, through the node's own served
//! routes (`/v1/tree/leaves`, `/v1/anchors`, `/v1/coinbase`) and their own
//! codecs. Nothing here states a rule: the tree is the node's leaves in the
//! node's order, the anchors are the node's answer, and a burn note is
//! reconstructed by the dispatcher `apply_state` appends through
//! (`qlab_node::coinbase_note_parts_for`) under the genesis file's form.
//!
//! **The anchor set is the node's LOCAL finality, V7 is the RECORD's.**
//! `/v1/anchors` answers from `ChainState::finalized_height`; a bundle's
//! absorbed roots are judged by the latest finality record on chain
//! (`qlab_devnet::body::v6_anchor_ok`), which can trail local finality by a
//! cadence. A root chosen here is therefore valid at the latest once the next
//! record covers it — the submitter retries; the anchor window (1,152 blocks)
//! is two orders of magnitude wider than that lag.
// The `f5box` command (the next PR) is the non-test consumer of the rest.
#![allow(dead_code)]
use qlab_cbserver::codec::{BlockCoinbase, CoinbasePage};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::forms::GenesisForm;
use qlab_node::{AnchorSet, TreeLeaves};
use qlab_wrapper::codec::digest_from_bytes;

use crate::f3::native::Digest;

/// A node's served routes, by path and query. `Err` for anything but a 200.
pub(crate) trait Get {
    fn get(&self, path: &str) -> Result<Vec<u8>, String>;
}

/// Plain HTTP to a node's discovery address (`http://host:port`).
pub(crate) struct Http {
    pub base: String,
}

impl Get for Http {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        qlab_cbserver::client::http_get(&self.base, path).map_err(|e| format!("GET {path}: {e}"))
    }
}

/// What f5box reads from the node, once per run.
pub(crate) struct ChainView {
    /// The L1 commitment tree, rebuilt from the served leaves.
    pub tree: CommitmentTree,
    /// The node's valid-anchor set, as served (newest first).
    pub anchors: AnchorSet,
    /// Every block's coinbase facts, `0..=tip`, ascending.
    pub coinbase: Vec<BlockCoinbase>,
}

/// Read the three routes. The anchor set first: every root it names is a
/// prefix of the leaves read after it, so the two never disagree in the
/// direction that matters (a root with no matching local count).
pub(crate) fn read(node: &impl Get) -> Result<ChainView, String> {
    let anchors = AnchorSet::from_bytes(&node.get("/v1/anchors")?).map_err(|e| format!("/v1/anchors: {e:?}"))?;
    let mut tree = CommitmentTree::new();
    loop {
        let body = node.get(&format!("/v1/tree/leaves?from={}", tree.len()))?;
        let page = TreeLeaves::from_bytes(&body).map_err(|e| format!("/v1/tree/leaves: {e:?}"))?;
        if page.from != tree.len() {
            return Err(format!("/v1/tree/leaves: asked from {}, served from {}", tree.len(), page.from));
        }
        for leaf in &page.leaves {
            tree.append_bytes(leaf);
        }
        if page.leaves.is_empty() || tree.len() >= page.total {
            break;
        }
    }
    let mut coinbase: Vec<BlockCoinbase> = Vec::new();
    let mut from = 0u64;
    loop {
        let body = node.get(&format!("/v1/coinbase?from={from}&to={}", anchors.tip_height))?;
        let page = CoinbasePage::from_bytes(&body).map_err(|e| format!("/v1/coinbase: {e:?}"))?;
        let Some(last) = page.last_height() else { break };
        if last < from {
            return Err(format!("/v1/coinbase: a page from {from} ended at {last}"));
        }
        coinbase.extend(page.blocks);
        if last >= anchors.tip_height {
            break;
        }
        from = last + 1;
    }
    if coinbase.iter().enumerate().any(|(i, b)| b.height != i as u64) {
        return Err("/v1/coinbase: the stream is not every height from genesis".into());
    }
    Ok(ChainView { tree, anchors, coinbase })
}

/// One valid anchor as this tree states it: the leaf count whose root it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anchor {
    pub count: u64,
    pub root: Digest,
}

impl ChainView {
    /// The served anchors this tree reproduces, newest (largest count) first.
    /// A served root no prefix of the tree reproduces is an error: the tree
    /// and the anchor set disagree, and nothing built on either is sound.
    pub(crate) fn anchors(&self) -> Result<Vec<Anchor>, String> {
        let mut prefix = CommitmentTree::new();
        let mut by_root = std::collections::HashMap::new();
        by_root.insert(prefix.root(), 0u64);
        for i in 0..self.tree.len() {
            prefix.append(self.tree.leaf(i));
            by_root.insert(prefix.root(), i + 1);
        }
        let mut out = Vec::new();
        for bytes in &self.anchors.roots {
            let root = digest_from_bytes(bytes);
            let count = *by_root.get(&root).ok_or("a served anchor is no prefix of the served leaves")?;
            out.push(Anchor { count, root });
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.count));
        out.dedup();
        Ok(out)
    }

    /// Every burn note of `l2_id` the chain has appended: coinbase notes paid
    /// to `rkm_burn(l2_id)`, reconstructed under `form`, each found in the
    /// tree. A burn whose leaf is not appended yet (immature, frozen §2) is
    /// not one; ascending by minted height.
    pub(crate) fn burns(&self, form: GenesisForm, l2_id: u64) -> Vec<Burn> {
        let rkm = qlab_air::claim::rkm_burn(l2_id);
        self.coinbase
            .iter()
            .filter(|b| b.coinbase_rkm == rkm)
            .filter_map(|b| {
                let n = qlab_node::coinbase_note_parts_for(form, b.height, b.coinbase_rkm, b.coinbase, b.fees, b.name_burn)?;
                let note = qlab_air::claim::BurnNote { value: n.value, rkm: n.rkm, rho: n.rho, rseed: n.rseed };
                let cm = n.commitment();
                let pos = self.tree.position_of(&cm)?;
                Some(Burn { height: b.height, note, cm, pos })
            })
            .collect()
    }

    /// The burns minted but not appended yet at the served tip, each with the
    /// height its leaf appears at — the manifest's "why not yet".
    pub(crate) fn immature_burns(&self, l2_id: u64) -> Vec<(u64, u64)> {
        let rkm = qlab_air::claim::rkm_burn(l2_id);
        self.coinbase
            .iter()
            .filter(|b| b.coinbase_rkm == rkm && b.height + qlab_node::COINBASE_MATURITY_BLOCKS > self.anchors.tip_height)
            .map(|b| (b.height, qlab_node::coinbase_leaf_appears_at(b.height)))
            .collect()
    }
}

/// One burn note in the L1 tree.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Burn {
    /// The height whose block minted it.
    pub height: u64,
    pub note: qlab_air::claim::BurnNote,
    pub cm: Digest,
    /// Its leaf position in the L1 tree.
    pub pos: u64,
}
