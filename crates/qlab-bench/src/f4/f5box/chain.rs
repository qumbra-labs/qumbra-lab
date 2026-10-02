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
use std::collections::HashMap;

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
    /// Every prefix root of `tree` → its leaf count (computed once).
    by_root: HashMap<Digest, u64>,
    /// Every leaf → its position (computed once).
    by_leaf: HashMap<Digest, u64>,
}

/// Read the three routes. The anchor set first: every root it names is a
/// prefix of the leaves read after it, so the two never disagree in the
/// direction that matters (a root with no matching local count).
///
/// **Every stream must be whole, or the read fails by name** — a short page
/// is never taken for the end (#309/#312's lesson): the leaves must reach
/// the served `total` and never pass it, and the coinbase stream must hold
/// every height `0..=tip`.
pub(crate) fn read(node: &impl Get) -> Result<ChainView, String> {
    let anchors = AnchorSet::from_bytes(&node.get("/v1/anchors")?).map_err(|e| format!("/v1/anchors: {e:?}"))?;
    let mut tree = CommitmentTree::new();
    loop {
        let body = node.get(&format!("/v1/tree/leaves?from={}", tree.len()))?;
        let page = TreeLeaves::from_bytes(&body).map_err(|e| format!("/v1/tree/leaves: {e:?}"))?;
        if page.from != tree.len() {
            return Err(format!("/v1/tree/leaves: asked from {}, served from {}", tree.len(), page.from));
        }
        if tree.len() + page.leaves.len() as u64 > page.total {
            return Err(format!("/v1/tree/leaves: {} leaves past {} served with a total of {}", page.leaves.len(), tree.len(), page.total));
        }
        if page.leaves.is_empty() && tree.len() < page.total {
            return Err(format!("/v1/tree/leaves: an empty page at {} of a total of {}", tree.len(), page.total));
        }
        for leaf in &page.leaves {
            tree.append_bytes(leaf);
        }
        if tree.len() == page.total {
            break;
        }
    }
    let mut coinbase: Vec<BlockCoinbase> = Vec::new();
    while (coinbase.len() as u64) <= anchors.tip_height {
        let from = coinbase.len() as u64;
        let body = node.get(&format!("/v1/coinbase?from={from}&to={}", anchors.tip_height))?;
        let page = CoinbasePage::from_bytes(&body).map_err(|e| format!("/v1/coinbase: {e:?}"))?;
        if page.blocks.is_empty() {
            return Err(format!("/v1/coinbase: an empty page at {from} below the tip {}", anchors.tip_height));
        }
        for b in page.blocks {
            if b.height != coinbase.len() as u64 {
                return Err(format!("/v1/coinbase: height {} served where {} was due", b.height, coinbase.len()));
            }
            coinbase.push(b);
        }
    }
    if coinbase.len() as u64 != anchors.tip_height + 1 {
        return Err(format!("/v1/coinbase: {} heights for a tip of {}", coinbase.len(), anchors.tip_height));
    }
    let mut prefix = CommitmentTree::new();
    let mut by_root = HashMap::from([(prefix.root(), 0u64)]);
    let mut by_leaf = HashMap::new();
    for i in 0..tree.len() {
        let leaf = tree.leaf(i);
        prefix.append(leaf);
        by_root.insert(prefix.root(), i + 1);
        by_leaf.entry(leaf).or_insert(i);
    }
    Ok(ChainView { tree, anchors, coinbase, by_root, by_leaf })
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
        let mut out = Vec::new();
        for bytes in &self.anchors.roots {
            let root = digest_from_bytes(bytes);
            let count = *self.by_root.get(&root).ok_or("a served anchor is no prefix of the served leaves")?;
            out.push(Anchor { count, root });
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.count));
        out.dedup();
        Ok(out)
    }

    /// Every burn note of `l2_id` the chain has appended: coinbase notes paid
    /// to `rkm_burn(l2_id)`, reconstructed under `form`, each found in the
    /// tree; ascending by minted height. A burn still maturing (frozen §2) is
    /// not one yet ([`Self::immature_burns`]); a **matured** burn whose
    /// rebuilt commitment is in no served leaf is an error naming its height
    /// — the wrong form, or a server whose streams disagree.
    pub(crate) fn burns(&self, form: GenesisForm, l2_id: u64) -> Result<Vec<Burn>, String> {
        let rkm = qlab_air::claim::rkm_burn(l2_id);
        let mut out = Vec::new();
        for b in self.coinbase.iter().filter(|b| b.coinbase_rkm == rkm) {
            if qlab_node::coinbase_leaf_appears_at(b.height) > self.anchors.tip_height {
                continue;
            }
            let Some(n) = qlab_node::coinbase_note_parts_for(form, b.height, b.coinbase_rkm, b.coinbase, b.fees, b.name_burn) else {
                continue; // a block that minted nothing
            };
            let cm = n.commitment();
            let pos = *self.by_leaf.get(&cm).ok_or_else(|| {
                format!("the matured burn minted at {} rebuilds to a commitment in no served leaf (form {form:?})", b.height)
            })?;
            let note = qlab_air::claim::BurnNote { value: n.value, rkm: n.rkm, rho: n.rho, rseed: n.rseed };
            out.push(Burn { height: b.height, note, cm, pos });
        }
        Ok(out)
    }

    /// **Lab #831 W3b (ruling Q-B5): burns paid by L1 transactions.** f5box
    /// cannot discover one — a deposit's opening is sealed to its depositor —
    /// so each is supplied as an opening `(height, value, ρ, rseed)` and
    /// accepted only if, paid to `rkm_burn(l2_id)`, its rebuilt L1 commitment
    /// is a served leaf below the newest valid anchor. Refused by name
    /// otherwise; ascending by leaf position, like [`Self::burns`].
    /// Test-only until the box takes claim files as members (follow-up).
    #[cfg(test)]
    pub(crate) fn tx_burns(&self, l2_id: u64, openings: &[TxBurnOpening]) -> Result<Vec<Burn>, String> {
        let rkm = qlab_air::claim::rkm_burn(l2_id);
        let newest = self.anchors()?.first().copied().ok_or("no valid anchor is served: nothing is claimable yet")?;
        let mut out = Vec::with_capacity(openings.len());
        for o in openings {
            let note = qlab_air::claim::BurnNote { value: o.value, rkm, rho: o.rho, rseed: o.rseed };
            let cm = qlab_air::claim::l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
            let pos = *self.by_leaf.get(&cm).ok_or_else(|| {
                format!("the burn opened at height {} rebuilds to a commitment in no served leaf (not L2 {l2_id}'s burn, or not on this chain)", o.height)
            })?;
            if pos >= newest.count {
                return Err(format!(
                    "the burn at height {} is leaf {pos}, not under the newest anchor ({} leaves): not claimable until a later root is finalized",
                    o.height, newest.count
                ));
            }
            out.push(Burn { height: o.height, note, cm, pos });
        }
        out.sort_by_key(|b| b.pos);
        Ok(out)
    }

    /// The burns minted but not appended yet at the served tip, each with the
    /// height its leaf appears at — the manifest's "why not yet".
    pub(crate) fn immature_burns(&self, l2_id: u64) -> Vec<(u64, u64)> {
        let rkm = qlab_air::claim::rkm_burn(l2_id);
        self.coinbase
            .iter()
            .filter(|b| b.coinbase_rkm == rkm && qlab_node::coinbase_leaf_appears_at(b.height) > self.anchors.tip_height)
            .map(|b| (b.height, qlab_node::coinbase_leaf_appears_at(b.height)))
            .collect()
    }
}

/// A transaction-output burn's opening, as its depositor's wallet holds it
/// (`qlab_ledger::deposits::SetAside`): where it was mined and the note's
/// free fields; its `rkm` is the burn address by definition.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxBurnOpening {
    pub height: u64,
    pub value: u64,
    pub rho: Digest,
    pub rseed: Digest,
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
