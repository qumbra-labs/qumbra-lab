//! The per-asset supply ledger of an Annulet chain, recomputed from public
//! block bodies — lab issue #726 (L2-D1).
//!
//! Every Annulet transaction's public surface carries its `vPublic` terms: a
//! mint (issuer-authorized, proven in-circuit) or a redeem, per asset. Summed
//! per block they are the block's supply delta; summed over the main chain,
//! each asset's outstanding public supply. Nothing here is a consensus rule —
//! the node enforces the never-negative rule itself (`MemNode::apply_state`) —
//! this is the **recomputation** the explorer's attestation document and the
//! `qumbra-node audit-supply-l2` tool both perform, from bodies alone.
//!
//! **What it attests, and what it does not.** Issuance integrity: every unit
//! counted was minted by a `vPublic` term that the issuer's proof authorized,
//! read off public block bodies bound to the sealed headers. It is **not a
//! consensus commitment** (no header carries a supply figure at Phase 0 — the
//! `supply_cmt` chain is a named follow-up) and **not proof of reserves**
//! (`l2-architecture` §6.7): issuance ≠ reserves.
//!
//! The document shape ([`AttestDocument`]) is shared: the explorer serves it,
//! the audit tool reads it back as the `--claimed` side and compares.

use std::collections::BTreeMap;

use qlab_devnet::annulet::L2Surface;
use qlab_devnet::body::BlockBody;
use serde::{Deserialize, Serialize};

/// The mandatory label (`l2-architecture` §6.7).
pub const LABEL: &str = "issuance ≠ reserves";

/// What the figures are, stated where they are served (lab #726 ruling).
pub const FRAMING: &str = "Issuance integrity recomputed from public block bodies; replay it \
     yourself with `qumbra-node audit-supply-l2`. Not a consensus commitment.";

/// The do-it-yourself command printed beside the figures.
pub const REPLAY: &str =
    "qumbra-node audit-supply-l2 --data-dir <dir> --genesis <annulet-genesis> [--claimed <this document>]";

/// The attestation document's version.
pub const ATTEST_VERSION: u32 = 1;

/// One asset's public issuance at one height (or in total).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    pub minted: u128,
    pub redeemed: u128,
}

impl Flow {
    /// `minted − redeemed`.
    pub fn net(&self) -> i128 {
        self.minted as i128 - self.redeemed as i128
    }
}

/// The recomputed ledger: per height, per asset, the minted and redeemed
/// public amounts (heights and assets with no `vPublic` term are absent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetLedger {
    /// The main-chain tip height the ledger was folded to.
    pub tip_height: u64,
    pub flows: BTreeMap<u64, BTreeMap<u16, Flow>>,
}

impl AssetLedger {
    /// Fold `(height, body)` pairs of a main chain, in any order.
    pub fn fold<'a>(tip_height: u64, blocks: impl IntoIterator<Item = (u64, &'a BlockBody)>) -> Self {
        let mut flows: BTreeMap<u64, BTreeMap<u16, Flow>> = BTreeMap::new();
        for (height, body) in blocks {
            for tx in &body.txs {
                // An undecodable or absent surface carries no vPublic term (the
                // body rule refused malformed surfaces before the block was
                // applied; an L1-shaped entry has none).
                let Ok(Some(surface)) = L2Surface::decode(&tx.l2) else { continue };
                for term in surface.vpublic.iter().flatten() {
                    if term.amount == 0 {
                        continue;
                    }
                    let f = flows.entry(height).or_default().entry(term.asset).or_default();
                    if term.redeem {
                        f.redeemed += u128::from(term.amount);
                    } else {
                        f.minted += u128::from(term.amount);
                    }
                }
            }
        }
        flows.retain(|_, m| !m.is_empty());
        Self { tip_height, flows }
    }

    /// Per asset, the totals over the whole chain.
    pub fn totals(&self) -> BTreeMap<u16, Flow> {
        let mut t: BTreeMap<u16, Flow> = BTreeMap::new();
        for per in self.flows.values() {
            for (asset, f) in per {
                let e = t.entry(*asset).or_default();
                e.minted += f.minted;
                e.redeemed += f.redeemed;
            }
        }
        t
    }

    /// Per asset, the outstanding public supply `Σ minted − Σ redeemed`.
    pub fn outstanding(&self) -> BTreeMap<u16, i128> {
        self.totals().into_iter().map(|(a, f)| (a, f.net())).collect()
    }

    /// Compare against the node's own state (`MemNode::outstanding_supplies`
    /// and `supply_deltas`). Every disagreement is named by asset (and height
    /// for a delta); a zero entry on one side and absence on the other agree.
    pub fn compare_with_node(
        &self,
        node_outstanding: &BTreeMap<u16, i128>,
        node_deltas: &BTreeMap<u64, BTreeMap<u16, i128>>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let mine = self.outstanding();
        for asset in mine.keys().chain(node_outstanding.keys()).collect::<std::collections::BTreeSet<_>>() {
            let (a, b) = (mine.get(asset).copied().unwrap_or(0), node_outstanding.get(asset).copied().unwrap_or(0));
            if a != b {
                out.push(format!("outstanding asset={asset}: recomputed {a}, node {b}"));
            }
        }
        let heights: std::collections::BTreeSet<u64> =
            self.flows.keys().chain(node_deltas.keys()).copied().collect();
        for h in heights {
            let empty = BTreeMap::new();
            let mine_h: BTreeMap<u16, i128> = self
                .flows
                .get(&h)
                .map(|per| per.iter().map(|(a, f)| (*a, f.net())).collect())
                .unwrap_or_default();
            let node_h = node_deltas.get(&h).unwrap_or(&empty);
            for asset in mine_h.keys().chain(node_h.keys()).collect::<std::collections::BTreeSet<_>>() {
                let (a, b) = (mine_h.get(asset).copied().unwrap_or(0), node_h.get(asset).copied().unwrap_or(0));
                if a != b {
                    out.push(format!("delta height={h} asset={asset}: recomputed {a}, node {b}"));
                }
            }
        }
        out
    }

    /// The document a server publishes. `node_divergences` is what
    /// [`Self::compare_with_node`] found, served verbatim (never reconciled).
    pub fn document(&self, node_divergences: Vec<String>) -> AttestDocument {
        let totals = self.totals();
        AttestDocument {
            v: ATTEST_VERSION,
            label: LABEL.to_string(),
            framing: FRAMING.to_string(),
            replay: REPLAY.to_string(),
            tip_height: self.tip_height,
            assets: totals
                .iter()
                .map(|(asset, f)| AssetRow {
                    asset: *asset,
                    minted: f.minted.to_string(),
                    redeemed: f.redeemed.to_string(),
                    outstanding: f.net().to_string(),
                })
                .collect(),
            flows: self
                .flows
                .iter()
                .flat_map(|(h, per)| {
                    per.iter().map(move |(asset, f)| FlowRow {
                        height: *h,
                        asset: *asset,
                        minted: f.minted.to_string(),
                        redeemed: f.redeemed.to_string(),
                    })
                })
                .collect(),
            node_agrees: node_divergences.is_empty(),
            node_divergences,
        }
    }

    /// Compare a **claimed** document (the explorer's, read back) against this
    /// recomputation: every figure that differs, every row missing on either
    /// side, named by asset and height. Empty = the claim reproduces.
    pub fn compare_claimed(&self, claimed: &AttestDocument) -> Vec<String> {
        let mut out = Vec::new();
        if claimed.v != ATTEST_VERSION {
            out.push(format!("document version {} (this tool reads {ATTEST_VERSION})", claimed.v));
            return out;
        }
        if claimed.tip_height != self.tip_height {
            out.push(format!(
                "tip_height: claimed {}, recomputed {} (compare documents taken at the same tip)",
                claimed.tip_height, self.tip_height
            ));
        }
        let mine = self.document(Vec::new());
        diff_rows(
            &mine.assets.iter().map(|r| (r.asset.to_string(), r)).collect(),
            &claimed.assets.iter().map(|r| (r.asset.to_string(), r)).collect(),
            "asset",
            &mut out,
        );
        diff_rows(
            &mine.flows.iter().map(|r| (format!("height={} asset={}", r.height, r.asset), r)).collect(),
            &claimed.flows.iter().map(|r| (format!("height={} asset={}", r.height, r.asset), r)).collect(),
            "flow",
            &mut out,
        );
        out
    }
}

fn diff_rows<T: PartialEq + std::fmt::Debug>(
    mine: &BTreeMap<String, &T>,
    claimed: &BTreeMap<String, &T>,
    what: &str,
    out: &mut Vec<String>,
) {
    for (k, m) in mine {
        match claimed.get(k) {
            None => out.push(format!("{what} {k}: recomputed {m:?}, missing from the claim")),
            Some(c) if c != m => out.push(format!("{what} {k}: claimed {c:?}, recomputed {m:?}")),
            Some(_) => {}
        }
    }
    for (k, c) in claimed {
        if !mine.contains_key(k) {
            out.push(format!("{what} {k}: claimed {c:?}, absent from the recomputation"));
        }
    }
}

/// The served attestation document. Amounts are **decimal strings** — sums of
/// `u64` amounts overflow a JSON number's safe range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestDocument {
    pub v: u32,
    /// Always [`LABEL`].
    pub label: String,
    /// Always [`FRAMING`].
    pub framing: String,
    /// The do-it-yourself command ([`REPLAY`]).
    pub replay: String,
    pub tip_height: u64,
    /// Per asset, the chain totals.
    pub assets: Vec<AssetRow>,
    /// Per height and asset, the public flows (only non-empty rows).
    pub flows: Vec<FlowRow>,
    /// Whether the serving node's own state agrees with the recomputation.
    pub node_agrees: bool,
    /// Every disagreement, named — served verbatim, never reconciled.
    pub node_divergences: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRow {
    pub asset: u16,
    pub minted: String,
    pub redeemed: String,
    pub outstanding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRow {
    pub height: u64,
    pub asset: u16,
    pub minted: String,
    pub redeemed: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::annulet::{L2ShapeTag, VPublicTerm};
    use qlab_devnet::body::{TxEntry, TxPublic};
    use qlab_devnet::fees::{posted_fee, ArityBucket};

    const NONE: VPublicTerm = VPublicTerm { redeem: false, amount: 0, asset: 0 };

    fn term(redeem: bool, amount: u64, asset: u16) -> VPublicTerm {
        VPublicTerm { redeem, amount, asset }
    }

    /// A P-shaped transaction carrying `terms`; an S-shaped one when `None`.
    fn l2_tx(terms: Option<[VPublicTerm; 2]>, tag: u8) -> TxEntry {
        let mut tx = TxEntry::with_placeholder_discovery(b"p".to_vec(), TxPublic {
            anchor: [tag; 32],
            nullifiers: vec![[tag; 32]],
            commitments: vec![[tag.wrapping_add(80); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        });
        let shape = if terms.is_some() { L2ShapeTag::P } else { L2ShapeTag::S };
        tx.l2 = L2Surface { shape, registry_root: [9; 32], vpublic: terms }.encode();
        tx
    }

    fn body(txs: Vec<TxEntry>) -> BlockBody {
        BlockBody { txs, coinbase_payees: Vec::new() }
    }

    /// Asset 7: mint 1,000 at h1, mint 500 + redeem 200 at h2, an S transfer
    /// (no terms) at h3; asset 9: mint 40 at h2. The node agrees.
    type Fixture = (Vec<(u64, BlockBody)>, BTreeMap<u16, i128>, BTreeMap<u64, BTreeMap<u16, i128>>);

    fn chain() -> Fixture {
        let blocks = vec![
            (1, body(vec![l2_tx(Some([term(false, 1_000, 7), NONE]), 1)])),
            (
                2,
                body(vec![
                    l2_tx(Some([term(false, 500, 7), term(true, 200, 7)]), 2),
                    l2_tx(Some([NONE, term(false, 40, 9)]), 3),
                ]),
            ),
            (3, body(vec![l2_tx(None, 4)])),
        ];
        let node_out = BTreeMap::from([(7u16, 1_300i128), (9, 40)]);
        let node_deltas = BTreeMap::from([
            (1u64, BTreeMap::from([(7u16, 1_000i128)])),
            (2, BTreeMap::from([(7, 300), (9, 40)])),
        ]);
        (blocks, node_out, node_deltas)
    }

    fn ledger(blocks: &[(u64, BlockBody)]) -> AssetLedger {
        AssetLedger::fold(3, blocks.iter().map(|(h, b)| (*h, b)))
    }

    #[test]
    fn the_ledger_folds_mints_and_redeems_per_asset_and_height() {
        let (blocks, node_out, node_deltas) = chain();
        let l = ledger(&blocks);
        assert_eq!(l.totals()[&7], Flow { minted: 1_500, redeemed: 200 });
        assert_eq!(l.outstanding(), node_out);
        assert_eq!(l.flows[&2][&7], Flow { minted: 500, redeemed: 200 });
        assert!(!l.flows.contains_key(&3), "an S transfer carries no vPublic term");
        assert!(l.compare_with_node(&node_out, &node_deltas).is_empty(), "the node agrees");
    }

    /// A node whose state disagrees is named by asset and by height — never
    /// reconciled.
    #[test]
    fn a_node_divergence_is_named_by_asset_and_height() {
        let (blocks, mut node_out, mut node_deltas) = chain();
        node_out.insert(7, 1_301);
        node_deltas.get_mut(&2).unwrap().insert(9, 41);
        let d = ledger(&blocks).compare_with_node(&node_out, &node_deltas);
        assert!(d.contains(&"outstanding asset=7: recomputed 1300, node 1301".to_string()), "{d:?}");
        assert!(d.contains(&"delta height=2 asset=9: recomputed 40, node 41".to_string()), "{d:?}");
        assert_eq!(d.len(), 2);
    }

    /// The served document carries the label and the framing verbatim, and
    /// its own figures reproduce against themselves.
    #[test]
    fn the_document_carries_the_label_and_reproduces() {
        let (blocks, ..) = chain();
        let l = ledger(&blocks);
        let doc = l.document(Vec::new());
        assert_eq!(doc.label, "issuance ≠ reserves");
        assert!(doc.framing.contains("Not a consensus commitment"));
        assert!(doc.framing.contains("qumbra-node audit-supply-l2"));
        assert!(doc.node_agrees);
        assert_eq!(doc.assets.len(), 2);
        assert!(l.compare_claimed(&doc).is_empty());
    }

    /// 🔴 A tampered claim is caught by name: one inflated outstanding figure,
    /// one invented flow row, one dropped row.
    #[test]
    fn a_tampered_claim_is_named() {
        let (blocks, ..) = chain();
        let l = ledger(&blocks);
        let mut doc = l.document(Vec::new());
        doc.assets.iter_mut().find(|r| r.asset == 7).unwrap().outstanding = "1400".into();
        doc.flows.retain(|r| !(r.height == 2 && r.asset == 9));
        doc.flows.push(FlowRow { height: 3, asset: 7, minted: "5".into(), redeemed: "0".into() });
        let d = l.compare_claimed(&doc);
        assert!(d.iter().any(|m| m.starts_with("asset 7: claimed") && m.contains("1400")), "{d:?}");
        assert!(d.iter().any(|m| m.starts_with("flow height=2 asset=9:") && m.contains("missing from the claim")), "{d:?}");
        assert!(d.iter().any(|m| m.starts_with("flow height=3 asset=7:") && m.contains("absent from the recomputation")), "{d:?}");
        assert_eq!(d.len(), 3, "{d:?}");
    }
}
