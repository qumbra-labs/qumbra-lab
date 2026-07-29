//! Do these nodes agree on **what** they finalized?
//!
//! # The two divergences are not the same thing, and are never merged
//!
//! `qumbra-deploy/OPERATOR.md` §3 already draws this line and it is not re-derived
//! here, only honoured:
//!
//! - **`fid` divergence** — two nodes reporting the *same* `finalized_height` with
//!   *different* checkpoint identities. Two different checkpoints finalized at one
//!   height is the most severe failure this net can have: the R2 **STOP**. Before
//!   #110/#117 it was invisible, because `final=` says how high and never what, so
//!   both nodes printed identical telemetry while disagreeing.
//! - **`sid` divergence** — two nodes whose own committee keys signed different
//!   variants at the same slot. Ordinary, and a **finding**, not a stop: the
//!   minority still finalizes the majority's checkpoint, so at slot 3776 on
//!   2026-07-29 all four hosts would have shown the same `final` and the same
//!   `fid`, and exactly one would have shown a different `sid`. That is precisely
//!   why it needs a separate line: flattening it into the `fid` alarm would either
//!   promote a routine event to a stop, or hide it behind an all-clear.
//!
//! # What is compared, and what deliberately is not
//!
//! Identities are compared **only between nodes reporting the same finalized
//! height**. Nodes at different heights are not disagreeing — one is behind, which
//! on a live chain is the normal state of affairs — and a single telemetry sample
//! carries only the latest identity, so there is nothing at a shared height to
//! compare. That limit is rendered as lag, and stated, rather than being silently
//! rounded to "agreed".
//!
//! Unreachable nodes are excluded from the computation entirely. A timeout is
//! missing evidence, not conflicting evidence (see [`crate::poll`]).
//!
//! # n = 1 is not a special case
//!
//! One endpoint produces one height group with one identity, which has no two
//! distinct identities in it, which is [`Verdict::Agreed`]. The list is operational
//! config: with one entry this is a single-node health page and with four it is the
//! agreement view, over one code path rather than two.

use std::collections::BTreeMap;

use crate::poll::NodeReading;

/// The verdict on **what was finalized**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No two reachable nodes reported different identities at a shared height.
    /// Includes the case where nothing has been finalized anywhere yet.
    Agreed,
    /// A reachable node reported a finalized height but no identity for it, so
    /// agreement cannot be *established* — distinct from having been checked and
    /// found to hold. On a T0 net this means a node predating #117.
    Indeterminate,
    /// 🔴 Two reachable nodes finalized **different checkpoints at one height**.
    /// The R2 stop condition.
    Diverged,
}

/// The verdict on **what this net's committee keys signed**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedVerdict {
    /// Every node reporting a commitment at a shared slot reports the same one.
    Agreed,
    /// 🟡 A node's *own* held keys are committed to two different variants at one
    /// slot — it is equivocating against itself across its own key set. A finding.
    LocalSplit,
    /// 🟡 Two nodes signed different variants at the same slot. A finding: the
    /// minority still finalizes the majority's checkpoint, so this can be true
    /// while `fid` agrees everywhere.
    VariantSplit,
}

/// Which nodes reported which identity, at one height (or slot). `None` as the key
/// means the node reported the height/slot with **no** identity — absent for a
/// finalized height, `split` for a signed slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdGroup {
    pub at: u64,
    /// Ascending by identity, and by label within an identity, so two runs against
    /// an unchanged net render byte-identically.
    pub ids: Vec<(Option<u64>, Vec<String>)>,
}

impl IdGroup {
    /// Distinct *known* identities at this height/slot.
    pub fn distinct_ids(&self) -> usize {
        self.ids.iter().filter(|(id, _)| id.is_some()).count()
    }
    /// Two or more nodes here reported different identities.
    pub fn is_split(&self) -> bool {
        self.distinct_ids() >= 2
    }
    /// How many nodes reported at this height/slot.
    pub fn nodes(&self) -> usize {
        self.ids.iter().map(|(_, l)| l.len()).sum()
    }
}

fn group(entries: Vec<(u64, Option<u64>, String)>) -> Vec<IdGroup> {
    let mut by_at: BTreeMap<u64, BTreeMap<Option<u64>, Vec<String>>> = BTreeMap::new();
    for (at, id, label) in entries {
        by_at.entry(at).or_default().entry(id).or_default().push(label);
    }
    by_at
        .into_iter()
        .map(|(at, ids)| IdGroup {
            at,
            ids: ids
                .into_iter()
                .map(|(id, mut labels)| {
                    labels.sort();
                    (id, labels)
                })
                .collect(),
        })
        .collect()
}

/// The full cross-node agreement picture for one poll.
#[derive(Clone, Debug)]
pub struct Agreement {
    // ---- what was finalized (`fid`) ----
    pub verdict: Verdict,
    /// One entry per finalized height any reachable node reported, ascending.
    pub finalized: Vec<IdGroup>,
    /// Reachable nodes that have finalized nothing at all. Not a fault — a node
    /// that just started has finalized nothing, and neither has a whole net before
    /// its first checkpoint closes.
    pub not_finalized: Vec<String>,

    // ---- what was signed (`sid`) ----
    pub signed_verdict: SignedVerdict,
    /// One entry per signed slot any reachable node reported, ascending.
    pub signed: Vec<IdGroup>,
    /// Nodes whose own held keys are split across two variants at one slot.
    pub local_splits: Vec<String>,
    /// Reachable nodes holding no committee keys, or which have signed nothing.
    /// Expected on a verify-only node; listed so "2 of 4 reported a commitment"
    /// is never mistaken for two nodes having gone quiet.
    pub not_signing: Vec<String>,

    // ---- who answered ----
    pub reachable: Vec<String>,
    /// Label + the reason, in configured order.
    pub unreachable: Vec<(String, String)>,
}

impl Agreement {
    /// Compute the verdicts over a poll's readings.
    pub fn of(readings: &[NodeReading]) -> Agreement {
        let mut reachable = Vec::new();
        let mut unreachable = Vec::new();
        let mut fin_entries = Vec::new();
        let mut not_finalized = Vec::new();
        let mut sig_entries = Vec::new();
        let mut local_splits = Vec::new();
        let mut not_signing = Vec::new();

        for r in readings {
            let label = r.endpoint.label.clone();
            let Some(t) = r.reading.telemetry() else {
                let why = match &r.reading {
                    crate::poll::Reading::Unreachable(w) => w.clone(),
                    crate::poll::Reading::Ok(_) => unreachable!(),
                };
                unreachable.push((label, why));
                continue;
            };
            reachable.push(label.clone());

            match t.finalized_height {
                Some(h) => fin_entries.push((h, t.finalized_id, label.clone())),
                None => not_finalized.push(label.clone()),
            }

            match t.signed {
                Some(c) => {
                    if c.id.is_none() {
                        local_splits.push(label.clone());
                    }
                    sig_entries.push((c.slot, c.id, label.clone()));
                }
                None => not_signing.push(label.clone()),
            }
        }

        let finalized = group(fin_entries);
        let signed = group(sig_entries);

        // 🔴 first: a known split outranks an unknown. A height where two nodes
        // reported different identities is a divergence whether or not some third
        // node failed to report one at all.
        let verdict = if finalized.iter().any(|g| g.is_split()) {
            Verdict::Diverged
        } else if finalized.iter().any(|g| g.ids.iter().any(|(id, _)| id.is_none())) {
            Verdict::Indeterminate
        } else {
            Verdict::Agreed
        };

        let signed_verdict = if signed.iter().any(|g| g.is_split()) {
            SignedVerdict::VariantSplit
        } else if !local_splits.is_empty() {
            SignedVerdict::LocalSplit
        } else {
            SignedVerdict::Agreed
        };

        Agreement {
            verdict,
            finalized,
            not_finalized,
            signed_verdict,
            signed,
            local_splits,
            not_signing,
            reachable,
            unreachable,
        }
    }

    /// The heights where two or more nodes could actually be compared. A height
    /// only one node reached proves nothing about agreement — it is reported, but
    /// it is not evidence either way.
    pub fn comparable_heights(&self) -> Vec<&IdGroup> {
        self.finalized.iter().filter(|g| g.nodes() >= 2).collect()
    }

    /// True when the readings are consistent with the net having finalized one
    /// history: no divergence and nothing unknown.
    pub fn is_clean(&self) -> bool {
        self.verdict == Verdict::Agreed && self.signed_verdict == SignedVerdict::Agreed
    }

    /// The process exit code. **Only an `fid` divergence is non-zero**: it is the
    /// one condition that means STOP, and an operator wiring this into an alert
    /// must not be paged for a node being down (that is what the rendered
    /// reachable count is for) or for an `sid` split (a finding, which is read, not
    /// reacted to at 3 a.m.).
    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Diverged => 2,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::{Endpoint, Reading};
    use qlab_node::telemetry::LocalCommitment;
    use qlab_node::Telemetry;
    use std::time::Duration;

    const MAX_LAG: u64 = 16;

    fn telem(tip: u64, fin: Option<u64>, fid: Option<u64>, signed: Option<(u64, Option<u64>)>) -> Telemetry {
        Telemetry::assemble(tip, fin, 75, 0, 3, 0, MAX_LAG)
            .with_checkpoint(fid, signed.map(|(slot, id)| LocalCommitment { slot, id }))
    }

    fn node(label: &str, t: Telemetry) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Ok(Box::new(t)),
            elapsed: Duration::from_millis(1),
        }
    }

    fn down(label: &str, why: &str) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Unreachable(why.into()),
            elapsed: Duration::from_millis(1),
        }
    }

    /// **Acceptance 1**: same `final`, different `fid` ⇒ disagreement; same `fid`
    /// ⇒ agreement. The height is held equal in both halves so the *only* thing
    /// that moves is the identity — which is the property, and it is the property
    /// that was undetectable before #110/#117.
    #[test]
    fn same_height_different_fid_is_disagreement_and_same_fid_is_agreement() {
        const H: u64 = 3776;
        let a = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), None);
        let same = telem(3801, Some(H), Some(0xaaaa_aaaa_aaaa), None);
        let other = telem(3799, Some(H), Some(0xbbbb_bbbb_bbbb), None);

        let agreed = Agreement::of(&[node("node0", a.clone()), node("node1", same)]);
        assert_eq!(agreed.verdict, Verdict::Agreed);
        assert_eq!(agreed.finalized.len(), 1, "one height, so one comparison");
        assert_eq!(agreed.finalized[0].at, H);
        assert_eq!(agreed.finalized[0].distinct_ids(), 1);
        assert_eq!(agreed.exit_code(), 0);

        let split = Agreement::of(&[node("node0", a), node("node1", other)]);
        assert_eq!(split.verdict, Verdict::Diverged, "🔴 two checkpoints at one height");
        assert!(split.finalized[0].is_split());
        assert_eq!(split.finalized[0].nodes(), 2);
        assert_eq!(split.exit_code(), 2, "the only condition that is non-zero");
        // …and the tip heights differing (3800 vs 3799) is NOT what made it a
        // divergence: the identities at the shared FINALIZED height are.
        assert_eq!(split.signed_verdict, SignedVerdict::Agreed, "no keys reported, no signed claim");
    }

    /// **Acceptance 2**: n = 1 renders through the same code path and shows
    /// agreement — the agreement check is trivially satisfied rather than special-
    /// cased. Both flavours: a node that has finalized something, and one that has
    /// not finalized anything yet.
    #[test]
    fn n_equals_one_is_agreement_through_the_same_path() {
        let one = Agreement::of(&[node("node0", telem(400, Some(384), Some(0xdead_beef_0001), Some((384, Some(0xdead_beef_0001))))) ]);
        assert_eq!(one.verdict, Verdict::Agreed);
        assert_eq!(one.signed_verdict, SignedVerdict::Agreed);
        assert_eq!(one.reachable.len(), 1);
        assert_eq!(one.finalized.len(), 1);
        assert!(one.comparable_heights().is_empty(), "one node compares with nobody");
        assert!(one.is_clean());
        assert_eq!(one.exit_code(), 0);

        // Cold start: nothing finalized anywhere is agreement, not a fault.
        let cold = Agreement::of(&[node("node0", telem(3, None, None, None))]);
        assert_eq!(cold.verdict, Verdict::Agreed);
        assert_eq!(cold.not_finalized, vec!["node0".to_string()]);
        assert!(cold.finalized.is_empty());
        assert_eq!(cold.exit_code(), 0);
    }

    /// **Acceptance 3**: an unreachable node is shown as unreachable, **not** as
    /// disagreeing — and it does not drag the verdict of the nodes that did answer.
    /// A timeout is missing evidence, not conflicting evidence.
    #[test]
    fn an_unreachable_node_is_unreachable_not_a_dissenter() {
        const H: u64 = 3776;
        let t = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), None);
        let a = Agreement::of(&[
            node("node0", t.clone()),
            node("node1", t.clone()),
            node("node2", t),
            down("node3", "connect 10.0.0.4:9410: Connection refused (os error 61)"),
        ]);

        assert_eq!(a.verdict, Verdict::Agreed, "3 answered and all agree");
        assert_eq!(a.reachable.len(), 3);
        assert_eq!(a.unreachable.len(), 1);
        assert_eq!(a.unreachable[0].0, "node3");
        assert!(a.unreachable[0].1.contains("Connection refused"), "the reason is carried");
        assert_eq!(a.exit_code(), 0, "a node being down must never page as a STOP");
        // The silent node contributes nothing to any group — not an unknown id, not
        // an extra height, nothing.
        assert_eq!(a.finalized.len(), 1);
        assert_eq!(a.finalized[0].nodes(), 3);
        assert!(!a.finalized[0].is_split());

        // Every node down is still not a disagreement — it is no evidence at all.
        let blind = Agreement::of(&[down("node0", "timed out"), down("node1", "timed out")]);
        assert_eq!(blind.verdict, Verdict::Agreed);
        assert!(blind.reachable.is_empty());
        assert_eq!(blind.exit_code(), 0);
    }

    /// Nodes at **different finalized heights** are lagging, not disagreeing: a
    /// single sample carries one identity, so there is nothing at a shared height
    /// to compare, and inventing a verdict from that would be the false alarm this
    /// view exists to prevent.
    #[test]
    fn different_finalized_heights_are_lag_and_not_a_verdict() {
        let ahead = telem(3800, Some(3776), Some(0xaaaa_aaaa_aaaa), None);
        let behind = telem(3700, Some(3680), Some(0xbbbb_bbbb_bbbb), None);
        let a = Agreement::of(&[node("node0", ahead), node("node1", behind)]);

        assert_eq!(a.verdict, Verdict::Agreed, "different heights, different identities: no conflict");
        assert_eq!(a.finalized.len(), 2, "two heights, each with one node");
        assert!(a.comparable_heights().is_empty(), "nothing was actually compared");
        assert_eq!(a.exit_code(), 0);
    }

    /// A node that reports a finalized height with **no identity** — the shape a
    /// pre-#117 node would have if it could be decoded at all — makes agreement
    /// *unestablished*, which is neither an all-clear nor an alarm.
    #[test]
    fn a_finalized_height_without_an_identity_is_indeterminate_not_agreed() {
        const H: u64 = 3776;
        let known = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), None);
        let blind = telem(3800, Some(H), None, None);
        let a = Agreement::of(&[node("node0", known.clone()), node("node1", blind)]);
        assert_eq!(a.verdict, Verdict::Indeterminate);
        assert_eq!(a.exit_code(), 0, "unknown is not the STOP; only a known split is");

        // …and a real split still wins over the unknown: 🔴 outranks 🟡.
        let other = telem(3800, Some(H), Some(0xbbbb_bbbb_bbbb), None);
        let worse = Agreement::of(&[
            node("node0", known),
            node("node1", telem(3800, Some(H), None, None)),
            node("node2", other),
        ]);
        assert_eq!(worse.verdict, Verdict::Diverged);
    }

    /// `sid` divergence is reported **separately** from `fid` divergence and at a
    /// different severity. This is the slot-3776 shape exactly: all nodes agree on
    /// `final` AND on `fid`, and one signed a different variant.
    #[test]
    fn sid_divergence_is_a_finding_beside_an_agreeing_fid_not_a_stop() {
        const H: u64 = 3776;
        let majority = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), Some((H, Some(0xaaaa_aaaa_aaaa))));
        let minority = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), Some((H, Some(0xcccc_cccc_cccc))));
        let a = Agreement::of(&[
            node("node0", majority.clone()),
            node("node1", majority),
            node("node2", minority),
        ]);

        assert_eq!(a.verdict, Verdict::Agreed, "the minority finalized the majority's checkpoint");
        assert_eq!(a.signed_verdict, SignedVerdict::VariantSplit, "🟡 and it signed another");
        assert_eq!(a.signed.len(), 1);
        assert_eq!(a.signed[0].at, H);
        assert_eq!(a.signed[0].distinct_ids(), 2);
        assert!(!a.is_clean());
        assert_eq!(a.exit_code(), 0, "a signed-variant split is read, not paged");
    }

    /// A node whose **own** keys are split across two variants at one slot, and a
    /// verify-only node holding no keys at all: one is a finding, the other is
    /// ordinary, and they must not look alike.
    #[test]
    fn a_nodes_own_key_split_is_a_finding_and_holding_no_keys_is_not() {
        const H: u64 = 3776;
        let own_split = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), Some((H, None)));
        let verify_only = telem(3800, Some(H), Some(0xaaaa_aaaa_aaaa), None);

        let a = Agreement::of(&[node("node0", own_split), node("node1", verify_only)]);
        assert_eq!(a.verdict, Verdict::Agreed);
        assert_eq!(a.signed_verdict, SignedVerdict::LocalSplit);
        assert_eq!(a.local_splits, vec!["node0".to_string()]);
        assert_eq!(a.not_signing, vec!["node1".to_string()], "no keys ⇒ not a split, just silent");
        assert_eq!(a.exit_code(), 0);
    }

    /// Grouping is deterministic: same readings in any order render the same
    /// groups, so two runs against an unchanged net produce identical output and a
    /// diff between them means something actually moved.
    #[test]
    fn grouping_is_order_independent_and_sorted() {
        let t1 = telem(3800, Some(3776), Some(0xaaaa_aaaa_aaaa), None);
        let t2 = telem(3800, Some(3776), Some(0xbbbb_bbbb_bbbb), None);
        let forward = Agreement::of(&[node("zeta", t1.clone()), node("alpha", t2.clone())]);
        let backward = Agreement::of(&[node("alpha", t2), node("zeta", t1)]);
        assert_eq!(forward.finalized, backward.finalized);
        assert_eq!(forward.finalized[0].ids[0].0, Some(0xaaaa_aaaa_aaaa));
        assert_eq!(forward.finalized[0].ids[0].1, vec!["zeta".to_string()]);
    }
}
