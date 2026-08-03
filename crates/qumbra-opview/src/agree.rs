//! Do these nodes agree on **what** they finalized?
//!
//! # The divergences are not the same thing, and are never merged
//!
//! `qumbra-deploy/OPERATOR.md` §3 already draws the first two lines and they are not
//! re-derived here, only honoured:
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
//! Issue #212 adds a third thing, and it is **two** alarms rather than one, because
//! the same pair of fields answers two different questions:
//!
//! - **A cross-host durable split** — two nodes reporting the same *durable* height
//!   ([`qlab_node::DurableView`]'s `dfin`) with different block identities
//!   (`dfinbh`). That is a **STOP**, at [`Verdict::Diverged`]'s severity and for a
//!   strictly stronger reason: `fid` reads head #1, which is discarded at shutdown,
//!   and this reads head #3, which is what both hosts come back as. *"These nodes
//!   finalized different things, and a restart will not undo it."*
//! - **A single node's head #1 vs head #3** ([`qlab_node::DurableAgreement`]) — a
//!   **finding**, not a stop. *"This node will come back different."* It is one node's
//!   two views of its own chain, nothing is yet inconsistent *between* hosts, and the
//!   routine cause is benign: `sync_state_finality` retries every drain, so the window
//!   between a checkpoint finalizing and its body being applied reads exactly like
//!   this. **Sustained is the alarm and one poll cannot establish sustained**, which
//!   is the same call the coordinator made for `cpq=1` on 2026-08-02 (*"watch, do not
//!   assume"*) and the same call #136 made for `UNAVAILABLE`: a condition every
//!   briefly-lagging node reports must not be a non-zero exit code, or operators
//!   learn to ignore the one code that means STOP. It is reported in the output as a
//!   greppable token instead — [`qlab_node::DurableAgreement::token`].
//!
//! 🔴 **`dfinbh` is a block-hash prefix and `fid` is a checkpoint identity. They are
//! not comparable and this module never compares them** — they sit in separately
//! typed groups ([`IdGroup<BlockIdentity>`] vs [`IdGroup<u64>`]) so the mistake does
//! not type-check, which is the same guard `qlab_node::BlockIdentity` installs one
//! layer down.
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

use qlab_node::{BlockIdentity, DurableAgreement, DurableView};

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

/// The verdict on **what survived**: head #3, across hosts (issue #212).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableVerdict {
    /// No two reachable nodes reported different block identities at a shared
    /// durable height. Includes the case where nothing is durably finalized anywhere.
    Agreed,
    /// A reachable node could not state a durable head, so agreement cannot be
    /// *established* — distinct from having been checked and found to hold.
    ///
    /// On a T0 net this is the **rolling-upgrade state**: a host still serving `0x03`
    /// has no durable head on its wire at all. [`Agreement::durable_blind`] carries
    /// which nodes and why, so this never has to be read as "the durable head is
    /// broken there".
    Indeterminate,
    /// 🔴 Two reachable nodes durably finalized **different blocks at one height**.
    ///
    /// A STOP, at [`Verdict::Diverged`]'s severity, and for a strictly stronger
    /// reason: this is the head both hosts come back as. An `fid` split is head #1,
    /// which is discarded at shutdown.
    Diverged,
}

/// Which nodes reported which identity, at one height (or slot). `None` as the key
/// means the node reported the height/slot with **no** identity — absent for a
/// finalized height, `split` for a signed slot.
///
/// **Generic in the identity type since issue #212**, and that is load-bearing
/// rather than tidiness: `fid`/`sid` are checkpoint identities (`u64`) and `dfinbh`
/// is a block-hash prefix ([`BlockIdentity`]). Both render at one width through one
/// helper, so nothing but the type keeps a reader — or this module — from lining one
/// up against the other, which is a comparison that cannot mean anything. With the
/// parameter, `Vec<IdGroup<u64>>` and `Vec<IdGroup<BlockIdentity>>` are different
/// types and mixing them does not compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdGroup<I = u64> {
    pub at: u64,
    /// Ascending by identity, and by label within an identity, so two runs against
    /// an unchanged net render byte-identically.
    pub ids: Vec<(Option<I>, Vec<String>)>,
}

impl<I> IdGroup<I> {
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

fn group<I: Ord>(entries: Vec<(u64, Option<I>, String)>) -> Vec<IdGroup<I>> {
    let mut by_at: BTreeMap<u64, BTreeMap<Option<I>, Vec<String>>> = BTreeMap::new();
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

    // ---- what survives a restart (`dfin`/`dfinbh`, issue #212) ----
    /// The **cross-host** verdict on head #3.
    pub durable_verdict: DurableVerdict,
    /// One entry per durable height any reachable node reported, ascending. The
    /// identities are **block** identities and are typed to keep them out of the
    /// `fid` groups above.
    pub durable: Vec<IdGroup<BlockIdentity>>,
    /// Reachable nodes whose head #3 has finalized nothing at all. Not a fault on a
    /// fresh net; on a node reporting a real `final=` it is
    /// [`DurableAgreement::NothingDurable`] and appears in [`Self::durable_lag`] too.
    pub not_durable: Vec<String>,
    /// **Per-node** head #1 vs head #3, for every node where they disagree — the
    /// 🟡 finding, kept apart from the cross-host verdict above because one says
    /// *"this node will come back different"* and the other says *"these nodes
    /// finalized different things"*.
    pub durable_lag: Vec<(String, DurableAgreement)>,
    /// Reachable nodes that stated no durable head, with the wire version they
    /// served. A version below [`qlab_node::DURABLE_HEAD_SINCE_VERSION`] is a host
    /// that has not been rolled yet — the roll state, not a defect.
    pub durable_blind: Vec<(String, u8)>,

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
        let mut dur_entries = Vec::new();
        let mut not_durable = Vec::new();
        let mut durable_lag = Vec::new();
        let mut durable_blind = Vec::new();

        for r in readings {
            let label = r.endpoint.label.clone();
            let Some(t) = r.reading.telemetry() else {
                let why = match &r.reading {
                    crate::poll::Reading::Unreachable(w) => w.clone(),
                    crate::poll::Reading::Ok { .. } => unreachable!(),
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

            // ---- issue #212: head #3 ----
            match t.durable {
                DurableView::Head(d) => dur_entries.push((d.height, Some(d.identity), label.clone())),
                DurableView::Nothing => not_durable.push(label.clone()),
                // The node answered and stated no durable head. The version says
                // whether that is "has not been rolled yet" or "this composition does
                // not read head #3", and both belong here rather than in a group,
                // because a node that could not answer is not a node at a height.
                DurableView::Unavailable => {
                    durable_blind.push((label.clone(), r.reading.wire_version().unwrap_or(0)));
                }
            }
            // The per-node comparison, from `Telemetry`'s single definition — this
            // module never re-derives it.
            let agreement = t.durable_agreement();
            if agreement.is_divergent() {
                durable_lag.push((label.clone(), agreement));
            }
        }

        let finalized = group(fin_entries);
        let signed = group(sig_entries);
        let durable = group(dur_entries);

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

        // The same precedence as `fid` (issue #212): 🔴 first, because a known split
        // outranks an unknown. A height where two nodes durably hold different blocks
        // is a divergence whether or not some third host has not been rolled yet.
        //
        // ⚠️ `not_durable` deliberately does NOT make this indeterminate. A node whose
        // head #3 holds nothing has answered the cross-host question — it is not at
        // any durable height, so it disagrees with nobody — and the fact that this is
        // alarming *about that node* is carried by `durable_lag`, at that alarm's own
        // severity. Folding it in here would page for a fresh net.
        let durable_verdict = if durable.iter().any(|g| g.is_split()) {
            DurableVerdict::Diverged
        } else if !durable_blind.is_empty() {
            DurableVerdict::Indeterminate
        } else {
            DurableVerdict::Agreed
        };

        Agreement {
            verdict,
            finalized,
            not_finalized,
            signed_verdict,
            signed,
            local_splits,
            not_signing,
            durable_verdict,
            durable,
            not_durable,
            durable_lag,
            durable_blind,
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

    /// The **durable** heights where two or more nodes could actually be compared
    /// (issue #212). Same rule as [`Self::comparable_heights`]: one node at a height
    /// is reported and is not evidence either way.
    pub fn comparable_durable_heights(&self) -> Vec<&IdGroup<BlockIdentity>> {
        self.durable.iter().filter(|g| g.nodes() >= 2).collect()
    }

    /// True when the readings are consistent with the net having finalized one
    /// history: no divergence and nothing unknown.
    ///
    /// Issue #212 folds the durable head in on both halves — a cross-host durable
    /// split and a single node whose two heads disagree both make the picture
    /// **not** clean, which is different from making it exit non-zero (see
    /// [`Self::exit_code`]).
    pub fn is_clean(&self) -> bool {
        self.verdict == Verdict::Agreed
            && self.signed_verdict == SignedVerdict::Agreed
            && self.durable_verdict == DurableVerdict::Agreed
            && self.durable_lag.is_empty()
    }

    /// The process exit code. **Only a cross-host identity divergence is non-zero**:
    /// those are the conditions that mean STOP, and an operator wiring this into an
    /// alert must not be paged for a node being down (that is what the rendered
    /// reachable count is for), for an `sid` split (a finding, which is read, not
    /// reacted to at 3 a.m.), or — since issue #212 — for a single node whose head #1
    /// is briefly ahead of its head #3.
    ///
    /// 🔴 **A durable split IS in the non-zero set** (issue #212), beside `fid`, and
    /// deliberately not as a third code. It is the same instruction to the operator —
    /// *stop, do not roll, preserve the data* — and a second STOP code would only
    /// make an alerting rule that already handles `2` fail to fire on the worse of
    /// the two conditions.
    ///
    /// 🟡 **[`DurableAgreement`] is NOT in it.** One poll cannot distinguish the
    /// hours-long node1 divergence from the ordinary window between a checkpoint
    /// finalizing and its body being applied, and a code that fires on every
    /// briefly-lagging node is a code operators mute — #136's ruling for
    /// `UNAVAILABLE`, applied to the same shape. The evidence is in the output, as
    /// [`DurableAgreement::token`].
    pub fn exit_code(&self) -> i32 {
        if self.verdict == Verdict::Diverged || self.durable_verdict == DurableVerdict::Diverged {
            2
        } else {
            0
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

    /// A snapshot from a real `qumbra-node` composition: it reads head #3, and here
    /// head #3 agrees with head #1 at the same height under one block identity.
    ///
    /// *(Issue #212 made this inject a durable head. It is the healthy default because
    /// it is what every live host reports — `dfin=2864` beside `final=2864` on all
    /// four T0 hosts, 2026-08-03 07:11:27Z. Tests that need head #3 to be absent,
    /// lagging, or split say so explicitly.)*
    fn telem(tip: u64, fin: Option<u64>, fid: Option<u64>, signed: Option<(u64, Option<u64>)>) -> Telemetry {
        with_durable(
            Telemetry::assemble(tip, fin, 75, 0, 3, 0, MAX_LAG)
                .with_checkpoint(fid, signed.map(|(slot, id)| LocalCommitment { slot, id })),
            fin.map(|h| (h, 0xdd)),
        )
    }

    fn node(label: &str, t: Telemetry) -> NodeReading {
        node_at(label, t, qlab_node::RPC_VERSION)
    }

    /// A node whose answer arrived on a specific wire version — the roll case
    /// (issue #212).
    fn node_at(label: &str, t: Telemetry, wire_version: u8) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Ok { telemetry: Box::new(t), wire_version },
            elapsed: Duration::from_millis(1),
        }
    }

    /// `telem` plus head #3 at `(height, first hash byte)`; `None` = head #3 read and
    /// holding nothing. Not calling it at all leaves the snapshot `Unavailable`.
    fn with_durable(t: Telemetry, head: Option<(u64, u8)>) -> Telemetry {
        t.with_durable_head(head.map(|(height, first)| {
            let mut hash = [0xee_u8; 32];
            hash[0] = first;
            (height, hash)
        }))
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

    // ---- issue #212: head #3 ------------------------------------------------

    /// **Acceptance (#212 E): the 2026-08-01 node1 case is now DETECTED, and before
    /// this change the same readings produced four-way agreement.**
    ///
    /// node1 held `final=1056 fid=fa3f9ac3680a` while its durable head was 1048 for
    /// hours. Every field the old wire carried is identical across all four hosts
    /// here — same `final`, same `fid` — so the `fid` verdict is `Agreed`, which is
    /// the correct answer to the question it asks and was the *whole* answer opview
    /// could give. The durable finding is the new one.
    #[test]
    fn the_2026_08_01_node1_divergence_is_visible_and_was_not_before() {
        const H: u64 = 1056;
        const FID: u64 = 0xfa3f_9ac3_680a;
        let healthy = telem(1060, Some(H), Some(FID), None);
        // Identical on every pre-#212 field, and its durable head is 8 behind.
        let node1 = with_durable(
            Telemetry::assemble(1060, Some(H), 75, 0, 3, 0, MAX_LAG).with_checkpoint(Some(FID), None),
            Some((1048, 0xdd)),
        );

        let a = Agreement::of(&[
            node("node0", healthy.clone()),
            node("node1", node1),
            node("node2", healthy.clone()),
            node("node3", healthy),
        ]);

        // What opview could already say, and it is not wrong — it is incomplete.
        assert_eq!(a.verdict, Verdict::Agreed, "head #1 agrees on all four, as it did then");
        assert_eq!(a.signed_verdict, SignedVerdict::Agreed);

        // 🟡 What it can say now.
        assert_eq!(a.durable_lag.len(), 1);
        assert_eq!(a.durable_lag[0].0, "node1");
        assert_eq!(
            a.durable_lag[0].1,
            DurableAgreement::TrackerAhead { tracker: 1056, durable: 1048 }
        );
        assert_eq!(a.durable_lag[0].1.token(), Some("DURABLE_LAG"));
        assert!(!a.is_clean(), "the picture is no longer clean, which is the point");

        // …and it is a FINDING: exit stays 0, because one poll cannot distinguish
        // "for hours" from "for this tick" and paging on the latter trains operators
        // to mute the code that means STOP (#136's ruling, same shape).
        assert_eq!(a.exit_code(), 0);
        // Cross-host, three nodes share durable height 1056 and agree; node1 is at
        // 1048 alone, so it disagrees with nobody. That is the honest cross-host
        // reading and it must not be inflated into a split.
        assert_eq!(a.durable_verdict, DurableVerdict::Agreed);
        assert_eq!(a.durable.len(), 2, "two durable heights, 1048 and 1056");
    }

    /// **Acceptance (#212 F): two hosts durably holding DIFFERENT blocks at one
    /// height is a STOP — exit 2, beside `fid`, and not a third exit code.**
    ///
    /// Note what agrees here: `final`, `fid`, `sid` and the durable *height*. Only the
    /// durable block identity differs, which is #84's sentence applied to head #3 —
    /// `dfin=` says how high, never what.
    #[test]
    fn two_nodes_durably_holding_different_blocks_at_one_height_is_a_stop() {
        const H: u64 = 2864;
        const FID: u64 = 0x63e4_2f7e_13a7;
        let base = Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG)
            .with_checkpoint(Some(FID), None);
        let a_node = with_durable(base.clone(), Some((H, 0xa1)));
        let b_node = with_durable(base, Some((H, 0xb2)));

        let a = Agreement::of(&[node("node0", a_node.clone()), node("node1", b_node)]);

        assert_eq!(a.verdict, Verdict::Agreed, "head #1 agrees — that is why this was invisible");
        assert_eq!(a.durable_verdict, DurableVerdict::Diverged);
        assert_eq!(a.durable.len(), 1, "one durable height, so one comparison");
        assert_eq!(a.durable[0].at, H);
        assert!(a.durable[0].is_split());
        assert_eq!(a.durable[0].distinct_ids(), 2);
        assert_eq!(a.comparable_durable_heights().len(), 1);
        assert!(a.durable_lag.is_empty(), "each node's own two heads agree");
        assert_eq!(a.exit_code(), 2, "the same STOP code as an fid split, not a third one");
        assert!(!a.is_clean());

        // Both nodes agreeing on the block is agreement, through the same path.
        let agreed = Agreement::of(&[node("node0", a_node.clone()), node("node1", a_node)]);
        assert_eq!(agreed.durable_verdict, DurableVerdict::Agreed);
        assert_eq!(agreed.exit_code(), 0);
        assert!(agreed.is_clean());
    }

    /// **Acceptance (#212 G — the roll): a host that has not been rolled yet is
    /// INDETERMINATE with its wire version, never a dissenter and never a fault.**
    ///
    /// This is the state of three of four hosts for most of a 23-minute roll. The
    /// rolled host's durable head is read; the un-rolled hosts' pre-existing fields
    /// are all read, which is the property that keeps the cross-host `fid` verdict
    /// answerable throughout — the thing a naive bump would have taken away.
    #[test]
    fn an_unrolled_host_is_indeterminate_with_its_wire_version_not_a_dissenter() {
        const H: u64 = 2864;
        const FID: u64 = 0x63e4_2f7e_13a7;
        let rolled = with_durable(
            Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG).with_checkpoint(Some(FID), None),
            Some((H, 0x63)),
        );
        // A 0x03 host decodes with no durable head at all — see
        // `Telemetry::from_bytes_compat`. The version is what attributes it.
        let unrolled = Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG)
            .with_checkpoint(Some(FID), None);

        let a = Agreement::of(&[
            node("node0", rolled),
            node_at("node1", unrolled.clone(), 0x03),
            node_at("node2", unrolled.clone(), 0x03),
            node_at("node3", unrolled, 0x03),
        ]);

        // 🔴 The property that matters: the cross-host `fid` verdict is still
        // answerable across all four hosts mid-roll.
        assert_eq!(a.reachable.len(), 4, "every host is still readable during the roll");
        assert!(a.unreachable.is_empty());
        assert_eq!(a.verdict, Verdict::Agreed);
        assert_eq!(a.comparable_heights().len(), 1, "all four compared at one height");

        // The durable verdict is honest about what it could not establish, and says
        // which hosts and why.
        assert_eq!(a.durable_verdict, DurableVerdict::Indeterminate);
        assert_eq!(a.durable_blind.len(), 3);
        assert_eq!(
            a.durable_blind.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(),
            vec!["node1", "node2", "node3"]
        );
        assert!(a.durable_blind.iter().all(|(_, v)| *v == 0x03));
        assert!(
            a.durable_blind.iter().all(|(_, v)| *v < qlab_node::DURABLE_HEAD_SINCE_VERSION),
            "these wires predate the field — a roll state, not a fault"
        );
        assert!(a.not_durable.is_empty(), "`no durable head stated` is not `head #3 holds nothing`");
        assert!(a.durable_lag.is_empty(), "an unmade comparison is not a finding");
        assert_eq!(a.exit_code(), 0, "an un-rolled host must never page as a STOP");

        // 🔴 …and a known split still outranks the unknown: 🔴 over INDETERMINATE.
        let split_mid_roll = Agreement::of(&[
            node("node0", with_durable(
                Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG).with_checkpoint(Some(FID), None),
                Some((H, 0xa1)),
            )),
            node("node1", with_durable(
                Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG).with_checkpoint(Some(FID), None),
                Some((H, 0xb2)),
            )),
            node_at("node2", Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG), 0x03),
        ]);
        assert_eq!(split_mid_roll.durable_verdict, DurableVerdict::Diverged);
        assert_eq!(split_mid_roll.exit_code(), 2);
    }

    /// **Head #3 holding NOTHING beside a real `final=` is reported at the per-node
    /// severity, and does not drag the cross-host verdict.**
    ///
    /// A node that has durably finalized nothing is at no durable height, so it
    /// disagrees with nobody — and the reason that is nevertheless alarming is a fact
    /// about *that node*, which is where it is reported. Folding it into the cross-host
    /// verdict would page for a fresh net, where it is the correct reading.
    #[test]
    fn nothing_durable_is_a_per_node_finding_and_a_fresh_net_is_not_an_alarm() {
        const H: u64 = 2864;
        let stranded = with_durable(
            Telemetry::assemble(2871, Some(H), 75, 0, 3, 2, MAX_LAG).with_checkpoint(Some(1), None),
            None,
        );
        let a = Agreement::of(&[node("node0", telem(2871, Some(H), Some(1), None)), node("node1", stranded)]);
        assert_eq!(a.not_durable, vec!["node1".to_string()]);
        assert_eq!(a.durable_lag.len(), 1);
        assert_eq!(a.durable_lag[0].1, DurableAgreement::NothingDurable { tracker: H });
        assert_eq!(a.durable_lag[0].1.token(), Some("DURABLE_ABSENT"));
        assert_eq!(a.durable_verdict, DurableVerdict::Agreed, "it is at no height, so it splits nothing");
        assert_eq!(a.exit_code(), 0);
        assert!(!a.is_clean());

        // A whole fresh net: nothing finalized on either head, anywhere. Agreement,
        // no finding, clean.
        let cold = Agreement::of(&[node("node0", telem(3, None, None, None)), node("node1", telem(3, None, None, None))]);
        assert_eq!(cold.durable_verdict, DurableVerdict::Agreed);
        assert!(cold.not_durable.len() == 2, "both read head #3 and it holds nothing");
        assert!(cold.durable_lag.is_empty(), "nothing on either head is consistent, not a finding");
        assert!(cold.is_clean());
        assert_eq!(cold.exit_code(), 0);
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
