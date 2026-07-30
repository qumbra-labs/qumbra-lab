//! Rendering the view: one row per node, then the two verdicts.
//!
//! Plain text, fixed columns, no colour. It is read over ssh at 3 a.m. and it is
//! diffed against the last run, so **the same net renders the same bytes**: rows
//! follow the configured order, groups are sorted, and nothing carries a
//! wall-clock stamp the caller did not ask for.
//!
//! The two verdict lines are always both present, and always separate. Merging
//! them into one "healthy / unhealthy" would destroy the distinction the whole
//! view exists to preserve: an `fid` split is a STOP and an `sid` split is a
//! finding, and one line cannot say both.

use crate::agree::{Agreement, IdGroup, SignedVerdict, Verdict};
use crate::poll::{NodeReading, Reading};

use qlab_node::telemetry::{SupplyCoverage, LOCAL_COMMITMENT_SPLIT};

/// Render the per-node table.
pub fn table(readings: &[NodeReading]) -> String {
    let label_w = readings.iter().map(|r| r.endpoint.label.len()).max().unwrap_or(4).max(4);
    let mut out = String::new();
    out.push_str(&format!(
        "{:<label_w$}  {:>8} {:>8} {:>13} {:>9} {:>6} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>10} {:>8} {:>13}\n",
        "NODE", "TIP", "FINAL", "FID", "REGIME", "STALL", "AGE_S", "PEERS", "EPOCH", "C_SIZE",
        "C_ACT", "C_QRM", "DIFF", "SSLOT", "SID",
    ));
    for r in readings {
        match &r.reading {
            Reading::Ok(t) => {
                let regime = format!("{:?}", t.finality_status);
                out.push_str(&format!(
                    "{:<label_w$}  {:>8} {:>8} {:>13} {:>9} {:>6} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>10} {:>8} {:>13}\n",
                    r.endpoint.label,
                    t.tip_height,
                    t.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
                    t.fid_field(),
                    regime,
                    t.stall_depth,
                    // `-` while there is no finalized checkpoint to measure from —
                    // nothing finalized (S8) or finalized-at-genesis (#73). The rule
                    // is `Telemetry`'s, shared with the node's own TELEMETRY line.
                    t.age_field(),
                    t.peer_count,
                    t.epoch,
                    t.committee_size,
                    t.committee_active,
                    t.committee_quorum,
                    t.diff_field(),
                    t.sslot_field(),
                    t.sid_field(),
                ));
            }
            // An unreachable node gets a row of its own, marked as such, with the
            // reason on it — never a row of dashes that could be misread as a node
            // reporting nothing, and never a row omitted (a missing node is the
            // thing an operator most needs to see).
            Reading::Unreachable(why) => {
                out.push_str(&format!(
                    "{:<label_w$}  {:>8} {}\n",
                    r.endpoint.label, "UNREACHABLE", why
                ));
            }
        }
    }
    out
}

/// Whether any reachable node with complete state coverage reports an exact
/// scheduled-issuance mismatch.
///
/// A partial state ledger is unavailable, not divergent: the operator may infer
/// neither supply agreement nor a supply violation until it catches fork choice.
pub fn supply_diverged(readings: &[NodeReading]) -> bool {
    readings.iter().any(|reading| {
        reading
            .reading
            .telemetry()
            .is_some_and(|t| {
                t.supply_coverage() == SupplyCoverage::Complete
                    && t.supply.iter().any(|row| !row.agrees())
            })
    })
}

/// Render the scheduled-issuance attestation carried by each reachable node.
///
/// Fees are a separate column because they are transfers and `body.coinbase`
/// already excludes them. Pass/fail is the exact integer `DIV_BSL == 0`; the
/// relative column is context for humans, never a floating-point tolerance.
pub fn supply(readings: &[NodeReading]) -> String {
    let label_w = readings
        .iter()
        .map(|r| r.endpoint.label.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let mut out = String::from(
        "\nsupply attestation: scheduled body.coinbase; fees are transfers and are not subtracted; tolerance=0 bessel\n",
    );
    out.push_str(&format!(
        "{:<label_w$}  {:>7} {:>17} {:>20} {:>20} {:>14} {:>11} {:>14} {:>8}\n",
        "NODE", "EPOCH", "HEIGHTS", "MEASURED_BSL", "EXPECTED_BSL", "DIV_BSL", "RELATIVE",
        "FEES_BSL", "STATUS",
    ));
    let mut rows = 0usize;
    let mut unavailable = 0usize;
    for reading in readings {
        let Reading::Ok(t) = &reading.reading else {
            continue;
        };
        if let SupplyCoverage::Unavailable {
            state_tip,
            fork_choice_tip,
        } = t.supply_coverage()
        {
            unavailable += 1;
            let state_tip = state_tip.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "{:<label_w$}  UNAVAILABLE — state ledger tip {} does not match fork-choice tip {}; refusing partial supply figures\n",
                reading.endpoint.label, state_tip, fork_choice_tip,
            ));
            continue;
        }
        for row in &t.supply {
            rows += 1;
            let relative = if row.relative_divergence().is_finite() {
                format!("{:+.3e}", row.relative_divergence())
            } else {
                "+inf".to_string()
            };
            out.push_str(&format!(
                "{:<label_w$}  {:>7} {:>17} {:>20} {:>20} {:>+14} {:>11} {:>14} {:>8}\n",
                reading.endpoint.label,
                row.epoch,
                format!("{}..={}", row.start_height, row.end_height),
                row.measured_coinbase,
                row.expected_coinbase,
                row.divergence_bessel(),
                relative,
                row.fees,
                if row.agrees() { "AGREED" } else { "DIVERGED" },
            ));
        }
    }
    if rows == 0 && unavailable == 0 {
        out.push_str("no reachable node reported a supply epoch\n");
    }
    if unavailable != 0 {
        out.push_str(
            "An unavailable supply view means the state ledger is behind or otherwise disagrees with fork choice; conclude neither supply agreement nor a supply violation until the tips match.\n",
        );
    }
    if supply_diverged(readings) {
        out.push_str(
            "🔴 A non-zero divergence means a canonical block committed scheduled issuance outside the frozen curve; first preserve the node data and identify the first divergent epoch/block before restarting or rolling.\n",
        );
    }
    out
}

fn ids_line(g: &IdGroup, absent_means: &str) -> String {
    let parts: Vec<String> = g
        .ids
        .iter()
        .map(|(id, labels)| {
            let shown = match id {
                Some(v) => qlab_node::telemetry::LocalCommitment { slot: 0, id: Some(*v) }.id_field(),
                None => absent_means.to_string(),
            };
            format!("{shown} [{}]", labels.join(" "))
        })
        .collect();
    parts.join("  vs  ")
}

/// Render the two verdicts and the evidence under each.
pub fn verdicts(a: &Agreement) -> String {
    let mut out = String::new();
    let reach = a.reachable.len();
    let total = reach + a.unreachable.len();

    // ---- what was finalized -------------------------------------------------
    let head = match a.verdict {
        Verdict::Agreed => "AGREED",
        Verdict::Indeterminate => "INDETERMINATE",
        Verdict::Diverged => "🔴 DIVERGED",
    };
    out.push_str(&format!(
        "\ncheckpoint agreement (fid): {head} — {reach}/{total} nodes answered\n"
    ));
    if a.finalized.is_empty() {
        out.push_str("  nothing finalized on any node that answered\n");
    }
    for g in &a.finalized {
        let marker = if g.is_split() { "🔴" } else { "  " };
        out.push_str(&format!(
            "  {marker} final={:<8} {}\n",
            g.at,
            ids_line(g, "no identity reported")
        ));
    }
    if !a.not_finalized.is_empty() {
        out.push_str(&format!("     nothing finalized yet: {}\n", a.not_finalized.join(" ")));
    }
    match a.verdict {
        Verdict::Diverged => out.push_str(
            "     🔴 two different checkpoints finalized at one height. This is the R2 STOP \
             condition — stop, do not roll, and preserve the finalizer state on every host.\n",
        ),
        Verdict::Indeterminate => out.push_str(
            "     a node reported a finalized height with no identity, so agreement could not \
             be established (it is not known to hold, and not known to be broken).\n",
        ),
        Verdict::Agreed => {
            let comparable = a.comparable_heights();
            if comparable.is_empty() && a.finalized.len() > 1 {
                out.push_str(
                    "     no two nodes share a finalized height, so nothing was actually \
                     compared — this is lag, not agreement about identity.\n",
                );
            }
        }
    }

    // ---- what was signed ----------------------------------------------------
    let shead = match a.signed_verdict {
        SignedVerdict::Agreed => "AGREED",
        SignedVerdict::LocalSplit => "🟡 LOCAL SPLIT",
        SignedVerdict::VariantSplit => "🟡 VARIANT SPLIT",
    };
    out.push_str(&format!("\nsigned variant (sslot/sid): {shead}\n"));
    if a.signed.is_empty() {
        out.push_str("  no node that answered holds committee keys, or none has signed yet\n");
    }
    for g in &a.signed {
        let marker = if g.is_split() { "🟡" } else { "  " };
        out.push_str(&format!(
            "  {marker} sslot={:<8} {}\n",
            g.at,
            ids_line(g, LOCAL_COMMITMENT_SPLIT)
        ));
    }
    if !a.not_signing.is_empty() {
        out.push_str(&format!("     no committee keys / nothing signed: {}\n", a.not_signing.join(" ")));
    }
    match a.signed_verdict {
        SignedVerdict::VariantSplit => out.push_str(
            "     🟡 a FINDING, not a stop: the minority still finalizes the majority's \
             checkpoint, which is why fid can agree while this does not. Record it.\n",
        ),
        SignedVerdict::LocalSplit => out.push_str(&format!(
            "     🟡 a FINDING: {} holds keys committed to two different variants at one slot \
             — it is equivocating against itself across its own key set.\n",
            a.local_splits.join(" ")
        )),
        SignedVerdict::Agreed => {}
    }

    // ---- who did not answer -------------------------------------------------
    if !a.unreachable.is_empty() {
        out.push_str(&format!(
            "\nunreachable ({}): a timeout is missing evidence, not a disagreement — these \
             nodes are excluded from both verdicts above\n",
            a.unreachable.len()
        ));
        for (label, why) in &a.unreachable {
            out.push_str(&format!("  {label}: {why}\n"));
        }
    }
    out
}

/// The whole view: table, then verdicts.
pub fn view(readings: &[NodeReading], a: &Agreement) -> String {
    format!("{}{}{}", table(readings), supply(readings), verdicts(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::Endpoint;
    use qlab_node::telemetry::LocalCommitment;
    use qlab_node::{SupplyEpoch, Telemetry};
    use std::time::Duration;

    fn t_at(
        tip: u64,
        fin: Option<u64>,
        fid: Option<u64>,
        signed: Option<(u64, Option<u64>)>,
    ) -> Telemetry {
        Telemetry::assemble(tip, fin, 75, 0, 3, 0, 16)
            .with_committee(21, 19, 15)
            .with_checkpoint(fid, signed.map(|(slot, id)| LocalCommitment { slot, id }))
            .with_tip_difficulty(Some(1_048_576))
    }

    fn t(fin: Option<u64>, fid: Option<u64>, signed: Option<(u64, Option<u64>)>) -> Telemetry {
        t_at(3800, fin, fid, signed)
    }

    fn ok(label: &str, tel: Telemetry) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Ok(Box::new(tel)),
            elapsed: Duration::from_millis(2),
        }
    }
    fn down(label: &str) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Unreachable("connect: Connection refused".into()),
            elapsed: Duration::from_millis(1),
        }
    }

    /// The rendering keeps the three states visually distinct — and in particular an
    /// unreachable node is labelled UNREACHABLE with its reason, never rendered as a
    /// node that disagreed or as a row of blanks.
    #[test]
    fn unreachable_renders_as_unreachable_and_never_as_a_dissent() {
        let readings = vec![
            ok("node0", t(Some(3776), Some(0xaaaa_aaaa_aaaa), Some((3776, Some(0xaaaa_aaaa_aaaa))))),
            down("node3"),
        ];
        let a = Agreement::of(&readings);
        let text = view(&readings, &a);

        assert!(text.contains("UNREACHABLE"), "{text}");
        assert!(text.contains("Connection refused"), "{text}");
        assert!(text.contains("checkpoint agreement (fid): AGREED — 1/2 nodes answered"), "{text}");
        assert!(text.contains("excluded from both verdicts"), "{text}");
        assert!(!text.contains("DIVERGED"), "a down node must never render as a split:\n{text}");
    }

    /// A real divergence says STOP, in those words, and marks the height. An `sid`
    /// split on the same view says FINDING and is on its own line.
    #[test]
    fn the_two_divergences_render_at_different_severities() {
        let readings = vec![
            ok("node0", t(Some(3776), Some(0xaaaa_aaaa_aaaa), Some((3776, Some(0xaaaa_aaaa_aaaa))))),
            ok("node1", t(Some(3776), Some(0xbbbb_bbbb_bbbb), Some((3776, Some(0xcccc_cccc_cccc))))),
        ];
        let a = Agreement::of(&readings);
        let text = view(&readings, &a);

        assert!(text.contains("🔴 DIVERGED"), "{text}");
        assert!(text.contains("R2 STOP"), "{text}");
        assert!(text.contains("VARIANT SPLIT"), "{text}");
        assert!(text.contains("a FINDING, not a stop"), "{text}");
        // Both identities are shown, with who reported each — an alarm that does not
        // say what it saw cannot be acted on.
        assert!(text.contains("aaaaaaaaaaaa [node0]"), "{text}");
        assert!(text.contains("bbbbbbbbbbbb [node1]"), "{text}");
    }

    /// Issue #73: a node whose finalized head is still genesis (`FINAL` 0 — every
    /// fresh net, between start and its first non-genesis checkpoint) renders
    /// `AGE_S` as `-`, exactly like the node's own TELEMETRY line — never the
    /// tip−genesis subtraction that read as the wall clock on the #119 run.
    #[test]
    fn age_renders_as_dash_while_the_finalized_head_is_genesis() {
        let readings = vec![
            ok("node0", t(Some(0), Some(0xaaaa_aaaa_aaaa), None)),
            ok("node1", t(Some(3776), Some(0xaaaa_aaaa_aaaa), None)),
        ];
        let text = table(&readings);
        // AGE_S is the 7th column: NODE TIP FINAL FID REGIME STALL AGE_S …
        let age_of = |label: &str| {
            text.lines()
                .find(|l| l.starts_with(label))
                .unwrap()
                .split_whitespace()
                .nth(6)
                .unwrap()
                .to_string()
        };
        assert_eq!(age_of("node0"), "-", "finalized-at-genesis has no age to state:\n{text}");
        assert_eq!(age_of("node1"), "75", "a real finalized checkpoint reports its age:\n{text}");
    }

    /// Same readings ⇒ same bytes, whatever order they arrived in. The view is
    /// diffed between runs, so a spurious diff is a false alarm of its own.
    #[test]
    fn rendering_is_deterministic() {
        let a1 = ok("node0", t(Some(3776), Some(0xaaaa_aaaa_aaaa), None));
        let b1 = ok("node1", t(Some(3776), Some(0xaaaa_aaaa_aaaa), None));
        let one = vec![a1.clone(), b1.clone()];
        let two = vec![a1, b1];
        assert_eq!(view(&one, &Agreement::of(&one)), view(&two, &Agreement::of(&two)));
    }

    /// n = 1 renders a table and both verdicts, with no "not applicable" branch.
    #[test]
    fn n_equals_one_renders_a_whole_view() {
        let readings =
            vec![ok("node0", t(Some(384), Some(0x0102_0304_0506), Some((384, Some(0x0102_0304_0506)))))];
        let a = Agreement::of(&readings);
        let text = view(&readings, &a);
        assert!(text.contains("checkpoint agreement (fid): AGREED — 1/1 nodes answered"), "{text}");
        assert!(text.contains("signed variant (sslot/sid): AGREED"), "{text}");
        assert!(text.contains("010203040506"), "{text}");
        assert!(text.contains("1048576"), "difficulty renders:\n{text}");
        assert!(text.contains("C_SIZE"), "committee header renders:\n{text}");
        assert!(text.contains("    21     19     15"), "committee aggregates render:\n{text}");
    }

    /// **Acceptance (#121): the public view has no per-signer participation
    /// family.** Aggregates are useful; a roster availability map is an attacker's
    /// checklist. Keep the exact private metric/journal tokens out so a future
    /// well-meaning renderer addition breaks this test.
    #[test]
    fn public_view_cannot_render_per_signer_participation() {
        let readings =
            vec![ok("node0", t(Some(384), Some(0x0102_0304_0506), Some((384, Some(0x0102_0304_0506)))))];
        let text = view(&readings, &Agreement::of(&readings));
        for forbidden in [
            "qumbra_committee_signed",
            "qumbra_committee_absent",
            "voted=",
            "absent=",
        ] {
            assert!(!text.contains(forbidden), "public view leaked `{forbidden}`:\n{text}");
        }
    }

    /// The rendered view carries both halves of the supply acceptance: an honest
    /// epoch passes at exact zero, while a one-bessel error is visibly divergent
    /// and produces an operator action.
    #[test]
    fn supply_view_distinguishes_exact_match_from_one_bessel_error() {
        let honest = SupplyEpoch {
            epoch: 0,
            start_height: 0,
            end_height: 1151,
            measured_coinbase: 5_000_000_000,
            expected_coinbase: 5_000_000_000,
            fees: 456,
        };
        let wrong = SupplyEpoch {
            epoch: 1,
            start_height: 1152,
            end_height: 2303,
            measured_coinbase: 4_000_000_001,
            expected_coinbase: 4_000_000_000,
            fees: 789,
        };
        let readings = vec![ok(
            "node0",
            t_at(2303, Some(2303), Some(0x0102_0304_0506), None)
                .with_supply(vec![honest, wrong]),
        )];
        let text = view(&readings, &Agreement::of(&readings));
        assert!(text.contains("tolerance=0 bessel"), "{text}");
        assert!(text.contains("          +0"), "honest absolute divergence:\n{text}");
        assert!(text.contains("          +1"), "wrong absolute divergence:\n{text}");
        assert!(text.contains("DIVERGED"), "{text}");
        assert!(text.contains("first preserve the node data"), "{text}");
        assert!(supply_diverged(&readings));
    }

    /// Issue #130: the state machine can permanently trail fork choice because
    /// historical bodies are not transferred. A partial row is not rendered as
    /// `AGREED` (and cannot trigger the divergence exit); the operator gets one
    /// explicit refusal and the only conclusion the evidence supports.
    #[test]
    fn supply_view_refuses_when_state_machine_lags_fork_choice() {
        let partial = SupplyEpoch {
            epoch: 0,
            start_height: 0,
            end_height: 4,
            measured_coinbase: 123_456_789,
            expected_coinbase: 123_456_789,
            fees: 17,
        };
        let readings = vec![ok(
            "late-joiner",
            t_at(14, Some(8), Some(0x0102_0304_0506), None).with_supply(vec![partial]),
        )];

        let text = supply(&readings);
        assert!(
            text.contains(
                "late-joiner  UNAVAILABLE — state ledger tip 4 does not match fork-choice tip 14"
            ),
            "{text}"
        );
        assert!(
            text.contains("conclude neither supply agreement nor a supply violation"),
            "{text}"
        );
        assert!(!text.contains("123456789"), "partial figures must not render:\n{text}");
        assert!(!text.contains("AGREED"), "partial coverage must not claim agreement:\n{text}");
        assert!(!supply_diverged(&readings), "unavailable is not a supply violation");
    }
}
