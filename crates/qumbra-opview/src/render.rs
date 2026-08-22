//! Rendering the view: one row per node, then the two verdicts.
//!
//! Plain text, fixed columns, no colour. It is read over ssh at 3 a.m. and it is
//! diffed against the last run, so **the same net renders the same bytes**: rows
//! follow the configured order, groups are sorted, and nothing carries a
//! wall-clock stamp the caller did not ask for.
//!
//! The verdict lines are always all present, and always separate. Merging them into
//! one "healthy / unhealthy" would destroy the distinction the whole view exists to
//! preserve: an `fid` split is a STOP, an `sid` split is a finding, a durable split
//! is a STOP that survives a restart, and one node's two heads disagreeing is a
//! finding about that node — one line cannot say four things.

use crate::agree::{Agreement, DurableVerdict, IdGroup, SignedVerdict, Verdict};
use crate::poll::{NodeReading, Reading};

use qlab_node::telemetry::{SupplyCoverage, LOCAL_COMMITMENT_SPLIT};
use qlab_node::{BlockIdentity, DurableAgreement, DURABLE_HEAD_SINCE_VERSION};

/// How an identity renders in a group line.
///
/// A trait rather than a `to_string`, because the two identity spaces
/// ([`BlockIdentity`] and a checkpoint identity's raw `u64`) must keep their types
/// all the way to the last line that prints them — see [`IdGroup`]'s docs. They
/// render **identically on purpose**: one width, one scheme, so an operator reads the
/// digits the same way. That is exactly why the type, and not the rendering, is what
/// keeps them from being compared.
pub trait RenderId {
    fn render(&self) -> String;
}

impl RenderId for u64 {
    fn render(&self) -> String {
        qlab_node::telemetry::LocalCommitment { slot: 0, id: Some(*self) }.id_field()
    }
}

impl RenderId for BlockIdentity {
    fn render(&self) -> String {
        self.field()
    }
}

/// Render the per-node table.
///
/// `DFIN`/`DFINBH` are **appended at the end** (issue #212), under the same rule the
/// node's own `TELEMETRY` line follows for every addition since #87: every
/// pre-existing column keeps its name, position and meaning, so a `qumbra-ops/`
/// parser reading by column index does not shift.
pub fn table(readings: &[NodeReading]) -> String {
    let label_w = readings.iter().map(|r| r.endpoint.label.len()).max().unwrap_or(4).max(4);
    let mut out = String::new();
    out.push_str(&format!(
        "{:<label_w$}  {:>8} {:>8} {:>13} {:>9} {:>6} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>10} {:>8} {:>13} {:>8} {:>13}\n",
        "NODE", "TIP", "FINAL", "FID", "REGIME", "STALL", "AGE_S", "PEERS", "EPOCH", "C_SIZE",
        "C_ACT", "C_QRM", "DIFF", "SSLOT", "SID", "DFIN", "DFINBH",
    ));
    for r in readings {
        match &r.reading {
            Reading::Ok { telemetry: t, .. } => {
                let regime = format!("{:?}", t.finality_status);
                out.push_str(&format!(
                    "{:<label_w$}  {:>8} {:>8} {:>13} {:>9} {:>6} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>10} {:>8} {:>13} {:>8} {:>13}\n",
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
                    // Issue #212: head #3. `DFIN` is a height and `FINAL` is a
                    // height, and they are comparable — that comparison is the point.
                    // `DFINBH` is a BLOCK HASH prefix and `FID` is a checkpoint
                    // identity, and comparing THOSE two columns is meaningless
                    // however similar the digits look; the verdict block below says
                    // so in words and the type says so in code.
                    t.durable.height_field(),
                    t.durable.id_field(),
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
/// scheduled-issuance mismatch **that is not a scar this chain is known to carry**.
///
/// A partial state ledger is unavailable, not divergent: the operator may infer
/// neither supply agreement nor a supply violation until it catches fork choice.
///
/// 🔴 **The scar exclusion is not leniency** (#299 ruling item 2). The sequencing
/// ruling grandfathered height 1377 and accepted that epoch 1 reads DIVERGENT −4114
/// on this chain **forever**; it also named the price — *"a tool built to catch
/// supply violations must not train its readers to ignore red."* If this predicate
/// escalated on the scar, every operator view on the live net would carry a standing
/// 🔴 and the first real violation would arrive looking exactly like the noise the
/// operator had learned to scroll past. The scar keeps its row and its number (see
/// [`supply`]); what it loses is the escalation. The list is
/// `qlab_node::supply::KNOWN_SUPPLY_SCARS`, matched on epoch, both endpoints and the
/// exact divergence — one bessel either side of it still alarms.
pub fn supply_diverged(readings: &[NodeReading]) -> bool {
    readings.iter().any(|reading| {
        reading
            .reading
            .telemetry()
            .is_some_and(|t| {
                t.supply_coverage() == SupplyCoverage::Complete
                    && t.supply.iter().any(|row| row.is_unexplained_divergence())
            })
    })
}

/// Whether any reachable node reports a row that IS a known scar — so the view can
/// name it once, with its citation, instead of leaving an unexplained red number.
fn known_scar_seen(readings: &[NodeReading]) -> Option<&'static qlab_node::supply::KnownScar> {
    readings.iter().find_map(|reading| {
        reading
            .reading
            .telemetry()
            .and_then(|t| t.supply.iter().find_map(|row| row.known_scar()))
    })
}

/// Render the scheduled-issuance attestation carried by each reachable node.
///
/// Fees are a separate column because they are transfers and the body payee total
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
        let Reading::Ok { telemetry: t, .. } = &reading.reading else {
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
                if row.agrees() {
                    "AGREED"
                } else if row.known_scar().is_some() {
                    // Still red, still carrying its number — but named, so it is not
                    // one more unexplained DIVERGED for the operator to triage.
                    "KNOWN-SCAR"
                } else {
                    "DIVERGED"
                },
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
    if let Some(scar) = known_scar_seen(readings) {
        out.push_str(&format!(
            "KNOWN-SCAR epoch {} ({}..={}) {:+} bessel — grandfathered, NOT a new alarm: {}. Rows marked KNOWN-SCAR do not raise the divergence exit; any other non-zero total does.\n",
            scar.epoch,
            scar.start_height,
            scar.end_height,
            scar.divergence_bessel,
            scar.citation,
        ));
    }
    if supply_diverged(readings) {
        out.push_str(
            "🔴 A non-zero divergence means a canonical block committed scheduled issuance outside the frozen curve; first preserve the node data and identify the first divergent epoch/block before restarting or rolling.\n",
        );
    }
    out
}

fn ids_line<I: RenderId>(g: &IdGroup<I>, absent_means: &str) -> String {
    let parts: Vec<String> = g
        .ids
        .iter()
        .map(|(id, labels)| {
            let shown = match id {
                Some(v) => v.render(),
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

    // ---- what survives a restart (issue #212) -------------------------------
    let dhead = match a.durable_verdict {
        DurableVerdict::Agreed => "AGREED",
        DurableVerdict::Indeterminate => "INDETERMINATE",
        DurableVerdict::Diverged => "🔴 DIVERGED",
    };
    out.push_str(&format!("\ndurable finalized head (dfin/dfinbh): {dhead}\n"));
    out.push_str(
        "  head #3 — the head that survives a restart. `final`/`fid` above are head #1, \
         the committee tracker, which is discarded at shutdown.\n",
    );
    out.push_str(
        "  ⚠️ DFINBH is a BLOCK HASH prefix; FID is a checkpoint identity. \
         Comparing them is meaningless — compare DFINBH node-to-node at one DFIN only.\n",
    );
    if a.durable.is_empty() {
        out.push_str("  no node that answered has durably finalized anything\n");
    }
    for g in &a.durable {
        let marker = if g.is_split() { "🔴" } else { "  " };
        out.push_str(&format!(
            "  {marker} dfin={:<8} {}\n",
            g.at,
            ids_line(g, "no block identity reported")
        ));
    }
    if !a.not_durable.is_empty() {
        out.push_str(&format!(
            "     head #3 holds nothing: {}\n",
            a.not_durable.join(" ")
        ));
    }
    for (label, version) in &a.durable_blind {
        if *version < DURABLE_HEAD_SINCE_VERSION {
            out.push_str(&format!(
                "     {label}: wire 0x{version:02x} predates the durable head (issue #212) — \
                 this host has not been rolled yet, which is not a fault\n"
            ));
        } else {
            out.push_str(&format!(
                "     {label}: wire 0x{version:02x} carries the field and reported no durable \
                 head — this reader cannot see head #3 on that composition\n"
            ));
        }
    }
    match a.durable_verdict {
        DurableVerdict::Diverged => out.push_str(
            "     🔴 two different blocks durably finalized at one height. This is a STOP, and \
             it is worse than an fid split: head #3 is what these hosts come back as, so a \
             restart does not undo it. Stop, do not roll, and preserve the data dir on every \
             host.\n",
        ),
        DurableVerdict::Indeterminate => out.push_str(
            "     a node stated no durable head, so agreement could not be established (it is \
             not known to hold, and not known to be broken). During a roll this is expected \
             until every host serves the new wire.\n",
        ),
        DurableVerdict::Agreed => {
            let comparable = a.comparable_durable_heights();
            if comparable.is_empty() && a.durable.len() > 1 {
                out.push_str(
                    "     no two nodes share a durable height, so nothing was actually \
                     compared — this is lag, not agreement about identity.\n",
                );
            }
        }
    }

    // ---- one node's two heads (issue #212) — a FINDING, not a stop ----------
    if !a.durable_lag.is_empty() {
        out.push_str("\nhead #1 vs head #3, per node: 🟡 FINDING\n");
        for (label, agreement) in &a.durable_lag {
            let token = agreement.token().unwrap_or("");
            let detail = match agreement {
                DurableAgreement::TrackerAhead { tracker, durable } => format!(
                    "final={tracker} over a durable head of {durable} — this node will come back \
                     at {durable}"
                ),
                DurableAgreement::DurableAhead { tracker, durable } => format!(
                    "durable head {durable} is AHEAD of final={} — not reachable by construction, \
                     so this is a finding about the code and not about the net",
                    tracker.map(|t| t.to_string()).unwrap_or_else(|| "-".to_string())
                ),
                DurableAgreement::NothingDurable { tracker } => format!(
                    "final={tracker} and head #3 holds NOTHING — this node returns to genesis on \
                     a restart"
                ),
                DurableAgreement::Agreed | DurableAgreement::Unavailable => String::new(),
            };
            // The token is rendered as a BARE WORD — no trailing punctuation — because
            // alerting greps it, exactly as #136's `UNAVAILABLE` is grepped.
            out.push_str(&format!("  🟡 {label} {token} — {detail}\n"));
        }
        out.push_str(
            "     🟡 a FINDING, not a stop, and exit stays 0: one poll cannot tell the hours-long \
             2026-08-01 node1 divergence from the ordinary window between a checkpoint \
             finalizing and its body being applied. SUSTAINED is the alarm — re-poll, and read \
             it against the host's own slag= and fdrop=.\n",
        );
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

    /// A live-composition snapshot: head #3 read, and agreeing with head #1 (issue
    /// #212 — the healthy default, and what all four T0 hosts report).
    fn t_at(
        tip: u64,
        fin: Option<u64>,
        fid: Option<u64>,
        signed: Option<(u64, Option<u64>)>,
    ) -> Telemetry {
        durable(
            Telemetry::assemble(tip, fin, 75, 0, 3, 0, 16)
                .with_committee(21, 19, 15)
                .with_checkpoint(fid, signed.map(|(slot, id)| LocalCommitment { slot, id }))
                .with_tip_difficulty(Some(1_048_576)),
            fin.map(|h| (h, 0xdd)),
        )
    }

    fn t(fin: Option<u64>, fid: Option<u64>, signed: Option<(u64, Option<u64>)>) -> Telemetry {
        t_at(3800, fin, fid, signed)
    }

    fn durable(t: Telemetry, head: Option<(u64, u8)>) -> Telemetry {
        t.with_durable_head(head.map(|(height, first)| {
            let mut hash = [0xee_u8; 32];
            hash[0] = first;
            (height, hash)
        }))
    }

    fn ok(label: &str, tel: Telemetry) -> NodeReading {
        ok_at(label, tel, qlab_node::RPC_VERSION)
    }

    fn ok_at(label: &str, tel: Telemetry, wire_version: u8) -> NodeReading {
        NodeReading {
            endpoint: Endpoint { label: label.into(), base_url: format!("http://{label}:9410") },
            reading: Reading::Ok { telemetry: Box::new(tel), wire_version },
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

    // ---- issue #212: head #3 ------------------------------------------------

    /// **Acceptance (#212 H): the two new alarms render at DIFFERENT severities and
    /// on separate lines, and the view says in words that `DFINBH` and `FID` are not
    /// comparable.**
    ///
    /// The warning line is not decoration. `OPERATOR.md` §3 carries a section titled
    /// *"Two different values are called 'the genesis hash'. Comparing them is
    /// meaningless"* — written after an operator compared a block-header hash to a
    /// genesis-file hash and concluded a host was broken. The type system stops the
    /// mistake in code; this line is the half a human reads at 3 a.m.
    #[test]
    fn the_durable_alarms_render_apart_and_the_view_refuses_the_fid_comparison() {
        const H: u64 = 2864;
        // A cross-host durable split (🔴 STOP) and, on a third host, head #1 ahead of
        // head #3 (🟡 finding). Everything head #1 carries agrees on all three.
        let readings = vec![
            ok("node0", durable(t_at(2871, Some(H), Some(0xaaaa_aaaa_aaaa), None), Some((H, 0xa1)))),
            ok("node1", durable(t_at(2871, Some(H), Some(0xaaaa_aaaa_aaaa), None), Some((H, 0xb2)))),
            ok("node2", durable(t_at(2871, Some(H), Some(0xaaaa_aaaa_aaaa), None), Some((2856, 0xa1)))),
        ];
        let a = Agreement::of(&readings);
        let text = view(&readings, &a);

        // The `fid` verdict is untouched and still says AGREED — the two verdicts are
        // separate and this is the case that proves it.
        assert!(text.contains("checkpoint agreement (fid): AGREED"), "{text}");

        // 🔴 The durable split, in its own block, with both identities and who held
        // each — an alarm that does not say what it saw cannot be acted on.
        assert!(text.contains("durable finalized head (dfin/dfinbh): 🔴 DIVERGED"), "{text}");
        assert!(text.contains("a1eeeeeeeeee [node0]"), "{text}");
        assert!(text.contains("b2eeeeeeeeee [node1]"), "{text}");
        assert!(text.contains("head #3 is what these hosts come back as"), "{text}");
        assert_eq!(a.exit_code(), 2);

        // 🟡 The per-node finding, on its own line, at its own severity, with the
        // greppable token and the numbers.
        assert!(text.contains("head #1 vs head #3, per node: 🟡 FINDING"), "{text}");
        assert!(text.contains("node2 DURABLE_LAG"), "{text}");
        assert!(text.contains("final=2864 over a durable head of 2856"), "{text}");
        assert!(text.contains("a FINDING, not a stop, and exit stays 0"), "{text}");
        assert!(text.contains("SUSTAINED is the alarm"), "{text}");

        // 🔴 And the warning that keeps the trap from being re-sprung by eye.
        assert!(
            text.contains("DFINBH is a BLOCK HASH prefix; FID is a checkpoint identity"),
            "the view must refuse the meaningless comparison in words:\n{text}"
        );
        assert!(text.contains("Comparing them is meaningless"), "{text}");
    }

    /// **Acceptance (#212 I — the roll): an un-rolled host renders as INDETERMINATE
    /// with its wire version and the reason, and its own row still carries every
    /// pre-existing column.**
    ///
    /// The row is the point as much as the verdict: mid-roll an operator must still be
    /// able to read `FINAL`/`FID` off every host, or the cross-host question cannot be
    /// asked at all.
    #[test]
    fn an_unrolled_host_renders_its_wire_version_and_keeps_its_other_columns() {
        const H: u64 = 2864;
        let rolled = durable(t_at(2871, Some(H), Some(0xaaaa_aaaa_aaaa), None), Some((H, 0x63)));
        // `Unavailable` by construction — no `with_durable_head` call at all, which is
        // exactly what a `0x03` body decodes to.
        let unrolled = Telemetry::assemble(2871, Some(H), 75, 0, 3, 0, 16)
            .with_committee(21, 19, 15)
            .with_checkpoint(Some(0xaaaa_aaaa_aaaa), None)
            .with_tip_difficulty(Some(1_048_576));
        let readings = vec![ok("node0", rolled), ok_at("node1", unrolled, 0x03)];
        let a = Agreement::of(&readings);
        let text = view(&readings, &a);

        assert!(text.contains("durable finalized head (dfin/dfinbh): INDETERMINATE"), "{text}");
        assert!(
            text.contains("node1: wire 0x03 predates the durable head (issue #212)"),
            "the reason names the wire, not a defect:\n{text}"
        );
        assert!(text.contains("has not been rolled yet, which is not a fault"), "{text}");
        assert_eq!(a.exit_code(), 0, "an un-rolled host must never page as a STOP");

        // The un-rolled row still carries everything the old wire had; only the two
        // new columns are `-`.
        let row = text.lines().find(|l| l.starts_with("node1")).unwrap();
        assert!(row.contains("2871"), "tip renders: {row}");
        assert!(row.contains("aaaaaaaaaaaa"), "fid renders: {row}");
        let tail: Vec<&str> = row.split_whitespace().rev().take(2).collect();
        assert_eq!(tail, vec!["-", "-"], "DFIN and DFINBH are the two `-` columns: {row}");
        // …and the rolled host's are not.
        let rolled_row = text.lines().find(|l| l.starts_with("node0")).unwrap();
        assert!(rolled_row.contains("63eeeeeeeeee"), "{rolled_row}");
    }

    /// **`DURABLE_LAG` is a stable token and alerting may depend on it** — the same
    /// contract #136 gave `UNAVAILABLE`, and for the same reason: the condition it
    /// names exits `0`, so the exit status alone cannot tell "head #1 and head #3
    /// agree everywhere" from "one host will come back different".
    ///
    /// Pinned in both directions: present when the two heads disagree, and **absent**
    /// when they agree, or grepping it would mean nothing.
    #[test]
    fn durable_lag_is_a_stable_token_pinned_in_both_directions() {
        const H: u64 = 2864;
        let lagging = vec![ok("node0", durable(t_at(2871, Some(H), Some(1), None), Some((2856, 0xa1))))];
        let healthy = vec![ok("node0", durable(t_at(2871, Some(H), Some(1), None), Some((H, 0xa1))))];

        let lagging_text = view(&lagging, &Agreement::of(&lagging));
        let healthy_text = view(&healthy, &Agreement::of(&healthy));

        assert!(
            lagging_text.split_whitespace().any(|w| w == "DURABLE_LAG"),
            "a disagreement must render the token as a bare word:\n{lagging_text}"
        );
        assert!(
            !healthy_text.contains("DURABLE_LAG"),
            "agreement must not emit the token, or the grep says nothing:\n{healthy_text}"
        );
        // Neither is a STOP, which is exactly why the token has to carry the
        // distinction.
        assert_eq!(Agreement::of(&lagging).exit_code(), 0);
        assert_eq!(Agreement::of(&healthy).exit_code(), 0);
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
            burned: 0,
        };
        let wrong = SupplyEpoch {
            epoch: 1,
            start_height: 1152,
            end_height: 2303,
            measured_coinbase: 4_000_000_001,
            expected_coinbase: 4_000_000_000,
            fees: 789,
            burned: 0,
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

    /// **#299 ruling item 2 on the operator view.** The grandfathered epoch-1 scar
    /// keeps its row and its number but is named `KNOWN-SCAR`, does **not** raise the
    /// divergence escalation, and gets one citation line. Without this, every operator
    /// view on the live net would carry a standing 🔴 and the next real violation would
    /// arrive looking like noise. One bessel either side of the recorded total alarms.
    #[test]
    fn the_grandfathered_scar_is_named_and_does_not_raise_the_escalation() {
        fn scar_row(delta: i128) -> SupplyEpoch {
            let expected = 1_000_000_000u64;
            SupplyEpoch {
                epoch: 1,
                start_height: 1_152,
                end_height: 2_303,
                measured_coinbase: (expected as i128 + delta) as u64,
                expected_coinbase: expected,
                fees: 0,
                burned: 0,
            }
        }
        let readings = vec![ok(
            "node0",
            t_at(2_303, Some(2_303), Some(0x0102_0304_0506), None)
                .with_supply(vec![scar_row(-4_114)]),
        )];
        let text = view(&readings, &Agreement::of(&readings));
        assert!(text.contains("KNOWN-SCAR"), "the row is named:\n{text}");
        assert!(text.contains("-4114"), "the number is still published:\n{text}");
        assert!(text.contains("lab #299"), "with its citation:\n{text}");
        assert!(!text.contains("DIVERGED"), "not an unexplained divergence:\n{text}");
        assert!(
            !supply_diverged(&readings),
            "a grandfathered scar must not raise the divergence exit"
        );
        assert!(
            !text.contains("first preserve the node data"),
            "and must not print the violation runbook:\n{text}"
        );

        // Teeth: one bessel either side is a different fact and escalates.
        for other in [-4_113i128, -4_115] {
            let readings = vec![ok(
                "node0",
                t_at(2_303, Some(2_303), Some(0x0102_0304_0506), None)
                    .with_supply(vec![scar_row(other)]),
            )];
            assert!(supply_diverged(&readings), "divergence {other} must escalate");
            assert!(view(&readings, &Agreement::of(&readings)).contains("DIVERGED"));
        }
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
            burned: 0,
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

    /// **Issue #136: `UNAVAILABLE` is a stable token and alerting may depend on it.**
    ///
    /// It is the machine-readable half of #130's refusal, and it is the *only* thing
    /// that separates "supply was checked across the whole canonical chain and
    /// agreed" from "supply was never checked" — the assertions below show both
    /// leaving `supply_diverged` false, i.e. both exiting `0`. A script that reads
    /// only the exit status cannot tell them apart, so it must grep this token, and
    /// that makes the token a public contract in two directions:
    ///
    /// - it renders as a bare word under partial coverage, and
    /// - it is **absent** under complete coverage, or grepping it would mean nothing.
    ///
    /// Deliberately asserted as the bare token, separately from
    /// `supply_view_refuses_when_state_machine_lags_fork_choice`'s assertion on the
    /// whole refusal sentence: rewording that sentence must not be able to take the
    /// token with it. Same reason PR #126 pinned `!text.contains("AGREED")`.
    #[test]
    fn unavailable_is_a_stable_token_and_exit_zero_does_not_attest_coverage() {
        // One honest epoch, exact to the bessel. The only difference between the two
        // readings below is whether the state ledger has caught fork choice.
        let epoch = SupplyEpoch {
            epoch: 0,
            start_height: 0,
            end_height: 1151,
            measured_coinbase: 5_000_000_000,
            expected_coinbase: 5_000_000_000,
            fees: 456,
            burned: 0,
        };
        let lagging = vec![ok(
            "joining",
            t_at(1200, Some(1151), Some(0x0102_0304_0506), None).with_supply(vec![epoch.clone()]),
        )];
        let covered = vec![ok(
            "steady",
            t_at(1151, Some(1151), Some(0x0102_0304_0506), None).with_supply(vec![epoch]),
        )];

        let lagging_text = view(&lagging, &Agreement::of(&lagging));
        let covered_text = view(&covered, &Agreement::of(&covered));

        assert!(
            lagging_text.split_whitespace().any(|word| word == "UNAVAILABLE"),
            "incomplete coverage must render the token as a bare word:\n{lagging_text}"
        );
        assert!(
            !covered_text.contains("UNAVAILABLE"),
            "complete coverage must not emit the token, or the grep says nothing:\n{covered_text}"
        );
        // Complete coverage renders the figures the token's absence vouches for.
        assert!(covered_text.contains("5000000000"), "{covered_text}");
        assert!(!lagging_text.contains("5000000000"), "{lagging_text}");

        // The reason the token has to carry this: neither reading is a divergence,
        // so `main` exits 0 for both. Only the token separates them.
        assert!(!supply_diverged(&lagging), "partial coverage is not a violation");
        assert!(!supply_diverged(&covered), "an exact match is not a violation");
    }
}
