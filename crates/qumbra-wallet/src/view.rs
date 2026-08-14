//! Render a scan into the report a person reads — and the one rule it bends
//! around: **a balance the scan could not establish is UNAVAILABLE, never 0.**
//!
//! The verdicts come from [`Completeness`], which already distinguishes "empty
//! on the chain's authority" from "empty because this scan could not read". This
//! module formats those verdicts; it does not re-derive them (the explorer's
//! delegation rule, kept). The refused-figure token is the same `UNAVAILABLE`
//! opview (#136) and the explorer (#235) pin, so one grep covers all three
//! surfaces; totals print only when **every** scanned diversifier is `Complete`.
//!
//! # The second half of that rule (lab issue #314)
//!
//! A figure that could not subtract **spends** is UNAVAILABLE too, and for the
//! same reason: `spendable` is computed from outputs, so a wallet that has spent
//! over-quotes by exactly the notes it spent — which is what happened live,
//! under `verdict: complete`, minutes after this chain's first user send.
//!
//! Two mechanisms enforce it here rather than one, because this is the surface
//! that got it wrong:
//!
//! 1. [`DivScan::spendable_bessel`] is an `Option`, and it is `Some` **only**
//!    when the figure has been through the subtraction. There is no path that
//!    renders an unsubtracted number, because there is no unsubtracted number to
//!    render.
//! 2. [`SpentCoverage`] is stated on the report itself, next to the range —
//!    because a balance is a claim about a range *and* about how far its spends
//!    were checked, and a report that omits either invites being quoted as a
//!    claim about the chain.

use qlab_cbserver::client::{Completeness, ScanOutcome};

use qlab_ledger::spent::SpentReport;
// The vocabulary moved to qlab-ledger with the ledger it serves; imported back
// so there is exactly one spelling of UNAVAILABLE and one SpentCoverage.
pub use qlab_ledger::vocab::{SpentCoverage, UNAVAILABLE};

/// One diversifier's scan, reduced to what the report needs. A separate struct
/// (rather than holding `ScanOutcome` whole) so render tests can construct
/// every verdict without a devnet behind them.
pub struct DivScan {
    pub index: u64,
    pub address_short: String,
    pub completeness: Completeness,
    /// 🔴 `None` = **this figure does not exist**, and the renderer prints
    /// `UNAVAILABLE`. It is `Some` only after [`crate::spent::subtract_spent`]
    /// has run over a covered range — see the module docs.
    pub spendable_bessel: Option<u128>,
    pub shadowed_bessel: u128,
    /// Notes this scan opened whose nullifier is already on the chain —
    /// subtracted from the figure above, and reported rather than dropped.
    pub spent_count: usize,
    pub spent_bessel: u128,
    /// Set when the scan for this key NEVER STARTED (compact fetch/decode
    /// failed) — rendered as its own named verdict, not disguised as an
    /// empty `Incomplete`.
    pub never_started: Option<String>,
}

impl DivScan {
    /// A scan whose spends **have** been subtracted — the only constructor that
    /// produces a quotable figure.
    pub fn from_subtracted(
        index: u64,
        address_short: String,
        o: &ScanOutcome,
        spent: &SpentReport,
    ) -> DivScan {
        DivScan {
            index,
            address_short,
            completeness: o.completeness(),
            spendable_bessel: Some(spent.spendable_value()),
            shadowed_bessel: o.shadowed_value(),
            spent_count: spent.spent.len(),
            spent_bessel: spent.spent_value(),
            never_started: None,
        }
    }

    /// A scan whose figure cannot be quoted — the endpoint was unreachable, or
    /// the spends could not be subtracted. `why` is carried by the report-level
    /// [`SpentCoverage`] or by `never_started`; this constructor exists so no
    /// caller has to remember to blank the figure out.
    pub fn unquotable(index: u64, address_short: String, completeness: Completeness) -> DivScan {
        DivScan {
            index,
            address_short,
            completeness,
            spendable_bessel: None,
            shadowed_bessel: 0,
            spent_count: 0,
            spent_bessel: 0,
            never_started: None,
        }
    }
}

fn verdict_line(c: &Completeness) -> String {
    match c {
        Completeness::Complete => "complete".to_string(),
        Completeness::Incomplete { detected, opened } => format!(
            "{UNAVAILABLE} — {detected} output(s) are this key's by the committed discovery and \
             only {opened} could be read: something is here that this scan could not read"
        ),
        Completeness::Shadowed { opened, spendable } => format!(
            "shadowed — {} of {opened} opened note(s) are already dead (another note claims \
             their nullifier); spendable figures below EXCLUDE them",
            opened - spendable
        ),
        Completeness::IncompleteAndShadowed { detected, opened, spendable } => format!(
            "{UNAVAILABLE} + shadowed — {detected} detected / {opened} opened / {spendable} \
             spendable; both defects reported, neither hiding the other"
        ),
    }
}

/// The whole report. `range` is what was actually scanned — printed because a
/// balance is only ever a claim about a range, and a report that omits its
/// range invites quoting it as a claim about the chain. `spent` says how far the
/// spend-subtraction reached, for the same reason (lab issue #314).
pub fn render(scans: &[DivScan], range: (u64, u64), url: &str, spent: &SpentCoverage) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "scan of {} address(es) against {url}, heights {}..={}\n",
        scans.len(),
        range.0,
        range.1
    ));
    match spent {
        SpentCoverage::Covered { range: Some((a, b)) } => out.push_str(&format!(
            "spent-subtraction: the chain's nullifiers for {a}..={b} are in hand\n\n"
        )),
        SpentCoverage::Covered { range: None } => out.push_str(&format!(
            "spent-subtraction: the endpoint holds no block in {}..={} — nothing to subtract, \
             and nothing was found there either\n\n",
            range.0, range.1
        )),
        SpentCoverage::Unavailable { why } => out.push_str(&format!(
            "spent-subtraction: {UNAVAILABLE} — {why}\n\
             🔴 No spendable figure is printed below: a balance that cannot subtract this \
             wallet's own spends counts notes it has already spent.\n\n"
        )),
    }
    let mut all_quotable = true;
    for s in scans {
        let complete = s.never_started.is_none()
            && matches!(
                s.completeness,
                Completeness::Complete | Completeness::Shadowed { .. }
            );
        // 🔴 Two independent conditions, and BOTH must hold for a number to
        // appear: the scan read everything the chain says is this key's, and the
        // figure has been through the subtraction.
        let quotable = complete && s.spendable_bessel.is_some();
        all_quotable &= quotable;
        let verdict = match &s.never_started {
            Some(e) => format!("{UNAVAILABLE} — the scan never started: {e}"),
            None => verdict_line(&s.completeness),
        };
        out.push_str(&format!(
            "  [{}] {}\n      verdict:   {}\n",
            s.index, s.address_short, verdict
        ));
        match (quotable, s.spendable_bessel) {
            (true, Some(v)) => {
                out.push_str(&format!("      spendable: {v} bessel\n"));
                if s.spent_count > 0 {
                    out.push_str(&format!(
                        "      spent:     {} note(s), {} bessel already spent (subtracted above)\n",
                        s.spent_count, s.spent_bessel
                    ));
                }
                if s.shadowed_bessel > 0 {
                    out.push_str(&format!(
                        "      shadowed:  {} bessel (unspendable, excluded above)\n",
                        s.shadowed_bessel
                    ));
                }
            }
            // 🔴 The rule: no figure under a verdict that could not know. Even a
            // partial sum invites being quoted as a balance.
            _ => out.push_str(&format!("      spendable: {UNAVAILABLE}\n")),
        }
    }
    out.push('\n');
    if all_quotable {
        let total: u128 = scans.iter().filter_map(|s| s.spendable_bessel).sum();
        out.push_str(&format!("TOTAL spendable: {total} bessel\n"));
        if total == 0 {
            out.push_str(
                "(0 under a complete scan means nothing was paid to these addresses in this \
                 range, on the chain's authority)\n",
            );
        }
    } else {
        out.push_str(&format!(
            "TOTAL spendable: {UNAVAILABLE} — at least one address could not be fully read, or \
             its spends could not be subtracted; a partial total is not printed because it would \
             be quoted as a balance\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered() -> SpentCoverage {
        SpentCoverage::Covered { range: Some((0, 8)) }
    }

    fn div(idx: u64, c: Completeness, spend: u128, shadow: u128) -> DivScan {
        DivScan {
            index: idx,
            address_short: format!("qmbs1short{idx}"),
            completeness: c,
            spendable_bessel: Some(spend),
            shadowed_bessel: shadow,
            spent_count: 0,
            spent_bessel: 0,
            never_started: None,
        }
    }

    #[test]
    fn a_scan_that_never_started_is_its_own_named_verdict() {
        let mut d = div(0, Completeness::Complete, 999, 0);
        d.never_started = Some("connection refused".into());
        let r = render(&[d], (0, 8), "http://down", &covered());
        assert!(r.contains("never started: connection refused"));
        assert!(r.contains(UNAVAILABLE));
        assert!(!r.contains("999"), "no figure survives a scan that never ran");
    }

    #[test]
    fn a_complete_zero_is_zero_on_the_chains_authority() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (0, 8), "http://x", &covered());
        assert!(r.contains("TOTAL spendable: 0 bessel"));
        assert!(r.contains("on the chain's authority"));
        assert!(!r.contains(UNAVAILABLE));
    }

    #[test]
    fn an_incomplete_scan_renders_unavailable_and_never_a_number() {
        // Distinctive figure so absence is checkable as absence.
        let r = render(
            &[
                div(0, Completeness::Complete, 987_654_321, 0),
                div(1, Completeness::Incomplete { detected: 3, opened: 1 }, 111, 0),
            ],
            (0, 8),
            "http://x",
            &covered(),
        );
        assert!(r.contains(UNAVAILABLE), "the stable token");
        assert!(r.contains("could not read"));
        assert!(!r.contains("TOTAL spendable: 987654321"), "no partial total escapes");
        assert!(!r.contains("\n      spendable: 111"), "no figure under a blind verdict");
    }

    #[test]
    fn shadowed_notes_are_named_and_excluded_not_hidden() {
        let r = render(
            &[div(0, Completeness::Shadowed { opened: 3, spendable: 2 }, 500, 40)],
            (0, 8),
            "http://x",
            &covered(),
        );
        assert!(r.contains("already dead"));
        assert!(r.contains("spendable: 500 bessel"));
        assert!(r.contains("shadowed:  40 bessel"));
        assert!(r.contains("TOTAL spendable: 500"), "shadowed does not block the total");
    }

    #[test]
    fn the_range_is_always_on_the_report() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (5, 77), "http://n", &covered());
        assert!(r.contains("heights 5..=77"), "a balance is a claim about a range");
    }

    /// 🔴 **Lab issue #314's report, in the shape the live defect produced it.**
    /// Four 10-QMB notes, one of them spent: the figure DROPS by the spent note
    /// and the note is named rather than vanishing.
    #[test]
    fn a_spent_note_is_subtracted_and_reported_not_silently_dropped() {
        let mut d = div(0, Completeness::Complete, 3_899_000_000, 0);
        d.spent_count = 1;
        d.spent_bessel = 1_000_000_000;
        let r = render(&[d], (0, 5940), "http://x", &SpentCoverage::Covered { range: Some((0, 5940)) });
        assert!(r.contains("spendable: 3899000000 bessel"), "{r}");
        assert!(r.contains("spent:     1 note(s), 1000000000 bessel already spent"), "{r}");
        assert!(!r.contains("4899000000"), "the pre-#314 number must not appear anywhere");
        assert!(r.contains("nullifiers for 0..=5940 are in hand"), "the coverage is stated");
        assert!(r.contains("TOTAL spendable: 3899000000"));
    }

    /// 🔴 **The honesty rule (#314 scope item 3): an unsubtractable balance is
    /// UNAVAILABLE, with the reason — never a number under `complete`.** This is
    /// the exact shape of the live defect: the scan itself was fine, so the
    /// completeness verdict alone would have printed a confident wrong figure.
    #[test]
    fn a_scan_whose_spends_could_not_be_subtracted_quotes_nothing() {
        let unavailable = SpentCoverage::Unavailable {
            why: "the nullifier stream could not be read (404)".to_string(),
        };
        let r = render(
            &[DivScan::unquotable(0, "qmbs1short0".into(), Completeness::Complete)],
            (0, 5940),
            "http://x",
            &unavailable,
        );
        assert!(r.contains("verdict:   complete"), "the SCAN was complete — that is the trap");
        assert!(r.contains("spendable: UNAVAILABLE"), "{r}");
        assert!(r.contains("404"), "the reason travels to the person: {r}");
        assert!(r.contains("already spent"), "and it says what the risk is: {r}");
        assert!(r.contains("TOTAL spendable: UNAVAILABLE"));
    }

    /// The type makes the rule, not the renderer: a figure that never went
    /// through the subtraction is `None` and cannot be printed, even when the
    /// report-level coverage says the stream was fine.
    #[test]
    fn an_unsubtracted_figure_is_unprintable_even_under_a_covered_report() {
        let r = render(
            &[DivScan::unquotable(3, "qmbs1short3".into(), Completeness::Complete)],
            (0, 8),
            "http://x",
            &covered(),
        );
        assert!(r.contains("spendable: UNAVAILABLE"));
        assert!(r.contains("TOTAL spendable: UNAVAILABLE"));
    }
}
