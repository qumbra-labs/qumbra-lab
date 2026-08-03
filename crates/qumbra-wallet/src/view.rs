//! Render a scan into the report a person reads — and the one rule it bends
//! around: **a balance the scan could not establish is UNAVAILABLE, never 0.**
//!
//! The verdicts come from [`Completeness`], which already distinguishes "empty
//! on the chain's authority" from "empty because this scan could not read".
//! This module formats those verdicts; it does not re-derive them (the
//! explorer's delegation rule, kept). The refused-figure token is the same
//! `UNAVAILABLE` opview (#136) and the explorer (#235) pin, so one grep covers
//! all three surfaces; totals print only when **every** scanned diversifier is
//! `Complete`.

use qlab_cbserver::client::{Completeness, ScanOutcome};

/// The stable refused-figures token — same spelling as opview's and the
/// explorer's, deliberately.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// One diversifier's scan, reduced to what the report needs. A separate struct
/// (rather than holding `ScanOutcome` whole) so render tests can construct
/// every verdict without a devnet behind them.
pub struct DivScan {
    pub index: u64,
    pub address_short: String,
    pub completeness: Completeness,
    pub spendable_bessel: u128,
    pub shadowed_bessel: u128,
    /// Set when the scan for this key NEVER STARTED (compact fetch/decode
    /// failed) — rendered as its own named verdict, not disguised as an
    /// empty `Incomplete`.
    pub never_started: Option<String>,
}

impl DivScan {
    pub fn from_outcome(index: u64, address_short: String, o: &ScanOutcome) -> DivScan {
        DivScan {
            index,
            address_short,
            completeness: o.completeness(),
            spendable_bessel: o.spendable_value(),
            shadowed_bessel: o.shadowed_value(),
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
/// range invites quoting it as a claim about the chain.
pub fn render(scans: &[DivScan], range: (u64, u64), url: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "scan of {} address(es) against {url}, heights {}..={}\n\n",
        scans.len(),
        range.0,
        range.1
    ));
    let mut all_complete = true;
    for s in scans {
        let complete = s.never_started.is_none()
            && matches!(
                s.completeness,
                Completeness::Complete | Completeness::Shadowed { .. }
            );
        all_complete &= complete;
        let verdict = match &s.never_started {
            Some(e) => format!("{UNAVAILABLE} — the scan never started: {e}"),
            None => verdict_line(&s.completeness),
        };
        out.push_str(&format!(
            "  [{}] {}\n      verdict:   {}\n",
            s.index, s.address_short, verdict
        ));
        if complete {
            out.push_str(&format!("      spendable: {} bessel\n", s.spendable_bessel));
            if s.shadowed_bessel > 0 {
                out.push_str(&format!(
                    "      shadowed:  {} bessel (unspendable, excluded above)\n",
                    s.shadowed_bessel
                ));
            }
        } else {
            // 🔴 The rule: no figure under a verdict that could not know. Even a
            // partial sum invites being quoted as a balance.
            out.push_str(&format!("      spendable: {UNAVAILABLE}\n"));
        }
    }
    out.push('\n');
    if all_complete {
        let total: u128 = scans.iter().map(|s| s.spendable_bessel).sum();
        out.push_str(&format!("TOTAL spendable: {total} bessel\n"));
        if total == 0 {
            out.push_str(
                "(0 under a complete scan means nothing was paid to these addresses in this \
                 range, on the chain's authority)\n",
            );
        }
    } else {
        out.push_str(&format!(
            "TOTAL spendable: {UNAVAILABLE} — at least one address could not be fully read; a \
             partial total is not printed because it would be quoted as a balance\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn div(idx: u64, c: Completeness, spend: u128, shadow: u128) -> DivScan {
        DivScan {
            index: idx,
            address_short: format!("qmbs1short{idx}"),
            completeness: c,
            spendable_bessel: spend,
            shadowed_bessel: shadow,
            never_started: None,
        }
    }

    #[test]
    fn a_scan_that_never_started_is_its_own_named_verdict() {
        let mut d = div(0, Completeness::Complete, 999, 0);
        d.never_started = Some("connection refused".into());
        let r = render(&[d], (0, 8), "http://down");
        assert!(r.contains("never started: connection refused"));
        assert!(r.contains(UNAVAILABLE));
        assert!(!r.contains("999"), "no figure survives a scan that never ran");
    }

    #[test]
    fn a_complete_zero_is_zero_on_the_chains_authority() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (0, 8), "http://x");
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
        );
        assert!(r.contains("already dead"));
        assert!(r.contains("spendable: 500 bessel"));
        assert!(r.contains("shadowed:  40 bessel"));
        assert!(r.contains("TOTAL spendable: 500"), "shadowed does not block the total");
    }

    #[test]
    fn the_range_is_always_on_the_report() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (5, 77), "http://n");
        assert!(r.contains("heights 5..=77"), "a balance is a claim about a range");
    }
}
