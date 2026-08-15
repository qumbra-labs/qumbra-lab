//! The scan-report reduction — verdicts computed in Rust, rendered text
//! crossing the ABI, so Swift colors words and never re-derives a verdict.
//!
//! 🔴 **Known duplication, recorded on issue #246:** this is the same reduction
//! as `qumbra-wallet::view` (PR #244, unmerged as this crate is written). Not
//! stacked on that branch deliberately — a PR must be judgeable independently.
//! **Follow-up owed: when #244 lands, this crate depends on `qumbra-wallet`'s
//! lib and this module is deleted.** Until then the two copies share the
//! `UNAVAILABLE` token and the no-partial-totals rule verbatim.

use qlab_cbserver::client::{Completeness, ScanOutcome};

/// Same spelling as opview (#136), the explorer (#235) and the CLI (#244).
pub const UNAVAILABLE: &str = "UNAVAILABLE";

pub struct DivScan {
    pub index: u64,
    pub address_short: String,
    pub completeness: Completeness,
    pub spendable_bessel: u128,
    pub shadowed_bessel: u128,
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
            "{UNAVAILABLE} — {detected} output(s) are this key's and only {opened} could be \
             read: something is here that this scan could not read"
        ),
        Completeness::Shadowed { opened, spendable } => format!(
            "shadowed — {} of {opened} opened note(s) are already dead; spendable figures \
             EXCLUDE them",
            opened - spendable
        ),
        Completeness::IncompleteAndShadowed { detected, opened, spendable } => format!(
            "{UNAVAILABLE} + shadowed — {detected} detected / {opened} opened / {spendable} \
             spendable"
        ),
    }
}

/// The whole report, one string. Same three honest states as the CLI: a
/// complete 0 speaks on the chain's authority; an incomplete anything prints
/// the token and **no figure**; a scan that never started is its own verdict.
/// No partial totals, ever.
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
            && matches!(s.completeness, Completeness::Complete | Completeness::Shadowed { .. });
        all_complete &= complete;
        let verdict = match &s.never_started {
            Some(e) => format!("{UNAVAILABLE} — the scan never started: {e}"),
            None => verdict_line(&s.completeness),
        };
        out.push_str(&format!("  [{}] {}\n      verdict:   {verdict}\n", s.index, s.address_short));
        if complete {
            out.push_str(&format!("      spendable: {} bessel\n", s.spendable_bessel));
            if s.shadowed_bessel > 0 {
                out.push_str(&format!(
                    "      shadowed:  {} bessel (unspendable, excluded above)\n",
                    s.shadowed_bessel
                ));
            }
        } else {
            out.push_str(&format!("      spendable: {UNAVAILABLE}\n"));
        }
    }
    out.push('\n');
    if all_complete {
        let total: u128 = scans.iter().map(|s| s.spendable_bessel).sum();
        out.push_str(&format!("TOTAL spendable: {total} bessel\n"));
        if total == 0 {
            out.push_str(
                "(0 under a complete scan means no TRANSACTION paid these addresses in \
                 this range, on the chain's authority. Coinbase is not covered: the \
                 compact wire carries no coinbase_rkm, so a mining wallet reads 0 here \
                 whatever it earned — lab #415)\n",
            );
        }
    } else {
        out.push_str(&format!(
            "TOTAL spendable: {UNAVAILABLE} — at least one address could not be fully read\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn div(idx: u64, c: Completeness, spend: u128) -> DivScan {
        DivScan {
            index: idx,
            address_short: format!("qs1x{idx}"),
            completeness: c,
            spendable_bessel: spend,
            shadowed_bessel: 0,
            never_started: None,
        }
    }

    #[test]
    fn the_three_honest_states_hold_at_this_copy_too() {
        // Complete zero: the chain's authority.
        let r = render(&[div(0, Completeness::Complete, 0)], (0, 8), "u");
        assert!(r.contains("chain's authority") && !r.contains(UNAVAILABLE));
        // Incomplete: token, no figure, no partial total.
        let r = render(
            &[div(0, Completeness::Complete, 777), div(1, Completeness::Incomplete { detected: 2, opened: 0 }, 0)],
            (0, 8),
            "u",
        );
        assert!(r.contains(UNAVAILABLE) && !r.contains("TOTAL spendable: 777"));
        // Never started: its own verdict.
        let mut d = div(0, Completeness::Complete, 55);
        d.never_started = Some("refused".into());
        let r = render(&[d], (0, 8), "u");
        assert!(r.contains("never started: refused") && !r.contains("55"));
    }
}
