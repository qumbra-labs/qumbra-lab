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

use crate::coinbase::MinedReport;
use qlab_ledger::spent::SpentReport;
// The vocabulary moved to qlab-ledger with the ledger it serves; imported back
// so there is exactly one spelling of UNAVAILABLE and one SpentCoverage.
pub use qlab_ledger::vocab::{SpentCoverage, UNAVAILABLE};

/// How far the coinbase stream reached — a report-level fact, like
/// [`SpentCoverage`], because the stream is fetched once for the whole scan and
/// covers every address in it (lab #415).
///
/// 🔴 **This is what decides whether the report may un-narrow PR #420's verdict
/// language.** `Covered` means the scan actually looked at coinbase over the
/// range; `Unavailable` means it did not, and the narrowed claim — *"a complete
/// verdict speaks for transactions"* — stands, with the reason. Anything else
/// would be the original defect wearing a newer costume: a verdict that says it
/// saw everything, printed by a reader that could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoinbaseCoverage {
    /// The chain's coinbase payees are in hand for `range`, so every block in it
    /// has been matched against this wallet's own keys. `None` means the
    /// endpoint held **no** main-chain block in the requested range at all —
    /// a covered state, not a failed one.
    Covered { range: Option<(u64, u64)> },
    /// The stream could not be read or did not reach far enough — carries the
    /// reason, verbatim. The common case is a node older than lab #415, which
    /// answers 404, and that is an honest answer rather than a fault.
    Unavailable { why: String },
}

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

/// The mined section (lab #415) — what this wallet's own `rkm` earned over the
/// scanned range, split spendable vs maturing, or the named reason there is no
/// figure.
///
/// Three states, and the middle one is the one this whole route exists to make
/// expressible:
///
/// - **not looked at** — the endpoint does not serve `/v1/coinbase` (every node
///   older than lab #415) or the stream refused. Named, with the reason, and the
///   verdict language below stays narrowed.
/// - **looked at, nothing found** — a real answer on the chain's authority, and
///   the one a non-mining wallet gets.
/// - **looked at, found** — the figure, plus what is still maturing and the
///   height it changes at.
fn render_mined(
    mined: Option<&MinedReport>,
    coverage: &CoinbaseCoverage,
    range: (u64, u64),
) -> String {
    let mut out = String::new();
    match (mined, coverage) {
        (_, CoinbaseCoverage::Unavailable { .. }) | (None, _) => {
            let why = match coverage {
                CoinbaseCoverage::Unavailable { why } => why.clone(),
                // Covered but no report: the nullifier stream failed, so the
                // mined notes could not be checked for spends either. Saying
                // "coinbase unavailable" without that reason would send a miner
                // to look at the wrong endpoint.
                CoinbaseCoverage::Covered { .. } => {
                    "the coinbase stream was read, but this wallet's spends could not be \
                     subtracted from it (see spent-subtraction above) — a mined balance that \
                     cannot subtract spends counts coins it has already spent"
                        .to_string()
                }
            };
            out.push_str(&format!(
                "mined (coinbase): {UNAVAILABLE} — {why}\n\
                 🔴 This scan did NOT look at coinbase. If this wallet's rkm mines, what it \
                 earned is not in any figure below.\n\n"
            ));
        }
        (Some(m), CoinbaseCoverage::Covered { range: covered }) => {
            match covered {
                Some((a, b)) => out.push_str(&format!(
                    "mined (coinbase): the chain's payees for {a}..={b} are in hand\n"
                )),
                None => out.push_str(&format!(
                    "mined (coinbase): the endpoint holds no block in {}..={} — nothing mined \
                     there, and nothing else was found there either\n",
                    range.0, range.1
                )),
            }
            if m.blocks_mined() == 0 {
                out.push_str(
                    "      no block in this range paid this wallet's rkm, on the chain's \
                     authority\n\n",
                );
                return out;
            }
            out.push_str(&format!(
                "      blocks mined: {} (as of height {})\n      spendable:    {} bessel\n",
                m.blocks_mined(),
                m.as_of,
                m.spendable_value(),
            ));
            if !m.maturing.is_empty() {
                out.push_str(&format!(
                    "      maturing:     {} bessel in {} block(s) — NOT spendable yet; the \
                     first matures when the tip reaches {}\n",
                    m.maturing_value(),
                    m.maturing.len(),
                    // `next_maturity` is `Some` whenever `maturing` is non-empty.
                    m.next_maturity().unwrap_or(0),
                ));
            }
            if !m.spent.is_empty() {
                out.push_str(&format!(
                    "      spent:        {} bessel in {} mined note(s) already spent \
                     (subtracted above)\n",
                    m.spent_value(),
                    m.spent.len(),
                ));
            }
            out.push('\n');
        }
    }
    out
}

/// The whole report. `range` is what was actually scanned — printed because a
/// balance is only ever a claim about a range, and a report that omits its
/// range invites quoting it as a claim about the chain. `spent` says how far the
/// spend-subtraction reached, for the same reason (lab issue #314).
pub fn render(
    scans: &[DivScan],
    range: (u64, u64),
    url: &str,
    spent: &SpentCoverage,
    mined: Option<&MinedReport>,
    coinbase: &CoinbaseCoverage,
) -> String {
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
    // The mined half, stated before the per-address rows because a miner's first
    // question is whether they were paid at all (lab #415).
    out.push_str(&render_mined(mined, coinbase, range));
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
    // 🔴 The un-narrowing rule (lab #415): the total speaks for coinbase ONLY on
    // a scan that actually fetched `/v1/coinbase` over this range and could
    // subtract spends from what it found. Otherwise PR #420's narrowed claim
    // stands, verbatim — a verdict must not widen because a newer binary is
    // running, only because a newer answer was received.
    let mined_quotable =
        mined.is_some() && matches!(coinbase, CoinbaseCoverage::Covered { .. });
    if all_quotable {
        let tx_total: u128 = scans.iter().filter_map(|s| s.spendable_bessel).sum();
        let mined_total = mined.map_or(0, MinedReport::spendable_value);
        let total = if mined_quotable { tx_total + mined_total } else { tx_total };
        out.push_str(&format!("TOTAL spendable: {total} bessel\n"));
        if mined_quotable {
            if mined_total > 0 {
                out.push_str(&format!(
                    "(transactions {tx_total} + mined {mined_total}; maturing coinbase is NOT \
                     included — see the mined line above)\n"
                ));
            }
            if total == 0 {
                out.push_str(
                    "(0 under a complete scan, with the coinbase stream covering the same \
                     range, means nothing was paid to these addresses AND no block in this \
                     range paid their rkm — on the chain's authority)\n",
                );
            }
        } else if total == 0 {
            out.push_str(
                "(0 under a complete scan means no TRANSACTION paid these addresses in \
                 this range, on the chain's authority. Coinbase is not covered: this scan \
                 could not read /v1/coinbase, so a mining wallet reads 0 here whatever it \
                 earned — lab #415)\n",
            );
        } else {
            out.push_str(
                "(TRANSACTIONS ONLY: this scan could not read /v1/coinbase, so anything this \
                 wallet's rkm mined is missing from the figure above — lab #415)\n",
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

    /// The pre-#415 world, and the one every un-rolled node is still in: the
    /// coinbase route could not be read. Every test that predates lab #415 uses
    /// it, which is deliberate — their assertions are about a scan that did NOT
    /// look at coinbase, and PR #420's narrowed language is exactly what such a
    /// scan must still print.
    fn no_coinbase() -> CoinbaseCoverage {
        CoinbaseCoverage::Unavailable {
            why: "the coinbase stream could not be read (non-200 response: HTTP 404)".to_string(),
        }
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
        let r = render(&[d], (0, 8), "http://down", &covered(), None, &no_coinbase());
        assert!(r.contains("never started: connection refused"));
        assert!(r.contains(UNAVAILABLE));
        assert!(!r.contains("999"), "no figure survives a scan that never ran");
    }

    #[test]
    fn a_complete_zero_is_zero_for_transactions_and_says_coinbase_is_outside_it() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (0, 8), "http://x", &covered(), None, &no_coinbase());
        assert!(r.contains("TOTAL spendable: 0 bessel"));
        assert!(r.contains("on the chain's authority"));
        // lab #415: the sentence beside that phrase used to claim the chain's
        // authority over a category the scan cannot see. Locked here because the
        // wording change that fixed it broke NO test — the false claim had never
        // been protected, so nothing would have stopped it coming back.
        assert!(
            r.contains("Coinbase is not covered"),
            "a complete verdict must name coinbase as outside it: {r}"
        );
        assert!(
            !r.contains("means nothing was paid to these addresses"),
            "the unqualified claim must not return: {r}"
        );
        // 🔴 Lab #415 changed what this last assertion can say, and the change
        // is the point. The token now appears exactly once — on the mined line,
        // because this scan could not read `/v1/coinbase` — and nowhere near a
        // per-address figure or the total, which are as quotable as they were.
        assert!(
            r.contains(&format!("mined (coinbase): {UNAVAILABLE}")),
            "a scan that did not look at coinbase says so: {r}"
        );
        assert_eq!(r.matches(UNAVAILABLE).count(), 1, "and only there: {r}");
        assert!(!r.contains("spendable: UNAVAILABLE"), "{r}");
        assert!(!r.contains("TOTAL spendable: UNAVAILABLE"), "{r}");
    }

    // ---- lab #415: the mined half ------------------------------------------

    fn mined_covered() -> CoinbaseCoverage {
        CoinbaseCoverage::Covered { range: Some((0, 8)) }
    }

    fn mined_note(minted_height: u64, value: u64, matured: bool) -> crate::coinbase::MinedNote {
        use qlab_node::{coinbase_leaf_appears_at, CoinbaseMaturity};
        let leaf_at = coinbase_leaf_appears_at(minted_height);
        crate::coinbase::MinedNote {
            minted_height,
            div_index: 0,
            note: qlab_note::note::Note {
                value,
                rkm: [1, 2, 3, 4],
                rho: [5, 6, 7, 8],
                rseed: [9, 9, 9, 9],
            },
            maturity: if matured {
                CoinbaseMaturity::Matured { leaf_at }
            } else {
                CoinbaseMaturity::Immature { leaf_at, blocks_remaining: 7 }
            },
            spent_height: None,
        }
    }

    /// 🔴 **The acceptance shape at the surface a miner reads: a non-zero
    /// figure, the maturity split, and the height the next note matures at.**
    ///
    /// The maturing value is deliberately NOT in the total — it is money this
    /// wallet owns and cannot spend, and folding the two would make the total
    /// wrong in the direction that invites a failed send.
    #[test]
    fn a_mining_wallet_reads_non_zero_with_the_split_and_the_maturity_height() {
        let report = MinedReport {
            spendable: vec![mined_note(1, 3_250_000_000, true)],
            maturing: vec![mined_note(300, 3_250_000_000, false)],
            spent: vec![],
            as_of: 320,
        };
        let r = render(
            &[div(0, Completeness::Complete, 0, 0)],
            (0, 320),
            "https://seed.qumbra.org",
            &SpentCoverage::Covered { range: Some((0, 320)) },
            Some(&report),
            &CoinbaseCoverage::Covered { range: Some((0, 320)) },
        );
        assert!(r.contains("blocks mined: 2 (as of height 320)"), "{r}");
        assert!(r.contains("spendable:    3250000000 bessel"), "{r}");
        assert!(r.contains("maturing:     3250000000 bessel in 1 block(s)"), "{r}");
        assert!(
            r.contains(&format!("tip reaches {}", qlab_node::coinbase_leaf_appears_at(300))),
            "the miner's second question is answered with a height: {r}"
        );
        // 🔴 The figure a mining-only wallet used to read as 0.
        assert!(r.contains("TOTAL spendable: 3250000000 bessel"), "{r}");
        assert!(r.contains("transactions 0 + mined 3250000000"), "{r}");
        assert!(!r.contains("6500000000"), "maturing must NOT be summed into the total: {r}");
        assert!(!r.contains(UNAVAILABLE), "nothing here is unknown: {r}");
    }

    /// 🔴 **The un-narrowing rule: the verdict widens only for a scan that
    /// actually fetched the route.** Same wallet, same zero, two endpoints —
    /// the one that served coinbase may say the chain paid this wallet nothing,
    /// and the one that did not may not.
    #[test]
    fn the_verdict_un_narrows_only_when_coinbase_was_actually_fetched() {
        let none_mined = MinedReport { as_of: 8, ..MinedReport::default() };
        let looked = render(
            &[div(0, Completeness::Complete, 0, 0)],
            (0, 8),
            "http://x",
            &covered(),
            Some(&none_mined),
            &mined_covered(),
        );
        assert!(
            looked.contains("no block in this range paid this wallet's rkm"),
            "a covered scan states the mined half as a fact: {looked}"
        );
        assert!(
            looked.contains("nothing was paid to these addresses AND no block in this range \
                             paid their rkm"),
            "…and the total's claim widens to match: {looked}"
        );
        assert!(!looked.contains(UNAVAILABLE), "{looked}");

        let blind = render(
            &[div(0, Completeness::Complete, 0, 0)],
            (0, 8),
            "http://x",
            &covered(),
            None,
            &no_coinbase(),
        );
        assert!(
            blind.contains("no TRANSACTION paid these addresses"),
            "PR #420's narrowed claim stands when the route was not read: {blind}"
        );
        assert!(blind.contains("could not read /v1/coinbase"), "{blind}");
        assert!(
            !blind.contains("paid their rkm"),
            "the widened claim must not appear on a scan that did not look: {blind}"
        );
    }

    /// A non-zero transaction balance on a scan that could not read the coinbase
    /// route says so **beside the number**, not only in the mined section: the
    /// figure is true and incomplete at the same time, which is exactly the
    /// state PR #420 was filed about.
    #[test]
    fn a_non_zero_total_without_coinbase_is_labelled_transactions_only() {
        let r = render(
            &[div(0, Completeness::Complete, 4_200, 0)],
            (0, 8),
            "http://x",
            &covered(),
            None,
            &no_coinbase(),
        );
        assert!(r.contains("TOTAL spendable: 4200 bessel"), "{r}");
        assert!(r.contains("TRANSACTIONS ONLY"), "{r}");
        assert!(r.contains("lab #415"), "{r}");
    }

    /// Coinbase read, spends not: the mined figure is withheld too, and the
    /// reason points at the stream that actually failed rather than at the one
    /// that worked. A mined balance that cannot subtract spends is lab #314 on
    /// the new category.
    #[test]
    fn a_covered_coinbase_stream_still_quotes_nothing_without_the_spends() {
        let r = render(
            &[DivScan::unquotable(0, "qs1short".into(), Completeness::Complete)],
            (0, 8),
            "http://x",
            &SpentCoverage::Unavailable { why: "the nullifier stream could not be read".into() },
            None,
            &mined_covered(),
        );
        assert!(r.contains(&format!("mined (coinbase): {UNAVAILABLE}")), "{r}");
        assert!(
            r.contains("spends could not be subtracted"),
            "the reason names the stream that failed: {r}"
        );
        assert!(r.contains("TOTAL spendable: UNAVAILABLE"), "{r}");
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
            None,
            &no_coinbase(),
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
            None,
            &no_coinbase(),
        );
        assert!(r.contains("already dead"));
        assert!(r.contains("spendable: 500 bessel"));
        assert!(r.contains("shadowed:  40 bessel"));
        assert!(r.contains("TOTAL spendable: 500"), "shadowed does not block the total");
    }

    #[test]
    fn the_range_is_always_on_the_report() {
        let r = render(&[div(0, Completeness::Complete, 0, 0)], (5, 77), "http://n", &covered(), None, &no_coinbase());
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
        let r = render(&[d], (0, 5940), "http://x", &SpentCoverage::Covered { range: Some((0, 5940)) }, None, &no_coinbase());
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
            None,
            &no_coinbase(),
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
            None,
            &no_coinbase(),
        );
        assert!(r.contains("spendable: UNAVAILABLE"));
        assert!(r.contains("TOTAL spendable: UNAVAILABLE"));
    }
}
