//! The scan report — outputs, spends, and the rule that binds them.
//!
//! # Why this module exists, and it is a defect report
//!
//! This loop lived in `qumbra-wallet`'s `main.rs` and was **copied** into the
//! desktop shell, with a note above the copy recording the duplication as a
//! follow-up. The copy then diverged three times, and every divergence was a
//! user-visible defect that no test caught because each half was internally
//! consistent:
//!
//! | divergence | what the copy did |
//! |---|---|
//! | transport | kept `qlab-cbserver`'s plaintext GET, so the shell could not reach the https edge at all (desktop issue #1) |
//! | spent notes | never learned about [`crate::spent`], so it quoted notes the chain had already consumed — lab #314's ghost balance, live in a GUI after the CLI was fixed |
//! | shared types | `DivScan` gained fields and [`crate::view::render`] gained a parameter; the copy stopped compiling entirely |
//!
//! **The follow-up was the fix and nobody had time for it, three times.** So the
//! loop is here now, and the shells call it. A shell that wants a different
//! *presentation* renders [`DivScan`] itself; a shell does not get to re-derive
//! what is spendable.
//!
//! # The rule this module is really about
//!
//! A balance needs **two** halves: the outputs paid to these keys, and the
//! nullifiers the chain has since consumed. `spendable` is only meaningful where
//! both are known over the same heights. Where the second half is missing, this
//! module yields [`DivScan::unquotable`] — a named cannot-know — and **never** a
//! number computed from outputs alone. That is the whole of lab #314: the old
//! behaviour was not "slightly stale", it was a confident wrong figure under
//! `verdict: complete`.

use qlab_cbserver::client::{light_client_scan_with, ScanConfig, ScanOutcome};
use rand::rngs::StdRng;

use crate::net::{scan_fetch, HttpNullifierSource};
use crate::spent::{fetch_spent, subtract_spent};
use crate::store::WalletDir;
use crate::view::{DivScan, SpentCoverage};

/// The union of the height ranges several scans' outputs came from — the range
/// the nullifier stream must cover before any of their figures may be quoted
/// (lab issue #314). `None` when no scan saw a block at all.
pub fn widest_range(
    ranges: impl IntoIterator<Item = Option<(u64, u64)>>,
) -> Option<(u64, u64)> {
    ranges.into_iter().flatten().reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
}

/// Scan every allocated address over `from..=to`, subtract what the chain has
/// spent, and return the per-address rows plus the coverage the caller must
/// print beside them.
///
/// Callers render with [`crate::view::render`], passing the returned coverage —
/// the two are a pair and splitting them is how a figure loses its caveat.
///
/// This never returns `Err`. A scan that could not start is a *row* with a named
/// reason, because the honest report of four addresses where one endpoint hiccup
/// occurred is three figures and one cannot-know — not an aborted command and
/// certainly not a zero.
pub fn scan_report(
    w: &WalletDir,
    url: &str,
    from: u64,
    to: u64,
    rng: &mut StdRng,
) -> (Vec<DivScan>, SpentCoverage) {
    let wallet = w.wallet();

    // ---- 1. The outputs, per allocated address. ----------------------------
    let mut outcomes: Vec<(u64, String, Result<ScanOutcome, String>)> = Vec::new();
    for &idx in &w.allocated {
        let d = wallet.diversifier_at_index(idx);
        let kp = wallet.diversified_keypair(&d);
        let short = wallet.address_at_index(idx).short().encode();
        // `Err` here means the scan NEVER STARTED for this key (compact fetch or
        // decode failed) — render the named cannot-know verdict rather than
        // aborting the whole report or, worse, printing a zero.
        //
        // The fetch is this crate's, so the scan reaches an https edge; the scan
        // FLOW is still qlab-cbserver's, unmodified. Do not "simplify" this to
        // `light_client_scan` — that wrapper's own fetch is plaintext-only by
        // decision, and taking it is exactly divergence #1 in this module's
        // header.
        let mut fetch = scan_fetch(url);
        let got = light_client_scan_with(&mut fetch, &kp.dk, from, to, ScanConfig::default(), rng)
            .map_err(|e| e.to_string());
        outcomes.push((idx, short, got));
    }

    // ---- 2. The spends, over the range the outputs actually reached. -------
    let outputs =
        widest_range(outcomes.iter().filter_map(|(_, _, o)| o.as_ref().ok()).map(|o| {
            o.stats.compact_range_served
        }));
    let (coverage, set) = match fetch_spent(&HttpNullifierSource::new(url), from, to) {
        Err(e) => (SpentCoverage::Unavailable { why: e.to_string() }, None),
        Ok(set) => match set.covers_outputs(outputs) {
            Err(e) => (SpentCoverage::Unavailable { why: e.to_string() }, None),
            Ok(()) => (SpentCoverage::Covered { range: set.covered }, Some(set)),
        },
    };

    // ---- 3. The report. A figure exists only where both halves do. ---------
    let scans: Vec<DivScan> = outcomes
        .into_iter()
        .map(|(idx, short, got)| match (got, &set) {
            (Ok(outcome), Some(set)) => {
                let report = subtract_spent(&wallet, idx, &outcome.notes, set);
                DivScan::from_subtracted(idx, short, &outcome, &report)
            }
            (Ok(outcome), None) => DivScan::unquotable(idx, short, outcome.completeness()),
            (Err(e), _) => {
                let mut d = DivScan::unquotable(
                    idx,
                    short,
                    qlab_cbserver::client::Completeness::Complete,
                );
                d.never_started = Some(e);
                d
            }
        })
        .collect();

    (scans, coverage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widest_range_is_the_union_and_none_survives_nothing_seen() {
        assert_eq!(widest_range([None, None]), None);
        assert_eq!(widest_range([Some((5, 9)), None]), Some((5, 9)));
        assert_eq!(widest_range([Some((5, 9)), Some((2, 7))]), Some((2, 9)));
        assert_eq!(widest_range([Some((0, 0)), Some((100, 100))]), Some((0, 100)));
    }

    /// An unreachable endpoint must produce rows that carry a REASON, an
    /// `Unavailable` coverage, and **no figure anywhere** — never a zero that a
    /// caller could print beside `complete`.
    ///
    /// 🔴 **What this does NOT cover, said plainly so nobody reads it as more
    /// than it is.** A dead endpoint fails BOTH halves, so this exercises the
    /// `(Err, _)` arm — "the scan never started". Lab #314's actual shape is the
    /// `(Ok, None)` arm: outputs read fine, the nullifier stream did not, and the
    /// figure must still be withheld. Reaching that arm needs an endpoint that
    /// serves `/v1/compact` and fails `/v1/nullifiers`, i.e. a test HTTP server
    /// this repo does not otherwise have. The subtraction seam itself is
    /// exercised by `tests/spent_subtraction.rs` and by the first-spend e2e
    /// (`a_spent_note_stops_being_spendable_and_the_recipient_gains`); what has
    /// no pin is the *withholding* arm in this function. Worth one when a
    /// serving test harness exists.
    #[test]
    fn an_unreachable_endpoint_yields_reasons_and_no_figures() {
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        use rand::{Rng, SeedableRng};
        let dir = std::env::temp_dir().join("qmb_scan_report_unreachable");
        let _ = std::fs::remove_dir_all(&dir);
        let mut entropy = [0u8; ENTROPY_LEN];
        rand::rng().fill_bytes(&mut entropy);
        let w = WalletDir::create(&dir, MasterSeed::from_entropy(entropy)).expect("create wallet");

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let (scans, coverage) = scan_report(&w, "http://127.0.0.1:1", 0, 8, &mut rng);

        assert!(!scans.is_empty(), "a fresh wallet has address 0 allocated");
        assert!(
            matches!(coverage, SpentCoverage::Unavailable { .. }),
            "no nullifier stream means coverage cannot be claimed"
        );
        for s in &scans {
            assert!(s.never_started.is_some(), "every row names why it could not know");
            // `None` IS the absence of a figure — the field's own doc says the
            // renderer prints UNAVAILABLE for it. A `Some(0)` here would be the
            // #314 defect wearing its original costume.
            assert!(s.spendable_bessel.is_none(), "no figure may exist without both halves");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
