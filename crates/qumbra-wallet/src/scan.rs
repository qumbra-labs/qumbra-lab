//! What every caller reads off the chain before it may quote anything — and the
//! rule that binds the two streams together.
//!
//! # Why this is a module and not a function in a binary
//!
//! This loop has now been factored twice, independently, for the same reason.
//! PR #324 pulled it out of `scan` so `history` could not become a second path
//! to the same facts — *"a ledger that could disagree with the balance printed
//! beside it is worse than no ledger."* That argument does not stop at the
//! binary's edge: the desktop shell had **copied** the loop, and the copy
//! diverged three times, each divergence shipping:
//!
//! | divergence | what the copy did |
//! |---|---|
//! | transport | kept `qlab-cbserver`'s plaintext GET, so the shell could not reach the https edge at all |
//! | spent notes | never learned about [`crate::spent`], so it quoted notes the chain had already consumed — lab #314's ghost balance, live in a GUI after the CLI was fixed |
//! | shared types | `DivScan` gained fields and [`crate::view::render`] gained a parameter; the copy stopped compiling entirely |
//!
//! So [`gather`] moves here, unchanged, and the shells become callers like the
//! two commands already were. **A shell may choose its own presentation; it does
//! not get to re-derive what is spendable.**
//!
//! # The rule
//!
//! A balance needs **two** halves: the outputs paid to these keys, and the
//! nullifiers the chain has since consumed. `spendable` is meaningful only where
//! both are known over the same heights. Where the second is missing, callers
//! get [`DivScan::unquotable`] — a named cannot-know — and **never** a number
//! computed from outputs alone. That is the whole of lab #314: the old behaviour
//! was not "slightly stale", it was a confident wrong figure under
//! `verdict: complete`.

use qlab_cbserver::client::{light_client_scan_with, ScanConfig, ScanOutcome};

use crate::net::{scan_fetch, HttpNullifierSource};
use crate::spent::{fetch_spent, subtract_spent, SpentSet};
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

/// Everything a caller reads off the chain: one light-client scan per allocated
/// address, then the nullifier stream over the range those outputs actually came
/// from.
pub struct Gathered {
    pub outcomes: Vec<(u64, String, Result<ScanOutcome, String>)>,
    pub coverage: SpentCoverage,
    pub set: Option<SpentSet>,
}

/// 🔴 **One gatherer, every caller.** `history` is a different rendering of
/// exactly the facts `scan` quotes its balance from, so it must not be a second
/// path to them — a ledger that could disagree with the balance printed beside
/// it is worse than no ledger. The `--to`/`--from` semantics, the never-started
/// verdict, the coverage rule and the fetch order are therefore shared here
/// rather than reimplemented per caller. **The desktop shell is a caller too**,
/// and was the copy that proved the point.
///
/// The nullifier stream is fetched **after** every scan, deliberately: the chain
/// only grows, so a node that advanced mid-scan gives the second fetch MORE
/// coverage than the outputs need, never less. Fetching it first would turn an
/// ordinary block arrival into a spurious `UNAVAILABLE`.
pub fn gather(w: &WalletDir, url: &str, from: u64, to: u64) -> Gathered {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    let wallet = w.wallet();
    // Seed the decoy rng from the OS CSPRNG (StdRng has no direct from-OS
    // constructor at this rand pin; the 32-byte seed carries the entropy).
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    let mut rng = StdRng::from_seed(seed_bytes);

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
        // decision, and taking it is divergence #1 in this module's header.
        let mut fetch = scan_fetch(url);
        let got = light_client_scan_with(&mut fetch, &kp.dk, from, to, ScanConfig::default(), &mut rng)
            .map_err(|e| e.to_string());
        outcomes.push((idx, short, got));
    }

    // ---- 2. The spends, over the range the outputs actually reached. -------
    let outputs = widest_range(
        outcomes.iter().filter_map(|(_, _, o)| o.as_ref().ok()).map(|o| o.stats.compact_range_served),
    );
    let (coverage, set) = match fetch_spent(&HttpNullifierSource::new(url), from, to) {
        Err(e) => (SpentCoverage::Unavailable { why: e.to_string() }, None),
        Ok(set) => match set.covers_outputs(outputs) {
            Err(e) => (SpentCoverage::Unavailable { why: e.to_string() }, None),
            Ok(()) => (SpentCoverage::Covered { range: set.covered }, Some(set)),
        },
    };
    Gathered { outcomes, coverage, set }
}

/// The balance view over [`gather`] — the rows a caller renders with
/// [`crate::view::render`], and the coverage it must print beside them.
///
/// The two are a pair; splitting them is how a figure loses its caveat, which is
/// why they are returned together rather than left for a caller to re-pair.
///
/// This never fails. A scan that could not start is a *row* with a named reason,
/// because the honest report of four addresses where one endpoint hiccupped is
/// three figures and one cannot-know — not an aborted command, and certainly not
/// a zero.
pub fn scan_report(
    w: &WalletDir,
    url: &str,
    from: u64,
    to: u64,
) -> (Vec<DivScan>, SpentCoverage) {
    let wallet = w.wallet();
    let Gathered { outcomes, coverage, set } = gather(w, url, from, to);

    // A figure exists only where BOTH halves do.
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
    /// no pin is the *withholding* arm in `scan_report`. Worth one when a serving
    /// test harness exists.
    #[test]
    fn an_unreachable_endpoint_yields_reasons_and_no_figures() {
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        use rand::Rng;
        let dir = std::env::temp_dir().join("qmb_scan_report_unreachable");
        let _ = std::fs::remove_dir_all(&dir);
        let mut entropy = [0u8; ENTROPY_LEN];
        rand::rng().fill_bytes(&mut entropy);
        let w = WalletDir::create(&dir, MasterSeed::from_entropy(entropy)).expect("create wallet");

        let (scans, coverage) = scan_report(&w, "http://127.0.0.1:1", 0, 8);

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
