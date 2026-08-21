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

use crate::coinbase::{match_mined, MinedChain, MinedReport};
#[cfg(feature = "net")]
use crate::coinbase::fetch_coinbase;
#[cfg(feature = "net")]
use crate::net::{scan_fetch, HttpCoinbaseSource, HttpNullifierSource};
use crate::spent::{subtract_spent, SpentSet};
use crate::store::WalletDir;
use crate::view::{CoinbaseCoverage, DivScan, SpentCoverage};

/// The union of the height ranges several scans' outputs came from — the range
/// the nullifier stream must cover before any of their figures may be quoted
/// (lab issue #314). `None` when no scan saw a block at all.
// Moved to qlab-ledger (#407) so the FFI asks it the same way; re-exported to
// keep this module's callers and tests unchanged.
pub use qlab_ledger::spent::widest_range;

/// Everything a caller reads off the chain: one light-client scan per allocated
/// address, the coinbase stream, then the nullifier stream over the range those
/// outputs actually came from.
pub struct Gathered {
    pub outcomes: Vec<(u64, String, Result<ScanOutcome, String>)>,
    pub coverage: SpentCoverage,
    pub set: Option<SpentSet>,
    /// How far the coinbase stream reached, or why it could not (lab #415).
    /// **This is what decides whether the report may un-narrow PR #420's
    /// verdict language**: a scan that did not fetch the route has not looked at
    /// coinbase, and must keep saying so.
    pub coinbase_coverage: CoinbaseCoverage,
    /// The per-block coinbase facts, `None` when the route could not be read.
    pub mined: Option<MinedChain>,
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
#[cfg(feature = "net")]
/// `form` is the genesis form of the net `url` serves — it rides the fetched
/// [`MinedChain`] into the coinbase derivation and is what makes the mined
/// figure a note the chain actually committed to (lab #566).
pub fn gather(
    w: &WalletDir,
    url: &str,
    from: u64,
    to: u64,
    form: qlab_devnet::forms::GenesisForm,
) -> Gathered {
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

    // ---- 2. The coinbase, over the same range (lab #415). ------------------
    //
    // Fetched BEFORE the nullifier stream and AFTER the scans, for the reason
    // the ordering comment above gives: the chain only grows, so the spend
    // stream fetched last covers at least what both of the other two reached.
    // A mined note is spendable and can therefore be spent, so its heights must
    // be inside the nullifier coverage exactly as an output's are — which is why
    // the range below folds coinbase in rather than judging it separately.
    let (coinbase_coverage, mined) =
        match fetch_coinbase(&HttpCoinbaseSource::new(url), from, to, form) {
            Err(e) => (CoinbaseCoverage::Unavailable { why: e.to_string() }, None),
            Ok(chain) => (CoinbaseCoverage::Covered { range: chain.covered }, Some(chain)),
        };

    // ---- 3. The spends, over the range the outputs actually reached. -------
    let outputs = widest_range(
        outcomes
            .iter()
            .filter_map(|(_, _, o)| o.as_ref().ok())
            .map(|o| o.stats.compact_range_served)
            .chain(std::iter::once(mined.as_ref().and_then(|m| m.covered))),
    );
    let (coverage, set) = qlab_ledger::spent::coverage_for(
        &HttpNullifierSource::new(url),
        from,
        to,
        outputs,
    );
    Gathered { outcomes, coverage, set, coinbase_coverage, mined }
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
#[cfg(feature = "net")]
pub fn scan_report(
    w: &WalletDir,
    url: &str,
    from: u64,
    to: u64,
    form: qlab_devnet::forms::GenesisForm,
) -> ScanReport {
    let wallet = w.wallet();
    let Gathered { outcomes, coverage, set, coinbase_coverage, mined } =
        gather(w, url, from, to, form);

    // The mined half. A figure exists only where BOTH streams do, exactly as for
    // transaction outputs: a coinbase note can be spent, so one that could not be
    // checked against the nullifier stream is not quotable either (lab #314's
    // rule, applied to the category lab #415 made visible).
    let coinbase = match (&mined, &set) {
        (Some(chain), Some(set)) => Some(match_mined(&wallet, &w.allocated, chain, set)),
        _ => None,
    };

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

    ScanReport { scans, spent: coverage, coinbase, coinbase_coverage }
}

/// Everything [`crate::view::render`] needs, kept together for the reason the
/// figure and its coverage always are: **a number and the caveat that makes it
/// true travel as one value or they get separated.** The coinbase half is a
/// second instance of exactly that pair.
#[cfg(feature = "net")]
pub struct ScanReport {
    /// One row per allocated address — transaction outputs.
    pub scans: Vec<DivScan>,
    /// How far the spend-subtraction reached (lab #314).
    pub spent: SpentCoverage,
    /// This wallet's mined notes, `None` when they could not be established.
    /// `Some` with an empty report is a real answer — "you mined nothing in this
    /// range" — and is exactly what `None` must never be confused with.
    pub coinbase: Option<MinedReport>,
    /// How far the coinbase stream reached, or why it could not (lab #415).
    pub coinbase_coverage: CoinbaseCoverage,
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

        let report =
            scan_report(&w, "http://127.0.0.1:1", 0, 8, qlab_devnet::forms::GenesisForm::V4);
        let (scans, coverage) = (report.scans, report.spent);
        assert!(
            matches!(report.coinbase_coverage, CoinbaseCoverage::Unavailable { .. }),
            "an unreachable endpoint cannot have shown this wallet what it mined either"
        );
        assert!(report.coinbase.is_none(), "and there is no mined figure to print");

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
