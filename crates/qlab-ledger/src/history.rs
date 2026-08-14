//! `history` — this wallet's own transaction ledger, derived from the chain.
//!
//! # Why this is a wallet view and not an explorer one
//!
//! The chain publishes commitments, nullifiers and ciphertexts. Only the party
//! holding the keys can say which of those are *theirs*, what they are worth,
//! and which ones it spent. The explorer deliberately never grows this surface
//! (design ruling on the three-layer model, 2026-08-10); the wallet is the only
//! place the question is answerable at all.
//!
//! # The derivation boundary, which this module exists to keep visible
//!
//! **Chain-derived** — trustless, and it works for all history including
//! everything that happened before this binary existed:
//!
//! - **received**: every note the scan detected and opened, at the height it
//!   was mined, for the address index it was paid to.
//! - **spent**: every one of this wallet's notes whose nullifier is on-chain,
//!   at the height of the block whose nullifier list carries it
//!   ([`crate::spent::SpentSet::height_of`], off the #314/#315 stream).
//! - **send events, reconstructed**: spent notes at height H grouped with the
//!   notes this wallet received at the same H ⇒
//!   `outgoing = inputs − change − posted_fee(bucket)`. The fee is public and is
//!   read from the posted table ([`qlab_devnet::fees::posted_fee`]), never
//!   stored.
//!
//! What the chain can **never** yield is the recipient — a transaction's
//! outputs are addressed to keys the sender does not hold, which is the privacy
//! property working. Chain-only send events render `recipient: not recorded`.
//!
//! **Locally recorded** — optional, clearly labeled, never trustless:
//! [`crate::sends::SendLog`] joins in the recipient this wallet typed at send
//! time, rendered as `recipient: … (local record)`. **The label IS the honesty
//! boundary**, and a wallet without the file (every wallet restored from a
//! mnemonic) degrades to chain-only cleanly.
//!
//! # Two inferences this module makes, and states in its own output
//!
//! 1. **Change is same-height co-occurrence.** A note this wallet received in
//!    the same block it spent in is read as that spend's change. The chain
//!    cannot distinguish it from somebody paying this wallet in that same
//!    block, so the ledger says so on the event rather than presenting the
//!    grouping as a fact.
//! 2. **Change is folded into its send, not listed as a receipt.** Change is
//!    this wallet's own money coming back; counting it as income would inflate
//!    `total in` and break the ledger's arithmetic. Folded in, the summary
//!    closes exactly: `total in − total out − fees = current spendable` for a
//!    wallet whose whole life is in range.
//!
//! # UNAVAILABLE discipline, identical to `scan`'s
//!
//! A range whose payloads or nullifiers could not be read leaves the ledger
//! unaccounted, and an unaccounted ledger prints **no totals** — the heights it
//! could not account for are named instead. Nothing here presents a partial
//! ledger as a complete one; that failure mode is what lab issue #314 cost, and
//! the vocabulary and the `UNAVAILABLE` token are the same three surfaces'
//! (opview #136, explorer #235, wallet `scan`).

use qlab_cbserver::client::{Completeness, ScanOutcome};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_wallet::Wallet;

use crate::sends::{SendLog, SendRecord};
use crate::spent::{subtract_spent, SpentSet};
use crate::vocab::{SpentCoverage, UNAVAILABLE};

/// One address's scan, as the CLI hands it over: `Err` means the scan never
/// started for that key (the compact fetch or decode failed), which is a named
/// verdict of its own and never an empty result.
pub struct AddressScan {
    pub div_index: u64,
    pub address_short: String,
    pub outcome: Result<ScanOutcome, String>,
}

/// A note this wallet received, as the ledger names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub height: u64,
    pub value: u64,
    pub div_index: u64,
    pub address_short: String,
    /// Opened and authenticated, but another note already claims its nullifier
    /// so it can never be spent (issue #215). Reported, never summed.
    pub shadowed: bool,
}

/// One of a send's inputs: a note this wallet owned whose nullifier the chain
/// published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentInput {
    /// The height the note was **received** at.
    pub received_height: u64,
    pub value: u64,
    pub div_index: u64,
}

/// What left the wallet in a send event — three states, because two of them are
/// honest answers that are not a number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outgoing {
    /// `inputs − change − posted_fee`, with the fee attributed.
    Exact { amount: u128, fee: u64 },
    /// No change came back at this height, so the amount and the posted fee
    /// cannot be separated inside the value that left. Their **sum** is exact.
    FeeInseparable { amount_and_fee: u128 },
    /// The group cannot be read as one transaction. No number is produced and
    /// the summary refuses its totals — guessing a transaction count would
    /// guess the fee multiple with it.
    Unavailable { why: String },
}

/// A send, reconstructed from same-height co-occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendEvent {
    /// The height whose nullifier list carries the inputs — the chain's own
    /// date for this spend.
    pub height: u64,
    pub inputs: Vec<SpentInput>,
    pub inputs_total: u128,
    /// Notes received at the same height, read as this send's change.
    pub change: Vec<Received>,
    pub change_total: u128,
    pub outgoing: Outgoing,
    /// The local `sends.v1` record this event joined to, if there is one. The
    /// ONLY non-chain field in the ledger.
    pub local: Option<SendRecord>,
    /// More than one local record claimed this event — recorded rather than
    /// silently picking one.
    pub ambiguous_local: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Received(Received),
    Send(SendEvent),
}

impl Event {
    pub fn height(&self) -> u64 {
        match self {
            Event::Received(r) => r.height,
            Event::Send(s) => s.height,
        }
    }
}

/// The totals, which exist **only** for a fully accounted ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totals {
    /// Received, excluding change (change is folded into its send event).
    pub total_in: u128,
    /// What left the wallet. For events whose fee could not be separated this
    /// includes that fee — `fee_inseparable_events` says how many.
    pub total_out: u128,
    /// Fees this ledger could attribute.
    pub fees_paid: u128,
    /// Send events whose fee is inside `total_out` rather than in `fees_paid`.
    pub fee_inseparable_events: usize,
}

/// The ledger.
pub struct Ledger {
    /// The heights that were asked for.
    pub range: (u64, u64),
    /// The heights the compact stream actually served, across every address —
    /// a server holds what it holds, and a ledger is a claim about a range.
    pub outputs_served: Option<(u64, u64)>,
    pub events: Vec<Event>,
    pub coverage: SpentCoverage,
    /// Per-address verdicts, in the same vocabulary `scan` renders.
    pub verdicts: Vec<(u64, String, Completeness, Option<String>)>,
    /// 🔴 What this ledger could NOT account for, each with its reason. Empty
    /// is the only state in which totals exist.
    pub gaps: Vec<String>,
    pub totals: Option<Totals>,
    /// `scan`'s own subtracted figure, reused — `None` when it is not quotable.
    pub current_spendable: Option<u128>,
    /// Detected, opened, and unspendable — never in any total above.
    pub shadowed_total: u128,
    /// Local records that joined to no event in this range. They may have
    /// landed outside it, or never landed at all; either way an unjoined record
    /// is stated rather than left to look like a send that never happened.
    pub unmatched_records: usize,
}

/// Build the ledger.
///
/// `set` is the chain's nullifiers with their heights; it is `None` exactly
/// when `coverage` is [`SpentCoverage::Unavailable`], and in that case **no
/// send event can be derived at all** — a wallet that cannot read the nullifier
/// stream does not know which of its notes are gone.
pub fn build(
    wallet: &Wallet,
    scans: &[AddressScan],
    set: Option<&SpentSet>,
    coverage: &SpentCoverage,
    log: Option<&SendLog>,
    range: (u64, u64),
) -> Ledger {
    let mut received: Vec<Received> = Vec::new();
    let mut spent: Vec<(u64, SpentInput, [u8; 32])> = Vec::new(); // (spent_height, input, nf)
    let mut verdicts = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    let mut outputs_served: Option<(u64, u64)> = None;
    let mut shadowed_total: u128 = 0;
    let mut spendable_total: u128 = 0;
    let mut spendable_quotable = set.is_some();

    for scan in scans {
        let outcome = match &scan.outcome {
            Ok(o) => o,
            Err(why) => {
                verdicts.push((
                    scan.div_index,
                    scan.address_short.clone(),
                    Completeness::Complete,
                    Some(why.clone()),
                ));
                gaps.push(format!(
                    "outputs for address [{}] over heights {}..={}: the scan never started ({why})",
                    scan.div_index, range.0, range.1
                ));
                spendable_quotable = false;
                continue;
            }
        };
        let completeness = outcome.completeness();
        verdicts.push((scan.div_index, scan.address_short.clone(), completeness, None));
        match &completeness {
            Completeness::Complete | Completeness::Shadowed { .. } => {}
            Completeness::Incomplete { detected, opened }
            | Completeness::IncompleteAndShadowed { detected, opened, .. } => {
                gaps.push(format!(
                    "outputs for address [{}]: {detected} output(s) are this key's by the \
                     committed discovery and only {opened} could be read, so some of this \
                     address's events over {}..={} are missing from the ledger below",
                    scan.div_index, range.0, range.1
                ));
                spendable_quotable = false;
            }
        }
        if let Some(served) = outcome.stats.compact_range_served {
            outputs_served = Some(match outputs_served {
                Some((a, b)) => (a.min(served.0), b.max(served.1)),
                None => served,
            });
        }

        for note in &outcome.notes {
            received.push(Received {
                height: note.height,
                value: note.detected.note.value,
                div_index: scan.div_index,
                address_short: scan.address_short.clone(),
                shadowed: false,
            });
        }
        for dead in &outcome.shadowed {
            shadowed_total += u128::from(dead.note.detected.note.value);
            received.push(Received {
                height: dead.note.height,
                value: dead.note.detected.note.value,
                div_index: scan.div_index,
                address_short: scan.address_short.clone(),
                shadowed: true,
            });
        }

        // The spends, on the SAME subtraction the balance runs — imported, not
        // a second reading of the same idea.
        if let Some(set) = set {
            let report = subtract_spent(wallet, scan.div_index, &outcome.notes, set);
            spendable_total += report.spendable_value();
            for s in &report.spent {
                spent.push((
                    s.spent_height,
                    SpentInput {
                        received_height: s.note.height,
                        value: s.note.detected.note.value,
                        div_index: scan.div_index,
                    },
                    s.nullifier,
                ));
            }
        }
    }

    if let SpentCoverage::Unavailable { why } = coverage {
        gaps.push(format!(
            "spends over heights {}..={}: {why} — no send event can be derived without the \
             chain's nullifiers, so this ledger shows receipts only",
            range.0, range.1
        ));
    }

    // ---- group the spends into send events, by height ----------------------
    let mut heights: Vec<u64> = spent.iter().map(|(h, _, _)| *h).collect();
    heights.sort_unstable();
    heights.dedup();

    let mut events: Vec<Event> = Vec::new();
    let mut change_keys: Vec<(u64, u64, u64)> = Vec::new(); // (height, div_index, value)
    let mut unmatched = log.map_or(0, |l| l.records.len());

    for h in heights {
        let mut inputs: Vec<SpentInput> = Vec::new();
        let mut nfs: Vec<[u8; 32]> = Vec::new();
        for (sh, input, nf) in &spent {
            if *sh == h {
                inputs.push(input.clone());
                nfs.push(*nf);
            }
        }
        // Change candidates: this wallet's spendable-list notes at the same
        // height. Shadowed notes are deliberately NOT candidates — see below.
        let change: Vec<Received> =
            received.iter().filter(|r| r.height == h && !r.shadowed).cloned().collect();
        let shadowed_here = received.iter().any(|r| r.height == h && r.shadowed);

        let inputs_total: u128 = inputs.iter().map(|i| u128::from(i.value)).sum();
        let change_total: u128 = change.iter().map(|c| u128::from(c.value)).sum();
        let fee = posted_fee(ArityBucket::TwoByTwo);

        let outgoing = if shadowed_here {
            Outgoing::Unavailable {
                why: format!(
                    "a shadowed output sits at height {h}; the chain cannot say whether it was \
                     this send's change or a payment in, so the amount that left is not derivable"
                ),
            }
        } else if inputs.len() > 2 || change.len() > 1 {
            Outgoing::Unavailable {
                why: format!(
                    "height {h} carries {} of this wallet's spent note(s) and {} note(s) back — \
                     more than the frozen 2×2 bucket moves in one transaction, so this is more \
                     than one send and the chain cannot separate them (the fee multiple is not \
                     derivable either)",
                    inputs.len(),
                    change.len()
                ),
            }
        } else if change.is_empty() {
            Outgoing::FeeInseparable { amount_and_fee: inputs_total }
        } else if inputs_total < change_total + u128::from(fee) {
            Outgoing::Unavailable {
                why: format!(
                    "at height {h} this wallet spent {inputs_total} bessel and received \
                     {change_total} back, which the posted fee of {fee} cannot reconcile — the \
                     note(s) received here are not this send's change"
                ),
            }
        } else {
            Outgoing::Exact { amount: inputs_total - change_total - u128::from(fee), fee }
        };

        // Only a group that reconciles has its receipts folded in as change; an
        // unreadable group leaves them where they are, as receipts, so nothing
        // disappears from the ledger on the strength of a failed inference.
        let folded = matches!(outgoing, Outgoing::Exact { .. });
        if folded {
            for c in &change {
                change_keys.push((c.height, c.div_index, c.value));
            }
        }

        let matches = log.map(|l| l.matching(&nfs)).unwrap_or_default();
        if !matches.is_empty() {
            unmatched -= matches.len();
        }
        events.push(Event::Send(SendEvent {
            height: h,
            inputs,
            inputs_total,
            change: if folded { change.clone() } else { Vec::new() },
            change_total: if folded { change_total } else { 0 },
            outgoing,
            local: matches.first().map(|r| (*r).clone()),
            ambiguous_local: matches.len() > 1,
        }));
    }

    // ---- the receipts that are not change ----------------------------------
    for r in &received {
        let mut key = Some((r.height, r.div_index, r.value));
        if let Some(pos) = change_keys.iter().position(|k| Some(*k) == key) {
            change_keys.remove(pos); // one receipt folded per change note
            key = None;
        }
        if key.is_some() {
            events.push(Event::Received(r.clone()));
        }
    }

    // Chronological. Ties: receipts before sends (a send's own change is
    // already folded in, so a receipt at a send height is somebody else's
    // payment), then by address index and value — deterministic, so two runs
    // over the same chain render identically.
    events.sort_by_key(|e| match e {
        Event::Received(r) => (r.height, 0u8, r.div_index, u128::from(r.value)),
        Event::Send(s) => (s.height, 1u8, 0, s.inputs_total),
    });

    for e in &events {
        if let Event::Send(s) = e {
            if let Outgoing::Unavailable { why } = &s.outgoing {
                gaps.push(format!("the send at height {}: {why}", s.height));
            }
        }
    }

    let totals = if gaps.is_empty() {
        let mut total_out: u128 = 0;
        let mut fees_paid: u128 = 0;
        let mut inseparable = 0usize;
        for e in &events {
            if let Event::Send(s) = e {
                match &s.outgoing {
                    Outgoing::Exact { amount, fee } => {
                        total_out += amount;
                        fees_paid += u128::from(*fee);
                    }
                    Outgoing::FeeInseparable { amount_and_fee } => {
                        total_out += amount_and_fee;
                        inseparable += 1;
                    }
                    Outgoing::Unavailable { .. } => unreachable!("gaps would not be empty"),
                }
            }
        }
        let total_in: u128 = events
            .iter()
            .filter_map(|e| match e {
                Event::Received(r) if !r.shadowed => Some(u128::from(r.value)),
                _ => None,
            })
            .sum();
        Some(Totals { total_in, total_out, fees_paid, fee_inseparable_events: inseparable })
    } else {
        None
    };

    Ledger {
        range,
        outputs_served,
        events,
        coverage: coverage.clone(),
        verdicts,
        gaps,
        totals,
        current_spendable: if spendable_quotable { Some(spendable_total) } else { None },
        shadowed_total,
        unmatched_records: unmatched,
    }
}

fn verdict_line(c: &Completeness, never_started: &Option<String>) -> String {
    if let Some(why) = never_started {
        return format!("{UNAVAILABLE} — the scan never started: {why}");
    }
    match c {
        Completeness::Complete => "complete".to_string(),
        Completeness::Incomplete { detected, opened } => format!(
            "{UNAVAILABLE} — {detected} output(s) are this key's by the committed discovery and \
             only {opened} could be read"
        ),
        Completeness::Shadowed { opened, spendable } => format!(
            "shadowed — {} of {opened} opened note(s) are already dead (another note claims their \
             nullifier)",
            opened - spendable
        ),
        Completeness::IncompleteAndShadowed { detected, opened, spendable } => format!(
            "{UNAVAILABLE} + shadowed — {detected} detected / {opened} opened / {spendable} \
             spendable"
        ),
    }
}

/// Render the ledger a person reads: chronological, heights first, one event
/// per block of lines, and a summary footer that exists only when the ledger is
/// fully accounted.
pub fn render(ledger: &Ledger, url: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "history of {} address(es) against {url}, heights {}..={}\n",
        ledger.verdicts.len(),
        ledger.range.0,
        ledger.range.1
    ));
    match ledger.outputs_served {
        Some((a, b)) => out.push_str(&format!("outputs served: heights {a}..={b}\n")),
        None => out.push_str("outputs served: no block at all in this range\n"),
    }
    match &ledger.coverage {
        SpentCoverage::Covered { range: Some((a, b)) } => {
            out.push_str(&format!("spent-subtraction: the chain's nullifiers for {a}..={b} are in hand\n"))
        }
        SpentCoverage::Covered { range: None } => out.push_str(
            "spent-subtraction: the endpoint holds no block in this range — nothing to subtract\n",
        ),
        SpentCoverage::Unavailable { why } => out.push_str(&format!(
            "spent-subtraction: {UNAVAILABLE} — {why}\n"
        )),
    }
    for (idx, short, completeness, never) in &ledger.verdicts {
        out.push_str(&format!(
            "  [{idx}] {short}: {}\n",
            verdict_line(completeness, never)
        ));
    }
    out.push('\n');

    if ledger.events.is_empty() {
        out.push_str("no events: this wallet neither received nor spent anything in this range\n");
    }
    for event in &ledger.events {
        match event {
            Event::Received(r) => {
                out.push_str(&format!("height {}  RECEIVED\n", r.height));
                out.push_str(&format!("    value:     {} bessel\n", r.value));
                out.push_str(&format!("    address:   [{}] {}\n", r.div_index, r.address_short));
                if r.shadowed {
                    out.push_str(
                        "    shadowed:  another note already claims this one's nullifier — it can \
                         never be spent, and it is in no total below\n",
                    );
                }
            }
            Event::Send(s) => {
                out.push_str(&format!("height {}  SEND\n", s.height));
                for i in &s.inputs {
                    out.push_str(&format!(
                        "    input:     {} bessel (the note received at height {}, address [{}])\n",
                        i.value, i.received_height, i.div_index
                    ));
                }
                out.push_str(&format!("    inputs:    {} bessel total\n", s.inputs_total));
                if s.change.is_empty() {
                    out.push_str(
                        "    change:    none at this height — the whole input value left this \
                         wallet\n",
                    );
                } else {
                    out.push_str(&format!(
                        "    change:    {} bessel back to this wallet (inferred: {} note(s) \
                         received in this same block)\n",
                        s.change_total,
                        s.change.len()
                    ));
                }
                match &s.outgoing {
                    Outgoing::Exact { amount, fee } => {
                        out.push_str(&format!("    fee:       {fee} bessel (posted, 2×2 bucket)\n"));
                        out.push_str(&format!("    out:       {amount} bessel\n"));
                    }
                    Outgoing::FeeInseparable { amount_and_fee } => {
                        out.push_str(&format!(
                            "    out:       {amount_and_fee} bessel — amount AND fee together; \
                             with no change at this height the posted fee cannot be attributed \
                             inside it\n"
                        ));
                    }
                    Outgoing::Unavailable { why } => {
                        out.push_str(&format!("    out:       {UNAVAILABLE} — {why}\n"));
                    }
                }
                match (&s.local, s.ambiguous_local) {
                    (Some(r), false) => {
                        out.push_str(&format!(
                            "    recipient: {} (local record)\n",
                            r.recipient_short
                        ));
                        out.push_str(&format!(
                            "    tx:        {} (local record, submitted at node tip {})\n",
                            crate::sends::hex32(&r.txid),
                            r.submitted_at_tip
                        ));
                    }
                    (Some(r), true) => {
                        out.push_str(&format!(
                            "    recipient: {} (local record — 🔴 MORE THAN ONE local record \
                             claims this event; the others are not shown)\n",
                            r.recipient_short
                        ));
                    }
                    (None, _) => {
                        out.push_str(
                            "    recipient: not recorded — the chain does not carry it (the \
                             outputs are addressed to keys this wallet does not hold), and there \
                             is no local sends.v1 record for this event. A wallet restored from a \
                             mnemonic never has one.\n",
                        );
                    }
                }
            }
        }
        out.push('\n');
    }

    out.push_str("SUMMARY\n");
    match &ledger.totals {
        Some(t) => {
            out.push_str(&format!(
                "  total in:          {} bessel (change excluded — it is folded into its send)\n",
                t.total_in
            ));
            out.push_str(&format!("  total out:         {} bessel", t.total_out));
            if t.fee_inseparable_events > 0 {
                out.push_str(&format!(
                    " (includes the fee of {} event(s) with no change, where the two are not \
                     separable)",
                    t.fee_inseparable_events
                ));
            }
            out.push('\n');
            out.push_str(&format!("  fees paid:         {} bessel", t.fees_paid));
            if t.fee_inseparable_events > 0 {
                out.push_str(&format!(
                    " (excludes {} event(s) counted in `total out` above)",
                    t.fee_inseparable_events
                ));
            }
            out.push('\n');
        }
        None => {
            out.push_str(&format!(
                "  total in:          {UNAVAILABLE}\n  total out:         {UNAVAILABLE}\n  \
                 fees paid:         {UNAVAILABLE}\n"
            ));
        }
    }
    match ledger.current_spendable {
        Some(v) => out.push_str(&format!("  current spendable: {v} bessel\n")),
        None => out.push_str(&format!("  current spendable: {UNAVAILABLE}\n")),
    }
    if ledger.shadowed_total > 0 {
        out.push_str(&format!(
            "  shadowed:          {} bessel — detected, opened, unspendable; in no total above\n",
            ledger.shadowed_total
        ));
    }
    if ledger.unmatched_records > 0 {
        out.push_str(&format!(
            "  local records:     {} recorded send(s) joined no event in this range — they may \
             have landed outside it, or never landed\n",
            ledger.unmatched_records
        ));
    }
    if !ledger.gaps.is_empty() {
        out.push_str(&format!(
            "\n🔴 {UNAVAILABLE}: this ledger is NOT complete, so no totals are printed above. \
             What it could not account for:\n"
        ));
        for gap in &ledger.gaps {
            out.push_str(&format!("  - {gap}\n"));
        }
    }
    out
}

/// A rendered ledger plus the caveats a caller must show beside it.
///
/// The notes are **data, not output**, because the two callers place them
/// differently — the CLI writes them to stderr, a GUI has no stderr and must put
/// them in the panel. Returning them as strings is what lets one flow serve
/// both without either re-deriving the ledger.
pub struct HistoryReport {
    /// The ledger, already rendered.
    pub text: String,
    /// 🔴 **Show these.** Each one names a reason a `recipient:` line below reads
    /// `not recorded`. Dropping them turns "this wallet has no local record of
    /// who it paid" into an unexplained blank, which is the same class of lie as
    /// a balance quoted without its coverage.
    pub notes: Vec<String>,
}

/// The structured result of the history flow, before any terminal-oriented
/// rendering. Native clients consume this so they can build accessible views
/// without parsing [`HistoryReport::text`]. All accounting and `UNAVAILABLE`
/// decisions remain in this crate.
pub struct HistoryData {
    pub ledger: Ledger,
    pub notes: Vec<String>,
}

/// The whole `history` flow: the local send log if there is one, the two chain
/// streams via [`crate::scan::gather`], and the rendered ledger.
///
/// 🔴 **One flow, every caller — the same rule [`crate::scan`] exists for.** This
/// was ~20 lines in the CLI, and a shell that wanted the ledger would have had
/// to copy them. That copy has been made before, three times, and each time it
/// diverged on the axis nobody was watching (transport, then spent-note
/// subtraction, then the shared types). The ledger is a worse thing to diverge
/// than the balance: it is the wallet's account of its own past, and two of them
/// disagreeing is not a stale number but a contradiction.
///
/// The local record is **optional enrichment and must never stop a chain-derived
/// ledger from rendering** — an unreadable file becomes a note and the ledger
/// continues, chain-only.
#[cfg(feature = "net")]
pub fn report(
    dir: &std::path::Path,
    w: &crate::store::WalletDir,
    url: &str,
    from: u64,
    to: u64,
) -> HistoryReport {
    let data = report_data(dir, w, url, from, to);
    HistoryReport { text: render(&data.ledger, url), notes: data.notes }
}

/// Run the same history flow as [`report`], returning its typed ledger.
#[cfg(feature = "net")]
pub fn report_data(
    dir: &std::path::Path,
    w: &crate::store::WalletDir,
    url: &str,
    from: u64,
    to: u64,
) -> HistoryData {
    use crate::sends::{SendLog, SENDS_FILE};

    let wallet = w.wallet();
    let mut notes: Vec<String> = Vec::new();

    let log = match SendLog::load(dir) {
        Ok(log) => log,
        Err(e) => {
            notes.push(format!(
                "{e} — the ledger below is chain-only, so every `recipient:` line reads \
                 `not recorded`."
            ));
            None
        }
    };
    if log.is_none() {
        notes.push(format!(
            "no {SENDS_FILE} in this wallet dir, so recipients are not shown. That file is \
             written by `send` on this machine and is NEVER recoverable from a mnemonic; \
             everything else below comes from the chain."
        ));
    }

    let crate::scan::Gathered { outcomes, coverage, set } = crate::scan::gather(w, url, from, to);
    let scans: Vec<AddressScan> = outcomes
        .into_iter()
        .map(|(div_index, address_short, outcome)| AddressScan { div_index, address_short, outcome })
        .collect();
    let ledger = build(&wallet, &scans, set.as_ref(), &coverage, log.as_ref(), (from, to));
    HistoryData { ledger, notes }
}

#[cfg(test)]
mod tests {
    /// The local send log is optional enrichment; its absence is a NOTE, never a
    /// missing ledger and never a silent blank.
    ///
    /// A restored wallet never has a `sends.v1` — it is written by `send` on one
    /// machine and is not recoverable from a mnemonic — so this is the ordinary
    /// state for anyone who moved wallets, not an edge case. The endpoint here is
    /// dead as well, which is the harsher combination: no local record AND no
    /// chain. Both facts must reach the caller.
    #[test]
    fn a_wallet_with_no_send_log_gets_a_note_and_still_gets_a_ledger() {
        use crate::store::WalletDir;
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        use rand::Rng;

        let dir = std::env::temp_dir().join("qmb_history_report_no_log");
        let _ = std::fs::remove_dir_all(&dir);
        let mut entropy = [0u8; ENTROPY_LEN];
        rand::rng().fill_bytes(&mut entropy);
        let w = WalletDir::create(&dir, MasterSeed::from_entropy(entropy)).expect("create wallet");

        let out = super::report(&dir, &w, "http://127.0.0.1:1", 0, 8);

        assert!(
            out.notes.iter().any(|n| n.contains(crate::sends::SENDS_FILE)),
            "the absent local record must be NAMED: {:?}",
            out.notes
        );
        assert!(!out.text.is_empty(), "a chain-only ledger still renders");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;
    use qlab_cbserver::client::{LocatedNote, ScanStats, ShadowedNote, UnopenedOutput};
    use qlab_note::note::Note;
    use qlab_note::scan::DetectedNote;
    use qlab_wallet::seed::MasterSeed;

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([0x51; 32]), 0)
    }

    /// A note this wallet owns at `div_index`, received at `height`.
    fn note(w: &Wallet, div_index: u64, value: u64, tag: u64) -> Note {
        Note {
            value,
            rkm: w.rkm(w.diversifier_at_index(div_index)),
            rho: [tag, tag + 1, tag + 2, tag + 3],
            rseed: [tag + 9, tag + 8, tag + 7, tag + 6],
        }
    }

    fn located(n: &Note, height: u64) -> LocatedNote {
        LocatedNote {
            height,
            tx_index: 0,
            recipient_index: 0,
            cm: qlab_note::hash::digest_bytes(&n.commitment()),
            detected: DetectedNote { index: 0, note: *n },
        }
    }

    fn outcome(notes: Vec<LocatedNote>, served: (u64, u64)) -> ScanOutcome {
        let n = notes.len();
        ScanOutcome {
            notes,
            unopened: Vec::new(),
            shadowed: Vec::new(),
            stats: ScanStats {
                compact_bytes: 0,
                compact_range_served: Some(served),
                detected_outputs: n,
                matched_fetches: n,
                decoy_fetches: 0,
                notes_found: n,
                shadowed_outputs: 0,
            },
        }
    }

    fn scan_of(w: &Wallet, idx: u64, o: ScanOutcome) -> AddressScan {
        AddressScan {
            div_index: idx,
            address_short: w.address_at_index(idx).short().encode(),
            outcome: Ok(o),
        }
    }

    fn covered(range: (u64, u64)) -> SpentCoverage {
        SpentCoverage::Covered { range: Some(range) }
    }

    const FEE: u64 = 1_000_000;

    /// 🔴 **The whole story, in the shape the first user journey produced it**:
    /// 10 QMB received at height 4, then a send at height 9 that spends it, pays
    /// 1 QMB out and brings 8.99 QMB of change home. Exactly two events, and the
    /// summary closes: `in − out − fees == current spendable`.
    #[test]
    fn a_grant_then_a_send_is_exactly_two_events_that_reconcile() {
        let w = wallet();
        assert_eq!(FEE, posted_fee(ArityBucket::TwoByTwo), "the posted table, not a copy");
        let grant = note(&w, 0, 1_000_000_000, 100);
        let change = note(&w, 0, 899_000_000, 200);
        let nf = crate::spent::note_nullifier(&w, 0, &grant);

        let scans = vec![scan_of(
            &w,
            0,
            outcome(vec![located(&grant, 4), located(&change, 9)], (0, 12)),
        )];
        let set = SpentSet::from_parts(Some((0, 12)), [(9, nf)]);
        let l = build(&w, &scans, Some(&set), &covered((0, 12)), None, (0, 12));

        assert!(l.gaps.is_empty(), "{:?}", l.gaps);
        assert_eq!(l.events.len(), 2, "the change is folded into its send, not a third event");

        match &l.events[0] {
            Event::Received(r) => {
                assert_eq!((r.height, r.value, r.div_index), (4, 1_000_000_000, 0));
                assert!(!r.shadowed);
            }
            other => panic!("first event is the receipt, got {other:?}"),
        }
        let send = match &l.events[1] {
            Event::Send(s) => s,
            other => panic!("second event is the send, got {other:?}"),
        };
        assert_eq!(send.height, 9, "the chain's date is the nullifier's block, not the note's");
        assert_eq!(send.inputs, vec![SpentInput { received_height: 4, value: 1_000_000_000, div_index: 0 }]);
        assert_eq!(send.change_total, 899_000_000);
        assert_eq!(
            send.outgoing,
            Outgoing::Exact { amount: 100_000_000, fee: FEE },
            "inputs − change − posted fee"
        );
        assert!(send.local.is_none(), "no sends.v1 in this wallet");

        let t = l.totals.clone().expect("a fully accounted ledger has totals");
        assert_eq!(t.total_in, 1_000_000_000, "the change is NOT income");
        assert_eq!(t.total_out, 100_000_000);
        assert_eq!(t.fees_paid, u128::from(FEE));
        assert_eq!(t.fee_inseparable_events, 0);
        assert_eq!(l.current_spendable, Some(899_000_000), "scan's own subtracted figure");
        // 🔴 The arithmetic the fold exists for.
        assert_eq!(
            t.total_in - t.total_out - t.fees_paid,
            l.current_spendable.unwrap(),
            "in − out − fees == spendable"
        );

        let text = render(&l, "http://edge");
        assert!(text.contains("height 4  RECEIVED"), "{text}");
        assert!(text.contains("height 9  SEND"), "{text}");
        assert!(text.contains("recipient: not recorded"), "{text}");
        assert!(text.contains("restored from a mnemonic never has one"), "{text}");
        assert!(text.contains("fee:       1000000 bessel (posted, 2×2 bucket)"), "{text}");
        assert!(text.contains("out:       100000000 bessel"), "{text}");
        assert!(text.contains("current spendable: 899000000 bessel"), "{text}");
    }

    /// The local record turns exactly one line from `not recorded` into a
    /// labeled recipient, and changes no number anywhere.
    #[test]
    fn a_local_record_labels_the_recipient_and_moves_no_figure() {
        let w = wallet();
        let grant = note(&w, 0, 1_000_000_000, 100);
        let change = note(&w, 0, 899_000_000, 200);
        let nf = crate::spent::note_nullifier(&w, 0, &grant);
        let scans = vec![scan_of(&w, 0, outcome(vec![located(&grant, 4), located(&change, 9)], (0, 12)))];
        let set = SpentSet::from_parts(Some((0, 12)), [(9, nf)]);

        let log = SendLog {
            records: vec![SendRecord {
                txid: [0xAB; 32],
                // Deliberately NOT the mined height: the join is the nullifiers.
                submitted_at_tip: 7,
                amount: 100_000_000,
                fee: FEE,
                recipient_short: "qmbs1thestranger".into(),
                nullifiers: vec![nf, [0xDD; 32]],
            }],
        };

        let chain_only = build(&w, &scans, Some(&set), &covered((0, 12)), None, (0, 12));
        let with_log = build(&w, &scans, Some(&set), &covered((0, 12)), Some(&log), (0, 12));
        assert_eq!(chain_only.totals, with_log.totals, "local memory moves no chain figure");
        assert_eq!(chain_only.current_spendable, with_log.current_spendable);
        assert_eq!(with_log.unmatched_records, 0);

        let text = render(&with_log, "http://edge");
        assert!(text.contains("recipient: qmbs1thestranger (local record)"), "{text}");
        assert!(text.contains(&format!("tx:        {}", "ab".repeat(32))), "{text}");
        assert!(text.contains("submitted at node tip 7"), "{text}");
        assert!(!text.contains("recipient: not recorded"), "{text}");

        // A record for a send that is not in this range joins nothing and says so.
        let orphan = SendLog {
            records: vec![SendRecord {
                txid: [0x11; 32],
                submitted_at_tip: 3,
                amount: 5,
                fee: FEE,
                recipient_short: "qmbs1elsewhere".into(),
                nullifiers: vec![[0x77; 32]],
            }],
        };
        let l = build(&w, &scans, Some(&set), &covered((0, 12)), Some(&orphan), (0, 12));
        assert_eq!(l.unmatched_records, 1);
        assert!(render(&l, "http://e").contains("joined no event in this range"));
    }

    /// The no-change edge: the whole input value left, and the fee cannot be
    /// separated from it. Said, not guessed.
    #[test]
    fn a_spend_with_no_change_reports_value_out_with_the_fee_unattributable() {
        let w = wallet();
        let n = note(&w, 0, 1_000_000_000, 300);
        let nf = crate::spent::note_nullifier(&w, 0, &n);
        let scans = vec![scan_of(&w, 0, outcome(vec![located(&n, 2)], (0, 9)))];
        let set = SpentSet::from_parts(Some((0, 9)), [(6, nf)]);
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));

        let send = match &l.events[1] {
            Event::Send(s) => s,
            other => panic!("expected a send, got {other:?}"),
        };
        assert!(send.change.is_empty());
        assert_eq!(send.outgoing, Outgoing::FeeInseparable { amount_and_fee: 1_000_000_000 });

        let t = l.totals.clone().expect("this ledger IS accounted — the sum is exact");
        assert_eq!(t.total_out, 1_000_000_000);
        assert_eq!(t.fees_paid, 0, "no fee is attributed…");
        assert_eq!(t.fee_inseparable_events, 1, "…and the report says how many are inside total out");
        assert_eq!(l.current_spendable, Some(0));

        let text = render(&l, "http://e");
        assert!(text.contains("change:    none at this height"), "{text}");
        assert!(text.contains("amount AND fee together"), "{text}");
        assert!(text.contains("not separable"), "{text}");
    }

    /// 🔴 The coverage-gap refusal: a nullifier stream that could not be read
    /// leaves the ledger with receipts only, no send events, no totals, and the
    /// heights it could not account for named.
    #[test]
    fn a_coverage_gap_refuses_the_totals_and_names_the_heights() {
        let w = wallet();
        let n = note(&w, 0, 1_000_000_000, 400);
        let scans = vec![scan_of(&w, 0, outcome(vec![located(&n, 2)], (0, 9)))];
        let coverage = SpentCoverage::Unavailable {
            why: "the nullifier stream could not be read (404)".into(),
        };
        let l = build(&w, &scans, None, &coverage, None, (0, 9));

        assert_eq!(l.events.len(), 1, "the receipt is still a chain fact");
        assert!(matches!(l.events[0], Event::Received(_)));
        assert!(l.totals.is_none(), "no totals over an unaccounted span");
        assert_eq!(l.current_spendable, None);
        assert_eq!(l.gaps.len(), 1, "{:?}", l.gaps);

        let text = render(&l, "http://e");
        assert!(text.contains("spent-subtraction: UNAVAILABLE"), "{text}");
        assert!(text.contains("404"), "the reason travels: {text}");
        assert!(text.contains("total in:          UNAVAILABLE"), "{text}");
        assert!(text.contains("current spendable: UNAVAILABLE"), "{text}");
        assert!(text.contains("spends over heights 0..=9"), "the span it could not account for: {text}");
        assert!(text.contains("this ledger is NOT complete"), "{text}");
    }

    /// A scan that could not read every output this key owns leaves the ledger
    /// unaccounted too — the events it did see are shown, and no total is.
    #[test]
    fn an_incomplete_scan_shows_its_events_but_refuses_the_totals() {
        let w = wallet();
        let n = note(&w, 0, 500, 500);
        let mut o = outcome(vec![located(&n, 3)], (0, 9));
        o.unopened.push(UnopenedOutput {
            height: 4,
            tx_index: 0,
            recipient_index: 0,
            output_index: 0,
            cm: [0x22; 32],
            why: qlab_cbserver::client::Unopened::PayloadUnavailable(
                "the /full route answered 404".into(),
            ),
        });
        o.stats.detected_outputs = 2;
        let scans = vec![scan_of(&w, 0, o)];
        let set = SpentSet::from_parts(Some((0, 9)), []);
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));

        assert_eq!(l.events.len(), 1);
        assert!(l.totals.is_none());
        assert_eq!(l.current_spendable, None);
        let text = render(&l, "http://e");
        assert!(text.contains("only 1 could be read"), "{text}");
        assert!(text.contains("missing from the ledger below"), "{text}");
        assert!(text.contains("total out:         UNAVAILABLE"), "{text}");
    }

    /// A scan that never started is its own named verdict, not an empty ledger.
    #[test]
    fn a_scan_that_never_started_is_named_and_blocks_every_total() {
        let w = wallet();
        let scans = vec![AddressScan {
            div_index: 0,
            address_short: "qmbs1short0".into(),
            outcome: Err("connection refused".into()),
        }];
        let set = SpentSet::from_parts(Some((0, 9)), []);
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));
        assert!(l.events.is_empty());
        assert!(l.totals.is_none());
        let text = render(&l, "http://down");
        assert!(text.contains("the scan never started: connection refused"), "{text}");
        assert!(text.contains("no events"), "{text}");
        assert!(text.contains("this ledger is NOT complete"), "{text}");
    }

    /// Two of this wallet's sends in ONE block cannot be separated by the
    /// chain, and the fee multiple cannot be guessed. The event says so and the
    /// totals refuse.
    #[test]
    fn more_than_one_send_at_a_height_is_unavailable_not_a_guessed_fee() {
        let w = wallet();
        let a = note(&w, 0, 1_000_000_000, 600);
        let b = note(&w, 0, 2_000_000_000, 700);
        let c = note(&w, 0, 3_000_000_000, 800);
        let change = note(&w, 0, 100_000_000, 900);
        let set = SpentSet::from_parts(
            Some((0, 9)),
            [
                (7, crate::spent::note_nullifier(&w, 0, &a)),
                (7, crate::spent::note_nullifier(&w, 0, &b)),
                (7, crate::spent::note_nullifier(&w, 0, &c)),
            ],
        );
        let scans = vec![scan_of(
            &w,
            0,
            outcome(
                vec![located(&a, 1), located(&b, 2), located(&c, 3), located(&change, 7)],
                (0, 9),
            ),
        )];
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));

        let send = l
            .events
            .iter()
            .find_map(|e| match e {
                Event::Send(s) => Some(s),
                _ => None,
            })
            .expect("a send event");
        assert_eq!(send.inputs.len(), 3);
        assert!(matches!(send.outgoing, Outgoing::Unavailable { .. }), "{:?}", send.outgoing);
        assert!(l.totals.is_none(), "no total over an unreadable group");

        // The receipt at the send height is NOT folded away on a failed
        // inference — nothing disappears from the ledger because a guess failed.
        assert!(
            l.events.iter().any(|e| matches!(e, Event::Received(r) if r.height == 7)),
            "the note received at the send height is still shown"
        );
        let text = render(&l, "http://e");
        assert!(text.contains("more than the frozen 2×2 bucket moves"), "{text}");
        assert!(text.contains("out:       UNAVAILABLE"), "{text}");
    }

    /// A shadowed note is a received event, labeled, in no total — and it makes
    /// a send at its own height unreadable rather than silently wrong.
    #[test]
    fn a_shadowed_note_is_reported_and_never_summed() {
        let w = wallet();
        let live = note(&w, 0, 700, 1000);
        let dead = note(&w, 0, 40, 1100);
        let mut o = outcome(vec![located(&live, 3)], (0, 9));
        o.shadowed.push(ShadowedNote {
            note: located(&dead, 5),
            claimed_by: located(&live, 3).at(),
            claim: qlab_cbserver::client::NullifierClaim::of(&live),
        });
        o.stats.detected_outputs = 2;
        o.stats.shadowed_outputs = 1;
        let scans = vec![scan_of(&w, 0, o)];
        let set = SpentSet::from_parts(Some((0, 9)), []);
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));

        assert_eq!(l.shadowed_total, 40);
        assert_eq!(l.events.len(), 2);
        let t = l.totals.clone().expect("shadowing alone does not unaccount the ledger");
        assert_eq!(t.total_in, 700, "the dead note is not income");
        assert_eq!(l.current_spendable, Some(700));
        let text = render(&l, "http://e");
        assert!(text.contains("shadowed:  another note already claims"), "{text}");
        assert!(text.contains("shadowed:          40 bessel"), "{text}");
    }

    /// Chronological, deterministic, and stable across runs.
    #[test]
    fn events_render_in_height_order() {
        let w = wallet();
        let early = note(&w, 0, 10, 1200);
        let late = note(&w, 1, 20, 1300);
        let scans = vec![
            scan_of(&w, 1, outcome(vec![located(&late, 9)], (0, 9))),
            scan_of(&w, 0, outcome(vec![located(&early, 2)], (0, 9))),
        ];
        let set = SpentSet::from_parts(Some((0, 9)), []);
        let l = build(&w, &scans, Some(&set), &covered((0, 9)), None, (0, 9));
        let heights: Vec<u64> = l.events.iter().map(|e| e.height()).collect();
        assert_eq!(heights, vec![2, 9]);
    }
}
