//! The ledger as DATA rather than as a paragraph (lab #556).
//!
//! `qmb_wallet_ledger_report_over_fetch` hands back one pre-rendered `char *`,
//! so every shell can display the ledger and none can lay it out — no per-row
//! amount, no verdict chip, nothing an accessibility reader can navigate. This
//! module is the same `Ledger`, serialized, so a native client can build rows.
//!
//! # The shape, and why this one
//!
//! Ruled by Larry on 2026-08-21 (recorded on lab #556): the **tagged
//! length-prefixed blob**, the same wire [`crate::events`] already uses.
//!
//! ```text
//! blob   := u32le record_count || record_count × record
//! record := u16le kind || u32le body_len || body_len bytes
//! ```
//!
//! Unknown kinds are **skipped by length**, so a shell built against v1 keeps
//! working when v2 adds a row type. That is the property that made this shape
//! win over typed getters (one export per field, and every addition an ABI
//! break) and over a JSON string (a document parser in four shells' money path,
//! and "malformed" as a failure mode nobody would answer the same way twice).
//!
//! Integers little-endian. `u128` crosses as 16 bytes LE — money here is
//! integer-exact and no float is reachable from it, so the width is carried
//! rather than narrowed. Where a body holds ONE string it is the tail; where it
//! holds two, each is `u32le len || bytes`.
//!
//! # 🔴 What this encoding must not do: collapse a three-state field
//!
//! Almost every interesting field in [`Ledger`] has a state that means *we
//! could not tell*, and it is never the same as zero:
//!
//!   - [`Totals`] is an `Option`, and **its absence is carried by the absence of
//!     the [`QMB_LEDGER_TOTALS`] record.** A zeroed totals record would say this
//!     wallet received nothing, when the truth is that the ledger could not
//!     account for what it received. Nothing in this encoder ever emits a
//!     zeroed totals row.
//!   - [`Outgoing`] is Exact / FeeInseparable / Unavailable. The middle one is
//!     the case where amount and fee cannot be separated but their SUM is
//!     exact; flattening it into either neighbour invents a fee or discards a
//!     figure that is known.
//!   - [`SpentCoverage`] is Covered / Unavailable, and `Covered{range: None}` —
//!     the endpoint held no main-chain block in the range — is a **covered**
//!     state, not a failure. Three distinct things, three encodings.
//!   - `shadowed` notes are reported and never summed; `ambiguous_local` means
//!     more than one local record claimed an event and none was picked.
//!
//! Every one of those is asserted in `tests`, because an encoder that quietly
//! flattens a state is indistinguishable from a correct one until somebody's
//! balance is wrong.
//!
//! # 🔴 No key material
//!
//! Same rule as [`crate::events`], for the same reason: these bytes cross to a
//! layer whose job is to display them. What crosses here is heights, values,
//! diversifier indices, short addresses, and operator-facing prose. A new kind
//! that needs to reference a note references a public fact about it — never
//! `rho`/`rseed`/seed/spending material.

use qlab_cbserver::client::Completeness;
use qlab_ledger::history::{Event, Ledger, Outgoing};
use qlab_ledger::vocab::SpentCoverage;

/// Anything this encoder version has no dedicated shape for. Body: UTF-8
/// display text. Present for the same reason [`crate::events`] has one: a
/// vocabulary that grows must never silently drop what it cannot name yet.
pub const QMB_LEDGER_OTHER: u16 = 0;

/// The claim's scope. Body: `u64le from || u64le to || u8 has_served ||
/// u64le served_from || u64le served_to`.
///
/// `has_served == 0` means the compact stream served nothing across every
/// address — a ledger is a claim about a range, and a range nobody served is
/// not the same as an empty one.
pub const QMB_LEDGER_RANGE: u16 = 1;

/// Whether this wallet's own spends have been subtracted. Body:
/// `u8 state || u8 has_range || u64le from || u64le to || why` where
/// `state` is 0 covered / 1 unavailable, and `why` is the UTF-8 tail
/// (empty when covered).
///
/// 🔴 `state == 0` with `has_range == 0` is the **covered** case where the
/// endpoint held no main-chain block in the range at all. It is not a failure
/// and must not be rendered as one.
pub const QMB_LEDGER_COVERAGE: u16 = 2;

/// A received note. Body: `u64le height || u64le value || u64le div_index ||
/// u8 shadowed || address_short` (UTF-8 tail).
///
/// `shadowed == 1` is opened and authenticated but unspendable forever, because
/// another note already claims its nullifier (issue #215). Reported, never
/// summed — a shell that adds these into a balance is wrong.
pub const QMB_LEDGER_RECEIVED: u16 = 3;

/// A send, reconstructed from same-height co-occurrence. Body:
/// `u64le height || u32le input_count || u128le inputs_total ||
/// u32le change_count || u128le change_total || u8 outgoing ||
/// u128le amount || u64le fee || u8 ambiguous_local || u8 has_local || why`
/// (UTF-8 tail).
///
/// `outgoing`: 0 Exact (`amount` and `fee` both meaningful) · 1 FeeInseparable
/// (`amount` is amount **and fee together**, `fee` is 0 and means nothing) ·
/// 2 Unavailable (no figure at all; `why` says why, and `amount`/`fee` are 0
/// and mean nothing).
///
/// 🔴 A shell must branch on `outgoing` before reading `amount`. Reading it
/// unconditionally turns "we cannot separate the fee" into a fee of zero.
pub const QMB_LEDGER_SEND: u16 = 4;

/// The totals. Body: `u128le total_in || u128le total_out || u128le fees_paid ||
/// u64le fee_inseparable_events`.
///
/// 🔴 **Emitted only when the ledger has totals at all.** Its ABSENCE is how
/// "this ledger could not account for everything" crosses — see
/// [`QMB_LEDGER_GAP`], whose presence is the reason. A shell must treat a
/// missing totals record as *unknown*, never as zero.
pub const QMB_LEDGER_TOTALS: u16 = 5;

/// One thing this ledger could not account for, with its reason. Body: UTF-8.
/// One record per gap; an empty gap list is the only state in which
/// [`QMB_LEDGER_TOTALS`] appears.
pub const QMB_LEDGER_GAP: u16 = 6;

/// A per-address verdict, in the vocabulary the scan report renders. Body:
/// `u64le div_index || u8 completeness || u64le detected || u64le opened ||
/// u64le spendable || u32le short_len || short || u32le why_len || why`.
///
/// `completeness`, and which counts mean anything for each:
///
/// | tag | variant | meaningful |
/// |-----|---------|------------|
/// | 0 | `Complete` | none — all three counts are 0 and mean nothing |
/// | 1 | `Incomplete` | `detected`, `opened` |
/// | 2 | `Shadowed` | `opened`, `spendable` |
/// | 3 | `IncompleteAndShadowed` | all three |
/// | 255 | a variant this encoder version does not know | none |
///
/// 🔴 The counts share one fixed layout so the body does not change size with
/// the tag, which means a shell MUST branch on the tag before reading them. A
/// `spendable` of 0 read out of an `Incomplete` verdict is not a verdict that
/// nothing is spendable — it is a field that variant does not carry.
///
/// 255 is emitted when this encoder meets a `Completeness` variant added after
/// it was written. That is a bug HERE rather than in the shell, and it crosses
/// as an admission rather than as a guess.
pub const QMB_LEDGER_VERDICT: u16 = 7;

/// Operator-facing prose from the history flow (`HistoryData::notes`). Body:
/// UTF-8. Display-only; nothing is derived from it.
pub const QMB_LEDGER_NOTE: u16 = 8;

/// The figures that are not totals. Body: `u8 has_spendable ||
/// u128le current_spendable || u128le shadowed_total ||
/// u64le unmatched_records`.
///
/// `has_spendable == 0` means the scan's subtracted figure is not quotable —
/// distinct from a spendable balance of zero. `unmatched_records` counts local
/// send records that joined to no event in this range: they may have landed
/// outside it or never landed, and either way an unjoined record is stated
/// rather than left looking like a send that never happened.
pub const QMB_LEDGER_SUMMARY: u16 = 9;

fn push_record(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
}

fn push_u128(body: &mut Vec<u8>, v: u128) {
    body.extend_from_slice(&v.to_le_bytes());
}

/// A `u32le`-prefixed string, for bodies that carry more than one.
fn push_str(body: &mut Vec<u8>, s: &str) {
    body.extend_from_slice(&(s.len() as u32).to_le_bytes());
    body.extend_from_slice(s.as_bytes());
}

/// The verdict's tag and its three counts.
///
/// Matched by name rather than by position: a reordering of that enum must not
/// silently renumber this wire. Non-exhaustive on purpose — `Completeness`
/// lives in another crate, so a variant added there must degrade to 255 rather
/// than fail to compile here and block the FFI on an unrelated change.
fn completeness_parts(c: &Completeness) -> (u8, u64, u64, u64) {
    match c {
        Completeness::Complete => (0, 0, 0, 0),
        Completeness::Incomplete { detected, opened } => (1, *detected as u64, *opened as u64, 0),
        Completeness::Shadowed { opened, spendable } => (2, 0, *opened as u64, *spendable as u64),
        Completeness::IncompleteAndShadowed { detected, opened, spendable } => {
            (3, *detected as u64, *opened as u64, *spendable as u64)
        }
        #[allow(unreachable_patterns)]
        _ => (255, 0, 0, 0),
    }
}

/// Serialize a [`Ledger`] and its notes for the ABI.
///
/// Record order is: RANGE, COVERAGE, one row per event in ledger order, TOTALS
/// (only if there are totals), every GAP, every VERDICT, SUMMARY, then NOTEs.
/// A consumer must not depend on that order beyond "events are in ledger
/// order" — the count and the per-record kind are the contract.
pub fn encode_ledger(ledger: &Ledger, notes: &[String]) -> Vec<u8> {
    let mut records: Vec<(u16, Vec<u8>)> = Vec::new();

    // ── the claim's scope ───────────────────────────────────────────────────
    let mut body = Vec::with_capacity(33);
    body.extend_from_slice(&ledger.range.0.to_le_bytes());
    body.extend_from_slice(&ledger.range.1.to_le_bytes());
    body.push(u8::from(ledger.outputs_served.is_some()));
    let (sf, st) = ledger.outputs_served.unwrap_or((0, 0));
    body.extend_from_slice(&sf.to_le_bytes());
    body.extend_from_slice(&st.to_le_bytes());
    records.push((QMB_LEDGER_RANGE, body));

    // ── whether spends were subtracted ─────────────────────────────────────
    let mut body = Vec::with_capacity(64);
    match &ledger.coverage {
        SpentCoverage::Covered { range } => {
            body.push(0);
            body.push(u8::from(range.is_some()));
            let (f, t) = range.unwrap_or((0, 0));
            body.extend_from_slice(&f.to_le_bytes());
            body.extend_from_slice(&t.to_le_bytes());
        }
        SpentCoverage::Unavailable { why } => {
            body.push(1);
            body.push(0);
            body.extend_from_slice(&0u64.to_le_bytes());
            body.extend_from_slice(&0u64.to_le_bytes());
            body.extend_from_slice(why.as_bytes());
        }
    }
    records.push((QMB_LEDGER_COVERAGE, body));

    // ── the rows, in ledger order ──────────────────────────────────────────
    for event in &ledger.events {
        match event {
            Event::Received(r) => {
                let mut body = Vec::with_capacity(25 + r.address_short.len());
                body.extend_from_slice(&r.height.to_le_bytes());
                body.extend_from_slice(&r.value.to_le_bytes());
                body.extend_from_slice(&r.div_index.to_le_bytes());
                body.push(u8::from(r.shadowed));
                body.extend_from_slice(r.address_short.as_bytes());
                records.push((QMB_LEDGER_RECEIVED, body));
            }
            Event::Send(s) => {
                let mut body = Vec::with_capacity(64);
                body.extend_from_slice(&s.height.to_le_bytes());
                body.extend_from_slice(&(s.inputs.len() as u32).to_le_bytes());
                push_u128(&mut body, s.inputs_total);
                body.extend_from_slice(&(s.change.len() as u32).to_le_bytes());
                push_u128(&mut body, s.change_total);
                // 🔴 The three states, kept three. `amount`/`fee` are written in
                // every arm so the body has one fixed layout, but the tag is
                // what says which of them mean anything.
                let (tag, amount, fee, why): (u8, u128, u64, &str) = match &s.outgoing {
                    Outgoing::Exact { amount, fee } => (0, *amount, *fee, ""),
                    Outgoing::FeeInseparable { amount_and_fee } => (1, *amount_and_fee, 0, ""),
                    Outgoing::Unavailable { why } => (2, 0, 0, why.as_str()),
                };
                body.push(tag);
                push_u128(&mut body, amount);
                body.extend_from_slice(&fee.to_le_bytes());
                body.push(u8::from(s.ambiguous_local));
                body.push(u8::from(s.local.is_some()));
                body.extend_from_slice(why.as_bytes());
                records.push((QMB_LEDGER_SEND, body));
            }
        }
    }

    // ── totals, ONLY if there are any ──────────────────────────────────────
    if let Some(t) = &ledger.totals {
        let mut body = Vec::with_capacity(56);
        push_u128(&mut body, t.total_in);
        push_u128(&mut body, t.total_out);
        push_u128(&mut body, t.fees_paid);
        body.extend_from_slice(&(t.fee_inseparable_events as u64).to_le_bytes());
        records.push((QMB_LEDGER_TOTALS, body));
    }

    for gap in &ledger.gaps {
        records.push((QMB_LEDGER_GAP, gap.as_bytes().to_vec()));
    }

    for (div_index, short, completeness, why) in &ledger.verdicts {
        let mut body = Vec::with_capacity(24 + short.len());
        body.extend_from_slice(&div_index.to_le_bytes());
        let (tag, detected, opened, spendable) = completeness_parts(completeness);
        body.push(tag);
        body.extend_from_slice(&detected.to_le_bytes());
        body.extend_from_slice(&opened.to_le_bytes());
        body.extend_from_slice(&spendable.to_le_bytes());
        push_str(&mut body, short);
        push_str(&mut body, why.as_deref().unwrap_or(""));
        records.push((QMB_LEDGER_VERDICT, body));
    }

    let mut body = Vec::with_capacity(41);
    body.push(u8::from(ledger.current_spendable.is_some()));
    push_u128(&mut body, ledger.current_spendable.unwrap_or(0));
    push_u128(&mut body, ledger.shadowed_total);
    body.extend_from_slice(&(ledger.unmatched_records as u64).to_le_bytes());
    records.push((QMB_LEDGER_SUMMARY, body));

    for note in notes {
        records.push((QMB_LEDGER_NOTE, note.as_bytes().to_vec()));
    }

    let mut out = Vec::with_capacity(8 + records.len() * 48);
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (kind, body) in &records {
        push_record(&mut out, *kind, body);
    }
    out
}
