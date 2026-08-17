//! The select driver's narration, serialized for the C ABI (lab #432).
//!
//! [`crate::qmb_select_step_events`] returns these bytes WITH each step result,
//! so a shell cannot pump a selection without being handed its narration —
//! lab #424's guardrail 1 (visible degradation), made structurally unskippable
//! at this boundary instead of hoped for.
//!
//! # The encoding, and why it is this shape
//!
//! Tagged, length-prefixed, unknown-kind-skippable — the wire discipline's §0
//! shape applied to the ABI. One deliberate divergence from the served wire's
//! codecs: those REJECT an unknown version (a consensus reader must never
//! guess), while a narration consumer must **skip** an unknown kind and keep
//! reading — a fifth event kind must not break a shipped shell that predates
//! it. The record's length prefix is what makes the skip possible.
//!
//! ```text
//! blob   := u32le record_count || record_count × record
//! record := u16le kind || u32le body_len || body_len bytes
//! ```
//!
//! All integers little-endian; all text UTF-8, NOT NUL-terminated (lengths are
//! explicit). The per-kind bodies are documented in `include/qumbra_ffi.h`,
//! which is the consumer's contract; the header-pin test holds the kind values
//! in this file and the header to the same list, in both directions.
//!
//! # 🔴 No key material may ever appear in an event payload
//!
//! Everything here crosses to a UI layer whose job is to DISPLAY it — logs,
//! screenshots, accessibility readers. The current vocabulary carries counts,
//! heights, one public tree root, and operator-facing prose; none of it is or
//! derives from key material, and `no_key_material_crosses_in_the_event_stream`
//! (tests/select_abi.rs) locks that from the consumer's side. Any new event
//! kind must be reviewed against this rule before it gets a tag — if a step
//! ever needs to reference a note, it references a public fact about it
//! (value, height, position), never `rho`/`rseed`/seed/spending material.

use qumbra_wallet::spend::SendStep;

/// Narration this encoder version has no dedicated shape for. Body: UTF-8
/// display text. Present so that nothing representable in the driver's
/// vocabulary is EVER silently dropped again — the defect this module exists
/// to close. Unreachable today: the driver emits only the four named kinds.
pub const QMB_EVENT_OTHER: u16 = 0;
/// Input selection finished. Body: `u64le spendable || u64le skipped_spent ||
/// u64le mined`.
pub const QMB_EVENT_SELECTED: u16 = 1;
/// Tree caught up, anchor chosen. Body: `u64le held || u64le fetched ||
/// u64le anchor_count || u64le node_tip || u8 has_finalized || u64le
/// finalized || u64le anchor_behind || anchor_root` (UTF-8 hex, the rest of
/// the body).
pub const QMB_EVENT_TREE: u16 = 2;
/// Something that must be SEEN but must not stop the spend. Body: UTF-8 text.
pub const QMB_EVENT_WARNING: u16 = 3;
/// 🔴 The coinbase stream could not be read (lab #424's ruling): selection ran
/// on TRANSACTION notes only, and the user must be shown so. Body: UTF-8 text.
pub const QMB_EVENT_COINBASE_UNAVAILABLE: u16 = 4;

fn push_record(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
}

/// Serialize a drained [`SendStep`] batch for the ABI. The match is
/// exhaustive on purpose: a new `SendStep` variant refuses to compile until
/// someone decides its shape here — deciding "drop it" silently is the one
/// option the compiler no longer offers.
pub fn encode_events(events: &[SendStep]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + events.len() * 32);
    out.extend_from_slice(&(events.len() as u32).to_le_bytes());
    for ev in events {
        match ev {
            SendStep::Selected { spendable, skipped_spent, mined } => {
                let mut body = Vec::with_capacity(24);
                body.extend_from_slice(&(*spendable as u64).to_le_bytes());
                body.extend_from_slice(&(*skipped_spent as u64).to_le_bytes());
                body.extend_from_slice(&(*mined as u64).to_le_bytes());
                push_record(&mut out, QMB_EVENT_SELECTED, &body);
            }
            SendStep::Tree {
                held,
                fetched,
                anchor_count,
                anchor_root,
                node_tip,
                finalized,
                anchor_behind,
            } => {
                let mut body = Vec::with_capacity(49 + anchor_root.len());
                body.extend_from_slice(&held.to_le_bytes());
                body.extend_from_slice(&fetched.to_le_bytes());
                body.extend_from_slice(&anchor_count.to_le_bytes());
                body.extend_from_slice(&node_tip.to_le_bytes());
                body.push(u8::from(finalized.is_some()));
                body.extend_from_slice(&finalized.unwrap_or(0).to_le_bytes());
                body.extend_from_slice(&anchor_behind.to_le_bytes());
                body.extend_from_slice(anchor_root.as_bytes());
                push_record(&mut out, QMB_EVENT_TREE, &body);
            }
            SendStep::Warning(text) => {
                push_record(&mut out, QMB_EVENT_WARNING, text.as_bytes());
            }
            SendStep::CoinbaseUnavailable { why } => {
                push_record(&mut out, QMB_EVENT_COINBASE_UNAVAILABLE, why.as_bytes());
            }
            // The sync flow's post-select vocabulary. `SelectDriver` never
            // emits these (it is phase 1 only; they belong to record/prove/
            // submit), so these arms are unreachable today — but "unreachable
            // today" is exactly how the original drop survived from #400 to
            // #430, so they cross as OTHER text rather than being dropped.
            SendStep::Resolved { recipient_short, contact } => {
                let text = match contact {
                    Some(c) => format!("recipient resolved: {recipient_short} (contact {c})"),
                    None => format!("recipient resolved: {recipient_short}"),
                };
                push_record(&mut out, QMB_EVENT_OTHER, text.as_bytes());
            }
            SendStep::Proving => {
                push_record(&mut out, QMB_EVENT_OTHER, b"proving (seconds and gigabytes)");
            }
            SendStep::Built { amount, fee, change, prove_secs, used_dummy } => {
                let text = format!(
                    "built: amount {amount} bessel, fee {fee}, change {change}, \
                     proved in {prove_secs:.2}s, dummy slot: {used_dummy}"
                );
                push_record(&mut out, QMB_EVENT_OTHER, text.as_bytes());
            }
            SendStep::Recorded => {
                push_record(&mut out, QMB_EVENT_OTHER, b"local send record written");
            }
            SendStep::Submitting => {
                push_record(&mut out, QMB_EVENT_OTHER, b"submitting");
            }
            SendStep::Answered { status, body } => {
                let text = format!("node answered {status}: {body}");
                push_record(&mut out, QMB_EVENT_OTHER, text.as_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32le(b: &[u8]) -> u32 {
        u32::from_le_bytes(b[..4].try_into().unwrap())
    }
    fn u16le(b: &[u8]) -> u16 {
        u16::from_le_bytes(b[..2].try_into().unwrap())
    }

    /// The exact bytes of a Warning record — `Warning` has no driver emission
    /// path yet (reported on lab #432), so its ENCODING is locked here while
    /// the arrival path is locked by the ABI tests on the kinds the driver can
    /// actually emit. When the driver gains a warning case, this vocabulary is
    /// already on the wire.
    #[test]
    fn a_warning_encodes_tagged_and_length_prefixed() {
        let blob = encode_events(&[SendStep::Warning("the ledger is unaffected".into())]);
        assert_eq!(u32le(&blob), 1, "record count");
        assert_eq!(u16le(&blob[4..]), QMB_EVENT_WARNING);
        assert_eq!(u32le(&blob[6..]) as usize, "the ledger is unaffected".len());
        assert_eq!(&blob[10..], b"the ledger is unaffected");
    }

    #[test]
    fn selected_and_coinbase_unavailable_encode_in_order() {
        let blob = encode_events(&[
            SendStep::CoinbaseUnavailable { why: "404".into() },
            SendStep::Selected { spendable: 3, skipped_spent: 1, mined: 2 },
        ]);
        assert_eq!(u32le(&blob), 2);
        // Record 1: the degradation precedes the selection line it explains.
        assert_eq!(u16le(&blob[4..]), QMB_EVENT_COINBASE_UNAVAILABLE);
        let l1 = u32le(&blob[6..]) as usize;
        assert_eq!(&blob[10..10 + l1], b"404");
        // Record 2.
        let r2 = 10 + l1;
        assert_eq!(u16le(&blob[r2..]), QMB_EVENT_SELECTED);
        assert_eq!(u32le(&blob[r2 + 2..]), 24);
        let body = &blob[r2 + 6..r2 + 30];
        assert_eq!(u64::from_le_bytes(body[0..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(body[8..16].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(body[16..24].try_into().unwrap()), 2);
    }

    /// The vocabulary's sync-flow variants cross as OTHER text — nothing the
    /// driver could ever hand `take_events` is droppable.
    #[test]
    fn sync_flow_variants_cross_as_other_rather_than_vanishing() {
        let blob = encode_events(&[SendStep::Proving, SendStep::Recorded]);
        assert_eq!(u32le(&blob), 2);
        assert_eq!(u16le(&blob[4..]), QMB_EVENT_OTHER);
    }

    #[test]
    fn an_empty_batch_is_a_count_of_zero() {
        assert_eq!(encode_events(&[]), 0u32.to_le_bytes().to_vec());
    }
}
