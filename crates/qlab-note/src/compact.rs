//! §2 compact-group framing — the ratified bytes, in the crate that owns the
//! types they frame.
//!
//! Per-tx compact group (wallet-interop-spec §2, exact):
//! ```text
//! tx_index      : varint (unsigned LEB128, little-endian base-128)
//! n_recipients  : u8
//!   per recipient:
//!     ml_kem_ct : 1088 bytes            (shared per (tx, recipient))
//!     n_outputs : u8
//!       per output:
//!         cm       : 32 bytes
//!         tag      : 8 bytes
//!         clue_len : u8  (= 0 at v1)
//!         clue     : clue_len bytes  (= 0 at v1)
//! ```
//!
//! All integers little-endian, and every varint is **canonical** — the shortest
//! encoding of its value, one byte string per value ([`read_varint`]).
//!
//! ## Why this lives here and not in `qlab-cbserver` (issue #188 baton 1)
//!
//! It used to live in `qlab-cbserver::codec`, which was the right home while
//! these bytes were a *serving* artifact. `discovery-on-the-consensus-wire.md`
//! **D2** puts the same bytes inside the block-body preimage, so
//! `qlab_devnet::body` now has to encode and decode them — and `qlab-cbserver`
//! **depends on** `qlab-devnet`, so the framing could not stay there without a
//! dependency cycle.
//!
//! D2's requirement is that there is exactly **one** encoder ("a re-encoding
//! step between the two would make *what the chain committed* and *what the
//! wallet scanned* two artifacts that can drift"). Duplicating the framing into
//! `qlab-devnet` is precisely the fork D2 forbids, and injecting a codec trait
//! the way `TxVerifier` is injected would make a consensus rule optional at the
//! seam. So the framing moved **down** to `qlab-note`, which already owns
//! [`CompactEntry`] and [`RecipientBundle`] and depends on neither crate.
//! `qlab-cbserver::codec` re-exports every item below, so its golden vector
//! (1177 bytes, digest `3ee2a5e6…`) still locks these exact bytes — that test is
//! now a **consensus** lock, per D2.
//!
//! The `/v1/compact` *response wrapper* (version byte, `n_blocks`, per-block
//! `height ‖ n_groups`) stays in `qlab-cbserver`: it is a serving envelope and
//! nothing in a block body commits to it.

use crate::kem::CT_LEN;
use crate::wire::{ClueSlot, CompactEntry, RecipientBundle, CM_LEN};

/// A decode error with enough shape to diagnose the byte that caused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Ran out of bytes while reading `what`.
    Truncated { what: &'static str },
    /// A format version byte that this reference does not implement.
    BadVersion { got: u8 },
    /// A `clue_len` this v1 reference does not support (only 0 at launch).
    UnsupportedClue { clue_len: u8 },
    /// A varint that does not terminate within 10 bytes (u64 overflow guard).
    VarintOverflow,
    /// A varint that is not the shortest encoding of its value — e.g. `0x80 0x00`
    /// for `0`. `len` is how many bytes the offending varint consumed.
    ///
    /// Two byte strings that decode to one value are a malleability vector the
    /// moment these bytes enter a consensus commitment
    /// (`discovery-on-the-consensus-wire.md` D6), so the decoder refuses them.
    NonCanonicalVarint { len: usize },
    /// Trailing bytes remained after a whole-buffer decode.
    TrailingBytes { remaining: usize },
    /// The committed region's payload section is not `n_entries × PAYLOAD_LEN`
    /// bytes. Issue #188 (a) as amended: every entry carries exactly one
    /// fixed-width payload, so the section's length is fully determined by the
    /// group contents that precede it and any other length is a second byte
    /// string for the same logical group.
    PayloadSectionLen { expected: usize, got: usize },
}

/// One transaction's compact group: its index within the block and the
/// per-recipient bundles (each a shared ML-KEM ct + its output entries).
///
/// `Clone` only: [`RecipientBundle`] derives `Clone` alone (it is ratified; we do
/// not edit it), so structural `PartialEq`/`Debug` cannot be derived here.
/// [`groups_eq`] is the field-wise comparison callers need.
#[derive(Clone, Default)]
pub struct CompactGroup {
    pub tx_index: u64,
    pub recipients: Vec<RecipientBundle>,
}

/// Shape-only, because the payload is ciphertext: printing 1,088 B of ML-KEM ct
/// per recipient into a test failure helps nobody. `RecipientBundle` cannot
/// derive `Debug` (ratified type, `Clone` only), so this is written by hand.
impl core::fmt::Debug for CompactGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompactGroup")
            .field("tx_index", &self.tx_index)
            .field("n_recipients", &self.recipients.len())
            .field("outputs_per_recipient", &self.recipients.iter().map(|r| r.entries.len()).collect::<Vec<_>>())
            .finish()
    }
}

impl CompactGroup {
    /// The output commitments this group describes, **in serving order:
    /// recipient-major, then per-output**.
    ///
    /// This ordering is `discovery-on-the-consensus-wire.md` **D4** and is not a
    /// preference — "an unordered rule would let two orderings of the same
    /// content produce two commitments". It is the same order the node RPC used
    /// to state privately, lifted here so consensus and serving read one
    /// function; that private copy was deleted in baton 2 rather than left to
    /// drift against this one.
    pub fn commitments(&self) -> Vec<[u8; CM_LEN]> {
        self.recipients
            .iter()
            .flat_map(|r| r.entries.iter().map(|e| e.cm))
            .collect()
    }

    /// Number of outputs described across every recipient.
    pub fn n_outputs(&self) -> usize {
        self.recipients.iter().map(|r| r.entries.len()).sum()
    }
}

/// Field-wise equality for two groups (neither `CompactGroup` nor
/// `RecipientBundle` can derive `PartialEq`; see the type's note).
pub fn groups_eq(a: &CompactGroup, b: &CompactGroup) -> bool {
    a.tx_index == b.tx_index
        && a.recipients.len() == b.recipients.len()
        && a.recipients
            .iter()
            .zip(&b.recipients)
            .all(|(x, y)| x.ct == y.ct && x.entries == y.entries)
}

// ---- varint (unsigned LEB128) ------------------------------------------------

/// Append `v` as unsigned LEB128 (little-endian base-128).
pub fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Read an unsigned LEB128 varint, advancing `pos`. Guards u64 overflow (≤10
/// bytes) and rejects **non-canonical** encodings.
///
/// Canonical = the shortest encoding of the value. Equivalently: the terminating
/// byte (the one without the continuation bit) is never `0x00` unless the whole
/// encoding is the single byte `0x00`. A multi-byte encoding whose last group is
/// zero is padded, and a padded encoding is a second byte string for a value that
/// already has one — `0x80 0x00` and `0x00` both mean `0`.
///
/// That is harmless while nothing commits to these bytes and is a malleability
/// vector the moment they enter a consensus commitment, which is why
/// `discovery-on-the-consensus-wire.md` D6 requires the rejection **before** any
/// preimage work. [`write_varint`] already emits only shortest encodings, so this
/// tightens the decoder without moving a single byte the encoder produces.
pub fn read_varint(b: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    let start = *pos;
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos).ok_or(CodecError::Truncated { what: "varint" })?;
        *pos += 1;
        if shift >= 64 || (shift == 63 && byte > 1) {
            return Err(CodecError::VarintOverflow);
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            let len = *pos - start;
            // A terminating 0x00 after at least one continuation byte means the
            // top group is zero: a longer encoding of a value that fits in fewer
            // bytes. `0x00` alone is the canonical encoding of 0 and is fine.
            if len > 1 && byte == 0 {
                return Err(CodecError::NonCanonicalVarint { len });
            }
            return Ok(result);
        }
        shift += 7;
    }
}

// ---- per-output entry --------------------------------------------------------

/// Encode one compact entry per §2: `cm(32) ‖ tag(8) ‖ clue_len(u8) ‖ clue`.
/// For the launch (empty) clue this is exactly `cm ‖ tag ‖ 0x00`.
pub fn write_entry(out: &mut Vec<u8>, e: &CompactEntry) {
    out.extend_from_slice(&e.cm);
    out.extend_from_slice(&e.tag);
    match e.clue {
        // clue_len = 0, no clue bytes.
        ClueSlot::Empty => out.push(0),
    }
}

pub fn read_entry(b: &[u8], pos: &mut usize) -> Result<CompactEntry, CodecError> {
    let end = *pos + 32 + 8 + 1;
    if b.len() < end {
        return Err(CodecError::Truncated { what: "compact entry" });
    }
    let mut cm = [0u8; 32];
    cm.copy_from_slice(&b[*pos..*pos + 32]);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&b[*pos + 32..*pos + 40]);
    let clue_len = b[*pos + 40];
    *pos = end;
    if clue_len != 0 {
        // v1 reserves the byte but activates no clue payload (Decision 2).
        return Err(CodecError::UnsupportedClue { clue_len });
    }
    Ok(CompactEntry {
        cm,
        tag,
        clue: ClueSlot::Empty,
    })
}

// ---- recipient bundle --------------------------------------------------------

pub fn write_bundle(out: &mut Vec<u8>, r: &RecipientBundle) {
    out.extend_from_slice(&r.ct);
    debug_assert!(r.entries.len() <= u8::MAX as usize, "n_outputs is a u8");
    out.push(r.entries.len() as u8);
    for e in &r.entries {
        write_entry(out, e);
    }
}

pub fn read_bundle(b: &[u8], pos: &mut usize) -> Result<RecipientBundle, CodecError> {
    if b.len() < *pos + CT_LEN {
        return Err(CodecError::Truncated { what: "ml_kem_ct" });
    }
    let mut ct = [0u8; CT_LEN];
    ct.copy_from_slice(&b[*pos..*pos + CT_LEN]);
    *pos += CT_LEN;
    let n_outputs = *b.get(*pos).ok_or(CodecError::Truncated { what: "n_outputs" })?;
    *pos += 1;
    let mut entries = Vec::with_capacity(n_outputs as usize);
    for _ in 0..n_outputs {
        entries.push(read_entry(b, pos)?);
    }
    Ok(RecipientBundle { ct, entries })
}

// ---- compact group -----------------------------------------------------------

// ---- group *contents* — the part a block body commits to ---------------------
//
// A group on the serving wire is `tx_index(varint) ‖ contents`. The block body
// commits to **contents only**; see [`write_group_contents`].

/// Encode a group's contents: `n_recipients(u8) ‖ [ct(1088) ‖ n_outputs(u8) ‖
/// entries]`. **No `tx_index`.**
///
/// 🔴 **Why the index is not in here** (issue #188 baton 1, a deviation from a
/// literal reading of `discovery-on-the-consensus-wire.md` D2, reported on the
/// issue): a transaction's index within a block is not known until the block is
/// assembled, and a transaction is built, gossiped and deduplicated by
/// `keccak256(encode_tx(..))` long before that. Committing `tx_index` inside the
/// transaction would force the assembler to rewrite the transaction's own bytes
/// at inclusion time, which moves its id between the mempool and the block and
/// breaks compact-block reconstruction.
///
/// D1's own reasoning is the argument for leaving it out — *"an index is a
/// second thing that can disagree with the first; positional containment cannot
/// disagree with itself."* Serving stays a projection rather than a re-encoding:
/// `/v1/compact` emits `varint(position) ‖ committed_bytes`, a concatenation
/// whose only new byte group is derived from the body's own ordering.
///
/// **Consequence, stated because it is load-bearing:** every field here is
/// fixed-width or single-valued, so the committed region contains **no varint
/// at all** and admits exactly one byte string per logical group by
/// construction. D6 is still required for the serving wire (step 4) and is
/// already landed (`PR #149`); it simply never gets a chance to matter inside
/// the preimage.
pub fn write_group_contents(out: &mut Vec<u8>, recipients: &[RecipientBundle]) {
    debug_assert!(recipients.len() <= u8::MAX as usize, "n_recipients is a u8");
    out.push(recipients.len() as u8);
    for r in recipients {
        write_bundle(out, r);
    }
}

pub fn read_group_contents(
    b: &[u8],
    pos: &mut usize,
) -> Result<Vec<RecipientBundle>, CodecError> {
    let n_recipients = *b
        .get(*pos)
        .ok_or(CodecError::Truncated { what: "n_recipients" })?;
    *pos += 1;
    let mut recipients = Vec::with_capacity(n_recipients as usize);
    for _ in 0..n_recipients {
        recipients.push(read_bundle(b, pos)?);
    }
    Ok(recipients)
}

/// Encode group contents to their own buffer — **the exact bytes a block body
/// commits to** (D1/D3).
pub fn encode_group_contents(recipients: &[RecipientBundle]) -> Vec<u8> {
    let mut out = Vec::new();
    write_group_contents(&mut out, recipients);
    out
}

/// Decode group contents from a whole buffer, rejecting trailing bytes.
///
/// This is the consensus entry point. `discovery-on-the-consensus-wire.md` §4
/// rule 3 requires that the bytes "decode, decode canonically (D6), and
/// re-encode to themselves"; with no varint in the region, canonicity reduces to
/// **exact consumption**, because a well-formed prefix followed by junk would
/// otherwise be a second byte string for the same logical group.
pub fn decode_group_contents(b: &[u8]) -> Result<Vec<RecipientBundle>, CodecError> {
    let mut pos = 0usize;
    let r = read_group_contents(b, &mut pos)?;
    if pos != b.len() {
        return Err(CodecError::TrailingBytes {
            remaining: b.len() - pos,
        });
    }
    Ok(r)
}

/// Width of one committed AEAD payload: the 104-byte note plaintext
/// ([`crate::note::NOTE_PLAINTEXT_LEN`]) plus ChaCha20-Poly1305's 16-byte tag.
///
/// 🔴 **Fixed-width, and that is the property the committed region rests on.**
/// `write_group_contents`'s note explains that the region contains no varint at
/// all and therefore admits exactly one byte string per logical group. Relocating
/// the payloads keeps that true only because every payload is the same size — the
/// entry count is already carried by `n_outputs`, so the section needs no length
/// prefix and D6's canonicity question still never gets a chance to matter inside
/// the preimage.
///
/// **It stayed 120 B rather than shrinking to 56.** Issue #188 (a) originally
/// dropped `rkm` and ρ as recipient-derivable; that failed one scanner class down
/// — an `Ivk` deliberately cannot derive `rkm` (issue #32), and `/v1/compact`
/// carries no nullifier so a light client cannot derive ρ. Amended 2026-08-04:
/// *"this is not a size decision"* — 64 B is 0.04 % of a transaction.
pub const PAYLOAD_LEN: usize = crate::note::NOTE_PLAINTEXT_LEN + 16;

// ---- the committed discovery region -----------------------------------------
//
// `group_contents ‖ payloads` — the exact bytes a block body commits to since
// issue #188 (a). Serving still projects only the `group_contents` prefix, so
// `/v1/compact`'s golden vector is untouched and a light server stays a mirror
// of the body rather than a second source.

/// Total entries across all recipients — the payload count, by construction.
pub fn contents_entry_count(recipients: &[RecipientBundle]) -> usize {
    recipients.iter().map(|r| r.entries.len()).sum()
}

/// Encode the committed discovery region. `payloads` is flat, in D4 order
/// (recipient-major, then per-output), one per entry.
///
/// Panics if the count or any width is wrong: those are caller bugs at
/// construction time, not decode failures — the decoder's job is to refuse the
/// same conditions arriving from the wire.
pub fn encode_committed_discovery(
    recipients: &[RecipientBundle],
    payloads: &[Vec<u8>],
) -> Vec<u8> {
    let want = contents_entry_count(recipients);
    assert_eq!(payloads.len(), want, "one payload per discovery entry (D4 order)");
    let mut out = Vec::new();
    write_group_contents(&mut out, recipients);
    for p in payloads {
        assert_eq!(p.len(), PAYLOAD_LEN, "committed payloads are fixed-width");
        out.extend_from_slice(p);
    }
    out
}

/// Decode the committed discovery region, rejecting trailing bytes and any
/// payload section that is not exactly `n_entries × PAYLOAD_LEN`.
///
/// This is the consensus entry point. With no varint in the region, canonicity
/// reduces to **exact consumption** — and the payload section's length being
/// fully determined is what keeps that reduction valid.
pub fn decode_committed_discovery(
    b: &[u8],
) -> Result<(Vec<RecipientBundle>, Vec<Vec<u8>>), CodecError> {
    let mut pos = 0usize;
    let recipients = read_group_contents(b, &mut pos)?;
    let n = contents_entry_count(&recipients);
    let expected = n * PAYLOAD_LEN;
    let got = b.len() - pos;
    if got != expected {
        return Err(CodecError::PayloadSectionLen { expected, got });
    }
    let payloads = (0..n)
        .map(|i| b[pos + i * PAYLOAD_LEN..pos + (i + 1) * PAYLOAD_LEN].to_vec())
        .collect();
    Ok((recipients, payloads))
}

/// The `group_contents` prefix of a committed region — what `/v1/compact`
/// serves. A **projection**, never a re-encoding: the bytes are copied out of the
/// committed blob rather than rebuilt, so serving cannot drift from the body.
pub fn committed_contents_prefix(b: &[u8]) -> Result<&[u8], CodecError> {
    let mut pos = 0usize;
    let _ = read_group_contents(b, &mut pos)?;
    Ok(&b[..pos])
}

/// The committed region's **payload section**, grouped by recipient — what
/// `/v1/block/{h}/tx/{i}/full` serves (issue #188, the serving+open baton).
///
/// A **projection**, exactly like [`committed_contents_prefix`] is for the
/// compact wire: every payload here is a copy of `PAYLOAD_LEN` bytes out of the
/// committed blob. Nothing is re-encoded, nothing is derived, and no second
/// source is consulted — so a served payload cannot differ from the one the
/// block body's preimage covers.
///
/// The grouping is not a choice either. The section is flat and in **D4 order**
/// (recipient-major, then per-output), one payload per entry, so the recipient
/// boundaries are `recipients[i].entries.len()` — the same region's own
/// declaration of its shape. `decode_committed_discovery` has already refused
/// any section whose length is not `n_entries × PAYLOAD_LEN`, so the walk below
/// consumes the flat list exactly.
///
/// The outer list is per recipient **including recipients with no outputs**: a
/// bundle with `n_outputs = 0` contributes an empty payload list, never a
/// missing one, because the served index must be the committed index. A wallet
/// that detected on recipient `i` reads payload list `i`.
pub fn committed_payloads_per_recipient(
    b: &[u8],
) -> Result<Vec<Vec<Vec<u8>>>, CodecError> {
    let (recipients, flat) = decode_committed_discovery(b)?;
    let mut out = Vec::with_capacity(recipients.len());
    let mut pos = 0usize;
    for r in &recipients {
        let n = r.entries.len();
        out.push(flat[pos..pos + n].to_vec());
        pos += n;
    }
    debug_assert_eq!(pos, flat.len(), "the payload count is the entry count, by decode");
    Ok(out)
}

/// The commitments a group's contents describe, in D4's order (recipient-major,
/// then per-output).
pub fn contents_commitments(recipients: &[RecipientBundle]) -> Vec<[u8; CM_LEN]> {
    recipients
        .iter()
        .flat_map(|r| r.entries.iter().map(|e| e.cm))
        .collect()
}

// ---- full group (serving form) -----------------------------------------------

/// Encode one per-tx compact group for the serving wire: `tx_index(varint) ‖
/// contents`. No leading version byte — groups nest inside a versioned response.
pub fn write_group(out: &mut Vec<u8>, g: &CompactGroup) {
    write_varint(out, g.tx_index);
    write_group_contents(out, &g.recipients);
}

pub fn read_group(b: &[u8], pos: &mut usize) -> Result<CompactGroup, CodecError> {
    let tx_index = read_varint(b, pos)?;
    let recipients = read_group_contents(b, pos)?;
    Ok(CompactGroup { tx_index, recipients })
}

/// Encode one group to its own buffer — the bytes `/v1/compact` serves.
pub fn encode_group(g: &CompactGroup) -> Vec<u8> {
    let mut out = Vec::new();
    write_group(&mut out, g);
    out
}

/// Decode **exactly one** serving-form group from a whole buffer, rejecting
/// trailing bytes. `tx_index` canonicity is [`read_varint`]'s job (D6).
pub fn decode_group(b: &[u8]) -> Result<CompactGroup, CodecError> {
    let mut pos = 0usize;
    let g = read_group(b, &mut pos)?;
    if pos != b.len() {
        return Err(CodecError::TrailingBytes {
            remaining: b.len() - pos,
        });
    }
    Ok(g)
}

/// Exact serialized bytes of one compact group (for the measured report).
pub fn group_len(g: &CompactGroup) -> usize {
    encode_group(g).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: u8) -> CompactEntry {
        CompactEntry {
            cm: [seed; 32],
            tag: [seed ^ 0xa5; 8],
            clue: ClueSlot::Empty,
        }
    }

    fn ct_pattern(base: u8) -> [u8; CT_LEN] {
        core::array::from_fn(|i| base.wrapping_add((i % 251) as u8))
    }

    fn sample_group() -> CompactGroup {
        CompactGroup {
            tx_index: 3,
            recipients: vec![
                RecipientBundle { ct: ct_pattern(0x10), entries: vec![entry(1), entry(2)] },
                RecipientBundle { ct: ct_pattern(0x40), entries: vec![entry(9)] },
            ],
        }
    }

    #[test]
    fn group_roundtrips_and_reencodes_to_itself() {
        let g = sample_group();
        let bytes = encode_group(&g);
        let back = decode_group(&bytes).expect("group decodes");
        assert!(groups_eq(&back, &g));
        assert_eq!(encode_group(&back), bytes, "re-encode is byte-identical");
    }

    #[test]
    fn commitments_are_recipient_major_then_per_output() {
        // D4's ordering, asserted as an order and not just a set.
        let g = sample_group();
        assert_eq!(g.commitments(), vec![[1u8; 32], [2u8; 32], [9u8; 32]]);
        assert_eq!(g.n_outputs(), 3);
    }

    #[test]
    fn committed_contents_are_the_serving_group_minus_its_index_varint() {
        // The projection property, as a byte identity rather than a claim:
        // serving = varint(position) ‖ committed_bytes. Nothing is re-encoded.
        let g = sample_group();
        let committed = encode_group_contents(&g.recipients);
        let mut served = Vec::new();
        write_varint(&mut served, g.tx_index);
        served.extend_from_slice(&committed);
        assert_eq!(served, encode_group(&g));
    }

    #[test]
    fn committed_contents_round_trip_and_contain_no_varint() {
        let g = sample_group();
        let bytes = encode_group_contents(&g.recipients);
        let back = decode_group_contents(&bytes).expect("contents decode");
        assert_eq!(encode_group_contents(&back), bytes, "re-encode is byte-identical");
        assert_eq!(contents_commitments(&back), g.commitments());

        // Every field is fixed-width or single-valued, so the length is a pure
        // function of the shape — the arithmetic no varint could satisfy.
        let expected = 1 // n_recipients
            + 2 * (CT_LEN + 1) // two bundles: ct + n_outputs
            + 3 * CompactEntry::LEN_EMPTY_CLUE; // three entries in total
        assert_eq!(bytes.len(), expected);
    }

    fn payload(seed: u8) -> Vec<u8> {
        (0..PAYLOAD_LEN).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    /// The payload section regroups by recipient in D4 order, and every byte it
    /// hands back is a **copy out of the committed blob at its own offset** —
    /// the projection property, asserted as offset arithmetic rather than as a
    /// round-trip through the encoder (a round-trip would pass even if serving
    /// re-encoded).
    #[test]
    fn payloads_project_out_of_the_committed_region_at_their_own_offsets() {
        let g = sample_group(); // recipients: 2 entries, then 1 entry
        let payloads = vec![payload(0x10), payload(0x20), payload(0x30)];
        let committed = encode_committed_discovery(&g.recipients, &payloads);

        let per_recipient = committed_payloads_per_recipient(&committed).expect("decodes");
        assert_eq!(per_recipient.len(), 2, "one list per recipient, including empty ones");
        assert_eq!(per_recipient[0], vec![payload(0x10), payload(0x20)]);
        assert_eq!(per_recipient[1], vec![payload(0x30)]);

        // Byte identity against the blob itself: the section starts where the
        // `group_contents` prefix ends and is `n_entries × PAYLOAD_LEN` long.
        let prefix = committed_contents_prefix(&committed).expect("prefix decodes");
        let start = prefix.len();
        assert_eq!(committed.len() - start, 3 * PAYLOAD_LEN);
        for (i, p) in per_recipient.concat().iter().enumerate() {
            let at = start + i * PAYLOAD_LEN;
            assert_eq!(
                p.as_slice(),
                &committed[at..at + PAYLOAD_LEN],
                "payload {i} is the committed bytes at its own offset, not a re-encoding"
            );
        }
    }

    /// A recipient with no outputs contributes an **empty list, never a missing
    /// one**: the served index has to be the committed index, or a wallet that
    /// detected on recipient `i` would read somebody else's payloads.
    #[test]
    fn a_recipient_with_no_outputs_keeps_its_position_in_the_payload_section() {
        let recipients = vec![
            RecipientBundle { ct: ct_pattern(0x01), entries: vec![] },
            RecipientBundle { ct: ct_pattern(0x02), entries: vec![entry(7)] },
        ];
        let committed = encode_committed_discovery(&recipients, &[payload(0x55)]);
        let per_recipient = committed_payloads_per_recipient(&committed).expect("decodes");
        assert_eq!(per_recipient.len(), 2);
        assert!(per_recipient[0].is_empty(), "position kept, list empty");
        assert_eq!(per_recipient[1], vec![payload(0x55)]);
    }

    /// A region whose payload section is the wrong length is refused by the
    /// decoder before any grouping happens — never grouped into short lists,
    /// which a wallet would read as `PayloadMissing` about a chain that
    /// committed the payload.
    #[test]
    fn a_short_payload_section_is_refused_not_grouped_short() {
        let g = sample_group();
        let payloads = vec![payload(1), payload(2), payload(3)];
        let good = encode_committed_discovery(&g.recipients, &payloads);
        let short = &good[..good.len() - PAYLOAD_LEN];
        assert!(matches!(
            committed_payloads_per_recipient(short),
            Err(CodecError::PayloadSectionLen { expected, got })
                if expected == 3 * PAYLOAD_LEN && got == 2 * PAYLOAD_LEN
        ));
    }

    #[test]
    fn committed_contents_reject_trailing_and_truncation() {
        let g = sample_group();
        let good = encode_group_contents(&g.recipients);
        let mut extra = good.clone();
        extra.push(0x00);
        assert!(matches!(
            decode_group_contents(&extra),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
        assert!(matches!(
            decode_group_contents(&good[..good.len() - 1]),
            Err(CodecError::Truncated { .. })
        ));
        // The empty contents are one byte and nothing else decodes to them.
        assert_eq!(encode_group_contents(&[]), vec![0x00]);
        assert!(decode_group_contents(&[]).is_err());
    }

    #[test]
    fn the_empty_group_is_two_bytes_and_describes_nothing() {
        let g = CompactGroup { tx_index: 0, recipients: vec![] };
        assert_eq!(encode_group(&g), vec![0x00, 0x00], "tx_index=0 ‖ n_recipients=0");
        assert!(g.commitments().is_empty());
    }

    #[test]
    fn a_group_followed_by_junk_is_rejected() {
        let mut bytes = encode_group(&sample_group());
        bytes.push(0xff);
        assert!(matches!(
            decode_group(&bytes),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn a_padded_tx_index_is_rejected() {
        // The one varint in the group framing. `0x83 0x00` and `0x03` are two
        // byte strings for one group; after D6 only one of them decodes.
        let good = encode_group(&sample_group());
        assert_eq!(good[0], 0x03, "tx_index 3 is a one-byte varint");
        let mut padded = vec![0x83, 0x00];
        padded.extend_from_slice(&good[1..]);
        assert!(matches!(
            decode_group(&padded),
            Err(CodecError::NonCanonicalVarint { len: 2 })
        ));
    }
}
