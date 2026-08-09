//! §2 compact-group wire framing — the FROZEN reference bytes.
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
//! All integers little-endian, and every varint is **canonical** — the shortest
//! encoding of its value, one byte string per value ([`read_varint`]). A format
//! version byte leads every response
//! ([`crate::WIRE_VERSION`]). The response wrapper `/v1/compact` returns:
//! ```text
//! version   : u8 (= 0x01)
//! n_blocks  : varint
//!   per block: height(varint) ‖ n_groups(varint) ‖ [group ...]
//! ```
//!
//! The per-output encoding is byte-identical to qlab-note's
//! [`CompactEntry::to_bytes`] for the empty (v1) clue — asserted in tests — so
//! this framing composes with the ratified wire rather than forking it.
//!
//! ## Where the group framing lives (issue #188 baton 1)
//!
//! The **per-tx group** framing (varints, entry, bundle, group) moved to
//! [`qlab_note::compact`] and is re-exported here unchanged, so every existing
//! path — including the golden vector below — reads exactly the bytes it always
//! did. It had to move because `discovery-on-the-consensus-wire.md` D2 puts
//! those exact bytes into the block-body preimage, and `qlab-devnet` (which owns
//! the body) cannot depend on this crate: this crate depends on it. D2 forbids a
//! second encoder, so the framing moved *down* rather than being duplicated —
//! see that module's header for the full reasoning.
//!
//! What stays here is the **response wrapper** (`version ‖ n_blocks ‖ per-block
//! height ‖ n_groups`), a serving envelope no block body commits to.
//!
//! 🔴 **`golden_bytes_lock_the_framing` is now a consensus lock, not a wire
//! lock** (D2): changing those bytes changes `BlockBody::commitment()`.
//!
//! > **Scope narrowed 2026-08-04** (issue #188 (a) as amended, the mint baton's
//! > stage-3 relocation). The line above was written when the framing bytes
//! > *were* the whole of what a body commits. They are now a **prefix** of it.
//! >
//! > **(a) What this golden locks:** the framing of the committed region's
//! > `group_contents` **prefix** — which is exactly the source `/v1/compact`
//! > projects, and therefore still a consensus lock, because a prefix of the
//! > preimage is as load-bearing as the rest of it.
//! >
//! > **(b) Where the whole preimage is locked:**
//! > `qlab_devnet::body::tests::golden_body_commitment_bytes`. When the payload
//! > section moves, **that** is the test that goes red — this one does not, and
//! > must not.
//! >
//! > **(c) Why it narrowed:** stage 3 relocated the AEAD payloads *into* the
//! > committed region (`group_contents ‖ payloads`, one fixed 120-byte payload
//! > per entry). The accepted placement kept the served wire byte-identical via
//! > the projection, so these bytes did not change — **only their scope did.**
//! > Nothing went red, which is precisely why it is written down: a sentence that
//! > stays true while quietly meaning less than it says is the failure mode this
//! > baton has now hit twice (the other was `Ivk`'s "scanning is unaffected").

pub use qlab_note::compact::{
    committed_contents_prefix, committed_payloads_per_recipient, contents_commitments,
    contents_entry_count, decode_committed_discovery, decode_group, decode_group_contents,
    encode_committed_discovery, encode_group, encode_group_contents, group_len, groups_eq,
    read_bundle, read_entry, read_group, read_group_contents, read_varint, write_bundle,
    write_entry, write_group, write_group_contents, write_varint, CodecError, CompactGroup,
    PAYLOAD_LEN,
};

use crate::WIRE_VERSION;

/// One block's compact groups (the unit `/v1/compact` streams).
#[derive(Clone)]
pub struct CompactBlock {
    pub height: u64,
    pub groups: Vec<CompactGroup>,
}

// ---- /v1/compact response ----------------------------------------------------

/// Encode a range-stream response: `version ‖ n_blocks ‖ [height ‖ n_groups ‖ groups]`.
pub fn encode_compact_response(blocks: &[CompactBlock]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(WIRE_VERSION);
    write_varint(&mut out, blocks.len() as u64);
    for blk in blocks {
        write_varint(&mut out, blk.height);
        write_varint(&mut out, blk.groups.len() as u64);
        for g in &blk.groups {
            write_group(&mut out, g);
        }
    }
    out
}

/// Decode a `/v1/compact` range-stream response. Rejects trailing bytes.
pub fn decode_compact_response(b: &[u8]) -> Result<Vec<CompactBlock>, CodecError> {
    let mut pos = 0usize;
    let ver = *b.get(pos).ok_or(CodecError::Truncated { what: "version" })?;
    pos += 1;
    if ver != WIRE_VERSION {
        return Err(CodecError::BadVersion { got: ver });
    }
    let n_blocks = read_varint(b, &mut pos)?;
    let mut blocks = Vec::with_capacity(n_blocks as usize);
    for _ in 0..n_blocks {
        let height = read_varint(b, &mut pos)?;
        let n_groups = read_varint(b, &mut pos)?;
        let mut groups = Vec::with_capacity(n_groups as usize);
        for _ in 0..n_groups {
            groups.push(read_group(b, &mut pos)?);
        }
        blocks.push(CompactBlock { height, groups });
    }
    if pos != b.len() {
        return Err(CodecError::TrailingBytes {
            remaining: b.len() - pos,
        });
    }
    Ok(blocks)
}

// ---- /v1/block/<h>/tx/<i>/full response --------------------------------------

/// Encode the full-fetch payloads for one tx (the AEAD ciphertexts a wallet
/// pulls only for matched notes): `version ‖ n_recipients ‖ [n_payloads ‖
/// [payload_len(varint) ‖ payload_bytes]]`.
pub fn encode_full_response(payloads_per_recipient: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(WIRE_VERSION);
    debug_assert!(payloads_per_recipient.len() <= u8::MAX as usize);
    out.push(payloads_per_recipient.len() as u8);
    for payloads in payloads_per_recipient {
        debug_assert!(payloads.len() <= u8::MAX as usize);
        out.push(payloads.len() as u8);
        for p in payloads {
            write_varint(&mut out, p.len() as u64);
            out.extend_from_slice(p);
        }
    }
    out
}

/// Decode a `/full` response into per-recipient payload lists.
pub fn decode_full_response(b: &[u8]) -> Result<Vec<Vec<Vec<u8>>>, CodecError> {
    let mut pos = 0usize;
    let ver = *b.get(pos).ok_or(CodecError::Truncated { what: "version" })?;
    pos += 1;
    if ver != WIRE_VERSION {
        return Err(CodecError::BadVersion { got: ver });
    }
    let n_recipients = *b
        .get(pos)
        .ok_or(CodecError::Truncated { what: "n_recipients" })?;
    pos += 1;
    let mut out = Vec::with_capacity(n_recipients as usize);
    for _ in 0..n_recipients {
        let n_payloads = *b
            .get(pos)
            .ok_or(CodecError::Truncated { what: "n_payloads" })?;
        pos += 1;
        let mut payloads = Vec::with_capacity(n_payloads as usize);
        for _ in 0..n_payloads {
            let len = read_varint(b, &mut pos)? as usize;
            if b.len() < pos + len {
                return Err(CodecError::Truncated { what: "payload" });
            }
            payloads.push(b[pos..pos + len].to_vec());
            pos += len;
        }
        out.push(payloads);
    }
    if pos != b.len() {
        return Err(CodecError::TrailingBytes {
            remaining: b.len() - pos,
        });
    }
    Ok(out)
}

// ---- /v1/nullifiers response (lab issue #314) --------------------------------

/// The most main-chain blocks one `/v1/nullifiers` response will ever carry.
///
/// The same contract shape, and the same number, as `qlab_node`'s
/// `MAX_COMPACT_BLOCKS` — on purpose, because the client that pages this stream
/// is the client that pages `/v1/compact`, over the same requested range. A
/// response carries every height in `[from, to]` the server holds, up to this
/// many blocks; a client whose page ends below `to` resumes from the last
/// height + 1. `[devnet-placeholder]`, testnet-tunable, NOT frozen: the framing
/// carries `n_blocks` and every height explicitly, so this bound can move
/// without touching a golden.
pub const MAX_NULLIFIER_BLOCKS: usize = 1024;

/// One block's spent nullifiers, as the block published them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockNullifiers {
    pub height: u64,
    /// The block's nullifier section, in block order (transaction order, then
    /// each transaction's declared order). **Empty is a real answer**: a block
    /// that spends nothing carries an empty list and is served as such.
    pub nullifiers: Vec<[u8; 32]>,
}

/// One page of the chain's per-block nullifier lists (`GET
/// /v1/nullifiers?from=&to=` — lab issue #314).
///
/// ## What this is for, and why it is safe to serve
///
/// A wallet's `spendable` is computed from outputs, and a discovery group
/// deliberately carries no nullifier (#188 (a) as amended, under #32's `Ivk`
/// boundary) — so before this wire existed **nothing in a scan could learn that
/// a note it opened had since been spent**, and every wallet that had ever spent
/// over-quoted its balance under `verdict: complete`. This is the missing half:
/// the server publishes the nullifiers each block already committed, the wallet
/// derives its own notes' nullifiers from keys only it holds, and the match
/// happens **locally**.
///
/// 🔴 **Bulk per range, never a membership query.** There is no
/// `?nullifier=<nf>` form of this route and there must never be one: asking a
/// server "is nf X spent" tells that server which notes are the asker's, which
/// is exactly the linkage the discovery design refuses. The bytes here are
/// already public — consensus published every one of them to enforce the
/// double-spend rule — so serving them adds nothing an `Ivk` could not already
/// obtain; a probe would add the **question**, and the question is the leak.
///
/// ## Wire — the compact family's version byte, deliberately
///
/// `version ‖ from(varint) ‖ to(varint) ‖ n_blocks(varint) ‖
///  [height(varint) ‖ n(varint) ‖ nf(32) × n] × n_blocks`
///
/// It lives in this module, at [`WIRE_VERSION`], rather than beside the node's
/// own surfaces, because it is a **sibling of `/v1/compact` by every structural
/// test**: same projection, same `[from, to]` range paging, same light client,
/// and served by both this reference server and a deployed `qumbra-node`. A
/// wallet pointed at either must be able to subtract its spends, and a wire that
/// only one of them could speak would have left the reference server serving a
/// balance nobody may quote.
///
/// Adding a wire to this family does not move its version: every existing
/// payload is byte-for-byte what it was, and an older server simply 404s, which
/// the client renders as `UNAVAILABLE` with the reason (that refusal is required
/// behaviour here, not a fallback).
///
/// `from`/`to` are echoed so a paging client cannot misattribute a page (the
/// leaf stream's discipline). Heights are ascending and **every** height the
/// server holds in range is present, including the ones that spend nothing — an
/// omitted height is indistinguishable from an unserved one, and "this block
/// spent nothing" is precisely the fact a balance subtracts against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierPage {
    /// Echo of the request's `from`.
    pub from: u64,
    /// Echo of the request's `to`.
    pub to: u64,
    /// Ascending by height; at most [`MAX_NULLIFIER_BLOCKS`] entries.
    pub blocks: Vec<BlockNullifiers>,
}

impl NullifierPage {
    /// Build the page for `[from, to]` over an **ascending** per-block source,
    /// applying the bound. One implementation of the truncation arithmetic, used
    /// by every server that serves this route.
    pub fn page(
        blocks: impl IntoIterator<Item = BlockNullifiers>,
        from: u64,
        to: u64,
    ) -> NullifierPage {
        let mut out = Vec::new();
        for b in blocks {
            if b.height < from || b.height > to {
                continue;
            }
            if out.len() == MAX_NULLIFIER_BLOCKS {
                break;
            }
            out.push(b);
        }
        NullifierPage { from, to, blocks: out }
    }

    /// The highest height this page carries — where a paging client resumes
    /// from (`+ 1`).
    pub fn last_height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.height)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(WIRE_VERSION);
        write_varint(&mut out, self.from);
        write_varint(&mut out, self.to);
        write_varint(&mut out, self.blocks.len() as u64);
        for b in &self.blocks {
            write_varint(&mut out, b.height);
            write_varint(&mut out, b.nullifiers.len() as u64);
            for nf in &b.nullifiers {
                out.extend_from_slice(nf);
            }
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<NullifierPage, CodecError> {
        let mut pos = 0usize;
        let ver = *b.get(pos).ok_or(CodecError::Truncated { what: "version" })?;
        pos += 1;
        if ver != WIRE_VERSION {
            return Err(CodecError::BadVersion { got: ver });
        }
        let from = read_varint(b, &mut pos)?;
        let to = read_varint(b, &mut pos)?;
        let n_blocks = read_varint(b, &mut pos)?;
        // Both counts are attacker-adjacent input on a served wire: cap every
        // allocation by what the remaining bytes could actually hold, so a tiny
        // payload claiming 2^60 entries is a `Truncated` refusal and not a giant
        // allocation.
        let mut blocks = Vec::with_capacity((n_blocks as usize).min(b.len() / 2));
        for _ in 0..n_blocks {
            let height = read_varint(b, &mut pos)?;
            let n = read_varint(b, &mut pos)?;
            let mut nullifiers = Vec::with_capacity((n as usize).min(b.len() / 32));
            for _ in 0..n {
                if b.len() < pos + 32 {
                    return Err(CodecError::Truncated { what: "nullifier" });
                }
                nullifiers.push(b[pos..pos + 32].try_into().expect("32 bytes"));
                pos += 32;
            }
            blocks.push(BlockNullifiers { height, nullifiers });
        }
        if pos != b.len() {
            return Err(CodecError::TrailingBytes { remaining: b.len() - pos });
        }
        Ok(NullifierPage { from, to, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::reference::keccak_f;
    use qlab_note::kem::CT_LEN;
    use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};

    // Field-wise bundle equality (RecipientBundle derives Clone only).
    fn bundle_eq(a: &RecipientBundle, b: &RecipientBundle) -> bool {
        a.ct == b.ct && a.entries == b.entries
    }

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

    // ---- varint ----
    #[test]
    fn varint_roundtrip_edge_values() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let mut pos = 0;
            assert_eq!(read_varint(&out, &mut pos).unwrap(), v);
            assert_eq!(pos, out.len(), "varint consumes exactly its bytes for {v}");
        }
        // Known encodings.
        let mut o = Vec::new();
        write_varint(&mut o, 300);
        assert_eq!(o, vec![0xac, 0x02], "LEB128(300) = ac 02");
    }

    #[test]
    fn varint_overflow_rejected() {
        // 11 continuation bytes cannot be a u64.
        let bad = vec![0x80u8; 11];
        let mut pos = 0;
        assert_eq!(read_varint(&bad, &mut pos), Err(CodecError::VarintOverflow));
    }

    /// Append one padding byte: set the continuation bit on the current last
    /// byte and add a zero group. Same value, one byte longer, non-canonical.
    fn pad_once(v: &[u8]) -> Vec<u8> {
        let mut out = v.to_vec();
        *out.last_mut().expect("varint is never empty") |= 0x80;
        out.push(0x00);
        out
    }

    #[test]
    fn padded_zero_is_rejected_and_bare_zero_is_accepted() {
        // D6, the exact pair the spec names: `0x80 0x00` and `0x00` are two byte
        // strings for one value, and that is what a consensus commitment cannot
        // tolerate. After this change only one of them decodes at all.
        let mut pos = 0;
        assert_eq!(read_varint(&[0x00], &mut pos), Ok(0), "bare 0x00 is canonical 0");
        assert_eq!(pos, 1, "and consumes exactly its one byte");

        let mut pos = 0;
        assert_eq!(
            read_varint(&[0x80, 0x00], &mut pos),
            Err(CodecError::NonCanonicalVarint { len: 2 }),
            "0x80 0x00 is a padded 0 and is rejected"
        );

        // The property, stated as the spec states it: they no longer decode to
        // the same value, because the padded one no longer decodes.
        let mut p1 = 0;
        let mut p2 = 0;
        let canonical = read_varint(&[0x00], &mut p1);
        let padded = read_varint(&[0x80, 0x00], &mut p2);
        assert_ne!(canonical, padded, "one value, one byte string");

        // The same holds one value up: `0x81 0x00` vs `0x01`.
        let mut pos = 0;
        assert_eq!(read_varint(&[0x01], &mut pos), Ok(1));
        let mut pos = 0;
        assert_eq!(
            read_varint(&[0x81, 0x00], &mut pos),
            Err(CodecError::NonCanonicalVarint { len: 2 })
        );
    }

    #[test]
    fn canonical_varints_over_a_range_accept_encoder_output_and_reject_padding() {
        // A range, not a hand-picked pair: one example proves the check exists,
        // a range proves it is the *shortest-encoding* check and not something
        // that merely happens to catch `0x80 0x00`.
        let values: Vec<u64> = (0u64..=1_000)
            .chain([
                126, 127, 128, 129, 16_382, 16_383, 16_384, 16_385,
                2_097_151, 2_097_152, u32::MAX as u64, u32::MAX as u64 + 1,
                u64::MAX / 2, u64::MAX - 1, u64::MAX,
            ])
            .collect();

        for v in values {
            let mut enc = Vec::new();
            write_varint(&mut enc, v);

            // 1. The encoder's output decodes, round-trips, and is consumed whole.
            let mut pos = 0;
            assert_eq!(read_varint(&enc, &mut pos), Ok(v), "round-trip {v}");
            assert_eq!(pos, enc.len(), "consumes exactly its bytes for {v}");

            // 2. It re-encodes to itself — §4's "re-encode to themselves" check
            //    holds by construction once the decoder is canonical.
            let mut re = Vec::new();
            write_varint(&mut re, v);
            assert_eq!(re, enc, "re-encode is byte-identical for {v}");

            // 3. The encoder never emits a padded form: only a 1-byte encoding
            //    may end in 0x00.
            assert!(
                enc.len() == 1 || *enc.last().unwrap() != 0x00,
                "write_varint emits the shortest encoding for {v}"
            );

            // 4. The one-byte-longer variant of the SAME value is rejected.
            let padded = pad_once(&enc);
            assert_eq!(padded.len(), enc.len() + 1);
            let mut pos = 0;
            let got = read_varint(&padded, &mut pos);
            if enc.len() == 10 {
                // An 11-byte varint cannot be a u64 at all; the ≤10-byte ceiling
                // fires first and the value is still refused. Reported as
                // overflow, not non-canonical — the length guard is the older
                // and stricter statement about the same bytes.
                assert_eq!(got, Err(CodecError::VarintOverflow), "padded {v} (10-byte)");
            } else {
                assert_eq!(
                    got,
                    Err(CodecError::NonCanonicalVarint { len: enc.len() + 1 }),
                    "padded {v}"
                );
            }

            // 5. Two bytes of padding are refused too (padding is not a parity
            //    trick), where the ≤10-byte ceiling leaves room for it.
            if enc.len() <= 8 {
                let mut pos = 0;
                assert_eq!(
                    read_varint(&pad_once(&padded), &mut pos),
                    Err(CodecError::NonCanonicalVarint { len: enc.len() + 2 }),
                    "twice-padded {v}"
                );
            }
        }
    }

    #[test]
    fn compact_response_rejects_a_padded_varint_field() {
        // The check has to reach the wire path, not just the primitive: a
        // response whose `n_blocks` is padded must not decode. Hand-built,
        // because the encoder cannot produce this.
        let good = encode_compact_response(&sample_blocks());
        assert!(decode_compact_response(&good).is_ok());

        // good[1] is n_blocks (= 3, one byte). Replace it with 0x83 0x00.
        let mut padded = Vec::new();
        padded.push(good[0]);
        padded.extend_from_slice(&[good[1] | 0x80, 0x00]);
        padded.extend_from_slice(&good[2..]);
        assert!(
            matches!(
                decode_compact_response(&padded),
                Err(CodecError::NonCanonicalVarint { len: 2 })
            ),
            "a padded n_blocks is refused by the response decoder"
        );
    }

    #[test]
    fn truncation_is_still_reported_as_truncation_not_canonicity() {
        // The stricter varint must not move where a short buffer is reported:
        // a buffer cut mid-varint is Truncated, and one cut mid-body is caught
        // by the body reader, exactly as before.
        let mut pos = 0;
        assert_eq!(
            read_varint(&[0x80], &mut pos),
            Err(CodecError::Truncated { what: "varint" }),
            "a continuation byte with nothing after it is truncation"
        );

        let good = encode_compact_response(&sample_blocks());
        for cut in [1usize, 2, 3, 5, 50, good.len() - 1] {
            assert!(
                matches!(
                    decode_compact_response(&good[..cut]),
                    Err(CodecError::Truncated { .. })
                ),
                "prefix of length {cut} is reported as truncation"
            );
        }

        // And TrailingBytes still wins when there is a whole message plus extra.
        let mut extra = good.clone();
        extra.push(0xff);
        assert!(matches!(
            decode_compact_response(&extra),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
    }

    // ---- per-output equivalence to qlab-note ----
    #[test]
    fn entry_encoding_equals_qlab_note_compact_entry() {
        // THE composition guarantee: §2's `cm ‖ tag ‖ clue_len=0` is exactly
        // qlab-note's CompactEntry::to_bytes() for the empty clue.
        let e = entry(0x3c);
        let mut mine = Vec::new();
        write_entry(&mut mine, &e);
        assert_eq!(mine, e.to_bytes(), "§2 per-output == qlab-note CompactEntry bytes");
        assert_eq!(mine.len(), CompactEntry::LEN_EMPTY_CLUE);
    }

    #[test]
    fn unsupported_clue_rejected() {
        let e = entry(1);
        let mut b = Vec::new();
        write_entry(&mut b, &e);
        b[40] = 0x01; // non-empty clue version/len
        let mut pos = 0;
        assert_eq!(
            read_entry(&b, &mut pos),
            Err(CodecError::UnsupportedClue { clue_len: 1 })
        );
    }

    // ---- group / response round-trip ----
    fn sample_blocks() -> Vec<CompactBlock> {
        let r_2of1 = RecipientBundle {
            ct: ct_pattern(0x10),
            entries: vec![entry(1), entry(2)],
        };
        let r_1of1 = RecipientBundle {
            ct: ct_pattern(0x40),
            entries: vec![entry(9)],
        };
        vec![
            CompactBlock {
                height: 5,
                groups: vec![
                    CompactGroup { tx_index: 0, recipients: vec![r_2of1.clone()] },
                    CompactGroup { tx_index: 1, recipients: vec![r_1of1.clone(), r_2of1.clone()] },
                ],
            },
            CompactBlock { height: 6, groups: vec![] }, // empty block
            CompactBlock {
                height: 300, // multi-byte varint height
                groups: vec![CompactGroup { tx_index: 130, recipients: vec![r_1of1] }],
            },
        ]
    }

    #[test]
    fn compact_response_roundtrip() {
        let blocks = sample_blocks();
        let bytes = encode_compact_response(&blocks);
        let back = decode_compact_response(&bytes).unwrap();
        assert_eq!(back.len(), blocks.len());
        for (a, b) in back.iter().zip(&blocks) {
            assert_eq!(a.height, b.height);
            assert_eq!(a.groups.len(), b.groups.len());
            for (ga, gb) in a.groups.iter().zip(&b.groups) {
                assert_eq!(ga.tx_index, gb.tx_index);
                assert_eq!(ga.recipients.len(), gb.recipients.len());
                for (ra, rb) in ga.recipients.iter().zip(&gb.recipients) {
                    assert!(bundle_eq(ra, rb), "recipient bundle round-trips");
                }
            }
        }
    }

    #[test]
    fn decode_rejects_bad_version_and_trailing() {
        let mut bytes = encode_compact_response(&sample_blocks());
        let good = bytes.clone();
        bytes[0] = 0x02;
        assert!(matches!(
            decode_compact_response(&bytes),
            Err(CodecError::BadVersion { got: 2 })
        ));
        let mut extra = good.clone();
        extra.push(0xff);
        assert!(matches!(
            decode_compact_response(&extra),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
        // Truncation anywhere is caught.
        assert!(decode_compact_response(&good[..good.len() - 1]).is_err());
    }

    #[test]
    fn full_response_roundtrip() {
        let payloads = vec![
            vec![vec![1u8, 2, 3], vec![4, 5]],
            vec![vec![9u8; 100]],
        ];
        let bytes = encode_full_response(&payloads);
        assert_eq!(decode_full_response(&bytes).unwrap(), payloads);
    }

    /// GOLDEN BYTES — this crate is the reference; these bytes lock the §2
    /// framing. A single known compact group with deterministic ct/cm/tag; we
    /// assert the exact header framing bytes, the exact total length, and a
    /// Keccak-256 digest over the whole serialization. Any framing drift breaks
    /// this test (and thus the spec's meaning).
    #[test]
    fn golden_bytes_lock_the_framing() {
        // One block (height 7), one tx (index 2), one recipient (2-of-1),
        // deterministic ct filled 0x00,0x01,... and two fixed entries.
        let ct: [u8; CT_LEN] = core::array::from_fn(|i| (i % 256) as u8);
        let e0 = CompactEntry { cm: [0xAA; 32], tag: [0xBB; 8], clue: ClueSlot::Empty };
        let e1 = CompactEntry { cm: [0xCC; 32], tag: [0xDD; 8], clue: ClueSlot::Empty };
        let group = CompactGroup {
            tx_index: 2,
            recipients: vec![RecipientBundle { ct, entries: vec![e0, e1] }],
        };
        let block = CompactBlock { height: 7, groups: vec![group] };
        let bytes = encode_compact_response(&[block]);

        // Exact total length: version(1) + n_blocks(1) + height(1) + n_groups(1)
        //   + tx_index(1) + n_recipients(1) + ct(1088) + n_outputs(1)
        //   + 2 * (cm 32 + tag 8 + clue_len 1) = 4 + 2 + 1088 + 1 + 82 = 1177.
        assert_eq!(bytes.len(), 1177, "golden total length");

        // Exact framing header (everything up to the ct): version, n_blocks,
        // height, n_groups, tx_index, n_recipients.
        assert_eq!(&bytes[..6], &[0x01, 0x01, 0x07, 0x01, 0x02, 0x01], "golden header");
        // ct occupies bytes 6..1094 and equals the known pattern.
        assert_eq!(&bytes[6..6 + CT_LEN], &ct[..], "golden ct region");
        // n_outputs then the two entries.
        assert_eq!(bytes[6 + CT_LEN], 0x02, "golden n_outputs");
        let off = 6 + CT_LEN + 1;
        assert_eq!(&bytes[off..off + 32], &[0xAA; 32], "golden e0.cm");
        assert_eq!(&bytes[off + 32..off + 40], &[0xBB; 8], "golden e0.tag");
        assert_eq!(bytes[off + 40], 0x00, "golden e0.clue_len");
        assert_eq!(&bytes[off + 41..off + 73], &[0xCC; 32], "golden e1.cm");
        assert_eq!(&bytes[off + 73..off + 81], &[0xDD; 8], "golden e1.tag");
        assert_eq!(bytes[off + 81], 0x00, "golden e1.clue_len");

        // Whole-serialization Keccak-256 digest (via qlab-air's permutation) —
        // the single value that locks every byte at once.
        let digest = keccak256_bytes(&bytes);
        assert_eq!(
            hex(&digest),
            "3ee2a5e66192bdba4d86e3f6283edbf8ed842f2ef854b724e60b071c9cf54017",
            "GOLDEN digest — update ONLY with an intentional, documented framing change"
        );

        // Round-trips.
        let back = decode_compact_response(&bytes).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].height, 7);
        assert_eq!(back[0].groups[0].tx_index, 2);
    }

    // ---- /v1/nullifiers (lab issue #314) ------------------------------------

    /// GOLDEN BYTES — the nullifier-stream framing. Same class as
    /// `/v1/compact`'s: a *served* wire a wallet's balance depends on, so it
    /// freezes deliberately with byte-exact vectors rather than by accident.
    ///
    /// The empty-block entry is part of the golden on purpose: a height that
    /// spends nothing must be *present and empty*, because an omitted height is
    /// indistinguishable from an unserved one and a client that cannot tell
    /// those apart cannot honestly say whether it covered the range.
    #[test]
    fn golden_bytes_lock_the_nullifier_stream_framing() {
        let page = NullifierPage {
            from: 4,
            to: 6,
            blocks: vec![
                BlockNullifiers { height: 4, nullifiers: vec![[0xA1; 32], [0xB2; 32]] },
                BlockNullifiers { height: 5, nullifiers: vec![] },
                BlockNullifiers { height: 6, nullifiers: vec![[0xC3; 32]] },
            ],
        };
        let bytes = page.to_bytes();

        // version(1) + from(1) + to(1) + n_blocks(1) = 4, then
        //   height(1) + n(1) + 2 × 32 = 66
        //   height(1) + n(1)          =  2
        //   height(1) + n(1) + 1 × 32 = 34
        assert_eq!(bytes.len(), 4 + 66 + 2 + 34, "golden total length");
        assert_eq!(
            &bytes[..4],
            &[0x01, 0x04, 0x06, 0x03],
            "golden header — WIRE_VERSION, from, to, n_blocks (the compact family's varints)"
        );
        assert_eq!(&bytes[4..6], &[0x04, 0x02], "golden block 0: height, n");
        assert_eq!(&bytes[6..38], &[0xA1; 32], "golden block 0 nf 0");
        assert_eq!(&bytes[38..70], &[0xB2; 32], "golden block 0 nf 1");
        assert_eq!(
            &bytes[70..72],
            &[0x05, 0x00],
            "golden block 1 — a block that spends nothing IS served, with n = 0"
        );
        assert_eq!(&bytes[72..74], &[0x06, 0x01], "golden block 2: height, n");
        assert_eq!(&bytes[74..106], &[0xC3; 32], "golden block 2 nf 0");

        let digest = keccak256_bytes(&bytes);
        assert_eq!(
            hex(&digest),
            "c99f517c19b564dbb07356acc46850368d9eba037512a7327a7f0e7ff9aab85c",
            "GOLDEN digest — update ONLY with an intentional, documented framing change"
        );

        assert_eq!(NullifierPage::from_bytes(&bytes).unwrap(), page, "and it round-trips");

        // The empty page — "I hold nothing in that range" — is framing too.
        let empty = NullifierPage { from: 9, to: 9, blocks: vec![] };
        let ebytes = empty.to_bytes();
        assert_eq!(ebytes, vec![0x01, 0x09, 0x09, 0x00], "golden empty page");
        assert_eq!(NullifierPage::from_bytes(&ebytes).unwrap(), empty);
    }

    /// The nullifier wire rejects exactly like the compact wire, and a claimed
    /// count the bytes cannot hold is a refusal rather than an allocation — at
    /// BOTH levels of the framing (blocks and nullifiers).
    #[test]
    fn nullifier_stream_rejects_bad_version_trailing_truncation_and_count_lies() {
        let good = NullifierPage {
            from: 0,
            to: 1,
            blocks: vec![BlockNullifiers { height: 1, nullifiers: vec![[0x11; 32]] }],
        }
        .to_bytes();
        assert_eq!(NullifierPage::from_bytes(&good).unwrap().blocks.len(), 1);

        let mut bad_v = good.clone();
        bad_v[0] = 0x02;
        assert_eq!(
            NullifierPage::from_bytes(&bad_v),
            Err(CodecError::BadVersion { got: 2 })
        );

        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(
            NullifierPage::from_bytes(&extra),
            Err(CodecError::TrailingBytes { .. })
        ));

        assert!(matches!(
            NullifierPage::from_bytes(&good[..good.len() - 1]),
            Err(CodecError::Truncated { .. })
        ));

        // A header claiming 2^60 blocks, and a block claiming 2^60 nullifiers:
        // `Truncated` both times, never a giant allocation.
        let mut lie_blocks = vec![WIRE_VERSION];
        write_varint(&mut lie_blocks, 0);
        write_varint(&mut lie_blocks, 0);
        write_varint(&mut lie_blocks, 1u64 << 60);
        assert!(matches!(
            NullifierPage::from_bytes(&lie_blocks),
            Err(CodecError::Truncated { .. })
        ));

        let mut lie_nfs = vec![WIRE_VERSION];
        write_varint(&mut lie_nfs, 0);
        write_varint(&mut lie_nfs, 0);
        write_varint(&mut lie_nfs, 1);
        write_varint(&mut lie_nfs, 0);
        write_varint(&mut lie_nfs, 1u64 << 60);
        assert!(matches!(
            NullifierPage::from_bytes(&lie_nfs),
            Err(CodecError::Truncated { .. })
        ));
    }

    /// The page arithmetic: bounded at [`MAX_NULLIFIER_BLOCKS`], the client
    /// resumes from the last height + 1, and a range the source does not reach
    /// is an **empty page**, never an error.
    ///
    /// This is lab issue #312's paging contract on a second route, and it is why
    /// the client half ships in the same change: a truncated page that read as a
    /// complete one would leave a wallet quietly failing to subtract a spend in
    /// the missing tail.
    #[test]
    fn nullifier_pages_are_bounded_and_the_client_resumes_from_the_last_height() {
        let all: Vec<BlockNullifiers> = (0..MAX_NULLIFIER_BLOCKS as u64 + 5)
            .map(|h| {
                let mut nf = [0u8; 32];
                nf[..8].copy_from_slice(&h.to_le_bytes());
                BlockNullifiers { height: h, nullifiers: vec![nf] }
            })
            .collect();

        let p0 = NullifierPage::page(all.iter().cloned(), 0, u64::MAX);
        assert_eq!(
            p0.blocks.len(),
            MAX_NULLIFIER_BLOCKS,
            "a full page is the bound, not the chain"
        );
        assert_eq!(p0.last_height(), Some(MAX_NULLIFIER_BLOCKS as u64 - 1));
        assert!(p0.last_height().unwrap() < p0.to, "…and it visibly ends below the request");

        let p1 = NullifierPage::page(all.iter().cloned(), p0.last_height().unwrap() + 1, u64::MAX);
        assert_eq!(p1.blocks.len(), 5, "the rest arrives on the next page");
        assert_eq!(p1.blocks[0].height, MAX_NULLIFIER_BLOCKS as u64);

        let beyond = NullifierPage::page(all.iter().cloned(), 99_999, 100_000);
        assert!(beyond.blocks.is_empty(), "a range the source does not hold is empty, not an error");
        assert_eq!((beyond.from, beyond.to), (99_999, 100_000), "the echoes are the request's");
    }

    // Local Keccak-256 (original pad10*1) over qlab-air's permutation, mirroring
    // qlab_note::hash::keccak256 without depending on its privacy.
    fn keccak256_bytes(input: &[u8]) -> [u8; 32] {
        const RATE: usize = 136;
        let mut state = [0u64; 25];
        let mut chunks = input.chunks_exact(RATE);
        for block in &mut chunks {
            xor_rate(&mut state, block.try_into().unwrap());
            state = keccak_f(&state);
        }
        let rem = chunks.remainder();
        let mut last = [0u8; RATE];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] ^= 0x01;
        last[RATE - 1] ^= 0x80;
        xor_rate(&mut state, &last);
        state = keccak_f(&state);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        out
    }
    fn xor_rate(state: &mut [u64; 25], block: &[u8; 136]) {
        for (i, lane) in state.iter_mut().take(17).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *lane ^= u64::from_le_bytes(b);
        }
    }
    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
