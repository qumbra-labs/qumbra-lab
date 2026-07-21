//! Compact-entry wire layout — the ratified Decision 1/2 shape.
//!
//! Per-note compact entry (note-discovery.md §2 table):
//!
//! | cm 32 B | ML-KEM-768 ct 1,088 B shared per (tx, recipient) | tag 8 B | clue 1 B (empty, versioned) |
//!
//! The ML-KEM ciphertext is **amortized**: stored ONCE per `(tx, recipient)`
//! in a [`RecipientBundle`], not repeated per note. The AEAD payload/memo is
//! NOT part of this compact stream — it is full-fetched only for matched notes
//! (see `scan`). Amortized bytes/note = `32 + 8 + 1 + ceil(1088 / k)`.

use crate::derive::TAG_LEN;
use crate::kem::CT_LEN;

/// Note-commitment length on the wire (little-endian lanes of the `[u64;4]`).
pub const CM_LEN: usize = 32;
/// Clue-slot byte value meaning "empty / no clue" at launch.
pub const CLUE_EMPTY: u8 = 0x00;

/// The versioned clue slot — Decision 2's genesis byte-reservation. Empty at
/// launch (1 byte `0x00`); a future network upgrade activates a fixed-size
/// (~1 KB) OMR clue behind a non-zero version. Reserving the byte now is the
/// whole point of Decision 2 (fields retrofit, bytes in a fixed format do not).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClueSlot {
    /// No clue (launch). Serializes to a single `0x00` byte.
    Empty,
}

impl ClueSlot {
    pub fn serialized_len(&self) -> usize {
        match self {
            ClueSlot::Empty => 1,
        }
    }
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            ClueSlot::Empty => out.push(CLUE_EMPTY),
        }
    }
}

/// One compact per-note entry. The shared ML-KEM ct lives in the bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompactEntry {
    /// Note commitment (authenticity anchor; little-endian lanes).
    pub cm: [u8; CM_LEN],
    /// Detection tag (post-decap filter before full-fetch).
    pub tag: [u8; TAG_LEN],
    /// Versioned clue slot (empty at launch).
    pub clue: ClueSlot,
}

impl CompactEntry {
    /// Serialized length with an empty clue: cm(32) + tag(8) + clue(1).
    pub const LEN_EMPTY_CLUE: usize = CM_LEN + TAG_LEN + 1;

    pub fn serialized_len(&self) -> usize {
        CM_LEN + TAG_LEN + self.clue.serialized_len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_len());
        out.extend_from_slice(&self.cm);
        out.extend_from_slice(&self.tag);
        self.clue.write(&mut out);
        out
    }

    /// Parse one entry, returning it and the number of bytes consumed.
    /// Returns `None` on a short buffer or an unsupported (non-empty) clue
    /// version — the launch format only carries the empty clue.
    pub fn from_bytes(b: &[u8]) -> Option<(CompactEntry, usize)> {
        if b.len() < Self::LEN_EMPTY_CLUE {
            return None;
        }
        let mut cm = [0u8; CM_LEN];
        cm.copy_from_slice(&b[..CM_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&b[CM_LEN..CM_LEN + TAG_LEN]);
        let clue_byte = b[CM_LEN + TAG_LEN];
        if clue_byte != CLUE_EMPTY {
            return None; // reserved: OMR clue not supported until activation
        }
        Some((
            CompactEntry {
                cm,
                tag,
                clue: ClueSlot::Empty,
            },
            Self::LEN_EMPTY_CLUE,
        ))
    }
}

/// All compact entries for one `(tx, recipient)` sharing a single ML-KEM ct.
#[derive(Clone)]
pub struct RecipientBundle {
    /// The shared 1,088-B ML-KEM-768 ciphertext (amortized across `entries`).
    pub ct: [u8; CT_LEN],
    /// One compact entry per output to this recipient.
    pub entries: Vec<CompactEntry>,
}

impl RecipientBundle {
    /// Total compact-stream bytes a wallet downloads for this bundle:
    /// the shared ct once + every entry.
    pub fn compact_stream_len(&self) -> usize {
        CT_LEN + self.entries.iter().map(|e| e.serialized_len()).sum::<usize>()
    }
}

/// Amortized compact-stream bytes per note for a recipient with `k` outputs in
/// one tx: `cm(32) + tag(8) + clue(1) + ceil(1088 / k)`.
pub fn bytes_per_note_amortized(k: usize) -> usize {
    assert!(k >= 1, "a recipient bundle has at least one output");
    let ct_share = CT_LEN.div_ceil(k);
    CM_LEN + TAG_LEN + 1 + ct_share
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: u8) -> CompactEntry {
        CompactEntry {
            cm: [seed; CM_LEN],
            tag: [seed ^ 0xff; TAG_LEN],
            clue: ClueSlot::Empty,
        }
    }

    #[test]
    fn entry_roundtrip_and_len() {
        assert_eq!(CompactEntry::LEN_EMPTY_CLUE, 41);
        let e = entry(0xab);
        assert_eq!(e.serialized_len(), 41);
        let bytes = e.to_bytes();
        assert_eq!(bytes.len(), 41);
        let (parsed, n) = CompactEntry::from_bytes(&bytes).unwrap();
        assert_eq!(n, 41);
        assert_eq!(parsed, e);
        // Short buffer and reserved (non-empty) clue both reject.
        assert!(CompactEntry::from_bytes(&bytes[..40]).is_none());
        let mut bad = bytes.clone();
        bad[40] = 0x01; // non-empty clue version
        assert!(CompactEntry::from_bytes(&bad).is_none());
    }

    #[test]
    fn bytes_per_note_matches_doc() {
        // 1-of-1 (unamortized) ≈ doc's ~1.1 KB; 2-of-1 ≈ doc's ~600 B.
        assert_eq!(bytes_per_note_amortized(1), 1129);
        assert_eq!(bytes_per_note_amortized(2), 585);
    }

    #[test]
    fn bundle_len_matches_formula() {
        for k in [1usize, 2, 3, 4] {
            let bundle = RecipientBundle {
                ct: [7u8; CT_LEN],
                entries: (0..k as u8).map(entry).collect(),
            };
            // Exact stream size divided by k equals the amortized formula when
            // 1088 is divisible by k; otherwise the formula's ceil is an upper
            // bound on the average — assert the exact identity per the formula.
            let exact = bundle.compact_stream_len();
            assert_eq!(exact, CT_LEN + k * CompactEntry::LEN_EMPTY_CLUE);
            if CT_LEN % k == 0 {
                assert_eq!(exact / k, bytes_per_note_amortized(k));
            }
        }
    }
}
