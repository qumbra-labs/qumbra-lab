//! LEB128 varints — the protocol-spec §5 framing primitive, **not re-rolled**.
//!
//! §5 mandates "unsigned LEB128 ≤ 10 B". Rather than implement a second LEB128
//! (which could silently drift from the ratified note-discovery wire), this crate
//! re-exports the golden-locked codec from `qlab-cbserver` and uses it everywhere
//! a varint appears — so there is exactly one LEB128 in the tree, the one whose
//! output is locked to the spec digest `3ee2a5e6…`.

pub use qlab_cbserver::codec::{read_varint, write_varint, CodecError};

/// The §5 wire-version lead byte (`0x01`), re-exported for the compact-block
/// relay path so it reads the same constant the note-discovery server writes.
pub use qlab_cbserver::WIRE_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundaries() {
        for v in [0u64, 1, 127, 128, 300, 16_383, 16_384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len(), "consumed all bytes for {v}");
        }
    }

    #[test]
    fn single_byte_below_128() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x7F);
        assert_eq!(buf, vec![0x7F], "values < 128 are one byte (§5)");
    }

    #[test]
    fn overflow_beyond_ten_bytes_is_rejected() {
        // Eleven continuation bytes → past the u64 / ≤10-byte ceiling; the reused
        // decoder guards this (§5 "≤ 10 B"), so we inherit the rejection.
        let bad = [0x80u8; 11];
        let mut pos = 0;
        assert_eq!(read_varint(&bad, &mut pos), Err(CodecError::VarintOverflow));
    }

    #[test]
    fn truncated_varint_is_rejected() {
        let buf = [0x80u8]; // continuation bit set, no following byte
        let mut pos = 0;
        assert!(read_varint(&buf, &mut pos).is_err());
    }
}
