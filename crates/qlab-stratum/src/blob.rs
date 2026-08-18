//! v5 header blob layout — the bytes a stratum `job.blob` carries.
//!
//! Authority: pool-t1-brief §3 (DECIDED route A) + lab PR #472
//! `BlockHeader::preimage_for(GenesisForm::V5)`. Constants here are the ruled
//! offsets; once #472 merges they must assert equal to
//! `qlab_devnet::header::{HEADER_PREIMAGE_LEN_V5, HEADER_VERSION_BYTE_V5}`.
//!
//! ```text
//!   0–31   prev (32)
//!   32     header format version = 0x05
//!   33–38  height, u48 LE
//!   39–42  miner nonce window (4) — xmrig grinds here
//!   43–46  pool extra-nonce (4) — pool sets per connection
//!   47–54  timestamp, u64 LE
//!   55–62  difficulty, u64 LE
//!   63–94  tx_body_commitment (32)
//!   95     AggregateProofSlot tag (0xA6)
//!   96     EpochSupplyAttestation tag (0x59)
//! ```

/// v5 header preimage / stratum blob length (bytes).
pub const V5_BLOB_LEN: usize = 97;

/// Header format version byte at offset 32.
pub const V5_HEADER_VERSION: u8 = 0x05;

/// Offset of the 4-byte miner grind window (xmrig `nonceOffset` for RandomX).
pub const V5_MINER_NONCE_OFF: usize = 39;

/// Width of the miner grind window (xmrig `nonceSize` for RandomX).
pub const V5_MINER_NONCE_LEN: usize = 4;

/// Offset of the 4-byte pool extra-nonce (high half of the u64 nonce).
pub const V5_EXTRANONCE_OFF: usize = 43;

/// Width of the pool extra-nonce.
pub const V5_EXTRANONCE_LEN: usize = 4;

/// Error from blob helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    /// Blob is not exactly [`V5_BLOB_LEN`] bytes.
    WrongLength { got: usize },
    /// Version byte at offset 32 is not [`V5_HEADER_VERSION`].
    BadVersion { got: u8 },
    /// Miner nonce hex is not exactly 4 bytes.
    BadMinerNonceLen { got: usize },
    /// Extra-nonce is not exactly 4 bytes.
    BadExtranonceLen { got: usize },
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::WrongLength { got } => {
                write!(f, "v5 blob length {got}, expected {V5_BLOB_LEN}")
            }
            BlobError::BadVersion { got } => {
                write!(f, "v5 blob version 0x{got:02x}, expected 0x{V5_HEADER_VERSION:02x}")
            }
            BlobError::BadMinerNonceLen { got } => {
                write!(f, "miner nonce length {got}, expected {V5_MINER_NONCE_LEN}")
            }
            BlobError::BadExtranonceLen { got } => {
                write!(f, "extranonce length {got}, expected {V5_EXTRANONCE_LEN}")
            }
        }
    }
}

impl std::error::Error for BlobError {}

/// Validate a decoded v5 blob: length + version byte.
pub fn check_v5_blob(blob: &[u8]) -> Result<(), BlobError> {
    if blob.len() != V5_BLOB_LEN {
        return Err(BlobError::WrongLength { got: blob.len() });
    }
    if blob[32] != V5_HEADER_VERSION {
        return Err(BlobError::BadVersion { got: blob[32] });
    }
    Ok(())
}

/// Read the 4-byte miner window (offsets 39–42).
pub fn miner_nonce_of(blob: &[u8]) -> Result<[u8; V5_MINER_NONCE_LEN], BlobError> {
    check_v5_blob(blob)?;
    let mut out = [0u8; V5_MINER_NONCE_LEN];
    out.copy_from_slice(&blob[V5_MINER_NONCE_OFF..V5_MINER_NONCE_OFF + V5_MINER_NONCE_LEN]);
    Ok(out)
}

/// Read the 4-byte pool extra-nonce (offsets 43–46).
pub fn extranonce_of(blob: &[u8]) -> Result<[u8; V5_EXTRANONCE_LEN], BlobError> {
    check_v5_blob(blob)?;
    let mut out = [0u8; V5_EXTRANONCE_LEN];
    out.copy_from_slice(&blob[V5_EXTRANONCE_OFF..V5_EXTRANONCE_OFF + V5_EXTRANONCE_LEN]);
    Ok(out)
}

/// Write the pool extra-nonce into a mutable blob (connection partition).
pub fn set_extranonce(blob: &mut [u8], extranonce: &[u8]) -> Result<(), BlobError> {
    check_v5_blob(blob)?;
    if extranonce.len() != V5_EXTRANONCE_LEN {
        return Err(BlobError::BadExtranonceLen {
            got: extranonce.len(),
        });
    }
    blob[V5_EXTRANONCE_OFF..V5_EXTRANONCE_OFF + V5_EXTRANONCE_LEN].copy_from_slice(extranonce);
    Ok(())
}

/// Apply a 4-byte miner nonce (from a stratum `submit`) into the blob's miner window.
pub fn apply_miner_nonce(blob: &mut [u8], miner_nonce: &[u8]) -> Result<(), BlobError> {
    check_v5_blob(blob)?;
    if miner_nonce.len() != V5_MINER_NONCE_LEN {
        return Err(BlobError::BadMinerNonceLen {
            got: miner_nonce.len(),
        });
    }
    blob[V5_MINER_NONCE_OFF..V5_MINER_NONCE_OFF + V5_MINER_NONCE_LEN].copy_from_slice(miner_nonce);
    Ok(())
}

/// Assemble the consensus `u64` nonce from miner window + extra-nonce bytes
/// (both little-endian halves of the LE u64 at offsets 39–46).
pub fn assemble_nonce(miner_nonce: &[u8], extranonce: &[u8]) -> Result<u64, BlobError> {
    if miner_nonce.len() != V5_MINER_NONCE_LEN {
        return Err(BlobError::BadMinerNonceLen {
            got: miner_nonce.len(),
        });
    }
    if extranonce.len() != V5_EXTRANONCE_LEN {
        return Err(BlobError::BadExtranonceLen {
            got: extranonce.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(miner_nonce);
    buf[4..].copy_from_slice(extranonce);
    Ok(u64::from_le_bytes(buf))
}

/// Read the assembled u64 nonce from a blob that already has both halves set.
pub fn nonce_u64_of(blob: &[u8]) -> Result<u64, BlobError> {
    let m = miner_nonce_of(blob)?;
    let e = extranonce_of(blob)?;
    assemble_nonce(&m, &e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_blob() -> Vec<u8> {
        // Deterministic 97-byte v5 preimage (same bytes as the fixture transcript).
        let mut b = vec![0u8; V5_BLOB_LEN];
        for i in 0..32 {
            b[i] = i as u8;
        }
        b[32] = V5_HEADER_VERSION;
        // height 123456 as u48 LE
        b[33..39].copy_from_slice(&(123456u64.to_le_bytes()[..6]));
        // extranonce 04 03 02 01; miner window zero
        b[43..47].copy_from_slice(&[0x04, 0x03, 0x02, 0x01]);
        b[47..55].copy_from_slice(&1_785_000_000u64.to_le_bytes());
        b[55..63].copy_from_slice(&1024u64.to_le_bytes());
        b[63..95].fill(0xAB);
        b[95] = 0xA6;
        b[96] = 0x59;
        b
    }

    #[test]
    fn windows_sit_at_ruled_offsets() {
        let mut blob = sample_blob();
        assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
        assert_eq!(extranonce_of(&blob).unwrap(), [0x04, 0x03, 0x02, 0x01]);

        apply_miner_nonce(&mut blob, &[0xd0, 0x03, 0x00, 0x40]).unwrap();
        assert_eq!(&blob[39..43], &[0xd0, 0x03, 0x00, 0x40]);
        // extranonce untouched
        assert_eq!(&blob[43..47], &[0x04, 0x03, 0x02, 0x01]);

        let n = nonce_u64_of(&blob).unwrap();
        assert_eq!(n, 0x0102_0304_4000_03d0);
    }

    #[test]
    fn rejects_wrong_length_and_version() {
        assert!(matches!(
            check_v5_blob(&[0u8; 98]),
            Err(BlobError::WrongLength { got: 98 })
        ));
        let mut bad = sample_blob();
        bad[32] = 0x04;
        assert!(matches!(
            check_v5_blob(&bad),
            Err(BlobError::BadVersion { got: 0x04 })
        ));
    }
}
