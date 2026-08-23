//! Stateful-WOTS reservation model and random-index collision arithmetic.
//!
//! The API enforces reserve-before-export inside one state file. It cannot make
//! an old backup monotonic or coordinate two independently restored devices;
//! tests make those failures executable. That is why this module is evidence
//! against selecting stateful WOTS+ under the current wallet product model,
//! not a claim that the P0 is solved.

use crate::{keccak256, Hash32};

const MAGIC: &[u8; 4] = b"QRS1";
const VERSION: u8 = 1;
const PREFIX_BYTES: usize = 4 + 1 + 1 + 4;
pub const ENCODED_BYTES: usize = PREFIX_BYTES + 32;
pub const MAX_TREE_DEPTH: u8 = 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsJournal {
    depth: u8,
    next_index: u32,
}

impl WotsJournal {
    pub fn new(depth: u8) -> Result<Self, String> {
        if depth == 0 || depth > MAX_TREE_DEPTH {
            return Err(format!("WOTS+ tree depth must be in 1..={MAX_TREE_DEPTH}"));
        }
        Ok(Self {
            depth,
            next_index: 0,
        })
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_BYTES);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.depth);
        out.extend_from_slice(&self.next_index.to_le_bytes());
        let checksum = keccak256(&[b"qumbra:remote-auth:wots-journal:v1", &out]);
        out.extend_from_slice(&checksum);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != ENCODED_BYTES {
            return Err(format!(
                "WOTS+ journal has {} bytes; expected {ENCODED_BYTES}",
                bytes.len()
            ));
        }
        if &bytes[..4] != MAGIC {
            return Err("WOTS+ journal has the wrong magic".into());
        }
        if bytes[4] != VERSION {
            return Err(format!(
                "WOTS+ journal version {} is not supported",
                bytes[4]
            ));
        }
        let expected = keccak256(&[
            b"qumbra:remote-auth:wots-journal:v1",
            &bytes[..PREFIX_BYTES],
        ]);
        if bytes[PREFIX_BYTES..] != expected {
            return Err("WOTS+ journal checksum mismatch".into());
        }
        let depth = bytes[5];
        let next_index = u32::from_le_bytes(bytes[6..10].try_into().unwrap());
        let journal = Self::new(depth)?;
        if next_index > journal.capacity() {
            return Err("WOTS+ journal index exceeds its tree".into());
        }
        Ok(Self { depth, next_index })
    }

    pub fn capacity(&self) -> u32 {
        1u32 << self.depth
    }

    /// Burn the next index and persist the increment before returning it to a
    /// signer. A failed persistence callback returns no index and rolls the
    /// in-memory increment back. A later job cancellation does not roll back.
    pub fn reserve_with(
        &mut self,
        persist: impl FnOnce(&[u8]) -> Result<(), String>,
    ) -> Result<u32, String> {
        if self.next_index == self.capacity() {
            return Err("WOTS+ address is exhausted".into());
        }
        let reserved = self.next_index;
        self.next_index += 1;
        let bytes = self.encode();
        if let Err(error) = persist(&bytes) {
            self.next_index = reserved;
            return Err(error);
        }
        Ok(reserved)
    }

    /// True when restoring `older` after `newer` can export an already-burned
    /// index. No checksum can distinguish a valid old backup from current state.
    pub fn rollback_reuses(newer: &Self, older: &Self) -> bool {
        newer.depth == older.depth && older.next_index < newer.next_index
    }
}

/// The exact ideal-uniform birthday union bound required by the decision
/// record: q(q-1)/2^(D+1), capped at one. A collision is catastrophic for the
/// random-index WOTS+ row and only a linkability event for ML-DSA.
pub fn birthday_bound(uses: u64, depth: u8) -> f64 {
    if uses < 2 {
        return 0.0;
    }
    let numerator = (uses as f64) * ((uses - 1) as f64);
    (numerator / 2f64.powi(depth as i32 + 1)).min(1.0)
}

/// Union bound for an attacker targeting `targets` independent address trees,
/// each used `uses_per_target` times. Cross-tree index equality is harmless;
/// the event being counted is at least one within-tree OTS-key reuse.
pub fn multi_target_birthday_bound(uses_per_target: u64, targets: u64, depth: u8) -> f64 {
    (birthday_bound(uses_per_target, depth) * targets as f64).min(1.0)
}

pub fn derive_index(entropy: &Hash32, depth: u8) -> Result<u32, String> {
    if depth == 0 || depth > MAX_TREE_DEPTH {
        return Err(format!(
            "random-index depth must be in 1..={MAX_TREE_DEPTH}"
        ));
    }
    let value = u32::from_le_bytes(entropy[..4].try_into().unwrap());
    Ok(value & ((1u32 << depth) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_is_persisted_before_export_and_cancellation_burns() {
        let mut journal = WotsJournal::new(4).unwrap();
        let mut persisted = Vec::new();
        let index = journal
            .reserve_with(|bytes| {
                persisted = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        assert_eq!(index, 0);
        assert_eq!(WotsJournal::decode(&persisted).unwrap().next_index(), 1);
        // The proving job is now cancelled. Index 0 stays burned.
        assert_eq!(journal.reserve_with(|_| Ok(())).unwrap(), 1);

        let before = journal.clone();
        assert!(journal.reserve_with(|_| Err("disk full".into())).is_err());
        assert_eq!(journal, before, "a failed durable write exports no index");
    }

    #[test]
    fn valid_old_backup_and_two_devices_still_reuse_the_same_index() {
        let backup = WotsJournal::new(16).unwrap();
        let mut device_a = backup.clone();
        assert_eq!(device_a.reserve_with(|_| Ok(())).unwrap(), 0);
        assert!(WotsJournal::rollback_reuses(&device_a, &backup));

        let mut device_b = backup;
        assert_eq!(device_b.reserve_with(|_| Ok(())).unwrap(), 0);
        assert_eq!(device_a.next_index(), device_b.next_index());
        // Both journals and checksums are locally valid. Coordination, not a
        // better file codec, is the missing product property.
        WotsJournal::decode(&device_a.encode()).unwrap();
        WotsJournal::decode(&device_b.encode()).unwrap();
    }

    #[test]
    fn journal_refuses_truncation_tampering_and_impossible_state() {
        let journal = WotsJournal::new(4).unwrap();
        let bytes = journal.encode();
        assert!(WotsJournal::decode(&bytes[..bytes.len() - 1]).is_err());

        let mut tampered = bytes.clone();
        tampered[6] ^= 1;
        assert!(WotsJournal::decode(&tampered).is_err());

        let exhausted = WotsJournal {
            depth: 4,
            next_index: 17,
        };
        assert!(WotsJournal::decode(&exhausted.encode()).is_err());
    }

    #[test]
    fn birthday_bound_matches_the_decision_formula() {
        assert_eq!(birthday_bound(0, 16), 0.0);
        assert_eq!(birthday_bound(1, 16), 0.0);
        assert!((birthday_bound(100, 16) - 9_900.0 / 131_072.0).abs() < 1e-15);
        assert!(
            (multi_target_birthday_bound(10, 1_000, 20) - (90.0 / 2_097_152.0) * 1_000.0).abs()
                < 1e-15
        );
        assert_eq!(derive_index(&[0xff; 32], 12).unwrap(), 4_095);
    }
}
