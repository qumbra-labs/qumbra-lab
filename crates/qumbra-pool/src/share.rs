//! Share-target filter. Byte selection is lab #490's export — this
//! module does not read `hash[0..8]` or `hash[24..32]` itself.
//!
//! Consensus ([`satisfies_target_for`]) keeps `<=` on both forms. The
//! pool SHARE filter mirrors stock xmrig's strict `<` (`CpuWorker.cpp`)
//! so a boundary hash consensus would accept is not rejected here as a
//! "low difficulty share" that xmrig would never have sent — and, more
//! importantly, a hash with work value == target is refused at the
//! pool (xmrig never submits `==`).

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::Hash32;
use qlab_devnet::pow::{hash_to_work_value_for, satisfies_target_for};

/// Whether a claimed PoW hash meets the job's share target under `form`.
///
/// Work value comes from [`hash_to_work_value_for`] (v5 = trailing-8-LE).
/// Comparison is **strict `<`** against the raw 8-byte job target.
pub fn share_meets_target(hash: &Hash32, target: u64, form: GenesisForm) -> bool {
    hash_to_work_value_for(hash, form) < target
}

/// Whether the same hash is a consensus block candidate (`<=` the
/// schedule difficulty). Uses [`satisfies_target_for`] verbatim —
/// consensus strictness is not ours to change.
pub fn is_block_candidate(hash: &Hash32, consensus_difficulty: u64, form: GenesisForm) -> bool {
    satisfies_target_for(hash, consensus_difficulty, form)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::pow::target_threshold;

    #[test]
    fn share_filter_is_strict_lt_while_consensus_is_le() {
        let d = 1024u64;
        let target = target_threshold(d);
        // Exact boundary under the v5 window: work value == target.
        let mut at = [0u8; 32];
        at[24..32].copy_from_slice(&target.to_le_bytes());
        assert_eq!(hash_to_work_value_for(&at, GenesisForm::V5), target);
        assert!(
            is_block_candidate(&at, d, GenesisForm::V5),
            "consensus keeps <= ; the boundary hash is a valid block"
        );
        assert!(satisfies_target_for(&at, d, GenesisForm::V5));
        assert!(
            !share_meets_target(&at, target, GenesisForm::V5),
            "share filter is xmrig's strict < ; == target is not a share"
        );

        // One below the target: both accept.
        let mut below = [0u8; 32];
        below[24..32].copy_from_slice(&(target - 1).to_le_bytes());
        assert!(share_meets_target(&below, target, GenesisForm::V5));
        assert!(satisfies_target_for(&below, d, GenesisForm::V5));
    }

    #[test]
    fn v5_filter_accepts_tail_le_that_v4_would_reject() {
        // #490's divergence vector: tail-LE small, head-BE huge.
        let mut tail_wins = [0xFFu8; 32];
        tail_wins[24..32].copy_from_slice(&7u64.to_le_bytes());
        let target = target_threshold(1_000_000);
        assert!(share_meets_target(&tail_wins, target, GenesisForm::V5));
        assert!(!share_meets_target(&tail_wins, target, GenesisForm::V4));

        let mut head_wins = [0xFFu8; 32];
        head_wins[..8].copy_from_slice(&7u64.to_be_bytes());
        assert!(share_meets_target(&head_wins, target, GenesisForm::V4));
        assert!(!share_meets_target(&head_wins, target, GenesisForm::V5));
    }
}
