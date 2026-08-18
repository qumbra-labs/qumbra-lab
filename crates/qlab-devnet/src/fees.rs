//! Posted-price fee schedule, ZIP-317-shape (consensus-and-network.md §8).
//!
//! **Fee = f(arity bucket)** — read from a small protocol table keyed on the
//! transaction's arity bucket, computable by anyone from public data. No fee
//! market, by design: varying fees are a privacy leak (§8 cites ZIP-313 and the
//! Monero nonstandard-fee fingerprinting result), so the fee is a deterministic
//! function of public transaction structure. Single native fee asset.
//!
//! The concrete tier values are the **FROZEN §5 fee table** (consensus-parameters,
//! decided 2026-07-22): 0.01 / 0.02 / 0.04 QMB for 2×2 / 4×4 / 8×8 (10⁶ / 2×10⁶
//! / 4×10⁶ bessel) — `params_devnet::FEE_MARGINAL_UNITS` converged to them at
//! M9-N4. The anti-spam block-weight penalty (§8) lives in `weight.rs`.

use crate::params_devnet::{FEE_GRACE_ACTIONS, FEE_MARGINAL_UNITS};

/// The transaction arity buckets Qumbra prices. The 2×2 bucket is the M3 shape;
/// 4×4 ≈ 2× and 8×8 ≈ 4× the circuit work (performance-budget §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArityBucket {
    /// 2 inputs, 2 outputs — the canonical shielded transaction.
    TwoByTwo,
    /// 4 inputs, 4 outputs.
    FourByFour,
    /// 8 inputs, 8 outputs.
    EightByEight,
}

impl ArityBucket {
    /// Logical actions in this bucket (ZIP-317 sense): `max(inputs, outputs)`.
    pub fn logical_actions(self) -> u32 {
        match self {
            ArityBucket::TwoByTwo => 2,
            ArityBucket::FourByFour => 4,
            ArityBucket::EightByEight => 8,
        }
    }

    /// The smallest bucket that fits a transaction of `inputs`×`outputs`.
    /// `None` if the transaction exceeds the largest supported bucket.
    pub fn for_arity(inputs: u32, outputs: u32) -> Option<ArityBucket> {
        let n = inputs.max(outputs);
        if n <= 2 {
            Some(ArityBucket::TwoByTwo)
        } else if n <= 4 {
            Some(ArityBucket::FourByFour)
        } else if n <= 8 {
            Some(ArityBucket::EightByEight)
        } else {
            None
        }
    }

    /// Every bucket, smallest first — the protocol fee table's key set.
    pub const ALL: [ArityBucket; 3] =
        [ArityBucket::TwoByTwo, ArityBucket::FourByFour, ArityBucket::EightByEight];

    /// **The one wire encoding of a bucket** (lab #470 stage 3, closing #233):
    /// an injective discriminant, 0/1/2. Used by BOTH the P2P tx codec and the
    /// v5 body-commitment preimage — one function, so the two spellings that
    /// #233 found agreeing only by coincidence are now the same fact. The
    /// v2/v3 body preimages keep writing [`Self::logical_actions`] — those
    /// bytes are frozen history (the live T1 goldens).
    ///
    /// Injective over the VARIANTS, not the action counts: a future variant
    /// sharing an action count with an existing one (the dummy-masked-2×2
    /// shape #219 considered) gets its own discriminant here and stays
    /// distinguishable in the v5 commitment — the exact confusion #233 filed.
    pub fn wire_discriminant(self) -> u8 {
        match self {
            ArityBucket::TwoByTwo => 0,
            ArityBucket::FourByFour => 1,
            ArityBucket::EightByEight => 2,
        }
    }

    /// Decode [`Self::wire_discriminant`]; `None` on unknown (reject-unknown —
    /// the caller names its own error).
    pub fn from_wire_discriminant(v: u8) -> Option<ArityBucket> {
        match v {
            0 => Some(ArityBucket::TwoByTwo),
            1 => Some(ArityBucket::FourByFour),
            2 => Some(ArityBucket::EightByEight),
            _ => None,
        }
    }
}

/// The posted price for a bucket: `FEE_MARGINAL_UNITS × max(FEE_GRACE_ACTIONS,
/// logical_actions)` (ZIP-317-shape). Deterministic and public.
pub fn posted_fee(bucket: ArityBucket) -> u64 {
    let actions = bucket.logical_actions().max(FEE_GRACE_ACTIONS);
    FEE_MARGINAL_UNITS * actions as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_is_deterministic_and_monotone_in_arity() {
        let f2 = posted_fee(ArityBucket::TwoByTwo);
        let f4 = posted_fee(ArityBucket::FourByFour);
        let f8 = posted_fee(ArityBucket::EightByEight);
        // Deterministic (same input → same fee) and non-decreasing in bucket size.
        assert_eq!(f2, posted_fee(ArityBucket::TwoByTwo));
        assert!(f2 <= f4 && f4 <= f8);
        // 2×2 = marginal × max(grace=2, 2) = marginal × 2.
        assert_eq!(f2, FEE_MARGINAL_UNITS * 2);
        assert_eq!(f8, FEE_MARGINAL_UNITS * 8);
    }

    #[test]
    fn posted_fees_are_the_frozen_absolutes() {
        // FROZEN §5 (consensus-parameters, decided 2026-07-22): 0.01 / 0.02 /
        // 0.04 QMB = 10⁶ / 2×10⁶ / 4×10⁶ bessel (1 QMB = 10⁸ bessel, frozen §8).
        assert_eq!(posted_fee(ArityBucket::TwoByTwo), 1_000_000);
        assert_eq!(posted_fee(ArityBucket::FourByFour), 2_000_000);
        assert_eq!(posted_fee(ArityBucket::EightByEight), 4_000_000);
    }

    #[test]
    fn bucketing_picks_the_smallest_fitting_tier() {
        assert_eq!(ArityBucket::for_arity(1, 2), Some(ArityBucket::TwoByTwo));
        assert_eq!(ArityBucket::for_arity(2, 2), Some(ArityBucket::TwoByTwo));
        assert_eq!(ArityBucket::for_arity(3, 1), Some(ArityBucket::FourByFour));
        assert_eq!(ArityBucket::for_arity(2, 5), Some(ArityBucket::EightByEight));
        assert_eq!(ArityBucket::for_arity(9, 9), None);
    }

    #[test]
    fn table_covers_all_buckets() {
        // The public table is keyed on every supported bucket.
        assert_eq!(ArityBucket::ALL.len(), 3);
        for b in ArityBucket::ALL {
            assert!(posted_fee(b) > 0);
        }
    }
    /// Lab #470 stage 3 (#233): the ONE wire encoding — injective over the
    /// variants, round-trips, rejects unknowns, and its values are PINNED to
    /// the live v4 tx wire's 0/1/2 (the p2p codec has written these since M6;
    /// changing them would break the frozen tx wire, so they are a compat
    /// lock, not an arbitrary choice).
    #[test]
    fn wire_discriminant_is_the_one_pinned_encoding() {
        assert_eq!(ArityBucket::TwoByTwo.wire_discriminant(), 0);
        assert_eq!(ArityBucket::FourByFour.wire_discriminant(), 1);
        assert_eq!(ArityBucket::EightByEight.wire_discriminant(), 2);
        for b in ArityBucket::ALL {
            assert_eq!(ArityBucket::from_wire_discriminant(b.wire_discriminant()), Some(b));
        }
        for v in [3u8, 4, 0xFF] {
            assert_eq!(ArityBucket::from_wire_discriminant(v), None);
        }
    }

}
