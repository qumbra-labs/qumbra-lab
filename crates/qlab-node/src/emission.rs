//! Coinbase emission — the normative integer form (protocol-spec §6, frozen §2).
//!
//! Qumbra's block subsidy is defined as the **integer difference of a rounded
//! closed-form cumulative supply**, not as a per-block reward formula. This is
//! deliberate: the closed form `S(h)` is the supply-audit anchor (tokenomics §1
//! job 4 — the only consensus-transparent value flow in a shielded pool), and
//! defining the per-block coinbase as a *difference of the rounded cumulative*
//! makes the sum telescope back to the cumulative **exactly**, with no drift:
//!
//! ```text
//!   S(h)          = r0·(1−(1−d)^h)/d          for h ≤ h_t
//!                 = S(h_t) + tail·(h − h_t)    for h > h_t   (Monero-class floor)
//!   S_atomic(h)   = round(S(h) · 10⁸)          bessel  (1 QMB = 10⁸ bessel, frozen §8)
//!   coinbase(h)   = S_atomic(h+1) − S_atomic(h)                    (protocol-spec §6)
//!   ⇒  Σ_{i<h} coinbase(i) = S_atomic(h)   exactly  (telescoping, test-locked)
//! ```
//!
//! The FROZEN B2 constants (consensus-parameters §2): `r0 = 50 QMB`,
//! `d = 8.237e-7` (per-block decay), `tail = 1.22441 QMB/block`; `h_t` = the
//! first height where the decay component drops to the tail. The closed form and
//! `S(h)` come straight from [`qlab_econ::Model`] (the emission simulator that
//! produced candidate B2, PR #36) — this module does **not** re-derive `d`/`tail`
//! from targets (which could round differently); it pins the frozen constants
//! directly, so `qlab-node` and the design's audit anchor evaluate the *same*
//! `S(h)`.
//!
//! Per-block the reward is split **65 % miners / 15 % committee / 20 % treasury**
//! (frozen §3), applied to `coinbase(h)`; fees are paid to miners on top, never
//! burned (tokenomics §6). Coinbase outputs mature after **144 blocks** (frozen
//! §2) — enforced by the mempool ([`crate::mempool`]).

use qlab_econ::model::{Family, Model};

/// Atomic subunits per coin: **1 QMB = 10⁸ bessel** (frozen §8).
pub const BESSEL_PER_QMB: u64 = 100_000_000;

/// Initial block reward `r0` in QMB (frozen §2, B2 — decided 2026-07-22).
pub const R0_QMB: f64 = 50.0;

/// Per-block geometric decay `d` (frozen §2, B2 — derived from {r0, 2-year
/// half-life, 75 s blocks}, pinned as a frozen constant here).
pub const DECAY_D: f64 = 8.237e-7;

/// Perpetual tail floor in QMB/block (frozen §2, B2 — the 0.87 %-activation tail).
pub const TAIL_QMB: f64 = 1.22441;

/// Coinbase maturity delay in blocks (frozen §2 — 144 = 3.0 h at 75 s, ⅛ epoch;
/// covers the PR #46 worst measured reorg depth 118 with margin).
pub const COINBASE_MATURITY_BLOCKS: u64 = 144;

/// Reward split numerators over 100 (frozen §3): 65 % miners / 15 % committee /
/// 20 % treasury.
pub const SPLIT_MINER_PCT: u64 = 65;
pub const SPLIT_COMMITTEE_PCT: u64 = 15;
pub const SPLIT_TREASURY_PCT: u64 = 20;

/// The frozen B2 emission curve — the exact `S(h)` the supply attestation uses.
/// Pins the frozen constants directly (no target re-derivation).
fn frozen_curve() -> Model {
    Model {
        family: Family::MoneroClass,
        r0: R0_QMB,
        d: DECAY_D,
        tail: TAIL_QMB,
        // Block time only scales the sim's calendar framing; it does not enter
        // `supply(h)` (a pure function of height). Pinned at the frozen 75 s.
        block_time_s: 75.0,
    }
}

/// Cumulative supply **at** height `h` (coins emitted through block `h−1`, so
/// `S_atomic(0) = 0`), in **bessel**: `round(S(h) · 10⁸)` (protocol-spec §6).
///
/// `S(h)` is monotone non-decreasing, so `S_atomic` is too — which is what makes
/// every [`coinbase`] non-negative.
pub fn s_atomic(h: u64) -> u64 {
    let coins = frozen_curve().supply(h as f64);
    // round-half-away-from-zero on a non-negative value; `S(h) ≥ 0` always.
    (coins * BESSEL_PER_QMB as f64).round() as u64
}

/// The block subsidy at height `h` in **bessel**: `S_atomic(h+1) − S_atomic(h)`
/// (protocol-spec §6). Non-negative and telescoping by construction.
pub fn coinbase(h: u64) -> u64 {
    // S_atomic is monotone, so this never underflows; saturating_sub is a belt-
    // and-braces guard against f64 rounding jitter (never observed — the tail
    // reward is ≥ 1.22441 QMB ≈ 1.22e8 bessel, dwarfing ±1-bessel round error).
    s_atomic(h + 1).saturating_sub(s_atomic(h))
}

/// The 65/15/20 division of a block's coinbase (frozen §3). Committee and
/// treasury take floored shares; the miner absorbs the rounding remainder (so
/// the three parts sum to `total` exactly — no bessel is minted or lost).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardSplit {
    /// Miner share (65 % + rounding remainder). The block-assembly miner also
    /// earns the block's fees on top of this (see [`crate::mempool`]).
    pub miner: u64,
    /// Finality-committee share (15 %).
    pub committee: u64,
    /// Consensus-native treasury share (20 %).
    pub treasury: u64,
}

impl RewardSplit {
    /// Split `total` bessel 65/15/20; miner absorbs the remainder.
    pub fn of(total: u64) -> Self {
        let t = total as u128;
        let committee = (t * SPLIT_COMMITTEE_PCT as u128 / 100) as u64;
        let treasury = (t * SPLIT_TREASURY_PCT as u128 / 100) as u64;
        let miner = total - committee - treasury;
        Self { miner, committee, treasury }
    }

    /// The three parts summed — always equal to the `total` passed to [`of`].
    pub fn total(&self) -> u64 {
        self.miner + self.committee + self.treasury
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_coinbase_is_r0() {
        // S_atomic(0) = 0; S_atomic(1) = r0 (one block emitted). So coinbase(0)
        // is exactly the initial reward: 50 QMB = 5×10⁹ bessel (frozen §2/§8).
        assert_eq!(s_atomic(0), 0);
        assert_eq!(s_atomic(1), 50 * BESSEL_PER_QMB);
        assert_eq!(coinbase(0), 50 * BESSEL_PER_QMB);
        assert_eq!(coinbase(0), 5_000_000_000);
    }

    #[test]
    fn coinbase_telescopes_to_s_atomic_exactly() {
        // Σ_{i<h} coinbase(i) == S_atomic(h) — the audit-anchor invariant that
        // makes the per-block subsidy a difference of the rounded cumulative.
        for &h in &[0u64, 1, 2, 10, 100, 1_000, 10_000, 100_000] {
            let sum: u64 = (0..h).map(coinbase).sum();
            assert_eq!(sum, s_atomic(h), "telescoping broke at h={h}");
        }
    }

    #[test]
    fn coinbase_is_non_negative_and_positive_through_and_past_the_tail() {
        // Monotone S ⇒ coinbase ≥ 0 everywhere. And because MoneroClass floors
        // the reward at the tail, coinbase stays strictly positive forever —
        // check a spread of heights incl. around the tail activation (~4.5M).
        let ht = frozen_curve().tail_activation_height() as u64;
        for &h in &[0u64, 1, 1_000, 1_000_000, ht - 1, ht, ht + 1, ht + 1_000_000] {
            let c = coinbase(h);
            assert!(c > 0, "coinbase({h}) = {c} must be positive");
        }
        // Tail-era reward is exactly the floor: ~1.22441 QMB/block in bessel.
        let tail_bessel = (TAIL_QMB * BESSEL_PER_QMB as f64).round() as u64;
        let deep = coinbase(ht + 500_000);
        assert!(
            deep.abs_diff(tail_bessel) <= 1,
            "deep-tail coinbase {deep} ≈ tail floor {tail_bessel}"
        );
    }

    #[test]
    fn tail_activates_near_the_design_height() {
        // Design record (consensus-parameters §2 / econ sweep): tail activates
        // ~block 4,503,708 (year ~10.7). Confirm the frozen constants land there.
        let ht = frozen_curve().tail_activation_height() as u64;
        assert!(
            (4_400_000..4_600_000).contains(&ht),
            "tail activation {ht} near the design's 4,503,708"
        );
    }

    #[test]
    fn split_is_65_15_20_and_sums_exactly() {
        let s = RewardSplit::of(coinbase(0)); // 5×10⁹ bessel, divides cleanly
        assert_eq!(s.miner, 3_250_000_000); // 65 %
        assert_eq!(s.committee, 750_000_000); // 15 %
        assert_eq!(s.treasury, 1_000_000_000); // 20 %
        assert_eq!(s.total(), coinbase(0));

        // Remainder always goes to the miner; parts always sum to the total.
        for total in [0u64, 1, 2, 3, 7, 99, 100, 101, 1_222_441, u64::MAX / 2] {
            let s = RewardSplit::of(total);
            assert_eq!(s.total(), total, "split of {total} must sum exactly");
            assert_eq!(s.committee, (total as u128 * 15 / 100) as u64);
            assert_eq!(s.treasury, (total as u128 * 20 / 100) as u64);
        }
    }
}
