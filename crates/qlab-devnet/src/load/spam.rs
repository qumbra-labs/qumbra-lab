//! Spam-flood scenario sweep (issue #42 item 2).
//!
//! **Question.** Under a sustained flood at the decided fee floor, with the
//! attacker budget swept as multiples of daily emission (the Rucknium native
//! anchor — adversary budget capped at the daily security budget), how does the
//! block-weight governor bound chain growth, and what does the attack cost as a
//! fraction of emission — across candidate `[open]` constant sets?
//!
//! **Model (deterministic — no RNG).** All spam is 2×2 (the worst-case
//! bytes-per-fee vehicle, `load::two_by_two...`). Each block a *rational* miner
//! fills to where marginal fee = marginal penalty:
//!
//! ```text
//!   revenue(b) = (b / w)·fee  +  base_reward − penalty(b, M)
//!   penalty(b, M) = base_reward · (b − M)² / M²      for M < b ≤ 2M
//!   d/db revenue = 0  ⇒  b* = M + fee·M² / (2·base·w)   (clamped to [M, 2M])
//! ```
//!
//! where `w` = per-tx weight (proof + overhead), `M` = the governor's effective
//! median (penalty-free zone), `base_reward` = the block's base coinbase. Up to
//! `M` there is no penalty, so the miner always fills to `min(M, affordable)`; the
//! attacker's budget caps affordable bytes. The realized block weight feeds the
//! governor, `M` evolves, and we read the steady state.
//!
//! **Key economics.** Because the penalty scales with `base_reward` and
//! `base_reward ≫ fee_floor` at launch (50 QMB vs 0.01 QMB), `b*` sits barely
//! above `M`: a rational miner will **not** grow blocks past the free zone for
//! spam fees. So sustained block size is pinned near `min_weight`, and the
//! governor's grip *weakens as emission decays* (tail `base_reward` ≈ 1.22 QMB is
//! far closer to the fee) — the sweep reports both eras.

use crate::weight::{weight_limit, WeightGovernor, WeightParams};

use super::{
    BESSEL_PER_QMB, BLOCKS_PER_DAY, FEE_2X2_BESSEL, LAUNCH_DAILY_EMISSION_QMB, R0_QMB,
    TX_2X2_BYTES, TX_OVERHEAD_BYTES,
};

/// Per-tx weight in bytes (proof + public-surface overhead) — the flood unit.
pub const SPAM_TX_WEIGHT: u64 = TX_2X2_BYTES + TX_OVERHEAD_BYTES;

/// One swept constant set with a provenance label.
#[derive(Clone, Copy, Debug)]
pub struct ConstantSet {
    pub label: &'static str,
    pub params: WeightParams,
}

/// Emission era the flood runs in (the base reward the penalty scales against).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Era {
    /// Launch: base reward r0 = 50 QMB (consensus-parameters §2).
    Launch,
    /// Tail: base reward ≈ 1.22441 QMB/block (consensus-parameters §2 derived tail).
    Tail,
}

/// Tail base reward, bessel: 1.22441 QMB (consensus-parameters §2 derived tail).
pub const TAIL_REWARD_BESSEL: u64 = 122_441_000;

impl Era {
    /// Base reward for this era, in **bessel** (integer atomic units).
    pub fn base_reward_bessel(self) -> u64 {
        match self {
            Era::Launch => R0_QMB * BESSEL_PER_QMB, // 5e9 bessel
            Era::Tail => TAIL_REWARD_BESSEL,
        }
    }

    /// Daily emission for this era, in QMB (the budget-anchor denominator).
    pub fn daily_emission_qmb(self) -> u64 {
        match self {
            Era::Launch => LAUNCH_DAILY_EMISSION_QMB, // 57_600
            Era::Tail => (TAIL_REWARD_BESSEL * BLOCKS_PER_DAY) / BESSEL_PER_QMB, // ≈ 1_410
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Era::Launch => "launch",
            Era::Tail => "tail",
        }
    }
}

/// The measured outcome of one flood scenario.
#[derive(Clone, Debug)]
pub struct SpamResult {
    pub label: &'static str,
    pub era: Era,
    pub budget_mult: f64,
    /// Effective median (penalty-free zone) at the end of the sim, bytes.
    pub final_effective_median_bytes: u64,
    /// Largest single block produced, bytes.
    pub peak_block_bytes: u64,
    /// Steady-state chain growth, MB/day (mean block bytes over the final day).
    pub chain_growth_mb_per_day: f64,
    /// Attacker's realized daily fee cost as a % of daily emission (the Rucknium
    /// anchor). Below `budget_mult×100%` when the governor caps inclusion.
    pub attacker_cost_pct_emission: f64,
    /// Effective-median growth over the whole sim (`final / start`). Under a
    /// permanent flood the marginal-penalty equilibrium `b* > M` drives a slow
    /// upward creep; this quantifies it. `long_window` is the dominant damper.
    pub growth_factor: f64,
    /// Convenience flag: did the median stay within 2× its start over the sim
    /// horizon? A *reported* outcome, not an invariant — false for a small
    /// long-window under a long, well-funded flood.
    pub governor_bounded: bool,
}

/// The rational-miner equilibrium block weight `b*` given effective median `m`,
/// base reward, and the per-tx weight — clamped to `[m, 2m]` (integer math).
fn rational_block_weight(m: u64, base_reward: u64, params: &WeightParams) -> u64 {
    // b* = m + fee·m² / (2·base·w). u128 throughout.
    let extra = (FEE_2X2_BESSEL as u128 * m as u128 * m as u128)
        / (2u128 * base_reward as u128 * SPAM_TX_WEIGHT as u128);
    let b = m as u128 + extra;
    (b.min(weight_limit(m, params) as u128)) as u64
}

/// Run one flood scenario to steady state and measure it.
pub fn run_scenario(cs: &ConstantSet, era: Era, budget_mult: f64, days: u64) -> SpamResult {
    let mut gov = WeightGovernor::new(cs.params);
    let base = era.base_reward_bessel();
    let start_median = gov.effective_median();

    // Affordable spam bytes per block from the daily budget = budget_mult ×
    // daily-emission (QMB) spread across the day's blocks, divided by per-byte fee
    // cost (fee per w bytes).
    let daily_budget_bessel =
        (budget_mult * era.daily_emission_qmb() as f64 * BESSEL_PER_QMB as f64) as u128;
    let per_block_budget_bessel = daily_budget_bessel / BLOCKS_PER_DAY as u128;
    let affordable_bytes =
        ((per_block_budget_bessel * SPAM_TX_WEIGHT as u128) / FEE_2X2_BESSEL as u128) as u64;

    let total_blocks = days * BLOCKS_PER_DAY;
    let last_day_start = total_blocks.saturating_sub(BLOCKS_PER_DAY);

    let mut peak = 0u64;
    let mut last_day_bytes: u128 = 0;
    let mut last_day_cost_bessel: u128 = 0;

    for t in 0..total_blocks {
        let m = gov.effective_median();
        let b_star = rational_block_weight(m, base, &cs.params);
        // Miner fills to the rational stop, but no more than the attacker supplies.
        let block_bytes = b_star.min(affordable_bytes);
        gov.push_block(block_bytes);
        peak = peak.max(block_bytes);

        if t >= last_day_start {
            last_day_bytes += block_bytes as u128;
            let ntx = block_bytes / SPAM_TX_WEIGHT;
            last_day_cost_bessel += ntx as u128 * FEE_2X2_BESSEL as u128;
        }
    }

    let day_blocks = (total_blocks - last_day_start).max(1) as f64;
    let mean_block_bytes = last_day_bytes as f64 / day_blocks;
    let chain_growth_mb_per_day = mean_block_bytes * BLOCKS_PER_DAY as f64 / (1024.0 * 1024.0);
    // last_day_cost is already exactly one day's worth of blocks.
    let daily_cost_bessel = last_day_cost_bessel as f64;
    let daily_emission_bessel = era.daily_emission_qmb() as f64 * BESSEL_PER_QMB as f64;
    let attacker_cost_pct_emission = 100.0 * daily_cost_bessel / daily_emission_bessel;
    let final_median = gov.effective_median();
    let growth_factor = final_median as f64 / start_median.max(1) as f64;

    SpamResult {
        label: cs.label,
        era,
        budget_mult,
        final_effective_median_bytes: final_median,
        peak_block_bytes: peak,
        chain_growth_mb_per_day,
        attacker_cost_pct_emission,
        growth_factor,
        governor_bounded: final_median <= 2 * start_median,
    }
}

/// A reference "governor OFF" baseline: no penalty, no cap — the miner includes
/// everything the attacker can afford. Shows unbounded growth scaling directly
/// with budget, i.e. what the governor is buying. Returns MB/day.
pub fn run_no_governor(era: Era, budget_mult: f64) -> f64 {
    let daily_budget_qmb = budget_mult * era.daily_emission_qmb() as f64;
    // Every fee-QMB buys (BESSEL_PER_QMB / fee) txs × w bytes.
    let bytes_per_qmb =
        BESSEL_PER_QMB as f64 / FEE_2X2_BESSEL as f64 * SPAM_TX_WEIGHT as f64;
    daily_budget_qmb * bytes_per_qmb / (1024.0 * 1024.0)
}

/// The candidate constant sets the headline sweep covers. All fields `[open]`;
/// the set varies the free-zone floor (`min_weight`), the long-term cap, and the
/// short-term ceiling to expose which constant governs sustained bloat.
pub fn candidate_sets() -> Vec<ConstantSet> {
    let base = WeightParams::devnet_default();
    vec![
        ConstantSet { label: "S0 devnet-default (10MB free, 1.4x, st50)", params: base },
        ConstantSet {
            label: "S1 small-free-zone (2MB)",
            params: WeightParams { min_weight: 2 * 1024 * 1024, ..base },
        },
        ConstantSet {
            label: "S2 long-window 50k (creep damper)",
            params: WeightParams { long_window: 50_000, ..base },
        },
        ConstantSet {
            label: "S3 tight-lt-cap (1.2x)",
            params: WeightParams { lt_cap_num: 6, lt_cap_den: 5, ..base },
        },
        ConstantSet {
            label: "S4 loose-lt-cap (2.0x) + st200",
            params: WeightParams { lt_cap_num: 2, lt_cap_den: 1, st_cap: 200, ..base },
        },
    ]
}

/// Budget multiples of daily emission the sweep runs (Rucknium anchor).
pub const BUDGET_MULTS: [f64; 5] = [0.5, 1.0, 2.0, 5.0, 10.0];

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> ConstantSet {
        candidate_sets()[0]
    }

    #[test]
    fn peak_block_never_exceeds_the_final_medians_hard_cap() {
        // Each block is ≤ 2×M(t) and M is non-decreasing, so the largest block
        // ever produced is ≤ 2× the final effective median (the hard cap).
        let r = run_scenario(&set(), Era::Launch, 10.0, 20);
        assert!(r.peak_block_bytes <= 2 * r.final_effective_median_bytes);
    }

    #[test]
    fn permanent_flood_creeps_the_median_upward_not_downward() {
        // Under a sustained flood the marginal-penalty equilibrium b* > M drives a
        // slow upward creep (Monero-shape); the median never shrinks.
        let r = run_scenario(&set(), Era::Launch, 5.0, 20);
        assert!(r.growth_factor >= 1.0, "median must not shrink under flood");
    }

    #[test]
    fn a_longer_long_window_damps_the_creep() {
        // The dominant creep damper is the long-median window: S2 (50k) must grow
        // strictly less than S0 (5k) under the same flood.
        let sets = candidate_sets();
        let s0 = run_scenario(&sets[0], Era::Launch, 5.0, 20); // long_window 5_000
        let s2 = run_scenario(&sets[2], Era::Launch, 5.0, 20); // long_window 50_000
        assert!(
            s2.growth_factor < s0.growth_factor,
            "longer long-window must damp creep: s2={} s0={}",
            s2.growth_factor,
            s0.growth_factor
        );
    }

    #[test]
    fn rational_block_is_at_least_the_free_zone_and_at_most_double() {
        let p = WeightParams::devnet_default();
        let m = p.min_weight;
        let b = rational_block_weight(m, Era::Launch.base_reward_bessel(), &p);
        assert!(b >= m, "miner always fills at least the penalty-free zone");
        assert!(b <= 2 * m, "never past the hard cap");
    }

    #[test]
    fn tail_era_gives_more_ground_than_launch() {
        // The penalty scales with base_reward; a smaller tail reward ⇒ the miner
        // tolerates a larger over-median block for the same fee.
        let p = WeightParams::devnet_default();
        let m = p.min_weight;
        let launch = rational_block_weight(m, Era::Launch.base_reward_bessel(), &p);
        let tail = rational_block_weight(m, Era::Tail.base_reward_bessel(), &p);
        assert!(tail >= launch, "tail era must tolerate ≥ the launch block size");
    }

    #[test]
    fn no_governor_growth_scales_with_budget() {
        let g1 = run_no_governor(Era::Launch, 1.0);
        let g2 = run_no_governor(Era::Launch, 2.0);
        assert!((g2 - 2.0 * g1).abs() < 1e-6, "ungoverned growth is linear in budget");
        assert!(g1 > 0.0);
    }

    #[test]
    fn budget_limited_flood_costs_at_most_its_budget_fraction() {
        // Attacker cost as %emission can never exceed the budget it committed.
        let r = run_scenario(&set(), Era::Launch, 1.0, 20);
        assert!(
            r.attacker_cost_pct_emission <= 100.5,
            "cost {}% can't exceed the 100% (1×emission) budget",
            r.attacker_cost_pct_emission
        );
    }

    #[test]
    fn deterministic_reproduces_identically() {
        let a = run_scenario(&set(), Era::Launch, 2.0, 15);
        let b = run_scenario(&set(), Era::Launch, 2.0, 15);
        assert_eq!(a.final_effective_median_bytes, b.final_effective_median_bytes);
        assert_eq!(a.peak_block_bytes, b.peak_block_bytes);
        assert_eq!(
            a.chain_growth_mb_per_day.to_bits(),
            b.chain_growth_mb_per_day.to_bits()
        );
    }
}
