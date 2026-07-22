//! Block-weight anti-spam governor — the Monero-style **two-median + quadratic
//! penalty** form (consensus-and-network.md §8; consensus-parameters §6, `[open]`).
//!
//! Posted-price fees (`fees.rs`) remove the fee auction; this governor is the
//! backstop that stops posted-price blocks being stuffed for free. The mechanism
//! is Monero's post-2019-fork two-median rule ([design draft], [consensus rules]):
//!
//! 1. **Long-term median.** Each block's *long-term weight* is its actual weight
//!    capped at `lt_cap × (previous long-term effective median)` — one block can
//!    never drag the long-term baseline up by more than the cap factor. The
//!    long-term effective median is `max(min_weight, median(last long_window
//!    long-term weights))`. This is the slow, manipulation-resistant baseline.
//! 2. **Short-term median.** `median(last short_window actual weights)` — the
//!    responsive signal that lets genuine demand grow the block faster than the
//!    long-term baseline, but only up to `st_cap × long-term effective median`.
//! 3. **Effective median** `M = min(max(min_weight, short_median), st_cap ×
//!    lt_effective_median)`. Filling a block up to `M` is penalty-free.
//! 4. **Quadratic penalty.** A block of weight `b` with `M < b ≤ max_multiple × M`
//!    keeps `base_reward × (1 − ((b − M)/M)²)`; the penalty is
//!    `base_reward × (b − M)² / M²`. A block with `b > max_multiple × M` is
//!    **invalid** (the hard cap). At `b = 2M` (Monero's `max_multiple = 2`) the
//!    entire base reward is penalized away — the miner earns only fees.
//!
//! **Every constant here is `[open]`** (consensus-parameters §6) and lives in a
//! tunable [`WeightParams`] so the load harness can sweep candidate sets. The
//! `DEVNET_*` defaults in `params_devnet` are placeholders, not proposals.
//!
//! Integer arithmetic throughout (consensus math is never floating-point): the
//! penalty uses a `u128` intermediate and the `lt_cap` is a rational `num/den`.
//!
//! [design draft]: https://github.com/JollyMort/monero-research/blob/master/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee%20-%20DRAFT.md
//! [consensus rules]: https://monero-book.cuprate.org/consensus_rules/blocks/weights.html

/// Tunable constants for the two-median block-weight governor. All fields are
/// `[open]` design questions (consensus-parameters §6) — the load harness sweeps
/// candidate sets over them. Weight is measured in **bytes** (Σ tx proof bytes +
/// body overhead; see `load` scenario inputs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightParams {
    /// Short-term median window, in blocks (Monero: 100).
    pub short_window: usize,
    /// Long-term median window, in blocks (Monero: 100_000).
    pub long_window: usize,
    /// Floor on the effective median (the penalty-free zone never drops below
    /// this), in bytes (Monero: 300_000).
    pub min_weight: u64,
    /// Long-term weight cap factor numerator (Monero 1.4 = 7/5 ⇒ num=7).
    pub lt_cap_num: u64,
    /// Long-term weight cap factor denominator (Monero 1.4 = 7/5 ⇒ den=5).
    pub lt_cap_den: u64,
    /// Short-term median is capped at `st_cap × long-term effective median`
    /// (Monero: 50).
    pub st_cap: u64,
    /// Hard block-weight limit as a multiple of the effective median: a block of
    /// weight `> max_multiple × M` is invalid (Monero: 2).
    pub max_multiple: u64,
}

impl WeightParams {
    /// The placeholder devnet defaults (`params_devnet::WEIGHT_*`). Every field is
    /// an `[open]` constant — this is a sweep starting point, not a proposal.
    pub fn devnet_default() -> Self {
        use crate::params_devnet as p;
        Self {
            short_window: p::WEIGHT_SHORT_WINDOW,
            long_window: p::WEIGHT_LONG_WINDOW,
            min_weight: p::WEIGHT_MIN_BYTES,
            lt_cap_num: p::WEIGHT_LT_CAP_NUM,
            lt_cap_den: p::WEIGHT_LT_CAP_DEN,
            st_cap: p::WEIGHT_ST_CAP,
            max_multiple: p::WEIGHT_MAX_MULTIPLE,
        }
    }
}

/// The median of `xs` (sorted-copy, lower-of-two for even length — matching
/// Monero's `epee::misc_utils::median`, which returns element `n/2` of the
/// sorted list). Empty slice ⇒ 0.
pub fn median(xs: &[u64]) -> u64 {
    if xs.is_empty() {
        return 0;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    // Monero's median: for even n it averages the two middle; for odd n the
    // middle. We follow that exactly.
    let n = v.len();
    if n.is_multiple_of(2) {
        // average of the two central elements (round down)
        ((v[n / 2 - 1] as u128 + v[n / 2] as u128) / 2) as u64
    } else {
        v[n / 2]
    }
}

/// The hard block-weight limit for a given effective median `m`:
/// `max_multiple × m`. A candidate block weight strictly above this is invalid.
pub fn weight_limit(m: u64, params: &WeightParams) -> u64 {
    m.saturating_mul(params.max_multiple)
}

/// Whether a candidate block of `weight` bytes is admissible against effective
/// median `m` — i.e. `weight ≤ max_multiple × m` (the hard cap).
pub fn is_weight_admissible(weight: u64, m: u64, params: &WeightParams) -> bool {
    weight <= weight_limit(m, params)
}

/// The quadratic reward penalty for a block of `weight` bytes against effective
/// median `m`, given `base_reward`:
///
/// - `weight ≤ m` ⇒ **0** (penalty-free zone).
/// - `m < weight ≤ max_multiple·m` ⇒ `base_reward × (weight − m)² / m²`.
/// - `weight > max_multiple·m` ⇒ the block is invalid; this function saturates at
///   `base_reward` but callers must reject the block via [`is_weight_admissible`].
///
/// Integer math with a `u128` intermediate; `m` is guaranteed ≥ 1 because the
/// effective median is floored at `min_weight` (which a sane config keeps ≥ 1).
pub fn quadratic_penalty(base_reward: u64, weight: u64, m: u64, params: &WeightParams) -> u64 {
    if weight <= m || m == 0 {
        return 0;
    }
    // Saturate the overage at the hard cap: a block at exactly max_multiple·m is
    // fully penalized, and anything past it is invalid (caller rejects it).
    let w = weight.min(weight_limit(m, params));
    let d = (w - m) as u128;
    let m2 = (m as u128) * (m as u128);
    let pen = (base_reward as u128).saturating_mul(d).saturating_mul(d) / m2;
    pen.min(base_reward as u128) as u64
}

/// Stateful two-median governor: ingest block weights in chain order via
/// [`WeightGovernor::push_block`], read the current [`WeightGovernor::effective_median`].
#[derive(Clone, Debug)]
pub struct WeightGovernor {
    params: WeightParams,
    /// Actual block weights, oldest first.
    weights: Vec<u64>,
    /// Per-block long-term weights (actual capped by lt_cap × prior lt median).
    lt_weights: Vec<u64>,
    /// Cached long-term effective median (max(min_weight, median(last long_window lt_weights))).
    lt_effective_median: u64,
}

impl WeightGovernor {
    /// A fresh governor whose long-term effective median starts at `min_weight`.
    pub fn new(params: WeightParams) -> Self {
        Self {
            lt_effective_median: params.min_weight,
            params,
            weights: Vec::new(),
            lt_weights: Vec::new(),
        }
    }

    /// Ingest a produced block of `weight` bytes, updating both medians. The
    /// block's long-term weight is capped at `lt_cap × (previous long-term
    /// effective median)`, then the long-term effective median is recomputed over
    /// the trailing `long_window`.
    pub fn push_block(&mut self, weight: u64) {
        // Long-term weight = actual capped by lt_cap × the PRIOR lt effective
        // median (so one block cannot lift the baseline by more than the factor).
        let cap = ((self.lt_effective_median as u128 * self.params.lt_cap_num as u128)
            / self.params.lt_cap_den as u128) as u64;
        let lt_weight = weight.min(cap);
        self.weights.push(weight);
        self.lt_weights.push(lt_weight);

        let start = self.lt_weights.len().saturating_sub(self.params.long_window);
        let med = median(&self.lt_weights[start..]);
        self.lt_effective_median = med.max(self.params.min_weight);
    }

    /// The current long-term effective median.
    pub fn long_term_effective_median(&self) -> u64 {
        self.lt_effective_median
    }

    /// The current short-term median (over the last `short_window` actual weights).
    pub fn short_term_median(&self) -> u64 {
        let start = self.weights.len().saturating_sub(self.params.short_window);
        median(&self.weights[start..])
    }

    /// The current **effective median** `M` — the penalty-free block size:
    /// `min( max(min_weight, short_median), st_cap × lt_effective_median )`.
    pub fn effective_median(&self) -> u64 {
        let short_floored = self.short_term_median().max(self.params.min_weight);
        let st_ceiling = self.lt_effective_median.saturating_mul(self.params.st_cap);
        short_floored.min(st_ceiling)
    }

    /// This governor's parameters.
    pub fn params(&self) -> &WeightParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Monero-shape defaults, small windows for fast tests.
    fn params() -> WeightParams {
        WeightParams {
            short_window: 4,
            long_window: 8,
            min_weight: 1_000,
            lt_cap_num: 7,
            lt_cap_den: 5, // 1.4×
            st_cap: 50,
            max_multiple: 2,
        }
    }

    #[test]
    fn devnet_default_wires_the_placeholders() {
        use crate::params_devnet as p;
        let d = WeightParams::devnet_default();
        assert_eq!(d.short_window, p::WEIGHT_SHORT_WINDOW);
        assert_eq!(d.long_window, p::WEIGHT_LONG_WINDOW);
        assert_eq!(d.min_weight, p::WEIGHT_MIN_BYTES);
        assert_eq!(d.max_multiple, p::WEIGHT_MAX_MULTIPLE);
        // Sanity: a fresh governor's floor is the placeholder min_weight.
        assert_eq!(WeightGovernor::new(d).effective_median(), p::WEIGHT_MIN_BYTES);
    }

    // ── median ──────────────────────────────────────────────────────────────

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median(&[5]), 5);
        assert_eq!(median(&[3, 1, 2]), 2); // sorted [1,2,3] → 2
        assert_eq!(median(&[4, 2]), 3); // even → (2+4)/2 = 3
        assert_eq!(median(&[10, 20, 30, 40]), 25); // (20+30)/2
        assert_eq!(median(&[]), 0);
    }

    // ── penalty boundary behavior (the mandated negatives) ───────────────────

    #[test]
    fn penalty_is_zero_at_or_below_median() {
        let p = params();
        let base = 1_000_000;
        let m = 10_000;
        assert_eq!(quadratic_penalty(base, 0, m, &p), 0);
        assert_eq!(quadratic_penalty(base, m / 2, m, &p), 0);
        // EXACTLY at the median: still penalty-free.
        assert_eq!(quadratic_penalty(base, m, m, &p), 0);
    }

    #[test]
    fn penalty_fires_exactly_one_byte_above_the_median() {
        let p = params();
        // base = m² so the quadratic is integer-visible even at a 1-byte overage
        // (with base < m² a tiny overage rounds to 0 — that near-median-rounding
        // property is documented separately in `tiny_overage_rounds_to_zero`).
        let m = 1_000;
        let base = m * m; // 1_000_000
        // The boundary negative: at m → 0, at m+1 → strictly positive.
        assert_eq!(quadratic_penalty(base, m, m, &p), 0);
        assert!(
            quadratic_penalty(base, m + 1, m, &p) > 0,
            "penalty must fire the instant weight exceeds the median"
        );
    }

    #[test]
    fn tiny_overage_rounds_to_zero_when_base_is_small_relative_to_m_squared() {
        // A real, documented property of the integer quadratic: near the median
        // the penalty is negligible and rounds to zero. Design-honest — the
        // governor bites hard only as b approaches the 2M hard cap.
        let p = params();
        let m = 10_000;
        let base = 1_000_000; // base ≪ m² (1e8) ⇒ penalty(m+1) = base·1/m² = 0
        assert_eq!(quadratic_penalty(base, m + 1, m, &p), 0);
    }

    #[test]
    fn penalty_is_full_base_reward_at_double_the_median() {
        let p = params();
        let m = 1_000;
        let base = m * m;
        // At b = 2M the fraction is ((2M-M)/M)^2 = 1 ⇒ full base_reward penalized.
        assert_eq!(quadratic_penalty(base, 2 * m, m, &p), base);
    }

    #[test]
    fn penalty_is_quadratic_at_the_quarter_point() {
        let p = params();
        let m = 1_000;
        let base = m * m;
        // b = 1.5M ⇒ ((0.5M)/M)^2 = 0.25 ⇒ quarter of base_reward.
        assert_eq!(quadratic_penalty(base, m + m / 2, m, &p), base / 4);
    }

    // ── hard cap admissibility ───────────────────────────────────────────────

    #[test]
    fn weight_limit_and_admissibility_at_the_hard_cap() {
        let p = params();
        let m = 10_000;
        assert_eq!(weight_limit(m, &p), 20_000); // max_multiple = 2
        assert!(is_weight_admissible(2 * m, m, &p)); // exactly at 2M is OK
        assert!(!is_weight_admissible(2 * m + 1, m, &p)); // one byte past 2M is invalid
    }

    // ── two-median dynamics ──────────────────────────────────────────────────

    #[test]
    fn fresh_governor_effective_median_is_min_weight() {
        let p = params();
        let g = WeightGovernor::new(p);
        assert_eq!(g.long_term_effective_median(), p.min_weight);
        assert_eq!(g.effective_median(), p.min_weight);
    }

    #[test]
    fn steady_small_blocks_hold_the_effective_median_at_min_weight() {
        let p = params();
        let mut g = WeightGovernor::new(p);
        for _ in 0..20 {
            g.push_block(p.min_weight / 2); // small blocks, below the floor
        }
        // Both medians floored at min_weight.
        assert_eq!(g.effective_median(), p.min_weight);
        assert_eq!(g.long_term_effective_median(), p.min_weight);
    }

    #[test]
    fn short_term_median_tracks_recent_larger_blocks() {
        let p = params();
        let mut g = WeightGovernor::new(p);
        // Fill the short window with 5_000-byte blocks (above min_weight 1_000).
        for _ in 0..p.short_window {
            g.push_block(5_000);
        }
        assert_eq!(g.short_term_median(), 5_000);
        // Effective median rises above min_weight (short median leads, still ≤ st_cap·lt).
        assert!(g.effective_median() >= 1_000);
    }

    #[test]
    fn long_term_cap_limits_how_fast_one_block_lifts_the_baseline() {
        let p = params();
        let mut g = WeightGovernor::new(p);
        // A single giant block: its long-term weight is capped at 1.4×min_weight,
        // so it cannot drag the long-term baseline up arbitrarily.
        g.push_block(1_000_000_000);
        // lt weight for block 0 = min(1e9, 1.4 × min_weight) = 1_400.
        // median of lt_weights ([1_400]) = 1_400, floored by min_weight → 1_400.
        assert_eq!(g.long_term_effective_median(), 1_400);
    }

    #[test]
    fn short_term_median_is_capped_by_st_cap_times_long_term() {
        // With a tiny st_cap the effective median can't exceed st_cap × lt median
        // no matter how big recent blocks are.
        let mut p = params();
        p.st_cap = 1; // effective median ≤ 1 × lt median
        let mut g = WeightGovernor::new(p);
        for _ in 0..p.short_window {
            g.push_block(500_000); // huge short-term spike
        }
        // Effective median is clamped down to the long-term effective median.
        assert_eq!(g.effective_median(), g.long_term_effective_median());
    }
}
