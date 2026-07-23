//! LWMA-120 difficulty retarget (Zawy's **LWMA-1**).
//!
//! LWMA (Linearly Weighted Moving Average) retargets *every block* from a window
//! of the last `N` solvetimes, weighting the most recent solvetime `N×` and the
//! oldest `1×`. It is the field's standard answer to the timestamp-manipulation
//! and hashrate-oscillation attacks that sink slower retargets, and is what the
//! CryptoNote/RandomX ecosystem converged on. We use `N = 120` at the **frozen
//! 75 s** block time (consensus-parameters §2).
//!
//! ## The arithmetic (all in `u128`, exact integer form)
//!
//! For solvetimes `ST₁..ST_N` (oldest→newest) and the difficulties `D₁..D_N` of
//! the blocks that produced them:
//!
//! ```text
//!   L      = Σ i·STᵢ                    (linearly weighted solvetime sum)
//!   L      = max(L, N(N+1)·T / 20)      (low clamp: caps the per-retarget RISE
//!                                          at ~10× the window-average difficulty)
//!   sum_D  = Σ Dᵢ
//!   next_D = sum_D · T · (N+1) / (2·L)
//! ```
//!
//! On an exactly-on-target window (`STᵢ = T ∀i`) this yields `next_D = avg(D)`
//! *exactly*, so a steady chain does not drift. Each solvetime is first clamped:
//! non-increasing timestamps are treated as `+1 s` (per the reference), and a
//! single gap is capped at `6·T` so one outlier block cannot crater difficulty.
//! The result is floored at `1` (a 0 difficulty would make the target trivial).
//!
//! ## Parameter status
//!
//! `N = 120` and the clamps are **testnet-tunable and NOT frozen** (protocol-spec
//! §10 — full-M8 freezes the retarget at v1.1). `T = 75 s` is frozen. These follow
//! Zawy's LWMA-1 for provenance; they are prototype choices, not Qumbra proposals.

/// The recommended LWMA window length for Qumbra's prototype (N = 120).
/// Testnet-tunable, NOT frozen.
pub const LWMA_WINDOW: usize = 120;

/// Compute the difficulty a new block must carry, per LWMA-1, from a trailing
/// window.
///
/// - `timestamps`: the timestamps of the last `N + 1` blocks, oldest first. The
///   `N` consecutive differences are the solvetimes.
/// - `difficulties`: the difficulties of the last `N` blocks (block `i`'s
///   difficulty pairs with solvetime `timestamps[i+1] - timestamps[i]`).
/// - `t_target`: the target block time in seconds (`T`).
///
/// `N` is taken from `difficulties.len()`; `timestamps.len()` MUST be `N + 1`.
/// Returns a difficulty `≥ 1`. With an empty window (`N == 0`) returns `1` — the
/// caller is expected to hold the genesis difficulty during warmup rather than
/// call in with no history.
pub fn lwma_next_difficulty(timestamps: &[u64], difficulties: &[u64], t_target: u64) -> u64 {
    let n = difficulties.len();
    debug_assert_eq!(
        timestamps.len(),
        n + 1,
        "LWMA needs exactly N+1 timestamps for N difficulties"
    );
    if n == 0 || timestamps.len() != n + 1 {
        return 1;
    }

    let t = t_target.max(1) as u128;
    let n_u = n as u128;
    let six_t = 6 * t;

    // Linearly weighted solvetime sum L = Σ i·STᵢ (i = 1..N, newest weighted N).
    let mut weighted_solvetime: u128 = 0;
    let mut prev = timestamps[0];
    for (i, &next) in timestamps[1..].iter().enumerate() {
        // Out-of-sequence guard (reference LWMA-1): a non-increasing timestamp is
        // treated as prev+1, i.e. a 1 s solvetime.
        let this = if next > prev { next } else { prev + 1 };
        let solvetime = (this - prev).min(six_t as u64) as u128;
        prev = this;
        let weight = (i as u128) + 1; // i is 0-based here ⇒ oldest weight 1, newest N
        weighted_solvetime += weight * solvetime;
    }

    // Low clamp: bound how fast difficulty may rise (≈10× the window average).
    let l_floor = n_u * (n_u + 1) * t / 20;
    let l = weighted_solvetime.max(l_floor).max(1);

    let sum_d: u128 = difficulties.iter().map(|&d| d as u128).sum();

    // next_D = sum_D · T · (N+1) / (2·L)
    let next = sum_d * t * (n_u + 1) / (2 * l);
    next.clamp(1, u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 75; // frozen target block time
    const N: usize = 120;

    /// Build an on-cadence window: N+1 timestamps `spacing` apart and N blocks all
    /// at difficulty `d`.
    fn window(d: u64, spacing: u64, n: usize) -> (Vec<u64>, Vec<u64>) {
        let ts: Vec<u64> = (0..=n as u64).map(|i| i * spacing).collect();
        let ds: Vec<u64> = vec![d; n];
        (ts, ds)
    }

    #[test]
    fn on_target_window_is_a_fixed_point() {
        // STᵢ = T for all i ⇒ next difficulty == the window difficulty, exactly.
        let (ts, ds) = window(1_000_000, T, N);
        assert_eq!(lwma_next_difficulty(&ts, &ds, T), 1_000_000);
    }

    #[test]
    fn faster_blocks_raise_difficulty() {
        // Blocks arriving at half the target spacing ⇒ difficulty must rise.
        let (ts, ds) = window(1_000_000, T / 2, N);
        let next = lwma_next_difficulty(&ts, &ds, T);
        assert!(next > 1_000_000, "fast blocks must raise difficulty (got {next})");
    }

    #[test]
    fn slower_blocks_lower_difficulty() {
        // Blocks arriving at twice the target spacing ⇒ difficulty must fall,
        // roughly halving (2× spacing ⇒ ~½ difficulty).
        let (ts, ds) = window(1_000_000, 2 * T, N);
        let next = lwma_next_difficulty(&ts, &ds, T);
        assert!(next < 1_000_000, "slow blocks must lower difficulty (got {next})");
        assert!(
            (450_000..=550_000).contains(&next),
            "2× spacing should ~halve difficulty (got {next})"
        );
    }

    #[test]
    fn rise_is_capped_by_the_low_clamp() {
        // All solvetimes 0 (instant blocks) ⇒ the low-L clamp caps the rise at
        // ~10× the window-average difficulty rather than exploding.
        let (ts, ds) = window(1_000_000, 0, N);
        let next = lwma_next_difficulty(&ts, &ds, T);
        // ~10× (N(N+1)T/20 floor ⇒ 10·avg), allow a little integer slack.
        assert!(
            (9_000_000..=11_000_000).contains(&next),
            "instant blocks should be capped near 10× (got {next})"
        );
    }

    #[test]
    fn a_single_huge_gap_is_clamped_to_six_t() {
        // One enormous solvetime among on-target ones: its effect is bounded by the
        // 6T clamp, so difficulty dips modestly rather than collapsing.
        let mut ts: Vec<u64> = (0..=N as u64).map(|i| i * T).collect();
        // Blow out the most recent gap to 1000×T; only 6T should register.
        let last = *ts.last().unwrap();
        *ts.last_mut().unwrap() = last + 1000 * T;
        let ds = vec![1_000_000u64; N];
        let clamped = lwma_next_difficulty(&ts, &ds, T);

        // Compare to the same window with an *un-clamped* huge final solvetime by
        // building what an unbounded formula would give: difficulty must stay far
        // above that, i.e. the clamp protected it.
        assert!(clamped > 900_000, "6T clamp should keep the dip small (got {clamped})");
        assert!(clamped < 1_000_000, "the gap should still lower difficulty a bit");
    }

    #[test]
    fn out_of_sequence_timestamp_is_handled_deterministically() {
        // A backwards timestamp must not panic or underflow; it is treated as +1 s.
        let mut ts: Vec<u64> = (0..=N as u64).map(|i| i * T).collect();
        // Make one timestamp jump backwards below its predecessor.
        ts[N] = ts[N - 1].saturating_sub(10 * T);
        let ds = vec![1_000_000u64; N];
        let a = lwma_next_difficulty(&ts, &ds, T);
        let b = lwma_next_difficulty(&ts, &ds, T);
        assert_eq!(a, b, "must be deterministic on out-of-sequence input");
        assert!(a >= 1);
    }

    #[test]
    fn recency_weighting_a_recent_slowdown_lowers_more_than_an_old_one() {
        // Two windows: both have exactly one 3×T gap, one at the newest position,
        // one at the oldest. The recent slowdown (weight N) must pull difficulty
        // down MORE than the old one (weight 1).
        let make = |slow_at: usize| -> (Vec<u64>, Vec<u64>) {
            let mut spacings = vec![T; N];
            spacings[slow_at] = 3 * T;
            let mut ts = vec![0u64];
            for s in &spacings {
                ts.push(ts.last().unwrap() + s);
            }
            (ts, vec![1_000_000u64; N])
        };
        let (ts_recent, ds) = make(N - 1); // newest solvetime is slow
        let (ts_old, _) = make(0); // oldest solvetime is slow
        let recent = lwma_next_difficulty(&ts_recent, &ds, T);
        let old = lwma_next_difficulty(&ts_old, &ds, T);
        assert!(
            recent < old,
            "a recent slowdown must lower difficulty more than an old one (recent {recent} vs old {old})"
        );
    }

    #[test]
    fn result_is_floored_at_one() {
        // Absurdly slow blocks with tiny difficulty must never return 0.
        let (ts, ds) = window(1, 1_000_000 * T, N);
        assert!(lwma_next_difficulty(&ts, &ds, T) >= 1);
    }

    #[test]
    fn works_for_a_short_warmup_window() {
        // LWMA is well-defined for any N ≥ 1; a 3-block on-target window is a fixed
        // point too.
        let (ts, ds) = window(500, T, 3);
        assert_eq!(lwma_next_difficulty(&ts, &ds, T), 500);
    }

    #[test]
    fn empty_window_returns_floor() {
        assert_eq!(lwma_next_difficulty(&[0], &[], T), 1);
    }
}
