//! A tiny deterministic PRNG for the load-test sims — **SplitMix64** (Steele,
//! Lea & Flood 2014; the algorithm Java's `SplittableRandom` uses).
//!
//! The load harness must be **exactly reproducible** (bench discipline #3: a
//! number is publishable only after reproducing twice). A seeded, dependency-free
//! generator with a fixed algorithm guarantees `run1 == run2` byte-for-byte on any
//! machine — no `rand` crate, no platform entropy, no `Date`/wall-clock inputs.
//! This is a *statistical* PRNG for scenario draws (downtime patterns, block-race
//! timing), never a cryptographic one.

/// SplitMix64 state. Constructed from a `u64` seed; every draw is a pure function
/// of the running state, so a given seed replays an identical stream forever.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator. Distinct seeds give independent-looking streams.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next raw 64-bit value (the canonical SplitMix64 mixing function).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform `f64` in `[0, 1)` (53-bit mantissa precision).
    pub fn next_f64(&mut self) -> f64 {
        // Top 53 bits → [0,1). 2^53 as f64 is exact.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A Bernoulli draw: `true` with probability `p` (clamped to `[0,1]`).
    pub fn bernoulli(&mut self, p: f64) -> bool {
        self.next_f64() < p.clamp(0.0, 1.0)
    }

    /// A uniform integer in `[0, n)` (via rejection-free multiply-shift; `n == 0`
    /// returns 0). Adequate for sim indexing — not bias-free at cryptographic
    /// standards, but fully deterministic.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        ((self.next_u64() as u128 * n as u128) >> 64) as u64
    }

    /// An exponential inter-arrival time with rate `1/mean` (mean > 0). Used to
    /// model Poisson block arrivals in the reorg race sim. Returns `mean` if the
    /// uniform draw is degenerate.
    pub fn exponential(&mut self, mean: f64) -> f64 {
        let u = self.next_f64();
        if u <= 0.0 {
            return mean;
        }
        -mean * (1.0 - u).ln()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_replays_identical_stream() {
        let mut a = SplitMix64::new(0xDEAD_BEEF);
        let mut b = SplitMix64::new(0xDEAD_BEEF);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        // Overwhelmingly likely to differ within a few draws.
        let differ = (0..8).any(|_| a.next_u64() != b.next_u64());
        assert!(differ);
    }

    #[test]
    fn f64_is_in_unit_interval() {
        let mut r = SplitMix64::new(42);
        for _ in 0..10_000 {
            let x = r.next_f64();
            assert!((0.0..1.0).contains(&x), "f64 out of [0,1): {x}");
        }
    }

    #[test]
    fn bernoulli_frequency_is_roughly_p() {
        let mut r = SplitMix64::new(7);
        let n = 100_000;
        let hits = (0..n).filter(|_| r.bernoulli(0.25)).count();
        let freq = hits as f64 / n as f64;
        assert!((freq - 0.25).abs() < 0.01, "bernoulli(0.25) freq={freq}");
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = SplitMix64::new(99);
        for _ in 0..10_000 {
            assert!(r.below(6) < 6);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn exponential_mean_is_roughly_correct() {
        let mut r = SplitMix64::new(123);
        let n = 200_000;
        let mean = 75.0;
        let sum: f64 = (0..n).map(|_| r.exponential(mean)).sum();
        let sample_mean = sum / n as f64;
        // Within 2% of the target mean over 200k draws.
        assert!((sample_mean - mean).abs() / mean < 0.02, "exp mean={sample_mean}");
    }

    /// The load-bearing reproducibility guarantee: the first few draws of a fixed
    /// seed are pinned, so a regression in the mixing function is caught here (and
    /// run1/run2 tables can never silently drift).
    #[test]
    fn golden_first_draws_are_pinned() {
        let mut r = SplitMix64::new(0);
        // SplitMix64(0) canonical first outputs.
        assert_eq!(r.next_u64(), 16294208416658607535);
        assert_eq!(r.next_u64(), 7960286522194355700);
    }
}
