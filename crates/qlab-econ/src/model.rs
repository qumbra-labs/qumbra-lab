//! The emission-function family.
//!
//! Two closed-form families, both parameterized by `{initial reward r0, per-block
//! decay rate d, tail rate tail}` (tokenomics-and-issuance.md §7's three open
//! constants). The whole point of §1 job 4 is that **supply-at-height S(h) is an
//! exact closed form** — no era table, no per-block iteration required to audit
//! it — so every curve here exposes `supply(h)` as a single arithmetic expression.
//!
//! ## MoneroClass — `max(geometric decay, tail floor)`
//!
//! The literal §3 precedent. Monero's rule is `baseReward = (2^64−1−generated) >> 19`
//! — reward is a pure function of *cumulative issuance*, geometric in height, with
//! a hard constant floor. Here:
//!
//! ```text
//!   decayReward(h) = r0 · (1−d)^h            (equivalently d·(S_inf − S(h)), S_inf = r0/d)
//!   reward(h)      = max(decayReward(h), tail)
//! ```
//!
//! The tail is a **fixed absolute emission** — exactly the shape Todd's
//! asymptotic-non-inflation argument (§3) is about. Value-continuous, no cliffs;
//! it has a slope kink at tail activation (so C0, not C1 — the honest Monero
//! behavior; see `checks::continuity`).
//!
//! ## AdditiveSmooth — `tail + (r0−tail)·(1−d)^h`
//!
//! The genuinely-C∞ contrast: reward decays smoothly and asymptotically *toward*
//! the tail, never kinking. The cost is that the tail is only *approached*, never
//! a fixed constant emission — so Todd's fixed-emission argument applies only in
//! the limit. Offered so the coordinator can see the C1-vs-Todd trade explicitly.

/// Julian year in seconds (365.25 d). Long-horizon calendar framing.
pub const SECS_PER_YEAR: f64 = 365.25 * 86_400.0;

/// Atomic subunits per coin (8 decimals, BTC-class). Only used by the exact
/// integer audit-anchor test; the sweep works in coins (f64) — fine "to the coin".
pub const ATOMIC_PER_COIN: u128 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `max(r0·(1−d)^h, tail)` — Monero-class, fixed tail floor (§3 precedent).
    MoneroClass,
    /// `tail + (r0−tail)·(1−d)^h` — C∞, tail only approached.
    AdditiveSmooth,
}

/// One emission curve. All rates are in **coins**; `d` is the per-block geometric
/// decay rate (retention factor `k = 1−d`).
#[derive(Debug, Clone, Copy)]
pub struct Model {
    pub family: Family,
    /// Initial block reward at height 0 (coins).
    pub r0: f64,
    /// Per-block decay rate, in (0,1). `k = 1−d`.
    pub d: f64,
    /// Perpetual tail floor (coins/block). Must be > 0 (§1: pay PoW + committee
    /// forever) and < r0 (so the curve actually decays into the tail).
    pub tail: f64,
    /// Seconds per block (consensus doc band: 60–75 s).
    pub block_time_s: f64,
}

impl Model {
    /// Build a MoneroClass curve from human-facing targets:
    /// - `r0`               initial reward (coins/block) — pure denomination (see
    ///                      the R0-scale finding in the sweep); does not move any %-metric.
    /// - `half_life_years`  time for the *decay* reward to halve.
    /// - `block_time_s`     60–75 s.
    /// - `target_tail_infl` desired annual inflation at tail activation (Monero
    ///                      landed 0.87%). The tail rate is solved to hit it.
    pub fn monero_from_targets(
        r0: f64,
        half_life_years: f64,
        block_time_s: f64,
        target_tail_infl: f64,
    ) -> Model {
        let b = SECS_PER_YEAR / block_time_s; // blocks/year
        let half_life_blocks = half_life_years * b;
        // (1−d)^H = 1/2  ⇒  d = 1 − 2^(−1/H)
        let d = 1.0 - 0.5_f64.powf(1.0 / half_life_blocks);
        // Activation inflation ρ = tail·B·d / (r0 − tail)  (S(h_t) = (r0−tail)/d).
        // Solve for tail:  tail = ρ·r0 / (B·d + ρ).
        let tail = target_tail_infl * r0 / (b * d + target_tail_infl);
        Model { family: Family::MoneroClass, r0, d, tail, block_time_s }
    }

    /// Build an AdditiveSmooth curve with an explicit tail (coins/block) — its
    /// activation is soft, so there is no clean target-inflation solve. Meant for
    /// apples-to-apples contrast against a MoneroClass candidate (same r0, d, tail).
    pub fn additive(r0: f64, d: f64, tail: f64, block_time_s: f64) -> Model {
        Model { family: Family::AdditiveSmooth, r0, d, tail, block_time_s }
    }

    #[inline]
    pub fn k(&self) -> f64 {
        1.0 - self.d
    }

    #[inline]
    pub fn blocks_per_year(&self) -> f64 {
        SECS_PER_YEAR / self.block_time_s
    }

    /// `k^h`, computed as `exp(h·ln k)` — accurate for the millions-of-blocks
    /// heights this model sweeps (`powi` loses precision / overflows there).
    #[inline]
    fn k_pow(&self, h: f64) -> f64 {
        (h * self.k().ln()).exp()
    }

    /// The pure decaying component at height `h` (before the floor is applied).
    #[inline]
    pub fn decay_reward(&self, h: f64) -> f64 {
        match self.family {
            Family::MoneroClass => self.r0 * self.k_pow(h),
            Family::AdditiveSmooth => (self.r0 - self.tail) * self.k_pow(h),
        }
    }

    /// Block reward at height `h` (coins).
    #[inline]
    pub fn reward(&self, h: f64) -> f64 {
        match self.family {
            Family::MoneroClass => self.decay_reward(h).max(self.tail),
            Family::AdditiveSmooth => self.tail + self.decay_reward(h),
        }
    }

    /// Asymptotic pre-tail supply — the ceiling the decaying component approaches
    /// (S_inf for MoneroClass = r0/d; total excess-over-tail for AdditiveSmooth).
    /// There is **no hard cap** either way: the tail adds linearly forever (§ dec. 4).
    pub fn s_inf(&self) -> f64 {
        match self.family {
            Family::MoneroClass => self.r0 / self.d,
            Family::AdditiveSmooth => (self.r0 - self.tail) / self.d,
        }
    }

    /// The height at which the tail floor engages.
    ///
    /// - MoneroClass: first integer `h` with `decayReward(h) ≤ tail` — the exact
    ///   activation block, after which reward is constant.
    /// - AdditiveSmooth: the *soft* crossover where the decaying excess equals the
    ///   tail (i.e. reward = 2·tail); there is no hard activation.
    pub fn tail_activation_height(&self) -> f64 {
        // Solve decay_reward(h) = tail.
        let ratio = match self.family {
            Family::MoneroClass => self.tail / self.r0,
            Family::AdditiveSmooth => self.tail / (self.r0 - self.tail),
        };
        let h = ratio.ln() / self.k().ln();
        h.ceil().max(0.0)
    }

    /// **The audit anchor.** Cumulative supply emitted through block `h−1`
    /// (i.e. supply *at* height `h`, with S(0)=0), as an exact closed form.
    pub fn supply(&self, h: f64) -> f64 {
        match self.family {
            Family::MoneroClass => {
                let ht = self.tail_activation_height();
                if h <= ht {
                    // Σ_{i=0}^{h−1} r0·k^i = r0·(1 − k^h)/d
                    self.r0 * (1.0 - self.k_pow(h)) / self.d
                } else {
                    // decay through block ht−1, then constant tail
                    self.r0 * (1.0 - self.k_pow(ht)) / self.d + self.tail * (h - ht)
                }
            }
            Family::AdditiveSmooth => {
                // Σ_{i=0}^{h−1} [tail + (r0−tail)·k^i]
                self.tail * h + (self.r0 - self.tail) * (1.0 - self.k_pow(h)) / self.d
            }
        }
    }

    /// Supply at a whole number of years after genesis.
    pub fn supply_at_year(&self, year: f64) -> f64 {
        self.supply(year * self.blocks_per_year())
    }

    /// Annual inflation over calendar year `year` → `year+1`:
    /// `(S(end) − S(start)) / S(start)`. Undefined (returns 0) before any supply exists.
    pub fn annual_inflation(&self, year: f64) -> f64 {
        let s0 = self.supply_at_year(year);
        if s0 <= 0.0 {
            return 0.0;
        }
        let s1 = self.supply_at_year(year + 1.0);
        (s1 - s0) / s0
    }
}
