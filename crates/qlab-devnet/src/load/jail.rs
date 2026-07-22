//! Downtime jail-threshold `(X%, Y-block)` grid sweep (issue #42 item 4) — the
//! measured basis for the `[open]` downtime jail threshold (consensus-parameters
//! §4: "signing < X % of a Y-block window", Cosmos shape).
//!
//! **Rule (Cosmos shape).** A validator is jailed the moment its *missed* count
//! over the trailing `Y`-block window exceeds `(1 − X)·Y` — i.e. it signed fewer
//! than `X` of the last `Y` blocks. Jail is **no-slash** (committee-governance §3);
//! it maps directly onto [`crate::committee::CommitteeState::jail`].
//!
//! **Two things the grid trades off:**
//! - **Detection lag** — for a validator that goes fully dark, misses accrue one
//!   per block, so the jail fires after exactly `⌈(1 − X)·Y⌉` blocks. Larger `Y`
//!   or lower `X` ⇒ slower detection.
//! - **False-jail rate** — a validator with *acceptable* uptime should almost
//!   never be jailed. Benign misses (transient blips, HA failover) and
//!   *correlated* network blips push a healthy validator toward the threshold;
//!   too strict an `(X, Y)` jails good operators. Measured by Monte-Carlo over the
//!   seeded [`super::rng::SplitMix64`] (⇒ `run1 == run2`).
//!
//! At N = 21 *named* validators (committee-governance §1) an over-eager jail is a
//! real operational cost (a good operator briefly loses income), so the design
//! wants the loosest `(X, Y)` that still detects genuine downtime within a useful
//! lag.

use super::rng::SplitMix64;
use super::{BLOCK_TIME_SECS, EPOCH_BLOCKS};

/// One grid cell's measured outcome.
#[derive(Clone, Debug)]
pub struct JailCell {
    /// Signed-fraction threshold `X` (jail if signed% over the window < X).
    pub x: f64,
    /// Window length `Y`, blocks.
    pub y: u64,
    /// Detection lag for a fully-offline validator, blocks = `⌈(1−X)·Y⌉`.
    pub detection_lag_blocks: u64,
    /// Detection lag in wall-clock seconds at the decided 75-s cadence.
    pub detection_lag_secs: u64,
    /// False-jail rate at realistic named-entity uptime (99.0 %), independent
    /// misses only — fraction of healthy validator-epochs jailed at least once.
    pub false_jail_rate_p99: f64,
    /// False-jail rate under a *correlated* network-blip stress (99.0 % base
    /// uptime + occasional all-validator blip blocks) — where false jails cluster.
    pub false_jail_rate_blips: f64,
}

/// Config for the false-jail Monte-Carlo.
#[derive(Clone, Copy, Debug)]
pub struct JailSimConfig {
    pub n_validators: usize,
    pub epochs: u64,
    /// Per-block per-validator sign probability for a *healthy* validator.
    pub p_up: f64,
    /// Per-block probability of a correlated blip (all validators miss that block).
    pub p_blip: f64,
    pub seed: u64,
}

impl Default for JailSimConfig {
    fn default() -> Self {
        Self { n_validators: 21, epochs: 8, p_up: 0.99, p_blip: 0.0, seed: 0x4A41_4C00 }
    }
}

/// Detection lag (blocks) for a fully-offline validator under `(x, y)`.
pub fn detection_lag_blocks(x: f64, y: u64) -> u64 {
    // Jailed once missed > (1−X)·Y ⇒ at block ⌈(1−X)·Y⌉ (one miss per block).
    ((1.0 - x) * y as f64).ceil() as u64
}

/// Measure the false-jail rate: fraction of *healthy* validator-epochs in which a
/// validator (only benign / correlated-blip misses, never a genuine outage) trips
/// the `(x, y)` jail rule at least once. Incremental trailing-window counter.
pub fn false_jail_rate(x: f64, y: u64, cfg: &JailSimConfig) -> f64 {
    let miss_budget = ((1.0 - x) * y as f64).floor() as u64; // jail once missed > this
    let mut rng = SplitMix64::new(cfg.seed ^ (y.wrapping_mul(0x1000_0001)) ^ ((x * 1e6) as u64));
    let total_blocks = cfg.epochs * EPOCH_BLOCKS;
    let n = cfg.n_validators;

    let mut jailed = vec![false; n]; // did validator v get (falsely) jailed this run?
    // Per-validator trailing-window miss bookkeeping.
    let mut miss_hist: Vec<Vec<bool>> = vec![Vec::with_capacity(y as usize); n];
    let mut miss_in_window: Vec<u64> = vec![0; n];

    for b in 0..total_blocks {
        let blip = rng.bernoulli(cfg.p_blip);
        for v in 0..n {
            // Healthy validator signs w.p. p_up, unless this is a correlated blip.
            let signed = !blip && rng.bernoulli(cfg.p_up);
            let missed = !signed;
            miss_hist[v].push(missed);
            if missed {
                miss_in_window[v] += 1;
            }
            // Evict the block leaving the trailing Y-window.
            if b >= y {
                let leaving = miss_hist[v][(b - y) as usize];
                if leaving {
                    miss_in_window[v] -= 1;
                }
            }
            if miss_in_window[v] > miss_budget {
                jailed[v] = true;
            }
        }
    }

    jailed.iter().filter(|&&j| j).count() as f64 / n as f64
}

/// The X grid (signed-fraction thresholds) — from Cosmos-lenient (5 %) to strict.
pub const X_SWEEP: [f64; 4] = [0.05, 0.10, 0.33, 0.50];

/// The Y grid (window lengths, blocks) — fractions of the 1_152-block epoch.
pub const Y_SWEEP: [u64; 4] = [50, 100, 288, 576];

/// Run the full `(X, Y)` grid and return one [`JailCell`] per cell.
pub fn run_grid(cfg: &JailSimConfig) -> Vec<JailCell> {
    let mut out = Vec::new();
    for &x in &X_SWEEP {
        for &y in &Y_SWEEP {
            let lag = detection_lag_blocks(x, y);
            let blip_cfg = JailSimConfig { p_blip: 0.02, ..*cfg }; // 2% correlated blips
            out.push(JailCell {
                x,
                y,
                detection_lag_blocks: lag,
                detection_lag_secs: lag * BLOCK_TIME_SECS,
                false_jail_rate_p99: false_jail_rate(x, y, cfg),
                false_jail_rate_blips: false_jail_rate(x, y, &blip_cfg),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{devnet_committee, CommitteeState};
    use crate::params_devnet::BOND_AMOUNT;

    #[test]
    fn detection_lag_is_one_minus_x_times_y() {
        assert_eq!(detection_lag_blocks(0.05, 100), 95);
        assert_eq!(detection_lag_blocks(0.50, 100), 50);
        assert_eq!(detection_lag_blocks(0.10, 288), 260); // ceil(0.9*288=259.2)
        // Lower X and larger Y both slow detection.
        assert!(detection_lag_blocks(0.05, 576) > detection_lag_blocks(0.50, 50));
    }

    #[test]
    fn realistic_uptime_is_not_falsely_jailed_at_lenient_thresholds() {
        // 99% uptime, independent misses: at the Cosmos-lenient end no healthy
        // validator is jailed (needs to miss >95% of the window — impossible at
        // 1% miss rate).
        let cfg = JailSimConfig::default();
        assert_eq!(false_jail_rate(0.05, 100, &cfg), 0.0);
        assert_eq!(false_jail_rate(0.10, 288, &cfg), 0.0);
    }

    #[test]
    fn stricter_threshold_raises_false_jail_rate() {
        // Monotone-ish: a much stricter X (jail if you miss even a little) can trip
        // healthy validators on a small window; lenient X never does.
        let cfg = JailSimConfig { p_up: 0.90, ..JailSimConfig::default() }; // poor uptime
        let lenient = false_jail_rate(0.05, 100, &cfg);
        let strict = false_jail_rate(0.50, 50, &cfg);
        assert!(strict >= lenient, "strict {strict} vs lenient {lenient}");
    }

    #[test]
    fn deterministic_reproduces_identically() {
        let cfg = JailSimConfig::default();
        assert_eq!(false_jail_rate(0.33, 100, &cfg), false_jail_rate(0.33, 100, &cfg));
        let g1 = run_grid(&cfg);
        let g2 = run_grid(&cfg);
        for (a, b) in g1.iter().zip(g2.iter()) {
            assert_eq!(a.false_jail_rate_p99.to_bits(), b.false_jail_rate_p99.to_bits());
            assert_eq!(a.detection_lag_blocks, b.detection_lag_blocks);
        }
    }

    #[test]
    fn correlated_blips_raise_false_jails_versus_independent() {
        // Correlated all-validator blips push every validator's miss count up
        // together — false jails are ≥ the independent case at the same (X,Y).
        let cfg = JailSimConfig::default();
        let indep = false_jail_rate(0.50, 50, &cfg);
        let blips = false_jail_rate(0.50, 50, &JailSimConfig { p_blip: 0.10, ..cfg });
        assert!(blips >= indep, "blips {blips} vs indep {indep}");
    }

    /// Grounding: a jail decision from the sweep maps onto the real committee
    /// state machine — jailing drops the validator from the active set until the
    /// term, with no slash (committee-governance §3).
    #[test]
    fn jail_decision_applies_to_real_committee_state() {
        let (committee, _) = devnet_committee(21);
        let mut state = CommitteeState::new(committee, BOND_AMOUNT);
        let offline = 7usize;
        let lag = detection_lag_blocks(0.10, 100); // 90 blocks
        // The rule fires at `lag`; jail until `lag + JAIL term` (use lag+32).
        assert!(state.jail(offline, lag + 32));
        assert!(!state.is_active(offline, lag + 10), "jailed during the term");
        assert!(state.is_active(offline, lag + 32), "auto-readmitted after");
        assert_eq!(state.bond(offline), Some(BOND_AMOUNT), "downtime is NO-slash");
    }
}
