//! The four §1 jobs, as explicit pass/fail assertions.
//!
//! §1 lists four jobs the emission rule must satisfy *simultaneously*. Three of
//! them are structural properties of any well-formed curve in this family (they
//! pass for every sane candidate — that is itself the finding: the Monero-class
//! shape satisfies the jobs by construction, and the real choices are the
//! *quantitative* trade-offs the metrics surface). The checks are written so they
//! genuinely CAN fail — the test suite feeds each one a pathological curve to
//! prove it has teeth.
//!
//! | § job | check here |
//! |---|---|
//! | perpetual PoW subsidy + committee opex | `committee_perpetually_funded` (tail > 0) |
//! | fund dev / audit anchor / no legitimacy debt | `supply_is_closed_form` |
//! | asymptotically non-inflationary (§3, Todd) | `inflation_asymptotes_to_zero` |
//! | closed-form + cliff-free audit anchor (§1 job 4) | `no_cliffs` |

use crate::model::{Family, Model};

#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Short job name for the report's pass/fail column.
    pub job: &'static str,
    pub pass: bool,
    pub detail: String,
}

/// Sum of block rewards over `[from, to)` (coins), evaluated pointwise from the
/// reward function — the *independent* path the closed form is checked against.
pub fn running_sum(m: &Model, from: u64, to: u64) -> f64 {
    let mut acc = 0.0;
    for h in from..to {
        acc += m.reward(h as f64);
    }
    acc
}

/// §1 job (asymptotic non-inflation, §3 / Todd): annual inflation trends to 0.
///
/// Asserts inflation is non-increasing from tail activation onward and drops
/// below 0.5%/yr in the far future.
pub fn inflation_asymptotes_to_zero(m: &Model) -> CheckResult {
    let start = m.tail_activation_height().max(0.0) / m.blocks_per_year();
    let start_y = start.ceil().max(1.0) as u64;

    // Monotone non-increasing across the tail regime (sampled yearly to 200).
    let mut monotone = true;
    let mut prev = m.annual_inflation(start_y as f64);
    let mut worst_rise = 0.0_f64;
    for y in (start_y + 1)..=200 {
        let cur = m.annual_inflation(y as f64);
        // allow a hair of f64 noise
        if cur > prev + 1e-12 {
            monotone = false;
            worst_rise = worst_rise.max(cur - prev);
        }
        prev = cur;
    }

    let i50 = m.annual_inflation(50.0);
    let i1000 = m.annual_inflation(1000.0);
    let far_small = i1000 < 0.005;
    let trending = i1000 < i50;

    let pass = monotone && far_small && trending;
    CheckResult {
        job: "inflation→0",
        pass,
        detail: format!(
            "infl y50={:.3}% y1000={:.4}%; monotone-from-tail={} (worst rise {:.2e}); far<0.5%={}",
            i50 * 100.0,
            i1000 * 100.0,
            monotone,
            worst_rise,
            far_small
        ),
    }
}

/// §1 job 4 (audit anchor): supply-at-height is an exact closed form matching the
/// running coinbase sum "to the coin" — no era table.
///
/// Cross-checks the closed form against the independent pointwise running sum over
/// two windows: the launch decay phase, and (for MoneroClass) a window straddling
/// tail activation where a transition bug would show.
pub fn supply_is_closed_form(m: &Model) -> CheckResult {
    let bpy = m.blocks_per_year();
    let h50 = (50.0 * bpy) as u64;

    let mut max_drift = 0.0_f64;

    // Window 1: launch phase.
    let w1 = (2_000_000u64).min(h50);
    let sum1 = running_sum(m, 0, w1);
    let closed1 = m.supply(w1 as f64);
    max_drift = max_drift.max((sum1 - closed1).abs());

    // Window 2: straddle tail activation (MoneroClass has the kink there).
    if m.family == Family::MoneroClass {
        let ht = m.tail_activation_height() as u64;
        let a = ht.saturating_sub(500_000);
        let b = (ht + 500_000).min(h50.max(ht + 1));
        if b > a {
            let sum2 = running_sum(m, a, b);
            let closed2 = m.supply(b as f64) - m.supply(a as f64);
            max_drift = max_drift.max((sum2 - closed2).abs());
        }
    }

    // Structural: S(0)=0 and strictly increasing at samples.
    let zero_ok = m.supply(0.0).abs() < 1e-9;
    let mut increasing = true;
    let mut ps = -1.0;
    for &y in &[1.0, 5.0, 10.0, 20.0, 50.0, 100.0] {
        let s = m.supply_at_year(y);
        if s <= ps {
            increasing = false;
        }
        ps = s;
    }

    let pass = max_drift < 1.0 && zero_ok && increasing;
    CheckResult {
        job: "closed-form",
        pass,
        detail: format!(
            "running-sum vs closed-form drift {:.4} coin (< 1); S(0)=0 {}; strictly-increasing {}",
            max_drift, zero_ok, increasing
        ),
    }
}

/// §1 job (perpetual PoW subsidy + committee opex): the tail keeps miners AND the
/// committee paid forever, and the committee wage is finite/positive at N ≈ 20–50.
///
/// The hard job — perpetual funding — passes iff `tail > 0`. The wage-vs-subsidy
/// judgment is price-dependent (out of scope), so this surfaces the front-loading
/// ratio (year-1 committee wage ÷ perpetual tail wage) rather than deciding it.
pub fn committee_perpetually_funded(m: &Model) -> CheckResult {
    use crate::metrics::COMMITTEE_SHARE;
    let bpy = m.blocks_per_year();
    let tail_wage_20 = COMMITTEE_SHARE * m.tail * bpy / 20.0;
    let emission_y1 = m.supply_at_year(2.0) - m.supply_at_year(1.0);
    let wage_y1_20 = COMMITTEE_SHARE * emission_y1 / 20.0;
    let frontload = if tail_wage_20 > 0.0 { wage_y1_20 / tail_wage_20 } else { f64::INFINITY };

    let perpetual = m.tail > 0.0 && tail_wage_20.is_finite() && tail_wage_20 > 0.0;
    // Illustrative, DISCLOSED front-loading flag — not a decision: year-1 committee
    // income > 30× the perpetual wage reads as a launch subsidy rather than a wage.
    let front_loaded = frontload > 30.0;

    CheckResult {
        job: "committee-funded",
        pass: perpetual,
        detail: format!(
            "perpetual committee+PoW subsidy (tail>0)={}; front-loading {:.0}× (y1÷tail wage){}",
            perpetual,
            frontload,
            if front_loaded { " [flag: subsidy-shaped launch]" } else { "" }
        ),
    }
}

/// §1 job 4 (cliff-free): no halving cliffs — the reward curve has no downward
/// value jump. The stronger `(C1-continuous)` parenthetical is reported too:
/// MoneroClass is C0 (a slope kink at tail activation, exactly like Monero);
/// AdditiveSmooth is C∞.
pub fn no_cliffs(m: &Model) -> CheckResult {
    let bpy = m.blocks_per_year();
    let h50 = (50.0 * bpy) as u64;

    // Largest single-block relative drop = "cliffiness". Smooth decay gives ≈ d
    // (~1e-6/block); a halving would show 0.5. Scan the launch phase + the
    // activation neighborhood.
    let mut max_drop = 0.0_f64;
    let mut scan = |from: u64, to: u64| {
        for h in from..to {
            let r0 = m.reward(h as f64);
            let r1 = m.reward((h + 1) as f64);
            if r0 > 0.0 && r1 < r0 {
                max_drop = max_drop.max((r0 - r1) / r0);
            }
        }
    };
    scan(0, (2_000_000u64).min(h50));
    let ht = m.tail_activation_height() as u64;
    scan(ht.saturating_sub(2_000), ht + 2_000);

    let no_cliff = max_drop < 1e-3; // a real cliff is O(0.5); smooth decay is O(1e-6)
    let c1 = matches!(m.family, Family::AdditiveSmooth);

    CheckResult {
        job: "no-cliffs",
        pass: no_cliff,
        detail: format!(
            "max single-block drop {:.2e} (<1e-3 = no cliff); {}",
            max_drop,
            if c1 {
                "C∞ (smooth, C1 too)"
            } else {
                "C0 — slope kink at tail activation (Monero behavior), no cliff"
            }
        ),
    }
}

/// Run all four checks.
pub fn all_checks(m: &Model) -> Vec<CheckResult> {
    vec![
        inflation_asymptotes_to_zero(m),
        supply_is_closed_form(m),
        committee_perpetually_funded(m),
        no_cliffs(m),
    ]
}

/// True iff every job-check passes.
pub fn all_pass(m: &Model) -> bool {
    all_checks(m).iter().all(|c| c.pass)
}
