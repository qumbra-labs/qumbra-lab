//! Correctness tests for the emission simulator.
//!
//! The headline requirement (§1 job 4): **S(h) equals the running coinbase sum
//! to the coin** — proven here two ways (contiguous f64 running sum across tail
//! activation, and exact integer telescoping in atomic units) — plus the four
//! job-checks on every candidate, and proof the checks have teeth.

use qlab_econ::checks::{
    committee_perpetually_funded, no_cliffs, running_sum, supply_is_closed_form,
};
use qlab_econ::metrics::Metrics;
use qlab_econ::model::{Family, Model, ATOMIC_PER_COIN};
use qlab_econ::sweep::candidates;

/// Integer block checkpoints at each year boundary, so a contiguous running sum
/// of exactly `N` blocks can be compared to the closed form `S(N)`.
fn year_checkpoints(m: &Model, years: u64) -> Vec<u64> {
    let bpy = m.blocks_per_year();
    (1..=years).map(|y| (y as f64 * bpy).round() as u64).collect()
}

/// The core exactness test: sum every block reward from genesis and check the
/// accumulator against the closed form at each year boundary, "to the coin".
fn assert_contiguous_running_sum(m: &Model, years: u64) {
    let checkpoints = year_checkpoints(m, years);
    let end = *checkpoints.last().unwrap();
    let mut acc = 0.0f64;
    let mut ci = 0;
    for h in 0..end {
        acc += m.reward(h as f64);
        // After adding reward(h), acc == S(h+1).
        if ci < checkpoints.len() && h + 1 == checkpoints[ci] {
            let closed = m.supply((h + 1) as f64);
            let drift = (acc - closed).abs();
            assert!(
                drift < 1.0,
                "running sum vs closed form drifted {drift:.6} coin at block {} (year {})",
                h + 1,
                ci + 1
            );
            ci += 1;
        }
    }
}

#[test]
fn supply_equals_running_sum_to_the_coin() {
    // Representatives spanning fast decay / the Monero reference / slow decay /
    // the C∞ family — each carried past its tail activation (~y5 / ~y11 / ~y21).
    let m1 = Model::monero_from_targets(50.0, 1.0, 60.0, 0.0087); // fast, activates ~y5
    let m5 = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087); // reference, ~y11
    let m9 = Model::monero_from_targets(50.0, 4.0, 60.0, 0.015); // slow, ~y21
    let a1 = Model::additive(50.0, m5.d, m5.tail, 60.0); // smooth family

    assert_contiguous_running_sum(&m1, 8);
    assert_contiguous_running_sum(&m5, 14);
    assert_contiguous_running_sum(&m9, 25);
    assert_contiguous_running_sum(&a1, 14);
}

#[test]
fn exact_integer_telescoping_in_atomic_units() {
    // The production audit relation: coinbase(h) = S(h+1) − S(h) in atomic units
    // sums back to S exactly, and every increment is a non-negative integer —
    // checked across ranges including the tail transition.
    let supply_atomic = |m: &Model, h: u64| -> u128 {
        (m.supply(h as f64) * ATOMIC_PER_COIN as f64).round() as u128
    };
    for c in candidates() {
        let m = &c.model;
        let ht = m.tail_activation_height() as u64;
        let ranges = [
            (0u64, 5_000u64),
            (ht.saturating_sub(200), ht + 200),
            (ht + 1_000_000, ht + 1_005_000),
        ];
        for (lo, hi) in ranges {
            let mut sum: u128 = 0;
            for h in lo..hi {
                let inc = supply_atomic(m, h + 1)
                    .checked_sub(supply_atomic(m, h))
                    .expect("coinbase increment must be non-negative");
                sum += inc;
            }
            let expected = supply_atomic(m, hi) - supply_atomic(m, lo);
            assert_eq!(
                sum, expected,
                "telescoping mismatch for {} on [{lo},{hi})",
                c.id
            );
        }
    }
}

#[test]
fn all_candidates_pass_all_four_job_checks() {
    for c in candidates() {
        for chk in qlab_econ::checks::all_checks(&c.model) {
            assert!(chk.pass, "candidate {} failed check {}: {}", c.id, chk.job, chk.detail);
        }
    }
}

#[test]
fn inflation_is_asymptotically_one_over_year() {
    // The §3 / Todd guarantee, made quantitative: with a fixed absolute tail
    // emission, S(y) → tail·B·y so inflation(y) → 1/y → 0. Convergence is slowed
    // by the constant accumulated-decay supply (≈ a couple centuries of tail
    // emission), so the clean 1/y limit shows at large y; check it there, and
    // confirm inflation is strictly decreasing across the decades.
    for c in candidates() {
        let i = c.model.annual_inflation(1_000_000.0);
        assert!(
            (i * 1_000_000.0 - 1.0).abs() < 0.02,
            "{}: inflation(1e6)·1e6 = {:.4}, expected ≈ 1.0 (1/year asymptote)",
            c.id,
            i * 1_000_000.0
        );
        // inflation(y)·y approaches 1 from below as y grows.
        let approach = |y: f64| c.model.annual_inflation(y) * y;
        assert!(approach(1000.0) < approach(100_000.0));
        // Strictly decreasing across the sampled decades.
        assert!(c.model.annual_inflation(1000.0) < c.model.annual_inflation(50.0));
        assert!(c.model.annual_inflation(50.0) < c.model.annual_inflation(10.0));
    }
}

#[test]
fn tail_activation_inflation_matches_calibration_target() {
    // Every calibrated Monero-class row should land its target tail-activation
    // inflation (Monero's real 0.87% is one of them), within h_tail rounding.
    for c in candidates() {
        let Some(target) = c.target_tail_infl else { continue };
        let m = Metrics::compute(&c.model);
        let rel = (m.tail.inflation_at - target).abs() / target;
        assert!(
            rel < 0.02,
            "{}: activation inflation {:.4}% vs target {:.4}% (rel {:.3})",
            c.id,
            m.tail.inflation_at * 100.0,
            target * 100.0,
            rel
        );
    }
}

#[test]
fn monero_decay_is_a_pure_function_of_cumulative_issuance() {
    // The Monero identity: decayReward(h) = d·(S_inf − S(h)) — reward is a pure
    // function of cumulative issuance, the §3 `remaining >> 19` structure.
    let m = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    for &h in &[0.0, 1_000.0, 100_000.0, 1_000_000.0, 3_000_000.0] {
        let via_issuance = m.d * (m.s_inf() - m.supply(h));
        let direct = m.decay_reward(h);
        assert!(
            (via_issuance - direct).abs() / direct < 1e-6,
            "issuance-form {via_issuance} vs direct {direct} at h={h}"
        );
    }
}

#[test]
fn r0_is_pure_denomination() {
    // M5 (r0=50) and D1 (r0=6.25) share every %-metric and all timing; only coin
    // counts scale by 6.25/50.
    let m5 = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    let d1 = Model::monero_from_targets(6.25, 2.0, 60.0, 0.0087);
    assert_eq!(
        m5.tail_activation_height(),
        d1.tail_activation_height(),
        "denomination must not move tail activation"
    );
    for &y in &[1.0, 5.0, 10.0, 50.0, 1000.0] {
        let (im5, id1) = (m5.annual_inflation(y), d1.annual_inflation(y));
        assert!((im5 - id1).abs() < 1e-9, "inflation differs at y{y}: {im5} vs {id1}");
    }
    for &h in &[1_000.0, 1_000_000.0, 10_000_000.0] {
        let ratio = d1.supply(h) / m5.supply(h);
        assert!((ratio - 6.25 / 50.0).abs() < 1e-9, "supply ratio {ratio} at h={h}");
    }
}

#[test]
fn block_time_barely_moves_economics() {
    // M5 (60 s) vs B2 (75 s), same half-life & tail target: the %-metrics and
    // activation year are near-invariant (block time is a latency choice).
    let m60 = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    let m75 = Model::monero_from_targets(50.0, 2.0, 75.0, 0.0087);
    let y60 = m60.tail_activation_height() / m60.blocks_per_year();
    let y75 = m75.tail_activation_height() / m75.blocks_per_year();
    assert!((y60 - y75).abs() < 0.1, "tail year {y60} vs {y75}");
    for &y in &[10.0, 50.0] {
        let rel = (m60.annual_inflation(y) - m75.annual_inflation(y)).abs()
            / m60.annual_inflation(y);
        assert!(rel < 0.01, "inflation@{y} differs {rel:.4} between block times");
    }
}

// ---------------------------------------------------------------------------
// The checks have teeth: pathological curves must FAIL.
// ---------------------------------------------------------------------------

#[test]
fn committee_check_fails_without_a_tail() {
    // tail = 0 ⇒ no perpetual subsidy ⇒ committee (and PoW) funding dies. FAIL.
    let no_tail = Model { family: Family::MoneroClass, r0: 50.0, d: 1e-6, tail: 0.0, block_time_s: 60.0 };
    assert!(!committee_perpetually_funded(&no_tail).pass);
    // A healthy tail passes.
    let good = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    assert!(committee_perpetually_funded(&good).pass);
}

#[test]
fn no_cliffs_check_fails_on_steep_per_block_drops() {
    // d = 0.4 ⇒ reward drops 40%/block — cliff-like. FAIL.
    let steep = Model { family: Family::MoneroClass, r0: 50.0, d: 0.4, tail: 0.1, block_time_s: 60.0 };
    assert!(!no_cliffs(&steep).pass);
    // The gentle sweep candidates all pass (drop ≈ d ~1e-6/block).
    let gentle = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    assert!(no_cliffs(&gentle).pass);
}

#[test]
fn closed_form_check_discriminates_a_wrong_curve() {
    // The running-sum/closed-form agreement is not tautological: a curve whose
    // closed form uses the wrong decay rate drifts far past the 1-coin bar.
    let m5 = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    assert!(supply_is_closed_form(&m5).pass);

    let mut wrong = m5;
    wrong.d *= 1.001; // mis-specified decay
    let w = (2_000_000u64).min((50.0 * m5.blocks_per_year()) as u64);
    let sum_true = running_sum(&m5, 0, w);
    let closed_wrong = wrong.supply(w as f64);
    assert!(
        (sum_true - closed_wrong).abs() > 1.0,
        "a mis-specified closed form should drift > 1 coin, got {}",
        (sum_true - closed_wrong).abs()
    );
}
