//! Everything the consensus-parameters appendix needs to *see* per candidate.
//!
//! All flows are derived from the [`Model`]'s closed-form supply. The 65/15/20
//! split (§4) is applied to emission; the committee wage is surfaced at N ∈ {20,50}
//! (§4b MVI framing) — but note the wage-vs-subsidy line is ultimately
//! price-dependent, which this crate flags rather than decides.

use crate::model::Model;

/// Block-reward split — DECIDED in tokenomics-and-issuance.md §4 (this is the one
/// thing the doc fixes; the *constants* the split applies to are what's open).
pub const MINER_SHARE: f64 = 0.65;
pub const COMMITTEE_SHARE: f64 = 0.15;
pub const TREASURY_SHARE: f64 = 0.20;

/// Committee sizes to price (consensus §5 / §4b: N ≈ 20–50).
pub const COMMITTEE_N: [u32; 2] = [20, 50];

/// Years at which to sample the supply curve for the report.
pub const SUPPLY_SAMPLE_YEARS: [f64; 7] = [1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0];

/// Far-future years used to demonstrate inflation → 0 beyond the horizon.
pub const FARFUTURE_YEARS: [f64; 3] = [100.0, 500.0, 1000.0];

/// Era boundaries (years) for the 65/15/20 flow table.
pub const ERA_BOUNDS: [(f64, f64); 5] =
    [(0.0, 1.0), (1.0, 5.0), (5.0, 10.0), (10.0, 20.0), (20.0, 50.0)];

#[derive(Debug, Clone)]
pub struct SupplyPoint {
    pub year: f64,
    pub supply: f64,
    /// Supply as a fraction of the asymptotic pre-tail ceiling S_inf.
    pub frac_of_s_inf: f64,
}

#[derive(Debug, Clone)]
pub struct InflationPoint {
    pub year: f64,
    pub inflation: f64,
}

/// Absolute 65/15/20 flows over one era (coins).
#[derive(Debug, Clone)]
pub struct EraFlow {
    pub label: String,
    pub year_start: f64,
    pub year_end: f64,
    pub total: f64,
    pub miner: f64,
    pub committee: f64,
    pub treasury: f64,
}

/// The tail-activation facts (Monero cross-reference: 0.87% at activation).
#[derive(Debug, Clone)]
pub struct TailActivation {
    pub height: f64,
    pub year: f64,
    pub supply_at: f64,
    /// Annual inflation in the year tail activation lands.
    pub inflation_at: f64,
}

/// Committee wage at one N, at one point in time (coins/validator/year).
#[derive(Debug, Clone)]
pub struct CommitteeWage {
    pub n: u32,
    pub per_validator_year1: f64,
    pub per_validator_year10: f64,
    /// The **perpetual** steady-state wage in the tail regime — the number the
    /// tail rate sets forever (§4b: the committee's Minimum-Viable-Issuance floor).
    pub per_validator_tail: f64,
}

/// The full metric bundle for one candidate curve.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub s_inf: f64,
    pub supply_curve: Vec<SupplyPoint>,
    pub inflation_trajectory: Vec<InflationPoint>,
    pub farfuture_inflation: Vec<InflationPoint>,
    pub tail: TailActivation,
    pub era_flows: Vec<EraFlow>,
    pub committee_wages: Vec<CommitteeWage>,
    /// Total supply at the 50-year horizon.
    pub supply_50y: f64,
    /// Initial (block-0) reward, echoed for the table.
    pub r0: f64,
    /// Tail rate (coins/block).
    pub tail_rate: f64,
}

impl Metrics {
    pub fn compute(m: &Model) -> Metrics {
        let s_inf = m.s_inf();

        let supply_curve = SUPPLY_SAMPLE_YEARS
            .iter()
            .map(|&year| {
                let supply = m.supply_at_year(year);
                SupplyPoint { year, supply, frac_of_s_inf: supply / s_inf }
            })
            .collect();

        // Annual inflation for years 1..=50 (year here = start of the interval).
        let inflation_trajectory = (1..=50)
            .map(|y| {
                let year = y as f64;
                InflationPoint { year, inflation: m.annual_inflation(year) }
            })
            .collect();

        let farfuture_inflation = FARFUTURE_YEARS
            .iter()
            .map(|&year| InflationPoint { year, inflation: m.annual_inflation(year) })
            .collect();

        let ht = m.tail_activation_height();
        let tail_year = ht / m.blocks_per_year();
        let tail = TailActivation {
            height: ht,
            year: tail_year,
            supply_at: m.supply(ht),
            inflation_at: m.annual_inflation(tail_year),
        };

        let era_flows = ERA_BOUNDS
            .iter()
            .map(|&(a, b)| {
                let total = m.supply_at_year(b) - m.supply_at_year(a);
                EraFlow {
                    label: format!("y{:.0}–{:.0}", a, b),
                    year_start: a,
                    year_end: b,
                    total,
                    miner: total * MINER_SHARE,
                    committee: total * COMMITTEE_SHARE,
                    treasury: total * TREASURY_SHARE,
                }
            })
            .collect();

        // Committee wage: 15% of that year's emission, split N ways. The tail wage
        // is the steady state 0.15·tail·B / N (constant once the tail engages).
        let emission_year = |y: f64| m.supply_at_year(y + 1.0) - m.supply_at_year(y);
        let tail_emission_year = m.tail * m.blocks_per_year();
        let committee_wages = COMMITTEE_N
            .iter()
            .map(|&n| {
                let nf = n as f64;
                CommitteeWage {
                    n,
                    per_validator_year1: COMMITTEE_SHARE * emission_year(1.0) / nf,
                    per_validator_year10: COMMITTEE_SHARE * emission_year(10.0) / nf,
                    per_validator_tail: COMMITTEE_SHARE * tail_emission_year / nf,
                }
            })
            .collect();

        Metrics {
            s_inf,
            supply_curve,
            inflation_trajectory,
            farfuture_inflation,
            tail,
            era_flows,
            committee_wages,
            supply_50y: m.supply_at_year(50.0),
            r0: m.r0,
            tail_rate: m.tail,
        }
    }
}
