//! The candidate parameter grid.
//!
//! The economic *shape* is set by three knobs: decay speed (half-life), the
//! target tail-activation inflation, and block time. The initial reward `r0` is
//! shown to be pure **denomination** — it scales absolute coin counts but moves
//! no %-metric or timing (demonstrated by the `D`-series row and asserted in the
//! tests). Nothing here is chosen; every row is a candidate with its trade-offs.

use crate::model::Model;

/// One candidate curve plus the human knobs that produced it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: String,
    pub family: &'static str,
    pub block_time_s: f64,
    pub half_life_years: f64,
    pub r0: f64,
    /// Target tail-activation inflation used to solve the tail (Monero-class only).
    pub target_tail_infl: Option<f64>,
    pub model: Model,
}

/// Build the full sweep grid.
pub fn candidates() -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut push_monero =
        |id: String, bt: f64, hl: f64, r0: f64, tt: f64| {
            let model = Model::monero_from_targets(r0, hl, bt, tt);
            out.push(Candidate {
                id,
                family: "Monero",
                block_time_s: bt,
                half_life_years: hl,
                r0,
                target_tail_infl: Some(tt),
                model,
            });
        };

    // --- Primary 60 s grid: half-life × target-tail-inflation (r0 = 50) ---------
    let half_lives = [1.0, 2.0, 4.0];
    let tail_targets = [0.005, 0.0087, 0.015]; // 0.87% = Monero's activation reference
    let mut n = 1;
    for &hl in &half_lives {
        for &tt in &tail_targets {
            push_monero(format!("M{n}"), 60.0, hl, 50.0, tt);
            n += 1;
        }
    }

    // --- Block-time sensitivity: 75 s at the Monero-reference 0.87% -------------
    let mut b = 1;
    for &hl in &half_lives {
        push_monero(format!("B{b}"), 75.0, hl, 50.0, 0.0087);
        b += 1;
    }

    // --- Denomination demo: a very different r0, same shape as M5 --------------
    // (hl=2y, 60 s, 0.87%) — should reproduce every %-metric of M5 exactly.
    push_monero("D1".to_string(), 60.0, 2.0, 6.25, 0.0087);

    // --- AdditiveSmooth (C∞) contrasts, mirroring M5's (d, tail) ---------------
    // Same decay rate and tail as M5 so the C1-vs-Todd trade is apples-to-apples.
    let m5 = Model::monero_from_targets(50.0, 2.0, 60.0, 0.0087);
    out.push(Candidate {
        id: "A1".to_string(),
        family: "Additive",
        block_time_s: 60.0,
        half_life_years: 2.0,
        r0: 50.0,
        target_tail_infl: None,
        model: Model::additive(50.0, m5.d, m5.tail, 60.0),
    });
    let m1 = Model::monero_from_targets(50.0, 1.0, 60.0, 0.0087);
    out.push(Candidate {
        id: "A2".to_string(),
        family: "Additive",
        block_time_s: 60.0,
        half_life_years: 1.0,
        r0: 50.0,
        target_tail_infl: None,
        model: Model::additive(50.0, m1.d, m1.tail, 60.0),
    });

    out
}
