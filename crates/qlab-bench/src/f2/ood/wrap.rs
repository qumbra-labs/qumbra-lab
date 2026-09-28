//! F2b-4 preparation (issue #750): the full-size C1 and C2 of ONE real hiding
//! leaf proof, for `qlab-bench f2wrap`. Two stages:
//!
//! - **check**: build both honest traces for all `num_queries` query slots,
//!   scan every row of each with p3-air's constraint evaluator (the row loop
//!   of `p3_air::check_constraints`, which `qlab_air::l2test` — test-only by
//!   its own Cargo contract — wraps for the tests), and run the native
//!   `check_seams`, `check_coverage` and R-PV `check_leaf_pvs`. No proving.
//! - **prove**: prove C1 and C2 under a NON-hiding outer config (the ruled
//!   outer PCS, #750 stage-0 ruling 1: `qlab_consensus::legacy`, at the M4
//!   interior's own lanes `m4interior::INTERIOR_B2_CFG` / `INTERIOR_B4_CFG`),
//!   verify both natively, and report dimensions, constraint counts, degree,
//!   proof bytes and wall times. Peak memory is the operator's
//!   `/usr/bin/time -v` reading; the report carries the stage-0 k-model's
//!   [P] expectation beside it, never a measured value.
//!
//! Materialization is bounded twice: [`Plan::admit`] refuses, from the
//! `price::composed_*` layout alone, a component whose width × height would
//! exceed the budget before any trace or ROM exists, and `C1Air::new` /
//! `C2Air::new` check the same budget on the built layout before allocating.
//! Components are built one at a time and each trace is dropped before the
//! next is built, so a run's peak is the larger component's, not the sum.
use std::time::Instant;

use p3_air::symbolic::{get_symbolic_constraints, AirLayout, SymbolicAirBuilder};
use p3_air::{Air, BaseAir, ConstraintFailure, DebugConstraintBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::ViewPair;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{prove, verify, Proof, ProverConstraintFolder, VerifierConstraintFolder};
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
use qlab_consensus::{Config, FriCfg};
use qlab_l2::{Shape, L2_CFG_PROVISIONAL};
use serde_json::{json, Map, Value};

use super::lane::{phase_ranges, Phased};
use super::seam::{check_coverage, check_leaf_pvs, check_seams};
use super::{c1, c2, compare_native, proof_inputs, require, Dims, Inputs, Program, Result, Val, E};
use crate::f2::price;
use crate::m4interior::{INTERIOR_B2_CFG, INTERIOR_B4_CFG};

type OuterConfig = LegacyNonHidingConfig;
/// The consumer's native check on C1's public values (R-PV option (c)).
type PvCheck = Box<dyn Fn(&[Val]) -> Result<()>>;

/// The #750 stage-0 memory model (§3): `peak_GiB ≈ k × width × 2^(h − 18)`,
/// fitted on the legacy non-hiding M4 interior (issue #257's anchors). A
/// planning model with no calibrated interval, not a bound.
const K_B4: f64 = 0.004_279_69;
const K_B2: f64 = 0.002_656_45;

/// The outer (aggregation) lane: non-hiding, the M4 interior's.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::f2) enum Outer {
    B2,
    B4,
}

impl Outer {
    pub(in crate::f2) fn parse(s: &str) -> Result<Self> {
        match s {
            "b2" => Ok(Self::B2),
            "b4" => Ok(Self::B4),
            _ => Err("--outer must be b2|b4".into()),
        }
    }
    fn cfg(self) -> FriCfg {
        match self {
            Self::B2 => INTERIOR_B2_CFG,
            Self::B4 => INTERIOR_B4_CFG,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::B2 => "b2/q86/g22/fp16/a16",
            Self::B4 => "b4/q43/g22/fp16/a16",
        }
    }
}

/// Which components a prove run proves (a check run always builds both:
/// the seam needs them).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::f2) enum Component {
    C1,
    C2,
    Both,
}

impl Component {
    pub(in crate::f2) fn parse(s: &str) -> Result<Self> {
        match s {
            "c1" => Ok(Self::C1),
            "c2" => Ok(Self::C2),
            "both" => Ok(Self::Both),
            _ => Err("--component must be c1|c2|both".into()),
        }
    }
    fn c1(self) -> bool {
        self != Self::C2
    }
    fn c2(self) -> bool {
        self != Self::C1
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::f2) enum Mode {
    Check,
    Prove(Outer, Component),
}

/// [P] Both components' dimensions from `price::composed_c1` /
/// `composed_c2`, before anything is built.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::f2) struct Plan {
    pub(in crate::f2) c1_width: usize,
    pub(in crate::f2) c1_periodic: usize,
    pub(in crate::f2) c1_rows: usize,
    pub(in crate::f2) c2_width: usize,
    pub(in crate::f2) c2_rows: usize,
}

fn field(v: &Value, key: &str) -> Result<usize> {
    v[key]
        .as_u64()
        .map(|x| x as usize)
        .ok_or_else(|| format!("composed layout lacks `{key}`"))
}

fn gib(k: f64, width: usize, rows: usize) -> f64 {
    let v = k * width as f64 * rows as f64 / f64::from(1u32 << 18);
    (v * 1000.0).round() / 1000.0
}

impl Plan {
    pub(in crate::f2) fn of(shape: Shape) -> Result<Self> {
        let (c1, c2) = (price::composed_c1(shape)?, price::composed_c2(shape));
        Ok(Self {
            c1_width: field(&c1, "component_columns")?,
            c1_periodic: field(&c1, "periodic_columns")?,
            c1_rows: field(&c1, "padded_rows")?,
            c2_width: field(&c2, "component_columns")?,
            c2_rows: field(&c2, "padded_rows")?,
        })
    }

    /// Cells `C1Air::new` budgets: main columns plus the ROM's periodic
    /// columns, at the padded height.
    fn c1_cells(&self) -> Option<usize> {
        self.c1_rows.checked_mul(self.c1_width + self.c1_periodic)
    }
    fn c2_cells(&self) -> Option<usize> {
        self.c2_rows.checked_mul(self.c2_width)
    }

    /// Refuse, from the plan alone, a run whose components would exceed
    /// `max_cells`: nothing is allocated before this passes.
    pub(in crate::f2) fn admit(&self, max_cells: usize) -> Result<()> {
        for (name, cells) in [("C1", self.c1_cells()), ("C2", self.c2_cells())] {
            let cells = cells.ok_or_else(|| format!("{name} cell count overflows"))?;
            require(
                cells <= max_cells,
                &format!(
                    "{name} plan ({cells} cells) exceeds --max-cells {max_cells}; nothing allocated"
                ),
            )?;
        }
        Ok(())
    }

    pub(in crate::f2) fn report(&self) -> Value {
        let peaks =
            |w: usize, rows: usize| json!({"b2": gib(K_B2, w, rows), "b4": gib(K_B4, w, rows)});
        json!({"evidence": "P", "source": "price::composed_c1 / composed_c2 (source-derived layouts)",
            "c1": {"component_columns": self.c1_width, "periodic_columns": self.c1_periodic,
                "padded_rows": self.c1_rows, "cells_budgeted": self.c1_cells()},
            "c2": {"component_columns": self.c2_width, "periodic_columns": 0,
                "padded_rows": self.c2_rows, "cells_budgeted": self.c2_cells()},
            "expected_peak_gib": {"evidence": "P",
                "source": "issue #750 stage-0 §3 k-model: peak_GiB ≈ k × width × 2^(h−18), k_b2 = 0.00265645, k_b4 = 0.00427969 (legacy non-hiding M4 fits); planning model, not a bound",
                "c1_main_columns": peaks(self.c1_width, self.c1_rows),
                "c1_main_plus_periodic_columns": peaks(self.c1_width + self.c1_periodic, self.c1_rows),
                "c2": peaks(self.c2_width, self.c2_rows)}})
    }
}

/// One inner leaf: everything C1 and C2 read from it, and the R-PV check
/// its PVs answer to.
pub(super) struct Leaf<'a> {
    pub(super) dims: Dims,
    pub(super) chunks: usize,
    pub(super) program: Program,
    pub(super) inputs: Inputs,
    pub(super) proof: &'a Proof<Config>,
    pub(super) pvs: &'a [Val],
    pub(super) cfg: FriCfg,
    /// R-PV option (c): the consumer's native range check on C1's PVs.
    pub(super) pv_check: PvCheck,
}

/// The OOD program of a verifier AIR, and the native identity on the
/// proof's openings (residual zero), before anything is built on it.
fn compiled<A>(dims: Dims, air: &A, inputs: &Inputs) -> Result<Program>
where
    A: Air<SymbolicAirBuilder<Val>> + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
{
    let program = Program::compile_dims(dims, air)?;
    let values = compare_native(&program, air, inputs)?;
    require(
        values[program.residual] == E::ZERO,
        "native OOD identity fails on the leaf's openings",
    )?;
    Ok(program)
}

impl<'a> Leaf<'a> {
    /// A real L2 leaf of `shape` under the L2 lane.
    pub(super) fn of(shape: Shape, proof: &'a Proof<Config>, pvs: &'a [Val]) -> Result<Self> {
        let inputs = proof_inputs(shape, proof, pvs)?;
        let program = match shape {
            Shape::S => compiled(shape.into(), &qlab_l2::verifier_air_s(), &inputs)?,
            Shape::P => compiled(shape.into(), &qlab_l2::verifier_air_p(), &inputs)?,
            Shape::R => compiled(shape.into(), &qlab_l2::verifier_air_r(), &inputs)?,
        };
        Ok(Self {
            dims: shape.into(),
            chunks: proof.opened_values.quotient_chunks.len(),
            program,
            inputs,
            proof,
            pvs,
            cfg: L2_CFG_PROVISIONAL,
            pv_check: Box::new(move |c1_pvs| check_leaf_pvs(shape, c1_pvs)),
        })
    }
}

/// p3-air 0.6.1's `check_constraints` row evaluation, verbatim in effect
/// (same builder, selectors and wrap-around next row), with the periodic
/// columns read once per scan rather than rebuilt per row.
fn eval_row<A>(
    air: &A,
    trace: &RowMajorMatrix<Val>,
    pvs: &[Val],
    periodic: &[Vec<Val>],
    row: usize,
) -> Vec<ConstraintFailure>
where
    A: for<'b> Air<DebugConstraintBuilder<'b, Val>>,
{
    let (h, w) = (trace.height(), trace.width());
    let next = (row + 1) % h;
    let local = &trace.values[row * w..(row + 1) * w];
    let nxt = &trace.values[next * w..(next + 1) * w];
    let main = ViewPair::new(
        RowMajorMatrixView::new_row(local),
        RowMajorMatrixView::new_row(nxt),
    );
    let prep = ViewPair::new(
        RowMajorMatrixView::new(&[], 0),
        RowMajorMatrixView::new(&[], 0),
    );
    let periodic_row: Vec<Val> = periodic.iter().map(|c| c[row % c.len()]).collect();
    let mut builder = DebugConstraintBuilder::new(
        row,
        main,
        prep,
        pvs,
        Val::from_bool(row == 0),
        Val::from_bool(row == h - 1),
        Val::from_bool(row != h - 1),
        &periodic_row,
    );
    air.eval(&mut builder);
    builder.into_failures()
}

/// The SAT scan: EVERY row evaluated (in parallel), violations named by the
/// component's constraint group.
fn scan<A>(air: &A, trace: &RowMajorMatrix<Val>, pvs: &[Val]) -> Value
where
    A: Phased + Sync + for<'b> Air<DebugConstraintBuilder<'b, Val>>,
{
    let t = Instant::now();
    let ranges = phase_ranges(air);
    let periodic = air.periodic_columns();
    let mut bad: Vec<(usize, usize, usize)> = (0..trace.height())
        .into_par_iter()
        .filter_map(|row| {
            let f = eval_row(air, trace, pvs, &periodic, row);
            (!f.is_empty()).then(|| (row, f.len(), f[0].constraint))
        })
        .collect();
    bad.sort_unstable();
    let group = |c: usize| {
        ranges
            .iter()
            .position(|r| r.contains(&c))
            .map_or("?", |p| air.phases()[p])
    };
    json!({"evidence": "M", "source": "every row, p3-air check_constraints evaluator",
        "pass": bad.is_empty(), "rows_scanned": trace.height(),
        "constraints_per_row": ranges.last().map_or(0, |r| r.end),
        "violating_rows": bad.len(), "violations": bad.iter().map(|b| b.1).sum::<usize>(),
        "first_violations": bad.iter().take(8).map(|&(row, n, c)| json!({"row": row,
            "violations": n, "first_constraint": c, "group": group(c)})).collect::<Vec<_>>(),
        "seconds": t.elapsed().as_secs_f64()})
}

/// Constraint count and maximum degree, on the symbolic builder.
fn symbolic<A: Air<SymbolicAirBuilder<Val>>>(air: &A) -> (usize, usize) {
    let cs = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
    let degree = cs.iter().map(|c| c.degree_multiple()).max().unwrap_or(0);
    (cs.len(), degree)
}

/// What was built, against the plan, and its maximum constraint degree.
fn built<A>(air: &A, trace: &RowMajorMatrix<Val>, planned: (usize, usize, usize)) -> (Value, usize)
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let (constraints, degree) = symbolic(air);
    let (w, h, periodic) = (trace.width(), trace.height(), air.num_periodic_columns());
    let v = json!({"evidence": "M", "source": "the trace this run allocated; constraints on the symbolic builder",
        "width": w, "height": h, "log_height": h.trailing_zeros(), "periodic_columns": periodic,
        "public_values": air.num_public_values(), "constraints": constraints, "max_degree": degree,
        "matches_plan": (w, h, periodic) == planned});
    (v, degree)
}

fn outcome(r: Result<()>) -> Value {
    match r {
        Ok(()) => json!({"pass": true}),
        Err(e) => json!({"pass": false, "error": e}),
    }
}

/// The check stage for `leaf`, C2 covering `slots`. `plan` is `None` for a
/// leaf that is not an L2 shape (a test's toy).
pub(super) fn check_leaf(
    leaf: &Leaf<'_>,
    slots: Vec<usize>,
    plan: Option<Plan>,
    max_cells: usize,
) -> Result<Value> {
    let mut checks = Map::new();
    let t = Instant::now();
    let c1::Honest {
        air,
        trace,
        pvs,
        seam: c1_seam,
    } = c1::honest(
        &leaf.program,
        &leaf.inputs,
        leaf.proof,
        leaf.pvs,
        &leaf.cfg,
        max_cells,
    )?;
    let c1_build_s = t.elapsed().as_secs_f64();
    let c1_planned = plan.map(|p| (p.c1_width, p.c1_rows, p.c1_periodic));
    let (c1_built, c1_degree) = built(&air, &trace, c1_planned.unwrap_or_default());
    let c1_scan = scan(&air, &trace, &pvs);
    drop(trace);
    checks.insert("c1_sat".into(), json!(c1_scan["pass"]));
    checks.insert("c1_degree_at_most_3".into(), json!(c1_degree <= 3));
    // R-PV option (c): every inner PV exposed unchanged, then range-checked
    // natively by the leaf AIR's widths.
    let n = air.inner_pv_len();
    checks.insert(
        "c1_exposes_every_inner_pv".into(),
        json!(n == leaf.pvs.len() && pvs[..n] == *leaf.pvs),
    );
    let leaf_pvs = outcome((leaf.pv_check)(&pvs));
    checks.insert("leaf_pv_widths".into(), leaf_pvs["pass"].clone());
    drop(air);
    let t = Instant::now();
    let c2::Honest {
        air,
        trace,
        pvs: c2_pvs,
        seam: c2_seam,
    } = c2::honest(
        leaf.dims,
        leaf.chunks,
        &leaf.cfg,
        &c1_seam,
        slots,
        leaf.proof,
        max_cells,
    )?;
    let c2_build_s = t.elapsed().as_secs_f64();
    let c2_planned = plan.map(|p| (p.c2_width, p.c2_rows, 0));
    let (c2_built, c2_degree) = built(&air, &trace, c2_planned.unwrap_or_default());
    let c2_scan = scan(&air, &trace, &c2_pvs);
    drop(trace);
    checks.insert("c2_sat".into(), json!(c2_scan["pass"]));
    checks.insert("c2_degree_at_most_3".into(), json!(c2_degree <= 3));
    let seams = outcome(check_seams(&c1_seam, &c2_seam));
    let coverage = outcome(check_coverage(&c1_seam, &c2_seam));
    checks.insert("seams".into(), seams["pass"].clone());
    checks.insert("coverage".into(), coverage["pass"].clone());
    if plan.is_some() {
        checks.insert(
            "layouts_match_plan".into(),
            json!(c1_built["matches_plan"] == true && c2_built["matches_plan"] == true),
        );
    }
    let all_pass = checks.values().all(|v| *v == true);
    Ok(
        json!({"stage": "check", "all_pass": all_pass, "checks": checks,
        "c1": {"built": c1_built, "build_seconds": c1_build_s, "sat_scan": c1_scan,
            "leaf_pv_widths": leaf_pvs},
        "c2": {"built": c2_built, "build_seconds": c2_build_s, "sat_scan": c2_scan,
            "covered_queries": c2_seam.indices.len()},
        "seams": seams, "coverage": coverage}),
    )
}

/// Prove and natively verify one component under the outer config.
fn prove_component<A>(
    air: &A,
    trace: RowMajorMatrix<Val>,
    pvs: &[Val],
    config: &OuterConfig,
    planned: (usize, usize, usize),
) -> Value
where
    A: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'b> Air<DebugConstraintBuilder<'b, Val>>
        + for<'b> Air<ProverConstraintFolder<'b, OuterConfig>>
        + for<'b> Air<VerifierConstraintFolder<'b, OuterConfig>>,
{
    let (dims, _) = built(air, &trace, planned);
    let t = Instant::now();
    let proof = prove(config, air, trace, pvs);
    let prove_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let verified = verify(config, air, &proof, pvs);
    let verify_s = t.elapsed().as_secs_f64();
    let bytes = bincode::serialize(&proof).map(|b| b.len()).ok();
    json!({"built": dims,
        "proof_bytes": {"evidence": "M", "source": "bincode::serialize (as m4interior)", "value": bytes},
        "prove_seconds": {"evidence": "M", "value": prove_s},
        "verify_seconds": {"evidence": "M", "value": verify_s},
        "native_verified": verified.is_ok(),
        "verify_error": verified.err().map(|e| format!("{e:?}"))})
}

/// The prove stage for a real leaf of `shape`: C1 (always built, its seam
/// feeds C2), then C2 over every query slot, each proved if selected.
pub(super) fn prove_leaf(
    leaf: &Leaf<'_>,
    plan: Plan,
    outer: Outer,
    component: Component,
    max_cells: usize,
) -> Result<Value> {
    let config = make_legacy_config_with(&outer.cfg());
    let c1::Honest {
        air,
        trace,
        pvs,
        seam: c1_seam,
    } = c1::honest(
        &leaf.program,
        &leaf.inputs,
        leaf.proof,
        leaf.pvs,
        &leaf.cfg,
        max_cells,
    )?;
    let leaf_pvs = outcome((leaf.pv_check)(&pvs));
    let planned = (plan.c1_width, plan.c1_rows, plan.c1_periodic);
    let c1_report = if component.c1() {
        prove_component(&air, trace, &pvs, &config, planned)
    } else {
        drop(trace);
        json!("not proved (--component c2); built for its seam only")
    };
    drop(air);
    let (c2_report, seams, coverage) = if component.c2() {
        let c2::Honest {
            air,
            trace,
            pvs,
            seam,
        } = c2::honest(
            leaf.dims,
            leaf.chunks,
            &leaf.cfg,
            &c1_seam,
            (0..leaf.cfg.num_queries).collect(),
            leaf.proof,
            max_cells,
        )?;
        let seams = outcome(check_seams(&c1_seam, &seam));
        let coverage = outcome(check_coverage(&c1_seam, &seam));
        let planned = (plan.c2_width, plan.c2_rows, 0);
        (
            prove_component(&air, trace, &pvs, &config, planned),
            seams,
            coverage,
        )
    } else {
        (
            json!("not built (--component c1)"),
            Value::Null,
            Value::Null,
        )
    };
    let verified = [&c1_report, &c2_report]
        .iter()
        .all(|r| !r.is_object() || r["native_verified"] == true);
    Ok(
        json!({"stage": "prove", "outer_lane": outer.label(), "outer_pcs": "non-hiding (qlab_consensus::legacy)",
        "outer_config_source": "m4interior::INTERIOR_B2_CFG / INTERIOR_B4_CFG",
        "all_pass": verified && leaf_pvs["pass"] == true && seams["pass"] != false && coverage["pass"] != false,
        "c1": c1_report, "c2": c2_report, "leaf_pv_widths": leaf_pvs, "seams": seams, "coverage": coverage,
        "peak_rss": {"evidence": "M", "value": null,
            "operator_records": "`Maximum resident set size (kbytes)` from the /usr/bin/time -v wrapping this process; GiB = kbytes / 1024^2. Compare with plan.expected_peak_gib [P]."}}),
    )
}

/// `f2wrap` for a real leaf of `shape`.
pub(in crate::f2) fn run(
    shape: Shape,
    proof: &Proof<Config>,
    pvs: &[Val],
    plan: Plan,
    mode: Mode,
    max_cells: usize,
) -> Result<Value> {
    plan.admit(max_cells)?;
    let leaf = Leaf::of(shape, proof, pvs)?;
    match mode {
        Mode::Check => check_leaf(
            &leaf,
            (0..leaf.cfg.num_queries).collect(),
            Some(plan),
            max_cells,
        ),
        Mode::Prove(outer, component) => prove_leaf(&leaf, plan, outer, component, max_cells),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fri_fs::tests::shared;
    use super::super::lane::toy::{copy, regrind, violation_set, Toy};
    use super::super::open::{self, QUOTIENT, RANDOM, TRACE};
    use super::super::proof_inputs_dims;
    use super::super::seam::{check_pv_widths, PvWidth};
    use super::*;

    /// The shared log-8 toy leaf, with a width table that treats both of its
    /// PVs as 16-bit chunks. Its PV 1 is the recurrence's last value, far
    /// above 2^16: the table is what refuses it, never C1.
    fn toy_leaf() -> Leaf<'static> {
        let sh = shared();
        let dims = Dims {
            width: 2,
            pv_len: 2,
            log_height: sh.log_height,
        };
        let inputs = proof_inputs_dims(dims, sh.proof, sh.pvs).unwrap();
        let program = Program::compile_dims(dims, &Toy).unwrap();
        let widths = ["toy_x", "toy_y"].map(|group| PvWidth {
            group,
            index: 0,
            bits: 16,
        });
        Leaf {
            dims,
            chunks: sh.proof.opened_values.quotient_chunks.len(),
            program,
            inputs,
            proof: sh.proof,
            pvs: sh.pvs,
            cfg: L2_CFG_PROVISIONAL,
            pv_check: Box::new(move |pvs| check_pv_widths(&widths, pvs)),
        }
    }

    /// The check stage end to end on the toy leaf, C2 over two query slots
    /// (the C2 tests' instance): both traces SAT at degree 3, seams equal,
    /// every inner PV exposed. Coverage fails (two of 43 slots), and R-PV's
    /// native check refuses the toy's PV 1 by name while C1 accepted it.
    #[test]
    fn f2wrap_check_stage_on_the_toy_leaf() {
        let leaf = toy_leaf();
        let path = open::Geom::new(leaf.dims, leaf.chunks, &leaf.cfg)
            .unwrap()
            .path;
        let idx = &shared().indices;
        let other = (1..idx.len())
            .find(|&i| idx[i] >> path != idx[0] >> path)
            .unwrap();
        let r = check_leaf(&leaf, vec![0, other], None, 64 << 20).unwrap();
        let c = &r["checks"];
        for pass in [
            "c1_sat",
            "c1_degree_at_most_3",
            "c1_exposes_every_inner_pv",
            "c2_sat",
            "c2_degree_at_most_3",
            "seams",
        ] {
            assert_eq!(c[pass], true, "{pass}: {r}");
        }
        assert_eq!(c["coverage"], false);
        assert_eq!(c["leaf_pv_widths"], false);
        let err = r["c1"]["leaf_pv_widths"]["error"].as_str().unwrap();
        assert!(err.contains("`toy_y[0]`"), "{err}");
        assert_eq!(r["all_pass"], false);
        assert_eq!(r["c2"]["covered_queries"], 2);
        assert_eq!(r["c1"]["sat_scan"]["violating_rows"], 0);
    }

    /// A budget below the plan is refused from the plan alone.
    #[test]
    fn f2wrap_plan_refuses_over_budget_before_building() {
        let plan = Plan {
            c1_width: 11_746,
            c1_periodic: 2_227,
            c1_rows: 1 << 15,
            c2_width: 5_058,
            c2_rows: 1 << 17,
        };
        let c1 = (11_746 + 2_227) << 15;
        let c2 = 5_058 << 17;
        assert!(plan.admit(c1.max(c2)).is_ok());
        let err = plan.admit(c2 - 1).unwrap_err();
        assert!(
            err.contains("C2 plan") && err.contains("nothing allocated"),
            "{err}"
        );
        let err = plan.admit(c1 - 1).unwrap_err();
        assert!(err.contains("C1 plan"), "{err}");
        let huge = Plan {
            c1_rows: usize::MAX,
            ..plan
        };
        assert!(huge.admit(usize::MAX).unwrap_err().contains("overflows"));
        // The k-model at the S3 plan: C2 dominates.
        let r = plan.report();
        assert_eq!(r["expected_peak_gib"]["c2"]["b4"], 10.823);
        assert_eq!(r["expected_peak_gib"]["c2"]["b2"], 6.718);
        assert_eq!(r["expected_peak_gib"]["c1_main_columns"]["b4"], 6.284);
    }

    /// C2's two-slot toy instance (the C2 tests'): slot 0 and the first slot
    /// whose cap entry differs.
    fn toy_slots(leaf: &Leaf<'_>) -> Vec<usize> {
        let path = open::Geom::new(leaf.dims, leaf.chunks, &leaf.cfg)
            .unwrap()
            .path;
        let idx = &shared().indices;
        let other = (1..idx.len())
            .find(|&i| idx[i] >> path != idx[0] >> path)
            .unwrap();
        vec![0, other]
    }

    /// F2b-5 (stage-0's "missing/altered randomizer" and "salt/path/point
    /// lengths"): a toy leaf proof missing a piece, or with a length the
    /// builders read changed, is refused by name by the builders
    /// `check_leaf` calls: C1's (`c1::honest`), C2's (`c2::honest`, on the
    /// covered slot 0) and the leaf's native OOD compile (`compiled`, which
    /// `Leaf::of` runs). For an L2 shape `f2wrap` runs `validate_geometry`
    /// and the native verifier before any of these; the census test names
    /// those refusals.
    #[test]
    fn f2wrap_builders_refuse_missing_or_misshapen_proofs_by_name() {
        type Edit = fn(&mut Proof<Config>);
        let leaf = toy_leaf();
        let sh = shared();
        let (cfg, max) = (L2_CFG_PROVISIONAL, 64 << 20);
        let edited = |edit: Edit| {
            let mut p = copy(sh.proof);
            edit(&mut p);
            p
        };
        let c1_side: [(Edit, &str); 3] = [
            (
                |p| p.commitments.random = None,
                "missing randomizer commitment",
            ),
            (
                |p| p.opened_values.random = None,
                "missing randomizer opening",
            ),
            (
                |p| p.opened_values.trace_next = None,
                "missing next-row opening",
            ),
        ];
        for (edit, name) in c1_side {
            let p = edited(edit);
            let err = c1::honest(&leaf.program, &leaf.inputs, &p, sh.pvs, &cfg, max)
                .err()
                .unwrap();
            assert_eq!(err, name);
        }
        let point: [Edit; 2] = [
            |p| p.opened_values.trace_local.push(E::ZERO),
            |p| p.opened_values.quotient_chunks[5].push(E::ZERO),
        ];
        for edit in point {
            let p = edited(edit);
            let inputs = proof_inputs_dims(leaf.dims, &p, sh.pvs).unwrap();
            let err = compiled(leaf.dims, &Toy, &inputs).err().unwrap();
            assert_eq!(err, "OOD input dimensions");
        }
        let seam = c1::honest(&leaf.program, &leaf.inputs, sh.proof, sh.pvs, &cfg, max)
            .unwrap()
            .seam;
        let slots = toy_slots(&leaf);
        let c2_side: [(Edit, &str); 9] = [
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].input_proof.pop();
                },
                "input batch count",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].input_proof[RANDOM].opened_values[0]
                        .push(Val::ZERO)
                },
                "opened row shape",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].input_proof[TRACE]
                        .opening_proof
                        .0[0]
                        .pop();
                },
                "salt shape",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].input_proof[QUOTIENT]
                        .opening_proof
                        .1
                        .pop();
                },
                "input path length",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0]
                        .commit_phase_openings
                        .pop();
                },
                "commit round count",
            ),
            (
                |p| p.opening_proof.1.query_proofs[0].commit_phase_openings[1].log_arity ^= 1,
                "log arity differs from the fixed schedule",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                        .sibling_values
                        .pop();
                },
                "sibling count",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                        .opening_proof
                        .0[0]
                        .pop();
                },
                "commit-phase salt shape",
            ),
            (
                |p| {
                    p.opening_proof.1.query_proofs[0].commit_phase_openings[1]
                        .opening_proof
                        .1
                        .pop();
                },
                "commit-phase path length",
            ),
        ];
        for (edit, name) in c2_side {
            let p = edited(edit);
            let err = c2::honest(leaf.dims, leaf.chunks, &cfg, &seam, slots.clone(), &p, max)
                .err()
                .unwrap();
            assert_eq!(err, name);
        }
    }

    /// F2b-5 (the kickoff's "legacy verifier fed a hiding proof"; stage-0:
    /// "never feed a hiding proof to the legacy verifier"). The legacy,
    /// non-hiding p3 verifier (the outer lane here, and the M4 modules)
    /// takes `Proof<LegacyNonHidingConfig>`, so a hiding `Proof<Config>`
    /// reaches it only re-typed. The most generous re-typing keeps every
    /// commitment, opened value and FRI value and drops only the Merkle
    /// salts, which the legacy MMCS has no slot for. It is refused by name
    /// before any transcript work: the randomizer the hiding PCS adds
    /// (`RandomizationError`); with the randomizer dropped too, the eight
    /// hiding quotient chunks where the non-hiding verifier expects two
    /// (`OpenedValuesDimensionMismatch`). The hiding verifier accepts the
    /// same proof. So the legacy verifier cannot stand in for C1's
    /// hiding-aware transcript.
    #[test]
    fn the_legacy_verifier_refuses_a_hiding_leaf_proof() {
        use p3_commit::BatchOpening;
        use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
        use p3_uni_stark::{Commitments, OpenedValues, VerificationError};
        let sh = shared();
        let retype = |p: &Proof<Config>, randomizer: bool| -> Proof<OuterConfig> {
            let (c, o, fri) = (&p.commitments, &p.opened_values, &p.opening_proof.1);
            let query_proofs = fri
                .query_proofs
                .iter()
                .map(|q| QueryProof {
                    input_proof: q
                        .input_proof
                        .iter()
                        .map(|b| BatchOpening {
                            opened_values: b.opened_values.clone(),
                            opening_proof: b.opening_proof.1.clone(),
                        })
                        .collect(),
                    commit_phase_openings: q
                        .commit_phase_openings
                        .iter()
                        .map(|s| CommitPhaseProofStep {
                            log_arity: s.log_arity,
                            sibling_values: s.sibling_values.clone(),
                            opening_proof: s.opening_proof.1.clone(),
                        })
                        .collect(),
                })
                .collect();
            Proof {
                commitments: Commitments {
                    trace: c.trace.clone(),
                    quotient_chunks: c.quotient_chunks.clone(),
                    random: c.random.clone().filter(|_| randomizer),
                },
                opened_values: OpenedValues {
                    trace_local: o.trace_local.clone(),
                    trace_next: o.trace_next.clone(),
                    preprocessed_local: o.preprocessed_local.clone(),
                    preprocessed_next: o.preprocessed_next.clone(),
                    quotient_chunks: o.quotient_chunks.clone(),
                    random: o.random.clone().filter(|_| randomizer),
                },
                opening_proof: FriProof {
                    commit_phase_commits: fri.commit_phase_commits.clone(),
                    commit_pow_witnesses: fri.commit_pow_witnesses.clone(),
                    query_proofs,
                    final_poly: fri.final_poly.clone(),
                    query_pow_witness: fri.query_pow_witness,
                },
                degree_bits: p.degree_bits,
            }
        };
        verify(&qlab_l2::make_config_l2(), &Toy, sh.proof, sh.pvs).unwrap();
        let legacy = make_legacy_config_with(&L2_CFG_PROVISIONAL);
        let err = verify(&legacy, &Toy, &retype(sh.proof, true), sh.pvs).unwrap_err();
        assert!(
            matches!(err, VerificationError::RandomizationError),
            "{err:?}"
        );
        let err = verify(&legacy, &Toy, &retype(sh.proof, false), sh.pvs).unwrap_err();
        assert!(
            format!("{err:?}").contains("OpenedValuesDimensionMismatch"),
            "{err:?}"
        );
    }

    /// F2b-5 (stage-0's "shape-specific public-state/fee routing"), toy:
    /// the leaf's two PVs swapped — each routed to the other's offset —
    /// under the honest proof. p3's verifier refuses it. The leaf's native
    /// compile (`compiled`) refuses it by name: the PVs are absorbed before
    /// α and read by the AIR, so the OOD identity fails. C1's builder
    /// refuses it while the PoW is the proof's own; re-ground, C1 exposes
    /// the swapped PVs unchanged and refuses on the last row alone
    /// (`machine_out`).
    #[test]
    fn f2wrap_refuses_toy_pvs_routed_to_the_wrong_offset() {
        let leaf = toy_leaf();
        let sh = shared();
        let cfg = L2_CFG_PROVISIONAL;
        let swapped = [sh.pvs[1], sh.pvs[0]];
        let mut proof = copy(sh.proof);
        assert!(verify(&qlab_l2::make_config_l2(), &Toy, &proof, &swapped).is_err());
        let inputs = proof_inputs_dims(leaf.dims, &proof, &swapped).unwrap();
        let err = compiled(leaf.dims, &Toy, &inputs).err().unwrap();
        assert_eq!(err, "native OOD identity fails on the leaf's openings");
        let err = c1::honest(&leaf.program, &inputs, &proof, &swapped, &cfg, 64 << 20)
            .err()
            .unwrap();
        assert_eq!(err, "query PoW sample is not zero");
        regrind(&mut proof, &swapped, leaf.dims.log_height);
        let h = c1::honest(&leaf.program, &inputs, &proof, &swapped, &cfg, 64 << 20).unwrap();
        assert_eq!(h.pvs[..2], swapped);
        assert_eq!(
            violation_set(&h.air, &h.trace, &h.pvs),
            [(h.trace.height() - 1, "machine_out")].into()
        );
    }

    /// F2b-5 (shape-specific routing on the real S3 leaf, the census test's
    /// shared proof): S3's PVs laid out as P3's (the vPublic block inserted
    /// before nf3) are refused by the S3 leaf's native compile by name, and
    /// S3's fee chunks routed to R's fee offset (where S carries cm1) make
    /// the OOD identity fail. The native S verifier refuses both. A
    /// full-size S3 C1 is beyond a CI test's budget; the toy test above
    /// shows the same routing refused in-circuit.
    #[test]
    fn f2wrap_refuses_s3_pvs_in_another_shapes_layout() {
        use qlab_air::{l2, l2p, l2r};
        let (proof, pvs) = crate::f2::s3_proof();
        assert!(Leaf::of(Shape::S, &proof, &pvs).is_ok());
        let mut as_p = pvs[..l2p::PV_VP1].to_vec();
        as_p.extend([Val::ZERO; l2p::PV_NF3 - l2p::PV_VP1]);
        as_p.extend_from_slice(&pvs[l2::PV_NF3..]);
        assert_eq!(as_p.len(), Shape::P.pv_len());
        let mut fee_at_r = pvs.clone();
        for i in 0..4 {
            fee_at_r.swap(l2::PV_FEE + i, l2r::PV_FEE + i);
        }
        assert_ne!(fee_at_r, pvs);
        for (bad, name) in [
            (&as_p, "OOD input dimensions"),
            (
                &fee_at_r,
                "native OOD identity fails on the leaf's openings",
            ),
        ] {
            assert!(!qlab_l2::verify_s(bad, &proof), "{name}");
            assert_eq!(Leaf::of(Shape::S, &proof, bad).err().unwrap(), name);
        }
    }
}
