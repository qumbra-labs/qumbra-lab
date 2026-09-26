//! Geometry and symbolic operation counts only. No trace/proof allocation.
use std::collections::HashSet;
use std::sync::Arc;

use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, SymbolicAirBuilder, SymbolicExpression,
};
use p3_air::Air;
use p3_uni_stark::get_log_num_quotient_chunks;
use qlab_consensus::{Val, CAP_HEIGHT, IS_ZK, SALT_ELEMS};
use qlab_l2::{Shape, L2_CFG_PROVISIONAL};
use serde_json::{json, Value};

#[derive(Default)]
struct Ops {
    add: usize,
    sub: usize,
    neg: usize,
    mul: usize,
    leaves: usize,
}

fn visit(expr: &Arc<SymbolicExpression<Val>>, seen: &mut HashSet<usize>, ops: &mut Ops) {
    if seen.insert(Arc::as_ptr(expr) as usize) {
        walk(expr, seen, ops);
    }
}

fn walk(expr: &SymbolicExpression<Val>, seen: &mut HashSet<usize>, ops: &mut Ops) {
    use p3_air::symbolic::SymbolicExpr::*;
    match expr {
        Leaf(_) => ops.leaves += 1,
        Add { x, y, .. } | Sub { x, y, .. } | Mul { x, y, .. } => {
            match expr {
                Add { .. } => ops.add += 1,
                Sub { .. } => ops.sub += 1,
                _ => ops.mul += 1,
            }
            visit(x, seen, ops);
            visit(y, seen, ops);
        }
        Neg { x, .. } => {
            ops.neg += 1;
            visit(x, seen, ops);
        }
    }
}

pub(super) fn air_report<A: Air<SymbolicAirBuilder<Val>>>(air: &A) -> Value {
    let layout = AirLayout::from_air::<Val>(air);
    let constraints = get_symbolic_constraints::<Val, _>(air, layout);
    let max_degree = constraints
        .iter()
        .map(|c| c.degree_multiple())
        .max()
        .unwrap_or(0);
    let mut ops = Ops::default();
    let mut seen = HashSet::new();
    for constraint in &constraints {
        walk(constraint, &mut seen, &mut ops);
    }
    // Match uni-stark's prover, including the extra ZK splitting factor.
    let chunks = 1usize << (get_log_num_quotient_chunks::<Val, _>(air, layout, IS_ZK) + IS_ZK);
    let periodic = air.periodic_columns();
    json!({"evidence": "P", "source": "live AIR symbolic DAG (pointer sharing; no structural CSE)",
        "trace_columns": layout.main_width, "public_values": layout.num_public_values,
        "constraints": constraints.len(), "max_constraint_degree": max_degree,
        "hiding_quotient_chunks": chunks,
        "periodic_columns": layout.num_periodic_columns,
        "periodic_column_lengths": periodic.iter().map(Vec::len).collect::<Vec<_>>(),
        "dag": {"add": ops.add, "sub": ops.sub, "neg": ops.neg, "mul": ops.mul, "leaf_reads": ops.leaves},
        "alpha_horner_unoptimized": {"mul": constraints.len(), "add": constraints.len()},
        "not_lowered": ["periodic evaluation at zeta", "quotient recombination and identity",
            "register allocation and lifetime bindings", "hiding opening arithmetic",
            "issue #78 repairs", "shape-specific state-transition and fee binding"],
        "complete_verifier_layout": false, "memory_gate_pass": false})
}

pub(super) fn symbolic(shape: Shape) -> Value {
    match shape {
        Shape::S => air_report(&qlab_l2::verifier_air_s()),
        Shape::P => air_report(&qlab_l2::verifier_air_p()),
        Shape::R => air_report(&qlab_l2::verifier_air_r()),
    }
}

#[derive(Debug)]
pub(super) struct Geometry {
    pub chunks: usize,
    pub input_path: usize,
    pub log_arities: Vec<usize>,
    pub fri_paths: Vec<usize>,
    pub leaf_per_query: usize,
    pub compress_per_query: usize,
    pub ood: usize,
    pub fs_floor: usize,
    pub duplicate: usize,
}

pub(super) fn geometry(shape: Shape, chunks: usize) -> Geometry {
    let cfg = L2_CFG_PROVISIONAL;
    let lde_log = shape.log_height() + IS_ZK + cfg.log_blowup;
    let mut remaining = lde_log - cfg.log_blowup - cfg.log_final_poly_len;
    let mut domain_log = lde_log;
    let mut log_arities = vec![];
    let mut fri_paths = vec![];
    while remaining > 0 {
        let arity = remaining.min(cfg.max_log_arity);
        remaining -= arity;
        domain_log -= arity;
        log_arities.push(arity);
        fri_paths.push(domain_log - CAP_HEIGHT);
    }
    let input_path = lde_log - CAP_HEIGHT;
    let leaf_per_query = (shape.width() + SALT_ELEMS).div_ceil(34)
        + (4 + SALT_ELEMS).div_ceil(34)
        + (chunks * (4 + SALT_ELEMS)).div_ceil(34)
        + log_arities
            .iter()
            .map(|a| (4 * (1usize << a) + SALT_ELEMS).div_ceil(34))
            .sum::<usize>();
    let compress_per_query = 3 * input_path + fri_paths.iter().sum::<usize>();
    let ood = 2 * shape.width() + 4 + 4 * chunks;
    let cap_bytes = (1usize << CAP_HEIGHT) * 32;
    let blocks = |bytes: usize| bytes / 136 + 1;
    let duplicate = blocks(32 + 16 * ood);
    // After final-poly/arity/PoW observation, one digest provides eight u32
    // draws. Query indices and the query-PoW check do not field-reject.
    let query_refills = (cfg.num_queries + 1).div_ceil(8) - 1;
    let fs_floor = blocks(12 + cap_bytes + 4 * shape.pv_len())
        + blocks(32 + 2 * cap_bytes)
        + duplicate
        + log_arities.len() * blocks(32 + cap_bytes)
        + blocks(32 + 16 * (1usize << cfg.log_final_poly_len) + 4 * log_arities.len() + 4)
        + query_refills;
    Geometry {
        chunks,
        input_path,
        log_arities,
        fri_paths,
        leaf_per_query,
        compress_per_query,
        ood,
        fs_floor,
        duplicate,
    }
}

impl Geometry {
    pub(super) fn report(&self, shape: Shape) -> Value {
        let cfg = L2_CFG_PROVISIONAL;
        let native =
            cfg.num_queries * (self.leaf_per_query + self.compress_per_query) + self.fs_floor;
        let lane = native + self.duplicate + 1;
        let rows = lane * 24;
        json!({"evidence": "P", "source": "pinned hiding PCS geometry; no rejection-refill lower bound",
            "trace_columns": shape.width(), "original_log_height": shape.log_height(),
            "committed_log_height": shape.log_height() + IS_ZK,
            "lde_log_height": shape.log_height() + IS_ZK + cfg.log_blowup,
            "query_count": cfg.num_queries, "cap_height": CAP_HEIGHT,
            "salt_elements_per_matrix_row": SALT_ELEMS,
            "opening_rounds": [
                {"kind": "randomizer", "matrices": 1, "columns_per_matrix": 4, "points": 1},
                {"kind": "trace", "matrices": 1, "columns_per_matrix": shape.width(), "points": 2},
                {"kind": "quotient", "matrices": self.chunks, "columns_per_matrix": 4, "points": 1}],
            "ood_extension_claims": self.ood,
            "input_paths_per_query": vec![self.input_path; 3],
            "fri_log_arities": self.log_arities, "fri_path_lengths": self.fri_paths,
            "leaf_permutations_per_query": self.leaf_per_query,
            "compressions_per_query": self.compress_per_query,
            "challenger_permutations_floor": self.fs_floor,
            "native_permutations_floor": native, "m4_style_lane_permutations_floor": lane,
            "opening_schedule_rows_floor": rows, "opening_schedule_padded_rows_floor": rows.next_power_of_two(),
            "complete_verifier_layout": false, "memory_gate_pass": false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiding_geometry_matches_stage_zero_and_extra_p_fold() {
        for (shape, ood, paths, leaf, compress, floor, lane) in [
            (Shape::S, 1478, vec![15, 11, 7, 3], 33, 93, 206, 5800),
            (Shape::P, 1632, vec![16, 12, 8, 4, 3], 36, 103, 227, 6398),
            (Shape::R, 1504, vec![14, 10, 6, 3], 33, 87, 208, 5547),
        ] {
            let g = geometry(shape, 8);
            assert_eq!(
                (g.ood, g.leaf_per_query, g.compress_per_query, g.fs_floor),
                (ood, leaf, compress, floor)
            );
            assert_eq!(g.fri_paths, paths);
            assert_eq!(g.report(shape)["m4_style_lane_permutations_floor"], lane);
        }
    }

    #[test]
    fn live_air_census_pins_hiding_chunks_and_periodic_columns() {
        for (shape, count, periodic) in [
            (Shape::S, 1113, 40),
            (Shape::P, 1328, 40),
            (Shape::R, 1226, 41),
        ] {
            let r = symbolic(shape);
            assert_eq!(r["constraints"], count);
            assert_eq!(r["periodic_columns"], periodic);
            assert_eq!(r["max_constraint_degree"], 4);
            assert_eq!(r["hiding_quotient_chunks"], 8);
            assert_eq!(r["memory_gate_pass"], false);
        }
    }
}
