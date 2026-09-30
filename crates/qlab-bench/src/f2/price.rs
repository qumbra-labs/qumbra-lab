//! Geometry and symbolic operation counts only. No trace/proof allocation.
use std::collections::HashSet;
use std::sync::Arc;

use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, SymbolicAirBuilder, SymbolicExpression,
};
use p3_air::Air;
use p3_keccak_air::NUM_KECCAK_COLS;
use p3_uni_stark::get_log_num_quotient_chunks;
use qlab_consensus::{FriCfg, Val, CAP_HEIGHT, IS_ZK, SALT_ELEMS};
use qlab_l2::Shape;
use crate::f2::F2_LANE;
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

/// LDE height of a hiding commitment to a `log_height` trace on the L2 lane.
pub(super) fn lde_log(log_height: usize) -> usize {
    log_height + IS_ZK + F2_LANE.log_blowup
}

/// Leaf absorb perms for one salted matrix row of `width` base values:
/// 17 u64 lanes = 34 base values per Keccak-f.
fn leaf_perms(width: usize) -> usize {
    (width + SALT_ELEMS).div_ceil(34)
}

/// The FRI fold schedule p3-fri 0.6.1's prover commits to when every input
/// sits at one LDE height (`prover.rs` `commit_phase` via
/// `compute_log_arity_for_round` with no smaller input left): fold by the
/// maximum arity until the final height `log_blowup + log_final_poly_len`.
/// Hiding uni-stark commits the trace, the quotient chunks and the randomizer
/// all at 2N rows, so this is the L2 lane's schedule. F2b-2b-i's transcript
/// layout takes its rounds from here and cross-checks a real proof's.
pub(super) fn fri_log_arities(lde_log: usize, cfg: &FriCfg) -> Vec<usize> {
    let mut remaining = lde_log - cfg.log_blowup - cfg.log_final_poly_len;
    let mut log_arities = vec![];
    while remaining > 0 {
        let arity = remaining.min(cfg.max_log_arity);
        remaining -= arity;
        log_arities.push(arity);
    }
    log_arities
}

pub(super) fn geometry(shape: Shape, chunks: usize) -> Geometry {
    let cfg = F2_LANE;
    let lde_log = lde_log(shape.log_height());
    let log_arities = fri_log_arities(lde_log, &cfg);
    let mut domain_log = lde_log;
    let mut fri_paths = vec![];
    for &arity in &log_arities {
        domain_log -= arity;
        fri_paths.push(domain_log - CAP_HEIGHT);
    }
    let input_path = lde_log - CAP_HEIGHT;
    let leaf_per_query = leaf_perms(shape.width())
        + leaf_perms(4)
        + (chunks * (4 + SALT_ELEMS)).div_ceil(34)
        + log_arities
            .iter()
            .map(|a| leaf_perms(4 * (1usize << a)))
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

/// [P] The register machine's ROM priced two ways, for whoever verifies the
/// proof that carries it (F2b-2a census hook; no layout is chosen here).
///
/// - **Periodic**: the verifier interpolates nothing at run time but must
///   evaluate each full-period column at zeta — Horner over `rom_rows`
///   coefficients, one extension mul + add each. No PCS cost: the columns are
///   AIR constants, never committed or opened.
/// - **Committed preprocessed**: one more hiding commitment on the L2 lane.
///   Its cap joins F0 (uni-stark observes the preprocessed commitment there),
///   each column is opened at zeta (one extension value, 16 transcript bytes
///   in F2), each query opens one salted leaf row of it plus one more input
///   path, the reduced opening gains one fri_alpha term per column, and the
///   OOD DAG reads each opened value as an input instead of evaluating it.
///
/// Both are stated; which one F2 uses is a layout decision, not made in code.
pub(super) fn rom_encoding(rom_width: usize, rom_log_height: usize) -> Value {
    let cfg = F2_LANE;
    let rows = 1usize << rom_log_height;
    let path = lde_log(rom_log_height) - CAP_HEIGHT;
    let leaf = leaf_perms(rom_width);
    json!({"evidence": "P", "source": "reference ROM width/height; L2-lane hiding PCS geometry (price::geometry formulas)",
        "rom_columns": rom_width, "rom_rows": rows,
        "periodic": {"ood_extension_mul": rom_width * rows, "ood_extension_add": rom_width * rows,
            "pcs_cost": 0},
        "committed_preprocessed": {"f0_cap_bytes": (1usize << CAP_HEIGHT) * 32,
            "f2_opened_bytes": 16 * rom_width,
            "leaf_permutations_per_query": leaf, "input_paths_per_query": 1,
            "path_compressions_per_query": path, "query_count": cfg.num_queries,
            "leaf_permutations_total": leaf * cfg.num_queries,
            "path_compressions_total": path * cfg.num_queries,
            "fri_alpha_terms": rom_width, "dag_input_reads": rom_width},
        "layout_decided": false})
}

/// [P] F2b-2b-ii's input-opening component (`ood/open.rs`) at `queries`
/// covered queries, on the L2 lane: the lane perms each query costs, the
/// reduced-opening arithmetic, and the component's dense width, height,
/// periodic and public-value counts. `open.rs`'s tests pin this formula to
/// the toy instance they build; `input_openings_split_the_census` pins its
/// perm counts to the census geometry.
///
/// - Leaf perms per batch: row ‖ salt (`SALT_ELEMS`) per matrix, two words
///   per u64, 17 u64 per overwrite-sponge block. A multi-block leaf whose
///   last block is short carries tail lanes (one periodic role column).
/// - Compressions: `lde - CAP_HEIGHT` per batch, three batches.
/// - Reduced opening, per query: one `alpha^k * p(x)` extension-by-base
///   product per opened term, `lde` base products for x, two inverse checks
///   and two extension products for ro; per instance: the alpha powers and
///   the z-sums (`terms - 1` and `terms` extension products).
/// - Columns: Keccak, 1,088 message bits (no S bits: the sponge
///   overwrites), 68 canonicity, 8 accumulator, the query registers
///   (2 lde + 24) and the held cells (16 + 8 terms + 4 queries). The held
///   alpha-power and z-value tables are 8 terms wide and dominate at L2
///   widths.
pub(super) fn input_openings(
    width: usize,
    log_height: usize,
    chunks: usize,
    queries: usize,
) -> Value {
    let lde = lde_log(log_height);
    let path = lde - CAP_HEIGHT;
    let (mut leaf, mut roles, mut carries) = (vec![], 0, 0);
    for (mats, cols) in [(1, 4), (1, width), (chunks, 4)] {
        let u64s = (mats * (cols + SALT_ELEMS)).div_ceil(2);
        let blocks = u64s.div_ceil(17);
        leaf.push(blocks);
        roles += blocks;
        if blocks > 1 && !u64s.is_multiple_of(17) {
            carries += 1;
        }
    }
    let leaf_total: usize = leaf.iter().sum();
    let per_query = leaf_total + 3 * path;
    let terms = 4 + 2 * width + 4 * chunks;
    let rows = queries * per_query * 24;
    let (ctx, held) = (2 * lde + 24, 16 + 8 * terms + 4 * queries);
    let columns = NUM_KECCAK_COLS + 64 * 17 + 2 * 34 + 8 + ctx + held;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    json!({"evidence": "P", "source": "F2b-2b-ii layout (ood/open.rs), source-derived; toy pinned by its tests",
        "queries": queries, "lde_log_height": lde, "path_levels": path,
        "leaf_permutations_per_query": {"randomizer": leaf[0], "trace": leaf[1], "quotient": leaf[2]},
        "leaf_permutations_per_query_total": leaf_total,
        "path_compressions_per_query": 3 * path,
        "permutations_per_query": per_query,
        "leaf_permutations_total": leaf_total * queries,
        "path_compressions_total": 3 * path * queries,
        "lane_rows": rows, "padded_rows": rows.next_power_of_two(),
        "reduced_opening_per_query": {"opened_terms": terms, "ext_by_base_mul": terms,
            "x_chain_base_mul": lde, "ext_inverse_checks": 2, "ext_mul": 4},
        "reduced_opening_per_instance": {"alpha_power_ext_mul": terms - 1, "z_sum_ext_mul": terms},
        "component_columns": columns,
        "column_split": {"keccak": NUM_KECCAK_COLS, "message_bits": 64 * 17, "canonical": 2 * 34,
            "accumulator": 8, "query_registers": ctx, "held": held},
        "periodic_columns": 4 + roles + carries + path + 3 + queries,
        "public_values": 6 * cap_words + 4 + 4 * terms + 4 + queries + 4 * queries,
        "complete_verifier_layout": false, "memory_gate_pass": false})
}

/// [P] F2b-2b-iii's query-phase component (`ood/fold.rs`) at `queries`
/// covered queries, on the L2 lane: per round, the commit-phase leaf perms
/// and path compressions each query costs, the fold arithmetic, and the
/// component's dense width, height, periodic and public-value counts.
/// `fold.rs`'s honest test pins this formula to the toy instance it builds;
/// `query_phase_splits_the_census` pins the perm counts to the census's FRI
/// share.
///
/// - Leaf perms per round: the arity-n group as 4n base limbs ‖ salt
///   (`SALT_ELEMS`), two words per u64, 17 u64 per overwrite block (a
///   multi-block leaf with a short last block carries tail lanes: one
///   periodic role column).
/// - Compressions: folded log-height − `CAP_HEIGHT` per round.
/// - Fold, per round: u = beta * s^-1 (one ext-by-base product), n − 2
///   extension products for u^2..u^{n-1}, n − 1 for sum d_k u^k, the
///   inverse-DFT combinations d_k (n^2 ext-by-constant terms, linear), n
///   ext-by-base products for the position select, and one base product per
///   s^-1 chain bit. NO inverse witness: 1/n and s^-1 are constants or
///   constant-factor chains driven by the index bits.
/// - Final: `log_blowup + log_final_poly_len` base products for x, and
///   `final_len − 1` Horner steps (ext-by-base product + add).
/// - Columns: Keccak, 1,088 message bits, 68 canonicity, the query
///   registers (index bits, 12 cap one-hot, per round 4n group + 2n − 2
///   position + h s^-1 + 4(n − 1) powers; 4(R + 1) running values; the
///   final x chain; 4·final_len Horner cells) and the held betas and final
///   polynomial.
pub(super) fn query_phase(log_height: usize, queries: usize) -> Value {
    let cfg = F2_LANE;
    let lde = lde_log(log_height);
    let arities = fri_log_arities(lde, &cfg);
    let final_bits = cfg.log_blowup + cfg.log_final_poly_len;
    let final_len = 1usize << cfg.log_final_poly_len;
    let (mut leaf, mut comp, mut carries, mut regs) = (0, 0, 0, 0);
    let (mut ext_mul, mut ext_by_base, mut chain_mul) = (0, 0, 0);
    let mut rounds = vec![];
    let mut height = lde;
    for &a in &arities {
        let n = 1usize << a;
        let folded = height - a;
        let path = folded - CAP_HEIGHT;
        let u64s = (4 * n + SALT_ELEMS).div_ceil(2);
        let blocks = u64s.div_ceil(17);
        if blocks > 1 && !u64s.is_multiple_of(17) {
            carries += 1;
        }
        leaf += blocks;
        comp += path;
        regs += 4 * n + (2 * n - 2) + folded + 4 * (n - 1);
        ext_mul += (n - 2) + (n - 1);
        ext_by_base += 1 + n;
        chain_mul += folded;
        rounds.push(json!({"log_arity": a, "folded_log_height": folded,
            "leaf_permutations": blocks, "path_compressions": path}));
        height = folded;
    }
    let r = arities.len();
    regs += lde + 12 + 4 * (r + 1) + final_bits + 4 * final_len;
    let held = 4 * r + 4 * final_len;
    let per_query = leaf + comp;
    let lane_rows = queries * per_query * 24;
    let columns = NUM_KECCAK_COLS + 64 * 17 + 2 * 34 + regs + held;
    let path0 = lde - arities[0] - CAP_HEIGHT;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    json!({"evidence": "P", "source": "F2b-2b-iii layout (ood/fold.rs), source-derived; toy pinned by its tests",
        "queries": queries, "lde_log_height": lde, "fri_log_arities": arities, "rounds": rounds,
        "final_log_height": final_bits, "final_poly_len": final_len,
        "leaf_permutations_per_query": leaf, "path_compressions_per_query": comp,
        "permutations_per_query": per_query,
        "leaf_permutations_total": leaf * queries, "path_compressions_total": comp * queries,
        "lane_rows": lane_rows, "padded_rows": lane_rows.next_power_of_two(),
        "fold_per_query": {"ext_mul": ext_mul, "ext_by_base_mul": ext_by_base,
            "s_inverse_chain_base_mul": chain_mul, "final_x_base_mul": final_bits,
            "horner_ext_by_base_mul": final_len - 1, "inverse_witnesses": 0},
        "component_columns": columns,
        "column_split": {"keccak": NUM_KECCAK_COLS, "message_bits": 64 * 17, "canonical": 2 * 34,
            "query_registers": regs, "held": held},
        "periodic_columns": 4 + leaf + carries + path0 + r + queries,
        "public_values": 2 * cap_words * r + 4 * r + 4 * final_len + queries + 4 * queries,
        "complete_verifier_layout": false, "memory_gate_pass": false})
}

/// The register machine's dimensions (`ood::machine_dims` for a shape, the
/// toy's own in C1's honest test).
pub(super) struct MachineDims {
    /// Main columns: 12 + 4 · registers.
    pub(super) width: usize,
    /// Full-period ROM columns: 12 + 3 · registers + inputs.
    pub(super) rom_width: usize,
    /// Input extension values (one held 4-limb cell each).
    pub(super) inputs: usize,
    /// Padded rows of the schedule.
    pub(super) height: usize,
}

/// Main columns C1's lever L1 adds (`ood/c1.rs`): nine running powers q_j,
/// T = q_8 · fri_alpha, the point-masked copies pA_j and pB_j (4 limbs each),
/// two step-0 parity gates, and the Az and Bz accumulators.
const C1_L1_COLUMNS: usize = 4 * 9 * 3 + 4 + 2 + 2 * 4;

/// [P] F2b composition slice C1 (`ood/c1.rs`): 2a's transcript-bound
/// machine and 2b-i's FRI transcript on ONE duplex Keccak lane, with the
/// Az/Bz accumulation (L1). Source-derived; C1's honest test pins this
/// formula to the toy instance it builds, and `composed_c1_pins_the_census`
/// pins the lane to the census's challenger count.
///
/// - Lane perms: every challenger flush of the hiding transcript (F0, F1, F2,
///   one G per commit round, H, and a refill per query window after the
///   first), plus one final refill whose first block carries the last
///   window's digest bits: the census's `challenger_permutations_floor` + 1.
/// - Columns: Keccak, M and S bits (duplex), 68 canonicity, 72 draw, one
///   perm-ring column per lane perm (the scheduling that replaces 2a/2b-i's
///   full-period step-0 selectors), L1, the held fri_alpha, 4 per machine
///   input, the machine's registers.
/// - Periodic: the machine ROM only, full period (L5 deferred). Its cost to
///   the verifier of this proof is one Horner evaluation per column at ζ,
///   `rom_columns × padded_rows` extension multiplies; the sponge selectors
///   the ring replaced would have added `(perms + 2) × padded_rows`.
/// - Public values: the inner PVs and every cap (trace, quotient,
///   randomizer, commit rounds; 16-bit limbs), then the seam outputs ζ,
///   fri_alpha, Az, Bz, every β, the final polynomial and the query indices.
pub(super) fn composed_c1_layout(
    width: usize,
    pv_len: usize,
    log_height: usize,
    chunks: usize,
    m: &MachineDims,
) -> Value {
    let cfg = F2_LANE;
    let lde = lde_log(log_height);
    let arities = fri_log_arities(lde, &cfg);
    let rounds = arities.len();
    let final_len = 1usize << cfg.log_final_poly_len;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    let terms = 4 + 2 * width + 4 * chunks;
    // pad10*1 always adds at least one byte: words / 34 + 1 blocks.
    let blocks = |words: usize| words / 34 + 1;
    let windows = (cfg.num_queries + 1).div_ceil(8);
    let (f0, f1, f2) = (
        blocks(3 + cap_words + pv_len),
        blocks(8 + 2 * cap_words),
        blocks(8 + 4 * terms),
    );
    let (g, h) = (
        rounds * blocks(8 + cap_words),
        blocks(8 + 4 * final_len + rounds + 1),
    );
    let perms = f0 + f1 + f2 + g + h + windows;
    let lane_rows = 24 * perms;
    let rows = lane_rows.next_power_of_two().max(m.height);
    let lane = NUM_KECCAK_COLS + 2 * 64 * 17 + 2 * 34 + 8 * 9;
    let columns = lane + perms + C1_L1_COLUMNS + 4 + 4 * m.inputs + m.width;
    let outputs = 16 + 4 * rounds + 4 * final_len + cfg.num_queries;
    json!({"evidence": "P", "source": "F2b composition C1 layout (ood/c1.rs), source-derived; toy pinned by its tests",
        "lane_permutations": perms, "challenger_permutations": perms - 1,
        "flush_blocks": {"f0": f0, "f1": f1, "f2_opened_values": f2, "commit_rounds": g,
            "final_poly_arities_pow": h, "query_windows": windows},
        "opened_terms": terms, "lane_rows": lane_rows, "machine_rows": m.height,
        "padded_rows": rows,
        "component_columns": columns,
        "column_split": {"keccak": NUM_KECCAK_COLS, "message_and_state_bits": 2 * 64 * 17,
            "canonical": 2 * 34, "draw": 8 * 9, "perm_ring": perms, "l1_accumulation": C1_L1_COLUMNS,
            "held_fri_alpha": 4, "machine_inputs": 4 * m.inputs, "machine": m.width},
        "periodic_columns": m.rom_width, "periodic_column_length": rows,
        "rom_ood_extension_mul": m.rom_width * rows,
        "replaced_sponge_selectors_ood_extension_mul": (perms + 2) * rows,
        "public_values": pv_len + (3 + rounds) * 2 * cap_words + outputs,
        "seam_outputs": outputs,
        "complete_verifier_layout": false, "memory_gate_pass": false})
}

/// [P] `composed_c1_layout` for a shape, its machine compiled from the
/// shape's live OOD DAG.
pub(super) fn composed_c1(shape: Shape) -> Result<Value, String> {
    let m = super::ood::machine_dims(shape)?;
    Ok(composed_c1_layout(
        shape.width(),
        shape.pv_len(),
        shape.log_height(),
        8,
        &m,
    ))
}

/// Held fri_alpha powers C2's lever L2 keeps (`ood/c2.rs`): α^1..α^34, one
/// per rate word, since a leaf block carries at most 34 row values.
const C2_POWER_TABLE: usize = 34;

/// [P] F2b composition slice C2 (`ood/c2.rs`): 2b-ii's input openings and
/// 2b-iii's query phase as per-query segments on ONE overwrite-mode Keccak
/// lane, with levers L2 (incremental fri_alpha powers) and L3 (ro and the
/// index bits handed off as registers). Source-derived; C2's honest tests
/// pin this formula to the toy instance and to a two-query S3 instance, and
/// `composed_c2_pins_the_census_and_the_plan` pins the lane to the census.
///
/// - Lane perms per query: 2b-ii's input leaves and 3 x (lde - CAP_HEIGHT)
///   input levels, then 2b-iii's commit-phase leaves and paths. At 43 queries
///   these are ALL of the census's leaf and path perms; C1 carries the
///   challenger's.
/// - Columns: Keccak, 1,088 message bits (no S bits), 68 canonicity, the
///   position ring (one per segment perm) and the query ring (one per query),
///   materialized last-row gates (one per index bit a path level reads, one
///   per cap check), the query registers (index bits and ro — the hand-off —,
///   12 cap one-hot, the x chain, two inverses, per round 4n group + 2n - 2
///   position + h s^-1 + 4(n - 1) powers, 4R running values, the final x
///   chain, 4·final_len Horner cells), six running extension cells (p, pn,
///   pw, blk, Ax, Bx) and the held seam values (ζ, α^1..α^34, α^w, Az, Bz,
///   every β, the final polynomial).
/// - Periodic: none. Scheduling is Keccak's step flags and the two rings.
/// - Public values: the seam (every cap, ζ, fri_alpha, Az, Bz, every β, the
///   final polynomial, the covered indices).
pub(super) fn composed_c2_layout(
    width: usize,
    log_height: usize,
    chunks: usize,
    queries: usize,
) -> Value {
    let cfg = F2_LANE;
    let lde = lde_log(log_height);
    let path = lde - CAP_HEIGHT;
    let blocks = |u64s: usize| u64s.div_ceil(17);
    let in_leaf: usize = [(1, 4), (1, width), (chunks, 4)]
        .iter()
        .map(|&(mats, cols)| blocks((mats * (cols + SALT_ELEMS)).div_ceil(2)))
        .sum();
    let in_comp = 3 * path;
    let arities = fri_log_arities(lde, &cfg);
    let rounds = arities.len();
    let final_bits = cfg.log_blowup + cfg.log_final_poly_len;
    let final_len = 1usize << cfg.log_final_poly_len;
    let (mut fri_leaf, mut fri_comp, mut round_regs) = (0, 0, 0);
    let mut height = lde;
    for &a in &arities {
        let n = 1usize << a;
        let folded = height - a;
        fri_leaf += blocks((4 * n + SALT_ELEMS).div_ceil(2));
        fri_comp += folded - CAP_HEIGHT;
        round_regs += 4 * n + (2 * n - 2) + folded + 4 * (n - 1);
        height = folded;
    }
    let per_query = in_leaf + in_comp + fri_leaf + fri_comp;
    let lane_rows = queries * per_query * 24;
    let rings = per_query + queries;
    let gates = path + 3 + rounds;
    let handoff = lde + 4;
    let registers = handoff + 12 + lde + 8 + round_regs + 4 * rounds + final_bits + 4 * final_len;
    let running = 6 * 4;
    let held = 4 + 4 * C2_POWER_TABLE + 4 + 8 + 4 * rounds + 4 * final_len;
    let lane = NUM_KECCAK_COLS + 64 * 17 + 2 * 34;
    let columns = lane + rings + gates + registers + running + held;
    let terms = 4 + 2 * width + 4 * chunks;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    json!({"evidence": "P", "source": "F2b composition C2 layout (ood/c2.rs), source-derived; toy and two-query S3 pinned by its tests",
        "queries": queries, "lde_log_height": lde, "fri_log_arities": arities,
        "permutations_per_query": per_query,
        "per_query": {"input_leaf": in_leaf, "input_path": in_comp,
            "commit_leaf": fri_leaf, "commit_path": fri_comp},
        "leaf_permutations_total": (in_leaf + fri_leaf) * queries,
        "path_compressions_total": (in_comp + fri_comp) * queries,
        "lane_rows": lane_rows, "padded_rows": lane_rows.next_power_of_two(),
        "component_columns": columns,
        "column_split": {"keccak": NUM_KECCAK_COLS, "message_bits": 64 * 17, "canonical": 2 * 34,
            "position_and_query_rings": rings, "last_row_gates": gates,
            "query_registers": registers, "hand_off_registers": handoff,
            "running": running, "held": held},
        "periodic_columns": 0,
        "public_values": 2 * cap_words * (3 + rounds) + 16 + 4 * rounds + 4 * final_len + queries,
        "opened_terms": terms,
        "levers": {"l1_z_value_table_removed": 4 * terms, "l2_alpha_power_table_removed": 4 * terms,
            "l2_power_cells_added": 4 * C2_POWER_TABLE + 4 + 4 * 4,
            "l3_duplicate_index_and_one_hot_avoided": lde + 12},
        "complete_verifier_layout": false, "memory_gate_pass": false})
}

/// [P] `composed_c2_layout` for a shape, covering all queries.
pub(crate) fn composed_c2(shape: Shape) -> Value {
    composed_c2_layout(
        shape.width(),
        shape.log_height(),
        8,
        F2_LANE.num_queries,
    )
}

impl Geometry {
    pub(super) fn report(&self, shape: Shape) -> Value {
        let cfg = F2_LANE;
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
    fn input_openings_split_the_census() {
        // The input-batch share plus the FRI commit-phase share is the
        // census geometry's per-query count, for every shape; at S, 43
        // queries, that is the measured 1,419 leaf / 3,999 path perms.
        let cfg = F2_LANE;
        for (shape, leaf, comp, columns, periodic, pvs) in [
            (Shape::S, 25, 57, 15_877, 96, 6_519),
            (Shape::P, 27, 60, 17_111, 99, 7_135),
            (Shape::R, 25, 54, 16_083, 95, 6_623),
        ] {
            let g = geometry(shape, 8);
            let r = input_openings(shape.width(), shape.log_height(), 8, cfg.num_queries);
            let fri_leaf: usize = g
                .log_arities
                .iter()
                .map(|a| leaf_perms(4 * (1usize << a)))
                .sum();
            let fri_comp: usize = g.fri_paths.iter().sum();
            assert_eq!(r["leaf_permutations_per_query_total"], leaf);
            assert_eq!(r["path_compressions_per_query"], comp);
            assert_eq!(leaf + fri_leaf, g.leaf_per_query);
            assert_eq!(comp + fri_comp, g.compress_per_query);
            assert_eq!(r["component_columns"], columns);
            assert_eq!(r["periodic_columns"], periodic);
            assert_eq!(r["public_values"], pvs);
            assert_eq!(r["padded_rows"], 1 << 17);
            assert_eq!(r["reduced_opening_per_query"]["opened_terms"], g.ood);
        }
        let s = input_openings(Shape::S.width(), Shape::S.log_height(), 8, 43);
        assert_eq!(s["leaf_permutations_total"], 1075);
        assert_eq!(s["path_compressions_total"], 2451);
        assert_eq!(1075 + 43 * 8, 1419);
        assert_eq!(2451 + 43 * 36, 3999);
        assert_eq!(s["lane_rows"], 84_624);
    }

    #[test]
    fn query_phase_splits_the_census() {
        // The query phase's perms are the census geometry's FRI commit-phase
        // share, for every shape; with the input share they are the whole
        // per-query count. At S, 43 queries: the measured 344 leaf / 1,548
        // path perms (1,419 − 1,075 and 3,999 − 2,451).
        let cfg = F2_LANE;
        for (shape, leaf, comp, columns, periodic, pvs) in [
            (Shape::S, 8, 36, 4_657, 74, 807),
            (Shape::P, 9, 43, 4_690, 77, 939),
            (Shape::R, 8, 33, 4_573, 74, 807),
        ] {
            let g = geometry(shape, 8);
            let i = input_openings(shape.width(), shape.log_height(), 8, cfg.num_queries);
            let q = query_phase(shape.log_height(), cfg.num_queries);
            assert_eq!(q["fri_log_arities"], json!(g.log_arities));
            assert_eq!(q["leaf_permutations_per_query"], leaf);
            assert_eq!(q["path_compressions_per_query"], comp);
            assert_eq!(comp, g.fri_paths.iter().sum::<usize>());
            let input = |k: &str| i[k].as_u64().unwrap() as usize;
            assert_eq!(
                input("leaf_permutations_per_query_total") + leaf,
                g.leaf_per_query
            );
            assert_eq!(
                input("path_compressions_per_query") + comp,
                g.compress_per_query
            );
            assert_eq!(q["component_columns"], columns);
            assert_eq!(q["periodic_columns"], periodic);
            assert_eq!(q["public_values"], pvs);
            assert_eq!(q["padded_rows"], 1 << 16);
            assert_eq!(q["fold_per_query"]["inverse_witnesses"], 0);
        }
        let s = query_phase(Shape::S.log_height(), 43);
        assert_eq!(s["leaf_permutations_total"], 344);
        assert_eq!(s["path_compressions_total"], 1548);
        assert_eq!(1075 + 344, 1419);
        assert_eq!(2451 + 1548, 3999);
        assert_eq!(s["lane_rows"], 45_408);
    }

    #[test]
    fn composed_c1_pins_the_census() {
        // C1's lane is the whole challenger transcript plus one carrier
        // refill: at S3, the census's 206 challenger perms + 1. The machine
        // dimensions are F2b-0's (S3 1,216 x 2^15, ROM 2,227, 1,312 inputs).
        for (shape, perms, columns, rom, pvs) in [
            (Shape::S, 207, 11_746, 2_227, 1_151),
            (Shape::P, 228, 12_655, 2_593, 1_295),
            (Shape::R, 209, 12_040, 2_364, 1_136),
        ] {
            let g = geometry(shape, 8);
            let c = composed_c1(shape).unwrap();
            assert_eq!(c["challenger_permutations"], g.fs_floor);
            assert_eq!(c["lane_permutations"], perms);
            assert_eq!(c["component_columns"], columns);
            assert_eq!(c["periodic_columns"], rom);
            assert_eq!(c["public_values"], pvs);
            assert_eq!(c["padded_rows"], 1 << 15);
            assert_eq!(c["opened_terms"], g.ood);
            assert_eq!(c["seam_outputs"], 16 + 4 * g.log_arities.len() + 64 + 43);
        }
        let s = composed_c1(Shape::S).unwrap();
        assert_eq!(s["challenger_permutations"], 206);
        assert_eq!(s["lane_rows"], 207 * 24);
        assert_eq!(s["rom_ood_extension_mul"], 2_227 << 15);
        assert_eq!(s["replaced_sponge_selectors_ood_extension_mul"], 209 << 15);
    }

    #[test]
    fn composed_c2_pins_the_census_and_the_plan() {
        // C2's lane is every leaf and path perm of the census geometry (C1
        // carries the challenger's): at S3, 43 x (25 + 8) = 1,419 leaf and
        // 43 x (57 + 36) = 3,999 path perms. The plan: about 5.0k columns x
        // 2^17 at S3, 2^18 at P3; no periodic column.
        for (shape, per_query, columns, rows, pvs) in [
            (Shape::S, 126, 5_058, 1 << 17, 1_035),
            (Shape::P, 139, 5_107, 1 << 18, 1_167),
            (Shape::R, 120, 4_966, 1 << 17, 1_035),
        ] {
            let g = geometry(shape, 8);
            let c = composed_c2(shape);
            assert_eq!(
                c["leaf_permutations_total"],
                43 * g.leaf_per_query,
                "{shape:?}"
            );
            assert_eq!(c["path_compressions_total"], 43 * g.compress_per_query);
            assert_eq!(c["permutations_per_query"], per_query);
            assert_eq!(c["component_columns"], columns);
            assert_eq!(c["padded_rows"], rows);
            assert_eq!(c["periodic_columns"], 0);
            assert_eq!(c["public_values"], pvs);
            assert_eq!(c["opened_terms"], g.ood);
            // The seam is C1's export after its inner PVs.
            let c1 = composed_c1(shape).unwrap();
            assert_eq!(
                c1["public_values"].as_u64().unwrap() as usize - shape.pv_len(),
                pvs
            );
        }
        let s = composed_c2(Shape::S);
        assert_eq!(s["leaf_permutations_total"], 1_419);
        assert_eq!(s["path_compressions_total"], 3_999);
        assert_eq!(s["lane_rows"], 130_032);
        assert_eq!(s["levers"]["l2_alpha_power_table_removed"], 5_912);
        assert_eq!(s["levers"]["l1_z_value_table_removed"], 5_912);
    }

    #[test]
    fn rom_encoding_states_both_costs_from_one_geometry() {
        // 100 columns x 2^10 rows: lde 2^13 on the b4 hiding lane, cap 2^3.
        let r = rom_encoding(100, 10);
        assert_eq!(r["rom_rows"], 1024);
        assert_eq!(r["periodic"]["ood_extension_mul"], 102_400);
        assert_eq!(r["periodic"]["pcs_cost"], 0);
        let c = &r["committed_preprocessed"];
        assert_eq!(c["f2_opened_bytes"], 1600);
        assert_eq!(c["f0_cap_bytes"], 256);
        assert_eq!(c["leaf_permutations_per_query"], 4); // (100 + 4) / 34, rounded up
        assert_eq!(c["path_compressions_per_query"], 10);
        assert_eq!(c["leaf_permutations_total"], 4 * 43);
        assert_eq!(c["dag_input_reads"], 100);
        assert_eq!(r["layout_decided"], false);
        // Same formula as the shape geometry: a shape-height ROM has the
        // shape's input path.
        let g = geometry(Shape::S, 8);
        assert_eq!(
            rom_encoding(1, Shape::S.log_height())["committed_preprocessed"]
                ["path_compressions_per_query"],
            g.input_path
        );
    }

    #[test]
    fn live_air_census_pins_hiding_chunks_and_periodic_columns() {
        for (shape, count, periodic) in [
            (Shape::S, 1113, 40),
            (Shape::P, 1358, 40),
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
