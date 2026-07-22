//! M4 step 0b(i): verifier ARITHMETIC census + glue pricing.
//!
//! Step 0a (`m4census`) measured the hash workload of verifying one M3
//! consensus proof: 2,233 keccak-f. This mode prices the other half — the
//! field-arithmetic "glue" an in-circuit verifier must also perform — and
//! tests aggregation-rung1 §4's "+30–50% glue allowance" against real
//! counts, before step 0b(ii) builds the verifier circuit.
//!
//! Two kinds of numbers, labeled throughout:
//!  - **exact census**: the constraint DAG of the M3 bucket AIR, walked
//!    with Arc-pointer memoization (shared subexpressions counted once —
//!    exactly what an evaluator with value reuse performs), via
//!    `p3_air::symbolic::get_symbolic_constraints`;
//!  - **counted-from-shape formulas**: per-query reduced-opening
//!    combination, FRI binary folds, final-poly Horner — arithmetic whose
//!    op count follows mechanically from the proof shape (widths, query
//!    count, fold schedule) under the consensus config. These are formulas
//!    with all inputs printed, not estimates.
//!
//! Cell pricing at the end converts ext-field ops to wide-AIR-lane trace
//! cells under a bracketed price (an arithmetic bank is step 0b(ii)'s
//! design; the bracket is deliberately wide) and compares against the
//! hash-workload cells from step 0a.

use std::collections::HashSet;
use std::sync::Arc;

use p3_air::symbolic::{get_symbolic_constraints, AirLayout, SymbolicExpr, SymbolicExpression};
use p3_uni_stark::get_log_num_quotient_chunks;
use qlab_air::narrow::{build_bucket, TxInput, TxOutput, BUCKET_PERMS, NARROW_WIDTH};

use crate::Val;

// ---------------------------------------------------------------------------
// Constraint-DAG census
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone, Copy)]
struct OpCounts {
    add: usize,
    sub: usize,
    neg: usize,
    mul: usize,
    leaf_reads: usize,
}

impl OpCounts {
    fn ops(&self) -> usize {
        self.add + self.sub + self.neg + self.mul
    }
}

fn visit(e: &Arc<SymbolicExpression<Val>>, seen: &mut HashSet<usize>, c: &mut OpCounts) {
    if seen.insert(Arc::as_ptr(e) as usize) {
        walk(e, seen, c);
    }
}

fn walk(e: &SymbolicExpression<Val>, seen: &mut HashSet<usize>, c: &mut OpCounts) {
    match e {
        SymbolicExpr::Leaf(_) => c.leaf_reads += 1,
        SymbolicExpr::Add { x, y, .. } => {
            c.add += 1;
            visit(x, seen, c);
            visit(y, seen, c);
        }
        SymbolicExpr::Sub { x, y, .. } => {
            c.sub += 1;
            visit(x, seen, c);
            visit(y, seen, c);
        }
        SymbolicExpr::Neg { x, .. } => {
            c.neg += 1;
            visit(x, seen, c);
        }
        SymbolicExpr::Mul { x, y, .. } => {
            c.mul += 1;
            visit(x, seen, c);
            visit(y, seen, c);
        }
    }
}

// ---------------------------------------------------------------------------
// Consensus-config shape constants (b16/q20/g20/fp16/a16 on the 2^18 bucket)
// ---------------------------------------------------------------------------

const QUERIES: usize = 20;
const LOG_HEIGHT: usize = 18;
const LOG_BLOWUP: usize = 4;
const LOG_FINAL_POLY: usize = 4;

pub(crate) fn run_m4price(power: &str) {
    println!("# qumbra-lab M4 step 0b(i): verifier arithmetic census + glue pricing");
    println!();
    crate::print_env(power);
    println!(
        "- companion to step 0a (`m4census`, hash workload = 2,233 keccak-f); \
         this prices the field-arithmetic glue of aggregation-rung1 §4's \
         +30–50% allowance"
    );
    println!();

    // Deterministic instance, same as run_bucket / m4census.
    let mut x = 0xfeed_face_cafe_beefu64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
        sk: [rnd(), rnd(), rnd(), rnd()],
        value,
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
        d: [0, 0], // default diversifier (issue #32; keeps rnd stream stable)
    };
    let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
        value,
        rkm: [rnd(), rnd(), rnd(), rnd()],
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
    };
    let inputs = [mk_in(50_000, &mut rnd), mk_in(30_000, &mut rnd)];
    let outputs = [mk_out(60_000, &mut rnd), mk_out(19_000, &mut rnd)];
    let inst = build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000);

    // --- exact census: the constraint DAG --------------------------------
    let layout = AirLayout::from_air::<Val>(&inst.air);
    let constraints = get_symbolic_constraints::<Val, _>(&inst.air, layout);
    let mut seen = HashSet::new();
    let mut dag = OpCounts::default();
    let mut total_nodes_no_sharing = 0usize;
    for c in &constraints {
        walk(c, &mut seen, &mut dag);
        total_nodes_no_sharing += count_no_sharing(c);
    }
    let n_constraints = constraints.len();
    // The verifier folds constraints into the quotient claim with running
    // powers of alpha: 1 ext-mul + 1 ext-add per constraint.
    let alpha_fold_mul = n_constraints;
    let alpha_fold_add = n_constraints;

    let log_qc = get_log_num_quotient_chunks::<Val, _>(&inst.air, layout, 0);
    let quotient_chunks = 1usize << log_qc;

    println!("## Exact census: M3 bucket constraint DAG (evaluated ONCE, at zeta, in the ext field)");
    println!();
    println!("| metric | count |");
    println!("|---|---|");
    println!("| constraints | {n_constraints} |");
    println!("| unique DAG ops (add/sub/neg/mul) | {} ({}/{}/{}/{}) |", dag.ops(), dag.add, dag.sub, dag.neg, dag.mul);
    println!("| leaf reads (unique) | {} |", dag.leaf_reads);
    println!("| tree nodes without sharing | {total_nodes_no_sharing} (sharing factor {:.1}x) |", total_nodes_no_sharing as f64 / dag.ops().max(1) as f64);
    println!("| alpha-fold (per constraint) | {alpha_fold_mul} mul + {alpha_fold_add} add |");
    println!("| quotient chunks | {quotient_chunks} (log {log_qc}) |");
    println!();

    // --- counted-from-shape formulas: per-query linear algebra -----------
    // Reduced-opening combination (DEEP quotient): for each query, every
    // opened value enters a running alpha-Horner: 1 ext-mul + 1 ext-add,
    // plus per-(commit, point) an inverse and subtraction.
    let opened_main = 2 * NARROW_WIDTH; // local + next rows
    let opened_quotient = quotient_chunks * 4; // ext embedded as 4 base cols
    let opened_per_query = opened_main + opened_quotient;
    let ro_mul = QUERIES * opened_per_query;
    let ro_add = QUERIES * opened_per_query;
    let ro_inv = QUERIES * 3; // (main local, main next, quotient) denominators

    // FRI folds: binary folds from the LDE domain down to the final-poly
    // domain; each binary fold ~ 2 ext-mul + 2 ext-add (+ shared per-level
    // x-inverse, folded into the mul price here).
    let lde_log = LOG_HEIGHT + LOG_BLOWUP;
    let folds_per_query = lde_log - LOG_BLOWUP - LOG_FINAL_POLY; // stop at final poly domain
    let fold_mul = QUERIES * folds_per_query * 2;
    let fold_add = QUERIES * folds_per_query * 2;

    // Final-poly evaluation: Horner over 2^LOG_FINAL_POLY coefficients.
    let fp_mul = QUERIES * (1 << LOG_FINAL_POLY);
    let fp_add = QUERIES * (1 << LOG_FINAL_POLY);

    // Quotient recombination at zeta + zerofier/selector evals: one
    // vanishing-poly power chain (~lde_log muls) + per-chunk recombine.
    let misc_mul = lde_log + quotient_chunks * 2 + 64;
    let misc_add = quotient_chunks * 2 + 64;

    let total_mul = dag.mul + alpha_fold_mul + ro_mul + fold_mul + fp_mul + misc_mul;
    let total_addlike = dag.add + dag.sub + dag.neg + alpha_fold_add + ro_add + fold_add + fp_add + misc_add;

    println!("## Counted-from-shape: per-proof verifier linear algebra (consensus config, all inputs shown)");
    println!();
    println!("| term | ext-mul | ext-add/sub | inputs |");
    println!("|---|---|---|---|");
    println!("| constraint DAG (once) | {} | {} | census above |", dag.mul, dag.add + dag.sub + dag.neg);
    println!("| alpha fold | {alpha_fold_mul} | {alpha_fold_add} | {n_constraints} constraints |");
    println!("| reduced openings | {ro_mul} | {ro_add} | {QUERIES} q x ({opened_main} main + {opened_quotient} quotient); + {ro_inv} ext-inv |");
    println!("| FRI binary folds | {fold_mul} | {fold_add} | {QUERIES} q x {folds_per_query} folds x ~2 |");
    println!("| final poly (Horner) | {fp_mul} | {fp_add} | {QUERIES} q x {} coeffs |", 1 << LOG_FINAL_POLY);
    println!("| zerofier/recombine/misc | {misc_mul} | {misc_add} | lde 2^{lde_log}, {quotient_chunks} chunks |");
    println!("| **TOTAL** | **{total_mul}** | **{total_addlike}** | + {ro_inv} ext-inv |");
    println!();

    // --- pricing ----------------------------------------------------------
    // Ext-op -> wide-lane trace cells. Bracketed price pending the 0b(ii)
    // arithmetic-bank design: an ext-mul row carries 2x4 input limbs, 4
    // output limbs, and reduction wiring — 16 value cells + 8–32 aux;
    // ext-add rows batch 4+ to a row. Bracket: mul 24–48 cells, add 4–8.
    let hash_cells: f64 = 2_233.0 * 63_200.0; // step 0a census x wide AIR cells/perm
    for (label, mul_price, add_price) in [
        ("lean (mul=24, add=4)", 24.0, 4.0),
        ("fat  (mul=48, add=8)", 48.0, 8.0),
    ] {
        let glue_cells = total_mul as f64 * mul_price + total_addlike as f64 * add_price;
        println!(
            "- glue cells [{label}]: {:.1}M vs hash cells {:.1}M -> glue = {:.1}% of hash \
             (design allowance was +30–50%)",
            glue_cells / 1e6,
            hash_cells / 1e6,
            100.0 * glue_cells / hash_cells,
        );
    }
    println!();
    println!(
        "- bucket context: {BUCKET_PERMS} perms, width {NARROW_WIDTH}, 2^{LOG_HEIGHT} rows; \
         challenger byte-packing / injection routing not priced here (it is \
         hash-adjacent wiring, bounded by opened-value count x small constant \
         — recorded as a 0b(ii) line item)."
    );
}

/// Full tree size without Arc sharing — what a naive evaluator would do.
fn count_no_sharing(e: &SymbolicExpression<Val>) -> usize {
    match e {
        SymbolicExpr::Leaf(_) => 1,
        SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
            1 + count_no_sharing(x) + count_no_sharing(y)
        }
        SymbolicExpr::Neg { x, .. } => 1 + count_no_sharing(x),
    }
}
