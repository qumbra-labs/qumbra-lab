//! Lab #767 F3-2c — the leaf's prove mode and the interior census.
//!
//! - **`qlab-bench f3leaf --prove --outer b2|b4 [--k N | --shapes PSR…]`**:
//!   build an honest leaf of `k` transactions, scan it (p3's row loop), prove
//!   it under the NON-hiding outer config (`qlab_consensus::legacy`, the M4
//!   interior's lanes `INTERIOR_B2_CFG` / `INTERIOR_B4_CFG` — the #767
//!   stage-0: every value the leaf touches is public, so no hiding), verify
//!   natively, report JSON. Peak memory is the operator's `/usr/bin/time`
//!   reading; the report carries F2's k-model [P] beside it.
//! - **`qlab-bench f3census --interior`**: the ruling's Q3 census — what an
//!   interior verifying two state-leaf proofs would carry, per outer lane and
//!   `k`: the leaf proof's geometry, its opened values, the challenger's and
//!   the query phase's Keccak perms, and a C2-class query-component layout
//!   (F2's `price::composed_c2_layout` formula at the outer config, without
//!   hiding: no randomizer matrix, no salts). Every figure **[P]**,
//!   source-derived; the OOD evaluation is reported as the leaf AIR's
//!   symbolic DAG — F2's OOD machine compiler is hiding-only, so no machine
//!   is compiled for this AIR.
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SymbolicExpression};
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove, verify};
use qlab_consensus::legacy::make_legacy_config_with;
use qlab_consensus::{FriCfg, Val, CAP_HEIGHT};
use qlab_devnet::annulet::L2ShapeTag;
use serde_json::{json, Value};

use super::census::{row, K_B2, K_B4};
use super::leaf::{first_violation, LeafAir, LEAF_PV_LEN, LEAF_WIDTH};
use super::neg::{fixture, honest, SEED};

// Lab #785 F5-1: the outer-lane enum moved to qlab-wrapper; its k-model
// constant stays a bench fact.
pub(crate) use qlab_wrapper::config::Outer;

/// The k-model memory constant for `outer` (was `Outer::k_model`).
pub(crate) fn k_model(outer: Outer) -> f64 {
    match outer {
        Outer::B2 => K_B2,
        Outer::B4 => K_B4,
    }
}

/// A `k`-leaf's shapes when none are given: P and S alternating, the one
/// allowed R at position 1 (k ≥ 2) — every segment kind is exercised.
pub(crate) fn default_shapes(k: usize) -> Vec<L2ShapeTag> {
    (0..k)
        .map(|i| match i {
            1 => L2ShapeTag::R,
            i if i % 2 == 0 => L2ShapeTag::P,
            _ => L2ShapeTag::S,
        })
        .collect()
}

/// Parse `--shapes PSR…`, or `--k N` for [`default_shapes`].
pub(crate) fn shapes_arg(args: &[String]) -> Result<Vec<L2ShapeTag>, String> {
    let get = |key: &str| args.iter().position(|a| a == key).and_then(|i| args.get(i + 1));
    match (get("--shapes"), get("--k")) {
        (Some(_), Some(_)) => Err("give --shapes or --k, not both".into()),
        (Some(s), None) if s.is_empty() => Err("--shapes needs at least one shape".into()),
        (Some(s), None) => s
            .chars()
            .map(|c| match c {
                'S' => Ok(L2ShapeTag::S),
                'P' => Ok(L2ShapeTag::P),
                'R' => Ok(L2ShapeTag::R),
                other => Err(format!("unknown shape {other}")),
            })
            .collect(),
        (None, Some(k)) => match k.parse::<usize>() {
            Ok(0) => Err("--k must be at least 1".into()),
            Ok(k) => Ok(default_shapes(k)),
            Err(_) => Err("--k takes a count".into()),
        },
        (None, None) => Ok(vec![L2ShapeTag::P]),
    }
}

/// The leaf's quotient chunks on a non-hiding config (degree 3: two).
pub(crate) fn quotient_chunks(air: &LeafAir) -> usize {
    1 << get_log_num_quotient_chunks::<Val, _>(air, AirLayout::from_air::<Val>(air), 0)
}

/// `f3leaf --prove`: one honest leaf, proven and verified.
pub(crate) fn prove_run(args: &[String]) -> Result<(), String> {
    let outer = Outer::parse(
        args.iter().position(|a| a == "--outer").and_then(|i| args.get(i + 1)).ok_or("--prove needs --outer b2|b4")?,
    )?;
    let shapes = shapes_arg(args)?;
    let k = shapes.len();
    let t = Instant::now();
    let fx = fixture(&shapes, SEED);
    let (air, trace, pvs) = honest(&fx);
    let gen_s = t.elapsed().as_secs_f64();
    let (w, h) = (trace.width(), trace.height());
    let t = Instant::now();
    let scan = first_violation(&air, &trace, &pvs);
    let scan_s = t.elapsed().as_secs_f64();
    if let Some((r, ph)) = &scan {
        return Err(format!("the honest leaf does not hold at row {r}: {ph:?} — not proving"));
    }
    let layout = AirLayout::from_air::<Val>(&air);
    let constraints = get_symbolic_constraints::<Val, _>(&air, layout).len();
    let degree = get_max_constraint_degree::<Val, _>(&air, layout);
    let chunks = quotient_chunks(&air);
    let config = make_legacy_config_with(&outer.cfg());
    let t = Instant::now();
    let proof = prove(&config, &air, trace, &pvs);
    let prove_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let verified = verify(&config, &air, &proof, &pvs);
    let verify_s = t.elapsed().as_secs_f64();
    let bytes = bincode::serialize(&proof).map(|b| b.len()).ok();
    let scale = w as f64 * 2f64.powi(h.trailing_zeros() as i32 - 18);
    let report = json!({
        "mode": "f3leaf --prove", "issue": 767, "k": k,
        "shapes": shapes.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>(),
        "outer_lane": outer.label(), "outer_pcs": "non-hiding (qlab_consensus::legacy)",
        "built": {"evidence": "M", "width": w, "height": h, "log_height": h.trailing_zeros(),
            "public_values": LEAF_PV_LEN, "constraints": constraints, "max_degree": degree, "quotient_chunks": chunks},
        "honest_scan": {"evidence": "M", "every_row_holds": true, "seconds": scan_s},
        "trace_gen_seconds": {"evidence": "M", "value": gen_s},
        "prove_seconds": {"evidence": "M", "value": prove_s},
        "verify_seconds": {"evidence": "M", "value": verify_s},
        "proof_bytes": {"evidence": "M", "source": "bincode::serialize", "value": bytes},
        "native_verified": verified.is_ok(),
        "verify_error": verified.err().map(|e| format!("{e:?}")),
        "expected_peak_gib": {"evidence": "P", "source": "F2's k-model, peak ≈ K × width × 2^(h−18), a planning model",
            "value": (k_model(outer) * scale * 100.0).round() / 100.0},
        "peak_rss": {"evidence": "M", "value": null, "operator_records": "maximum resident set size from /usr/bin/time wrapping this process"},
    });
    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
    if report["native_verified"] != true {
        return Err("the proof does not verify".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The interior census [P]
// ---------------------------------------------------------------------------

/// p3-fri 0.6.1's fold schedule with every input at one LDE height (F2's
/// `price::fri_log_arities`).
pub(crate) fn fri_log_arities(lde_log: usize, cfg: &FriCfg) -> Vec<usize> {
    let mut remaining = lde_log - cfg.log_blowup - cfg.log_final_poly_len;
    let mut v = vec![];
    while remaining > 0 {
        let a = remaining.min(cfg.max_log_arity);
        remaining -= a;
        v.push(a);
    }
    v
}

/// One state-leaf proof's verification, counted [P].
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LeafVerify {
    pub log_height: usize,
    pub lde: usize,
    pub chunks: usize,
    pub arities: Vec<usize>,
    pub queries: usize,
    /// Extension elements the proof opens: the trace at ζ and ζ·g, each
    /// quotient chunk's four base polynomials at ζ.
    pub opened_ext: usize,
    /// The challenger's Keccak perms (C1-class).
    pub challenger_perms: usize,
    /// Keccak perms one query costs (C2-class): leaves and paths.
    pub per_query_perms: usize,
    /// The C2-class query component's columns.
    pub query_columns: usize,
}

/// Count one leaf proof's verification at `outer` for a leaf of `log_height`
/// rows. Source: F2's `price::composed_c1_layout` (flush blocks) and
/// `composed_c2_layout` (per-query perms and columns), at `outer`'s config
/// and **without hiding**: one quotient cap observed (no randomizer), two
/// input matrices per query (trace, quotient), no salts, two cap checks.
pub(crate) fn leaf_verify(log_height: usize, chunks: usize, outer: Outer) -> LeafVerify {
    let cfg = outer.cfg();
    let lde = log_height + cfg.log_blowup;
    let arities = fri_log_arities(lde, &cfg);
    let rounds = arities.len();
    let final_len = 1usize << cfg.log_final_poly_len;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    let terms = 2 * LEAF_WIDTH + 4 * chunks;
    // Challenger: pad10*1 over 34-word blocks, one flush per observation.
    let flush = |words: usize| words / 34 + 1;
    let windows = (cfg.num_queries + 1).div_ceil(8);
    let challenger = flush(3 + cap_words + LEAF_PV_LEN)
        + flush(8 + cap_words)
        + flush(8 + 4 * terms)
        + rounds * flush(8 + cap_words)
        + flush(8 + 4 * final_len + rounds + 1)
        + windows;
    // Query phase: overwrite-mode leaves over 17 u64 lanes a perm.
    let blocks = |u64s: usize| u64s.div_ceil(17);
    let path = lde - CAP_HEIGHT;
    let in_leaf = blocks(LEAF_WIDTH.div_ceil(2)) + blocks((4 * chunks).div_ceil(2));
    let in_comp = 2 * path;
    let (mut fri_leaf, mut fri_comp, mut round_regs) = (0, 0, 0);
    let mut height = lde;
    for &a in &arities {
        let n = 1usize << a;
        let folded = height - a;
        fri_leaf += blocks((4 * n).div_ceil(2));
        fri_comp += folded - CAP_HEIGHT;
        round_regs += 4 * n + (2 * n - 2) + folded + 4 * (n - 1);
        height = folded;
    }
    let per_query = in_leaf + in_comp + fri_leaf + fri_comp;
    let final_bits = cfg.log_blowup + cfg.log_final_poly_len;
    let lane = p3_keccak_air::NUM_KECCAK_COLS + 64 * 17 + 2 * 34;
    let rings = per_query + cfg.num_queries;
    let gates = path + 2 + rounds;
    let registers = (lde + 4) + 12 + lde + 8 + round_regs + 4 * rounds + final_bits + 4 * final_len;
    let held = 4 + 4 * 34 + 4 + 8 + 4 * rounds + 4 * final_len;
    LeafVerify {
        log_height,
        lde,
        chunks,
        arities,
        queries: cfg.num_queries,
        opened_ext: terms,
        challenger_perms: challenger,
        per_query_perms: per_query,
        query_columns: lane + rings + gates + registers + 6 * 4 + held,
    }
}

/// The leaf AIR's symbolic DAG: constraints and operations (pointer-shared,
/// F2's `price::air_report` walk) — the OOD evaluation an interior repeats
/// per child.
pub(crate) fn ood_dag(air: &LeafAir) -> (usize, [usize; 4]) {
    fn walk(e: &SymbolicExpression<Val>, seen: &mut HashSet<usize>, ops: &mut [usize; 4]) {
        use p3_air::symbolic::SymbolicExpr::*;
        match e {
            Leaf(_) => {}
            Add { x, y, .. } | Sub { x, y, .. } | Mul { x, y, .. } => {
                ops[match e {
                    Add { .. } => 0,
                    Sub { .. } => 1,
                    _ => 2,
                }] += 1;
                visit(x, seen, ops);
                visit(y, seen, ops);
            }
            Neg { x, .. } => {
                ops[3] += 1;
                visit(x, seen, ops);
            }
        }
    }
    fn visit(e: &Arc<SymbolicExpression<Val>>, seen: &mut HashSet<usize>, ops: &mut [usize; 4]) {
        if seen.insert(Arc::as_ptr(e) as usize) {
            walk(e, seen, ops);
        }
    }
    let cs = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
    let (mut seen, mut ops) = (HashSet::new(), [0; 4]);
    for c in &cs {
        walk(c, &mut seen, &mut ops);
    }
    (cs.len(), ops)
}

/// `f3census --interior`: two state-leaf proofs per interior, k ∈ {4, 8, 16},
/// both outer lanes.
pub(crate) fn interior_report() -> Value {
    let air = LeafAir::new(1);
    let chunks = quotient_chunks(&air);
    let (constraints, ops) = ood_dag(&air);
    let mut rows = Vec::new();
    for outer in [Outer::B2, Outer::B4] {
        for k in [4, 8, 16] {
            let lh = row(k).log_h as usize;
            let v = leaf_verify(lh, chunks, outer);
            let perms = 2 * (v.challenger_perms + v.queries * v.per_query_perms);
            let q_rows = (24 * v.queries * v.per_query_perms).next_power_of_two();
            let gib = |cols: usize, rows: usize| {
                (k_model(outer) * cols as f64 * 2f64.powi(rows.trailing_zeros() as i32 - 18) * 10.0).round() / 10.0
            };
            rows.push(json!({
                "outer": outer.label(), "k": k, "leaf_log_height": lh, "leaf_lde": v.lde,
                "fri_log_arities": v.arities, "queries": v.queries,
                "opened_ext_elements_per_leaf": v.opened_ext,
                "challenger_perms_per_leaf": v.challenger_perms,
                "perms_per_query": v.per_query_perms,
                "interior_keccak_perms_two_leaves": perms,
                "query_component_per_leaf": {"columns": v.query_columns, "padded_rows": q_rows,
                    "k_model_gib_same_lane": gib(v.query_columns, q_rows)},
            }));
        }
    }
    json!({"evidence": "P", "issue": 767, "ruling": "Q3: the interior over state leaves, census only",
        "leaf": {"width": LEAF_WIDTH, "public_values": LEAF_PV_LEN, "quotient_chunks_non_hiding": chunks,
            "ood_dag": {"constraints": constraints, "add": ops[0], "sub": ops[1], "mul": ops[2], "neg": ops[3]}},
        "chain": "root_out(L) = root_in(R) for N, n_next, C, c_next, R and SD_out(L) = SD_in(R): 68 PV-chunk equalities, no perms",
        "source": "F2 price::composed_c1_layout flush blocks and composed_c2_layout, at the outer config, non-hiding (no randomizer, no salts, two input matrices)",
        "not_counted": ["the OOD register machine (F2's compiler is hiding-only; the DAG above is its input)",
            "C1-class column layout", "the interior's own public values and its outer proof"],
        "rows": rows})
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    /// The default shapes exercise every segment kind with at most one R.
    #[test]
    fn f3bench_default_shapes() {
        use L2ShapeTag::{P, R, S};
        assert_eq!(default_shapes(1), vec![P]);
        assert_eq!(default_shapes(4), vec![P, R, P, S]);
        assert_eq!(default_shapes(16).iter().filter(|t| **t == R).count(), 1);
    }

    /// The interior census [P], pinned to `qlab-bench f3census --interior`'s
    /// output: per (outer, k), the leaf's log height and LDE, FRI arities,
    /// queries, opened extension elements, challenger perms, perms per query,
    /// both leaves' perms, and the query component's columns and rows.
    #[test]
    fn f3census_interior_is_pinned() {
        let chunks = quotient_chunks(&LeafAir::new(1));
        assert_eq!(chunks, 2);
        /// (outer, k, log h, lde, arities, queries, opened, challenger, per query, both leaves, columns, rows)
        type Row = (Outer, usize, usize, usize, &'static [usize], usize, usize, usize, usize, usize, usize, usize);
        // F5-4d (lab #785): one leaf column more opens 2 more terms (ζ, ζ·g),
        // and 4·terms + 8 = 25,840 words crosses a 34-word flush block: one
        // more challenger perm, both proofs +2. Queries and columns unmoved.
        #[rustfmt::skip]
        let want: [Row; 6] = [
            (Outer::B2, 4, 16, 17, &[4, 4, 4], 86, 6458, 793, 148, 27042, 4922, 524288),
            (Outer::B2, 8, 17, 18, &[4, 4, 4, 1], 86, 6458, 796, 156, 28424, 4964, 524288),
            (Outer::B2, 16, 18, 19, &[4, 4, 4, 2], 86, 6458, 796, 161, 29284, 4995, 524288),
            (Outer::B4, 4, 16, 18, &[4, 4, 4], 43, 6458, 788, 153, 14734, 4891, 262144),
            (Outer::B4, 8, 17, 19, &[4, 4, 4, 1], 43, 6458, 791, 162, 15514, 4935, 262144),
            (Outer::B4, 16, 18, 20, &[4, 4, 4, 2], 43, 6458, 791, 167, 15944, 4966, 262144),
        ];
        for (outer, k, lh, lde, ar, q, opened, ch, pq, both, cols, rows) in want {
            assert_eq!(row(k).log_h as usize, lh, "{outer:?} k = {k}");
            let v = leaf_verify(lh, chunks, outer);
            let got = (v.lde, v.arities.clone(), v.queries, v.opened_ext, v.challenger_perms, v.per_query_perms, v.query_columns);
            assert_eq!(got, (lde, ar.to_vec(), q, opened, ch, pq, cols), "{outer:?} k = {k}");
            assert_eq!(2 * (ch + q * pq), both);
            assert_eq!((24 * q * pq).next_power_of_two(), rows);
        }
    }

    /// `--k 0` and an empty `--shapes` are refused as arguments, before any
    /// leaf is built (`LeafAir::new` asserts k ≥ 1).
    #[test]
    fn f3bench_refuses_an_empty_leaf() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(shapes_arg(&args(&["--k", "0"])), Err("--k must be at least 1".into()));
        assert_eq!(shapes_arg(&args(&["--shapes", ""])), Err("--shapes needs at least one shape".into()));
        assert!(shapes_arg(&args(&["--k", "x"])).is_err());
        assert_eq!(shapes_arg(&args(&["--k", "2"])).map(|v| v.len()), Ok(2));
    }

    /// One real round trip on the lane: a one-transaction leaf proven on the
    /// decided outer lane (b2, non-hiding) and verified natively; a PV moved
    /// after proving is refused. [P] ≈ 0.5 GiB (k-model at 2^14 × 3,225).
    #[test]
    fn f3leaf_proves_and_verifies_at_b2() {
        let fx = fixture(&[L2ShapeTag::P], SEED);
        let (air, trace, mut pvs) = honest(&fx);
        assert_eq!(quotient_chunks(&air), 2, "degree 3 on a non-hiding config");
        let config = make_legacy_config_with(&Outer::B2.cfg());
        let proof = prove(&config, &air, trace, &pvs);
        verify(&config, &air, &proof, &pvs).expect("the leaf proof verifies");
        pvs[super::super::leaf::PV_SIDE] += Val::from_u32(1);
        assert!(verify(&config, &air, &proof, &pvs).is_err(), "a moved N out is refused");
    }
}
