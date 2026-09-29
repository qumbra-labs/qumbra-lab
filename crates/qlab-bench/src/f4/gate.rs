//! Lab #782 F4b-1 (b) — **the W query component on M4's interior layout**:
//! `m4gate`'s `VerifierGateAir` pointed at a real W proof.
//!
//! ```text
//! qlab-bench f4gate --k N --child b2|b4 --outer b2|b4 [--check] [--prove]
//! ```
//!
//! Proves an honest `k`-slot W on the child lane, records its verification
//! (`m4gaterec::walk_with_cfg`, AIR-agnostic), builds the one-child gate
//! trace at [`w_gate_shape`] (`build_gate_trace`), optionally scans every row
//! (`--check`) and proves the gate on the outer lane (`--prove`). One
//! component covers every one of the child's queries (86 at b2, 43 at b4);
//! its rows and columns are the fan-in answer for a W child. The report also
//! carries condition (c)'s [P] line for a two-child node (W plus one rung-1
//! C2 output) on the same layout.
//!
//! **What the M4 layout verifies** (`m4gate`'s module doc): the child's full
//! transcript, its Merkle openings and the FRI arithmetic, i.e. the PCS
//! opening layer. The **quotient identity** (the child AIR's constraints at
//! ζ, C1-class) is not wired there: this component is a query component, as
//! condition (b) asks, and the OOD half is F4b-2's.
//!
//! The one M4 assumption that does not carry over — the epoch Σfee rider of
//! the two-child interior, which reads the child's PV tail as an M3 fee — is
//! outside the one-child gate; a W-verifying interior must not reuse it
//! (W's PV tail is `exit_cmt`).
#![cfg_attr(not(test), allow(dead_code))]
use std::time::Instant;

use p3_air::{Air, BaseAir, DebugConstraintBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove, verify};
use qlab_consensus::legacy::make_legacy_config_with;
use qlab_consensus::Val;
use serde_json::json;

use super::bench::default_kinds;
use super::neg::{honest, wfixture_rows, P_ROWS, SEED};
use super::wleaf::{WAir, W_PV_LEN, W_WIDTH};
use crate::f3::bench::{fri_log_arities, Outer};
use crate::m4gate::{build_gate_trace, lane_plan, GateLayout, GateShape, VerifierGateAir};
use crate::m4gaterec::walk_with_cfg;

/// The gate shape that verifies a W of `log_height` rows proven on `child`.
pub(crate) fn w_gate_shape(log_height: usize, child: Outer) -> GateShape {
    let cfg = child.cfg();
    let air = WAir::new(1);
    let chunks = 1usize << get_log_num_quotient_chunks::<Val, _>(&air, p3_air::symbolic::AirLayout::from_air::<Val>(&air), 0);
    let log_max = log_height + cfg.log_blowup;
    GateShape {
        tw: W_WIDTH,
        qw: 4 * chunks,
        n_pvs: W_PV_LEN,
        nq: cfg.num_queries,
        log_max,
        grind_bits: cfg.grind_bits,
        log_arities: fri_log_arities(log_max, &cfg),
        cap_len: 1 << qlab_consensus::CAP_HEIGHT,
        log_blowup: cfg.log_blowup,
        merge_lane: false,
        export_f2dig: false,
    }
}

/// A generic child's shape on the same layout (condition (c)'s [P] line).
pub(crate) fn child_gate_shape(width: usize, pv_len: usize, log_height: usize, chunks: usize, child: Outer) -> GateShape {
    let cfg = child.cfg();
    let log_max = log_height + cfg.log_blowup;
    GateShape {
        tw: width,
        qw: 4 * chunks,
        n_pvs: pv_len,
        nq: cfg.num_queries,
        log_max,
        grind_bits: cfg.grind_bits,
        log_arities: fri_log_arities(log_max, &cfg),
        cap_len: 1 << qlab_consensus::CAP_HEIGHT,
        log_blowup: cfg.log_blowup,
        merge_lane: false,
        export_f2dig: false,
    }
}

/// [P] a child's lane perms on this layout without a proof, counted as
/// `m4gate::lane_plan` lays them out: every observation flush's blocks, the
/// index refills, the trailer, flush 2's duplicate, then every query's
/// program (`qslots`). The refills are exact for the last phase, which
/// samples bits (the query PoW and the indices), never by rejection. A
/// rejected field draw earlier (p ≈ 2^-7 a draw) costs one more u32 word,
/// and one more perm only when it crosses an 8-word digest boundary
/// (PR #783 review W5). F4b-1's box measured the lane at
/// 8,380 / 9,200 / 16,214 perms (W at K = 1 b4, K = 16 b4, K = 16 b2); the
/// first census missed the refills, trailer and duplicate (824–829 perms).
pub(crate) fn perms_p(shape: &GateShape) -> usize {
    let blocks = shape.flush_blocks();
    // After the last observation: one draw for the query PoW and one per
    // query index, eight u32 draws a digest, the first from that flush.
    let refills = (shape.nq + 1).div_ceil(8) - 1;
    blocks.iter().sum::<usize>() + refills + 1 + blocks[2] + shape.nq * shape.qslots()
}

/// Every row's constraints, in parallel; the lowest failing row.
pub(super) fn scan<A>(air: &A, trace: &RowMajorMatrix<Val>, pvs: &[Val]) -> Option<usize>
where
    A: for<'a> Air<DebugConstraintBuilder<'a, Val>> + BaseAir<Val> + Sync,
{
    use core::sync::atomic::{AtomicUsize, Ordering};
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::ViewPair;
    use p3_maybe_rayon::prelude::*;
    let h = trace.height();
    let best = AtomicUsize::new(usize::MAX);
    (0..h.div_ceil(1024)).into_par_iter().for_each(|ch| {
        for row in ch * 1024..((ch + 1) * 1024).min(h) {
            if row >= best.load(Ordering::Relaxed) {
                return;
            }
            let local = trace.row_slice(row).expect("a row");
            let nxt = trace.row_slice((row + 1) % h).expect("a row");
            let main = ViewPair::new(RowMajorMatrixView::new_row(&*local), RowMajorMatrixView::new_row(&*nxt));
            let prep = ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0));
            let mut b = DebugConstraintBuilder::new(
                row,
                main,
                prep,
                pvs,
                Val::from_bool(row == 0),
                Val::from_bool(row == h - 1),
                Val::from_bool(row != h - 1),
                &[],
            );
            air.eval(&mut b);
            if !b.into_failures().is_empty() {
                best.fetch_min(row, Ordering::Relaxed);
                return;
            }
        }
    });
    let r = best.into_inner();
    (r != usize::MAX).then_some(r)
}

/// `f4gate …`.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let get = |key: &str| args.iter().position(|a| a == key).and_then(|i| args.get(i + 1));
    let k = get("--k").ok_or("--k N is required")?.parse::<usize>().map_err(|e| e.to_string())?;
    if k == 0 || super::verify::VERSIONS.iter().all(|(_, kk, _)| *kk != k) {
        return Err(format!("no wrapper version has k = {k}"));
    }
    let child = Outer::parse(get("--child").ok_or("--child b2|b4 is required")?)?;
    let outer = Outer::parse(get("--outer").ok_or("--outer b2|b4 is required")?)?;
    let (check, do_prove) = (args.iter().any(|a| a == "--check"), args.iter().any(|a| a == "--prove"));

    // The child: an honest k-slot W, proven on `child`.
    let t = Instant::now();
    let fx = wfixture_rows(&default_kinds(k), SEED, P_ROWS);
    let (w_air, w_trace, w_pvs) = honest(&fx);
    let log_h = w_trace.height().trailing_zeros() as usize;
    let child_cfg = make_legacy_config_with(&child.cfg());
    let w_proof = prove(&child_cfg, &w_air, w_trace, &w_pvs);
    let child_prove_s = t.elapsed().as_secs_f64();
    let w_ok = verify(&child_cfg, &w_air, &w_proof, &w_pvs).is_ok();
    let w_bytes = bincode::serialize(&w_proof).map(|b| b.len()).ok();

    // Its verification, recorded; the gate's shape and layout. A panic in
    // the M4 machinery on this new child shape is reported, not a crash
    // (review V2).
    let t = Instant::now();
    let sched = walk_with_cfg(&w_proof, &w_pvs, &child.cfg());
    let shape = w_gate_shape(log_h, child);
    let fail = |stage: &str, e: Box<dyn std::any::Any + Send>| -> String {
        let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        let skeleton = json!({"mode": "f4gate", "issue": 782, "k": k, "child_lane": child.label(), "outer_lane": outer.label(),
            "child": {"verified": w_ok, "proof_bytes": w_bytes}, "error": {"stage": stage, "panic": msg}});
        println!("{}", serde_json::to_string_pretty(&skeleton).expect("json"));
        format!("{stage} panicked: {msg}")
    };
    let perms = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lane_plan(&sched, &shape).0.len()))
        .map_err(|e| fail("lane_plan", e))?;
    let rows = (perms * 24).next_power_of_two();
    let width = GateLayout::from_shape(&shape).gate_width;
    let walk_s = t.elapsed().as_secs_f64();
    let (leaf, compress, challenger) = sched.native_counts;
    let gib = |outer: Outer, cols: usize, rows: usize| {
        let k = match outer {
            Outer::B2 => super::rec::K_B2,
            Outer::B4 => super::rec::K_B4,
        };
        (k * cols as f64 * 2f64.powi(rows.trailing_zeros() as i32 - 18) * 10.0).round() / 10.0
    };

    // Condition (c), [P]: W plus one rung-1 C2 (P, F2's widest) on this layout.
    let c2 = crate::f2::price::composed_c2(qlab_l2::Shape::P);
    let (c2_cols, c2_rows) = (c2["component_columns"].as_u64().unwrap_or(0) as usize, c2["padded_rows"].as_u64().unwrap_or(0) as usize);
    let c2_shape = child_gate_shape(c2_cols, c2["public_values"].as_u64().unwrap_or(0) as usize, c2_rows.trailing_zeros() as usize, 2, outer);
    let two_perms = perms + perms_p(&c2_shape) + 1;
    let two_rows = (two_perms * 24).next_power_of_two();
    let two_width = width.max(GateLayout::from_shape(&GateShape { merge_lane: true, tw: width.max(c2_cols), ..shape.clone() }).gate_width);

    let mut report = json!({
        "mode": "f4gate", "issue": 782, "k": k, "child_lane": child.label(), "outer_lane": outer.label(),
        "child": {"evidence": "M", "log_height": log_h, "width": W_WIDTH, "public_values": W_PV_LEN,
            "fixture_and_prove_seconds": child_prove_s, "verified": w_ok, "proof_bytes": w_bytes},
        "gate_shape": {"tw": shape.tw, "qw": shape.qw, "n_pvs": shape.n_pvs, "nq": shape.nq, "log_max": shape.log_max,
            "log_arities": shape.log_arities, "qslots": shape.qslots()},
        "component": {"evidence": "M (built from the recorded walk)", "lane_perms": perms, "rows": rows, "columns": width,
            "queries_covered": shape.nq, "components_to_cover_all_queries": 1,
            "perms_p_check": perms_p(&shape),
            "perms_match": perms.abs_diff(perms_p(&shape)) * 20 <= perms,
            "perms_match_tolerance": "±5 %",
            "native_keccak_f": {"leaf": leaf, "compress": compress, "challenger": challenger},
            "walk_and_plan_seconds": walk_s,
            "k_model_gib": {"evidence": "P", "outer": gib(outer, width, rows)}},
        "two_child_node_p": {"evidence": "P, rough", "children": "this W + one rung-1 C2 of shape P (F2's widest)",
            "caveat": "heterogeneous children: the C2 child's perms are perms_p from its shape (no proof, no walk), the columns are the wider child's plus the merge lane, and m4gate's two-child interior was only ever built for two children of ONE shape",
            "layout_note": "resolved by F4b-1's box (issue #782): the k-model overstated the one-child gate cells by ≈ 33 % at outer b2 and ≈ 7 % at outer b4; the measured slope is ≈ 7.6 GiB per 2^18 rows at outer b2 and ≈ 15.1 at outer b4",
            "c2_child": {"columns": c2_cols, "rows": c2_rows, "lane_perms_p": perms_p(&c2_shape)},
            "lane_perms": two_perms, "rows": two_rows, "columns_at_least": two_width,
            "k_model_gib": gib(outer, two_width, two_rows)},
        "scope": "the PCS opening layer (transcript, Merkle, FRI) of the child; the quotient identity at ζ is F4b-2's (not wired in m4gate)",
        "peak_rss": {"evidence": "M", "value": null, "operator_records": "maximum resident set size from /usr/bin/time -v"},
    });

    if check || do_prove {
        // The prover's LDE reserve, allocated with the trace (review V1: a
        // late reserve costs ~3× RSS; m4interior passes log_blowup too).
        let reserve = if do_prove { outer.cfg().log_blowup } else { 0 };
        let t = Instant::now();
        let (trace, meta) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build_gate_trace(&sched, &w_pvs, &shape, reserve)))
            .map_err(|e| fail("build_gate_trace", e))?;
        let build_s = t.elapsed().as_secs_f64();
        let air = VerifierGateAir::new_with_shape(shape.clone());
        report["component"]["trace_build_seconds"] = json!(build_s);
        report["component"]["extra_capacity_bits"] = json!(reserve);
        report["component"]["trace"] = json!([trace.height(), trace.width()]);
        if check {
            let t = Instant::now();
            let bad = scan(&air, &trace, &meta.opvs);
            report["component"]["scan"] = json!({"every_row_holds": bad.is_none(), "first_failing_row": bad, "seconds": t.elapsed().as_secs_f64()});
            if bad.is_some() {
                println!("{}", serde_json::to_string_pretty(&report).expect("json"));
                return Err("the W gate trace does not hold".into());
            }
        }
        if do_prove {
            let cfg = make_legacy_config_with(&outer.cfg());
            let t = Instant::now();
            let proof = prove(&cfg, &air, trace, &meta.opvs);
            let prove_s = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let ok = verify(&cfg, &air, &proof, &meta.opvs);
            report["component"]["prove"] = json!({"evidence": "M", "prove_seconds": prove_s, "verify_seconds": t.elapsed().as_secs_f64(),
                "verified": ok.is_ok(), "error": ok.err().map(|e| format!("{e:?}")),
                "proof_bytes": bincode::serialize(&proof).map(|b| b.len()).ok()});
        }
    }
    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
    let failed = !w_ok || report["component"]["prove"]["verified"] == false;
    if failed {
        return Err("a proof did not verify".into());
    }
    Ok(())
}
