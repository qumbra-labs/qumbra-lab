//! Lab #782 F4b-2 — **the OOD half**: the quotient identity at ζ of a
//! non-hiding child (W, and `m4gate`'s own AIR as a child), as F2's C1
//! compiled with `zk = 0` (`f2::ood`).
//!
//! ```text
//! qlab-bench f4ood --census [w|gate]
//! qlab-bench f4ood --fingerprint s|p|r
//! qlab-bench f4ood --k N --child b2|b4 --outer b2|b4 [--check] [--prove] [--node] [--max-cells N]
//! ```
//!
//! `--census` compiles each child's OOD program from its AIR's symbolic
//! constraints (no proof, no trace) and reports the DAG, the register
//! machine and the C1 component's lane perms, rows and columns, with the
//! scaled memory beside them [P].
//!
//! `--fingerprint` prints the hiding C1's layout fingerprint for a real L2
//! shape (condition (4): `zk` leaves F2's hiding path byte-for-byte).
//!
//! The component run proves an honest `k`-slot W on the child lane, then
//! builds its OOD component (`f2::ood::legacy_ood`: the DAG checked against
//! p3's own fold at ζ, the `zk = 0` C1 built from the proof); `--check`
//! scans every row (plus the one-limb F2-digest negative), `--prove` proves
//! it on the outer lane. `--node` adds the query component (`m4gate` at
//! `w_gate_shape` with `export_f2dig`) and the native seam between the two:
//! caps, inner PVs and the F2 digest, each compared limb for limb.
#![cfg_attr(not(test), allow(dead_code))]
use serde_json::{json, Value};

use std::time::Instant;

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};
use qlab_consensus::legacy::make_legacy_config_with;
use qlab_consensus::Val;

use super::bench::default_kinds;
use super::gate::{scan, w_gate_shape};
use super::neg::{honest, wfixture_rows, P_ROWS, SEED};
use super::wleaf::{w_height, WAir, W_PV_LEN, W_WIDTH};
use crate::f3::bench::Outer;
use crate::m4gate::{build_gate_trace, monty_rr, outer_pvs, GateLayout, GateShape, VerifierGateAir, F2DIG_LIMBS};
use crate::m4gaterec::walk_with_cfg;

/// The two measured slopes the census scales by, per main-column cell
/// (the coordinator's ruling on the first census: they disagree by ≈ 3×, so
/// every [P] GiB carries both).
/// - `gate`: F4b-1's W-gate cells (issue #782's box), GiB per 3,800 columns
///   × 2^18 rows at an outer b2 / b4 lane (≈ 7.6 B per cell at b2).
/// - `f2_c1`: F2's measured C1 (P, 12,655 main columns × 2^15, ROM included
///   in the peak but not in the cells) at outer b2, ≈ 25 B per cell; its b4
///   figure doubles the b2 one, as the gate cells did.
const GATE_B2: f64 = 7.6 / (3_800.0 * 262_144.0);
const GATE_B4: f64 = 15.1 / (3_800.0 * 262_144.0);
const F2C1_B2: f64 = 10.41 / (12_655.0 * 32_768.0);

/// Extension degree: one extension value is four base columns.
const D: usize = 4;

fn gib(cols: usize, rows: usize) -> Value {
    let cells = cols as f64 * rows as f64;
    let r = |x: f64| (x * cells * 10.0).round() / 10.0;
    json!({"evidence": "P", "outer_b2": {"gate_slope": r(GATE_B2), "f2_c1_slope": r(F2C1_B2)},
        "outer_b4": {"gate_slope": r(GATE_B4), "f2_c1_slope": r(2.0 * F2C1_B2)},
        "caveat": "main columns × rows only: the ROM (periodic columns) is not in the cells; F2's slope has its ROM inside the peak, the gate slope has no ROM at all"})
}

/// C1's columns, ROM and rows under the current input discipline and the
/// two levers (count-only, lab #782's ruling (a)/(b)), each with both slopes.
///
/// The machine is a one-hot register file: `12 + 4R` columns and a ROM of
/// `12 + 3R + inputs` (A/B/destination one-hots and one input selector),
/// with every input a held column of `D` cells on every row.
fn levers(v: &Value) -> Value {
    let u = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0) as usize;
    let (cols, rows, rom, inputs) = (u("/c1/columns"), u("/c1/rows"), u("/c1/rom_columns"), u("/machine/inputs"));
    let (r, rb, ra) = (u("/lever_registers/current"), u("/lever_registers/held_operands"), u("/lever_registers/streamed"));
    let pvs = u("/c1/public_values");
    // What the next rung pays to verify this component as its child on the
    // `m4gate` layout (degree-3 C1: 2 quotient chunks), at each lane.
    let next = |c: usize, h: usize| {
        let at = |lane: Outer| {
            let p = super::gate::perms_p(&super::gate::child_gate_shape(c, pvs, h.trailing_zeros() as usize, 2, lane));
            json!({"lane_perms": p, "rows": (24 * p).next_power_of_two()})
        };
        json!({"evidence": "P", "source": "perms_p on child_gate_shape", "proven_at_b4_43q": at(Outer::B4), "proven_at_b2_86q": at(Outer::B2)})
    };
    let row = |name: &str, c: usize, m: usize, h: usize, regs: usize, note: &str| {
        json!({"discipline": name, "extension_registers": regs, "columns": c, "rom_columns": m, "rows": h,
            "memory_gib": gib(c, h), "next_rung_query_component": next(c, h), "note": note})
    };
    let mut out = vec![
        row("current", cols, rom, rows, r, "inputs held (D columns each, every row) and copied into registers"),
        row("held operands (lever b)", cols - D * (r - rb), 12 + 3 * rb + 2 * inputs, rows, rb,
            "inputs stay held columns but are read directly as A/B operands, never copied into a register; A and B one-hots span registers ∪ inputs"),
        row("streamed (lever a)", cols - D * inputs - D * r + D * ra, 12 + 3 * ra, rows, ra,
            "no held inputs: each opening enters a register at the row where C1's lane absorbs it (transcript order), greedy schedule; needs the machine's input steps aligned to the lane's absorb rows, not priced"),
    ];
    // Narrow and tall: ruled in as a count (the coordinator, on the lever
    // pricing) so the design call has a number for the option that needs a
    // new prover capability. One instruction per row, operands fetched from a
    // memory by a lookup/permutation argument, the ROM a looked-up table.
    // Machine columns, stated: a, b, c as extension values (12) + three
    // addresses (3) + three read timestamps (3) + opcode (1) + constant limbs
    // (4) + one ROM-lookup multiplicity (1) = 24 main, plus three logup
    // running sums as extension columns (12) = 36. Rows: one per instruction
    // plus one memory write per input (factor 1 + inputs / instructions).
    // The Keccak lane and the rest of C1's non-machine columns stay as today,
    // in their own table at the lane's height; the next rung opens both
    // tables per query, so its row width is the sum.
    const NARROW_MACHINE_COLUMNS: usize = 36;
    let instr = u("/dag/register_schedule/instructions");
    let non_machine = cols - D * inputs - (12 + D * r);
    let lane_rows = (24 * u("/c1/lane_perms")).next_power_of_two();
    let narrow_rows = (instr + inputs + 1).next_power_of_two();
    let cells = |c: usize, h: usize| c as f64 * h as f64;
    let narrow_cells = cells(NARROW_MACHINE_COLUMNS, narrow_rows) + cells(non_machine, lane_rows);
    let eq_cols = (narrow_cells / narrow_rows as f64).ceil() as usize;
    let mut narrow = row("narrow and tall (requires a lookup argument p3-uni-stark 0.6.1 lacks)",
        NARROW_MACHINE_COLUMNS + non_machine, 0, narrow_rows, 0,
        "machine table 36 columns (24 main + 3 logup running sums × D) × (instructions + inputs) rows; the Keccak lane and C1's other non-machine columns unchanged in their own table at the lane's height; the ROM becomes a looked-up table (its own few columns, not priced); REQUIRES a lookup/permutation argument p3-uni-stark 0.6.1 does not have");
    narrow["tables"] = json!({"machine": {"columns": NARROW_MACHINE_COLUMNS, "rows": narrow_rows,
            "rows_factor_over_instructions": (instr + inputs) as f64 / instr.max(1) as f64},
        "lane_and_rest": {"columns": non_machine, "rows": lane_rows}});
    narrow["memory_gib"] = gib(eq_cols, narrow_rows);
    narrow["next_rung_query_component"] = next(NARROW_MACHINE_COLUMNS + non_machine, narrow_rows);
    out.push(narrow);
    for w in [16usize, 32, 64] {
        let h = rows.max((D * inputs).div_ceil(w).next_power_of_two());
        out.push(row(&format!("random-access input lane, w = {w} (bound)"), cols - D * inputs + w, rom, h, r,
            "UNATTAINABLE as stated: an AIR row sees only itself and the next, so a w-column lane can hand a value only to the row it sits on; random access needs a permutation or lookup argument, which p3-uni-stark 0.6.1 does not have. A lower bound, not a design"));
    }
    json!(out)
}

fn with_scale(mut v: Value) -> Value {
    v["levers"] = levers(&v);
    let (rows, cols) = (v["c1"]["rows"].as_u64().unwrap_or(0) as usize, v["c1"]["columns"].as_u64().unwrap_or(0) as usize);
    v["c1"]["memory_gib"] = gib(cols, rows);
    v
}

/// The census: W at K ∈ {1, 16} on each child lane, and the gate AIR that
/// verifies a K = 16 W (as the next rung's child).
pub(crate) fn census(which: &str) -> Result<Value, String> {
    let mut w = vec![];
    for k in [1usize, 16].into_iter().filter(|_| which != "gate") {
        let log_h = w_height(k).trailing_zeros() as usize;
        for child in [Outer::B4, Outer::B2] {
            let v = crate::f2::ood::ood_census(W_WIDTH, W_PV_LEN, log_h, &WAir::new(k), &child.cfg())?;
            let mut v = with_scale(v);
            v["name"] = json!(format!("W, K = {k}, proven at {}", child.label()));
            w.push(v);
        }
    }
    let mut gates = vec![];
    for (child, outer) in [(Outer::B4, Outer::B2), (Outer::B4, Outer::B4)].into_iter().filter(|_| which != "w") {
        let shape = w_gate_shape(w_height(16).trailing_zeros() as usize, child);
        let air = VerifierGateAir::new_with_shape(shape.clone());
        let width = GateLayout::from_shape(&shape).gate_width;
        let rows = (24 * super::gate::perms_p(&shape)).next_power_of_two();
        let v = crate::f2::ood::ood_census(width, shape.n_opvs(), rows.trailing_zeros() as usize, &air, &outer.cfg())?;
        let mut v = with_scale(v);
        v["name"] = json!(format!("m4gate verifying W (K = 16, {}) proven at {}", child.label(), outer.label()));
        gates.push(v);
    }
    Ok(json!({"mode": "f4ood --census", "issue": 782, "evidence": "P", "w": w, "gate_as_child": gates}))
}

/// C1's cell budget by default: main columns plus ROM, W at K = 16 is
/// ≈ 5.8 G cells and the gate-as-child ≈ 6.8 G (the census).
const MAX_CELLS: usize = 8 << 30;

fn hex(limbs: &[Val]) -> String {
    use p3_field::PrimeField32;
    limbs.iter().flat_map(|l| (l.as_canonical_u32() as u16).to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

/// The native seam between a W's query component (`m4gate` outer PVs at
/// `shape`, with `export_f2dig`) and its OOD component (C1's exports):
/// caps, inner PVs (the gate carries them in Monty transcript encoding) and
/// the F2 digest, limb for limb.
pub(crate) fn seam(shape: &GateShape, gate_opvs: &[Val], ood: &crate::f2::ood::LegacyOod) -> Value {
    assert!(shape.export_f2dig, "the seam needs the query component's F2 digest");
    let rr = monty_rr();
    let caps = gate_opvs[..shape.opv_f0dig()] == ood.caps[..];
    let pvs = gate_opvs[shape.opv_pvs()..shape.opv_f2dig()].iter().copied().eq(ood.inner_pvs.iter().map(|v| *v * rr));
    let gate_dig = &gate_opvs[shape.opv_f2dig()..shape.opv_f2dig() + F2DIG_LIMBS];
    let dig = gate_dig == &ood.f2dig[..];
    json!({"holds": caps && pvs && dig, "caps_equal": caps, "cap_limbs": [shape.opv_f0dig(), ood.caps.len()],
        "inner_pvs_equal": pvs, "f2_digest_equal": dig,
        "f2_digest": {"query_component": hex(gate_dig), "ood_component": hex(&ood.f2dig)}})
}

/// `f4ood …`.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    if let Some(i) = args.iter().position(|a| a == "--census") {
        let which = args.get(i + 1).map_or("all", String::as_str);
        println!("{}", serde_json::to_string_pretty(&census(which)?).expect("json"));
        return Ok(());
    }
    let get = |key: &str| args.iter().position(|a| a == key).and_then(|i| args.get(i + 1));
    if let Some(sh) = get("--fingerprint") {
        let shape = match sh.as_str() {
            "s" => qlab_l2::Shape::S,
            "p" => qlab_l2::Shape::P,
            "r" => qlab_l2::Shape::R,
            other => return Err(format!("--fingerprint s|p|r, not {other}")),
        };
        println!("{}", serde_json::to_string_pretty(&crate::f2::ood::hiding_c1_fingerprint(shape)?).expect("json"));
        return Ok(());
    }
    let k = get("--k").ok_or("--k N is required (or --census)")?.parse::<usize>().map_err(|e| e.to_string())?;
    if k == 0 || super::verify::VERSIONS.iter().all(|(_, kk, _)| *kk != k) {
        return Err(format!("no wrapper version has k = {k}"));
    }
    let child = Outer::parse(get("--child").ok_or("--child b2|b4 is required")?)?;
    let outer = Outer::parse(get("--outer").ok_or("--outer b2|b4 is required")?)?;
    let flag = |f: &str| args.iter().any(|a| a == f);
    let (check, do_prove, node) = (flag("--check"), flag("--prove"), flag("--node"));
    let max_cells = get("--max-cells").map_or(Ok(MAX_CELLS), |v| v.parse::<usize>().map_err(|e| e.to_string()))?;

    // The child: an honest k-slot W, proven on `child` (as f4gate).
    let t = Instant::now();
    let fx = wfixture_rows(&default_kinds(k), SEED, P_ROWS);
    let (w_air, w_trace, w_pvs) = honest(&fx);
    let log_h = w_trace.height().trailing_zeros() as usize;
    let child_cfg = make_legacy_config_with(&child.cfg());
    let w_proof = prove(&child_cfg, &w_air, w_trace, &w_pvs);
    let w_ok = verify(&child_cfg, &w_air, &w_proof, &w_pvs).is_ok();
    let mut report = json!({"mode": "f4ood", "issue": 782, "k": k, "child_lane": child.label(), "outer_lane": outer.label(),
        "child": {"evidence": "M", "log_height": log_h, "width": W_WIDTH, "public_values": W_PV_LEN,
            "fixture_and_prove_seconds": t.elapsed().as_secs_f64(), "verified": w_ok},
        "peak_rss": {"evidence": "M", "value": null, "operator_records": "maximum resident set size from /usr/bin/time"}});

    // The OOD component (C1, zk = 0).
    let ood = crate::f2::ood::legacy_ood((W_WIDTH, W_PV_LEN, log_h), &w_air, &w_proof, &w_pvs, &child.cfg(), check,
        do_prove.then(|| outer.cfg()).as_ref(), max_cells)?;
    report["ood_component"] = ood.report.clone();
    let mut ok = w_ok && ood.ok;

    if node {
        // The query component with the F2 digest exported, and the seam.
        let sched = walk_with_cfg(&w_proof, &w_pvs, &child.cfg());
        let shape = GateShape { export_f2dig: true, ..w_gate_shape(log_h, child) };
        let mut q = json!({"columns": GateLayout::from_shape(&shape).gate_width, "public_values": shape.n_opvs()});
        let mut opvs = outer_pvs(&sched, &w_pvs, &shape);
        if check || do_prove {
            let reserve = if do_prove { outer.cfg().log_blowup } else { 0 };
            let t = Instant::now();
            let (trace, meta) = build_gate_trace(&sched, &w_pvs, &shape, reserve);
            q["build_seconds"] = json!(t.elapsed().as_secs_f64());
            q["trace"] = json!([trace.height(), trace.width()]);
            ok &= meta.opvs == opvs;
            opvs = meta.opvs;
            let air = VerifierGateAir::new_with_shape(shape.clone());
            if check {
                let t = Instant::now();
                let bad = scan(&air, &trace, &opvs);
                // Condition (1)'s other side: one exported limb moved.
                let mut moved = opvs.clone();
                moved[shape.opv_f2dig() + 5] += Val::ONE;
                let neg = scan(&air, &trace, &moved);
                q["scan"] = json!({"every_row_holds": bad.is_none(), "first_failing_row": bad, "seconds": t.elapsed().as_secs_f64()});
                q["f2dig_perturbed"] = json!({"limb": 5, "rejected": neg.is_some(), "first_failing_row": neg});
                ok &= bad.is_none() && neg.is_some();
            }
            if do_prove {
                let cfg = make_legacy_config_with(&outer.cfg());
                let t = Instant::now();
                let proof = prove(&cfg, &air, trace, &opvs);
                let prove_s = t.elapsed().as_secs_f64();
                let v = verify(&cfg, &air, &proof, &opvs);
                ok &= v.is_ok();
                q["prove"] = json!({"evidence": "M", "prove_seconds": prove_s, "verified": v.is_ok(),
                    "error": v.err().map(|e| format!("{e:?}")), "proof_bytes": bincode::serialize(&proof).map(|b| b.len()).ok()});
            }
        }
        let seam = seam(&shape, &opvs, &ood);
        ok &= seam["holds"] == true;
        report["query_component"] = q;
        report["seam"] = seam;
    }
    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
    if !ok {
        return Err("f4ood: a stage did not hold".into());
    }
    Ok(())
}
