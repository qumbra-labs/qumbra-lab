//! Lab #775 F4-4 — **`qlab-bench f4leaf --prove`**: one measured cell of the
//! wrapper chain, `(k, outer lane)`, for the box script (condition (d)).
//!
//! ```text
//! qlab-bench f4leaf --prove --outer b2|b4 [--k N | --kinds SPRC…]
//!            [--member-bytes S=…,P=…,R=…,C=…] [--member-source TEXT]
//! ```
//!
//! One process, each step timed once: build the `k`-slot fixture (its `prev`
//! the genesis surface's commitment); scan W in full (refuse to prove on a
//! failing row); prove W under the non-hiding outer lane and verify it; prove
//! the deposit-sum proof over the claims' openings under the hiding L2
//! config and verify it; run `verify_wrapper` end to end (V0–V9; V3 and V9
//! real). **The member proofs are stubs** — one L2 member prove is 7–30 GiB
//! (shape P ≈ 31 GiB at b4 since the hiding PCS), so `k` real members do not
//! fit one process; the stub checks the chain's `l2_id` and the PVs, so V2's
//! `u32` gate runs on the real PV vectors. `verify_wrapper`'s wall is
//! therefore the **stub-member** path; the full verifier adds each member's
//! own verify time, measured per shape by the existing modes (`zkpeak --case
//! p|claim`, `l2shape --shape s|r --pcs hiding`), which also give the member
//! proof bytes passed in as `--member-bytes`.
//!
//! Output: one JSON object on stdout; the exit code is 0 iff the honest scan
//! holds, W verifies, the deposit proof verifies and `verify_wrapper`
//! accepts. Peak memory is the operator's `/usr/bin/time -v` reading.
use std::time::Instant;

use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove, verify};
use qlab_consensus::legacy::make_legacy_config_with;
use qlab_consensus::Val;
use serde_json::{json, Value};

use super::dep::{prove_dep, verify_dep_u32, DEP_HEIGHT, DEP_WIDTH};
use super::native::{check_wrapper_leaf, WInputs, WTag};
use super::neg::{fx_pvs, honest, try_wfixture_rows, P_ROWS, SEED};
use super::verify::{verify_wrapper, version_for, Bundle, BundleMember, MemberVerifier, Surface};
use super::wleaf::{first_violation, W_PV_LEN};
use crate::f3::bench::Outer;
use crate::f3::native::Digest;

/// The chain the bench's stub members are proven for.
pub(crate) const BENCH_L2_ID: u64 = 7;

/// A `k`-slot mix: slot 1 is R, slots `i ≡ 3 (mod 4)` are claims, even slots
/// P, the rest S — K = 4: P R P C; K = 8: 4 P, 1 S, 1 R, 2 C; K = 16: 8 P,
/// 3 S, 1 R, 4 C.
pub(crate) fn default_kinds(k: usize) -> Vec<WTag> {
    (0..k)
        .map(|i| match i {
            1 => WTag::R,
            i if i % 4 == 3 => WTag::C,
            i if i % 2 == 0 => WTag::P,
            _ => WTag::S,
        })
        .collect()
}

/// `--kinds SPRC…`.
pub(crate) fn parse_kinds(spec: &str) -> Result<Vec<WTag>, String> {
    let v: Vec<WTag> = spec
        .chars()
        .map(|c| match c {
            'S' => Ok(WTag::S),
            'P' => Ok(WTag::P),
            'R' => Ok(WTag::R),
            'C' => Ok(WTag::C),
            o => Err(format!("unknown kind {o}")),
        })
        .collect::<Result<_, _>>()?;
    if v.is_empty() {
        return Err("--kinds needs at least one".into());
    }
    Ok(v)
}

/// The stub member path: the chain's `l2_id` and the member's own PVs.
struct StubMembers;
impl MemberVerifier<Vec<u32>> for StubMembers {
    fn verify(&self, m: &BundleMember<Vec<u32>>, l2_id: u64) -> Result<(), String> {
        if l2_id != BENCH_L2_ID {
            return Err("wrong l2_id".into());
        }
        (m.proof == m.pvs).then_some(()).ok_or_else(|| "stub mismatch".into())
    }
}

/// `--member-bytes S=…,P=…,R=…,C=…`: one proof's bytes per shape.
pub(crate) fn parse_member_bytes(spec: &str) -> Result<[u64; 4], String> {
    let mut out = [None; 4];
    for part in spec.split(',') {
        let (k, v) = part.split_once('=').ok_or("--member-bytes takes S=…,P=…,R=…,C=…")?;
        let i = match k {
            "S" => 0,
            "P" => 1,
            "R" => 2,
            "C" => 3,
            o => return Err(format!("unknown shape {o}")),
        };
        if out[i].is_some() {
            return Err(format!("--member-bytes gives {k} twice"));
        }
        out[i] = Some(v.parse::<u64>().map_err(|e| e.to_string())?);
    }
    let all: Option<Vec<u64>> = out.iter().copied().collect();
    all.map(|v| [v[0], v[1], v[2], v[3]]).ok_or_else(|| "--member-bytes needs all of S, P, R, C".into())
}

fn shape_index(t: WTag) -> usize {
    match t {
        WTag::S => 0,
        WTag::P => 1,
        WTag::R => 2,
        WTag::C => 3,
    }
}

/// One cell: the report and whether its four checks hold.
pub(crate) fn cell(kinds: &[WTag], outer: Outer, member_bytes: Option<[u64; 4]>, member_source: Option<&str>) -> Result<(Value, bool), String> {
    let k = kinds.len();
    let version = version_for(k, outer).ok_or_else(|| format!("no wrapper version for k = {k} on {}", outer.label()))?;

    // The fixture, its `prev` the genesis surface's commitment (review U1:
    // timed apart from the trace).
    let t = Instant::now();
    let mut fx = try_wfixture_rows(kinds, SEED, P_ROWS)?;
    let genesis = Surface::genesis(version, BENCH_L2_ID, fx.rin);
    fx.inp = WInputs { prev: genesis.commitment, ..fx.inp.clone() };
    let mut st = fx.pre.clone();
    let (rin, wit, rout) = st.apply(&fx.inp, &fx.members).map_err(|e| format!("the fixture wrapper: {e:?}"))?;
    fx.exit_cmt = check_wrapper_leaf(&rin, &fx.inp, &fx.members, &wit).map_err(|e| format!("its check: {e:?}"))?.1;
    (fx.rin, fx.wit, fx.rout) = (rin, wit, rout);
    let fixture_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (air, trace, pvs) = honest(&fx);
    let gen_s = t.elapsed().as_secs_f64();
    let (width, height) = (trace.width(), trace.height());

    let t = Instant::now();
    let scan = first_violation(&air, &trace, &pvs);
    let scan_s = t.elapsed().as_secs_f64();
    if let Some((r, ph)) = &scan {
        return Err(format!("the honest wrapper does not hold at row {r}: {ph:?} — not proving"));
    }
    let layout = AirLayout::from_air::<Val>(&air);
    let constraints = get_symbolic_constraints::<Val, _>(&air, layout).len();
    let degree = get_max_constraint_degree::<Val, _>(&air, layout);
    let chunks = 1usize << get_log_num_quotient_chunks::<Val, _>(&air, layout, 0);

    // W.
    // Version 1 proves on W_V1_CFG (b2/q91); measurement versions on their lane.
    let w_cfg = qlab_wrapper::verify::version_cfg(version).expect("the version exists");
    let config = make_legacy_config_with(&w_cfg);
    let t = Instant::now();
    let proof = prove(&config, &air, trace, &pvs);
    let prove_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let w_ok = verify(&config, &air, &proof, &pvs);
    let verify_s = t.elapsed().as_secs_f64();
    let w_bytes = bincode::serialize(&proof).map(|b| b.len() as u64).ok();

    // The deposit-sum proof.
    let t = Instant::now();
    let (dep_pvs, dep_proof) = prove_dep(&fx.deps).ok_or("the claims' openings do not fit a deposit proof")?;
    let dep_prove_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let dep_ok = verify_dep_u32(&dep_pvs, &dep_proof);
    let dep_verify_s = t.elapsed().as_secs_f64();
    let dep_bytes = bincode::serialize(&dep_proof).map(|b| b.len() as u64).ok();

    // verify_wrapper, end to end (stub members).
    let w_pvs: Vec<u32> = fx_pvs(&fx).iter().map(|v| v.as_canonical_u32()).collect();
    debug_assert_eq!(w_pvs.len(), W_PV_LEN);
    let bundle = Bundle {
        version,
        w_pvs: w_pvs.clone(),
        w_proof: &proof,
        members: fx.members.iter().map(|m| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: m.pvs.clone() }).collect(),
        dep_pvs: dep_pvs.clone(),
        dep_proof: &dep_proof,
    };
    let anchor_ok: &dyn Fn(&Digest) -> bool = &|_| true;
    let t = Instant::now();
    let vw = verify_wrapper(&bundle, &genesis, &StubMembers, anchor_ok);
    let vw_s = t.elapsed().as_secs_f64();

    // Bundle bytes: W and the deposit proof measured here; members as given.
    let counts = kinds.iter().fold([0u64; 4], |mut c, t| {
        c[shape_index(*t)] += 1;
        c
    });
    let member_pv_words: usize = fx.members.iter().map(|m| m.pvs.len()).sum();
    let pv_bytes = 4 * (W_PV_LEN + dep_pvs.len() + member_pv_words) as u64;
    let members_total = member_bytes.map(|mb| (0..4).map(|i| mb[i] * counts[i]).sum::<u64>());
    let bundle_total = match (w_bytes, dep_bytes, members_total) {
        (Some(w), Some(d), Some(m)) => Some(w + d + m + pv_bytes),
        _ => None,
    };
    let scale = width as f64 * 2f64.powi(height.trailing_zeros() as i32 - 18);
    let ok = w_ok.is_ok() && dep_ok && vw.is_ok();
    let report = json!({
        "mode": "f4leaf --prove", "issue": 775, "k": k,
        "kinds": kinds.iter().map(|t| format!("{t:?}")).collect::<Vec<_>>(),
        "kind_counts": {"S": counts[0], "P": counts[1], "R": counts[2], "C": counts[3]},
        "version": version, "outer_lane": outer.label(), "w_lane": w_cfg.label(), "outer_pcs": "non-hiding (qlab_consensus::legacy)",
        "built": {"evidence": "M", "width": width, "height": height, "log_height": height.trailing_zeros(),
            "public_values": W_PV_LEN, "constraints": constraints, "max_degree": degree, "quotient_chunks": chunks},
        "honest_scan": {"evidence": "M", "every_row_holds": true, "seconds": scan_s},
        "fixture_seconds": {"evidence": "M", "value": fixture_s,
            "contains": "the k-slot fixture's synthesis, the genesis surface, the rebuild on its commitment (apply + check_wrapper_leaf)"},
        "trace_gen_seconds": {"evidence": "M", "value": gen_s, "contains": "W's plan and render only"},
        "prove_seconds": {"evidence": "M", "value": prove_s, "contains": "exactly p3 prove(); excludes trace generation"},
        "verify_seconds": {"evidence": "M", "value": verify_s, "contains": "exactly p3 verify() of W; the config is built outside"},
        "timers_note": "the timers overlap and must not be summed: verify_wrapper.seconds re-runs V3 (W verify) and V9 (deposit verify); the full verifier = verify_wrapper.seconds + Σ member verify, nothing else added",
        "w_proof_bytes": {"evidence": "M", "source": "bincode::serialize", "value": w_bytes},
        "native_verified": w_ok.is_ok(),
        "verify_error": w_ok.err().map(|e| format!("{e:?}")),
        "dep": {"evidence": "M", "n": fx.deps.len(), "rows": DEP_HEIGHT, "width": DEP_WIDTH, "pcs": "hiding (qlab_l2::make_config_l2)",
            "prove_seconds": dep_prove_s, "verify_seconds": dep_verify_s, "proof_bytes": dep_bytes, "verified": dep_ok,
            "contains": "prove_seconds: its PVs, plan, render and prove; verify_seconds: the u32 gate, config and AIR construction, and verify"},
        "verify_wrapper": {"evidence": "M", "label": "stub members", "seconds": vw_s, "ok": vw.is_ok(),
            "contains": "V0–V9 in full: W's verify (V3) and the deposit proof's (V9), their configs and AIRs built inside; stub member checks (V2)",
            "anchor_ok": "stub: every absorbed root accepted (V7 is F5's L1 rule)",
            "error": vw.err().map(|e| format!("{e:?}")), "members": "stub",
            "members_reason": "one L2 member prove is 7–30 GiB (P ≈ 31 GiB at b4, hiding PCS): k real members do not fit one process; the full verifier = this path + Σ each member's own verify, measured per shape"},
        "bundle_bytes": {"value": bundle_total,
            "evidence": "M (W and the deposit proof, this cell) + member proof bytes as given (--member-bytes)",
            "parts": {"w": w_bytes, "dep": dep_bytes, "members": members_total, "pvs": pv_bytes,
                "member_bytes_by_shape": member_bytes.map(|mb| json!({"S": mb[0], "P": mb[1], "R": mb[2], "C": mb[3]})),
                "member_source": member_source}},
        "expected_peak_gib": {"evidence": "P", "source": "F2's k-model, peak ≈ K × width × 2^(h−18), a prediction only",
            "value": (crate::f3::bench::k_model(outer) * scale * 100.0).round() / 100.0},
        "peak_rss": {"evidence": "M", "value": null, "operator_records": "maximum resident set size from /usr/bin/time -v wrapping this process"},
    });
    Ok((report, ok))
}

/// `f4leaf --prove …`.
pub(crate) fn prove_run(args: &[String]) -> Result<(), String> {
    let get = |key: &str| args.iter().position(|a| a == key).and_then(|i| args.get(i + 1));
    let outer = Outer::parse(get("--outer").ok_or("--prove needs --outer b2|b4")?)?;
    // k is checked against the versions before anything is built (review U3).
    let has_version = |k: usize| version_for(k, outer).map(|_| ()).ok_or_else(|| format!("no wrapper version for k = {k} on {}", outer.label()));
    let kinds = match (get("--kinds"), get("--k")) {
        (Some(_), Some(_)) => return Err("give --kinds or --k, not both".into()),
        (Some(s), None) => {
            has_version(s.chars().count())?;
            parse_kinds(s)?
        }
        (None, Some(k)) => match k.parse::<usize>() {
            Ok(0) => return Err("--k must be at least 1".into()),
            Ok(k) => {
                has_version(k)?;
                default_kinds(k)
            }
            Err(_) => return Err("--k takes a count".into()),
        },
        (None, None) => return Err("--prove needs --k N or --kinds SPRC…".into()),
    };
    let member_bytes = get("--member-bytes").map(|s| parse_member_bytes(s)).transpose()?;
    let (report, ok) = cell(&kinds, outer, member_bytes, get("--member-source").map(String::as_str))?;
    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
    if !ok {
        return Err("the cell did not verify end to end".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mix and the argument parsers.
    #[test]
    fn f4bench_mix_and_args() {
        let count = |k: usize| {
            default_kinds(k).iter().fold([0; 4], |mut c, t| {
                c[shape_index(*t)] += 1;
                c
            })
        };
        // [S, P, R, C]
        assert_eq!([count(4), count(8), count(16)], [[0, 2, 1, 1], [1, 4, 1, 2], [3, 8, 1, 4]]);
        assert_eq!(parse_member_bytes("S=1,P=2,R=3,C=4"), Ok([1, 2, 3, 4]));
        assert!(parse_member_bytes("S=1,P=2,R=3").is_err());
        assert!(parse_member_bytes("S=1,P=2,R=3,C=4,S=5").is_err(), "a duplicate key");
        // A kinds list W refuses (a second R) is an Err, never a panic.
        assert!(cell(&[WTag::R, WTag::R], Outer::B2, None, None).is_err());
        assert!(parse_kinds("SX").is_err());
        for k in [4, 8, 16] {
            assert!(version_for(k, Outer::B2).is_some() && version_for(k, Outer::B4).is_some(), "k = {k}");
        }
    }

    /// The lane's smoke cell (condition (5)): K = 1, a claim, b2 — every key
    /// the box script reads is present, and the four checks hold.
    #[test]
    fn f4bench_smoke_cell() {
        let (r, ok) = cell(&[WTag::C], Outer::B2, Some([1, 2, 3, 4]), Some("test")).expect("the cell");
        assert!(ok, "{r:#}");
        for key in [
            "/native_verified",
            "/honest_scan/every_row_holds",
            "/dep/verified",
            "/verify_wrapper/ok",
            "/built/height",
            "/built/width",
            "/prove_seconds/value",
            "/verify_seconds/value",
            "/w_proof_bytes/value",
            "/dep/proof_bytes",
            "/dep/prove_seconds",
            "/verify_wrapper/seconds",
            "/bundle_bytes/value",
        ] {
            assert!(r.pointer(key).is_some_and(|v| !v.is_null()), "{key} missing in {r:#}");
        }
        assert_eq!(r["verify_wrapper"]["label"], "stub members");
        assert!(r["verify_wrapper"]["anchor_ok"].as_str().is_some_and(|s| s.starts_with("stub")));
        assert!(r.pointer("/fixture_seconds/value").is_some_and(|v| !v.is_null()));
        assert_eq!(r["dep"]["n"], 1);
        assert_eq!(r["bundle_bytes"]["parts"]["members"], 4, "one claim at 4 B");
    }
}
