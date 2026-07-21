//! M4 step 2 (棒 1): the end-to-end tree-assembly driver.
//!
//! Where `m4interior` proves ONE interior rectangle in isolation for the RSS
//! gate, this module drives the whole two-level tree in a single process:
//! two DISTINCT M3 transaction proofs → two leaf `VerifierGateAir` proofs
//! (proved serially, each native-verified then dropped so the interior prove
//! never coexists with a leaf's LDE) → one interior root proof → the full
//! native verification chain. That chain includes, as a HARD ASSERTION, issue
//! #24's consumer-side invariant `root == keccak-merge(opvsL, opvsR)`: the
//! aggregation soundness argument's compositional leg is a code fact in the
//! acceptance path here, not a verbal promise (PR #23 residual).
//!
//! The interior lane (`--lane b4|b2`) is the interior's OWN FRI config, chosen
//! independently of the fixed b4/q40 config each child leaf commits at (per
//! aggregation-rung1 §7.3 the per-level config is still an open design item;
//! this driver's measured data informs it — see `run_m4assembly`).

use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};

use crate::m4gate::{build_interior_trace, GateShape, VerifierGateAir};
use crate::m4interior::{epoch_fee_sum_expected, merge_root, EPOCH_FEE_LIMBS, MERGE_ROOT_LIMBS};
use crate::m4treerec::{leaf_proof, leaf_proof_variant, walk_leaf, AGG_CFG};
use crate::m4gaterec::Schedule;
use crate::{make_config_with, FriCfg, Val};

/// Issue #24 consumer-side invariant as a hard predicate: the interior proof's
/// exposed root public values (`opvs[2·n_opvs .. 2·n_opvs+MERGE_ROOT_LIMBS]`,
/// the §2 binding root) must equal `keccak-merge(opvsL, opvsR)` recomputed
/// natively over the two children's public opvs. Any consumer of an interior
/// proof holds all three (the proof's public root + both children's public
/// opvs) and can run this on public data with no proof — aggregation-rung1 §2's
/// "detectable by any node without any proof". The driver calls this as an
/// `assert!` AFTER native-verifying the interior proof.
pub(crate) fn consumer_root_ok(
    interior_opvs: &[Val],
    opvs_l: &[Val],
    opvs_r: &[Val],
    n_opvs: usize,
) -> bool {
    let native = merge_root(opvs_l, opvs_r);
    let base = 2 * n_opvs;
    interior_opvs.len() >= base + MERGE_ROOT_LIMBS
        && interior_opvs[base..base + MERGE_ROOT_LIMBS] == native[..]
}

/// Epoch supply-attestation rider (棒 3-3) consumer check: the exposed root
/// `Σfee` must equal the fee total recomputed from the consumer's OWN verified
/// children opvs (not the prover-carried halves) — exactly parallel to
/// `consumer_root_ok` for issue #24. The circuit binds `Σfee` to the carried fee
/// slots; this native recompute binds it to the REAL children, so a faked child
/// fee is caught here even though it is SAT at the circuit level (the issue #24
/// boundary — see `interior_epoch_fee_boundary`).
pub(crate) fn consumer_fee_ok(
    interior_opvs: &[Val],
    opvs_l: &[Val],
    opvs_r: &[Val],
    n_opvs: usize,
) -> bool {
    let sfee_base = 2 * n_opvs + MERGE_ROOT_LIMBS;
    let expected = epoch_fee_sum_expected(opvs_l, opvs_r);
    interior_opvs.len() >= sfee_base + EPOCH_FEE_LIMBS
        && interior_opvs[sfee_base..sfee_base + EPOCH_FEE_LIMBS] == expected[..]
}

/// Prove one leaf wide proof, native-verify it, size it, record its schedule,
/// then DROP the proof (only the schedule + opvs survive into the interior, so
/// the leaf's ~12 GB LDE never coexists with the interior prove). Returns
/// `(schedule, opvs, prove_seconds, fixed_bytes)`.
fn prove_verify_walk_leaf(variant: bool) -> (Schedule, Vec<Val>, f64, usize) {
    use std::time::Instant;
    let t = Instant::now();
    let (leaf, opvs) = if variant { leaf_proof_variant() } else { leaf_proof() };
    let prove_s = t.elapsed().as_secs_f64();
    // Native verify at the leaf's committed (fixed) aggregation config.
    let config = make_config_with(&AGG_CFG);
    let air = VerifierGateAir::new();
    verify(&config, &air, &leaf, &opvs).expect("native verify of a child leaf wide proof");
    let fixed = bincode::serialize(&leaf).expect("bincode").len();
    let sched = walk_leaf(&leaf, &opvs);
    drop(leaf);
    (sched, opvs, prove_s, fixed)
}

/// `m4assembly` bench mode (M4 step 2 棒 1): end-to-end two-level tree.
///
/// Proves the whole tree in one process and reports the whole-tree wall time
/// (2 leaf + 1 interior) plus each segment's fixed proof size, for the selected
/// interior lane. Peak RSS/footprint (read from an external `/usr/bin/time -l`
/// wrapping the process) is attributable to the INTERIOR segment — the leaves
/// are freed before it — so this is also the interior peak-footprint reading of
/// aggregation-rung1 §7.1 (per deliverable 3, only the interior segment's peak
/// is recorded; the leaf's is already in `docs/m4gate-step0bii-run*.md`).
///
/// `--lane b2` (b2/q80) is the default interior lane (DECIDED 2026-07-21, Larry
/// — aggregation-rung1 §4: true-32 GB-box fit + issue #24 headroom + clean 4.8 s
/// prove); `--lane b4` (b4/q40) stays available as an optional flag. Both ~100
/// bits (make_config_with asserts 40·2+22 = 80·1+22 = 102, post-B′). Defaults to b2.
pub(crate) fn run_m4assembly(power: &str, lane: Option<&str>) {
    use p3_matrix::Matrix;
    use std::time::Instant;

    let (lane_name, cfg): (&str, FriCfg) = match lane.unwrap_or("b2") {
        "b2" => (
            "b2/q80/g22/fp16/a16",
            FriCfg { log_blowup: 1, num_queries: 80, grind_bits: 22, log_final_poly_len: 4, max_log_arity: 4 },
        ),
        "b4" => (
            "b4/q40/g22/fp16/a16",
            FriCfg { log_blowup: 2, num_queries: 40, grind_bits: 22, log_final_poly_len: 4, max_log_arity: 4 },
        ),
        other => panic!("unknown --lane `{other}` (expected b4 | b2)"),
    };

    println!("# qumbra-lab M4 step 2: end-to-end tree/root assembly (m4assembly)");
    println!();
    crate::print_env(power);
    println!("- interior lane: **{lane_name}** (the INTERIOR's own FRI config; each child leaf is committed at the fixed b4/q40 aggregation config independently).");
    println!("- chain: 2 DISTINCT M3 tx proofs → 2 leaf wide proofs (proved serially, each native-verified then dropped) → 1 interior root proof → full native verification chain.");
    println!("- issue #24 HARD ASSERTION in this driver: `root_pv == keccak-merge(opvsL, opvsR)` (native recompute over public opvs) — the compositional soundness leg as a code fact, not a promise.");
    println!("- peak footprint (from external `/usr/bin/time -l`) is the INTERIOR segment's — the leaves are freed first. §7.1: any run with nonzero swap-ins/pageouts is disqualified.");
    println!();

    let tree_t = Instant::now();

    // 棒 1: two DISTINCT children, proved serially. Each leaf is proved,
    // native-verified, sized, walked, then dropped before the next allocation.
    eprintln!("== m4assembly [{lane_name}]: proving child L (b4/q40 leaf, ~12 GB transient)... ==");
    let (sched_l, opvs_l, leaf_l_s, leaf_l_bytes) = prove_verify_walk_leaf(false);
    eprintln!("== m4assembly [{lane_name}]: proving child R (DISTINCT M3 witness, ~12 GB transient)... ==");
    let (sched_r, opvs_r, leaf_r_s, leaf_r_bytes) = prove_verify_walk_leaf(true);
    debug_assert_ne!(opvs_l, opvs_r, "distinct children must have distinct opvs");

    // 棒 1/2/3: the interior root proof at the selected lane.
    eprintln!("== m4assembly [{lane_name}]: building + proving the interior root (peak-footprint segment)... ==");
    let shape = GateShape::wide();
    let n_opvs = shape.n_opvs();
    let (trace, meta) = build_interior_trace(&sched_l, &sched_r, &opvs_l, &opvs_r, &shape, cfg.log_blowup);
    let n_rows = trace.height();
    let config = make_config_with(&cfg);
    let air = VerifierGateAir::new_interior();
    let int_t = Instant::now();
    let proof = prove(&config, &air, trace, &meta.opvs);
    let interior_s = int_t.elapsed().as_secs_f64();

    // Full native verification chain, root-side.
    eprintln!("== m4assembly [{lane_name}]: native-verifying the interior root proof... ==");
    verify(&config, &air, &proof, &meta.opvs).expect("native verify of the interior root proof");
    let interior_bytes = bincode::serialize(&proof).expect("bincode").len();

    // Issue #24 consumer-side invariant — HARD ASSERTION (the whole point of 棒 1).
    assert!(
        consumer_root_ok(&meta.opvs, &opvs_l, &opvs_r, n_opvs),
        "issue #24 consumer check FAILED: interior root pv != keccak-merge(opvsL, opvsR)"
    );
    // 棒 3-3 epoch Σfee rider — HARD ASSERTION: the exposed root Σfee equals the
    // two children's summed fees (public data).
    assert!(
        consumer_fee_ok(&meta.opvs, &opvs_l, &opvs_r, n_opvs),
        "epoch Σfee consumer check FAILED: root Σfee != fee(childL) + fee(childR) over verified opvs"
    );
    // Report the exposed Σfee limbs (Monty-scaled, per the R-homogeneous pv
    // interface — the consumer de-scales + carry-recombines to the plain total).
    let sfee_base = 2 * n_opvs + MERGE_ROOT_LIMBS;
    let sfee: Vec<Val> = meta.opvs[sfee_base..sfee_base + EPOCH_FEE_LIMBS].to_vec();

    let tree_s = tree_t.elapsed().as_secs_f64();
    let kb = |b: usize| b as f64 / 1024.0;

    println!("## Whole-tree assembly — lane {lane_name}");
    println!();
    println!("| segment | wall s | fixed proof |");
    println!("|---|---|---|");
    println!("| leaf L (b4/q40) | {leaf_l_s:.2} | {:.1} KB |", kb(leaf_l_bytes));
    println!("| leaf R (b4/q40, distinct) | {leaf_r_s:.2} | {:.1} KB |", kb(leaf_r_bytes));
    println!("| interior root ({lane_name}) | {interior_s:.2} | {:.2} MB |", kb(interior_bytes) / 1024.0);
    println!("| **whole tree (2 leaf + 1 interior)** | **{tree_s:.2}** | — |");
    println!();
    println!("- interior rows: {n_rows} (2^{}).", n_rows.trailing_zeros());
    println!("- native verification chain: both leaves + interior root all verified; issue #24 consumer check PASSED (`root == keccak-merge(opvsL, opvsR)`).");
    println!("- epoch Σfee rider: exposed + bound (`Σfee == feeL + feeR`); consumer check PASSED. Σfee limbs (Monty-scaled) = {sfee:?}.");
    println!();
    println!(
        "Peak footprint: read `phys_footprint` (peak) / `maximum resident set size` from the \
         `/usr/bin/time -l` line wrapping THIS process — attributable to the interior segment. \
         Reproduce each headline lane twice; b4 and b2 both. The §7.3 per-level operating-point \
         call is the coordinator's — this driver reports numbers only."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The issue #24 consumer predicate is exact and tamper-sensitive, tested
    /// cheaply (no proving) on synthetic opvs: a matching root passes; any
    /// perturbed root limb fails. This is the predicate the driver hard-asserts.
    #[test]
    fn consumer_root_predicate_binds() {
        let opvs_l: Vec<Val> = (0..40u32).map(Val::from_u32).collect();
        let opvs_r: Vec<Val> = (100..140u32).map(Val::from_u32).collect();
        let n_opvs = opvs_l.len();
        let root = merge_root(&opvs_l, &opvs_r);
        assert_eq!(root.len(), MERGE_ROOT_LIMBS);

        // Honest interior opvs = [opvsL | opvsR | merge_root].
        let mut interior = opvs_l.clone();
        interior.extend_from_slice(&opvs_r);
        interior.extend_from_slice(&root);
        assert!(consumer_root_ok(&interior, &opvs_l, &opvs_r, n_opvs), "honest root must pass");

        // Tamper each root limb in turn → predicate must reject.
        for j in 0..MERGE_ROOT_LIMBS {
            let mut bad = interior.clone();
            bad[2 * n_opvs + j] += Val::ONE;
            assert!(!consumer_root_ok(&bad, &opvs_l, &opvs_r, n_opvs), "tampered root limb {j} must fail");
        }
        // Wrong child opvs (would change the native merge) → reject.
        let mut other_r = opvs_r.clone();
        other_r[0] += Val::ONE;
        assert!(!consumer_root_ok(&interior, &opvs_l, &other_r, n_opvs), "mismatched child opvs must fail");
    }

    /// The epoch Σfee consumer predicate recomputes the expected sum from the
    /// (verified) children's opvs: an honest exposed Σfee passes; a tampered
    /// exposed Σfee, or a child whose fee differs from what the sum was built
    /// from, fails. Cheap synthetic opvs (fee = the opvs tail).
    #[test]
    fn consumer_fee_predicate_binds() {
        let opvs_l: Vec<Val> = (0..40u32).map(Val::from_u32).collect();
        let opvs_r: Vec<Val> = (100..140u32).map(Val::from_u32).collect();
        let n_opvs = opvs_l.len();
        // Honest interior opvs = [opvsL | opvsR | merge_root | Σfee]. The exposed
        // Σfee is the circuit's value = (feeL + feeR)·rr = epoch_fee_sum_expected.
        let mut interior = opvs_l.clone();
        interior.extend_from_slice(&opvs_r);
        interior.extend_from_slice(&merge_root(&opvs_l, &opvs_r));
        interior.extend_from_slice(&epoch_fee_sum_expected(&opvs_l, &opvs_r));
        assert!(consumer_fee_ok(&interior, &opvs_l, &opvs_r, n_opvs), "honest Σfee must pass");

        let sfee_base = 2 * n_opvs + MERGE_ROOT_LIMBS;
        // Tamper the exposed Σfee → reject.
        for j in 0..EPOCH_FEE_LIMBS {
            let mut bad = interior.clone();
            bad[sfee_base + j] += Val::ONE;
            assert!(!consumer_fee_ok(&bad, &opvs_l, &opvs_r, n_opvs), "tampered Σfee limb {j} must fail");
        }
        // A child whose real fee differs from the exposed sum's basis → reject
        // (the consumer recomputes from its OWN verified children).
        let mut real_r = opvs_r.clone();
        real_r[n_opvs - EPOCH_FEE_LIMBS] += Val::ONE; // childR fee tail differs
        assert!(!consumer_fee_ok(&interior, &opvs_l, &real_r, n_opvs), "child fee mismatch must fail");
    }
}
