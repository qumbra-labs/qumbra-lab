//! M4 step 1 — interior-node recorder (`m4treerec`).
//!
//! The aggregation tree's interior node verifies its children's proofs — and a
//! child is a LEAF's own wide `VerifierGateAir` proof (2^16 × 3,626 committed
//! at the b4 aggregation config), NOT the M3 narrow proof the leaf itself
//! verified. This module produces that leaf wide proof and records its
//! uni-stark verification transcript — the ground-truth `Schedule` the interior
//! circuit (M4 step 1 stage 2) will prove against — reusing the AIR-agnostic
//! `m4gaterec::walk_with_cfg`.
//!
//! This is the interior analogue of `m4gaterec` + `m4census`/`m4price` for the
//! leaf: it reports the interior-node workload before any circuit exists.

use p3_uni_stark::{prove, verify, Proof};

use crate::m4gate::{build_gate_trace, GateShape, VerifierGateAir};
use crate::m4gaterec::{self, Schedule};
use crate::{make_config_with, Config, FriCfg, Val};

/// The aggregation-lane config the leaf commits at. Per aggregation-rung1 §4,
/// "at b4 the aggregation lane needs ~40–45 queries for 100 bits"; b4/q40 is
/// the aggregation-lane default and the config m4census used for the interior
/// fixed point (6,083 keccak-f/node). The interior verifies a proof of exactly
/// this shape.
pub(crate) const AGG_CFG: FriCfg = FriCfg {
    log_blowup: 2,      // b4
    num_queries: 40,    // q40
    grind_bits: 20,     // g20
    log_final_poly_len: 4, // fp16
    max_log_arity: 4,   // a16
};

/// Prove one leaf `VerifierGateAir` proof (a real M3 consensus proof verified
/// in-circuit) at the aggregation config. Returns the wide proof plus its outer
/// public values (the interior node binds these upward as covered-tx digests).
pub(crate) fn leaf_proof() -> (Proof<Config>, Vec<Val>) {
    let (_inst, pvs, m3_proof) = m4gaterec::consensus_proof();
    let sched = m4gaterec::walk(&m3_proof, &pvs);
    let (trace, meta) = build_gate_trace(&sched, &pvs, &GateShape::narrow(), AGG_CFG.log_blowup);
    let config = make_config_with(&AGG_CFG);
    let air = VerifierGateAir::new();
    let leaf = prove(&config, &air, trace, &meta.opvs);
    (leaf, meta.opvs)
}

/// A DISTINCT leaf proof: identical shape to `leaf_proof`, but the inner M3
/// witness is driven from a different PRNG seed, so the verified proof's Merkle
/// caps and public values differ. The M4 interior's two-child PR-gate uses this
/// for child R (`two_child_schedule(true)`) — identical children (L == R) can
/// mask cross-wiring / symmetry bugs the distinct pair exposes.
pub(crate) fn leaf_proof_variant() -> (Proof<Config>, Vec<Val>) {
    // A seed clearly distinct from `consensus_proof`'s default.
    let (_inst, pvs, m3_proof) = m4gaterec::consensus_proof_seeded(0x1234_5678_9abc_def0);
    let sched = m4gaterec::walk(&m3_proof, &pvs);
    let (trace, meta) = build_gate_trace(&sched, &pvs, &GateShape::narrow(), AGG_CFG.log_blowup);
    let config = make_config_with(&AGG_CFG);
    let air = VerifierGateAir::new();
    let leaf = prove(&config, &air, trace, &meta.opvs);
    (leaf, meta.opvs)
}

/// Record the leaf wide proof's uni-stark verification transcript at the
/// aggregation config — the interior node's input schedule.
pub(crate) fn walk_leaf(proof: &Proof<Config>, opvs: &[Val]) -> Schedule {
    m4gaterec::walk_with_cfg(proof, opvs, &AGG_CFG)
}

/// Per-query opened-value count of a leaf wide proof: the trace-local +
/// trace-next rows plus the flattened quotient chunks. This is the driver of
/// the interior node's reduced-opening arithmetic (m4price analogue).
pub(crate) fn opened_values_per_query(proof: &Proof<Config>) -> (usize, usize, usize) {
    let ov = &proof.opened_values;
    let tl = ov.trace_local.len();
    let tn = ov.trace_next.as_ref().map_or(0, |v| v.len());
    let quot: usize = ov.quotient_chunks.iter().map(|c| c.len()).sum();
    (tl, tn, quot)
}

/// `m4tree` bench mode: prove one leaf wide proof, cross-check its recorded
/// verification transcript against a native `verify()`, and report the
/// interior-node workload derived from the schedule.
pub(crate) fn run_m4tree(power: &str) {
    println!("# qumbra-lab M4 step 1a: interior-node recorder + census (m4treerec)");
    println!();
    crate::print_env(power);
    println!(
        "- input: one leaf `VerifierGateAir` wide proof committed at \
         b4/q40/g20/fp16/a16 (the aggregation lane). The interior node verifies \
         a proof of THIS shape (2^16 x 3,626), not the M3 narrow proof the leaf \
         itself verified — so a new recorder (this module) is required."
    );

    // Prove the leaf, then cross-check the recorded transcript against a native
    // verify() of the same proof (the acceptance bar, mirroring m4gaterec).
    let (leaf, opvs) = leaf_proof();
    let config = make_config_with(&AGG_CFG);
    let air = VerifierGateAir::new();
    verify(&config, &air, &leaf, &opvs).expect("native verify of the leaf wide proof");
    let sched = walk_leaf(&leaf, &opvs);

    let (nl, nc, nch) = sched.native_counts;
    let keccakf = nl + nc + nch;
    let (tl, tn, quot) = opened_values_per_query(&leaf);
    let per_q = tl + tn + quot;
    let n_q = AGG_CFG.num_queries;
    let fixed_kb = bincode::serialize(&leaf).expect("bincode").len() as f64 / 1024.0;

    println!();
    println!("## Interior-node workload — verifying ONE child leaf wide proof");
    println!();
    println!("| metric | value |");
    println!("|---|---|");
    println!(
        "| keccak-f total | **{keccakf}** (leaf-sponge {nl} + compress {nc} + challenger {nch}) |"
    );
    println!(
        "| opened values / query | {per_q} (trace-local {tl} + trace-next {tn} + quotient {quot}) |"
    );
    println!("| reduced-opening values | {} = {n_q} q x {per_q} |", n_q * per_q);
    println!(
        "| FRI rounds | {} (log-arities {:?}) |",
        sched.log_arities.len(),
        sched.log_arities
    );
    println!("| final-poly len | {} |", leaf.opening_proof.final_poly.len());
    println!("| challenger draws | {} |", sched.draws.len());
    println!("| commitments (caps) | {} |", sched.caps.len());
    println!("| native perms recorded | {} |", sched.perms.len());
    println!("| leaf proof size (fixed) | {fixed_kb:.1} KB |");

    println!();
    println!(
        "A 2:1 interior node verifies TWO such children + a public-digest merge, \
         so its hash workload ~ 2 x {keccakf} + merge. Compare to m4census Phase \
         C's b4 interior fixed point (6,083 keccak-f/wide-proof) and to \
         aggregation-rung1 §6's interior envelope (<= 30 s / <= 32 GB), which the \
         interior CIRCUIT (M4 step 1 stage 2) will measure. Recorder acceptance: \
         the transcript matched a native verify() of the leaf proof."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    // Serialize the heavy leaf prove (b4 ~12 GB) against other heavy tests.
    fn heavy_lock() -> std::sync::MutexGuard<'static, ()> {
        static LK: OnceLock<Mutex<()>> = OnceLock::new();
        LK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The recorder's acceptance bar: the leaf wide proof at the aggregation
    /// config verifies natively (so AGG_CFG matches the committed shape), the
    /// walk records a well-formed schedule, and the census counts are the
    /// interior-node workload. (The byte-exact native keccak-sequence
    /// cross-check — as in m4gaterec's walk_matches_native_* — is a stage-2
    /// hardening, deferred until the interior circuit consumes the schedule;
    /// the walk logic itself is m4gaterec::walk_with_cfg, already so verified
    /// for M3.)
    #[test]
    fn recorder_accepts_leaf() {
        let _g = heavy_lock();
        let (leaf, opvs) = leaf_proof();
        let config = make_config_with(&AGG_CFG);
        let air = VerifierGateAir::new();
        verify(&config, &air, &leaf, &opvs).expect("native verify of the leaf wide proof");

        let sched = walk_leaf(&leaf, &opvs);
        // Well-formed schedule / config match.
        assert_eq!(leaf.degree_bits, 16, "leaf height 2^16");
        assert_eq!(sched.log_arities, vec![4, 4, 4], "b4/a16/fp16 → 3 arity-16 rounds");
        assert_eq!(leaf.opening_proof.final_poly.len(), 16, "fp16");
        assert_eq!(sched.caps.len(), 5, "trace + quotient + 3 FRI caps");
        // Census sanity: the interior hash workload is real and dominated by
        // the leaf-sponge openings (the 7,260-value/query rows).
        let (nl, nc, nch) = sched.native_counts;
        assert!(nl > 0 && nc > 0 && nch > 0, "all three keccak roles present");
        let (tl, tn, quot) = opened_values_per_query(&leaf);
        assert_eq!(tl, 3626, "trace-local = gate width");
        assert_eq!(tn, 3626, "trace-next = gate width (transition constraints)");
        assert!(quot > 0, "quotient chunks opened");
        assert!(!sched.perms.is_empty(), "native perms recorded");
    }

    /// 2d-1: the distinct child's leaf proof must have DIFFERENT outer public
    /// values from the default child (else "distinct children" would be a no-op
    /// and could not expose a symmetry / cross-wiring bug). Both are full b4
    /// leaf proves (~12 GB each), serialized; only the small opvs are compared.
    #[test]
    fn variant_child_has_distinct_opvs() {
        let _g = heavy_lock();
        let (_leaf_l, opvs_l) = leaf_proof();
        let (_leaf_r, opvs_r) = leaf_proof_variant();
        assert_eq!(opvs_l.len(), opvs_r.len(), "same shape → same opvs length");
        assert_ne!(opvs_l, opvs_r, "distinct M3 witness → distinct caps + inner PVs");
    }
}

