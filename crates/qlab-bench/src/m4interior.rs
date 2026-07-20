//! M4 step 1 stage 2 (棒 2/3): the interior aggregation node — verify TWO child
//! leaf proofs in one rectangle and merge their public digests into the interior
//! root. Circuit analogue of `m4treerec` (which only records one child). The
//! two-child trace assembly lives in `m4gate::build_interior_trace`; this module
//! sources the child schedules and (stage 3) drives the full `prove` for the
//! peak-RSS-vs-32 GB gate.

use crate::m4gaterec::Schedule;
use crate::Val;

/// Two child verification schedules + their outer public values.
///
/// - `distinct == false` (2c): reuse ONE leaf proof for both children. Sufficient
///   for two-child SAT, per-lane tamper binding, and the stage-3 RSS gate, and it
///   halves the ~0.67 s / ~12 GB leaf prove. `opvs_l == opvs_r`, so a single
///   outer-PV set serves both cap comparisons.
/// - `distinct == true` (2d PR-gate): a second, different leaf proof so `L != R`
///   — this catches symmetry / cross-wiring bugs that identical children mask.
pub(crate) fn two_child_schedule(distinct: bool) -> (Schedule, Schedule, Vec<Val>, Vec<Val>) {
    let (leaf_l, opvs_l) = crate::m4treerec::leaf_proof();
    let sched_l = crate::m4treerec::walk_leaf(&leaf_l, &opvs_l);
    if !distinct {
        // Same leaf for both children: re-walk (cheap, ~ms) rather than require
        // Schedule: Clone. The expensive part (the ~12 GB leaf prove) runs once.
        let sched_r = crate::m4treerec::walk_leaf(&leaf_l, &opvs_l);
        return (sched_l, sched_r, opvs_l.clone(), opvs_l);
    }
    // 2d: prove a distinct child (a different M3 witness) via
    // `m4treerec::leaf_proof_variant` (added in that slice).
    unimplemented!("distinct children land in slice 2d (leaf_proof_variant)")
}

/// `m4interior` bench mode (stage 3): prove the full two-child interior at b4 and
/// report prove time + peak RSS vs aggregation-rung1 §6's ≤ 30 s / ≤ 32 GB gate.
/// Implemented in stage 3 (after 棒 3 lands).
pub(crate) fn run_m4interior(_power: &str) {
    unimplemented!("m4interior bench (stage-3 prove + peak RSS) is implemented in stage 3")
}
