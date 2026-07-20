//! M4 step 1 stage 2 (棒 2/3): the interior aggregation node — verify TWO child
//! leaf proofs in one rectangle and merge their public digests into the interior
//! root. Circuit analogue of `m4treerec` (which only records one child). The
//! two-child trace assembly lives in `m4gate::build_interior_trace`; this module
//! sources the child schedules and (stage 3) drives the full `prove` for the
//! peak-RSS-vs-32 GB gate.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::m4gaterec::{keccakf, Schedule};
use crate::Val;

/// Merge-root digest length in field limbs (32-byte keccak digest = 16 u16
/// limbs, matching the cap-limb encoding in `outer_pvs`).
pub(crate) const MERGE_ROOT_LIMBS: usize = 16;

/// Overwrite-mode keccak sponge over `bytes` (the leaf-sponge convention: the
/// rate lanes are OVERWRITTEN by each block's message, the capacity is carried;
/// pad10*1). Returns each permutation's INPUT state (rate = message block,
/// capacity = previous output's capacity) plus the 32-byte digest. The
/// in-circuit merge lane replays these exact perms; 棒3-2 binds each preimage's
/// rate to the message and its capacity to the previous perm's output.
fn sponge_overwrite(bytes: &[u8]) -> (Vec<[u64; 25]>, [u8; 32]) {
    let mut msg = bytes.to_vec();
    let pad = 136 - (msg.len() % 136); // 1..=136 (never 0 → always a pad block tail)
    let start = msg.len();
    msg.resize(msg.len() + pad, 0);
    msg[start] ^= 0x01;
    *msg.last_mut().unwrap() ^= 0x80;

    let mut state = [0u64; 25];
    let mut inputs = Vec::with_capacity(msg.len() / 136);
    for block in msg.chunks(136) {
        for (l, lane) in block.chunks(8).enumerate() {
            state[l] = u64::from_le_bytes(lane.try_into().unwrap()); // OVERWRITE rate (17 lanes)
        }
        inputs.push(state);
        state = keccakf(&state);
    }
    let mut dig = [0u8; 32];
    for l in 0..4 {
        dig[8 * l..8 * l + 8].copy_from_slice(&state[l].to_le_bytes());
    }
    (inputs, dig)
}

/// Serialize public values as u32-LE bytes (every KoalaBear value is < p < 2^31,
/// so a u32 is lossless): the child's public surface (caps + covered-tx inner
/// PVs) fed to the merge sponge.
fn opvs_bytes(vals: &[Val]) -> Vec<u8> {
    let mut b = Vec::with_capacity(vals.len() * 4);
    for v in vals {
        b.extend_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
    b
}

/// The interior root's 32-byte digest, as `MERGE_ROOT_LIMBS` u16 field limbs
/// (LE), per aggregation-rung1 §2: `root = keccak( keccak(opvsL) ‖ keccak(opvsR) )`.
/// `dL/dR` commit each child's full public surface (⊇ §2's covered-tx digests).
pub(crate) fn merge_root(opvs_l: &[Val], opvs_r: &[Val]) -> Vec<Val> {
    let (_, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (_, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    let mut m = dl.to_vec();
    m.extend_from_slice(&dr); // 64 bytes → one merge block
    let (_, root) = sponge_overwrite(&m);
    root
        .chunks(2)
        .map(|c| Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32))
        .collect()
}

/// The child sub-sponge digests `(dL, dR)` as `MERGE_ROOT_LIMBS` u16 limbs each
/// (LE), i.e. `keccak(opvsL)` / `keccak(opvsR)`. The interior circuit captures dL
/// (child-L's last merge perm output) into a carry register and reads dR from
/// child-R's last perm (adjacent to the root perm); both feed the root perm.
pub(crate) fn child_digests(opvs_l: &[Val], opvs_r: &[Val]) -> (Vec<Val>, Vec<Val>) {
    let to_limbs = |d: [u8; 32]| -> Vec<Val> {
        d.chunks(2)
            .map(|c| Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32))
            .collect()
    };
    let (_, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (_, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    (to_limbs(dl), to_limbs(dr))
}

/// The merge lane's permutation INPUT states, in lane order: child-L opvs sponge,
/// child-R opvs sponge, then the root perm (absorbing `dL ‖ dR`). Appended after
/// both children's perms in `build_interior_trace`; the KeccakAir verifies each
/// permutation's keccak-f, and 棒3-2 binds the preimages to the public values.
pub(crate) fn merge_perm_inputs(opvs_l: &[Val], opvs_r: &[Val]) -> Vec<[u64; 25]> {
    let (mut inputs, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (r_inputs, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    inputs.extend(r_inputs);
    let mut m = dl.to_vec();
    m.extend_from_slice(&dr);
    let (root_inputs, _) = sponge_overwrite(&m);
    inputs.extend(root_inputs);
    inputs
}

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
    // 2d: prove a distinct child (a different M3 witness) so `L != R`.
    let (leaf_r, opvs_r) = crate::m4treerec::leaf_proof_variant();
    let sched_r = crate::m4treerec::walk_leaf(&leaf_r, &opvs_r);
    debug_assert_ne!(opvs_l, opvs_r, "distinct children must have distinct opvs");
    (sched_l, sched_r, opvs_l, opvs_r)
}

/// `m4interior` bench mode (stage 3): prove the full two-child interior at b4 and
/// report prove time + peak RSS vs aggregation-rung1 §6's ≤ 30 s / ≤ 32 GB gate.
/// Implemented in stage 3 (after 棒 3 lands).
pub(crate) fn run_m4interior(_power: &str) {
    unimplemented!("m4interior bench (stage-3 prove + peak RSS) is implemented in stage 3")
}
