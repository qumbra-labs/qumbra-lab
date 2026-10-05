//! Lab #896 seam E1: the **v2** (Candidate A authorization) shape identities,
//! beside v1 and changing nothing of it.
//!
//! A net runs exactly one version, chosen by its genesis (seam E2's
//! `L2AuthForm` axis), so the v2 entries are separate functions rather than a
//! version parameter on the v1 ones: a v1 caller cannot reach a v2 verifier
//! by accident, and every v1 entry, pin and golden is byte-identical.
//!
//! v2 differs from v1 by the AIRs (`qlab_air::l2{,p,r}` with
//! `L2Version::V2Auth`, seams B/C/D) and by the public values: each
//! authorization slot's leaf (`mldsa_leaf(index, vk)`, four lanes → 16
//! 16-bit chunks) is appended after the v1 PVs.

use std::sync::OnceLock;

use p3_uni_stark::{prove, verify};

use qlab_air::{l2, l2p, l2r};

use crate::{
    make_config_l2, public_values, pv_in_range, pv_u32_in_range, Config, Proof, Shape, Val, L2_CFG,
};

/// v2 geometry of `shape`.
pub const fn width(shape: Shape) -> usize {
    match shape {
        Shape::S => l2::L2_WIDTH_V2,
        Shape::P => l2p::L2P_WIDTH_V2,
        Shape::R => l2r::L2R_WIDTH_V2,
    }
}

/// log2 of the v2 trace height: S and P 2^20, R 2^19.
pub const fn log_height(shape: Shape) -> usize {
    match shape {
        Shape::S => l2::SHAPE_S_LOG_HEIGHT_V2,
        Shape::P => l2p::SHAPE_P_LOG_HEIGHT,
        Shape::R => l2r::SHAPE_R_LOG_HEIGHT_V2,
    }
}

/// v2 program perms, including the leading dummy slot (S 194, P 288, R 94).
pub const fn perms(shape: Shape) -> usize {
    match shape {
        Shape::S => l2::SHAPE_S_PERMS_V2,
        Shape::P => l2p::SHAPE_P_PERMS_V2,
        Shape::R => l2r::SHAPE_R_PERMS_V2,
    }
}

/// v2 public-value length (S 164, P 192, R 117).
pub const fn pv_len(shape: Shape) -> usize {
    match shape {
        Shape::S => l2::PV_LEN_V2,
        Shape::P => l2p::PV_LEN_V2,
        Shape::R => l2r::PV_LEN_V2,
    }
}

/// Authorization slots, i.e. leaf PVs (S/P 3, R 1).
pub const fn auth_slots(shape: Shape) -> usize {
    match shape {
        Shape::S | Shape::P => 3,
        Shape::R => 1,
    }
}

/// Offset of slot `k`'s leaf (16 chunks) in the v2 PV vector.
pub const fn pv_leaf(shape: Shape, k: usize) -> usize {
    match shape {
        Shape::S => l2::PV_LEAF1 + 16 * k,
        Shape::P => l2p::PV_LEAF1 + 16 * k,
        Shape::R => l2r::PV_LEAF,
    }
}

/// The v2 PV range premise (lab #758): v1's bits, then 16 bits per leaf chunk.
pub fn audit_pv_bits(shape: Shape) -> Vec<u32> {
    let mut b = match shape {
        Shape::S => l2::audit_pv_bits(),
        Shape::P => l2p::audit_pv_bits(),
        Shape::R => l2r::audit_pv_bits(),
    };
    b.resize(pv_len(shape), 16);
    b
}

/// The canonical v2 program of `shape`, read off the fabricated v2 builders
/// (every v2 builder emits the same program; the verifier AIR reads only it).
pub fn canonical_program(shape: Shape) -> &'static [u32] {
    static S: OnceLock<Vec<u32>> = OnceLock::new();
    static P: OnceLock<Vec<u32>> = OnceLock::new();
    static R: OnceLock<Vec<u32>> = OnceLock::new();
    match shape {
        Shape::S => S.get_or_init(|| l2::fabricated_bucket_l2_v2().air.program),
        Shape::P => P.get_or_init(|| l2p::fabricated_bucket_l2p_v2().air.program),
        Shape::R => R.get_or_init(|| l2r::fabricated_shape_r_v2().inst.air.program),
    }
}

/// The witness-free v2 AIRs a verifier uses.
pub fn verifier_air_s() -> l2::L2ShapeSAir {
    l2::L2ShapeSAir {
        program: canonical_program(Shape::S).to_vec(),
        ..l2::L2ShapeSAir::chain_only_v2(log_height(Shape::S))
    }
}

pub fn verifier_air_p() -> l2p::L2ShapePAir {
    l2p::L2ShapePAir {
        program: canonical_program(Shape::P).to_vec(),
        ..l2p::L2ShapePAir::chain_only_v2(log_height(Shape::P))
    }
}

pub fn verifier_air_r() -> l2r::L2ShapeRAir {
    let canon = l2r::verifier_air_r_v2();
    l2r::L2ShapeRAir {
        program: canonical_program(Shape::R).to_vec(),
        ..canon
    }
}

// ---------------------------------------------------------------- prove

// The v2 `prove_*` take `(air, u32 PVs)` rather than an instance type: the
// three v2 builders return three different instance structs.

/// Prove a v2 shape-S instance (its AIR and `u32` PVs) under the L2 lane.
pub fn prove_s(air: &l2::L2ShapeSAir, pvs: &[u32]) -> (Vec<Val>, Proof<Config>) {
    assert!(
        air.is_v2() && air.log_height == log_height(Shape::S),
        "a v2 shape-S instance at 2^20"
    );
    let pvs = public_values(pvs);
    let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), air, trace, &pvs);
    (pvs, proof)
}

pub fn prove_p(air: &l2p::L2ShapePAir, pvs: &[u32]) -> (Vec<Val>, Proof<Config>) {
    assert!(
        air.is_v2() && air.log_height == log_height(Shape::P),
        "a v2 shape-P instance at 2^20"
    );
    let pvs = public_values(pvs);
    let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), air, trace, &pvs);
    (pvs, proof)
}

pub fn prove_r(air: &l2r::L2ShapeRAir, pvs: &[u32]) -> (Vec<Val>, Proof<Config>) {
    assert!(
        air.is_v2() && air.log_height == log_height(Shape::R),
        "a v2 shape-R instance at 2^19"
    );
    let pvs = public_values(pvs);
    let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), air, trace, &pvs);
    (pvs, proof)
}

// ---------------------------------------------------------------- verify

/// `true` iff `proof` is a valid v2 shape-S proof for `pvs` under the L2
/// lane. A wrong-length or out-of-range PV vector is refused first.
pub fn verify_s(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pv_in_range(pvs, &audit_pv_bits(Shape::S))
        && verify(&make_config_l2(), &verifier_air_s(), proof, pvs).is_ok()
}

pub fn verify_p(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pv_in_range(pvs, &audit_pv_bits(Shape::P))
        && verify(&make_config_l2(), &verifier_air_p(), proof, pvs).is_ok()
}

pub fn verify_r(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pv_in_range(pvs, &audit_pv_bits(Shape::R))
        && verify(&make_config_l2(), &verifier_air_r(), proof, pvs).is_ok()
}

/// The typed v2 entries: `u32` PVs, range-checked before the mod-p conversion
/// (the v1 `_u32` entries' rule).
pub fn verify_s_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &audit_pv_bits(Shape::S)) && verify_s(&public_values(pvs), proof)
}

pub fn verify_p_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &audit_pv_bits(Shape::P)) && verify_p(&public_values(pvs), proof)
}

pub fn verify_r_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &audit_pv_bits(Shape::R)) && verify_r(&public_values(pvs), proof)
}
