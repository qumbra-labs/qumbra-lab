//! Lab #937 (D1 route 1): the **v3** shape identities — v2 plus a third
//! output, for shapes S and P only (R stays v2). Beside v1 and v2, changing
//! nothing of either: a net runs exactly one version, chosen by its genesis,
//! so the v3 entries are separate functions, as v2's are.
//!
//! v3 differs from v2 by the AIRs (`qlab_air::l2{,p}` with `L2Version::V3`)
//! and by one appended public value: the third output commitment
//! (`PV_CM3`, 16 16-bit chunks) after v2's leaves.

use std::sync::OnceLock;

use p3_uni_stark::{prove, verify};

use qlab_air::{l2, l2p};

use crate::{
    make_config_l2, public_values, pv_in_range, pv_u32_in_range, v2, Config, Proof, Shape, Val, L2_CFG,
};

fn s_or_p(shape: Shape) {
    assert!(shape != Shape::R, "shape R has no v3 (it stays v2)");
}

/// v3 geometry of `shape` (S or P).
pub fn width(shape: Shape) -> usize {
    s_or_p(shape);
    match shape {
        Shape::S => l2::L2_WIDTH_V3,
        _ => l2p::L2P_WIDTH_V3,
    }
}

/// log2 of the v3 trace height: S and P 2^20.
pub fn log_height(shape: Shape) -> usize {
    s_or_p(shape);
    match shape {
        Shape::S => l2::SHAPE_S_LOG_HEIGHT_V3,
        _ => l2p::SHAPE_P_LOG_HEIGHT,
    }
}

/// v3 program perms, including the leading dummy slot (S 197, P 291).
pub fn perms(shape: Shape) -> usize {
    s_or_p(shape);
    match shape {
        Shape::S => l2::SHAPE_S_PERMS_V3,
        _ => l2p::SHAPE_P_PERMS_V3,
    }
}

/// v3 public-value length (S 180, P 208).
pub fn pv_len(shape: Shape) -> usize {
    s_or_p(shape);
    match shape {
        Shape::S => l2::PV_LEN_V3,
        _ => l2p::PV_LEN_V3,
    }
}

/// Offset of the third output commitment (16 chunks): v2's PV length.
pub fn pv_cm3(shape: Shape) -> usize {
    s_or_p(shape);
    match shape {
        Shape::S => l2::PV_CM3,
        _ => l2p::PV_CM3,
    }
}

/// The v3 PV range premise (lab #758): v2's bits, then 16 bits per `cm3`
/// chunk.
pub fn audit_pv_bits(shape: Shape) -> Vec<u32> {
    let mut b = v2::audit_pv_bits(shape);
    b.resize(pv_len(shape), 16);
    b
}

/// The census's verifier-supplied leaf PVs: v2's offsets, unchanged.
pub fn audit_leaf_pv_inputs(shape: Shape) -> Vec<usize> {
    s_or_p(shape);
    v2::audit_leaf_pv_inputs(shape)
}

/// The canonical v3 program of `shape`, read off the fabricated v3 builders.
pub fn canonical_program(shape: Shape) -> &'static [u32] {
    static S: OnceLock<Vec<u32>> = OnceLock::new();
    static P: OnceLock<Vec<u32>> = OnceLock::new();
    s_or_p(shape);
    match shape {
        Shape::S => S.get_or_init(|| l2::fabricated_bucket_l2_v3().air.program),
        _ => P.get_or_init(|| l2p::fabricated_bucket_l2p_v3().air.program),
    }
}

/// The witness-free v3 AIRs a verifier uses.
pub fn verifier_air_s() -> l2::L2ShapeSAir {
    l2::L2ShapeSAir {
        program: canonical_program(Shape::S).to_vec(),
        ..l2::L2ShapeSAir::chain_only_v3(log_height(Shape::S))
    }
}

pub fn verifier_air_p() -> l2p::L2ShapePAir {
    l2p::L2ShapePAir {
        program: canonical_program(Shape::P).to_vec(),
        ..l2p::L2ShapePAir::chain_only_v3(log_height(Shape::P))
    }
}

// ---------------------------------------------------------------- prove

/// Prove a v3 shape-S instance (its AIR and `u32` PVs) under the L2 lane.
pub fn prove_s(air: &l2::L2ShapeSAir, pvs: &[u32]) -> (Vec<Val>, Proof<Config>) {
    assert!(
        air.version == l2::L2Version::V3 && air.log_height == log_height(Shape::S),
        "a v3 shape-S instance at 2^20"
    );
    let pvs = public_values(pvs);
    let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), air, trace, &pvs);
    (pvs, proof)
}

pub fn prove_p(air: &l2p::L2ShapePAir, pvs: &[u32]) -> (Vec<Val>, Proof<Config>) {
    assert!(
        air.version == l2::L2Version::V3 && air.log_height == log_height(Shape::P),
        "a v3 shape-P instance at 2^20"
    );
    let pvs = public_values(pvs);
    let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), air, trace, &pvs);
    (pvs, proof)
}

// ---------------------------------------------------------------- verify

/// `true` iff `proof` is a valid v3 shape-S proof for `pvs` under the L2
/// lane. A wrong-length or out-of-range PV vector is refused first.
pub fn verify_s(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pv_in_range(pvs, &audit_pv_bits(Shape::S))
        && verify(&make_config_l2(), &verifier_air_s(), proof, pvs).is_ok()
}

pub fn verify_p(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pv_in_range(pvs, &audit_pv_bits(Shape::P))
        && verify(&make_config_l2(), &verifier_air_p(), proof, pvs).is_ok()
}

pub fn verify_s_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &audit_pv_bits(Shape::S)) && verify_s(&public_values(pvs), proof)
}

pub fn verify_p_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &audit_pv_bits(Shape::P)) && verify_p(&public_values(pvs), proof)
}

// ---------------------------------------------------------------- pins

// The v3 shape digests are pinned from an `l2_goldens` run (lab #724's
// print-then-pin), in a follow-up commit on this PR.
