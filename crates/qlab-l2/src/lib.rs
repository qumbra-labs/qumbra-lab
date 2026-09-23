//! qlab-l2 — the Annulet (Qumbra L2) consensus crate: what `qlab-consensus` is
//! for the L1, for the L2 transaction circuit family (lab issue #704,
//! l2-roadmap A1; design `l2-own-circuit-decision.md` §2).
//!
//! It owns:
//!
//! - **the L2 lane** — [`L2_CFG_PROVISIONAL`] and [`make_config_l2`], the one
//!   site where the L2's `StarkConfig` is built. **Provisional**: the #704
//!   ruling parks the lane freeze behind a coordinator-side review of the
//!   lane's PCS configuration, so no proof-wire byte count is pinned here.
//! - **the shapes** — [`Shape`] with its geometry and PV layout, re-exported
//!   from `qlab-air` (never re-typed), the canonical program, and the
//!   [`digest`] that pins each shape's v1 constants and constraint set.
//! - **prove / verify** — [`prove_s`]/[`verify_s`], [`prove_p`]/[`verify_p`].
//!   Verification takes no instance: both AIRs' `eval` read exactly one struct
//!   field, `program`, so the verifier's AIR is a pure function of the shape
//!   ([`verifier_air_s`], [`verifier_air_p`]; lab #704 P13, locked by
//!   `l2_verifier_air_is_instance_independent`).
//! - **fixtures** — the deterministic instances W3 measured ([`fixture`]).
//!
//! Workspace dependencies are exactly `qlab-air` + `qlab-consensus`
//! (`l2_crate_deps_are_exactly_air_and_consensus`).

use std::sync::OnceLock;

use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};

pub use qlab_consensus::{Config, FriCfg, Proof, Val};

pub use qlab_air::l2::{
    pv_vec_l2 as pv_vec_s, L2BucketInstance, L2ShapeSAir, L2TxInput, L2TxOutput, RegistryLeaf,
    ASSET_BITS, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED, PV_ANCHOR, PV_CM1, PV_CM2, PV_FEE,
    PV_NF1, PV_NF2, PV_REGROOT, REGISTRY_DEPTH,
};
pub use qlab_air::l2p::{
    pv_vec_l2p as pv_vec_p, L2PBucketInstance, L2ShapePAir, PolicyAsset, VPublic, ALLOW_DEPTH,
    FLAG_REDEEM_OPEN, FREEZE_DEPTH, PV_VP1, PV_VP2,
};

pub mod digest;
pub mod fixture;

// ---------------------------------------------------------------------------
// The lane
// ---------------------------------------------------------------------------

/// The L2 lane — **PROVISIONAL**: **b4/q43/g22/fp16/a16**.
///
/// **Not frozen.** The lab #704 ruling parks the lane freeze behind a
/// coordinator-side review of the lane's PCS configuration, whose outcome can
/// move the proof wire without touching the AIRs. Hence no wire-byte pin
/// exists for the L2; the bytes measured under this lane (S 285,605 B,
/// P 312,677 B at `docs/w3-run{1..4}.md`) are recorded in
/// `docs/l2-shape-v1.md` as measurements, not pins.
///
/// **Why b4 — the only lane at degree 4.** Both shapes have max constraint
/// degree 4, i.e. 4 quotient chunks. At b2 (`log_blowup = 1`) the quotient
/// domain (4N) exceeds the committed LDE (2N), Plonky3 0.6.1 re-extends
/// through the iDFT fallback and `verify` rejects with
/// `OodEvaluationMismatch` — pinned by `qlab-bench`'s
/// `l2shape_b2_is_not_a_lane_for_a_degree_4_air`. b4 is the smallest blowup
/// that works; b8 costs 2.0× the RAM for −28 % bytes (W3 stage 1). Queries:
/// q43 at g22 = 43 × 1.853 + 22 = 101.6 bits under the 2197-corrected
/// accounting (`fri-soundness-accounting-2026-07.md` §6).
///
/// Equal in value to the M4 leaf lane (`qlab-bench`'s `AGG_CFG`) and
/// deliberately **not** cross-locked to it: the two lanes may diverge.
pub const L2_CFG_PROVISIONAL: FriCfg = FriCfg {
    log_blowup: 2,
    num_queries: 43,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// The L2 `StarkConfig` — **the one site** where the L2's PCS and FRI
/// parameters are chosen, so a lane or PCS change is one edit here.
pub fn make_config_l2() -> Config {
    qlab_consensus::make_config_with(&L2_CFG_PROVISIONAL)
}

// ---------------------------------------------------------------------------
// The shapes
// ---------------------------------------------------------------------------

/// log2 of the shape-S trace height (120 perms → 2^19).
pub const LOG_HEIGHT_S: usize = qlab_air::l2::SHAPE_S_LOG_HEIGHT;
/// log2 of the shape-P trace height (214 perms → 2^20).
pub const LOG_HEIGHT_P: usize = qlab_air::l2p::SHAPE_P_LOG_HEIGHT;

/// A shape of the L2 transaction circuit family. The shape is public, as
/// bucket arity is on L1 (`l2-own-circuit-decision` §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shape {
    /// Sovereign assets (Cloaked): the L1 statement + registry openings.
    S,
    /// Policy assets (Hybrid / Regulated): S + freeze non-membership +
    /// allowlist membership + `vPublic`.
    P,
}

impl Shape {
    /// Trace width (columns).
    pub const fn width(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::L2_WIDTH,
            Shape::P => qlab_air::l2p::L2P_WIDTH,
        }
    }
    /// log2 of the trace height.
    pub const fn log_height(self) -> usize {
        match self {
            Shape::S => LOG_HEIGHT_S,
            Shape::P => LOG_HEIGHT_P,
        }
    }
    /// Program perms, including the leading dummy warm-up slot.
    pub const fn perms(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::SHAPE_S_PERMS,
            Shape::P => qlab_air::l2p::SHAPE_P_PERMS,
        }
    }
    /// Public-value vector length.
    pub const fn pv_len(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::PV_LEN,
            Shape::P => qlab_air::l2p::PV_LEN,
        }
    }
    /// Offset of the row-`k` `vPublic` block (`redeem`, four 16-bit chunks of
    /// `amount`, `vpa`) — shape P only.
    pub const fn pv_vpublic(self, k: usize) -> Option<usize> {
        match self {
            Shape::S => None,
            Shape::P => Some(if k == 0 { PV_VP1 } else { PV_VP2 }),
        }
    }
}

/// The canonical program of `shape`: the role code of every program slot.
/// Read off the fixture's builder — every builder emits the same program
/// (`l2_verifier_air_is_instance_independent`), and `digest` pins it.
pub fn canonical_program(shape: Shape) -> &'static [u32] {
    static S: OnceLock<Vec<u32>> = OnceLock::new();
    static P: OnceLock<Vec<u32>> = OnceLock::new();
    match shape {
        Shape::S => S.get_or_init(|| fixture::shape_s().air.program.to_vec()),
        Shape::P => P.get_or_init(|| fixture::shape_p().air.program.to_vec()),
    }
}

/// The witness-free shape-S AIR a verifier uses.
pub fn verifier_air_s() -> L2ShapeSAir {
    L2ShapeSAir {
        program: canonical_program(Shape::S).try_into().expect("S program length"),
        ..L2ShapeSAir::chain_only(LOG_HEIGHT_S)
    }
}

/// The witness-free shape-P AIR a verifier uses.
pub fn verifier_air_p() -> L2ShapePAir {
    L2ShapePAir {
        program: canonical_program(Shape::P).try_into().expect("P program length"),
        ..L2ShapePAir::chain_only(LOG_HEIGHT_P)
    }
}

// ---------------------------------------------------------------------------
// Prove / verify
// ---------------------------------------------------------------------------

/// A public-value vector as field elements.
pub fn public_values(pvs: &[u32]) -> Vec<Val> {
    pvs.iter().map(|v| Val::from_u32(*v)).collect()
}

/// Prove a shape-S instance under the L2 lane. Returns the public values
/// alongside the proof.
pub fn prove_s(inst: &L2BucketInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_S, "shape S proves at 2^{LOG_HEIGHT_S}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG_PROVISIONAL.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// `true` iff `proof` is a valid shape-S proof for `pvs` under the L2 lane.
/// A wrong-length `pvs` is refused before verification.
pub fn verify_s(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pvs.len() == Shape::S.pv_len()
        && verify(&make_config_l2(), &verifier_air_s(), proof, pvs).is_ok()
}

/// Prove a shape-P instance under the L2 lane.
pub fn prove_p(inst: &L2PBucketInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_P, "shape P proves at 2^{LOG_HEIGHT_P}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG_PROVISIONAL.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// `true` iff `proof` is a valid shape-P proof for `pvs` under the L2 lane.
pub fn verify_p(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pvs.len() == Shape::P.pv_len()
        && verify(&make_config_l2(), &verifier_air_p(), proof, pvs).is_ok()
}

// ---------------------------------------------------------------------------
// Pins
// ---------------------------------------------------------------------------

/// The v1 shape digests (`digest::shape_digest`), lower-case hex.
pub const SHAPE_S_DIGEST_V1: &str = "PENDING";
/// See [`SHAPE_S_DIGEST_V1`].
pub const SHAPE_P_DIGEST_V1: &str = "PENDING";

#[cfg(test)]
mod tests;
