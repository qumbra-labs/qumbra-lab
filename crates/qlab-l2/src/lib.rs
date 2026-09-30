//! qlab-l2 — the Annulet (Qumbra L2) consensus crate: what `qlab-consensus` is
//! for the L1, for the L2 transaction circuit family (lab issue #704,
//! l2-roadmap A1; design `l2-own-circuit-decision.md` §2).
//!
//! It owns:
//!
//! - **the L2 lane** — [`L2_CFG`] and [`make_config_l2`], the one
//!   site where the L2's `StarkConfig` is built. **Provisional**: the #704
//!   ruling parks the lane freeze behind a coordinator-side review of the
//!   lane's PCS configuration, so no proof-wire byte count is pinned here.
//! - **the shapes** — [`Shape`] with its geometry and PV layout, re-exported
//!   from `qlab-air` (never re-typed), the canonical program, and the
//!   [`digest`] that pins each shape's v1 constants and constraint set.
//! - **prove / verify** — [`prove_s`]/[`verify_s`], [`prove_p`]/[`verify_p`],
//!   [`prove_r`]/[`verify_r`] (shape R, registry writes — lab #724).
//!   Verification takes no instance: every AIR's `eval` reads exactly one
//!   struct field, `program`, so the verifier's AIR is a pure function of the
//!   shape ([`verifier_air_s`], [`verifier_air_p`], [`verifier_air_r`]; lab
//!   #704 P13, locked by `l2_verifier_air_is_instance_independent`).
//! - **the claim** — the bridge's claim proof (F1, lab #756): [`claim`]'s
//!   `prove_claim` / `verify_claim`, the verifier's burn-address and tariff
//!   checks. Not a [`Shape`].
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
pub use qlab_air::l2r::{
    pv_vec_r, L2ShapeRAir, L2ShapeRInstance, RegistryWrite, SeedOutput, PV_ASSET as PV_R_ASSET,
    PV_CM_SEED as PV_R_CM_SEED, PV_NEW_ROOT as PV_R_NEW_ROOT, PV_OLD_ROOT as PV_R_OLD_ROOT,
};

pub mod claim;
pub mod digest;
pub mod fixture;

// ---------------------------------------------------------------------------
// The lane
// ---------------------------------------------------------------------------

/// The L2 lane — **FROZEN** at **b4/q45/g22/fp16/a16** (lab #785 F5-2,
/// Larry's Q-L2, 2026-09-30).
///
/// **Why q45.** The enshrined object is the wrapper *bundle* (Q2 = B): at
/// K = 16 it carries 18 proofs (16 members, W, the deposit-sum proof), so a
/// ≥ 100-bit bundle needs each proof at 100 + log₂ 18 = 104.17 conjectured
/// bits (the union bound). q43 gave 43 × 1.853 + 22 = 101.68; **q45 gives
/// 105.39**. W's own lane moves with it (`qlab-wrapper`'s `W_V1_CFG`,
/// b2/q91 = 104.81); composed, the bundle is 101.18 bits.
///
/// **Frozen, not provisional.** The lab #704 ruling had parked the freeze
/// behind a review of the lane's PCS configuration; Q-L2 settles it for v1.
/// The lane is not in this crate's shape digest (`digest`, by design) and
/// enters the L1 frozen parameters with F5's re-genesis (F5-3). The proof
/// bytes measured at q43 (S 285,605 B, P 312,677 B at
/// `docs/w3-run{1..4}.md`) are superseded; the q45 bytes are the post-merge
/// box measurement's. qlab-bench's F2 stays on the q43 lane it was measured
/// under (`crate::f2::F2_LANE` there).
///
/// **Why b4 — the only lane at degree 4.** Both shapes have max constraint
/// degree 4, i.e. 4 quotient chunks. At b2 (`log_blowup = 1`) the quotient
/// domain (4N) exceeds the committed LDE (2N), Plonky3 0.6.1 re-extends
/// through the iDFT fallback and `verify` rejects with
/// `OodEvaluationMismatch` — pinned by `qlab-bench`'s
/// `l2shape_b2_is_not_a_lane_for_a_degree_4_air`. b4 is the smallest blowup
/// that works; b8 costs 2.0× the RAM for −28 % bytes (W3 stage 1). Queries:
/// the 2197-corrected accounting (`fri-soundness-accounting-2026-07.md` §6)
/// at β = 1.853 bits per query and g22, as above.
///
/// Once equal in value to the M4 leaf lane (`qlab-bench`'s `AGG_CFG`, q43)
/// and deliberately **not** cross-locked to it: the two lanes now differ.
pub const L2_CFG: FriCfg = FriCfg {
    log_blowup: 2,
    num_queries: 45,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// The L2 `StarkConfig` — **the one site** where the L2's PCS and FRI
/// parameters are chosen, so a lane or PCS change is one edit here.
pub fn make_config_l2() -> Config {
    qlab_consensus::make_config_with(&L2_CFG)
}

// ---------------------------------------------------------------------------
// The shapes
// ---------------------------------------------------------------------------

/// log2 of the shape-S trace height (158 perms → 2^19; A4's S3).
pub const LOG_HEIGHT_S: usize = qlab_air::l2::SHAPE_S_LOG_HEIGHT;
/// log2 of the shape-P trace height (252 perms → 2^20; A4's P3).
pub const LOG_HEIGHT_P: usize = qlab_air::l2p::SHAPE_P_LOG_HEIGHT;
/// log2 of the shape-R trace height (79 perms → 2^18).
pub const LOG_HEIGHT_R: usize = qlab_air::l2r::SHAPE_R_LOG_HEIGHT;

/// **`fee_tier_r` — a labelled PLACEHOLDER** (lab #724, fee option (c)): the
/// fee a shape-R transaction pays, in fee-unit base units, in its own asset-0
/// spend. R takes the fee as a public value; the node checks it against this
/// tier when it applies R transactions (milestone B3b), where the value moves
/// into the Annulet genesis parameters beside `fee_tier_s` / `fee_tier_p` —
/// A2 deliberately leaves the genesis and its hash untouched.
///
/// **Registration is permissionless into 65,536 slots** (asset ids are 16-bit
/// registry indices; asset 0 is the fee asset and never writable), so
/// **`fee_tier_r` is the only price on exhausting the registry's slots**. The
/// placeholder is not that price; the pilot's tariff must be.
pub const FEE_TIER_R_PLACEHOLDER: u64 = 4;

/// A shape of the L2 transaction circuit family. The shape is public, as
/// bucket arity is on L1 (`l2-own-circuit-decision` §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shape {
    /// Sovereign assets (Cloaked): the L1 statement + registry openings.
    S,
    /// Policy assets (Hybrid / Regulated): S + freeze non-membership +
    /// allowlist membership + `vPublic`.
    P,
    /// Registry writes: one slot registered (empty → leaf) or updated (leaf →
    /// leaf, issuer key proven), with a 1-in / 1-out fee spend.
    R,
}

impl Shape {
    /// Trace width (columns).
    pub const fn width(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::L2_WIDTH,
            Shape::P => qlab_air::l2p::L2P_WIDTH,
            Shape::R => qlab_air::l2r::L2R_WIDTH,
        }
    }
    /// log2 of the trace height.
    pub const fn log_height(self) -> usize {
        match self {
            Shape::S => LOG_HEIGHT_S,
            Shape::P => LOG_HEIGHT_P,
            Shape::R => LOG_HEIGHT_R,
        }
    }
    /// Program perms, including the leading dummy warm-up slot.
    pub const fn perms(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::SHAPE_S_PERMS,
            Shape::P => qlab_air::l2p::SHAPE_P_PERMS,
            Shape::R => qlab_air::l2r::SHAPE_R_PERMS,
        }
    }
    /// Public-value vector length.
    pub const fn pv_len(self) -> usize {
        match self {
            Shape::S => qlab_air::l2::PV_LEN,
            Shape::P => qlab_air::l2p::PV_LEN,
            Shape::R => qlab_air::l2r::PV_LEN,
        }
    }
    /// Offset of the row-`k` `vPublic` block (`redeem`, four 16-bit chunks of
    /// `amount`, `vpa`) — shape P only.
    pub const fn pv_vpublic(self, k: usize) -> Option<usize> {
        match self {
            Shape::S | Shape::R => None,
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
    static R: OnceLock<Vec<u32>> = OnceLock::new();
    match shape {
        Shape::S => S.get_or_init(|| fixture::shape_s().air.program.to_vec()),
        Shape::P => P.get_or_init(|| fixture::shape_p().air.program.to_vec()),
        Shape::R => R.get_or_init(|| fixture::shape_r().air.program.to_vec()),
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

/// The witness-free shape-R AIR a verifier uses.
pub fn verifier_air_r() -> L2ShapeRAir {
    L2ShapeRAir {
        program: canonical_program(Shape::R).try_into().expect("R program length"),
        ..L2ShapeRAir::chain_only(LOG_HEIGHT_R)
    }
}

// ---------------------------------------------------------------------------
// Prove / verify
// ---------------------------------------------------------------------------

/// Every public value inside the range its AIR declares
/// (`qlab_air::*::audit_pv_bits`) — lab #758's premise, enforced at the
/// verifier so a raw field element cannot carry a non-canonical chunk.
pub fn pv_in_range(pvs: &[Val], bits: &[u32]) -> bool {
    use p3_field::PrimeField32;
    pvs.len() == bits.len() && pvs.iter().zip(bits).all(|(v, b)| *b >= 32 || v.as_canonical_u32() < 1 << b)
}

/// Every **`u32`** public value inside the range its AIR declares, checked
/// BEFORE the mod-p conversion: a width `b < 32` requires `v < 2^b`, as
/// `qlab_consensus::verify_proof` (lab PR #770) does; **stricter than L1**, a
/// 32-bit position also requires `v < p`, so no word is reduced mod p on its
/// way into the verifier. (Lab #775 review R1: [`pv_in_range`] sees the
/// reduced value, so `p + x` passes it as `x`.) The `Val`-typed `verify_*`
/// entries stay public for callers that build their own PVs as field
/// elements (`qlab-bench`'s F2 and zkpeak paths, the node's verifier); a
/// verifier handed `u32` words by someone else uses the `_u32` entries.
pub fn pv_u32_in_range(pvs: &[u32], bits: &[u32]) -> bool {
    use p3_field::PrimeField32;
    pvs.len() == bits.len() && pvs.iter().zip(bits).all(|(v, b)| if *b < 32 { *v < 1 << b } else { *v < Val::ORDER_U32 })
}

/// The typed shape-S entry: `u32` PVs, range-checked before conversion.
pub fn verify_s_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &qlab_air::l2::audit_pv_bits()) && verify_s(&public_values(pvs), proof)
}

/// The typed shape-P entry.
pub fn verify_p_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &qlab_air::l2p::audit_pv_bits()) && verify_p(&public_values(pvs), proof)
}

/// The typed shape-R entry.
pub fn verify_r_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pv_u32_in_range(pvs, &qlab_air::l2r::audit_pv_bits()) && verify_r(&public_values(pvs), proof)
}

/// A public-value vector as field elements.
pub fn public_values(pvs: &[u32]) -> Vec<Val> {
    pvs.iter().map(|v| Val::from_u32(*v)).collect()
}

/// Prove a shape-S instance under the L2 lane. Returns the public values
/// alongside the proof.
pub fn prove_s(inst: &L2BucketInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_S, "shape S proves at 2^{LOG_HEIGHT_S}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// `true` iff `proof` is a valid shape-S proof for `pvs` under the L2 lane.
/// A wrong-length `pvs` is refused before verification.
pub fn verify_s(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pvs.len() == Shape::S.pv_len()
        && pv_in_range(pvs, &qlab_air::l2::audit_pv_bits())
        && verify(&make_config_l2(), &verifier_air_s(), proof, pvs).is_ok()
}

/// Prove a shape-P instance under the L2 lane.
pub fn prove_p(inst: &L2PBucketInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_P, "shape P proves at 2^{LOG_HEIGHT_P}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// `true` iff `proof` is a valid shape-P proof for `pvs` under the L2 lane.
pub fn verify_p(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pvs.len() == Shape::P.pv_len()
        && pv_in_range(pvs, &qlab_air::l2p::audit_pv_bits())
        && verify(&make_config_l2(), &verifier_air_p(), proof, pvs).is_ok()
}

/// Prove a shape-R instance under the L2 lane.
pub fn prove_r(inst: &L2ShapeRInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_R, "shape R proves at 2^{LOG_HEIGHT_R}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// `true` iff `proof` is a valid shape-R proof for `pvs` under the L2 lane.
pub fn verify_r(pvs: &[Val], proof: &Proof<Config>) -> bool {
    pvs.len() == Shape::R.pv_len()
        && pv_in_range(pvs, &qlab_air::l2r::audit_pv_bits())
        && verify(&make_config_l2(), &verifier_air_r(), proof, pvs).is_ok()
}

// ---------------------------------------------------------------------------
// Pins
// ---------------------------------------------------------------------------

/// The v1 shape digests (`digest::shape_digest`), lower-case hex.
///
/// A4 (design #283): S3/P3 — the 3×2 shapes (slot 3 the fee input,
/// `d3` exact-or-dummy) over the NF operand-order constraint. S 721 cols /
/// 158 perms / 1,113 constraints; P 798 / 252 / 1,328. Named `l2_goldens`
/// run, twice, byte-identical. F5-4d (lab #785): P's exit edge — P 804 /
/// 252 / 1,358, 144 PVs (P was `57a1bc84…f9c0`); S and R unmoved. Named
/// `l2_goldens` run, twice, byte-identical.
pub const SHAPE_S_DIGEST_V1: &str = "0bd458286dc5608d25d17c6f8b1f2652387722a6a9c82a14aa97b7b5d03cf6a2";
/// See [`SHAPE_S_DIGEST_V1`].
pub const SHAPE_P_DIGEST_V1: &str = "a072476c85f42a3f30388e0c3b5372ea230d4347829057f360b05d8924b7999c";
/// See [`SHAPE_S_DIGEST_V1`] (lab #724; A3 lab #731 on main pins `5f081f55…507f`).
/// With the NF operand-order constraint over A3 — 1,226 constraints
/// (A3's 1,225 + 1); A2+NF was `cfdc4cbd…89e0`. Named `l2_goldens` run, twice,
/// byte-identical.
pub const SHAPE_R_DIGEST_V1: &str = "f1723d5d3729c32269936e9fff02bf3986de596bce8bb174ae0c892c51d496bd";

#[cfg(test)]
mod tests;
