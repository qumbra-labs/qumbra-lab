//! The Annulet shape-tag cross-lock (lab #706 P7).
//!
//! `qlab-devnet` may not depend on `qlab-l2` — `qumbra-ffi`'s iOS and wasm
//! builds depend on `qlab-devnet`, and `qlab-l2` brings the prover stack — so
//! the wire tag `qlab_devnet::annulet::L2ShapeTag` is a local copy of the
//! shape set. This crate sees both; the lock lives here.

use qlab_devnet::annulet::{L2ShapeTag, L2_SURFACE_LEN_P, L2_SURFACE_LEN_R, L2_SURFACE_LEN_S};
use qlab_l2::Shape;

/// Shape R (registry writes) carries its wire tag since B3b (lab #728) —
/// the sets are 1:1 again.
fn tag_of(shape: Shape) -> L2ShapeTag {
    match shape {
        Shape::S => L2ShapeTag::S,
        Shape::P => L2ShapeTag::P,
        Shape::R => L2ShapeTag::R,
    }
}

fn shape_of(tag: L2ShapeTag) -> Shape {
    match tag {
        L2ShapeTag::S => Shape::S,
        L2ShapeTag::P => Shape::P,
        L2ShapeTag::R => Shape::R,
    }
}

/// The two enums are the same set, both ways (both matches are exhaustive,
/// so a shape added on either side fails to compile here first).
#[test]
fn the_wire_tag_and_the_circuit_shape_are_one_set() {
    for shape in [Shape::S, Shape::P, Shape::R] {
        assert_eq!(shape_of(tag_of(shape)), shape);
    }
    for tag in [L2ShapeTag::S, L2ShapeTag::P, L2ShapeTag::R] {
        assert_eq!(tag_of(shape_of(tag)), tag);
        assert_eq!(L2ShapeTag::from_byte(tag.byte()), Some(tag));
    }
}

/// The surface carries exactly what the circuit's public values add over the
/// L1's: the registry root for both shapes, and the two `vPublic` rows for P
/// (the circuit's PV block per row is `redeem ‖ 4 × 16-bit amount chunks ‖
/// vpa` = 6 field elements; the wire's is `redeem u8 ‖ amount u64 ‖ asset
/// u16` = 11 bytes).
#[test]
fn the_surface_carries_the_circuits_extra_public_values() {
    assert_eq!(Shape::P.pv_len() - Shape::S.pv_len(), 2 * 6, "P adds two 6-element vPublic rows");
    assert_eq!(Shape::S.pv_vpublic(0), None);
    assert_eq!(Shape::P.pv_vpublic(0), Some(Shape::S.pv_len()));
    assert_eq!(L2_SURFACE_LEN_P - L2_SURFACE_LEN_S, 2 * (1 + 8 + 2));
    assert_eq!(L2_SURFACE_LEN_S, 1 + 32, "tag + registry_root (the 16 PV chunks at PV_REGROOT)");
    assert_eq!(qlab_l2::PV_REGROOT + 16, Shape::S.pv_len(), "registry_root is S's last PV block");
    assert_eq!(qlab_l2::ASSET_BITS, 16, "the wire's u16 asset id is the circuit's registry index");
    // R (lab #728): old root + new root + the written slot are public; the
    // surface carries the old root (tag + root, as S), the new root, and the
    // whole new leaf (15 lanes) whose lane 0 is the slot.
    assert_eq!(L2_SURFACE_LEN_R, L2_SURFACE_LEN_S + 32 + 15 * 8);
    assert_eq!(L2_SURFACE_LEN_R, 185);
    // A3 (lab #731): the seed's commitment is public too (PV_CM_SEED, 16
    // chunks appended) — carried as the transaction's second commitment, not
    // on the surface, which does not move.
    assert_eq!(Shape::R.pv_len(), 85 + 16);
    assert_eq!(
        (qlab_l2::PV_R_OLD_ROOT, qlab_l2::PV_R_NEW_ROOT, qlab_l2::PV_R_ASSET, qlab_l2::PV_R_CM_SEED),
        (52, 68, 84, 85)
    );
}
