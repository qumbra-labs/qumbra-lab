//! The Annulet shape-tag cross-lock (lab #706 P7).
//!
//! `qlab-devnet` may not depend on `qlab-l2` — `qumbra-ffi`'s iOS and wasm
//! builds depend on `qlab-devnet`, and `qlab-l2` brings the prover stack — so
//! the wire tag `qlab_devnet::annulet::L2ShapeTag` is a local copy of the
//! shape set. This crate sees both; the lock lives here.

use qlab_devnet::annulet::{L2ShapeTag, L2_SURFACE_LEN_P, L2_SURFACE_LEN_S};
use qlab_l2::Shape;

/// Shape R (registry writes, lab #724) is a circuit before it is a wire
/// shape: the node applies R transactions from milestone B3b, which adds its
/// tag. Until then R maps to no tag — explicitly, so this match stays
/// exhaustive and B3b's tag lands here as a one-line change.
fn tag_of(shape: Shape) -> Option<L2ShapeTag> {
    match shape {
        Shape::S => Some(L2ShapeTag::S),
        Shape::P => Some(L2ShapeTag::P),
        Shape::R => None,
    }
}

fn shape_of(tag: L2ShapeTag) -> Shape {
    match tag {
        L2ShapeTag::S => Shape::S,
        L2ShapeTag::P => Shape::P,
    }
}

/// The two enums are the same set, both ways, save R before B3b (both
/// matches are exhaustive, so a shape added on either side fails to compile
/// here first).
#[test]
fn the_wire_tag_and_the_circuit_shape_are_one_set() {
    for shape in [Shape::S, Shape::P] {
        assert_eq!(tag_of(shape).map(shape_of), Some(shape));
    }
    assert_eq!(tag_of(Shape::R), None, "R has no wire tag before B3b");
    for tag in [L2ShapeTag::S, L2ShapeTag::P] {
        assert_eq!(tag_of(shape_of(tag)), Some(tag));
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
}
