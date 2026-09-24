use super::*;
use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
use p3_air::BaseAir;
use p3_matrix::Matrix;

/// The provisional lane's value (lab #704 ruling: provisional, not frozen —
/// this lock guards against an *accidental* move; a deliberate one is the
/// lane review's to make, at [`make_config_l2`]).
#[test]
fn l2_cfg_provisional_is_value_locked() {
    assert_eq!(L2_CFG_PROVISIONAL.log_blowup, 2);
    assert_eq!(L2_CFG_PROVISIONAL.num_queries, 43);
    assert_eq!(L2_CFG_PROVISIONAL.grind_bits, 22);
    assert_eq!(L2_CFG_PROVISIONAL.log_final_poly_len, 4);
    assert_eq!(L2_CFG_PROVISIONAL.max_log_arity, 4);
    assert_eq!(L2_CFG_PROVISIONAL.label(), "b4/q43/g22/fp16/a16");
    // 2197-corrected: 43 × 1.853 + 22 = 101.6 ≥ 100; the capacity proxy
    // (43 × 2 + 22 = 108) is asserted inside make_config_with.
    let _ = make_config_l2();
}

/// Q3 of the #704 ruling: this crate's workspace dependencies are EXACTLY
/// `qlab-air` and `qlab-consensus` — read from `cargo metadata`, so an added
/// path dependency fails here by name.
#[test]
fn l2_crate_deps_are_exactly_air_and_consensus() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline", "--manifest-path", manifest])
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr));
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata json");
    let pkg = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == "qlab-l2")
        .expect("qlab-l2 in the workspace");
    let mut path_deps: Vec<String> = pkg["dependencies"]
        .as_array()
        .expect("dependencies")
        .iter()
        .filter(|d| d["kind"].is_null() && d.get("path").is_some_and(|p| !p.is_null()))
        .map(|d| d["name"].as_str().unwrap().to_string())
        .collect();
    path_deps.sort();
    assert_eq!(path_deps, ["qlab-air", "qlab-consensus"], "qlab-l2's workspace dependencies");
}

/// Geometry, per shape, read off the AIR the verifier uses: width, the
/// symbolic max constraint degree (4 ⇒ 4 quotient chunks — why b4 is the
/// lane), height, perms fit the height, PV length.
#[test]
fn l2_shape_geometry_is_locked() {
    let s = verifier_air_s();
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::width(&s), 702);
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::num_public_values(&s), 100);
    assert_eq!(get_max_constraint_degree::<Val, _>(&s, AirLayout::from_air::<Val>(&s)), 4);
    let p = verifier_air_p();
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::width(&p), Shape::P.width());
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::num_public_values(&p), 112);
    assert_eq!(get_max_constraint_degree::<Val, _>(&p, AirLayout::from_air::<Val>(&p)), 4);

    assert_eq!((Shape::S.width(), Shape::S.log_height(), Shape::S.perms(), Shape::S.pv_len()), (702, 19, 120, 100));
    assert_eq!((Shape::P.width(), Shape::P.log_height(), Shape::P.perms(), Shape::P.pv_len()), (778, 20, 214, 112));
    let r = verifier_air_r();
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::width(&r), Shape::R.width());
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::num_public_values(&r), 85);
    assert_eq!(get_max_constraint_degree::<Val, _>(&r, AirLayout::from_air::<Val>(&r)), 4);
    assert_eq!((Shape::R.width(), Shape::R.log_height(), Shape::R.perms(), Shape::R.pv_len()), (726, 18, 79, 85));
    assert_eq!((PV_R_OLD_ROOT, PV_R_NEW_ROOT, PV_R_ASSET), (52, 68, 84));
    assert_eq!(Shape::R.pv_vpublic(0), None);
    for sh in [Shape::S, Shape::P, Shape::R] {
        assert!(sh.perms() * qlab_air::l2::ROWS_PER_PERM <= 1 << sh.log_height(), "{sh:?} fits its height");
    }
    assert_eq!(PV_REGROOT, 84);
    assert_eq!((PV_VP1, PV_VP2), (100, 106));
    assert_eq!(Shape::P.pv_vpublic(1), Some(106));
    assert_eq!(Shape::S.pv_vpublic(0), None);
    assert_eq!(REGISTRY_DEPTH, 16);
    assert_eq!((FREEZE_DEPTH, ALLOW_DEPTH), (20, 20));
    assert_eq!(ASSET_BITS, 16);
}

/// #704 P13: the verifier's AIR is a function of the shape alone, because
/// `eval` reads only `program`. Every builder — honest, same-asset, the
/// #219 dummy slot, Regulated, a mint — emits the canonical program.
#[test]
fn l2_verifier_air_is_instance_independent() {
    use qlab_air::l2::{build_bucket_l2, build_bucket_l2_dummy1_fabricated};
    use qlab_air::l2p::{build_bucket_l2p, build_bucket_l2p_dummy1_fabricated, derive_rkm_l2};

    let inp = |seed: u64, value: u64, asset: u64| L2TxInput {
        sk: [seed, seed + 1, seed + 2, seed + 3],
        value,
        asset,
        rho: [seed + 4; 4],
        rseed: [seed + 5; 4],
        d: [seed + 6, seed + 7],
    };
    let out = |seed: u64, value: u64, asset: u64| L2TxOutput {
        value,
        asset,
        rkm: [seed; 4],
        rho: [seed + 1; 4],
        rseed: [seed + 2; 4],
    };
    let dummy = L2TxInput { sk: [9; 4], value: 0, asset: 0, rho: [8; 4], rseed: [7; 4], d: [0, 0] };

    let s_programs = [
        build_bucket_l2(LOG_HEIGHT_S, &[inp(10, 60, 0), inp(20, 40, 0)], &[out(1, 90, 0), out(2, 0, 0)], 10).air.program,
        build_bucket_l2_dummy1_fabricated(LOG_HEIGHT_S, &inp(30, 100, 7), &dummy, &[out(3, 60, 7), out(4, 40, 7)], 0).air.program,
        fixture::shape_s_at(LOG_HEIGHT_S + 1).air.program,
    ];
    for (i, p) in s_programs.iter().enumerate() {
        assert_eq!(&p[..], canonical_program(Shape::S), "shape-S builder {i}");
    }

    let isk = [0x1, 0x2, 0x3, 0x4];
    let a9 = inp(40, 50, 9);
    let reg9 = PolicyAsset::regulated(9, isk, false, &[], &[derive_rkm_l2(&a9)]);
    let p_programs = [
        // Regulated input.
        build_bucket_l2p(
            LOG_HEIGHT_P,
            &[inp(50, 20, 0), a9.clone()],
            &[out(5, 10, 0), out(6, 50, 9)],
            10,
            &[PolicyAsset::cloaked(0), reg9.clone()],
            [VPublic::NONE; 2],
        )
        .air
        .program,
        // A mint of 100 on row 2.
        build_bucket_l2p(
            LOG_HEIGHT_P,
            &[inp(60, 20, 0), inp(70, 50, 7)],
            &[out(7, 10, 0), out(8, 150, 7)],
            10,
            &[PolicyAsset::cloaked(0), PolicyAsset::hybrid(7, isk, false, &[])],
            [VPublic::NONE, VPublic::mint(100)],
        )
        .air
        .program,
        // The dummy slot.
        build_bucket_l2p_dummy1_fabricated(
            LOG_HEIGHT_P,
            &inp(80, 100, 0),
            &PolicyAsset::cloaked(0),
            &dummy,
            &[out(9, 60, 0), out(10, 30, 0)],
            10,
            [VPublic::NONE; 2],
        )
        .air
        .program,
    ];
    for (i, p) in p_programs.iter().enumerate() {
        assert_eq!(&p[..], canonical_program(Shape::P), "shape-P builder {i}");
    }

    // Shape R: a registration (REG = 1) and the fixture's update (REG = 0),
    // the latter at another height, emit one program.
    let reg = fixture::shape_r_registry();
    let new9 = RegistryLeaf { asset: 9, ..RegistryLeaf::cloaked(9) };
    let write = RegistryWrite {
        isk: [0; 4],
        old_leaf: None,
        new_leaf: new9,
        opening: qlab_air::l2r::registry_opening(&reg, 9).0,
    };
    let r_programs = [
        qlab_air::l2r::build_shape_r(LOG_HEIGHT_R, &inp(90, 20, 0), &out(11, 10, 0), 10, &write).air.program,
        fixture::shape_r_at(LOG_HEIGHT_R + 1).air.program,
    ];
    for (i, p) in r_programs.iter().enumerate() {
        assert_eq!(&p[..], canonical_program(Shape::R), "shape-R builder {i}");
    }
}

/// Shape S through the real prover under the provisional lane, verified by
/// the canonical (witness-free) AIR — the B4 API; the matrix width is read
/// off the trace `prove` is handed. A tampered public value is refused, and a
/// shape-P-length PV vector is refused before verification. **No byte pin**
/// (#704 ruling: the lane and the wire are provisional).
#[test]
fn l2_prove_verify_roundtrip_s() {
    let inst = fixture::shape_s();
    let trace = inst.air.generate_trace::<Val>(L2_CFG_PROVISIONAL.log_blowup);
    assert_eq!(trace.width(), Shape::S.width(), "width read off the matrix");
    drop(trace);
    let (pvs, proof) = prove_s(&inst);
    assert!(verify_s(&pvs, &proof), "the honest shape-S proof verifies");
    let mut bad = pvs.clone();
    bad[PV_REGROOT + 3] += Val::ONE;
    assert!(!verify_s(&bad, &proof), "a tampered registry_root is refused");
    let mut long = pvs.clone();
    long.resize(Shape::P.pv_len(), Val::ZERO);
    assert!(!verify_s(&long, &proof), "a P-length PV vector is refused");
    assert!(!verify_p(&long, &proof), "an S proof is not a P proof");
}

/// Shape P through the real prover under the provisional lane (~15 GB,
/// the heaviest test this crate carries), verified by the canonical AIR;
/// a tampered `vPublic` amount is refused.
#[test]
fn l2_prove_verify_roundtrip_p() {
    let inst = fixture::shape_p();
    let (pvs, proof) = prove_p(&inst);
    assert!(verify_p(&pvs, &proof), "the honest shape-P proof verifies");
    let mut bad = pvs.clone();
    bad[PV_VP2 + 1] += Val::ONE;
    assert!(!verify_p(&bad, &proof), "a mint claimed after the fact is refused");
    assert!(!verify_s(&pvs[..Shape::S.pv_len()], &proof), "a P proof is not an S proof");
}

/// Shape R through the real prover under the provisional lane — the
/// fixture's update of asset 7 — verified by the canonical AIR. A moved new
/// root and a moved asset id are refused; an R proof is not an S proof.
#[test]
fn l2_prove_verify_roundtrip_r() {
    let inst = fixture::shape_r();
    let (pvs, proof) = prove_r(&inst);
    assert!(verify_r(&pvs, &proof), "the honest shape-R proof verifies");
    let mut bad = pvs.clone();
    bad[PV_R_NEW_ROOT + 5] += Val::ONE;
    assert!(!verify_r(&bad, &proof), "a tampered new registry root is refused");
    let mut bad = pvs.clone();
    bad[PV_R_ASSET] = Val::from_u32(8);
    assert!(!verify_r(&bad, &proof), "a write of 7 claimed as a write of 8 is refused");
    let mut long = pvs.clone();
    long.resize(Shape::S.pv_len(), Val::ZERO);
    assert!(!verify_s(&long, &proof), "an R proof is not an S proof");
}

/// Q4: the digest is deterministic (computed twice, compared) and pinned.
/// On a mismatch the message carries the computed value.
#[test]
fn l2_shape_digests_are_pinned() {
    for (shape, pin) in [
        (Shape::S, SHAPE_S_DIGEST_V1),
        (Shape::P, SHAPE_P_DIGEST_V1),
        (Shape::R, SHAPE_R_DIGEST_V1),
    ] {
        let a = digest::shape_digest(shape);
        let b = digest::shape_digest(shape);
        assert_eq!(a, b, "{shape:?}: the shape digest is not deterministic");
        assert_eq!(digest::hex(&a), pin, "{shape:?} shape digest v1 — a moved digest is a freeze event");
    }
}

/// The fixtures' public-value vectors, hard-coded. A regression lock on the
/// PV layout and on every host hash feeding it (nullifiers, commitments, the
/// fabricated anchor and registry root).
#[test]
fn l2_golden_pv_vectors() {
    assert_eq!(fixture::shape_s().pvs, GOLDEN_PV_S, "shape-S fixture PVs");
    assert_eq!(fixture::shape_p().pvs, GOLDEN_PV_P, "shape-P fixture PVs");
    assert_eq!(fixture::shape_r().pvs, GOLDEN_PV_R, "shape-R fixture PVs");
}

const GOLDEN_PV_S: [u32; 100] = [
    47567, 50701, 8645, 268, 1401, 14377, 59103, 19368, 37372, 64110, 28058, 14795,
    41046, 41749, 54614, 20419, 39031, 11252, 22362, 59670, 41684, 44026, 40240, 48799,
    63219, 45515, 38322, 8243, 35056, 61893, 61827, 35752, 2880, 8224, 5437, 24925,
    62640, 35455, 48402, 44659, 9619, 26037, 6540, 32905, 18598, 35742, 6365, 24718,
    50688, 4143, 106, 18409, 26826, 23593, 51985, 63914, 21172, 24435, 32743, 3969,
    17483, 41042, 55144, 18434, 40570, 3114, 21344, 16856, 52164, 55263, 18540, 20940,
    6435, 293, 65194, 38136, 34738, 23990, 35723, 32617, 1000, 0, 0, 0,
    53792, 30833, 54941, 16693, 55283, 54043, 24684, 32197, 12515, 9213, 24882, 56603,
    37064, 61734, 43508, 41077,
];
const GOLDEN_PV_P: [u32; 112] = [
    47567, 50701, 8645, 268, 1401, 14377, 59103, 19368, 37372, 64110, 28058, 14795,
    41046, 41749, 54614, 20419, 39031, 11252, 22362, 59670, 41684, 44026, 40240, 48799,
    63219, 45515, 38322, 8243, 35056, 61893, 61827, 35752, 2880, 8224, 5437, 24925,
    62640, 35455, 48402, 44659, 9619, 26037, 6540, 32905, 18598, 35742, 6365, 24718,
    50688, 4143, 106, 18409, 26826, 23593, 51985, 63914, 21172, 24435, 32743, 3969,
    17483, 41042, 55144, 18434, 40570, 3114, 21344, 16856, 52164, 55263, 18540, 20940,
    6435, 293, 65194, 38136, 34738, 23990, 35723, 32617, 1000, 0, 0, 0,
    5516, 10200, 58993, 14765, 15376, 30000, 51619, 7131, 37300, 39386, 41061, 21527,
    64399, 4798, 55940, 64131, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];
const GOLDEN_PV_R: [u32; 85] = [
    40210, 52722, 42049, 47202, 16866, 52166, 40001, 49227, 20318, 14605, 28596, 16898,
    16795, 50602, 26734, 50280, 14021, 16243, 19640, 27876, 42645, 29850, 43298, 11495,
    40654, 52720, 22942, 4174, 41859, 13693, 26812, 53638, 326, 36143, 35358, 51258,
    26410, 5382, 65242, 63160, 33482, 45133, 19571, 43601, 22971, 60186, 29088, 3829,
    4, 0, 0, 0, 729, 41576, 19834, 39663, 62828, 48343, 20343, 11156,
    59798, 40184, 44693, 32699, 41413, 37638, 27109, 26826, 23596, 43144, 13309, 41900,
    1297, 62073, 47258, 33591, 46455, 7806, 53660, 31912, 45838, 16982, 8526, 31527,
    7,
];
