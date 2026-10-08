use super::*;
use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
use p3_air::BaseAir;
use p3_matrix::Matrix;

/// The frozen lane's value (lab #785 F5-2, Larry's Q-L2: b4/q45, frozen for
/// v1). Moving it is a consensus change: the bundle's composed security and
/// every member proof's bytes follow it.
#[test]
fn l2_cfg_is_value_locked() {
    assert_eq!(L2_CFG.log_blowup, 2);
    assert_eq!(L2_CFG.num_queries, 45);
    assert_eq!(L2_CFG.grind_bits, 22);
    assert_eq!(L2_CFG.log_final_poly_len, 4);
    assert_eq!(L2_CFG.max_log_arity, 4);
    assert_eq!(L2_CFG.label(), "b4/q45/g22/fp16/a16");
    // 2197-corrected: 45 × 1.853 + 22 = 105.39 ≥ 104.17 = 100 + log2(18), the
    // K = 16 bundle's per-proof budget; the capacity proxy (45 × 2 + 22 =
    // 112) is asserted inside make_config_with.
    assert!(45.0 * 1.853 + 22.0 >= 100.0 + 18f64.log2());
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
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::width(&s), 721);
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::num_public_values(&s), 116);
    assert_eq!(get_max_constraint_degree::<Val, _>(&s, AirLayout::from_air::<Val>(&s)), 4);
    let p = verifier_air_p();
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::width(&p), Shape::P.width());
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::num_public_values(&p), 144);
    assert_eq!(get_max_constraint_degree::<Val, _>(&p, AirLayout::from_air::<Val>(&p)), 4);

    // A4 (S3/P3): slot 3's fee chain and `PV_NF3` appended after each
    // shape's v1 PVs.
    assert_eq!((Shape::S.width(), Shape::S.log_height(), Shape::S.perms(), Shape::S.pv_len()), (721, 19, 158, 116));
    assert_eq!((Shape::P.width(), Shape::P.log_height(), Shape::P.perms(), Shape::P.pv_len()), (804, 20, 252, 144));
    // F5-4d (lab #785): P's exit edge (+6 columns) and recipient (+16 PVs).
    assert_eq!(qlab_air::l2p::PV_XRKM, 128);
    assert_eq!((qlab_air::l2::PV_NF3, qlab_air::l2p::PV_NF3), (100, 112));
    let r = verifier_air_r();
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::width(&r), Shape::R.width());
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::num_public_values(&r), 101);
    assert_eq!(get_max_constraint_degree::<Val, _>(&r, AirLayout::from_air::<Val>(&r)), 4);
    assert_eq!((Shape::R.width(), Shape::R.log_height(), Shape::R.perms(), Shape::R.pv_len()), (734, 18, 82, 101));
    assert_eq!((PV_R_OLD_ROOT, PV_R_NEW_ROOT, PV_R_ASSET, PV_R_CM_SEED), (52, 68, 84, 85));
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
        qlab_air::l2r::build_shape_r(LOG_HEIGHT_R, &inp(90, 20, 0), &out(11, 10, 0), 10, &write, &SeedOutput { rkm: [3; 4], rseed: [4; 4] }).air.program,
        fixture::shape_r_at(LOG_HEIGHT_R + 1).air.program,
    ];
    for (i, p) in r_programs.iter().enumerate() {
        assert_eq!(&p[..], canonical_program(Shape::R), "shape-R builder {i}");
    }
}

/// Shape S through the real prover under the L2 lane (q45, frozen by lab #785
/// F5-2), verified by
/// the canonical (witness-free) AIR — the B4 API; the matrix width is read
/// off the trace `prove` is handed. A tampered public value is refused, and a
/// shape-P-length PV vector is refused before verification. **No byte pin**
/// here: the q45 bytes are the F5-2 box pass's measurements, not this test's.
#[test]
fn l2_prove_verify_roundtrip_s() {
    let inst = fixture::shape_s();
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
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

/// Shape P through the real prover under the L2 lane (~15 GB,
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
    // E1: a v1 P proof is not a v2 P proof, at either PV length.
    assert!(!v2::verify_p(&pvs, &proof));
    let mut long = pvs.clone();
    long.resize(v2::pv_len(Shape::P), Val::ZERO);
    assert!(!v2::verify_p(&long, &proof), "a v1 P proof with zero leaves is not a v2 proof");
}

/// Shape R through the real prover under the L2 lane — the
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
    let mut bad = pvs.clone();
    bad[PV_R_CM_SEED + 3] += Val::ONE;
    assert!(!verify_r(&bad, &proof), "a tampered seed commitment is refused (A3)");
    assert!(!verify_r(&pvs[..85], &proof), "A2's 85-value surface is not an R surface any more");
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
    // A4 appended slot 3's nullifier; the v1 prefixes do not move.
    let (pv_s, pv_p) = (fixture::shape_s().pvs, fixture::shape_p().pvs);
    assert_eq!(pv_s[..100], GOLDEN_PV_S, "shape-S fixture PVs — the v1 prefix, byte for byte");
    assert_eq!(pv_s[100..], GOLDEN_PV_NF3, "shape-S fixture PVs — A4's nf3");
    assert_eq!(pv_p[..112], GOLDEN_PV_P, "shape-P fixture PVs — the v1 prefix, byte for byte");
    assert_eq!(pv_p[112..128], GOLDEN_PV_NF3, "shape-P fixture PVs — A4's nf3 (the same dummy slot 3)");
    assert_eq!(pv_p[128..], [0; 16], "shape-P fixture PVs — F5-4d's exit recipient, zero on a non-exit");
    // A3 appended the seed's commitment; A2's 85 values do not move.
    let pv_r = fixture::shape_r().pvs;
    assert_eq!(pv_r[..85], GOLDEN_PV_R, "shape-R fixture PVs — A2's prefix, byte for byte");
    assert_eq!(pv_r[85..], GOLDEN_PV_R_SEED, "shape-R fixture PVs — A3's seed commitment");
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
/// A4: the S/P fixtures' slot-3 nullifier (`PV_NF3..`) — the dummy fee
/// input both fixtures derive from input 1's ρ. From the named `l2_goldens`
/// run.
const GOLDEN_PV_NF3: [u32; 16] = [
    51833, 16215, 28991, 42064, 9855, 14274, 48732, 11757, 17817, 62036, 1191, 61283,
    34831, 47635, 28968, 37238,
];
/// A2's shape-R fixture PVs (lab #724), unchanged by A3.
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
/// A3's seed commitment for the shape-R fixture (lab #731): `PV_CM_SEED..`.
/// From the named `l2_goldens` run.
const GOLDEN_PV_R_SEED: [u32; 16] = [
    50464, 706, 23711, 6850, 64557, 55703, 13693, 8882, 29261, 54369, 37076, 54735,
    34478, 54309, 240, 48738,
];

/// Re-genesis batch 2 (lab #747): zero knowledge is live on every L2 shape at
/// rc = 0 — two proofs of the SAME witness differ and both verify, and no
/// random-codeword opening travels. Chain-only at 2^12 (as `l2shape`'s b2
/// control) keeps each shape to seconds; the L2 lane is the real one. A macro
/// because `generate_trace` is each shape's inherent method, not a trait's.
macro_rules! hiding_smoke {
    ($air:expr, $ty:ty) => {{
        let air = $air;
        let pvs = vec![Val::ZERO; <$ty as BaseAir<Val>>::num_public_values(&air)];
        let prove_once = || {
            let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
            let proof = prove(&make_config_l2(), &air, trace, &pvs);
            assert!(verify(&make_config_l2(), &air, &proof, &pvs).is_ok(), "a hiding L2 proof verifies");
            for round in &proof.opening_proof.0 {
                for mat in round {
                    for point in mat {
                        assert!(point.is_empty(), "rc = 0: no random-codeword opening travels");
                    }
                }
            }
            bincode::serialize(&proof).expect("bincode")
        };
        let (p1, p2) = (prove_once(), prove_once());
        assert_eq!(p1.len(), p2.len(), "same shape, same size");
        assert_ne!(p1, p2, "two proofs of one witness must differ");
    }};
}

#[test]
fn shape_s_two_proofs_of_one_witness_differ_and_both_verify() {
    hiding_smoke!(L2ShapeSAir::chain_only(12), L2ShapeSAir);
}

#[test]
fn shape_p_two_proofs_of_one_witness_differ_and_both_verify() {
    hiding_smoke!(qlab_air::l2p::L2ShapePAir::chain_only(12), qlab_air::l2p::L2ShapePAir);
}

#[test]
fn shape_r_two_proofs_of_one_witness_differ_and_both_verify() {
    hiding_smoke!(qlab_air::l2r::L2ShapeRAir::chain_only(12), qlab_air::l2r::L2ShapeRAir);
}

#[test]
fn claim_two_proofs_of_one_witness_differ_and_both_verify() {
    hiding_smoke!(qlab_air::claim::ClaimAir::chain_only(12), qlab_air::claim::ClaimAir);
}

/// Lab #758's public-value range premise, at the L2 verifiers: the fixtures'
/// honest vectors sit inside every declared range, and one chunk pushed to
/// 2^16 (or a `redeem` to 2) is outside — `verify_s/p/r` refuse such a
/// vector before reading the proof.
#[test]
fn l2_pv_range_premise_holds_and_is_enforced() {
    let s = public_values(&fixture::shape_s().pvs);
    let p = public_values(&fixture::shape_p().pvs);
    let r = public_values(&fixture::shape_r().pvs);
    let (bs, bp, br) = (qlab_air::l2::audit_pv_bits(), qlab_air::l2p::audit_pv_bits(), qlab_air::l2r::audit_pv_bits());
    assert!(pv_in_range(&s, &bs) && pv_in_range(&p, &bp) && pv_in_range(&r, &br), "the honest vectors");
    let mut bad = s.clone();
    bad[PV_FEE] += Val::from_u32(1 << 16);
    assert!(!pv_in_range(&bad, &bs), "a fee chunk ≥ 2^16");
    let mut bad = p.clone();
    bad[PV_VP1] = Val::TWO;
    assert!(!pv_in_range(&bad, &bp), "a redeem flag of 2");
    let mut bad = r.clone();
    bad[PV_R_NEW_ROOT + 7] += Val::from_u32(1 << 16);
    assert!(!pv_in_range(&bad, &br), "a root chunk ≥ 2^16");
    assert!(!pv_in_range(&s[..10], &bs), "a wrong length");
}

/// Lab #775 review R1: the typed entries' range check sees the `u32`, not
/// its mod-p reduction — `p + x` is refused where [`pv_in_range`] would
/// accept it as `x`, and a 32-bit position refuses `v ≥ p`.
#[test]
fn l2_u32_entries_refuse_words_above_their_width_before_reduction() {
    use p3_field::PrimeField32;
    let p = Val::ORDER_U32;
    let bits = [16, 32, 1];
    assert!(pv_u32_in_range(&[0xffff, p - 1, 1], &bits));
    assert!(!pv_u32_in_range(&[p + 3, 0, 0], &bits), "p + x at a 16-bit position");
    assert!(pv_in_range(&public_values(&[p + 3, 0, 0]), &bits), "the reduced check accepts it as x");
    assert!(!pv_u32_in_range(&[0, p, 0], &bits), "a 32-bit position at p");
    assert!(!pv_u32_in_range(&[0, u32::MAX, 0], &bits));
    assert!(!pv_u32_in_range(&[0, 0, 2], &bits), "a 1-bit position at 2");
    assert!(!pv_u32_in_range(&[0, 0], &bits), "the length");
}

/// Lab #896 seam B: shape S **v2** (Candidate A authorization) through the
/// real prover at 2^20, verified by the witness-free v2 AIR; degree still 4;
/// a tampered authorization leaf is refused. The v1 lane, shape and digest
/// are untouched (`l2_shape_digests_are_pinned`, `l2_shape_geometry_is_locked`).
/// Lane budget: one 2^20 S prove (≈ 2 × the 2^19 S prove, ~50 s on r7g).
#[test]
fn l2_v2_prove_verify_roundtrip_s() {
    use qlab_air::l2::{fabricated_bucket_l2_v2, verifier_air_s_v2, L2_WIDTH_V2, PV_LEAF2, PV_LEN_V2};
    let air = verifier_air_s_v2();
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::width(&air), L2_WIDTH_V2);
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::num_public_values(&air), PV_LEN_V2);
    assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);

    let inst = fabricated_bucket_l2_v2();
    assert_eq!(inst.air.program, air.program, "the verifier program is the builder's");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    assert_eq!(trace.width(), L2_WIDTH_V2);
    let proof = p3_uni_stark::prove(&make_config_l2(), &inst.air, trace, &pvs);
    assert!(p3_uni_stark::verify(&make_config_l2(), &air, &proof, &pvs).is_ok(), "honest v2 S verifies");
    let mut bad = pvs.clone();
    bad[PV_LEAF2] += Val::ONE;
    assert!(p3_uni_stark::verify(&make_config_l2(), &air, &proof, &bad).is_err(), "a tampered leaf is refused");
    // A v2 proof is not a v1 shape-S proof.
    assert!(!verify_s(&pvs[..Shape::S.pv_len()], &proof));
    // E1: the qlab-l2 v2 entry accepts it, typed and untyped, and refuses a
    // tampered leaf the same way.
    assert!(v2::verify_s(&pvs, &proof), "v2::verify_s accepts the honest proof");
    assert!(v2::verify_s_u32(&inst.pvs, &proof));
    assert!(!v2::verify_s(&bad, &proof));
    // The reverse direction without a new prove: the v2 entry refuses the
    // v1-length vector, and the v1 entry the v2-length one (above).
    assert!(!v2::verify_s(&pvs[..Shape::S.pv_len()], &proof));
    // Lab #937: a v2 proof is not a v3 proof — at v2's PV length, and with
    // a third commitment appended (zero, or a real one).
    assert!(!v3::verify_s(&pvs, &proof), "a v2 S proof at v2 length is not v3");
    let mut long = pvs.clone();
    long.resize(v3::pv_len(Shape::S), Val::ZERO);
    assert!(!v3::verify_s(&long, &proof), "a v2 S proof with cm3 = 0 is not v3");
    let v3_pvs = public_values(&qlab_air::l2::fabricated_bucket_l2_v3().pvs);
    long[v3::pv_cm3(Shape::S)..].copy_from_slice(&v3_pvs[v3::pv_cm3(Shape::S)..]);
    assert!(!v3::verify_s(&long, &proof), "a v2 S proof with a real cm3 is not v3");
}

/// Lab #937: shape S **v3** through the real prover at 2^20, verified by the
/// witness-free v3 AIR; degree still 4; a tampered `cm3` is refused; a v3
/// proof is not a v2 proof (the v2 → v3 direction rides on
/// `l2_v2_prove_verify_roundtrip_s`'s proof). Lane budget: one 2^20 S prove
/// (≈ the v2 S prove).
#[test]
fn l2_v3_prove_verify_roundtrip_s() {
    use qlab_air::l2::{fabricated_bucket_l2_v3, verifier_air_s_v3, L2_WIDTH_V3, PV_CM3, PV_LEN_V3};
    let air = verifier_air_s_v3();
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::width(&air), L2_WIDTH_V3);
    assert_eq!(<L2ShapeSAir as BaseAir<Val>>::num_public_values(&air), PV_LEN_V3);
    assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);

    let inst = fabricated_bucket_l2_v3();
    assert_eq!(inst.air.program, air.program, "the verifier program is the builder's");
    let (pvs, proof) = v3::prove_s(&inst.air, &inst.pvs);
    assert!(v3::verify_s(&pvs, &proof), "v3::verify_s accepts the honest proof");
    assert!(v3::verify_s_u32(&inst.pvs, &proof));
    let mut bad = pvs.clone();
    bad[PV_CM3] += Val::ONE;
    assert!(!v3::verify_s(&bad, &proof), "a tampered cm3 is refused");
    let mut swapped = pvs.clone();
    let (c2, c3) = (pvs[qlab_air::l2::PV_CM2..qlab_air::l2::PV_FEE].to_vec(), pvs[PV_CM3..].to_vec());
    swapped[qlab_air::l2::PV_CM2..qlab_air::l2::PV_FEE].copy_from_slice(&c3);
    swapped[PV_CM3..].copy_from_slice(&c2);
    assert!(!v3::verify_s(&swapped, &proof), "cm2/cm3 swapped are refused");
    // A v3 proof is not a v2 (nor v1) proof, at any of their lengths.
    assert!(!v2::verify_s(&pvs[..v2::pv_len(Shape::S)], &proof), "a v3 S proof is not v2");
    assert!(!v2::verify_s(&pvs, &proof));
    assert!(!verify_s(&pvs[..Shape::S.pv_len()], &proof), "a v3 S proof is not v1");
}

/// Lab #937: shape P **v3** geometry and degree, read off the witness-free
/// v3 AIR. No prove here, as for P v2 (`l2_v2_geometry_and_degree_p`): the
/// P v3 prove and memory figure is the rig measurement before the freeze.
#[test]
fn l2_v3_geometry_and_degree_p() {
    use qlab_air::l2p::{fabricated_bucket_l2p_v3, verifier_air_p_v3, L2P_WIDTH_V3, PV_LEN_V3};
    let air = verifier_air_p_v3();
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::width(&air), L2P_WIDTH_V3);
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::num_public_values(&air), PV_LEN_V3);
    assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);
    assert_eq!(fabricated_bucket_l2p_v3().air.program, air.program, "the verifier program is the builder's");
}

/// Lab #937: the v3 shape identities (S and P). Geometry read off the v3
/// verifier AIRs agrees with `v3::*`; `cm3` is the PV tail after v2's leaves;
/// the v3 digests are deterministic, distinct, and equal no v1 or v2 pin.
/// The hex pins land from an `l2_goldens` run (print-then-pin, lab #724).
#[test]
fn l2_v3_shape_identities() {
    for shape in [Shape::S, Shape::P] {
        let (w, pv) = match shape {
            Shape::S => {
                let a = v3::verifier_air_s();
                (<L2ShapeSAir as BaseAir<Val>>::width(&a), <L2ShapeSAir as BaseAir<Val>>::num_public_values(&a))
            }
            _ => {
                let a = v3::verifier_air_p();
                (<L2ShapePAir as BaseAir<Val>>::width(&a), <L2ShapePAir as BaseAir<Val>>::num_public_values(&a))
            }
        };
        assert_eq!((w, pv), (v3::width(shape), v3::pv_len(shape)), "{shape:?}");
        assert_eq!(v3::pv_cm3(shape), v2::pv_len(shape), "{shape:?}: cm3 follows v2's PVs");
        assert_eq!(v3::pv_cm3(shape) + 16, v3::pv_len(shape), "{shape:?}: cm3 is the tail");
        let fresh = match shape {
            Shape::S => qlab_air::l2::fabricated_bucket_l2_v3().air.program,
            _ => qlab_air::l2p::fabricated_bucket_l2p_v3().air.program,
        };
        assert_eq!(v3::canonical_program(shape), &fresh[..], "{shape:?}: canonical = freshly built");
        assert_eq!(v3::canonical_program(shape).iter().filter(|r| **r != qlab_air::l2::ROLE_DUMMY).count(), v3::perms(shape) - 1);
        let bits = v3::audit_pv_bits(shape);
        assert_eq!(bits.len(), v3::pv_len(shape));
        assert_eq!(bits[..v2::pv_len(shape)], v2::audit_pv_bits(shape)[..]);
        assert!(bits[v3::pv_cm3(shape)..].iter().all(|b| *b == 16));
        assert_eq!(v3::audit_leaf_pv_inputs(shape), v2::audit_leaf_pv_inputs(shape));
    }
    let d: Vec<String> = [Shape::S, Shape::P].iter().map(|s| digest::hex(&digest::shape_digest_v3(*s))).collect();
    let again: Vec<String> = [Shape::S, Shape::P].iter().map(|s| digest::hex(&digest::shape_digest_v3(*s))).collect();
    assert_eq!(d, again, "v3 digests are deterministic");
    assert_ne!(d[0], d[1]);
    for old in [SHAPE_S_DIGEST_V1, SHAPE_P_DIGEST_V1, SHAPE_R_DIGEST_V1, v2::SHAPE_S_DIGEST_V2, v2::SHAPE_P_DIGEST_V2, v2::SHAPE_R_DIGEST_V2] {
        assert!(!d.iter().any(|x| x == old), "a v3 digest equals a v1/v2 pin");
    }
    // The v3 typed entries refuse a v2-length PV vector before any proof work.
    assert!(!pv_u32_in_range(&vec![0; v2::pv_len(Shape::S)], &v3::audit_pv_bits(Shape::S)));
    assert!(!pv_u32_in_range(&vec![0; v2::pv_len(Shape::P)], &v3::audit_pv_bits(Shape::P)));
}

/// Lab #896 seam C: shape P **v2** geometry and degree, read off the
/// witness-free v2 AIR. No prove here: v1 P already peaks at 29.85 GiB at q45
/// (lab #785) and v2 is 53 columns wider — the P v2 prove + memory figure is
/// the coordinator's call (seam W's box measurement, or a dedicated lane).
#[test]
fn l2_v2_geometry_and_degree_p() {
    use qlab_air::l2p::{fabricated_bucket_l2p_v2, verifier_air_p_v2, L2P_WIDTH_V2, PV_LEN_V2};
    let air = verifier_air_p_v2();
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::width(&air), L2P_WIDTH_V2);
    assert_eq!(<L2ShapePAir as BaseAir<Val>>::num_public_values(&air), PV_LEN_V2);
    assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);
    assert_eq!(fabricated_bucket_l2p_v2().air.program, air.program, "the verifier program is the builder's");
}

/// Lab #896 seam D: shape R **v2** (Candidate A authorization) through the
/// real prover at 2^19, verified by the witness-free v2 AIR; degree still 4;
/// a tampered authorization leaf is refused. The v1 lane, shape and digest
/// are untouched (`l2_shape_digests_are_pinned`, `l2_shape_geometry_is_locked`).
/// Lane budget: one 2^19 R prove (≈ an S v1 prove, ~25 s on r7g).
#[test]
fn l2_v2_prove_verify_roundtrip_r() {
    use qlab_air::l2r::{fabricated_shape_r_v2, verifier_air_r_v2, L2R_WIDTH_V2, PV_LEAF, PV_LEN_V2};
    let air = verifier_air_r_v2();
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::width(&air), L2R_WIDTH_V2);
    assert_eq!(<L2ShapeRAir as BaseAir<Val>>::num_public_values(&air), PV_LEN_V2);
    assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);

    let inst = fabricated_shape_r_v2().inst;
    assert_eq!(inst.air.program, air.program, "the verifier program is the builder's");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    assert_eq!(trace.width(), L2R_WIDTH_V2);
    let proof = p3_uni_stark::prove(&make_config_l2(), &inst.air, trace, &pvs);
    assert!(p3_uni_stark::verify(&make_config_l2(), &air, &proof, &pvs).is_ok(), "honest v2 R verifies");
    let mut bad = pvs.clone();
    bad[PV_LEAF] += Val::ONE;
    assert!(p3_uni_stark::verify(&make_config_l2(), &air, &proof, &bad).is_err(), "a tampered leaf is refused");
    // A v2 proof is not a v1 shape-R proof.
    assert!(!verify_r(&pvs[..Shape::R.pv_len()], &proof));
    assert!(v2::verify_r(&pvs, &proof), "v2::verify_r accepts the honest proof");
    assert!(v2::verify_r_u32(&inst.pvs, &proof));
    assert!(!v2::verify_r(&bad, &proof));
    assert!(!v2::verify_r(&pvs[..Shape::R.pv_len()], &proof));
}

/// Lab #896 E1: the v2 shape identities. Geometry read off the v2 verifier
/// AIRs agrees with `v2::*`; the v2 digests are deterministic, pairwise
/// distinct, and never equal a v1 pin (different domain). The hex pins land
/// in a follow-up commit from an `l2_goldens` run (#724 precedent).
#[test]
fn l2_v2_shape_identities() {
    for shape in [Shape::S, Shape::P, Shape::R] {
        let (w, pv) = match shape {
            Shape::S => {
                let a = v2::verifier_air_s();
                (<L2ShapeSAir as BaseAir<Val>>::width(&a), <L2ShapeSAir as BaseAir<Val>>::num_public_values(&a))
            }
            Shape::P => {
                let a = v2::verifier_air_p();
                (<L2ShapePAir as BaseAir<Val>>::width(&a), <L2ShapePAir as BaseAir<Val>>::num_public_values(&a))
            }
            Shape::R => {
                let a = v2::verifier_air_r();
                (<L2ShapeRAir as BaseAir<Val>>::width(&a), <L2ShapeRAir as BaseAir<Val>>::num_public_values(&a))
            }
        };
        assert_eq!((w, pv), (v2::width(shape), v2::pv_len(shape)), "{shape:?}");
        let fresh = match shape {
            Shape::S => qlab_air::l2::fabricated_bucket_l2_v2().air.program,
            Shape::P => qlab_air::l2p::fabricated_bucket_l2p_v2().air.program,
            Shape::R => qlab_air::l2r::fabricated_shape_r_v2().inst.air.program,
        };
        assert_eq!(v2::canonical_program(shape), &fresh[..], "{shape:?}: canonical = freshly built");
        assert_eq!(v2::canonical_program(shape).iter().filter(|r| **r != qlab_air::l2::ROLE_DUMMY).count(), v2::perms(shape) - 1);
        let bits = v2::audit_pv_bits(shape);
        assert_eq!(bits.len(), v2::pv_len(shape));
        for k in 0..v2::auth_slots(shape) {
            assert!(bits[v2::pv_leaf(shape, k)..v2::pv_leaf(shape, k) + 16].iter().all(|b| *b == 16));
        }
        assert_eq!(v2::pv_leaf(shape, v2::auth_slots(shape) - 1) + 16, v2::pv_len(shape), "leaves are the tail");
    }
    let d: Vec<String> = [Shape::S, Shape::P, Shape::R].iter().map(|s| digest::hex(&digest::shape_digest_v2(*s))).collect();
    let again: Vec<String> = [Shape::S, Shape::P, Shape::R].iter().map(|s| digest::hex(&digest::shape_digest_v2(*s))).collect();
    assert_eq!(d, again, "v2 digests are deterministic");
    assert!(d[0] != d[1] && d[1] != d[2] && d[0] != d[2]);
    for v1 in [SHAPE_S_DIGEST_V1, SHAPE_P_DIGEST_V1, SHAPE_R_DIGEST_V1] {
        assert!(!d.iter().any(|x| x == v1), "a v2 digest equals a v1 pin");
    }
    // The v2 typed entries refuse a v1-length PV vector before any proof work.
    assert!(!pv_u32_in_range(&vec![0; Shape::S.pv_len()], &v2::audit_pv_bits(Shape::S)));
}

/// The leaf-derivation cross-lock (lab #896 E1): this vector is also
/// hard-coded in `qlab-remote-auth`'s annulet tests. Computed independently
/// (pycryptodome Keccak-256).
#[test]
fn l2_v2_mldsa_leaf_known_answer_is_cross_locked() {
    assert_eq!(
        digest::hex(&digest::mldsa_leaf_known_answer()),
        "75fb38f8035a154def1393c47fe147d3e40a700983ab2bd12a3facc7af0292ea"
    );
}

/// Lab #896 E1: the v2 shape digests are pinned (from the M box's
/// `l2_goldens` run at `7228a83f`). Constants, constraints (and their count)
/// and the whole digest, so a move names its half.
#[test]
fn l2_v2_shape_digests_are_pinned() {
    for (shape, pin) in [
        (Shape::S, v2::SHAPE_S_DIGEST_V2),
        (Shape::P, v2::SHAPE_P_DIGEST_V2),
        (Shape::R, v2::SHAPE_R_DIGEST_V2),
    ] {
        assert_eq!(digest::hex(&digest::shape_digest_v2(shape)), pin, "{shape:?} shape digest v2 — a moved digest is a freeze event");
    }
    for (shape, consts, constr, n) in v2::PINS_V2 {
        assert_eq!(digest::hex(&digest::constants_digest_v2(shape)), consts, "{shape:?} v2 constants");
        let (c, count) = digest::constraints_digest_v2(shape);
        assert_eq!((digest::hex(&c).as_str(), count), (constr, n), "{shape:?} v2 constraints");
    }
}

/// Lab #896 seam T (census premise): the leaf PVs the census takes as
/// verifier-supplied are exactly each slot's `pv_leaf(shape, k) .. + 16` — the
/// AIR's own leaf constants, inside the v2 PV vector, disjoint across slots —
/// and on the fabricated instances they hold the slot's leaf, chunked as the
/// node chunks it. So the premise cannot drift from the AIR.
#[test]
fn the_census_leaf_premise_is_exactly_the_airs_leaf_pvs() {
    use qlab_air::narrow::pv_chunks;
    let expect = |starts: &[usize]| -> Vec<usize> { starts.iter().flat_map(|&s| s..s + 16).collect() };
    let cases = [
        (Shape::S, vec![qlab_air::l2::PV_LEAF1, qlab_air::l2::PV_LEAF2, qlab_air::l2::PV_LEAF3]),
        (Shape::P, vec![qlab_air::l2p::PV_LEAF1, qlab_air::l2p::PV_LEAF2, qlab_air::l2p::PV_LEAF3]),
        (Shape::R, vec![qlab_air::l2r::PV_LEAF]),
    ];
    for (shape, starts) in cases {
        let got = v2::audit_leaf_pv_inputs(shape);
        assert_eq!(starts.len(), v2::auth_slots(shape), "{shape:?}: one leaf per auth slot");
        assert_eq!(got, expect(&starts), "{shape:?}: the premise is the AIR's leaf PVs");
        for (k, start) in starts.iter().enumerate() {
            assert_eq!(v2::pv_leaf(shape, k), *start, "{shape:?} slot {k}");
        }
        let mut sorted = got.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "{shape:?}: no PV named twice");
        assert!(got.iter().all(|&i| i < v2::pv_len(shape)), "{shape:?}: inside the v2 PV vector");
    }
    // The values: each slot's leaf sits at its premise PVs.
    let s = qlab_air::l2::fabricated_bucket_l2_v2();
    for (k, leaf) in s.leaves.iter().enumerate() {
        let at = v2::pv_leaf(Shape::S, k);
        assert_eq!(s.pvs[at..at + 16], pv_chunks(leaf), "S slot {k}");
    }
    let r = qlab_air::l2r::fabricated_shape_r_v2();
    let at = v2::pv_leaf(Shape::R, 0);
    assert_eq!(r.inst.pvs[at..at + 16], pv_chunks(&r.leaf), "R");
}
