//! Shape S v2 (Candidate A authorization) — lab #896 seam B.
//!
//! Cost model as `l2::tests` (lab #700 baton 3): the two honest v2 traces are
//! generated once (`OnceLock`) and scanned in full; every negative regenerates
//! its own trace and stops at the first violation, tail first. PV-only
//! negatives reuse the honest trace.

use std::sync::OnceLock;

use p3_air::{check_constraints, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use super::*;
use crate::l2test;

type F = KoalaBear;

const PROGRAM_END_V2: usize = SHAPE_S_PERMS_V2 * ROWS_PER_PERM;

fn pvs_f(pvs: &[u32]) -> Vec<F> {
    pvs.iter().map(|v| F::from_u32(*v)).collect()
}

fn refused(air: &L2ShapeSAir, pvs: &[u32]) -> bool {
    let trace = air.generate_trace::<F>(0);
    l2test::first_violation(air, &trace, &pvs_f(pvs), PROGRAM_END_V2).is_some()
}

fn slot_of(program: &[u32], role: u32, nth: usize) -> usize {
    program
        .iter()
        .enumerate()
        .filter(|(_, r)| **r == role)
        .map(|(i, _)| i)
        .nth(nth)
        .unwrap()
}

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

/// A fabricated authorization path: a deterministic leaf and siblings. The
/// AIR only sees the leaf (public), the path and the root it folds to.
fn auth_path(seed: u64, leaf_index: u32) -> L2AuthPath {
    let mut r = rng(seed);
    L2AuthPath {
        leaf: [r(), r(), r(), r()],
        leaf_index,
        siblings: core::array::from_fn(|_| [r(), r(), r(), r()]),
    }
}

fn input(seed: u64, value: u64, asset: u64, leaf_index: u32) -> L2AuthInput {
    let mut r = rng(seed);
    L2AuthInput {
        nk: [r(), r(), r(), r()],
        value,
        asset,
        rho: [r(), r(), r(), r()],
        rseed: [r(), r(), r(), r()],
        d: [r(), r()],
        auth: auth_path(seed ^ 0xa5a5, leaf_index),
    }
}

/// The device-made fee dummy: fresh nk/ρ/rseed and a throwaway auth path.
fn fee_dummy() -> FeeSlotV2 {
    FeeSlotV2::Dummy {
        input: input(0xfee0_d00d, 0, 0, 1833),
    }
}

fn out(seed: u64, value: u64, asset: u64) -> L2TxOutput {
    let mut r = rng(seed);
    L2TxOutput {
        value,
        asset,
        rkm: [r(), r(), r(), r()],
        rho: [r(), r(), r(), r()],
        rseed: [r(), r(), r(), r()],
    }
}

/// The canonical honest instance (`fabricated_bucket_l2_v2`).
fn honest_two_real() -> L2BucketInstanceV2 {
    fabricated_bucket_l2_v2()
}

/// One real input, slot 2 a dummy (`dv`): the dummy is off the commitment
/// tree but still proves its leaf under its own throwaway `auth_root`.
fn honest_dummy_slot_2() -> L2BucketInstanceV2 {
    let real = input(0x5555, 1_000, 0, 598);
    let dummy = input(0x6666, 0, 0, 489);
    let (_, _, cm) = derive_input_l2_v2(&real);
    let (w_real, anchor) = fabricated_single_tree(&cm);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(0)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_v2(
        SHAPE_S_LOG_HEIGHT_V2,
        &[real, dummy],
        &[out(0x7777, 600, 0), out(0x8888, 390, 0)],
        10,
        &[w_real, off_tree_witness()],
        anchor,
        &leaves,
        &rw,
        registry_root,
        &fee_dummy(),
        true,
    )
}

struct Fixture {
    inst: L2BucketInstanceV2,
    trace: RowMajorMatrix<F>,
}

fn fixture(cell: &'static OnceLock<Fixture>, make: fn() -> L2BucketInstanceV2) -> &'static Fixture {
    cell.get_or_init(|| {
        let inst = make();
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "honest v2");
        Fixture { inst, trace }
    })
}

fn two_real() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    fixture(&CELL, honest_two_real)
}

fn dummy2() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    fixture(&CELL, honest_dummy_slot_2)
}

// ------------------------------------------------------------------ geometry

/// The version parameter does not reach v1: its constants and widths are the
/// ones `SHAPE_S_DIGEST_V1` (qlab-l2 goldens) was taken over.
#[test]
fn l2v2_v1_geometry_is_unchanged() {
    assert_eq!(SHAPE_S_PERMS, 158);
    assert_eq!(PROGRAM_SLOTS, 160);
    assert_eq!(L2_WIDTH, 721);
    assert_eq!(PV_LEN, 116);
    let v1 = L2ShapeSAir::chain_only(SHAPE_S_LOG_HEIGHT);
    assert_eq!(v1.version, L2Version::V1);
    assert_eq!(v1.program.len(), PROGRAM_SLOTS);
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::width(&v1), L2_WIDTH);
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::num_public_values(&v1), PV_LEN);
}

#[test]
fn l2v2_geometry() {
    assert_eq!(D_AUTH, 12);
    assert_eq!(SHAPE_S_PERMS_V2, 194);
    assert_eq!(PROGRAM_SLOTS_V2, 196);
    assert_eq!(L2_WIDTH_V2, 774);
    assert_eq!(PV_LEN_V2, 164);
    assert_eq!(
        (PV_LEAF1, PV_LEAF2, PV_LEAF3),
        (PV_LEN, PV_LEN + 16, PV_LEN + 32)
    );
    // 194 perms do not fit 2^19 (170) and do fit 2^20 (341).
    const { assert!(SHAPE_S_PERMS_V2 * ROWS_PER_PERM > 1 << SHAPE_S_LOG_HEIGHT) };
    let inst = honest_two_real();
    assert_eq!(inst.air.program.len(), PROGRAM_SLOTS_V2);
    assert_eq!(
        inst.air
            .program
            .iter()
            .filter(|r| **r != ROLE_DUMMY)
            .count(),
        SHAPE_S_PERMS_V2 - 1
    );
    assert!(!inst.air.program.contains(&ROLE_ANK), "v2 has no ANK");
    assert!(!inst.air.program.contains(&ROLE_NF), "v2 NF is NFA");
    assert_eq!(
        inst.air
            .program
            .iter()
            .filter(|r| **r == ROLE_AAUTH)
            .count(),
        3
    );
    assert_eq!(
        inst.air
            .program
            .iter()
            .filter(|r| **r == ROLE_BAUTH)
            .count(),
        3
    );
    // Each chain: AAUTH, D−1 MERKLE, BAUTH, ARKM, contiguous.
    for k in 0..3 {
        let a = slot_of(&inst.air.program, ROLE_AAUTH, k);
        assert!(inst.air.program[a + 1..a + D_AUTH]
            .iter()
            .all(|r| *r == ROLE_MERKLE));
        assert_eq!(inst.air.program[a + D_AUTH], ROLE_BAUTH);
        assert_eq!(inst.air.program[a + D_AUTH + 1], ROLE_ARKM);
    }
    assert_eq!(inst.pvs.len(), PV_LEN_V2);
}

/// The v2 columns hold on an all-dummy program at a small height.
#[test]
fn l2v2_chain_only_satisfies_constraints() {
    let air = L2ShapeSAir::chain_only_v2(14);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), L2_WIDTH_V2);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN_V2]);
}

/// Host mirrors: AAUTH's level-0 node and the rkm block.
#[test]
fn l2v2_host_mirrors() {
    let p = auth_path(9, 0b1011);
    // Bit 0 set: the leaf is the right child at level 0.
    let lvl0 = crate::reference::merkle_node_state(&p.siblings[0], &p.leaf);
    let mut d: [u64; 4] = lvl0[..4].try_into().unwrap();
    for k in 1..D_AUTH {
        let st = if (p.leaf_index >> k) & 1 == 1 {
            crate::reference::merkle_node_state(&p.siblings[k], &d)
        } else {
            crate::reference::merkle_node_state(&d, &p.siblings[k])
        };
        d = st[..4].try_into().unwrap();
    }
    assert_eq!(p.root(), d);
    // rkm moves with auth_root (the note binds the tree).
    let inp = input(1, 5, 0, 3);
    let mut other = inp.clone();
    other.auth.siblings[0][0] ^= 1;
    assert_ne!(derive_input_l2_v2(&inp).1, derive_input_l2_v2(&other).1);
    assert_eq!(
        derive_input_l2_v2(&inp).0,
        derive_input_l2_v2(&other).0,
        "nf does not see the tree"
    );
}

// ------------------------------------------------------------------ honest

#[test]
fn l2v2_two_real_inputs_satisfy() {
    let fx = two_real();
    assert_eq!(fx.trace.width(), L2_WIDTH_V2);
}

#[test]
fn l2v2_dummy_slot_2_satisfies() {
    let _ = dummy2();
}

// ------------------------------------------------------------------ PV-only negatives

/// The last row of perm `slot`: where its gperm-gated closes fire.
fn close_row(slot: usize) -> usize {
    (slot + 1) * ROWS_PER_PERM - 1
}

/// Refused AT `row` (the gate's own close), and the honest trace is clean
/// there — "refused, and refused here", not by whatever the scan met first.
fn refused_at(
    air: &L2ShapeSAir,
    honest: &RowMajorMatrix<F>,
    honest_pvs: &[u32],
    bad: &RowMajorMatrix<F>,
    bad_pvs: &[u32],
    row: usize,
    what: &str,
) {
    assert!(
        l2test::violations_at(air, honest, &pvs_f(honest_pvs), row).is_empty(),
        "{what}: the honest trace is violated at row {row}"
    );
    assert!(
        !l2test::violations_at(air, bad, &pvs_f(bad_pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

/// A leaf that is not the public one: each slot's leaf is refused at that
/// slot's AAUTH close and nowhere else.
#[test]
fn l2v2_neg_leaf_not_the_public_value() {
    let fx = two_real();
    let rows: Vec<usize> = (0..3)
        .map(|k| close_row(slot_of(&fx.inst.air.program, ROLE_AAUTH, k)))
        .collect();
    for (k, base) in [PV_LEAF1, PV_LEAF2, PV_LEAF3].into_iter().enumerate() {
        let mut pvs = fx.inst.pvs.clone();
        pvs[base] ^= 1;
        let what = format!("leaf {k}");
        refused_at(&fx.inst.air, &fx.trace, &fx.inst.pvs, &fx.trace, &pvs, rows[k], &what);
        for (j, r) in rows.iter().enumerate().filter(|(j, _)| *j != k) {
            assert!(
                l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), *r).is_empty(),
                "{what}: also refused at slot {j}'s close — the latch selects the wrong PV"
            );
        }
    }
}

/// The latch mix-up: slots 1 and 2 swap leaves — both closes refuse.
#[test]
fn l2v2_neg_leaves_swapped_between_slots() {
    let fx = two_real();
    let mut pvs = fx.inst.pvs.clone();
    let (a, b) = (pvs[PV_LEAF1..PV_LEAF2].to_vec(), pvs[PV_LEAF2..PV_LEAF3].to_vec());
    pvs[PV_LEAF1..PV_LEAF2].copy_from_slice(&b);
    pvs[PV_LEAF2..PV_LEAF3].copy_from_slice(&a);
    for k in 0..2 {
        let row = close_row(slot_of(&fx.inst.air.program, ROLE_AAUTH, k));
        refused_at(&fx.inst.air, &fx.trace, &fx.inst.pvs, &fx.trace, &pvs, row, "swapped leaves");
    }
}

/// The dummy slot's leaf is bound too (every slot really signs).
#[test]
fn l2v2_neg_dummy_slot_leaf_not_the_public_value() {
    let fx = dummy2();
    let mut pvs = fx.inst.pvs.clone();
    pvs[PV_LEAF2] ^= 1;
    let row = close_row(slot_of(&fx.inst.air.program, ROLE_AAUTH, 1));
    refused_at(&fx.inst.air, &fx.trace, &fx.inst.pvs, &fx.trace, &pvs, row, "dummy leaf PV");
}

// ------------------------------------------------------------------ witness negatives

fn with<Fn_: FnOnce(&mut L2BucketInstanceV2)>(make: fn() -> L2BucketInstanceV2, f: Fn_) -> L2BucketInstanceV2 {
    let mut inst = make();
    f(&mut inst);
    inst
}

/// A tampered instance refused at chain `k`'s ARKM close (banks 1 and EQA
/// close there), against the honest fixture `fx`.
fn refused_at_arkm(fx: &Fixture, bad: &L2BucketInstanceV2, k: usize, what: &str) {
    let row = close_row(slot_of(&bad.air.program, ROLE_ARKM, k));
    let trace = bad.air.generate_trace::<F>(0);
    refused_at(&bad.air, &fx.trace, &fx.inst.pvs, &trace, &bad.pvs, row, what);
}

/// A different sibling at AAUTH: the path no longer reaches ARKM's root.
#[test]
fn l2v2_neg_sibling_at_level_0() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH, 0);
        i.air.slot_witness[s].w[4] ^= 1;
    });
    refused_at_arkm(two_real(), &inst, 0, "sibling at level 0");
}

/// A flipped path bit inside the auth path.
#[test]
fn l2v2_neg_path_bit_flipped() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH, 1) + 3;
        assert_eq!(i.air.program[s], ROLE_MERKLE);
        i.air.slot_witness[s].pbit = !i.air.slot_witness[s].pbit;
    });
    refused_at_arkm(two_real(), &inst, 1, "path bit");
}

/// ARKM absorbs a root that is not the path's: refused by bank EQA at
/// ARKM's close (the anchor also breaks later; the pin is the EQA close).
#[test]
fn l2v2_neg_auth_root_in_arkm_not_the_tree_root() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_ARKM, 0);
        i.air.slot_witness[s].w[7] ^= 1;
    });
    refused_at_arkm(two_real(), &inst, 0, "auth_root in ARKM");
}

/// The forgery shape for bank 1: a different nk at NFA, with nf republished
/// to match it, so only "NFA's nk = ARKM's nk" can refuse — at ARKM's close.
#[test]
fn l2v2_neg_nk_at_nfa_not_the_nk_in_rkm() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_NFA, 0);
        let mut nk = [0u64; 4];
        nk.copy_from_slice(&i.air.slot_witness[s].w[9..13]);
        nk[0] ^= 1;
        i.air.slot_witness[s].w[9..13].copy_from_slice(&nk);
        let mut rho = [0u64; 4];
        rho.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        let nf = l2_nf(&nk, &rho);
        i.pvs[PV_NF1..PV_NF1 + 16].copy_from_slice(&crate::narrow::pv_chunks(&nf));
    });
    refused_at_arkm(two_real(), &inst, 0, "nk at NFA");
}

/// ρ at NFA must be the note's ρ (bank 2): republish nf for the new ρ; bank
/// 2 closes at the chain's ACM.
#[test]
fn l2v2_neg_rho_at_nfa_not_the_note_rho() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_NFA, 0);
        let mut nk = [0u64; 4];
        nk.copy_from_slice(&i.air.slot_witness[s].w[9..13]);
        i.air.slot_witness[s].w[0] ^= 1;
        let mut rho = [0u64; 4];
        rho.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        let nf = l2_nf(&nk, &rho);
        i.pvs[PV_NF1..PV_NF1 + 16].copy_from_slice(&crate::narrow::pv_chunks(&nf));
    });
    let row = close_row(slot_of(&inst.air.program, ROLE_ACM, 0));
    let trace = inst.air.generate_trace::<F>(0);
    let fx = two_real();
    refused_at(&inst.air, &fx.trace, &fx.inst.pvs, &trace, &inst.pvs, row, "ρ at NFA");
}

/// Coordinator note 1: a dummy slot whose leaf is not under its `auth_root`.
/// Leaf and its PV move together, so only the path → root → ARKM chain can
/// refuse — the dummy latch relaxes the note tree, never the auth tree.
#[test]
fn l2v2_neg_dummy_slot_leaf_not_under_its_auth_root() {
    let inst = with(honest_dummy_slot_2, |i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH, 1);
        i.air.slot_witness[s].w[0] ^= 1;
        let mut leaf = [0u64; 4];
        leaf.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_LEAF2..PV_LEAF3].copy_from_slice(&crate::narrow::pv_chunks(&leaf));
    });
    refused_at_arkm(dummy2(), &inst, 1, "dummy slot 2 leaf not under its root");
}

/// The same for the fee slot's dummy (slot 3, `d3`), the `L3` side.
#[test]
fn l2v2_neg_fee_dummy_leaf_not_under_its_auth_root() {
    let inst = with(honest_two_real, |i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH, 2);
        i.air.slot_witness[s].w[0] ^= 1;
        let mut leaf = [0u64; 4];
        leaf.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_LEAF3..PV_LEN_V2].copy_from_slice(&crate::narrow::pv_chunks(&leaf));
    });
    refused_at_arkm(two_real(), &inst, 2, "fee dummy leaf not under its root");
}

/// Three real slots: the fee slot is a real asset-0 note worth exactly the
/// fee (`FeeSlotV2::Exact`, `d3 = 0`), all three in one commitment tree —
/// AAUTH 3, `L3` and `PV_LEAF3` on a real note.
fn honest_exact_fee() -> L2BucketInstanceV2 {
    let inputs = [input(0x1111, 100, 0, 2885), input(0x2222, 50, 7, 2468)];
    let fee_in = input(0x9999, 10, 0, 3350);
    let (_, _, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2_v2(&inputs[1]);
    let (_, _, cm3) = derive_input_l2_v2(&fee_in);
    let (w, anchor) = fabricated_tree3([&cm1, &cm2, &cm3]);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(7)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_v2(
        SHAPE_S_LOG_HEIGHT_V2,
        &inputs,
        &[out(0x3333, 100, 0), out(0x4444, 50, 7)],
        10,
        &[w[0], w[1]],
        anchor,
        &leaves,
        &rw,
        registry_root,
        &FeeSlotV2::Exact { input: fee_in, witness: w[2] },
        false,
    )
}

#[test]
fn l2v2_three_real_slots_with_an_exact_fee_note_satisfy() {
    let inst = honest_exact_fee();
    assert!(!inst.air.d3);
    let trace = inst.air.generate_trace::<F>(0);
    l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "three real slots");
    // Its leaf 3 is bound at AAUTH 3's close.
    let mut pvs = inst.pvs.clone();
    pvs[PV_LEAF3] ^= 1;
    let row = close_row(slot_of(&inst.air.program, ROLE_AAUTH, 2));
    refused_at(&inst.air, &trace, &inst.pvs, &trace, &pvs, row, "exact fee leaf");
}

/// A note committed under v1's rkm layout (pad in lane 7, no auth_root) does
/// not open under v2: the anchor no longer matches.
#[test]
fn l2v2_neg_note_under_the_v1_rkm_layout() {
    let inp = input(0x1111, 100, 0, 2885);
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&inp.nk);
    st[4] = 1 << 1;
    st[5] = inp.d[0];
    st[6] = inp.d[1];
    st[7] = 1;
    st[16] = 1 << 63;
    let rkm_v1: [u64; 4] = crate::reference::keccak_f(&st)[..4].try_into().unwrap();
    assert_ne!(rkm_v1, derive_input_l2_v2(&inp).1);
    let cm_v1 = l2_cm(inp.value, inp.asset, &rkm_v1, &inp.rho, &inp.rseed);
    let other = input(0x2222, 50, 7, 2468);
    let (_, _, cm2) = derive_input_l2_v2(&other);
    let (witnesses, anchor) = fabricated_shared_tree(&cm_v1, &cm2);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(7)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let inst = build_bucket_l2_v2(
        SHAPE_S_LOG_HEIGHT_V2,
        &[inp, other],
        &[out(0x3333, 90, 0), out(0x4444, 50, 7)],
        10,
        &witnesses,
        anchor,
        &leaves,
        &rw,
        registry_root,
        &fee_dummy(),
        false,
    );
    assert!(refused(&inst.air, &inst.pvs));
}

/// Lab #896 seam T: the v2 census tables are well formed, with no census
/// run: every manifest column lies inside the v2 width; every role it names
/// occurs in the canonical v2 program (and `ANK` / `NF`, gone from v2, are
/// neither named nor in the program); every column v2 appends falls in a
/// region v2 names; the v1 tables are untouched.
#[test]
fn v2_census_tables_are_well_formed() {
    let program = fabricated_bucket_l2_v2().air.program;
    let man = witness_manifest_v2();
    for e in &man {
        assert!(e.cols.iter().all(|&c| c < L2_WIDTH_V2), "{}: a column outside the v2 width", e.field);
        assert!(
            e.role == crate::detaudit::ANY_ROLE || program.contains(&e.role),
            "{}: role {} is not in the v2 program",
            e.field,
            e.role
        );
    }
    assert!(!man.iter().any(|e| e.role == ROLE_ANK || e.role == ROLE_NF), "no ANK / NF entry in v2");
    assert!(!program.contains(&ROLE_ANK) && !program.contains(&ROLE_NF), "the v2 program has no ANK / NF");
    let regions = audit_col_regions_v2();
    for col in L2_WIDTH..L2_WIDTH_V2 {
        let (name, start) = regions.iter().rev().find(|(_, s)| *s <= col).expect("a region");
        assert!(*start >= L2_WIDTH, "v2 column {col} falls in the v1 region {name}");
    }
    assert!(audit_col_regions().iter().all(|(_, s)| *s < L2_WIDTH), "the v1 regions are v1's");
    assert!(witness_manifest().iter().any(|e| e.role == ROLE_ANK), "the v1 manifest keeps ANK");
    assert!(witness_manifest().iter().all(|e| e.cols.iter().all(|&c| c < L2_WIDTH)), "the v1 manifest is v1-wide");
}
