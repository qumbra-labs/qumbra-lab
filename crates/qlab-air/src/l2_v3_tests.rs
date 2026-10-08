//! Shape S v3 (the third output) — lab #937, D1 route 1.
//!
//! Cost model as `l2_v2_tests`: the honest v3 traces are generated once
//! (`OnceLock`) and scanned in full; each witness negative regenerates its
//! own trace and is checked at the close that must refuse it. PV-only
//! negatives reuse the honest trace.

use std::sync::OnceLock;

use p3_air::{check_constraints, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use super::*;
use crate::l2test;

type F = KoalaBear;

const PROGRAM_END_V3: usize = SHAPE_S_PERMS_V3 * ROWS_PER_PERM;

fn pvs_f(pvs: &[u32]) -> Vec<F> {
    pvs.iter().map(|v| F::from_u32(*v)).collect()
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

/// The last row of perm `slot`: where its gperm-gated closes fire.
fn close_row(slot: usize) -> usize {
    (slot + 1) * ROWS_PER_PERM - 1
}

fn out(seed: u64, value: u64, asset: u64) -> L2TxOutput {
    mk_out_v3(seed, value, asset)
}

fn fee_dummy() -> FeeSlotV2 {
    FeeSlotV2::Dummy { input: fabricated_auth_input(0xfee0_d00d, 0, 0, 1833) }
}

/// The canonical inputs (100 @ 0, 50 @ 7) with caller-chosen outputs and fee;
/// the fee slot a device dummy.
fn two_real_with(outputs: [L2TxOutput; 3], fee: u64) -> L2BucketInstanceV3 {
    let inputs = [fabricated_auth_input(0x1111, 100, 0, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    let (_, _, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2_v2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(7)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_v3(
        SHAPE_S_LOG_HEIGHT_V3,
        &inputs,
        &outputs,
        fee,
        &witnesses,
        anchor,
        &leaves,
        &rw,
        registry_root,
        &fee_dummy(),
        false,
    )
}

/// One real asset-0 input, slot 2 a dummy (`dv`), three asset-0 outputs.
fn one_real_with(value: u64, outputs: [L2TxOutput; 3], fee: u64) -> L2BucketInstanceV3 {
    let real = fabricated_auth_input(0x5555, value, 0, 598);
    let dummy = fabricated_auth_input(0x6666, 0, 0, 489);
    let (_, _, cm) = derive_input_l2_v2(&real);
    let (w_real, anchor) = fabricated_single_tree(&cm);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(0)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_v3(
        SHAPE_S_LOG_HEIGHT_V3,
        &[real, dummy],
        &outputs,
        fee,
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
    inst: L2BucketInstanceV3,
    trace: RowMajorMatrix<F>,
}

fn fixture(cell: &'static OnceLock<Fixture>, make: fn() -> L2BucketInstanceV3) -> &'static Fixture {
    cell.get_or_init(|| {
        let inst = make();
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "honest v3");
        Fixture { inst, trace }
    })
}

fn canonical() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    fixture(&CELL, fabricated_bucket_l2_v3)
}

fn exact_fee() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    fixture(&CELL, fabricated_bucket_l2_v3_exact_fee)
}

/// `bad` (a tampered instance) violates a constraint at `row`, and the scan
/// over its whole program finds it refused.
fn refused_at(bad: &L2BucketInstanceV3, row: usize, what: &str) {
    let trace = bad.air.generate_trace::<F>(0);
    assert!(
        !l2test::violations_at(&bad.air, &trace, &pvs_f(&bad.pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

/// PV-only: `pvs` against the honest trace is refused at `row`, and the
/// honest PVs are clean there.
fn pv_refused_at(fx: &Fixture, pvs: &[u32], row: usize, what: &str) {
    assert!(
        l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&fx.inst.pvs), row).is_empty(),
        "{what}: the honest trace is violated at row {row}"
    );
    assert!(
        !l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

/// Rewrite the third output's ρ in the witness (`ACMOUT` #3, W5..8) and
/// claim the commitment that ρ gives — what a prover choosing ρ′₂ would do.
fn with_rho3(mut inst: L2BucketInstanceV3, rho: [u64; 4], o: &L2TxOutput) -> L2BucketInstanceV3 {
    let s = slot_of(&inst.air.program, ROLE_ACMOUT, 2);
    inst.air.slot_witness[s].w[5..9].copy_from_slice(&rho);
    let cm3 = l2_cm(o.value, o.asset, &o.rkm, &rho, &o.rseed);
    inst.pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&pv_chunks(&cm3));
    inst
}

// ------------------------------------------------------------------ geometry

/// v1 and v2 are untouched by the version parameter.
#[test]
fn l2v3_v1_v2_geometry_is_unchanged() {
    assert_eq!((SHAPE_S_PERMS, PROGRAM_SLOTS, L2_WIDTH, PV_LEN), (158, 160, 721, 116));
    assert_eq!((SHAPE_S_PERMS_V2, PROGRAM_SLOTS_V2, L2_WIDTH_V2, PV_LEN_V2), (194, 196, 774, 164));
    let v2 = L2ShapeSAir::chain_only_v2(SHAPE_S_LOG_HEIGHT_V2);
    assert!(v2.is_v2() && !v2.is_v3());
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::width(&v2), L2_WIDTH_V2);
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::num_public_values(&v2), PV_LEN_V2);
    let inst = fabricated_bucket_l2_v2();
    assert_eq!(inst.air.program.len(), PROGRAM_SLOTS_V2);
    assert_eq!(inst.air.program.iter().filter(|r| **r == ROLE_ACMOUT).count(), 2);
    assert_eq!(inst.pvs.len(), PV_LEN_V2);
}

#[test]
fn l2v3_geometry() {
    assert_eq!(SHAPE_S_PERMS_V3, 197);
    assert_eq!(PROGRAM_SLOTS_V3, 200);
    assert_eq!(L2_WIDTH_V3, 780);
    assert_eq!((PV_CM3, PV_LEN_V3), (PV_LEN_V2, PV_LEN_V2 + 16));
    let v3 = L2ShapeSAir::chain_only_v3(SHAPE_S_LOG_HEIGHT_V3);
    assert!(v3.is_v2() && v3.is_v3());
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::width(&v3), L2_WIDTH_V3);
    assert_eq!(<L2ShapeSAir as BaseAir<F>>::num_public_values(&v3), PV_LEN_V3);
    let inst = fabricated_bucket_l2_v3();
    let p = &inst.air.program;
    assert_eq!(p.len(), PROGRAM_SLOTS_V3);
    assert_eq!(p.iter().filter(|r| **r != ROLE_DUMMY).count(), SHAPE_S_PERMS_V3 - 1);
    // The tail, exactly.
    let t = slot_of(p, ROLE_ACMOUT, 0);
    assert_eq!(
        &p[t..t + 11],
        &[
            ROLE_ACMOUT,
            ROLE_BCM1,
            ROLE_ARHO,
            ROLE_ACMOUT,
            ROLE_BCM2,
            ROLE_ARHO,
            ROLE_ACMOUT,
            ROLE_BCM2,
            ROLE_BAL,
            ROLE_END,
            ROLE_DUMMY
        ]
    );
    // Everything before the tail is v2's program.
    let v2 = fabricated_bucket_l2_v2().air.program;
    assert_eq!(&p[..t], &v2[..t]);
    assert_eq!(inst.pvs.len(), PV_LEN_V3);
    // The PVs are v2's layout with `cm3` appended.
    let v2_layout = pv_vec_l2_v2(
        &inst.anchor,
        &inst.nf[0],
        &inst.nf[1],
        &inst.cm_out[0],
        &inst.cm_out[1],
        10,
        &inst.registry_root,
        &inst.nf[2],
        &inst.leaves,
    );
    assert_eq!(inst.pvs[..PV_CM3], v2_layout[..]);
    assert_eq!(inst.pvs[PV_CM3..], pv_chunks(&inst.cm_out[2]));
}

#[test]
fn l2v3_chain_only_satisfies_constraints() {
    let air = L2ShapeSAir::chain_only_v3(14);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), L2_WIDTH_V3);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN_V3]);
}

/// A v2 trace is not a v3 witness: the widths and PV lengths differ, so a v2
/// instance cannot even be evaluated against the v3 AIR (the proof-level
/// refusal is `qlab-l2`'s `v3` tests).
#[test]
fn l2v3_v2_instance_is_not_v3_shaped() {
    let v2 = fabricated_bucket_l2_v2();
    let v3 = verifier_air_s_v3();
    assert_ne!(<L2ShapeSAir as BaseAir<F>>::width(&v2.air), <L2ShapeSAir as BaseAir<F>>::width(&v3));
    assert_ne!(v2.pvs.len(), <L2ShapeSAir as BaseAir<F>>::num_public_values(&v3));
    assert_ne!(v2.air.program, v3.program);
}

// ------------------------------------------------------------------ ρ derivation

/// ρ′₀ = nf₀, ρ′₁ = H(nf₀ ‖ 8), ρ′₂ = H(nf₀ ‖ 9): the first two are the
/// frozen derivation, the third the same block with bit 0 of lane 4 set; the
/// three are pairwise distinct.
#[test]
fn l2v3_output_rhos_are_pairwise_distinct() {
    let inp = fabricated_auth_input(0x1111, 100, 0, 2885);
    let (nf0, _, _) = derive_input_l2_v2(&inp);
    let rho: [[u64; 4]; 3] = core::array::from_fn(|j| derive_output_rho_l2(&nf0, j));
    assert_eq!(rho[0], nf0);
    assert_eq!(rho[1], derive_output_rho(&nf0, 1));
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&nf0);
    st[4] = 9;
    st[5] = 1;
    st[16] = 1 << 63;
    assert_eq!(rho[2], crate::reference::keccak_f(&st)[..4]);
    assert_ne!(rho[0], rho[1]);
    assert_ne!(rho[0], rho[2]);
    assert_ne!(rho[1], rho[2]);
}

// ------------------------------------------------------------------ honest

#[test]
fn l2v3_canonical_satisfies() {
    let fx = canonical();
    assert_eq!(fx.trace.width(), L2_WIDTH_V3);
    assert!(fx.inst.air.sel_o3a, "output 3 is asset 0 = input 1's");
}

/// Three real input slots; the third output a zero-value note. It is an
/// ordinary note: its commitment is `l2_cm(0, asset, rkm, ρ′₂, rseed)`, the
/// formula every output uses — no special encoding (lab #937 D3).
#[test]
fn l2v3_zero_value_third_output_is_an_ordinary_note() {
    let fx = exact_fee();
    assert!(!fx.inst.air.d3);
    let o = out(0x5555, 0, 0);
    let rho2 = derive_output_rho_l2(&fx.inst.nf[0], 2);
    assert_eq!(fx.inst.cm_out[2], l2_cm(0, 0, &o.rkm, &rho2, &o.rseed));
    assert_eq!(fx.inst.pvs[PV_CM3..PV_LEN_V3], pv_chunks(&fx.inst.cm_out[2]));
}

#[test]
fn l2v3_dummy_slot_2_satisfies() {
    let inst = one_real_with(1_000, [out(0x7777, 600, 0), out(0x8888, 380, 0), out(0x9999, 10, 0)], 10);
    let trace = inst.air.generate_trace::<F>(0);
    l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "v3 dummy slot 2");
}

/// Four debits on one row (three outputs + the fee) take the chunk-0 carry
/// to −3 — v3's carry bias. In 2^18 = 4·2^16: three outputs of 2^16 − 1 and a
/// fee of 2^16 + 3 leave chunk 0 at exactly −3·2^16.
#[test]
fn l2v3_carry_of_minus_three_satisfies() {
    let m = 0xffff;
    let inst = one_real_with(1 << 18, [out(0x7777, m, 0), out(0x8888, m, 0), out(0x9999, m, 0)], (1 << 16) + 3);
    let trace = inst.air.generate_trace::<F>(0);
    l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "carry −3");
}

/// c = −4 is not encodable: the three carry bits are boolean, so `c = enc −
/// 3 ≥ −3`. A carry block set to encode −4 (bit 0 = −1) is refused at the
/// balance close row.
#[test]
fn l2v3_neg_carry_of_minus_four_is_refused() {
    let fx = canonical();
    let row = close_row(slot_of(&fx.inst.air.program, ROLE_BAL, 0));
    for off in [BLC_OFF, BLC2_OFF] {
        for j in 0..3 {
            let mut bad = fx.trace.clone();
            let w = bad.width();
            bad.values[row * w + off + 3 * j] = -F::ONE;
            bad.values[row * w + off + 3 * j + 1] = F::ZERO;
            bad.values[row * w + off + 3 * j + 2] = F::ZERO;
            assert!(
                !l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), row).is_empty(),
                "carry block {off}+{j} encoding −4 VERIFIED"
            );
        }
    }
}

/// The honest generator fails loudly on a carry outside −3..=4 instead of
/// clamping it: five debits' worth on one row (here an unbalanced witness
/// whose chunk 0 needs c = −4) panics, naming the chunk.
#[test]
#[should_panic(expected = "chunk 0: c = -4")]
fn l2v3_generator_refuses_an_unencodable_carry() {
    let m = 0xffff;
    // Chunk 0: 0 − 3·0xffff − 0xffff = −262140 → c₀ = −4.
    let inst = one_real_with(1 << 18, [out(0x7777, m, 0), out(0x8888, m, 0), out(0x9999, m, 0)], m);
    let _ = inst.air.generate_trace::<F>(0);
}

// ------------------------------------------------------------------ PV negatives

/// `PV_CM3` is bound at the second `BCM2`'s close; `PV_CM2` at the first's
/// and not the second's.
#[test]
fn l2v3_neg_cm3_not_the_public_value() {
    let fx = canonical();
    let (b1, b2) = (
        close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 0)),
        close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 1)),
    );
    let mut pvs = fx.inst.pvs.clone();
    pvs[PV_CM3] ^= 1;
    pv_refused_at(fx, &pvs, b2, "PV_CM3");
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b1).is_empty(), "PV_CM3 read at BCM2 #1");
    let mut pvs = fx.inst.pvs.clone();
    pvs[PV_CM2] ^= 1;
    pv_refused_at(fx, &pvs, b1, "PV_CM2");
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b2).is_empty(), "PV_CM2 read at BCM2 #2");
    // Outputs 2 and 3 swapped in the PVs: both closes refuse.
    let mut pvs = fx.inst.pvs.clone();
    let (c2, c3) = (pvs[PV_CM2..PV_FEE].to_vec(), pvs[PV_CM3..PV_LEN_V3].to_vec());
    pvs[PV_CM2..PV_FEE].copy_from_slice(&c3);
    pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&c2);
    pv_refused_at(fx, &pvs, b1, "swapped cm2/cm3");
    pv_refused_at(fx, &pvs, b2, "swapped cm2/cm3");
}

/// The zero-value third output claimed under a non-zero note's commitment
/// (same rkm/ρ/rseed, value 5): refused at its bind.
#[test]
fn l2v3_neg_zero_value_output_under_a_nonzero_commitment() {
    let fx = exact_fee();
    let o = out(0x5555, 0, 0);
    let rho2 = derive_output_rho_l2(&fx.inst.nf[0], 2);
    let mut pvs = fx.inst.pvs.clone();
    pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&pv_chunks(&l2_cm(5, 0, &o.rkm, &rho2, &o.rseed)));
    let row = close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 1));
    pv_refused_at(fx, &pvs, row, "zero-value output under a value-5 commitment");
}

// ------------------------------------------------------------------ witness negatives

/// ρ′₂ under the domain 8 (= ρ′₁): refused at output 3's ρ check (bank 3
/// closes at `ACMOUT` #3).
#[test]
fn l2v3_neg_rho3_under_domain_8() {
    let inst = fabricated_bucket_l2_v3();
    let rho = derive_output_rho(&inst.nf[0], 1);
    let row = close_row(slot_of(&inst.air.program, ROLE_ACMOUT, 2));
    let bad = with_rho3(inst, rho, &out(0x5555, 5, 0));
    refused_at(&bad, row, "ρ′₂ = H(nf₀ ‖ 8)");
}

/// ρ′₂ chosen freely (not nf₀-derived): refused at the same check.
#[test]
fn l2v3_neg_rho3_not_nf0_derived() {
    let inst = fabricated_bucket_l2_v3();
    let row = close_row(slot_of(&inst.air.program, ROLE_ACMOUT, 2));
    let bad = with_rho3(inst, [1, 2, 3, 4], &out(0x5555, 5, 0));
    refused_at(&bad, row, "ρ′₂ free");
}

/// The second `ARHO` fed `nf₁` (the second input's nullifier) with ρ′₂ =
/// H(nf₁ ‖ 9) consistently: refused at that `ARHO`'s close (its input must
/// be `PV_NF1`).
#[test]
fn l2v3_neg_rho3_derived_from_the_other_nullifier() {
    let mut inst = fabricated_bucket_l2_v3();
    let nf1 = inst.nf[1];
    let a = slot_of(&inst.air.program, ROLE_ARHO, 1);
    inst.air.slot_witness[a].w[5..9].copy_from_slice(&nf1);
    let rho = derive_output_rho_l2(&nf1, 2);
    let bad = with_rho3(inst, rho, &out(0x5555, 5, 0));
    refused_at(&bad, close_row(a), "ρ′₂ from nf₁");
}

/// Output 3's asset is input 1's (0), but `o3a` says row 2 (asset 7):
/// refused at the balance close.
#[test]
fn l2v3_neg_o3_misassigned() {
    let mut inst = fabricated_bucket_l2_v3();
    assert!(inst.air.sel_o3a);
    inst.air.sel_o3a = false;
    let row = close_row(slot_of(&inst.air.program, ROLE_BAL, 0));
    refused_at(&inst, row, "o3a flipped");
}

/// Output 3 carries an asset no input carries (9): refused under either
/// selector — `o3a` binds it to input 1's asset, `¬o3a` to input 2's.
#[test]
fn l2v3_neg_o3_asset_of_no_input() {
    let outputs = [out(0x3333, 85, 0), out(0x4444, 50, 7), out(0x5555, 5, 9)];
    for o3a in [true, false] {
        let mut inst = two_real_with(outputs, 10);
        inst.air.sel_o3a = o3a;
        let row = close_row(slot_of(&inst.air.program, ROLE_BAL, 0));
        refused_at(&inst, row, &format!("o3 asset 9, o3a = {o3a}"));
    }
}

/// Output 3 overspends by 1: refused at the balance close.
#[test]
fn l2v3_neg_third_output_breaks_balance() {
    let inst = two_real_with([out(0x3333, 85, 0), out(0x4444, 50, 7), out(0x5555, 6, 0)], 10);
    let row = close_row(slot_of(&inst.air.program, ROLE_BAL, 0));
    refused_at(&inst, row, "o3 overspend");
}

/// The zero-value third output's witness value set to 5 with the matching
/// commitment claimed: the value the note commits to is the value the
/// balance debits — refused at the balance close (the canonical rows are
/// exact).
#[test]
fn l2v3_neg_third_output_value_in_note_is_value_in_balance() {
    // Honest: 100 = 90 + 0 + fee 10 on row 1; then output 3 alone gains 5.
    let mut inst = two_real_with([out(0x3333, 90, 0), out(0x4444, 50, 7), out(0x5555, 0, 0)], 10);
    let s = slot_of(&inst.air.program, ROLE_ACMOUT, 2);
    inst.air.slot_witness[s].w[4] = 5;
    let o = out(0x5555, 5, 0);
    let rho2 = derive_output_rho_l2(&inst.nf[0], 2);
    inst.pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&pv_chunks(&l2_cm(5, 0, &o.rkm, &rho2, &o.rseed)));
    let row = close_row(slot_of(&inst.air.program, ROLE_BAL, 0));
    refused_at(&inst, row, "o3 value 5 committed, 0 debited");
}

/// `OM2` cleared after the first `BCM2` close (so the second `ARHO` would
/// absorb 8 and the second `BCM2` would bind `PV_CM2`): refused at the
/// first `BCM2` close, where `OM2` must rise.
#[test]
fn l2v3_neg_om2_not_set() {
    let fx = canonical();
    let b1 = close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 0));
    let mut bad = fx.trace.clone();
    let w = bad.width();
    for r in b1 + 1..PROGRAM_END_V3 {
        bad.values[r * w + OM2_COL] = F::ZERO;
    }
    assert!(
        !l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), b1).is_empty(),
        "OM2 held at 0 VERIFIED"
    );
}

/// Lab #937: the v3 census tables are well formed — v2's manifest (the
/// third span reuses its roles, all present in the v3 program), and every
/// column v3 appends falls in a region v3 names.
#[test]
fn v3_census_tables_are_well_formed() {
    let program = fabricated_bucket_l2_v3().air.program;
    for e in &witness_manifest_v3() {
        assert!(e.cols.iter().all(|&c| c < L2_WIDTH_V3), "{}: a column outside the v3 width", e.field);
        assert!(
            e.role == crate::detaudit::ANY_ROLE || program.contains(&e.role),
            "{}: role {} is not in the v3 program",
            e.field,
            e.role
        );
    }
    let regions = audit_col_regions_v3();
    for col in L2_WIDTH_V2..L2_WIDTH_V3 {
        let (name, start) = regions.iter().rev().find(|(_, s)| *s <= col).expect("a region");
        assert!(*start >= L2_WIDTH_V2, "v3 column {col} falls in the v2 region {name}");
    }
}
