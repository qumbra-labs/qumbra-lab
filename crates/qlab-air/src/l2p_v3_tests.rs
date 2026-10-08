//! Shape P v3 (the third output) — lab #937, D1 route 1. Shape S's v3 tests
//! (`l2_v3_tests`) carried to P, plus P's own: the third output against the
//! three asset tracks (A₁, A₂, the row's `vPublic` asset) under `q` and `¬q`,
//! and the carry range a fifth debit (an exit redeem) opens.

use std::sync::OnceLock;

use p3_air::{check_constraints, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use super::*;
use crate::l2::{derive_output_rho_l2, ROLE_ACMOUT, ROWS_PER_PERM};
use crate::l2test;
use crate::narrow::{fabricated_single_tree, off_tree_witness};

type F = KoalaBear;

const PROGRAM_END_V3: usize = SHAPE_P_PERMS_V3 * ROWS_PER_PERM;

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

fn close_row(slot: usize) -> usize {
    (slot + 1) * ROWS_PER_PERM - 1
}

fn hybrid7() -> PolicyAsset {
    PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[])
}

/// Inputs 100 @ `a1` and 50 @ `a2` (asset 7 Hybrid, anything else Cloaked).
fn two_in(a1: u64, a2: u64, outputs: [L2TxOutput; 3], fee: u64, vp: [VPublic; 2]) -> L2PBucketInstanceV3 {
    let inputs = [fabricated_auth_input(0x1111, 100, a1, 2885), fabricated_auth_input(0x2222, 50, a2, 2468)];
    let asset_of = |a: u64| if a == 7 { hybrid7() } else { PolicyAsset::cloaked(a) };
    build_bucket_l2p_v3_fabricated(&inputs, &outputs, fee, &[asset_of(a1), asset_of(a2)], vp)
}

/// One real asset-0 input worth `value`, slot 2 a dummy (`dv`, so `q`),
/// three asset-0 outputs, row 1 carrying an exit redeem of `redeem`.
fn exit_one_real(value: u64, outputs: [L2TxOutput; 3], fee: u64, redeem: u64) -> L2PBucketInstanceV3 {
    let real = fabricated_auth_input(0x5555, value, 0, 598);
    let dummy = fabricated_auth_input(0x6666, 0, 0, 489);
    let (_, rkm_r, cm) = derive_input_l2_v2(&real);
    let (_, rkm_d, _) = derive_input_l2_v2(&dummy);
    let (w, anchor) = fabricated_single_tree(&cm);
    let a0 = PolicyAsset::cloaked(0);
    let (rw, root) = fabricated_registry_tree(&a0.leaf().hash(), &a0.leaf().hash());
    let policy = [
        a0.policy_input_for(&rkm_r, rw[0]).expect("real input policy"),
        a0.policy_input_for(&rkm_d, rw[1]).expect("dummy input policy"),
    ];
    build_bucket_l2p_v3(
        SHAPE_P_LOG_HEIGHT,
        &[real, dummy],
        &outputs,
        fee,
        &[w, off_tree_witness()],
        anchor,
        &policy,
        root,
        [VPublic::redeem(redeem), VPublic::NONE],
        &FeeSlotV2::Dummy { input: fabricated_auth_input(0xfee0_d00d, 0, 0, 1833) },
        [0x0e, 0x0f, 0x10, 0x11],
        true,
    )
}

struct Fixture {
    inst: L2PBucketInstanceV3,
    trace: RowMajorMatrix<F>,
}

fn canonical() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    CELL.get_or_init(|| {
        let inst = fabricated_bucket_l2p_v3();
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "honest P v3");
        Fixture { inst, trace }
    })
}

fn assert_sat(inst: &L2PBucketInstanceV3, what: &str) {
    let trace = inst.air.generate_trace::<F>(0);
    l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), what);
}

fn refused_at(bad: &L2PBucketInstanceV3, row: usize, what: &str) {
    let trace = bad.air.generate_trace::<F>(0);
    assert!(
        !l2test::violations_at(&bad.air, &trace, &pvs_f(&bad.pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

fn bal_row(inst: &L2PBucketInstanceV3) -> usize {
    close_row(slot_of(&inst.air.program, ROLE_BAL, 0))
}

// ------------------------------------------------------------------ geometry

#[test]
fn l2pv3_v1_v2_geometry_is_unchanged() {
    assert_eq!((SHAPE_P_PERMS, PROGRAM_SLOTS, L2P_WIDTH, PV_LEN), (252, 252, 804, 144));
    assert_eq!((SHAPE_P_PERMS_V2, PROGRAM_SLOTS_V2, L2P_WIDTH_V2, PV_LEN_V2), (288, 288, 857, 192));
    let v2 = L2ShapePAir::chain_only_v2(SHAPE_P_LOG_HEIGHT);
    assert!(v2.is_v2() && !v2.is_v3());
    assert_eq!(<L2ShapePAir as BaseAir<F>>::width(&v2), L2P_WIDTH_V2);
    let inst = fabricated_bucket_l2p_v2();
    assert_eq!(inst.air.program.iter().filter(|r| **r == ROLE_ACMOUT).count(), 2);
    assert_eq!(inst.pvs.len(), PV_LEN_V2);
}

#[test]
fn l2pv3_geometry() {
    assert_eq!((SHAPE_P_PERMS_V3, PROGRAM_SLOTS_V3, L2P_WIDTH_V3), (291, 292, 871));
    assert_eq!((PV_CM3, PV_LEN_V3), (PV_LEN_V2, PV_LEN_V2 + 16));
    let v3 = L2ShapePAir::chain_only_v3(SHAPE_P_LOG_HEIGHT);
    assert!(v3.is_v2() && v3.is_v3());
    assert_eq!(<L2ShapePAir as BaseAir<F>>::width(&v3), L2P_WIDTH_V3);
    assert_eq!(<L2ShapePAir as BaseAir<F>>::num_public_values(&v3), PV_LEN_V3);
    let inst = fabricated_bucket_l2p_v3();
    let p = &inst.air.program;
    assert_eq!(p.len(), PROGRAM_SLOTS_V3);
    assert_eq!(p.iter().filter(|r| **r != ROLE_DUMMY).count(), SHAPE_P_PERMS_V3 - 1);
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
    assert_eq!(&p[..t], &fabricated_bucket_l2p_v2().air.program[..t]);
    assert_eq!(inst.pvs.len(), PV_LEN_V3);
    assert_eq!(inst.pvs[PV_CM3..], pv_chunks(&inst.cm_out[2]));
}

#[test]
fn l2pv3_chain_only_satisfies_constraints() {
    let air = L2ShapePAir::chain_only_v3(14);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), L2P_WIDTH_V3);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN_V3]);
}

#[test]
fn l2pv3_v2_instance_is_not_v3_shaped() {
    let v2 = fabricated_bucket_l2p_v2();
    let v3 = verifier_air_p_v3();
    assert_ne!(<L2ShapePAir as BaseAir<F>>::width(&v2.air), <L2ShapePAir as BaseAir<F>>::width(&v3));
    assert_ne!(v2.pvs.len(), <L2ShapePAir as BaseAir<F>>::num_public_values(&v3));
}

// ------------------------------------------------------------------ honest

#[test]
fn l2pv3_canonical_satisfies() {
    let fx = canonical();
    assert_eq!(fx.trace.width(), L2P_WIDTH_V3);
    assert!(fx.inst.air.sel_o3a);
}

/// The zero-value third output is an ordinary note (lab #937 D3).
#[test]
fn l2pv3_exact_fee_zero_value_third_output_satisfies() {
    let inst = fabricated_bucket_l2p_v3_exact_fee();
    assert!(!inst.air.d3);
    let o = mk_out_p(0x5555, 0, 0);
    let rho2 = derive_output_rho_l2(&inst.nf[0], 2);
    assert_eq!(inst.cm_out[2], l2_cm(0, 0, &o.rkm, &rho2, &o.rseed));
    assert_sat(&inst, "P v3 exact fee");
}

/// A row with a `vPublic` term and the third output on it: redeem 15 of
/// asset 7 on row 2 — 50 = 30 + 5 + 15; row 1: 100 = 90 + fee 10.
#[test]
fn l2pv3_third_output_on_a_vpublic_row_satisfies() {
    let inst = two_in(0, 7, [mk_out_p(0x3333, 90, 0), mk_out_p(0x4444, 30, 7), mk_out_p(0x5555, 5, 7)], 10, [VPublic::NONE, VPublic::redeem(15)]);
    assert!(!inst.air.sel_o3a);
    assert_eq!(inst.pvs[pv_vp_asset(1)], 7);
    assert_sat(&inst, "o3 on the redeem row");
}

/// Five debits on one chain — three outputs, the fee, an exit redeem of
/// asset 0 — take chunk 0's carry to −4, v3's bias-4 floor: 2^18 =
/// 3·0xffff + fee 0xffff + redeem 4, chunk 0 exactly −4·2^16.
#[test]
fn l2pv3_carry_of_minus_four_satisfies() {
    let m = 0xffff;
    let inst = exit_one_real(1 << 18, [mk_out_p(0x7777, m, 0), mk_out_p(0x8888, m, 0), mk_out_p(0x9999, m, 0)], m, 4);
    assert!(inst.air.sel_q);
    assert_sat(&inst, "carry −4");
}

// ------------------------------------------------------------------ carries

/// c = −5 is not encodable under bias 4 (boolean bits ⇒ c ≥ −4): a carry
/// block set to encode −5 is refused at the balance close.
#[test]
fn l2pv3_neg_carry_of_minus_five_is_refused() {
    let fx = canonical();
    let row = bal_row(&fx.inst);
    for off in [BLC_OFF, BLC2_OFF] {
        for j in 0..3 {
            let mut bad = fx.trace.clone();
            let w = bad.width();
            bad.values[row * w + off + 3 * j] = -F::ONE;
            bad.values[row * w + off + 3 * j + 1] = F::ZERO;
            bad.values[row * w + off + 3 * j + 2] = F::ZERO;
            assert!(
                !l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), row).is_empty(),
                "carry block {off}+{j} encoding −5 VERIFIED"
            );
        }
    }
}

/// The generator fails loudly on a carry outside −4..=3.
#[test]
#[should_panic(expected = "chunk 0: c = -5")]
fn l2pv3_generator_refuses_an_unencodable_carry() {
    let m = 0xffff;
    // Chunk 0: 0 − 3·0xffff − 0xffff − 0xffff = −327675 → c₀ = −5.
    let inst = exit_one_real(1 << 20, [mk_out_p(0x7777, m, 0), mk_out_p(0x8888, m, 0), mk_out_p(0x9999, m, 0)], m, m);
    let _ = inst.air.generate_trace::<F>(0);
}

// ------------------------------------------------------------------ PV negatives

#[test]
fn l2pv3_neg_cm3_not_the_public_value() {
    let fx = canonical();
    let (b1, b2) = (
        close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 0)),
        close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 1)),
    );
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&fx.inst.pvs), b2).is_empty());
    let mut pvs = fx.inst.pvs.clone();
    pvs[PV_CM3] ^= 1;
    assert!(!l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b2).is_empty(), "PV_CM3 VERIFIED");
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b1).is_empty(), "PV_CM3 read at BCM2 #1");
    let mut pvs = fx.inst.pvs.clone();
    pvs[crate::l2::PV_CM2] ^= 1;
    assert!(!l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b1).is_empty(), "PV_CM2 VERIFIED");
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), b2).is_empty(), "PV_CM2 read at BCM2 #2");
}

// ------------------------------------------------------------------ witness negatives

/// ρ′₂ under domain 8 (= ρ′₁): refused at `ACMOUT` #3's ρ check.
#[test]
fn l2pv3_neg_rho3_under_domain_8() {
    let mut inst = fabricated_bucket_l2p_v3();
    let s = slot_of(&inst.air.program, ROLE_ACMOUT, 2);
    let rho = crate::narrow::derive_output_rho(&inst.nf[0], 1);
    inst.air.slot_witness[s].w[5..9].copy_from_slice(&rho);
    let o = mk_out_p(0x5555, 5, 0);
    inst.pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&pv_chunks(&l2_cm(o.value, o.asset, &o.rkm, &rho, &o.rseed)));
    refused_at(&inst, close_row(s), "P ρ′₂ = H(nf₀ ‖ 8)");
}

/// The second `ARHO` fed the second input's nullifier: refused at its close
/// (its input must be `PV_NF1`).
#[test]
fn l2pv3_neg_rho3_derived_from_the_other_nullifier() {
    let mut inst = fabricated_bucket_l2p_v3();
    let nf1 = inst.nf[1];
    let a = slot_of(&inst.air.program, ROLE_ARHO, 1);
    inst.air.slot_witness[a].w[5..9].copy_from_slice(&nf1);
    let s = slot_of(&inst.air.program, ROLE_ACMOUT, 2);
    let rho = derive_output_rho_l2(&nf1, 2);
    inst.air.slot_witness[s].w[5..9].copy_from_slice(&rho);
    let o = mk_out_p(0x5555, 5, 0);
    inst.pvs[PV_CM3..PV_LEN_V3].copy_from_slice(&pv_chunks(&l2_cm(o.value, o.asset, &o.rkm, &rho, &o.rseed)));
    refused_at(&inst, close_row(a), "P ρ′₂ from nf₁");
}

/// The three asset tracks, `¬q` (inputs 0 and 7): output 3 carries asset 9,
/// which no input carries and no row reveals, and every row still balances
/// numerically — only the asset binding can refuse it.
/// - track A₁: `o3a`, row 1 = 100 − 80 − 10 − fee 10;
/// - track A₂: `¬o3a`, row 2 = 50 − 45 − 5;
/// - track vpa: `¬o3a` on the row redeeming asset 7, 50 − 30 − 5 − 15.
#[test]
fn l2pv3_neg_o3_asset_of_no_input_not_q() {
    let cases: [(&str, [L2TxOutput; 3], [VPublic; 2], bool); 3] = [
        ("A1", [mk_out_p(0x3333, 80, 0), mk_out_p(0x4444, 50, 7), mk_out_p(0x5555, 10, 9)], [VPublic::NONE; 2], true),
        ("A2", [mk_out_p(0x3333, 90, 0), mk_out_p(0x4444, 45, 7), mk_out_p(0x5555, 5, 9)], [VPublic::NONE; 2], false),
        (
            "vpa",
            [mk_out_p(0x3333, 90, 0), mk_out_p(0x4444, 30, 7), mk_out_p(0x5555, 5, 9)],
            [VPublic::NONE, VPublic::redeem(15)],
            false,
        ),
    ];
    for (track, outputs, vp, o3a) in cases {
        let mut inst = two_in(0, 7, outputs, 10, vp);
        assert!(!inst.air.sel_q);
        inst.air.sel_o3a = o3a;
        refused_at(&inst, bal_row(&inst), &format!("o3 asset 9 on track {track}"));
    }
}

/// The same under `q` (both inputs asset 0; the rows are summed, so either
/// selector balances): asset 9 refused under `o3a` and `¬o3a`.
#[test]
fn l2pv3_neg_o3_asset_of_no_input_q() {
    for o3a in [true, false] {
        let mut inst = two_in(0, 0, [mk_out_p(0x3333, 85, 0), mk_out_p(0x4444, 50, 0), mk_out_p(0x5555, 5, 9)], 10, [VPublic::NONE; 2]);
        assert!(inst.air.sel_q);
        inst.air.sel_o3a = o3a;
        refused_at(&inst, bal_row(&inst), &format!("q: o3 asset 9, o3a = {o3a}"));
    }
}

/// Output 3's asset is input 1's but `o3a` says row 2: refused.
#[test]
fn l2pv3_neg_o3_misassigned() {
    let mut inst = fabricated_bucket_l2p_v3();
    inst.air.sel_o3a = false;
    refused_at(&inst, bal_row(&inst), "P o3a flipped");
}

/// Output 3 overspends by 1: refused at the balance close.
#[test]
fn l2pv3_neg_third_output_breaks_balance() {
    let inst = two_in(0, 7, [mk_out_p(0x3333, 85, 0), mk_out_p(0x4444, 50, 7), mk_out_p(0x5555, 6, 0)], 10, [VPublic::NONE; 2]);
    refused_at(&inst, bal_row(&inst), "P o3 overspend");
}

/// `OM2` held at 0 after the first `BCM2`: refused at that close.
#[test]
fn l2pv3_neg_om2_not_set() {
    let fx = canonical();
    let b1 = close_row(slot_of(&fx.inst.air.program, ROLE_BCM2, 0));
    let mut bad = fx.trace.clone();
    let w = bad.width();
    for r in b1 + 1..PROGRAM_END_V3 {
        bad.values[r * w + OM2_COL] = F::ZERO;
    }
    assert!(
        !l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), b1).is_empty(),
        "P OM2 held at 0 VERIFIED"
    );
}

// ------------------------------------------------------------------ o3f (A′)

fn p_prover_fee() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    CELL.get_or_init(|| {
        let inst = fabricated_bucket_l2p_v3_prover_fee();
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "P o3f prover fee");
        Fixture { inst, trace }
    })
}

/// Lab #937 A′: shape S's fee-bank spend in P — two asset-7 notes, a fee
/// note of 13 paying the fee 10 and an asset-0 output 3 of 3 (the prover's
/// fee) through the bank; `o3a` off.
#[test]
fn l2pv3_o3f_prover_fee_beside_two_notes_of_one_asset_satisfies() {
    let fx = p_prover_fee();
    let a = &fx.inst.air;
    assert!(a.sel_o3f && !a.sel_o3a && !a.d3 && a.sel_q);
    let w = fx.trace.width();
    assert_eq!(fx.trace.values[bal_row(&fx.inst) * w + FB_OFF], F::from_u32(10), "the bank closed at the fee");
}

/// P's bank borrows across a chunk (note 2¹⁶ = fee 1 + output 3 of
/// 2¹⁶ − 1; c₀ = −1); every other carry encoding (c = 0, 1, −2) is refused
/// at the close.
#[test]
fn l2pv3_o3f_fee_bank_borrows_and_its_carry_cannot_lie() {
    let inst =
        fabricated_bucket_l2p_v3_fee_bank(1 << 16, [mk_out_p(0x3333, 100, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 0xffff, 0)], 1);
    assert!(inst.air.sel_o3f);
    let honest = inst.air.generate_trace::<F>(0);
    l2test::assert_satisfied(&inst.air, &honest, &pvs_f(&inst.pvs), "P fee-bank borrow");
    let row = bal_row(&inst);
    let w = honest.width();
    assert_eq!((honest.values[row * w + FBC_OFF], honest.values[row * w + FBC_OFF + 1]), (F::ONE, F::ZERO), "c₀ = −1");
    for (b0, b1, c) in [(0u32, 1u32, 0i32), (1, 1, 1), (0, 0, -2)] {
        let mut t = honest.clone();
        t.values[row * w + FBC_OFF] = F::from_u32(b0);
        t.values[row * w + FBC_OFF + 1] = F::from_u32(b1);
        assert!(!l2test::violations_at(&inst.air, &t, &pvs_f(&inst.pvs), row).is_empty(), "P carry c₀ = {c} VERIFIED");
    }
}

/// P: output 3's committed value is the value the bank debits (witness
/// value 4, commitment claimed to match, note 13 = 10 + 3): refused.
#[test]
fn l2pv3_neg_o3f_output_value_in_note_is_value_in_bank() {
    let mut inst = fabricated_bucket_l2p_v3_prover_fee();
    let s = slot_of(&inst.air.program, ROLE_ACMOUT, 2);
    inst.air.slot_witness[s].w[4] = 4;
    let o = mk_out_p(0x5555, 4, 0);
    let rho2 = derive_output_rho_l2(&inst.nf[0], 2);
    inst.pvs[PV_CM3..PV_LEN_V3]
        .copy_from_slice(&crate::narrow::pv_chunks(&crate::l2::l2_cm(4, 0, &o.rkm, &rho2, &o.rseed)));
    let row = bal_row(&inst);
    refused_at(&inst, row, "P o3 value 4 committed, 3 owed by the note");
}

/// P: `SF3 = AG[o3]·o3f` (SF3 = 0 on an accumulating row) and `o3f` boolean
/// (`o3f = 2`, row 0).
#[test]
fn l2pv3_neg_o3f_selector_gates() {
    let fx = p_prover_fee();
    let w = fx.trace.width();
    let r = (0..fx.trace.height()).find(|r| fx.trace.values[r * w + AG_O3_COL] == F::ONE).expect("an AG[o3] row");
    let mut bad = fx.trace.clone();
    bad.values[r * w + SF3_COL] = F::ZERO;
    assert!(!l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), r).is_empty(), "P SF3 = 0 VERIFIED");
    assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&fx.inst.pvs), 0).is_empty());
    let mut bad = fx.trace.clone();
    for row in 0..bad.height() {
        bad.values[row * w + O3F_COL] = F::from_u32(2);
    }
    assert!(!l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), 0).is_empty(), "P o3f = 2 VERIFIED");
}

/// Review F1 (P) — `o3f` set only while output 3 (asset 7) accumulates, then
/// cleared: the close is clean (O3 bound to A₂ = 7); the hold refuses it.
#[test]
fn l2pv3_neg_o3f_set_only_while_output_3_accumulates() {
    let mut inst =
        fabricated_bucket_l2p_v3_fee_bank(13, [mk_out_p(0x3333, 100, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 3, 7)], 10);
    inst.air.sel_o3f = true;
    inst.air.sel_o3a = false;
    let mut trace = inst.air.generate_trace::<F>(0);
    let w = trace.width();
    let last = (0..trace.height()).filter(|r| trace.values[r * w + AG_O3_COL] == F::ONE).max().expect("an AG[o3] row");
    for r in last + 1..trace.height() {
        trace.values[r * w + O3F_COL] = F::ZERO;
    }
    let close = bal_row(&inst);
    assert!(last < close);
    assert!(
        l2test::violations_at(&inst.air, &trace, &pvs_f(&inst.pvs), close).is_empty(),
        "the P close should be clean: the hold is the only gate"
    );
    assert!(!l2test::violations_at(&inst.air, &trace, &pvs_f(&inst.pvs), last).is_empty(), "P o3f falling VERIFIED");
}

/// Review F1 (P) — `o3f` set only on the close row: the hold refuses it at
/// the row before.
#[test]
fn l2pv3_neg_o3f_set_only_at_the_close() {
    let inst =
        fabricated_bucket_l2p_v3_fee_bank(10, [mk_out_p(0x3333, 97, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 3, 7)], 10);
    assert!(!inst.air.sel_o3f && inst.air.sel_o3a);
    let mut trace = inst.air.generate_trace::<F>(0);
    let close = bal_row(&inst);
    for r in [close - 1, close] {
        assert!(l2test::violations_at(&inst.air, &trace, &pvs_f(&inst.pvs), r).is_empty(), "honest P row {r}");
    }
    let w = trace.width();
    trace.values[close * w + O3F_COL] = F::ONE;
    assert!(!l2test::violations_at(&inst.air, &trace, &pvs_f(&inst.pvs), close - 1).is_empty(), "P o3f rising VERIFIED");
}

/// Without `o3f` the same P spend is unprovable under either `o3a`.
#[test]
fn l2pv3_neg_asset_0_third_output_beside_two_asset_7_notes_needs_o3f() {
    for o3a in [true, false] {
        let mut inst = fabricated_bucket_l2p_v3_prover_fee();
        inst.air.sel_o3f = false;
        inst.air.sel_o3a = o3a;
        let row = bal_row(&inst);
        refused_at(&inst, row, &format!("P asset-0 output 3 in a row, o3a = {o3a}"));
    }
}

/// The fee note one short of / one over fee + v(O3): refused at P's bank.
#[test]
fn l2pv3_neg_o3f_fee_note_not_fee_plus_output() {
    let outs = [mk_out_p(0x3333, 100, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 3, 0)];
    for note in [12, 14] {
        let inst = fabricated_bucket_l2p_v3_fee_bank(note, outs, 10);
        assert!(inst.air.sel_o3f);
        let row = bal_row(&inst);
        refused_at(&inst, row, &format!("P fee note {note} for 10 + 3"));
    }
}

/// `o3f` with output 3 of asset 7: refused at P's balance close.
#[test]
fn l2pv3_neg_o3f_output_of_a_nonzero_asset() {
    let mut inst =
        fabricated_bucket_l2p_v3_fee_bank(13, [mk_out_p(0x3333, 100, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 3, 7)], 10);
    assert!(!inst.air.sel_o3f);
    inst.air.sel_o3f = true;
    inst.air.sel_o3a = false;
    let row = bal_row(&inst);
    refused_at(&inst, row, "P o3f, output 3 of asset 7");
}

/// `o3f` beside a dummy slot 3, and `o3f` with `o3a`: both refused on the
/// canonical trace's first row, one mid-program row, the balance close and
/// the last row (the two gates are ungated).
#[test]
fn l2pv3_neg_o3f_with_d3_or_o3a() {
    let fx = canonical();
    assert!(fx.inst.air.d3);
    let w = fx.trace.width();
    let rows = [0, PROGRAM_END_V3 / 2, bal_row(&fx.inst), fx.trace.height() - 1];
    let mut bad = fx.trace.clone();
    for r in 0..bad.height() {
        bad.values[r * w + O3F_COL] = F::ONE;
    }
    for r in rows {
        assert!(!l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), r).is_empty(), "P o3f ∧ d3 VERIFIED at row {r}");
    }
    // With d3 cleared too, `o3f ∧ o3a` alone (the canonical `o3a` is on).
    assert!(fx.inst.air.sel_o3a);
    for r in 0..bad.height() {
        bad.values[r * w + D3_COL] = F::ZERO;
        bad.values[r * w + L3D3_COL] = F::ZERO;
    }
    for r in rows {
        assert!(!l2test::violations_at(&fx.inst.air, &bad, &pvs_f(&fx.inst.pvs), r).is_empty(), "P o3f ∧ o3a VERIFIED at row {r}");
    }
}

#[test]
fn v3_census_tables_are_well_formed() {
    let program = fabricated_bucket_l2p_v3().air.program;
    for e in &witness_manifest_v3() {
        assert!(e.cols.iter().all(|&c| c < L2P_WIDTH_V3), "{}: a column outside the v3 width", e.field);
        assert!(
            e.role == crate::detaudit::ANY_ROLE || program.contains(&e.role),
            "{}: role {} is not in the v3 program",
            e.field,
            e.role
        );
    }
    let regions = audit_col_regions_v3();
    for col in L2P_WIDTH_V2..L2P_WIDTH_V3 {
        let (name, start) = regions.iter().rev().find(|(_, s)| *s <= col).expect("a region");
        assert!(*start >= L2P_WIDTH_V2, "v3 column {col} falls in the v2 region {name}");
    }
    assert!(audit_sel2_accounting_v3().cols.contains(&SEL_O3A_COL));
}
