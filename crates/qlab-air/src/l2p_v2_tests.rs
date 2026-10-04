//! Shape P v2 (Candidate A authorization) — lab #896 seam C. Cost model as
//! `l2_v2_tests` (seam B): one honest trace (`OnceLock`), negatives pinned to
//! their gate's close row with `l2test::violations_at`.

use std::sync::OnceLock;

use p3_air::{check_constraints, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use super::*;
use crate::l2::{l2_nf, PV_NF1, ROLE_ARKM as ARKM, ROWS_PER_PERM};
use crate::l2test;

type F = KoalaBear;

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

struct Fixture {
    inst: L2PBucketInstance,
    trace: RowMajorMatrix<F>,
}

fn honest() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    CELL.get_or_init(|| {
        let inst = fabricated_bucket_l2p_v2();
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_f(&inst.pvs), "honest P v2");
        Fixture { inst, trace }
    })
}

/// Refused at `row`, clean there in the honest trace.
fn refused_at(
    bad_air: &L2ShapePAir,
    bad: &RowMajorMatrix<F>,
    bad_pvs: &[u32],
    row: usize,
    what: &str,
) {
    let fx = honest();
    assert!(
        l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&fx.inst.pvs), row).is_empty(),
        "{what}: the honest trace is violated at row {row}"
    );
    assert!(
        !l2test::violations_at(bad_air, bad, &pvs_f(bad_pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

fn tampered<Fn_: FnOnce(&mut L2PBucketInstance)>(f: Fn_) -> (L2PBucketInstance, RowMajorMatrix<F>) {
    let mut inst = fabricated_bucket_l2p_v2();
    f(&mut inst);
    let trace = inst.air.generate_trace::<F>(0);
    (inst, trace)
}

// ------------------------------------------------------------------ geometry

#[test]
fn l2pv2_v1_geometry_is_unchanged() {
    assert_eq!(SHAPE_P_PERMS, 252);
    assert_eq!(PROGRAM_SLOTS, 252);
    assert_eq!(L2P_WIDTH, 804);
    assert_eq!(PV_LEN, 144);
    let v1 = L2ShapePAir::chain_only(SHAPE_P_LOG_HEIGHT);
    assert_eq!(v1.version, L2Version::V1);
    assert_eq!(v1.program.len(), PROGRAM_SLOTS);
    assert_eq!(<L2ShapePAir as BaseAir<F>>::width(&v1), L2P_WIDTH);
    assert_eq!(<L2ShapePAir as BaseAir<F>>::num_public_values(&v1), PV_LEN);
}

#[test]
fn l2pv2_geometry() {
    assert_eq!(SHAPE_P_PERMS_V2, 288);
    assert_eq!(PROGRAM_SLOTS_V2, 288);
    assert_eq!(L2P_WIDTH_V2, 857);
    assert_eq!(PV_LEN_V2, 192);
    assert_eq!(
        (PV_LEAF1, PV_LEAF2, PV_LEAF3),
        (PV_LEN, PV_LEN + 16, PV_LEN + 32)
    );
    let inst = fabricated_bucket_l2p_v2();
    let p = &inst.air.program;
    assert_eq!(p.len(), PROGRAM_SLOTS_V2);
    assert_eq!(
        p.iter().filter(|r| **r != ROLE_DUMMY).count(),
        SHAPE_P_PERMS_V2 - 1
    );
    assert!(!p.contains(&ROLE_ANK) && !p.contains(&ROLE_NF));
    for k in 0..3 {
        let a = slot_of(p, ROLE_AAUTH, k);
        assert!(p[a + 1..a + D_AUTH].iter().all(|r| *r == ROLE_MERKLE));
        assert_eq!(p[a + D_AUTH], ROLE_BAUTH);
    }
    // Input chains: BAUTH → AISS → ARKM (AISS stays adjacent to ARKM, whose
    // boundary captures AISS's digest); the fee chain: BAUTH → ARKM.
    for k in 0..2 {
        let b = slot_of(p, ROLE_BAUTH, k);
        assert_eq!((p[b + 1], p[b + 2]), (ROLE_AISS, ARKM));
    }
    let b = slot_of(p, ROLE_BAUTH, 2);
    assert_eq!(p[b + 1], ARKM);
    assert_eq!(inst.pvs.len(), PV_LEN_V2);
}

#[test]
fn l2pv2_chain_only_satisfies_constraints() {
    let air = L2ShapePAir::chain_only_v2(14);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), L2P_WIDTH_V2);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN_V2]);
}

// ------------------------------------------------------------------ honest

#[test]
fn l2pv2_honest_holder_spend_satisfies() {
    assert_eq!(honest().trace.width(), L2P_WIDTH_V2);
}

// ------------------------------------------------------------------ negatives

/// Each slot's leaf is refused at that slot's AAUTH close and nowhere else.
#[test]
fn l2pv2_neg_leaf_not_the_public_value() {
    let fx = honest();
    let p = &fx.inst.air.program;
    let rows: Vec<usize> = (0..3)
        .map(|k| close_row(slot_of(p, ROLE_AAUTH, k)))
        .collect();
    for (k, base) in [PV_LEAF1, PV_LEAF2, PV_LEAF3].into_iter().enumerate() {
        let mut pvs = fx.inst.pvs.clone();
        pvs[base] ^= 1;
        refused_at(&fx.inst.air, &fx.trace, &pvs, rows[k], &format!("leaf {k}"));
        for (j, r) in rows.iter().enumerate().filter(|(j, _)| *j != k) {
            assert!(
                l2test::violations_at(&fx.inst.air, &fx.trace, &pvs_f(&pvs), *r).is_empty(),
                "leaf {k}: also refused at slot {j}'s close"
            );
        }
    }
}

/// ARKM absorbs a root that is not the path's: bank EQA at ARKM's close.
#[test]
fn l2pv2_neg_auth_root_in_arkm_not_the_tree_root() {
    let (bad, t) = tampered(|i| {
        let s = slot_of(&i.air.program, ARKM, 0);
        i.air.slot_witness[s].w[7] ^= 1;
    });
    let row = close_row(slot_of(&bad.air.program, ARKM, 0));
    refused_at(&bad.air, &t, &bad.pvs, row, "auth_root in ARKM");
}

/// Bank 1's forgery shape: another nk at NFA with nf republished — refused at
/// ARKM's close.
#[test]
fn l2pv2_neg_nk_at_nfa_not_the_nk_in_rkm() {
    let (bad, t) = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_NFA, 0);
        let mut nk = [0u64; 4];
        nk.copy_from_slice(&i.air.slot_witness[s].w[9..13]);
        nk[0] ^= 1;
        i.air.slot_witness[s].w[9..13].copy_from_slice(&nk);
        let mut rho = [0u64; 4];
        rho.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_NF1..PV_NF1 + 16].copy_from_slice(&pv_chunks(&l2_nf(&nk, &rho)));
    });
    let row = close_row(slot_of(&bad.air.program, ARKM, 0));
    refused_at(&bad.air, &t, &bad.pvs, row, "nk at NFA");
}

/// The fee slot's dummy leaf not under its `auth_root` (leaf and PV moved
/// together): refused at the fee chain's ARKM close.
#[test]
fn l2pv2_neg_fee_dummy_leaf_not_under_its_auth_root() {
    let (bad, t) = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH, 2);
        i.air.slot_witness[s].w[0] ^= 1;
        let mut leaf = [0u64; 4];
        leaf.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_LEAF3..PV_LEN_V2].copy_from_slice(&pv_chunks(&leaf));
    });
    let row = close_row(slot_of(&bad.air.program, ARKM, 2));
    refused_at(
        &bad.air,
        &t,
        &bad.pvs,
        row,
        "fee dummy leaf not under its root",
    );
}

/// P-specific: an `ARKM2` re-derivation with a different `auth_root` gives a
/// different `rkm′`, which v1's output-equality window to the first `ARKM`
/// refuses — the same root is forced into all three derivations. Whole-scan
/// (the window closes at `ACRED`/`ACM`, two different banks).
#[test]
fn l2pv2_neg_arkm2_with_another_auth_root() {
    let (bad, t) = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_ARKM2, 0);
        i.air.slot_witness[s].w[8] ^= 1;
    });
    assert!(
        l2test::first_violation(
            &bad.air,
            &t,
            &pvs_f(&bad.pvs),
            SHAPE_P_PERMS_V2 * ROWS_PER_PERM
        )
        .is_some(),
        "ARKM2 with another auth_root VERIFIED"
    );
}
