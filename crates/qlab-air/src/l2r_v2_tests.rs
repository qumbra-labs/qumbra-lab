//! Shape R v2 (Candidate A authorization) — lab #896 seam D. Mirrors shape S's
//! seam B tests: the honest v2 trace is generated once (`OnceLock`) and scanned
//! in full; every negative is pinned to its gate's close row with
//! `l2test::violations_at` (honest clean there, tampered refused there).

use std::sync::OnceLock;

use p3_air::{check_constraints, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use super::*;
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

/// The last row of perm `slot`: where its gperm-gated closes fire.
fn close_row(slot: usize) -> usize {
    (slot + 1) * ROWS_PER_PERM - 1
}

struct Fixture {
    inst: L2ShapeRInstanceV2,
    trace: RowMajorMatrix<F>,
}

fn honest() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    CELL.get_or_init(|| {
        let inst = fabricated_shape_r_v2();
        let trace = inst.inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(
            &inst.inst.air,
            &trace,
            &pvs_f(&inst.inst.pvs),
            "honest v2 R",
        );
        Fixture { inst, trace }
    })
}

/// Refused AT `row`, and the honest trace is clean there.
fn refused_at(bad: &L2ShapeRInstance, bad_trace: &RowMajorMatrix<F>, row: usize, what: &str) {
    let fx = honest();
    assert!(
        l2test::violations_at(&fx.inst.inst.air, &fx.trace, &pvs_f(&fx.inst.inst.pvs), row)
            .is_empty(),
        "{what}: the honest trace is violated at row {row}"
    );
    assert!(
        !l2test::violations_at(&bad.air, bad_trace, &pvs_f(&bad.pvs), row).is_empty(),
        "{what} VERIFIED at its close (row {row})"
    );
}

fn tampered(f: impl FnOnce(&mut L2ShapeRInstance)) -> L2ShapeRInstance {
    let mut inst = fabricated_shape_r_v2().inst;
    f(&mut inst);
    inst
}

fn refused_at_role(bad: &L2ShapeRInstance, role: u32, what: &str) {
    let row = close_row(slot_of(&bad.air.program, role, 0));
    let trace = bad.air.generate_trace::<F>(0);
    refused_at(bad, &trace, row, what);
}

// ------------------------------------------------------------------ geometry

/// The version parameter does not reach v1: R's constants and widths are the
/// ones `SHAPE_R_DIGEST_V1` (qlab-l2 goldens) was taken over.
#[test]
fn l2r_v2_v1_geometry_is_unchanged() {
    assert_eq!(SHAPE_R_PERMS, 82);
    assert_eq!(PROGRAM_SLOTS, 128);
    assert_eq!(L2R_WIDTH, 734);
    assert_eq!(PV_LEN, 101);
    let v1 = L2ShapeRAir::chain_only(SHAPE_R_LOG_HEIGHT);
    assert_eq!(v1.version, L2RVersion::V1);
    assert_eq!(v1.program.len(), PROGRAM_SLOTS);
    assert_eq!(<L2ShapeRAir as BaseAir<F>>::width(&v1), L2R_WIDTH);
    assert_eq!(<L2ShapeRAir as BaseAir<F>>::num_public_values(&v1), PV_LEN);
}

#[test]
fn l2r_v2_geometry() {
    assert_eq!(D_AUTH_R, 12);
    assert_eq!(SHAPE_R_PERMS_V2, 94);
    assert_eq!(SHAPE_R_LOG_HEIGHT_V2, 19);
    assert_eq!(PROGRAM_SLOTS_V2, 172);
    assert_eq!(L2R_WIDTH_V2, 785);
    assert_eq!((PV_LEAF, PV_LEN_V2), (PV_LEN, PV_LEN + 16));
    let inst = fabricated_shape_r_v2().inst;
    let p = &inst.air.program;
    assert_eq!(p.len(), PROGRAM_SLOTS_V2);
    assert_eq!(
        p.iter().filter(|r| **r != ROLE_DUMMY).count(),
        SHAPE_R_PERMS_V2 - 1
    );
    assert!(!p.contains(&ROLE_ANK), "v2 has no ANK");
    assert!(!p.contains(&ROLE_NF), "v2 NF is NFA");
    assert_eq!(p.iter().filter(|r| **r == ROLE_AAUTH_R).count(), 1);
    let a = slot_of(p, ROLE_AAUTH_R, 0);
    assert!(p[a + 1..a + D_AUTH_R].iter().all(|r| *r == ROLE_MERKLE));
    assert_eq!(p[a + D_AUTH_R], ROLE_BAUTH_R);
    assert_eq!(p[a + D_AUTH_R + 1], ROLE_ARKM);
    assert_eq!(inst.pvs.len(), PV_LEN_V2);
}

/// The v2 columns hold on an all-dummy program at a small height.
#[test]
fn l2r_v2_chain_only_satisfies_constraints() {
    let air = L2ShapeRAir::chain_only_v2(14);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), L2R_WIDTH_V2);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN_V2]);
}

/// Host mirrors: the root fold and the v2 rkm block.
#[test]
fn l2r_v2_host_mirrors() {
    let inp = fabricated_r_auth_input(7, 5, 0b101);
    let p = &inp.auth;
    let mut d = p.leaf;
    for k in 0..D_AUTH_R {
        let st = if (p.leaf_index >> k) & 1 == 1 {
            crate::reference::merkle_node_state(&p.siblings[k], &d)
        } else {
            crate::reference::merkle_node_state(&d, &p.siblings[k])
        };
        d = st[..4].try_into().unwrap();
    }
    assert_eq!(p.root(), d);
    let mut other = inp.clone();
    other.auth.siblings[3][1] ^= 1;
    assert_ne!(
        derive_input_r_v2(&inp).1,
        derive_input_r_v2(&other).1,
        "rkm binds the tree"
    );
    assert_eq!(
        derive_input_r_v2(&inp).0,
        derive_input_r_v2(&other).0,
        "nf does not see the tree"
    );
}

// ------------------------------------------------------------------ honest

#[test]
fn l2r_v2_honest_registration_satisfies() {
    let fx = honest();
    assert_eq!(fx.trace.width(), L2R_WIDTH_V2);
}

// ------------------------------------------------------------------ negatives

/// The leaf that is not the public one: refused at AAUTH's close.
#[test]
fn l2r_v2_neg_leaf_not_the_public_value() {
    let fx = honest();
    let mut bad = fx.inst.inst.clone();
    bad.pvs[PV_LEAF] ^= 1;
    let row = close_row(slot_of(&bad.air.program, ROLE_AAUTH_R, 0));
    refused_at(&bad, &fx.trace, row, "leaf PV");
}

#[test]
fn l2r_v2_neg_sibling_at_level_0() {
    let bad = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH_R, 0);
        i.air.slot_witness[s].w[4] ^= 1;
    });
    refused_at_role(&bad, ROLE_ARKM, "sibling at level 0");
}

#[test]
fn l2r_v2_neg_path_bit_flipped() {
    let bad = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_AAUTH_R, 0) + 5;
        assert_eq!(i.air.program[s], ROLE_MERKLE);
        i.air.slot_witness[s].pbit = !i.air.slot_witness[s].pbit;
    });
    refused_at_role(&bad, ROLE_ARKM, "path bit");
}

/// ARKM absorbs a root that is not the path's: bank EQA at ARKM's close.
#[test]
fn l2r_v2_neg_auth_root_in_arkm_not_the_tree_root() {
    let bad = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_ARKM, 0);
        i.air.slot_witness[s].w[8] ^= 1;
    });
    refused_at_role(&bad, ROLE_ARKM, "auth_root in ARKM");
}

/// Bank-1 forgery shape: a different nk at NFA with nf republished, so only
/// "NFA's nk = ARKM's nk" can refuse at ARKM's close.
#[test]
fn l2r_v2_neg_nk_at_nfa_not_the_nk_in_rkm() {
    let bad = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_NFA_R, 0);
        let mut nk = [0u64; 4];
        nk.copy_from_slice(&i.air.slot_witness[s].w[9..13]);
        nk[2] ^= 1;
        i.air.slot_witness[s].w[9..13].copy_from_slice(&nk);
        let mut rho = [0u64; 4];
        rho.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_NF..PV_NF + 16].copy_from_slice(&pv_chunks(&r_nf_v2(&nk, &rho)));
    });
    refused_at_role(&bad, ROLE_ARKM, "nk at NFA");
}

/// ρ at NFA must be the note's ρ: bank 2 at ACM's close (nf republished).
#[test]
fn l2r_v2_neg_rho_at_nfa_not_the_note_rho() {
    let bad = tampered(|i| {
        let s = slot_of(&i.air.program, ROLE_NFA_R, 0);
        let mut nk = [0u64; 4];
        nk.copy_from_slice(&i.air.slot_witness[s].w[9..13]);
        i.air.slot_witness[s].w[1] ^= 1;
        let mut rho = [0u64; 4];
        rho.copy_from_slice(&i.air.slot_witness[s].w[..4]);
        i.pvs[PV_NF..PV_NF + 16].copy_from_slice(&pv_chunks(&r_nf_v2(&nk, &rho)));
    });
    refused_at_role(&bad, ROLE_ACM, "ρ at NFA");
}
