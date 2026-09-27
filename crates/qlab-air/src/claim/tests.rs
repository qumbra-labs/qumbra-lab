//! The claim circuit's tests (lab #756). The cost model is `l2r`'s: the honest
//! instance is generated and scanned once for the module; every UNSAT claim
//! stops at its first violation and pins the perm it is refused at. A
//! negative that breaks more than one gate by construction (a moved `cnf`
//! breaks its bind and the credit's ρ close) states each refusal row by row
//! with `l2test::violations_at` instead — a parallel scan returns whichever
//! it meets first.

use std::sync::OnceLock;

use p3_air::check_constraints;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use super::*;
use crate::l2test::{self, Violation};
use crate::reference;

type F = KoalaBear;

fn pvs_of(inst: &ClaimInstance) -> Vec<F> {
    inst.pvs.iter().map(|v| F::from_u32(*v)).collect()
}
fn digest(state: &[u64; 25]) -> [u64; 4] {
    state[..4].try_into().unwrap()
}
fn slot_of(program: &[u32; PROGRAM_SLOTS], role: u32, nth: usize) -> usize {
    program.iter().enumerate().filter(|(_, r)| **r == role).map(|(i, _)| i).nth(nth).unwrap()
}
/// The last row of perm `slot` — where its close and bind gates fire.
fn close_row(slot: usize) -> usize {
    (slot + 1) * ROWS_PER_PERM - 1
}
fn set_pv(pvs: &mut [u32], base: usize, d: &[u64; 4]) {
    pvs[base..base + 16].copy_from_slice(&pv_chunks(d));
}

/// An UNSAT claim refused **at perm `slot`**.
fn assert_refused_at(inst: &ClaimInstance, slot: usize, what: &str) {
    let trace = inst.air.generate_trace::<F>(0);
    assert_trace_refused_at(&inst.air, &trace, &pvs_of(inst), slot, what);
}
fn assert_trace_refused_at(air: &ClaimAir, trace: &RowMajorMatrix<F>, pvs: &[F], slot: usize, what: &str) {
    match l2test::first_violation(air, trace, pvs, (slot + 1) * ROWS_PER_PERM) {
        None => panic!("{what} VERIFIED"),
        Some(v) => assert_eq!(
            v.row / ROWS_PER_PERM,
            slot,
            "{what}: refused, but at {v} (perm {}), not at perm {slot}",
            v.row / ROWS_PER_PERM
        ),
    }
}
/// Refused on row `row` (whatever else also refuses it).
fn assert_row_refuses(air: &ClaimAir, trace: &RowMajorMatrix<F>, pvs: &[F], row: usize, what: &str) {
    assert!(!l2test::violations_at(air, trace, pvs, row).is_empty(), "{what}: row {row} accepts");
}

// ---------------------------------------------------------------------------
// The fixture: a 250,000-unit burn into L2 1, fee 3. Its host hashes are
// pinned below against an independent Keccak-256 (pycryptodome, over bytes).
// ---------------------------------------------------------------------------

const L2_ID: u64 = 1;
const V: u64 = 250_000;
const FEE: u64 = 3;
const RHO: [u64; 4] = [0x0c1a_0001, 0x0c1a_0002, 0x0c1a_0003, 0x0c1a_0004];
const RSEED: [u64; 4] = [0x0c1a_0101, 0x0c1a_0102, 0x0c1a_0103, 0x0c1a_0104];
const R_V: [u64; 4] = [0x0c1a_0201, 0x0c1a_0202, 0x0c1a_0203, 0x0c1a_0204];
const CREDIT: ClaimCredit = ClaimCredit {
    rkm: [0x0c1a_0301, 0x0c1a_0302, 0x0c1a_0303, 0x0c1a_0304],
    rseed: [0x0c1a_0401, 0x0c1a_0402, 0x0c1a_0403, 0x0c1a_0404],
};

fn note() -> BurnNote {
    BurnNote { value: V, rkm: rkm_burn(L2_ID), rho: RHO, rseed: RSEED }
}
fn claim(note: &BurnNote, fee: u64) -> ClaimInstance {
    build_claim(CLAIM_LOG_HEIGHT, L2_ID, note, &R_V, &CREDIT, fee)
}

struct Fixture {
    inst: ClaimInstance,
    trace: RowMajorMatrix<F>,
    pvs: Vec<F>,
    verdict: Result<(), Violation>,
}
static HONEST: OnceLock<Fixture> = OnceLock::new();
fn honest() -> &'static Fixture {
    HONEST.get_or_init(|| {
        let inst = claim(&note(), FEE);
        let pvs = pvs_of(&inst);
        let trace = inst.air.generate_trace::<F>(0);
        let verdict = l2test::satisfied(&inst.air, &trace, &pvs);
        Fixture { inst, trace, pvs, verdict }
    })
}
impl Fixture {
    fn assert_sat(&self, what: &str) {
        if let Err(v) = &self.verdict {
            panic!("{what}: constraints not satisfied on {v}");
        }
    }
}
/// Program slot of `role` (its first occurrence).
fn at(role: u32) -> usize {
    slot_of(&honest().inst.air.program, role, 0)
}

/// Re-derive the credit over `cnf` (its ρ lanes and commitment) and republish
/// `cnf` and `cm2` — so a tamper upstream of the credit leaves it consistent.
fn republish_credit(inst: &mut ClaimInstance, cnf: [u64; 4]) {
    let out = slot_of(&inst.air.program, ROLE_ACMOUT, 0);
    inst.air.slot_witness[out].w[5..9].copy_from_slice(&cnf);
    let w = inst.air.slot_witness[out].w;
    inst.cnf = cnf;
    inst.cm2 = l2_cm(w[4], w[13], &w[..4].try_into().unwrap(), &cnf, &w[9..13].try_into().unwrap());
    let cm2 = inst.cm2;
    set_pv(&mut inst.pvs, PV_CNF, &cnf);
    set_pv(&mut inst.pvs, PV_CM2, &cm2);
}

// ---------------------------------------------------------------------------
// Pins — the three frozen derivations, against pycryptodome's Keccak-256 of
// the byte messages (`keccak.new(digest_bits=256)`), so each golden also
// checks the lane layout against byte-level Keccak.
// ---------------------------------------------------------------------------

fn hex(d: &[u64; 4]) -> String {
    d.iter().flat_map(|l| l.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

/// `rkm_burn(1)`, the fixture's `cm`, `cnf`, `Cv` and `cm2` (value `v − fee`,
/// asset 0, ρ = cnf) — computed by pycryptodome over the byte messages:
/// `tag ‖ u64le(1)`; `u64le(v) ‖ rkm_burn ‖ ρ ‖ rseed`; `CNF_TAG ‖ 00×6 ‖ cm ‖
/// rseed`; `CV_TAG ‖ 00×3 ‖ u64le(v) ‖ r_v`; `u64le(v−fee) ‖ u64le(0) ‖ rkm_dst
/// ‖ cnf ‖ rseed2` (lanes little-endian).
#[test]
fn claim_derivations_are_pinned() {
    assert_eq!((CNF_TAG.len(), CV_TAG.len(), BURN_TAG.len()), (18, 21, 17));
    let burn = rkm_burn(L2_ID);
    assert_eq!(hex(&burn), "64bc1142b61e0ea8042476b9c419448a0393ab8db4f7eac1af9f8d73a59a570e", "rkm_burn(1)");
    let cm = l1_cm(V, &burn, &RHO, &RSEED);
    assert_eq!(hex(&cm), "583fe08609f6e0d22e93f4033399cedf353848a4a900f920d1ca22ee2ef98f82", "the burn note's cm");
    let cnf = claim_cnf(&cm, &RSEED);
    assert_eq!(hex(&cnf), "3de9d9d6f8c30dfe7b880c02a7f56f3f1fada3b8c479be9a199b004e7cb9c867", "cnf");
    let cv = claim_cv(V, &R_V);
    assert_eq!(hex(&cv), "e817689be46af6dff42b4f345b219e396bf963c992c4d2500bd70bb9ac936193", "Cv");
    let cm2 = l2_cm(V - FEE, 0, &CREDIT.rkm, &cnf, &CREDIT.rseed);
    assert_eq!(hex(&cm2), "45e49d28345af04421a5d0e4c1dd1e23fcdb67cb7a38724f0240b410a7cc1a52", "cm2");
    // The fixture publishes exactly these.
    let inst = &honest().inst;
    assert_eq!((inst.cm, inst.cnf, inst.cv, inst.cm2, inst.rkm_burn), (cm, cnf, cv, cm2, burn));
    assert_eq!(inst.pvs, pv_vec_claim(&inst.anchor, &cnf, &cv, &cm2, &burn, FEE));
}

/// The lane forms equal the byte forms (the in-crate cross-check of the
/// table in the module doc), and the burn domain separates chains.
#[test]
fn claim_lane_forms_are_byte_keccak() {
    let cm = [0x1111, 0x2222, 0x3333, 0x4444];
    let lanes_le = |ws: &[u64]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
    let mut m = CNF_TAG.to_vec();
    m.resize(24, 0);
    m.extend(lanes_le(&cm));
    m.extend(lanes_le(&RSEED));
    assert_eq!(m.len(), 88);
    assert_eq!(keccak256_lanes(&m), claim_cnf(&cm, &RSEED));
    let mut m = CV_TAG.to_vec();
    m.resize(24, 0);
    m.extend(V.to_le_bytes());
    m.extend(lanes_le(&R_V));
    assert_eq!(m.len(), 64);
    assert_eq!(keccak256_lanes(&m), claim_cv(V, &R_V));
    let mut m = lanes_le(&[V]);
    m.extend(lanes_le(&cm));
    m.extend(lanes_le(&RHO));
    m.extend(lanes_le(&RSEED));
    assert_eq!(keccak256_lanes(&m), l1_cm(V, &cm, &RHO, &RSEED));
    assert_ne!(rkm_burn(1), rkm_burn(2), "every L2 its own pot");
}

/// `l1_cm` is the L1's own note commitment: `narrow::derive_input`'s `cm`
/// for a spendable note, recomputed from its rkm.
#[test]
fn claim_l1_cm_is_the_l1_commitment() {
    use crate::narrow::{derive_input, TxInput};
    let inp = TxInput { sk: [0x5a1, 0x5a2, 0x5a3, 0x5a4], value: V, rho: RHO, rseed: RSEED, d: [0x8d1, 0x8d2] };
    let (nk, _, cm) = derive_input(&inp);
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&nk);
    st[4] = 1 << 1;
    st[5] = inp.d[0];
    st[6] = inp.d[1];
    st[7] = 1;
    st[16] = 1 << 63;
    let rkm: [u64; 4] = reference::keccak_f(&st)[..4].try_into().unwrap();
    assert_eq!(l1_cm(V, &rkm, &RHO, &RSEED), cm);
}

/// N10's host half: `cnf` is not the Merkle parent of `(cm, rseed)` — the
/// tag and the pad position (lane 11, not 8) separate the two blocks.
///
/// `Cv` **does** share MERKLE's block shape (64 bytes, pad at lane 8): it is
/// the Merkle parent of `(CV_TAG ‖ v, r_v)`. Stated, not hidden: a Merkle
/// node equals some `Cv` only if its left child's first 21 bytes are the tag
/// — a preimage-class event (stage-0 §3), and the claim AIR never feeds a
/// Merkle output into AVC or the reverse.
#[test]
fn claim_domains_against_merkle() {
    let cm = honest().inst.cm;
    assert_ne!(claim_cnf(&cm, &RSEED), digest(&reference::merkle_node_state(&cm, &RSEED)));
    let left = [CV_TAG_LANES[0], CV_TAG_LANES[1], CV_TAG_LANES[2], V];
    assert_eq!(claim_cv(V, &R_V), digest(&reference::merkle_node_state(&left, &R_V)), "Cv's block is MERKLE-shaped");
    assert_eq!(CV_TAG_LANES[2] >> 40, 0, "the tag's last three bytes are the zero pad");
    assert_ne!(CV_TAG_LANES[..2], CNF_TAG_LANES[..2], "the two tags differ in their first 16 bytes");
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

#[test]
fn claim_chain_only_satisfies_constraints() {
    let air = ClaimAir::chain_only(10);
    let trace = air.generate_trace::<F>(0);
    check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN]);
}

/// Width 655, every column named: the engine and M3 machinery as `l2r.rs`
/// (491 up to the selectors), then the claim's own.
#[test]
fn claim_trace_width_is_read_off_the_matrix() {
    let air = ClaimAir::chain_only(10);
    let trace = air.generate_trace::<F>(0);
    assert_eq!(trace.width(), CLAIM_WIDTH, "width must be the matrix's own");
    let engine = 402; // narrow's Keccak-f engine, verbatim
    let machinery = 24 + 4 + 32 + 20 + 5 + 4; // PB, PH, PR (32 limbs), D, RB, LO
    let roles = 10 // SEL: MERKLE, ACM_BURN, ACNF, BCNF, MW1, BANCHOR, AVC, BVC, ACMOUT, BCM
        + 6 // INJ: merkle, acm_burn, acnf, mw1, avc, acmout
        + 1 // G4
        + 5 // CL: acm_burn, acnf, mw1, avc, acmout
        + 1 // BGCAP
        + 4; // BGC: banchor, bcnf, bvc, bcm
    let witness = 1 + 14 + 25; // PBIT, W, EFF
    let banks = 16 // BQ
        + 16 * 4 // RK, RS, CM, RH
        + 4 + 4 // VA, VB
        + 9; // BLC: the credit's borrow chain against the fee
    assert_eq!(machinery, 89);
    assert_eq!(roles, 27);
    assert_eq!(banks, 97);
    assert_eq!(trace.width(), engine + machinery + roles + witness + banks);
    assert_eq!(trace.width(), 655, "the claim width");
}

/// Max constraint degree 4, 4 quotient chunks (under ZK, degree 3 would be
/// the same prover). The degree-4 population is the 10 role selectors alone.
#[test]
fn claim_quotient_degree_is_4() {
    use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
    let air = ClaimAir::chain_only(CLAIM_LOG_HEIGHT);
    let deg = get_max_constraint_degree::<F, _>(&air, AirLayout::from_air::<F>(&air));
    assert_eq!(deg, 4, "max constraint degree");
    assert_eq!((deg - 1).next_power_of_two(), 4, "quotient chunks");
    let cs = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
    let deg4 = cs.iter().filter(|c| c.degree_multiple() == 4).count();
    assert_eq!(deg4, NSEL, "deg-4 constraints: the selectors");
}

/// 41 perms in 2^17, one ring period (no epoch), the program as documented.
#[test]
fn claim_program_geometry() {
    assert_eq!(CLAIM_PERMS, 41);
    assert_eq!(CLAIM_LOG_HEIGHT, 17);
    let p = &honest().inst.air.program;
    let mut want = vec![ROLE_DUMMY, ROLE_ACM_BURN, ROLE_ACNF, ROLE_BCNF, ROLE_MW1];
    want.extend(std::iter::repeat_n(ROLE_MERKLE, MERKLE_DEPTH - 1));
    want.extend([ROLE_BANCHOR, ROLE_AVC, ROLE_BVC, ROLE_ACMOUT, ROLE_BCM]);
    assert_eq!(want.len(), CLAIM_PERMS);
    assert_eq!(&p[..CLAIM_PERMS], &want[..]);
    assert!(p[CLAIM_PERMS..].iter().all(|r| *r == ROLE_DUMMY));
    let mut codes = SEL_CODES.to_vec();
    codes.push(ROLE_DUMMY);
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), NSEL + 1, "no two roles share a code");
    assert!(codes.iter().all(|c| *c < 1 << ROLE_BITS));
}

/// No END: the last gate of the program is BCM's bind on perm 40's last row,
/// inside the trace, and every row after it is gate-free — nothing is checked
/// at the trace's end. A moved `cm2` is refused on exactly that row; the
/// credit's banks close on ACMOUT's (perm 39) last row (`claim_neg_credit`).
#[test]
fn claim_last_perm_gates_fire() {
    let fx = honest();
    fx.assert_sat("precondition");
    let bcm = at(ROLE_BCM);
    assert_eq!(bcm, CLAIM_PERMS - 1, "BCM is the last perm");
    assert!(close_row(bcm) < fx.trace.height());
    let cell = |row: usize, col: usize| fx.trace.values[row * CLAIM_WIDTH + col];
    assert_eq!(cell(close_row(bcm), BGC_OFF + 3), F::ONE, "BCM's bind gate fires");
    assert_eq!(cell(close_row(at(ROLE_ACMOUT)), CL_OFF + CL_OUT), F::ONE, "ACMOUT's close fires");
    for row in close_row(bcm) + 1..fx.trace.height() {
        for col in (CL_OFF..CL_OFF + NCL).chain(BGC_OFF..BGC_OFF + NBGC).chain(SEL_OFF..SEL_OFF + NSEL) {
            assert_eq!(cell(row, col), F::ZERO, "a gate after the program: row {row} col {col}");
        }
    }
    let mut pvs = fx.pvs.clone();
    pvs[PV_CM2 + 15] += F::ONE;
    assert_trace_refused_at(&fx.inst.air, &fx.trace, &pvs, bcm, "a moved cm2 at the last perm");
    assert_row_refuses(&fx.inst.air, &fx.trace, &pvs, close_row(bcm), "BCM's bind");
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn claim_satisfies_constraints() {
    honest().assert_sat("the honest claim at 2^17");
}

/// The chain the AIR advances is the reference one, read off the trace.
#[test]
fn claim_chain_matches_reference() {
    let fx = honest();
    let out_of = |role: u32| digest(&ClaimAir::extract_state(&fx.trace, 24 * (at(role) + 1)));
    assert_eq!(out_of(ROLE_ACM_BURN), fx.inst.cm, "ACM_BURN = the burn note's cm");
    assert_eq!(out_of(ROLE_ACNF), fx.inst.cnf, "ACNF = cnf");
    assert_eq!(digest(&ClaimAir::extract_state(&fx.trace, 24 * at(ROLE_BANCHOR))), fx.inst.anchor);
    assert_eq!(out_of(ROLE_AVC), fx.inst.cv, "AVC = Cv");
    assert_eq!(out_of(ROLE_ACMOUT), fx.inst.cm2, "ACMOUT = cm2");
    assert_eq!(fx.inst.cm2, l2_cm(V - FEE, 0, &CREDIT.rkm, &fx.inst.cnf, &CREDIT.rseed));
}

/// A zero fee and a fee of the whole value (a 0-value credit) both verify.
#[test]
fn claim_fee_edges_satisfy() {
    for fee in [0, V] {
        let inst = claim(&note(), fee);
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs_of(&inst), &format!("fee {fee}"));
    }
}

// ---------------------------------------------------------------------------
// Negatives — the ruling's N1–N10 plus the fee. Each is a complete forgery
// where one exists (public values republished to match), refused at a pinned
// perm.
// ---------------------------------------------------------------------------

/// 🔴 N1: a note paying anyone but the burn address — a complete claim of
/// it (its own tree, anchor, cnf, credit), refused by the rkm bank.
#[test]
fn claim_neg_n1_note_not_to_the_burn_address() {
    let mut n = note();
    n.rkm = [0x9e1, 0x9e2, 0x9e3, 0x9e4];
    assert_refused_at(&claim(&n, FEE), at(ROLE_ACM_BURN), "a note to another rkm");
    // Another L2's burn address is "anyone else" too.
    n.rkm = rkm_burn(L2_ID + 1);
    assert_refused_at(&claim(&n, FEE), at(ROLE_ACM_BURN), "a burn into L2 2 claimed on L2 1");
}

/// 🔴 N2: a wrong sibling (the anchor kept), and a root that is not `A`.
#[test]
fn claim_neg_n2_path_misses_the_anchor() {
    let mut inst = honest().inst.clone();
    let s = slot_of(&inst.air.program, ROLE_MERKLE, 4);
    inst.air.slot_witness[s].w[2] ^= 1;
    assert_refused_at(&inst, at(ROLE_BANCHOR), "a wrong level-6 sibling");
    let mut inst = honest().inst.clone();
    let s = at(ROLE_MW1);
    inst.air.slot_witness[s].w[0] ^= 1 << 40;
    assert_refused_at(&inst, at(ROLE_BANCHOR), "a wrong level-1 sibling");
    let fx = honest();
    let mut pvs = fx.pvs.clone();
    pvs[PV_A + 9] += F::ONE;
    assert_trace_refused_at(&fx.inst.air, &fx.trace, &pvs, at(ROLE_BANCHOR), "a root that is not A");
}

/// 🔴 N3: PBIT = 1 on every non-Merkle role, one at a time — the blanket
/// `(1 − sel(MERKLE) − sel(MW1))·PBIT = 0` refuses it on that perm (the lab
/// #287 lesson). Slot 0 and slot 41 are dummies (the lead-in and the tail).
#[test]
fn claim_neg_n3_pbit_on_every_other_role() {
    honest().assert_sat("precondition");
    let p = honest().inst.air.program;
    let slots: Vec<usize> = (0..=CLAIM_PERMS)
        .filter(|s| p[*s] != ROLE_MERKLE && p[*s] != ROLE_MW1)
        .collect();
    assert_eq!(slots.len(), 10, "DUMMY ×2, ACM_BURN, ACNF, BCNF, BANCHOR, AVC, BVC, ACMOUT, BCM");
    l2test::fan_out(slots, l2test::ASSIGNMENT_FANOUT, |s| {
        let mut inst = honest().inst.clone();
        inst.air.slot_witness[s].pbit = true;
        assert_refused_at(&inst, s, &format!("PBIT = 1 on slot {s} (role {})", p[s]));
    });
    // And on the Merkle roles it is a path bit: flipping MW1's moves the
    // root, so the honest anchor refuses (the path is not a free choice).
    let mut inst = honest().inst.clone();
    inst.air.slot_witness[at(ROLE_MW1)].pbit = true;
    assert_refused_at(&inst, at(ROLE_BANCHOR), "MW1's path bit flipped");
}

/// 🔴 N4: cnf over another rseed — the credit and both publics re-derived
/// from it; the rseed bank refuses at ACNF.
#[test]
fn claim_neg_n4_cnf_over_another_rseed() {
    let mut inst = honest().inst.clone();
    let s = at(ROLE_ACNF);
    let other = [0xbad1, 0xbad2, 0xbad3, 0xbad4];
    inst.air.slot_witness[s].w[..4].copy_from_slice(&other);
    let cnf = claim_cnf(&inst.cm, &other);
    republish_credit(&mut inst, cnf);
    assert_refused_at(&inst, s, "cnf over an rseed that is not the note's");
}

/// 🔴 N5: the path opened from another note than the one cnf absorbed —
/// MW1's leaf is `cm′` (a note in the tree), the anchor republished to its
/// fold; the cm bank refuses at MW1.
#[test]
fn claim_neg_n5_path_from_another_note() {
    let mut inst = honest().inst.clone();
    let other = l1_cm(V, &rkm_burn(L2_ID), &RHO, &[0xbad1, 0xbad2, 0xbad3, 0xbad4]);
    let s = at(ROLE_MW1);
    inst.air.slot_witness[s].w[4..8].copy_from_slice(&other);
    let (path, _) = fabricated_single_tree(&other);
    inst.anchor = path.fold_root(&other);
    let anchor = inst.anchor;
    set_pv(&mut inst.pvs, PV_A, &anchor);
    assert_refused_at(&inst, s, "a path from cm′ under a cnf over cm");
}

/// 🔴 N6: Cv over another value than the burned one, each direction; `Cv`
/// republished. The v bank refuses at AVC.
#[test]
fn claim_neg_n6_cv_value_mismatch() {
    for (what, vc) in [("v + 1", V + 1), ("v − 1", V - 1), ("v + 2^32", V + (1 << 32))] {
        let mut inst = honest().inst.clone();
        let s = at(ROLE_AVC);
        inst.air.slot_witness[s].w[4] = vc;
        let cv = claim_cv(vc, &R_V);
        set_pv(&mut inst.pvs, PV_CV, &cv);
        assert_refused_at(&inst, s, &format!("Cv over {what}"));
    }
}

/// 🔴 N7 and the fee: the credit. Its value off `v − fee` each direction
/// (and the fee not deducted), refused by the borrow chain; asset 7 (on
/// ACMOUT's rows); ρ ≠ cnf (the ρ close). `cm2` republished every time.
#[test]
fn claim_neg_n7_credit() {
    let out = at(ROLE_ACMOUT);
    let republish = |inst: &mut ClaimInstance, f: &dyn Fn(&mut [u64; NW])| {
        f(&mut inst.air.slot_witness[out].w);
        let w = inst.air.slot_witness[out].w;
        inst.cm2 = l2_cm(w[4], w[13], &w[..4].try_into().unwrap(), &w[5..9].try_into().unwrap(), &w[9..13].try_into().unwrap());
        let cm2 = inst.cm2;
        set_pv(&mut inst.pvs, PV_CM2, &cm2);
    };
    for (what, v2) in [("v − fee + 1", V - FEE + 1), ("v − fee − 1", V - FEE - 1), ("v (no fee)", V)] {
        let mut inst = honest().inst.clone();
        republish(&mut inst, &|w| w[4] = v2);
        assert_refused_at(&inst, out, &format!("a credit of {what}"));
    }
    let mut inst = honest().inst.clone();
    republish(&mut inst, &|w| w[13] = 7);
    assert_refused_at(&inst, out, "a credit in asset 7");
    let mut inst = honest().inst.clone();
    republish(&mut inst, &|w| w[5..9].copy_from_slice(&[0x1111, 0x2222, 0x3333, 0x4444]));
    assert_refused_at(&inst, out, "a credit whose ρ is not cnf");
}

/// 🔴 The fee: above the burned value (the credit's value wraps — no borrow
/// chain closes), and a fee PV that is not the one the credit paid.
#[test]
fn claim_neg_fee() {
    let inst = claim(&note(), V + 1);
    assert_refused_at(&inst, at(ROLE_ACMOUT), "fee = v + 1");
    let inst = claim(&note(), u64::MAX);
    assert_refused_at(&inst, at(ROLE_ACMOUT), "fee = 2^64 − 1");
    let fx = honest();
    for (what, fee) in [("fee 4 for a credit of v − 3", 4u32), ("fee 2", 2)] {
        let mut pvs = fx.pvs.clone();
        pvs[PV_FEE] = F::from_u32(fee);
        assert_trace_refused_at(&fx.inst.air, &fx.trace, &pvs, at(ROLE_ACMOUT), what);
    }
    let mut pvs = fx.pvs.clone();
    pvs[PV_FEE + 2] += F::ONE;
    assert_trace_refused_at(&fx.inst.air, &fx.trace, &pvs, at(ROLE_ACMOUT), "fee + 2^32");
}

/// 🔴 N8: every public digest moved by one chunk, refused at its bind (or,
/// for `rkm_burn`, the rkm close). A moved `cnf` breaks two gates — its bind
/// and the credit's ρ close — so both rows are stated.
#[test]
fn claim_neg_n8_public_value_lies() {
    let fx = honest();
    fx.assert_sat("precondition");
    for (what, base, role) in [
        ("A", PV_A, ROLE_BANCHOR),
        ("Cv", PV_CV, ROLE_BVC),
        ("cm2", PV_CM2, ROLE_BCM),
        ("rkm_burn", PV_RKM_BURN, ROLE_ACM_BURN),
    ] {
        for k in [0, 7, 15] {
            let mut pvs = fx.pvs.clone();
            pvs[base + k] += F::ONE;
            assert_trace_refused_at(&fx.inst.air, &fx.trace, &pvs, at(role), &format!("{what} chunk {k} moved"));
        }
    }
    let mut pvs = fx.pvs.clone();
    pvs[PV_CNF + 4] += F::ONE;
    assert!(l2test::first_violation(&fx.inst.air, &fx.trace, &pvs, close_row(at(ROLE_BCM)) + 1).is_some());
    assert_row_refuses(&fx.inst.air, &fx.trace, &pvs, close_row(at(ROLE_BCNF)), "cnf moved: its bind");
    assert_row_refuses(&fx.inst.air, &fx.trace, &pvs, close_row(at(ROLE_ACMOUT)), "cnf moved: the credit's ρ");
}

/// 🔴 N9: a program-ring role swap (ACNF ↔ AVC, witnesses swapped with
/// them) against the canonical AIR — the ring pin refuses on row 0.
#[test]
fn claim_neg_n9_program_role_swap() {
    let fx = honest();
    let mut forged = fx.inst.air.clone();
    let (x, y) = (at(ROLE_ACNF), at(ROLE_AVC));
    forged.program.swap(x, y);
    forged.slot_witness.swap(x, y);
    let trace = forged.generate_trace::<F>(0);
    assert!(l2test::first_violation(&fx.inst.air, &trace, &fx.pvs, CLAIM_PERMS * ROWS_PER_PERM).is_some());
    assert_row_refuses(&fx.inst.air, &trace, &fx.pvs, 0, "the swapped program at the ring pin");
}

/// 🔴 N10: cnf absorbed in MERKLE's shape (no tag, pad at 512) — the
/// `(cm ‖ rseed)` node block — with cnf and the credit republished; the tag
/// constraints refuse it on ACNF's rows.
#[test]
fn claim_neg_n10_untagged_cnf() {
    let mut inst = honest().inst.clone();
    let cnf = digest(&reference::merkle_node_state(&inst.cm, &RSEED));
    assert_ne!(cnf, inst.cnf);
    republish_credit(&mut inst, cnf);
    let trace = inst.air.generate_trace_with::<F>(0, CnfForm::MerkleShaped);
    assert_eq!(digest(&ClaimAir::extract_state(&trace, 24 * (at(ROLE_ACNF) + 1))), cnf, "the forgery hashes as MERKLE");
    assert_trace_refused_at(&inst.air, &trace, &pvs_of(&inst), at(ROLE_ACNF), "a Merkle-shaped cnf");
}
