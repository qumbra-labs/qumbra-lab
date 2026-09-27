//! F1 — the bridge's **claim circuit** (W1), lab issue #756.
//!
//! A deposit is an ordinary L1 transaction paying the per-L2 burn address
//! `rkm_burn`; the depositor later proves, client-side, that the burn note
//! exists and credits its value to an L2 note. A **new AIR type beside the L2
//! shapes** — a fourth fork of the narrow engine (structure for structure, as
//! `l2r.rs`), never an edit to any of them. Pure helpers with identical
//! semantics are imported from `l2` and `narrow`.
//!
//! ## The statement (lab #756 stage-0, ruled 2026-09-27)
//!
//! Public: `A ‖ cnf ‖ Cv ‖ cm2 ‖ rkm_burn ‖ fee`. Private: the burn note's
//! opening (v, ρ′, rseed), its depth-32 path to `A`, the blind `r_v`, and the
//! credited note's (rkm_dst, rseed2). The AIR proves:
//!
//! 1. `cm = H(v ‖ rkm_burn ‖ ρ′ ‖ rseed)` — the **L1** note block, its rkm
//!    lanes equal to the public `rkm_burn` (bank `RK`);
//! 2. `cm` has a depth-32 path to `A`;
//! 3. `cnf = CNF(cm, rseed)` over that note's `cm` and `rseed` (bank `RS`);
//! 4. `Cv` opens to the same `v` (bank `VA`);
//! 5. `cm2 = l2_cm(v − fee, 0, rkm_dst, ρ = cnf, rseed2)` — the credited L2
//!    note, asset 0 bit by bit, its `ρ` the public `cnf` (bank `RH`), its value
//!    `v − fee` on one borrow chain (bank `VB`, the `BLC` carries — the §7
//!    claim bootstrap: a first-time depositor pays the fee out of the credit).
//!    `fee > v` is unprovable.
//!
//! `Cv` commits the **full** `v`, so a batch's `D = Σ v = Σ credits + Σ fees`.
//! The verifier checks `rkm_burn` against its own chain's constant and `fee`
//! against its claim tariff (`qlab-l2`'s claim module) — the AIR takes both as
//! public values so one AIR serves every chain.
//!
//! ## The three domain constants (frozen by F1)
//!
//! Standard byte-level Keccak-256 of lane-aligned messages, one permutation
//! each (rate 136 B, padding `0x01 … 0x80`):
//!
//! | name | message | lanes |
//! |---|---|---|
//! | `cnf` | `"qumbra:l2-claim:v1"` (18 B) ‖ `00`×6 ‖ `cm` ‖ `rseed` = 88 B | tag 0..3 · cm 3..7 · rseed 7..11 · pad lane 11 |
//! | `Cv` | `"qumbra:l2-claim-vc:v1"` (21 B) ‖ `00`×3 ‖ `v` (u64 LE) ‖ `r_v` = 64 B | tag 0..3 · v 3 · r_v 4..8 · pad lane 8 |
//! | `rkm_burn` | `"qumbra:l2-burn:v1"` (17 B) ‖ `l2_id` (u64 LE) = 25 B | off-circuit only |
//!
//! The tags are injected from periodic columns (a role-gated constant
//! equality through the full-state override), so a tag-less message in the
//! same slot is refused on the absorbing perm's rows.
//!
//! ### Program order (41 perms → 2^17)
//!
//! ```text
//! [DUMMY]
//! ACM_BURN → ACNF → BCNF                    the burn note, its claim nullifier
//! MW1 → 31×MERKLE → BANCHOR                 its path to A
//! AVC → BVC                                 the value commitment
//! ACMOUT → BCM                              the credit
//! ```
//!
//! After `ACNF → BCNF` the chained digest is `cnf`, so the first Merkle level
//! takes `cm` from witness lanes `W4..7` (`l2r`'s `MERKLE_W` block, `MW1`),
//! banked against `ACNF`'s chained `a` (bank `CM`).
//!
//! ### No epoch, no END
//!
//! 41 perms fit one period of the 128-slot program ring at 2^17 (42.7 perms),
//! so there is no wrapped second program (as `l2r`). Every bank closes on its
//! own role's last row and every bind on its bind's — the last gate of all is
//! `BCM`'s bind at perm 40's last row, inside the trace; nothing is checked at
//! the trace's end, so the program needs no `END` perm
//! (`claim_last_perm_gates_fire`). Perms 41.. are dummies.
//!
//! ### Column accounting: 655 — see `claim_trace_width_is_read_off_the_matrix`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::l2::{l2_cm, ROWS_PER_PERM};
use crate::narrow::{fabricated_single_tree, pv_chunks, MerkleWitness, MERKLE_DEPTH};
use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — the narrow engine verbatim, the M3 machinery at 5-bit codes (as
// `l2r.rs`), then the claim's gates and banks.
// ---------------------------------------------------------------------------

const A_OFF: usize = 0; // 25: round-input bits (chi output) — real on M rows
const C_OFF: usize = 25; // 5: column parities of `a`
const US_OFF: usize = 30; // 25: unpack of S slot 1 (chi inputs)
const AP_OFF: usize = 55; // 25: theta outputs — real on T rows
const X00_COL: usize = 80; // 1: chi lane (0,0) before iota
const S_OFF: usize = 81; // 126 slots (d = 1..=126)
const S_SLOTS: usize = 126;
const V_OFF: usize = S_OFF + S_SLOTS; // 207: 64 slots (d = 1..=64)
const V_SLOTS: usize = 64;
const UV_OFF: usize = V_OFF + V_SLOTS; // 271: 25: unpack of V slot 1
const U_OFF: usize = UV_OFF + 25; // 296: 65 slots (d = 1..=65)
const U_SLOTS: usize = 65;
const UU_OFF: usize = U_OFF + U_SLOTS; // 361: 10: unpack of U slot 1
const R_OFF: usize = UU_OFF + 10; // 371: 24 rotating iota-RC registers
const B_OFF: usize = R_OFF + 24; // 395: 7: bit-decomposition of R[0]
// --- M3 program machinery (as l2r.rs: 5-bit role codes, 32-limb ring) ---
const PB_OFF: usize = B_OFF + 7; // 402: 24: perm-boundary ring [1,0,..,0]
const PH_OFF: usize = PB_OFF + 24; // 426: 4: perm-phase ring (mod-4 counter)
const PR_LIMBS: usize = 32;
const PR_OFF: usize = PH_OFF + 4; // 430: 32: program ring, 4 slots x 5 bits/limb
const ROLE_BITS: usize = 5;
const D_OFF: usize = PR_OFF + PR_LIMBS; // 462: 20: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 4 * ROLE_BITS; // 482: 5: current perm's role bits
const LO_OFF: usize = RB_OFF + ROLE_BITS; // 487: 4: materialized low half-selectors
const NSEL: usize = 10; // materialized role selectors, order = SEL_CODES
const SEL_OFF: usize = LO_OFF + 4; // 491
/// Injection flags `bnd·sel(role)` [merkle, acm_burn, acnf, mw1, avc, acmout].
const NINJ: usize = 6;
const INJ_OFF: usize = SEL_OFF + NSEL; // 501
const INJ_MRK: usize = 0;
const INJ_ACM: usize = 1;
const INJ_ACNF: usize = 2;
const INJ_MW: usize = 3;
const INJ_AVC: usize = 4;
const INJ_OUT: usize = 5;
const G4_COL: usize = INJ_OFF + NINJ; // 507: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 508: merkle path bit (constant per perm)
const NW: usize = 14;
const W_OFF: usize = PBIT_COL + 1; // 509: 14 witness lanes (role-multiplexed)
/// Close gates `gperm·sel(role)` [acm_burn, acnf, mw1, avc, acmout].
const NCL: usize = 5;
const CL_OFF: usize = W_OFF + NW; // 523
const CL_ACM: usize = 0;
const CL_ACNF: usize = 1;
const CL_MW: usize = 2;
const CL_AVC: usize = 3;
const CL_OUT: usize = 4;
const BGCAP_COL: usize = CL_OFF + NCL; // 528: bind capture gate
/// Bind close gates [banchor, bcnf, bvc, bcm].
const NBGC: usize = 4;
const BGC_OFF: usize = BGCAP_COL + 1; // 529
const BQ_OFF: usize = BGC_OFF + NBGC; // 533: 16: bind bank
const RK_OFF: usize = BQ_OFF + 16; // 549: 16: burn rkm = pv(rkm_burn)
const RS_OFF: usize = RK_OFF + 16; // 565: 16: ACNF's rseed = the note's
const CM_OFF: usize = RS_OFF + 16; // 581: 16: MW1's leaf = ACNF's chained cm
const RH_OFF: usize = CM_OFF + 16; // 597: 16: the credit's ρ = pv(cnf)
const VA_OFF: usize = RH_OFF + 16; // 613: 4: Cv's v = the note's
const VB_OFF: usize = VA_OFF + 4; // 617: 4: the note's v − the credit's value
const BLC_OFF: usize = VB_OFF + 4; // 621: 9: VB's carry encodings against the fee
const EFF_OFF: usize = BLC_OFF + 9; // 630: 25: effective round input

/// The claim trace width.
pub const CLAIM_WIDTH: usize = EFF_OFF + 25; // 655

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 4 * PR_LIMBS; // 128

// Role codes are the claim AIR's own (its program is its own); the four with
// the narrow engine's semantics keep the narrow codes.
pub use crate::narrow::{ROLE_BANCHOR, ROLE_DUMMY, ROLE_MERKLE};
/// The credit's L2 note block (the L2 `ACMOUT` layout, `l2::ROLE_ACMOUT`).
pub use crate::l2::ROLE_ACMOUT;
/// The credit's bind — `cm2`.
pub const ROLE_BCM: u32 = crate::narrow::ROLE_BCM1;
/// The burn note's L1 commitment block, all-witness.
pub const ROLE_ACM_BURN: u32 = 2;
/// The claim-nullifier block: tag ‖ cm (chained) ‖ rseed.
pub const ROLE_ACNF: u32 = 3;
/// `cnf`'s bind.
pub const ROLE_BCNF: u32 = 4;
/// The first Merkle level, `MERKLE_W`: the leaf from `W4..7`.
pub const ROLE_MW1: u32 = 5;
/// The value-commitment block: tag ‖ v ‖ r_v.
pub const ROLE_AVC: u32 = 8;
/// `Cv`'s bind.
pub const ROLE_BVC: u32 = 9;

/// Role codes in materialized-selector order.
const SEL_CODES: [u32; NSEL] = [
    ROLE_MERKLE,
    ROLE_ACM_BURN,
    ROLE_ACNF,
    ROLE_BCNF,
    ROLE_MW1,
    ROLE_BANCHOR,
    ROLE_AVC,
    ROLE_BVC,
    ROLE_ACMOUT,
    ROLE_BCM,
];
const SEL_MERKLE: usize = 0;
const SEL_ACM: usize = 1;
const SEL_ACNF: usize = 2;
const SEL_BCNF: usize = 3;
const SEL_MW: usize = 4;
const SEL_BANCHOR: usize = 5;
const SEL_AVC: usize = 6;
const SEL_BVC: usize = 7;
const SEL_OUT: usize = 8;
const SEL_BCM: usize = 9;
/// The bind roles, in `BGC` order.
const BIND_SELS: [usize; NBGC] = [SEL_BANCHOR, SEL_BCNF, SEL_BVC, SEL_BCM];

/// Public-value layout: the anchor, the claim nullifier, the value
/// commitment, the credited note, the burn address (16 chunks each), the fee
/// (four 16-bit chunks).
pub const PV_A: usize = 0;
pub const PV_CNF: usize = 16;
pub const PV_CV: usize = 32;
pub const PV_CM2: usize = 48;
pub const PV_RKM_BURN: usize = 64;
pub const PV_FEE: usize = 80;
pub const PV_LEN: usize = 84;
const PV_BIND: [usize; NBGC] = [PV_A, PV_CNF, PV_CV, PV_CM2];

/// Build the full public-value vector for a claim.
pub fn pv_vec_claim(
    anchor: &[u64; 4],
    cnf: &[u64; 4],
    cv: &[u64; 4],
    cm2: &[u64; 4],
    rkm_burn: &[u64; 4],
    fee: u64,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, cnf, cv, cm2, rkm_burn] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    debug_assert_eq!(out.len(), PV_LEN);
    out
}

/// Perm slots used by the claim program, INCLUDING the leading dummy slot:
/// 1 + 3 + (1 + 31 + 1) + 2 + 2 = **41**, at 3072 rows each = 125,952 rows →
/// 2^17 (131,072), 1.7 spare perm slots.
pub const CLAIM_PERMS: usize = 1 + 3 + (MERKLE_DEPTH + 1) + 2 + 2;
/// log2 of the claim trace height.
pub const CLAIM_LOG_HEIGHT: usize = 17;
const _: () = assert!(CLAIM_PERMS * ROWS_PER_PERM <= 1 << CLAIM_LOG_HEIGHT);
// One program period covers the whole trace — the "no epoch" premise.
const _: () = assert!((1 << CLAIM_LOG_HEIGHT) / ROWS_PER_PERM < PROGRAM_SLOTS);

// ---------------------------------------------------------------------------
// The domain constants and the host derivations
// ---------------------------------------------------------------------------

/// `cnf`'s domain tag (18 bytes; zero-padded to three lanes).
pub const CNF_TAG: &[u8] = b"qumbra:l2-claim:v1";
/// `Cv`'s domain tag (21 bytes; zero-padded to three lanes).
pub const CV_TAG: &[u8] = b"qumbra:l2-claim-vc:v1";
/// The burn address's domain tag (17 bytes, followed by `l2_id` u64 LE).
pub const BURN_TAG: &[u8] = b"qumbra:l2-burn:v1";

/// A tag of at most 24 bytes, zero-padded, as three little-endian lanes.
const fn tag_lanes(tag: &[u8]) -> [u64; 3] {
    assert!(tag.len() <= 24);
    let mut out = [0u64; 3];
    let mut i = 0;
    while i < tag.len() {
        out[i / 8] |= (tag[i] as u64) << (8 * (i % 8));
        i += 1;
    }
    out
}
const CNF_TAG_LANES: [u64; 3] = tag_lanes(CNF_TAG);
const CV_TAG_LANES: [u64; 3] = tag_lanes(CV_TAG);

fn digest_of(st: &[u64; 25]) -> [u64; 4] {
    crate::reference::keccak_f(st)[..4].try_into().unwrap()
}

/// Keccak-256 of a byte message of at most 135 bytes (one block), as the
/// digest's four little-endian lanes.
pub fn keccak256_lanes(msg: &[u8]) -> [u64; 4] {
    assert!(msg.len() < 136, "one block");
    let mut block = [0u8; 136];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] ^= 0x01;
    block[135] ^= 0x80;
    let mut st = [0u64; 25];
    for (l, lane) in st.iter_mut().take(17).enumerate() {
        *lane = u64::from_le_bytes(block[8 * l..8 * l + 8].try_into().unwrap());
    }
    digest_of(&st)
}

/// The burn address of L2 `l2_id`: `Keccak256("qumbra:l2-burn:v1" ‖ l2_id
/// u64 LE)`, used directly as raw recipient key material (§4.1).
pub fn rkm_burn(l2_id: u64) -> [u64; 4] {
    let mut msg = BURN_TAG.to_vec();
    msg.extend_from_slice(&l2_id.to_le_bytes());
    keccak256_lanes(&msg)
}

/// The L1 note commitment `H(v ‖ rkm ‖ ρ ‖ rseed)` — `narrow::derive_input`'s
/// `cm` block (value lane 0, rkm 1..5, ρ 5..9, rseed 9..13, pad lane 13).
pub fn l1_cm(value: u64, rkm: &[u64; 4], rho: &[u64; 4], rseed: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[0] = value;
    st[1..5].copy_from_slice(rkm);
    st[5..9].copy_from_slice(rho);
    st[9..13].copy_from_slice(rseed);
    st[13] = 1;
    st[16] = 1 << 63;
    digest_of(&st)
}

/// The claim nullifier `cnf = Keccak256(CNF_TAG ‖ 00×6 ‖ cm ‖ rseed)` — the
/// block `ROLE_ACNF` absorbs.
pub fn claim_cnf(cm: &[u64; 4], rseed: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..3].copy_from_slice(&CNF_TAG_LANES);
    st[3..7].copy_from_slice(cm);
    st[7..11].copy_from_slice(rseed);
    st[11] = 1;
    st[16] = 1 << 63;
    digest_of(&st)
}

/// The value commitment `Cv = Keccak256(CV_TAG ‖ 00×3 ‖ v ‖ r_v)` — the block
/// `ROLE_AVC` absorbs.
pub fn claim_cv(value: u64, r_v: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..3].copy_from_slice(&CV_TAG_LANES);
    st[3] = value;
    st[4..8].copy_from_slice(r_v);
    st[8] = 1;
    st[16] = 1 << 63;
    digest_of(&st)
}

const fn s_col(d: usize) -> usize {
    S_OFF + d - 1
}
const fn v_col(d: usize) -> usize {
    V_OFF + d - 1
}
const fn u_col(d: usize) -> usize {
    U_OFF + d - 1
}

const fn inv_pi() -> [usize; 25] {
    let mut out = [0usize; 25];
    let mut bx = 0;
    while bx < 5 {
        let mut by = 0;
        while by < 5 {
            let y = bx;
            let x = (3 * (by + 15 - 3 * bx)) % 5;
            out[bx + 5 * by] = x + 5 * y;
            by += 1;
        }
        bx += 1;
    }
    out
}
const INV_PI: [usize; 25] = inv_pi();

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

/// Per-perm-slot witness: 14 generic 64-bit lanes plus the merkle path bit.
#[derive(Clone, Copy)]
pub struct ClaimSlotWitness {
    pub w: [u64; NW],
    pub pbit: bool,
}

impl Default for ClaimSlotWitness {
    fn default() -> Self {
        Self { w: [0; NW], pbit: false }
    }
}

/// The bridge's claim circuit.
#[cfg_attr(test, derive(Clone))] // the tests tamper owned copies; non-test build unchanged
pub struct ClaimAir {
    pub log_height: usize,
    /// 5-bit role code per program slot.
    pub program: [u32; PROGRAM_SLOTS],
    pub slot_witness: Vec<ClaimSlotWitness>,
    /// Public fee (needed to witness the credit's carry encodings).
    pub fee: u64,
}

impl ClaimAir {
    /// Every perm slot dummy, pure chaining — the geometry probe.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
            fee: 0,
        }
    }

    /// Program-ring limb i: slots 4i..4i+4, 5 bits each.
    fn pr_limb(&self, i: usize) -> u32 {
        (0..4)
            .map(|j| self.program[(4 * i + j) % PROGRAM_SLOTS] << (ROLE_BITS * j))
            .sum()
    }

    fn rc_bit(t: usize) -> bool {
        let z = t % 64;
        let mrow = (t / 64) % 2 == 0;
        if !mrow {
            return false;
        }
        let q = t / 128;
        (RC[(q + 23) % 24] >> z) & 1 == 1
    }

    fn rc_pack(j: usize) -> u32 {
        (0..7)
            .map(|k| (((RC[j] >> ((1u32 << k) - 1)) & 1) as u32) << k)
            .sum()
    }
}

/// Number of periodic columns: the narrow engine's 39, then the bits of the
/// three `cnf` tag lanes and of the three `Cv` tag lanes.
const NPERIODIC: usize = 45;
/// `tag_cnf(l)`: bit `z` of `cnf`'s tag lane `l` on the M rows.
const PER_TAG_CNF: usize = 39;
/// `tag_cv(l)`: bit `z` of `Cv`'s tag lane `l` on the M rows.
const PER_TAG_CV: usize = 42;

impl<F: Field> BaseAir<F> for ClaimAir {
    fn width(&self) -> usize {
        CLAIM_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PV_LEN
    }

    fn num_periodic_columns(&self) -> usize {
        NPERIODIC
    }

    /// The narrow engine's 39 period-128 columns ([mrow, u63, e1_0..e1_24,
    /// blast, sel_0..sel_6, pwk_0..pwk_3]) plus the six tag-lane columns.
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut cols = vec![Vec::with_capacity(128); NPERIODIC];
        for t in 0..128usize {
            let mrow = t < 64;
            cols[0].push(F::from_bool(mrow));
            cols[1].push(F::from_bool(t == 63));
            for l in 0..25 {
                let wrap = !mrow && (t - 64) + RHO[l] as usize >= 64;
                cols[2 + l].push(F::from_bool(wrap));
            }
            cols[27].push(F::from_bool(t == 127));
            for k in 0..7 {
                cols[28 + k].push(F::from_bool(mrow && t == (1 << k) - 1));
            }
            let z = t % 64;
            for j in 0..4 {
                let v = if z / 16 == j {
                    F::from_u32(1 << (z % 16))
                } else {
                    F::ZERO
                };
                cols[35 + j].push(v);
            }
            for l in 0..3 {
                cols[PER_TAG_CNF + l].push(F::from_bool(mrow && (CNF_TAG_LANES[l] >> z) & 1 == 1));
                cols[PER_TAG_CV + l].push(F::from_bool(mrow && (CV_TAG_LANES[l] >> z) & 1 == 1));
            }
        }
        cols
    }
}

fn xor2<E: Clone + core::ops::Add<Output = E> + core::ops::Sub<Output = E> + core::ops::Mul<Output = E>>(
    a: E,
    b: E,
    two: E,
) -> E {
    a.clone() + b.clone() - two * a * b
}

impl<AB: AirBuilder> Air<AB> for ClaimAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let two = AB::Expr::TWO;

        let main = builder.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();

        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let mrow = per[0].clone();
        let u63 = per[1].clone();
        let e1 = |l: usize| per[2 + l].clone();
        let blast = per[27].clone();
        let sel = |k: usize| per[28 + k].clone();
        let pwk = |j: usize| per[35 + j].clone();
        let tag_cnf = |l: usize| per[PER_TAG_CNF + l].clone();
        let tag_cv = |l: usize| per[PER_TAG_CV + l].clone();
        let trow = AB::Expr::ONE - mrow.clone();

        let rc = (0..7)
            .map(|k| sel(k) * local[B_OFF + k].clone())
            .fold(AB::Expr::ZERO, |acc, e| acc + e);

        let a = |l: usize| local[A_OFF + l].clone();
        let eff = |l: usize| local[EFF_OFF + l].clone();
        let c = |x: usize| local[C_OFF + x].clone();
        let us = |l: usize| local[US_OFF + l].clone();
        let ap = |l: usize| local[AP_OFF + l].clone();
        let uv = |l: usize| local[UV_OFF + l].clone();
        let uu = |i: usize| local[UU_OFF + i].clone();
        let x00 = local[X00_COL].clone();

        // --- Same-row constraints: the Keccak engine (verbatim from narrow.rs) ---
        for l in 0..25 {
            builder.assert_bool(local[US_OFF + l].clone());
            builder.assert_bool(local[UV_OFF + l].clone());
        }
        for i in 0..10 {
            builder.assert_bool(local[UU_OFF + i].clone());
        }
        for x in 0..5 {
            builder.assert_bool(local[C_OFF + x].clone());
        }
        let weighted = |off: usize, n: usize, row: &[AB::Expr]| -> AB::Expr {
            (0..n)
                .map(|i| row[off + i].clone() * AB::Expr::from_u32(1 << i))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        builder.assert_eq(weighted(US_OFF, 25, &local), local[s_col(1)].clone());
        builder.assert_eq(weighted(UV_OFF, 25, &local), local[v_col(1)].clone());
        builder.assert_eq(weighted(UU_OFF, 10, &local), local[u_col(1)].clone());

        let b = |bx: usize, by: usize| us(INV_PI[bx + 5 * by]);
        let chi = |x: usize, y: usize| -> AB::Expr {
            let b0 = b(x, y);
            let b1 = b((x + 1) % 5, y);
            let b2 = b((x + 2) % 5, y);
            let and = (AB::Expr::ONE - b1) * b2;
            xor2(b0, and, two.clone())
        };
        for y in 0..5 {
            for x in 0..5 {
                if (x, y) != (0, 0) {
                    builder.assert_eq(a(x + 5 * y), chi(x, y));
                }
            }
        }
        builder.assert_eq(x00.clone(), chi(0, 0));
        builder.assert_eq(a(0), xor2(x00, rc, two.clone()));

        for x in 0..5 {
            let s = (0..5)
                .map(|y| eff(x + 5 * y))
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            let d = s - c(x);
            builder.assert_zero(
                d.clone() * (d.clone() - two.clone()) * (d - two.clone() * two.clone()),
            );
        }

        for y in 0..5 {
            for x in 0..5 {
                let p = uv(x + 5 * y);
                let q = uu((x + 4) % 5);
                let r = uu(5 + (x + 1) % 5);
                let xor3 = p.clone() + q.clone() + r.clone()
                    - two.clone() * (p.clone() * q.clone() + p.clone() * r.clone() + q.clone() * r.clone())
                    + two.clone() * two.clone() * p * q * r;
                builder.assert_eq(ap(x + 5 * y), xor3);
            }
        }

        // --- Program machinery (as l2r.rs) ---
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[PB_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..4 {
            builder.when_first_row().assert_eq(
                local[PH_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..PR_LIMBS {
            builder.when_first_row().assert_eq(
                local[PR_OFF + i].clone(),
                AB::Expr::from_u32(self.pr_limb(i)),
            );
        }
        for k in 0..4 * ROLE_BITS {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 4 * ROLE_BITS, &local), local[PR_OFF].clone());
        for k in 0..ROLE_BITS {
            let sel_quarter = (0..4)
                .map(|phi| {
                    local[PH_OFF + (4 - phi) % 4].clone()
                        * local[D_OFF + ROLE_BITS * phi + k].clone()
                })
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            builder.assert_eq(local[RB_OFF + k].clone(), sel_quarter);
        }
        let r = |k: usize| local[RB_OFF + k].clone();
        let pair = |b0: AB::Expr, b1: AB::Expr, j: u32| -> AB::Expr {
            let t0 = if j & 1 == 1 { b0 } else { AB::Expr::ONE - b0 };
            let t1 = if j & 2 == 2 { b1 } else { AB::Expr::ONE - b1 };
            t0 * t1
        };
        for j in 0..4u32 {
            builder.assert_eq(local[LO_OFF + j as usize].clone(), pair(r(0), r(1), j));
        }
        for (i, code) in SEL_CODES.iter().enumerate() {
            let lo = local[LO_OFF + (code & 3) as usize].clone();
            let hi = pair(r(2), r(3), (code >> 2) & 3);
            let top = if (code >> 4) & 1 == 1 {
                r(4)
            } else {
                AB::Expr::ONE - r(4)
            };
            builder.assert_eq(local[SEL_OFF + i].clone(), lo * hi * top);
        }
        let sel_role = |i: usize| local[SEL_OFF + i].clone();
        let bnd = mrow.clone() * local[PB_OFF].clone();
        let gperm = blast.clone() * local[PB_OFF + 1].clone();
        for (i, s) in [SEL_MERKLE, SEL_ACM, SEL_ACNF, SEL_MW, SEL_AVC, SEL_OUT].iter().enumerate() {
            builder.assert_eq(local[INJ_OFF + i].clone(), bnd.clone() * sel_role(*s));
        }
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );
        builder.assert_bool(local[PBIT_COL].clone());
        // The blanket path-bit rule (the lab #287 lesson, from birth): only
        // the two Merkle blocks read PBIT, so it is 0 on every row of every
        // other role — DUMMY included (degree 2).
        builder.assert_zero(
            (AB::Expr::ONE - sel_role(SEL_MERKLE) - sel_role(SEL_MW)) * local[PBIT_COL].clone(),
        );
        for i in 0..NW {
            builder.assert_bool(local[W_OFF + i].clone());
        }
        let pbit = local[PBIT_COL].clone();
        let w = |i: usize| local[W_OFF + i].clone();
        let inj = |i: usize| local[INJ_OFF + i].clone();
        for l in 0..25 {
            let msg_mrk: AB::Expr = match l {
                0..=3 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * a(l),
                4..=7 => {
                    pbit.clone() * a(l - 4) + (AB::Expr::ONE - pbit.clone()) * w(l - 4)
                }
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // The burn note, the L1 block: v = W4, rkm = W0..3, ρ′ = W5..8,
            // rseed = W9..12, pad at lane 13.
            let msg_acm: AB::Expr = match l {
                0 => w(4),
                1..=4 => w(l - 1),
                5..=12 => w(l),
                13 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // cnf: tag ‖ cm (the chained digest — ACM_BURN's output) ‖
            // rseed = W0..3, pad at lane 11.
            let msg_cnf: AB::Expr = match l {
                0..=2 => tag_cnf(l),
                3..=6 => a(l - 3),
                7..=10 => w(l - 7),
                11 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // MERKLE_W (l2r's): the running digest is W4..7, the sibling W0..3.
            let msg_mw: AB::Expr = match l {
                0..=3 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * w(l + 4),
                4..=7 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * w(l - 4),
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // Cv: tag ‖ v = W4 ‖ r_v = W0..3, pad at lane 8.
            let msg_cv: AB::Expr = match l {
                0..=2 => tag_cv(l),
                3 => w(4),
                4..=7 => w(l - 4),
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // The credit, the L2 block: value W4, asset W13, rkm_dst W0..3,
            // ρ W5..8, rseed2 W9..12, pad at lane 14.
            let msg_out: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => w(l - 2),
                6..=13 => w(l - 1),
                14 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let expr = a(l)
                + inj(INJ_MRK) * (msg_mrk - a(l))
                + inj(INJ_ACM) * (msg_acm - a(l))
                + inj(INJ_ACNF) * (msg_cnf - a(l))
                + inj(INJ_MW) * (msg_mw - a(l))
                + inj(INJ_AVC) * (msg_cv - a(l))
                + inj(INJ_OUT) * (msg_out - a(l));
            builder.assert_eq(eff(l), expr);
        }
        // The credit is asset 0, bit by bit.
        builder.assert_zero(inj(INJ_OUT) * w(13));

        // --- Close gates ---
        let cl = |k: usize| local[CL_OFF + k].clone();
        for (k, s) in [SEL_ACM, SEL_ACNF, SEL_MW, SEL_AVC, SEL_OUT].iter().enumerate() {
            builder.assert_eq(cl(k), gperm.clone() * sel_role(*s));
        }
        let bindsum = BIND_SELS
            .iter()
            .map(|s| sel_role(*s))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        builder.assert_eq(local[BGCAP_COL].clone(), bnd.clone() * bindsum);
        for (x, s) in BIND_SELS.iter().enumerate() {
            builder.assert_eq(local[BGC_OFF + x].clone(), gperm.clone() * sel_role(*s));
        }

        let pvs: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv = |i: usize| -> AB::Expr { pvs[i].clone() };

        // --- Bind bank: four closes, each against its public digest ---
        for (x, base) in PV_BIND.iter().enumerate() {
            for j in 0..16 {
                builder.assert_zero(
                    local[BGC_OFF + x].clone() * (local[BQ_OFF + j].clone() - pv(base + j)),
                );
            }
        }

        // --- Bank closes, each on its role's last row ---
        for j in 0..16 {
            // The burn note pays the public burn address.
            builder.assert_zero(cl(CL_ACM) * (local[RK_OFF + j].clone() - pv(PV_RKM_BURN + j)));
            // cnf absorbs the note's own rseed.
            builder.assert_zero(cl(CL_ACNF) * local[RS_OFF + j].clone());
            // The path starts at the note cnf absorbed.
            builder.assert_zero(cl(CL_MW) * local[CM_OFF + j].clone());
            // The credit's ρ is the public cnf.
            builder.assert_zero(cl(CL_OUT) * (local[RH_OFF + j].clone() - pv(PV_CNF + j)));
        }
        for j in 0..4 {
            // Cv opens to the note's v.
            builder.assert_zero(cl(CL_AVC) * local[VA_OFF + j].clone());
        }
        for off in [BQ_OFF, RK_OFF, RS_OFF, CM_OFF, RH_OFF] {
            for j in 0..16 {
                builder.when_first_row().assert_zero(local[off + j].clone());
            }
        }
        for off in [VA_OFF, VB_OFF] {
            for j in 0..4 {
                builder.when_first_row().assert_zero(local[off + j].clone());
            }
        }

        // --- The credit: v − value2 = fee on one borrow chain (l2r's BAL) ---
        for k in 0..9 {
            builder.assert_bool(local[BLC_OFF + k].clone());
        }
        {
            let carry = |j: usize| -> AB::Expr {
                local[BLC_OFF + 3 * j].clone()
                    + local[BLC_OFF + 3 * j + 1].clone() * two.clone()
                    + local[BLC_OFF + 3 * j + 2].clone() * two.clone() * two.clone()
                    - two.clone()
            };
            let vb = |j: usize| local[VB_OFF + j].clone();
            let w16 = AB::Expr::from_u32(1 << 16);
            let close = cl(CL_OUT);
            builder.assert_zero(close.clone() * (vb(0) - pv(PV_FEE) - w16.clone() * carry(0)));
            for j in 1..3 {
                builder.assert_zero(
                    close.clone() * (vb(j) + carry(j - 1) - pv(PV_FEE + j) - w16.clone() * carry(j)),
                );
            }
            builder.assert_zero(close * (vb(3) + carry(2) - pv(PV_FEE + 3)));
        }

        // RC ring.
        for k in 0..7 {
            builder.assert_bool(local[B_OFF + k].clone());
        }
        builder.assert_eq(weighted(B_OFF, 7, &local), local[R_OFF].clone());
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[R_OFF + i].clone(),
                AB::Expr::from_u32(Self::rc_pack((23 + i) % 24)),
            );
        }

        // --- Transition constraints ---
        let mut t = builder.when_transition();

        for i in 0..24 {
            t.assert_eq(
                next[R_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[R_OFF + i].clone()
                    + blast.clone() * local[R_OFF + (i + 1) % 24].clone(),
            );
        }
        for i in 0..24 {
            t.assert_eq(
                next[PB_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[PB_OFF + i].clone()
                    + blast.clone() * local[PB_OFF + (i + 1) % 24].clone(),
            );
        }
        for i in 0..4 {
            t.assert_eq(
                next[PH_OFF + i].clone(),
                (AB::Expr::ONE - gperm.clone()) * local[PH_OFF + i].clone()
                    + gperm.clone() * local[PH_OFF + (i + 1) % 4].clone(),
            );
        }
        let g4 = local[G4_COL].clone();
        for i in 0..PR_LIMBS {
            t.assert_eq(
                next[PR_OFF + i].clone(),
                (AB::Expr::ONE - g4.clone()) * local[PR_OFF + i].clone()
                    + g4.clone() * local[PR_OFF + (i + 1) % PR_LIMBS].clone(),
            );
        }
        t.assert_zero(
            (AB::Expr::ONE - gperm.clone()) * (next[PBIT_COL].clone() - local[PBIT_COL].clone()),
        );

        for d in 1..=S_SLOTS {
            let mut expr = if d < S_SLOTS {
                local[s_col(d + 1)].clone()
            } else {
                AB::Expr::ZERO
            };
            for l in 0..25 {
                let wgt = AB::Expr::from_u32(1 << l);
                if RHO[l] as usize == d {
                    expr = expr + e1(l) * wgt.clone() * ap(l);
                }
                if 64 + RHO[l] as usize == d {
                    expr = expr + (trow.clone() - e1(l)) * wgt * ap(l);
                }
            }
            t.assert_eq(next[s_col(d)].clone(), expr);
        }
        for d in 1..V_SLOTS {
            t.assert_eq(next[v_col(d)].clone(), local[v_col(d + 1)].clone());
        }
        t.assert_eq(
            next[v_col(V_SLOTS)].clone(),
            mrow.clone() * weighted(EFF_OFF, 25, &local),
        );
        let lo_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << x))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        let hi_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << (5 + x)))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        t.assert_eq(
            next[u_col(1)].clone(),
            local[u_col(2)].clone() + u63.clone() * hi_c.clone(),
        );
        for d in 2..64 {
            t.assert_eq(next[u_col(d)].clone(), local[u_col(d + 1)].clone());
        }
        t.assert_eq(
            next[u_col(64)].clone(),
            local[u_col(65)].clone() + mrow.clone() * lo_c,
        );
        t.assert_eq(next[u_col(65)].clone(), (mrow.clone() - u63) * hi_c);

        // Bind bank: capture at the bind roles' boundary, reset after the close.
        let bgc_any = (0..NBGC)
            .map(|x| local[BGC_OFF + x].clone())
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - bgc_any.clone()) * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone() * pwk(j) * a(l),
                );
                // RK: the burn note's rkm lanes W0..3.
                t.assert_eq(
                    next[RK_OFF + idx].clone(),
                    local[RK_OFF + idx].clone() + inj(INJ_ACM) * pwk(j) * w(l),
                );
                // RS: +rseed W9..12 at ACM_BURN, −W0..3 at ACNF.
                t.assert_eq(
                    next[RS_OFF + idx].clone(),
                    local[RS_OFF + idx].clone() + inj(INJ_ACM) * pwk(j) * w(9 + l)
                        - inj(INJ_ACNF) * pwk(j) * w(l),
                );
                // CM: +a at ACNF (ACM_BURN's output, cm), −W4..7 at MW1.
                t.assert_eq(
                    next[CM_OFF + idx].clone(),
                    local[CM_OFF + idx].clone() + inj(INJ_ACNF) * pwk(j) * a(l)
                        - inj(INJ_MW) * pwk(j) * w(4 + l),
                );
                // RH: the credit's ρ lanes W5..8.
                t.assert_eq(
                    next[RH_OFF + idx].clone(),
                    local[RH_OFF + idx].clone() + inj(INJ_OUT) * pwk(j) * w(5 + l),
                );
            }
        }
        for j in 0..4 {
            // VA: +v at ACM_BURN, −v at AVC.
            t.assert_eq(
                next[VA_OFF + j].clone(),
                local[VA_OFF + j].clone() + (inj(INJ_ACM) - inj(INJ_AVC)) * pwk(j) * w(4),
            );
            // VB: +v at ACM_BURN, −value2 at ACMOUT.
            t.assert_eq(
                next[VB_OFF + j].clone(),
                local[VB_OFF + j].clone() + (inj(INJ_ACM) - inj(INJ_OUT)) * pwk(j) * w(4),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Instance builder
// ---------------------------------------------------------------------------

/// The burn note's opening. `rkm` is the note's recipient — `rkm_burn` of
/// the L2 it deposits into for any claimable note.
#[derive(Clone, Copy, Debug)]
pub struct BurnNote {
    pub value: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

/// The credited L2 note's free fields: whose it is and its blinding. Its
/// value is `v − fee`, its asset 0 and its `ρ` the claim's `cnf` — all fixed
/// by the circuit.
#[derive(Clone, Copy, Debug)]
pub struct ClaimCredit {
    pub rkm: [u64; 4],
    pub rseed: [u64; 4],
}

/// Everything a prover/verifier pair needs for one claim.
#[cfg_attr(test, derive(Clone))]
pub struct ClaimInstance {
    pub air: ClaimAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    /// The burn note's L1 commitment (private; the tree leaf).
    pub cm: [u64; 4],
    pub cnf: [u64; 4],
    pub cv: [u64; 4],
    pub cm2: [u64; 4],
    pub rkm_burn: [u64; 4],
}

/// A claim against a **fabricated** L1 commitment tree holding the burn note
/// alone (`narrow::fabricated_single_tree`), into L2 `l2_id`.
pub fn build_claim(
    log_height: usize,
    l2_id: u64,
    note: &BurnNote,
    r_v: &[u64; 4],
    credit: &ClaimCredit,
    fee: u64,
) -> ClaimInstance {
    let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
    let (witness, anchor) = fabricated_single_tree(&cm);
    build_claim_with_witness(log_height, &rkm_burn(l2_id), note, &witness, anchor, r_v, credit, fee)
}

/// A claim from a caller-supplied path + anchor, publishing `rkm_burn` as the
/// burn address. Nothing is asserted: a note paying another address, a path
/// that misses the anchor or a fee above `v` is simply unprovable, which is
/// what the negatives test. The credit's value is `v − fee` (wrapping, so a
/// `fee > v` instance can be built and refused).
#[allow(clippy::too_many_arguments)]
pub fn build_claim_with_witness(
    log_height: usize,
    rkm_burn: &[u64; 4],
    note: &BurnNote,
    path: &MerkleWitness,
    anchor: [u64; 4],
    r_v: &[u64; 4],
    credit: &ClaimCredit,
    fee: u64,
) -> ClaimInstance {
    let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
    let cnf = claim_cnf(&cm, &note.rseed);
    let cv = claim_cv(note.value, r_v);
    let value2 = note.value.wrapping_sub(fee);
    let cm2 = l2_cm(value2, 0, &credit.rkm, &cnf, &credit.rseed);

    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![ClaimSlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut put = |role: u32, w: ClaimSlotWitness| {
        program[slot] = role;
        sw[slot] = w;
        slot += 1;
    };
    let lanes = |f: &dyn Fn(&mut [u64; NW])| {
        let mut w = ClaimSlotWitness::default();
        f(&mut w.w);
        w
    };
    put(
        ROLE_ACM_BURN,
        lanes(&|w| {
            w[..4].copy_from_slice(&note.rkm);
            w[4] = note.value;
            w[5..9].copy_from_slice(&note.rho);
            w[9..13].copy_from_slice(&note.rseed);
        }),
    );
    put(ROLE_ACNF, lanes(&|w| w[..4].copy_from_slice(&note.rseed)));
    put(ROLE_BCNF, ClaimSlotWitness::default());
    for (lvl, (sib, bit)) in path.siblings.iter().zip(path.path_bits.iter()).enumerate() {
        let mut w = lanes(&|w| {
            w[..4].copy_from_slice(sib);
            if lvl == 0 {
                w[4..8].copy_from_slice(&cm);
            }
        });
        w.pbit = *bit;
        put(if lvl == 0 { ROLE_MW1 } else { ROLE_MERKLE }, w);
    }
    put(ROLE_BANCHOR, ClaimSlotWitness::default());
    put(
        ROLE_AVC,
        lanes(&|w| {
            w[..4].copy_from_slice(r_v);
            w[4] = note.value;
        }),
    );
    put(ROLE_BVC, ClaimSlotWitness::default());
    put(
        ROLE_ACMOUT,
        lanes(&|w| {
            w[..4].copy_from_slice(&credit.rkm);
            w[4] = value2;
            w[5..9].copy_from_slice(&cnf);
            w[9..13].copy_from_slice(&credit.rseed);
        }),
    );
    put(ROLE_BCM, ClaimSlotWitness::default());
    assert_eq!(slot, CLAIM_PERMS, "program layout drifted");

    let pvs = pv_vec_claim(&anchor, &cnf, &cv, &cm2, rkm_burn, fee);
    ClaimInstance {
        air: ClaimAir { log_height, program, slot_witness: sw, fee },
        pvs,
        anchor,
        cm,
        cnf,
        cv,
        cm2,
        rkm_burn: *rkm_burn,
    }
}

// ---------------------------------------------------------------------------
// Trace generation — l2r.rs's fill, mirrored constraint for constraint.
// ---------------------------------------------------------------------------

/// How `ACNF`'s block is formed: the frozen tagged message, or (the N10
/// negative only) MERKLE's untagged `cm ‖ rseed` node block.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CnfForm {
    Tagged,
    #[cfg_attr(not(test), allow(dead_code))]
    MerkleShaped,
}

impl ClaimAir {
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        self.generate_trace_with(extra_capacity_bits, CnfForm::Tagged)
    }

    fn generate_trace_with<F: Field>(&self, extra_capacity_bits: usize, cnf_form: CnfForm) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * CLAIM_WIDTH;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);

        let mut s = [0u32; S_SLOTS + 1];
        let mut v = [0u32; V_SLOTS + 1];
        let mut u = [0u32; U_SLOTS + 1];
        let mut r: [u32; 24] = core::array::from_fn(|i| Self::rc_pack((23 + i) % 24));
        let mut pb: [u32; 24] = core::array::from_fn(|i| (i == 0) as u32);
        let mut ph: [u32; 4] = core::array::from_fn(|i| (i == 0) as u32);
        let mut pr: [u32; PR_LIMBS] = core::array::from_fn(|i| self.pr_limb(i));
        let mut perm_idx = 0usize;
        let role_of = |p: usize| self.program[p % PROGRAM_SLOTS];
        let wit = |p: usize| -> ClaimSlotWitness {
            if self.slot_witness.is_empty() {
                ClaimSlotWitness::default()
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);
        let mut bq = [0i64; 16];
        let mut rk = [0i64; 16];
        let mut rs = [0i64; 16];
        let mut cmb = [0i64; 16];
        let mut rh = [0i64; 16];
        let mut va = [0i64; 4];
        let mut vb = [0i64; 4];

        let bit = |w: u32, i: usize| (w >> i) & 1;
        let sgn = |vv: i64| -> F {
            if vv >= 0 {
                F::from_u32(vv as u32)
            } else {
                -F::from_u32((-vv) as u32)
            }
        };

        for t in 0..height {
            let mrow = (t / 64) % 2 == 0;
            let z = t % 64;

            let us: [u32; 25] = core::array::from_fn(|l| bit(s[1], l));
            let uv: [u32; 25] = core::array::from_fn(|l| bit(v[1], l));
            let uu: [u32; 10] = core::array::from_fn(|i| bit(u[1], i));

            let b = |bx: usize, by: usize| us[INV_PI[bx + 5 * by]];
            let chi = |x: usize, y: usize| {
                b(x, y) ^ ((1 - b((x + 1) % 5, y)) & b((x + 2) % 5, y))
            };
            let x00 = chi(0, 0);
            let rc = Self::rc_bit(t) as u32;
            let a: [u32; 25] = core::array::from_fn(|l| {
                if l == 0 {
                    x00 ^ rc
                } else {
                    chi(l % 5, l / 5)
                }
            });
            let role_now = role_of(perm_idx);
            let bnd_now = ((mrow as u32) * pb[0]) == 1;
            let wbit: [u32; NW] = core::array::from_fn(|i| ((cur.w[i] >> z) & 1) as u32);
            let pbv = cur.pbit as u32;
            let z0 = (z == 0) as u32;
            let z63 = (z == 63) as u32;
            let tagc = |l: usize| ((CNF_TAG_LANES[l] >> z) & 1) as u32;
            let tagv = |l: usize| ((CV_TAG_LANES[l] >> z) & 1) as u32;
            let eff: [u32; 25] = core::array::from_fn(|l| {
                if !bnd_now {
                    return a[l];
                }
                match role_now {
                    ROLE_MERKLE => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * a[l],
                        4..=7 => pbv * a[l - 4] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACM_BURN => match l {
                        0 => wbit[4],
                        1..=4 => wbit[l - 1],
                        5..=12 => wbit[l],
                        13 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACNF if cnf_form == CnfForm::Tagged => match l {
                        0..=2 => tagc(l),
                        3..=6 => a[l - 3],
                        7..=10 => wbit[l - 7],
                        11 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACNF => match l {
                        0..=3 => a[l],
                        4..=7 => wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_MW1 => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * wbit[l + 4],
                        4..=7 => pbv * wbit[l] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AVC => match l {
                        0..=2 => tagv(l),
                        3 => wbit[4],
                        4..=7 => wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACMOUT => match l {
                        0 => wbit[4],
                        1 => wbit[13],
                        2..=5 => wbit[l - 2],
                        6..=13 => wbit[l - 1],
                        14 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    _ => a[l],
                }
            });
            let c: [u32; 5] = core::array::from_fn(|x| {
                eff[x] ^ eff[x + 5] ^ eff[x + 10] ^ eff[x + 15] ^ eff[x + 20]
            });
            let ap: [u32; 25] = core::array::from_fn(|l| {
                let x = l % 5;
                uv[l] ^ uu[(x + 4) % 5] ^ uu[5 + (x + 1) % 5]
            });

            let base = values.len();
            values.resize(base + CLAIM_WIDTH, F::ZERO);
            let row = &mut values[base..];
            for l in 0..25 {
                row[A_OFF + l] = F::from_u32(a[l]);
                row[US_OFF + l] = F::from_u32(us[l]);
                row[AP_OFF + l] = F::from_u32(ap[l]);
                row[UV_OFF + l] = F::from_u32(uv[l]);
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            for x in 0..5 {
                row[C_OFF + x] = F::from_u32(c[x]);
            }
            for i in 0..10 {
                row[UU_OFF + i] = F::from_u32(uu[i]);
            }
            row[X00_COL] = F::from_u32(x00);
            for (i, ri) in r.iter().enumerate() {
                row[R_OFF + i] = F::from_u32(*ri);
            }
            for k in 0..7 {
                row[B_OFF + k] = F::from_u32((r[0] >> k) & 1);
            }
            for (i, vv) in pb.iter().enumerate() {
                row[PB_OFF + i] = F::from_u32(*vv);
            }
            for (i, vv) in ph.iter().enumerate() {
                row[PH_OFF + i] = F::from_u32(*vv);
            }
            for (i, vv) in pr.iter().enumerate() {
                row[PR_OFF + i] = F::from_u32(*vv);
            }
            for k in 0..4 * ROLE_BITS {
                row[D_OFF + k] = F::from_u32((pr[0] >> k) & 1);
            }
            for k in 0..ROLE_BITS {
                row[RB_OFF + k] = F::from_u32((role_now >> k) & 1);
            }
            for j in 0..4u32 {
                row[LO_OFF + j as usize] = F::from_u32(((role_now & 3) == j) as u32);
            }
            let selv: [u32; NSEL] =
                core::array::from_fn(|i| (role_now == SEL_CODES[i]) as u32);
            for (i, vv) in selv.iter().enumerate() {
                row[SEL_OFF + i] = F::from_u32(*vv);
            }
            let bndv = (mrow as u32) * pb[0];
            let gpermv = ((t % 128 == 127) as u32) * pb[1];
            let injv: [u32; NINJ] = core::array::from_fn(|i| {
                bndv * selv[[SEL_MERKLE, SEL_ACM, SEL_ACNF, SEL_MW, SEL_AVC, SEL_OUT][i]]
            });
            for (i, vv) in injv.iter().enumerate() {
                row[INJ_OFF + i] = F::from_u32(*vv);
            }
            row[G4_COL] = F::from_u32(gpermv * ph[1]);
            let clv: [u32; NCL] = core::array::from_fn(|k| {
                gpermv * selv[[SEL_ACM, SEL_ACNF, SEL_MW, SEL_AVC, SEL_OUT][k]]
            });
            for (k, vv) in clv.iter().enumerate() {
                row[CL_OFF + k] = F::from_u32(*vv);
            }
            let bindsum: u32 = BIND_SELS.iter().map(|s| selv[*s]).sum();
            let bgcap = bndv * bindsum;
            let bgc_any = gpermv * bindsum;
            row[BGCAP_COL] = F::from_u32(bgcap);
            for (x, s) in BIND_SELS.iter().enumerate() {
                row[BGC_OFF + x] = F::from_u32(gpermv * selv[*s]);
            }
            row[PBIT_COL] = F::from_u32(pbv);
            for i in 0..NW {
                row[W_OFF + i] = F::from_u32(wbit[i]);
            }
            for (off, bank) in [(BQ_OFF, &bq), (RK_OFF, &rk), (RS_OFF, &rs), (CM_OFF, &cmb), (RH_OFF, &rh)] {
                for (i, acc) in bank.iter().enumerate() {
                    row[off + i] = sgn(*acc);
                }
            }
            for (off, bank) in [(VA_OFF, &va), (VB_OFF, &vb)] {
                for (i, acc) in bank.iter().enumerate() {
                    row[off + i] = sgn(*acc);
                }
            }
            // Carry encodings of the credit's chain against the fee.
            {
                let mut cc = [0i64; 3];
                let mut prev = 0i64;
                for j in 0..3 {
                    let tj = vb[j] + prev - ((self.fee >> (16 * j)) & 0xffff) as i64;
                    cc[j] = tj >> 16;
                    prev = cc[j];
                }
                for (j, cj) in cc.iter().enumerate() {
                    let enc = (cj + 2).clamp(0, 7) as u32;
                    for bb in 0..3 {
                        row[BLC_OFF + 3 * j + bb] = F::from_u32((enc >> bb) & 1);
                    }
                }
            }

            // Advance the accumulators.
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let wb = |i: usize| wbit[i] as i64;
                let (i_acm, i_acnf, i_mw) = (injv[INJ_ACM] as i64, injv[INJ_ACNF] as i64, injv[INJ_MW] as i64);
                let (i_avc, i_out) = (injv[INJ_AVC] as i64, injv[INJ_OUT] as i64);
                if bgc_any == 1 {
                    bq = [0i64; 16];
                }
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    let al = a[l] as i64;
                    bq[idx] += bgcap as i64 * wgt * al;
                    rk[idx] += i_acm * wgt * wb(l);
                    rs[idx] += i_acm * wgt * wb(9 + l) - i_acnf * wgt * wb(l);
                    cmb[idx] += i_acnf * wgt * al - i_mw * wgt * wb(4 + l);
                    rh[idx] += i_out * wgt * wb(5 + l);
                }
                va[jc] += (i_acm - i_avc) * wgt * wb(4);
                vb[jc] += (i_acm - i_out) * wgt * wb(4);
            }
            for d in 1..=S_SLOTS {
                row[s_col(d)] = F::from_u32(s[d]);
            }
            for d in 1..=V_SLOTS {
                row[v_col(d)] = F::from_u32(v[d]);
            }
            for d in 1..=U_SLOTS {
                row[u_col(d)] = F::from_u32(u[d]);
            }

            for d in 1..S_SLOTS {
                s[d] = s[d + 1];
            }
            s[S_SLOTS] = 0;
            if !mrow {
                let j = z;
                for l in 0..25 {
                    let rot = RHO[l] as usize;
                    let d = if j + rot >= 64 { rot } else { 64 + rot };
                    s[d] |= ap[l] << l;
                }
            }
            for d in 1..V_SLOTS {
                v[d] = v[d + 1];
            }
            v[V_SLOTS] = 0;
            for d in 1..U_SLOTS {
                u[d] = u[d + 1];
            }
            u[U_SLOTS] = 0;
            if t % 128 == 127 {
                r.rotate_left(1);
                if pb[1] == 1 {
                    if ph[1] == 1 {
                        pr.rotate_left(1);
                    }
                    ph.rotate_left(1);
                    perm_idx += 1;
                    cur = wit(perm_idx);
                }
                pb.rotate_left(1);
            }
            if mrow {
                let a_limb: u32 = (0..25).map(|l| eff[l] << l).sum();
                let lo: u32 = (0..5).map(|x| c[x] << x).sum();
                let hi: u32 = (0..5).map(|x| c[x] << (5 + x)).sum();
                v[V_SLOTS] = a_limb;
                u[64] |= lo;
                if z == 63 {
                    u[1] |= hi;
                } else {
                    u[65] |= hi;
                }
            }
        }

        RowMajorMatrix::new(values, CLAIM_WIDTH)
    }

    /// The state materialized at block `q` (the round-q input).
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * CLAIM_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}

#[cfg(test)]
mod tests;
