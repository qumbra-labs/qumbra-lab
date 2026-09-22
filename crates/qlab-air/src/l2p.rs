//! W3 stage 2 — the L2 transaction circuit family, **shape P** (policy assets:
//! Hybrid / Regulated), lab issue #700, built on the stage-0 and stage-1 rulings.
//!
//! A **new AIR type beside [`crate::l2::L2ShapeSAir`]** — shape S is measured
//! and its width/degree are test-locked, so P is a second fork of the narrow
//! engine (structure for structure, the same discipline `l2.rs` applied to
//! `narrow.rs`), never an edit to S. Pure helpers with identical semantics are
//! imported from `l2` (the registry types, the note block, the input
//! derivation, the fabricated trees) and from `narrow`.
//!
//! ## The statement (l2-own-circuit-decision §2.3, §3; #700 stage-1 ruling)
//!
//! Shape S plus, per input, **always present in the trace** (fixed shape) and
//! gated by the registry leaf's `mode`:
//!
//! - **freeze non-membership**, gadget (a) as RULED: an indexed (sorted) Merkle
//!   tree of depth 20 over frozen `rkm` values. The prover opens the **low
//!   leaf** `(key_lo, key_hi)` and proves `key_lo < rkm < key_hi` as two 256-bit
//!   comparisons, **bit-serial on `AFRZ`'s boundary rows** — `rkm` arrives there
//!   as the chained digest `a[0..4]` (the perm before is `ARKM`), `key_lo` rides
//!   `W0..3` and `key_hi` `W5..8`, all three on the same 64 rows. The leaf is
//!   hashed by `AFRZ` and folded by 20 `MERKLE` steps; the fold's root arrives
//!   as the chained digest at **`AREG`'s boundary rows**, where the leaf's
//!   `freeze_root` lanes `W5..8` sit — a same-row bit-serial equality, zero
//!   columns (the census's `AISS` move, applied to the root instead).
//! - **allowlist membership**: `ACRED = H(rkm ‖ D_CRED)` (rkm chained from a
//!   re-derivation `ARKM′`), 20 `MERKLE` steps, the root captured at `BALLOW`'s
//!   boundary and bound to `AREG`'s `allow_root` lanes `W9..12` through **bank 1**
//!   (idle after `ARKM` closes). Off (`mode ≠ Regulated`) ⇒ both legs are gated
//!   out and the path is over a dummy — the trace is still spent.
//! - **`vPublic` per balance row** (row k = input k's asset), public, signed:
//!   `s_k` (0 = mint, 1 = redeem), four 16-bit chunks `m_k`, and `vpa_k`, the
//!   asset id revealed when `m_k ≠ 0` (issuance is public by design). The row's
//!   borrow chain closes on `in − out − [fee] + (1 − 2s)·m = 0`. Under `q`
//!   (one distinct asset) `vPublic₂` must be 0.
//! - **`AISS = H(isk ‖ D_I)`**, one per input, its digest captured at `ARKM`'s
//!   boundary into the **bind bank** and closed against `AREG`'s `issuer_key`
//!   lanes `W0..3` — **required** (`REQ_k`) when the row mints, or redeems an
//!   asset whose `redeem_open` flag is off; otherwise the window is reset
//!   unchecked.
//! - **`mode` read as flags** (ruling): the leaf's `mode` lane is bound bit by
//!   bit to two per-input witness bools `hy_k` (Hybrid, bit 0) / `rg_k`
//!   (Regulated, bit 1), `flags` to `ropen_k` (bit 0 = `redeem_open`); every
//!   other bit is zero. Gates: freeze check ⇔ `hy ∨ rg`; allowlist ⇔ `rg`;
//!   `vPublic ≠ 0 ⇒ hy ∨ rg` — **a Cloaked asset carries `vPublic = 0`**
//!   (the ruling's "Cloaked-with-vPublic=0"; §3.6's "issuer with mint only"
//!   parenthetical is NOT built — recorded in the build notes as a finding).
//!
//! ### Program order (per input `k`; 102 perms each, 212 in all → 2^20)
//!
//! ```text
//! [DUMMY]
//! ANK → NF → BNF_k → AISS → ARKM → AFRZ → 20×MERKLE → AREG → 16×MERKLE → BREG
//!     → ARKM′ → ACRED → 20×MERKLE → BALLOW → ARKM″ → ACM → 32×MERKLE → BANCHOR   (×2)
//! ACMOUT_0 → BCM1 → ARHO → ACMOUT_1 → BCM2 → BAL → END
//! ```
//!
//! **Why three `ARKM`s and how they are bound.** The Keccak chain carries one
//! digest; the freeze comparison, the credential hash and the note block each
//! need `rkm` chained at their boundary, so `rkm` is derived three times. The
//! second and third (`ROLE_ARKM2`, no bank-1 legs) have free inputs, and their
//! **outputs** are bound to the first's through two sequential equality windows
//! on banks that are idle in the input chain: `rkm@AFRZ − rkm′@ACRED` on the
//! third bank (`EQ3`, idle until the outputs), `rkm′@ACRED − rkm″@ACM` on the
//! bind bank (idle between `BREG` and `BANCHOR`). No new accumulator: every
//! cross-row binding in shape P rides an existing bank's idle span.
//!
//! ### Column accounting over `L2_WIDTH = 702` (+72 → 774) — see
//! `l2p_trace_width_is_read_off_the_matrix`, every column named.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::l2::{
    derive_input_l2, fabricated_registry_tree, l2_cm, L2TxInput, L2TxOutput, RegistryLeaf,
    RegistryWitness, ASSET_BITS, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED, PV_ANCHOR, PV_CM1,
    PV_CM2, PV_FEE, PV_NF1, PV_NF2, PV_REGROOT, REGISTRY_DEPTH, ROLE_ACM, ROLE_ACMOUT, ROLE_ANK,
    ROLE_AREG, ROLE_ARHO, ROLE_ARKM, ROLE_BAL, ROLE_BANCHOR, ROLE_BCM1, ROLE_BCM2, ROLE_BNF1,
    ROLE_BNF2, ROLE_BREG, ROLE_DUMMY, ROLE_END, ROLE_MERKLE, ROLE_NF, ROWS_PER_PERM,
};
use crate::narrow::{
    derive_output_rho, fabricated_shared_tree, fabricated_single_tree, off_tree_witness,
    pv_chunks, MerkleWitness, MERKLE_DEPTH,
};
use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — the narrow engine verbatim, the M3 machinery at 5-bit codes
// (as `l2.rs`), the ring widened to 53 limbs, then shape S's additions, then
// shape P's.
// ---------------------------------------------------------------------------

const A_OFF: usize = 0;
const C_OFF: usize = 25;
const US_OFF: usize = 30;
const AP_OFF: usize = 55;
const X00_COL: usize = 80;
const S_OFF: usize = 81;
const S_SLOTS: usize = 126;
const V_OFF: usize = S_OFF + S_SLOTS; // 207
const V_SLOTS: usize = 64;
const UV_OFF: usize = V_OFF + V_SLOTS; // 271
const U_OFF: usize = UV_OFF + 25; // 296
const U_SLOTS: usize = 65;
const UU_OFF: usize = U_OFF + U_SLOTS; // 361
const R_OFF: usize = UU_OFF + 10; // 371
const B_OFF: usize = R_OFF + 24; // 395
const PB_OFF: usize = B_OFF + 7; // 402
const PH_OFF: usize = PB_OFF + 24; // 426
/// 53 limbs × 4 slots = 212 program slots: exactly the shape-P program (no
/// spare slot — the shape is fixed; a perm at a fixed height costs nothing,
/// a ring limb costs a column).
const PR_LIMBS: usize = 53;
const PR_OFF: usize = PH_OFF + 4; // 430
const ROLE_BITS: usize = 5;
const D_OFF: usize = PR_OFF + PR_LIMBS; // 483
const RB_OFF: usize = D_OFF + 4 * ROLE_BITS; // 503
const LO_OFF: usize = RB_OFF + ROLE_BITS; // 508
/// Shape S's 16 role selectors + AISS, AFRZ, ACRED, BALLOW, ARKM2.
const NSEL: usize = 21;
const SEL_OFF: usize = LO_OFF + 4; // 512
/// [mrk+nf, ank, arkm+arkm2, acm, acmout, arho, areg, aiss, afrz, acred]
const NINJ: usize = 10;
const INJ_OFF: usize = SEL_OFF + NSEL; // 533
const G4_COL: usize = INJ_OFF + NINJ; // 543
const PBIT_COL: usize = G4_COL + 1; // 544
const NW: usize = 15;
const W_OFF: usize = PBIT_COL + 1; // 545
const EQ_OFF: usize = W_OFF + NW; // 560
const EG_OFF: usize = EQ_OFF + 32; // 592
const EP_COL: usize = EG_OFF + 6; // 598
const GWRAP_COL: usize = EP_COL + 1; // 599
const NSE: usize = 8;
const SE_OFF: usize = GWRAP_COL + 1; // 600
const SE_RHO: usize = 6;
const SE_AREG: usize = 7;
const BQ_OFF: usize = SE_OFF + NSE; // 608
const BGCAP_COL: usize = BQ_OFF + 16; // 624
const BGRST_COL: usize = BGCAP_COL + 1; // 625
const NBGC: usize = 6;
const BGC_OFF: usize = BGRST_COL + 1; // 626
const BL_OFF: usize = BGC_OFF + NBGC; // 632
const BLC_OFF: usize = BL_OFF + 4; // 636
const BLCLOSE_COL: usize = BLC_OFF + 9; // 645
const INJ3E_COL: usize = BLCLOSE_COL + 1; // 646
const INJ4E_COL: usize = INJ3E_COL + 1; // 647
const EFF_OFF: usize = INJ4E_COL + 1; // 648
const LATCH_COL: usize = EFF_OFF + 25; // 673
const DV_COL: usize = LATCH_COL + 1; // 674
const LDV_COL: usize = DV_COL + 1; // 675
const OM_COL: usize = LDV_COL + 1; // 676
const EQ3_OFF: usize = OM_COL + 1; // 677
const EG3_OFF: usize = EQ3_OFF + 16; // 693
// --- shape S additions (verbatim) ---
const INJRE_COL: usize = EG3_OFF + 3; // 696
const AG_OFF: usize = INJRE_COL + 1; // 697
const AG_IN1: usize = 0;
const AG_IN2: usize = 1;
const AG_O1: usize = 2;
const AG_O2: usize = 3;
const AG_R1: usize = 4;
const AG_R2: usize = 5;
const AC_OFF: usize = AG_OFF + 6; // 703
const SEL2_OFF: usize = AC_OFF + 6; // 709
const S2_O1A: usize = 0;
const S2_O2A: usize = 1;
const S2_F1: usize = 2;
const S2_Q: usize = 3;
const QINV_COL: usize = SEL2_OFF + 4; // 713
const CQ_OFF: usize = QINV_COL + 1; // 714
const SG_OFF: usize = CQ_OFF + 2; // 716
const BL2_OFF: usize = SG_OFF + 2; // 718
const BLC2_OFF: usize = BL2_OFF + 4; // 722
/// Shape S's width, reproduced here with the ring/selector/injection growth:
/// 702 + 21 + 5 + 3 = 731.
const S_END: usize = BLC2_OFF + 9; // 731
// --- shape P additions ---
/// `inj(afrz) · ep` — the third bank's `+rkm` leg (and the comparison's
/// assertion gate).
const INJ_AFRZE_COL: usize = S_END; // 731
/// `inj(acred) · ep` — the third bank's `−rkm′` leg and the bind bank's `+rkm′`.
const INJ_ACREDE_COL: usize = INJ_AFRZE_COL + 1; // 732
/// `gperm · sel(acred) · ep` — closes and resets the third bank's rkm window.
const CLOSE_CRED_COL: usize = INJ_ACREDE_COL + 1; // 733
/// `bnd · sel(ballow) · ep` — bank 1's `+allow_fold` leg (gated by `ALW`).
const EGB_COL: usize = CLOSE_CRED_COL + 1; // 734
/// `gperm · sel(ballow) · ep` — bank 1's allowlist close.
const EGBC_COL: usize = EGB_COL + 1; // 735
/// `gperm · SE[areg]` — resets the bind bank after the AISS window.
const AREGE_COL: usize = EGBC_COL + 1; // 736
/// `AREGE · RQ` — the AISS window's gated close.
const CRQ_COL: usize = AREGE_COL + 1; // 737
/// Two 256-bit comparisons, bit-serial: `key_lo < rkm` (block 0) and
/// `rkm < key_hi` (block 1). Per block: 4 running `LT` flags, 4 running `EQ`
/// flags (one per lane, LSB → MSB over z), and 3 materialized lane-combines
/// `C1 = LT1 + EQ1·LT0`, `C2 = LT2 + EQ2·C1`, `C3 = LT3 + EQ3·C2` — `C3` at
/// z = 63 is the 256-bit verdict.
const CMP_OFF: usize = CRQ_COL + 1; // 738
const CMP_BLOCK: usize = 11;
const CMP_LT: usize = 0;
const CMP_EQ: usize = 4;
const CMP_C: usize = 8;
/// Per-input policy witness constants (bool unless noted), each bound
/// in-circuit: `hy`, `rg`, `ropen` (to the leaf's lanes), `nz` (to `Σm`),
/// `vpinv` (field, the nonzero-inverse for `nz`), `REQ = nz·(1 − s·ropen)`;
/// then the two "current input" muxes `RQ` and `ALW`.
const POL_OFF: usize = CMP_OFF + 2 * CMP_BLOCK; // 760
const POL_HY: usize = 0;
const POL_RG: usize = 2;
const POL_ROPEN: usize = 4;
const POL_NZ: usize = 6;
const POL_VPINV: usize = 8;
const POL_REQ: usize = 10;
const POL_RQ: usize = 12;
const POL_ALW: usize = 13;

/// The shape-P trace width.
pub const L2P_WIDTH: usize = POL_OFF + 14; // 774

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 4 * PR_LIMBS; // 212

// Role codes 0..=16 are `l2.rs`'s (re-exported through the imports above);
// 17..=21 are shape P's.
/// `issuer_key = H(isk ‖ D_I)`: isk = W0..4, D_I at lane 4 bit 7, pad at lane 5.
pub const ROLE_AISS: u32 = 17;
/// Freeze low leaf `H(key_lo ‖ key_hi)`: key_lo = W0..4 at lanes 0..4, key_hi
/// = W5..9 at lanes 4..8, leaf marker at lane 8 bit 3 (≠ the Merkle node's
/// pad at bit 0, so a leaf never collides with an interior node). The chained
/// digest `a[0..4]` on its boundary rows is `rkm` — compared, not absorbed.
pub const ROLE_AFRZ: u32 = 18;
/// `cred = H(rkm ‖ D_CRED)`: rkm = chained a[0..4], D_CRED at lane 4 bit 15,
/// pad at lane 5.
pub const ROLE_ACRED: u32 = 19;
/// Allow-fold capture point: no injection; bank 1 captures `a[0..4]` (the
/// depth-20 fold's root) on its boundary rows.
pub const ROLE_BALLOW: u32 = 20;
/// `rkm` re-derivation: `ARKM`'s message, no bank-1 legs.
pub const ROLE_ARKM2: u32 = 21;

const SEL_CODES: [u32; NSEL] = [
    ROLE_MERKLE,
    ROLE_NF,
    ROLE_ANK,
    ROLE_ARKM,
    ROLE_ACM,
    ROLE_ACMOUT,
    ROLE_BANCHOR,
    ROLE_BNF1,
    ROLE_BNF2,
    ROLE_BCM1,
    ROLE_BCM2,
    ROLE_BAL,
    ROLE_END,
    ROLE_ARHO,
    ROLE_AREG,
    ROLE_BREG,
    ROLE_AISS,
    ROLE_AFRZ,
    ROLE_ACRED,
    ROLE_BALLOW,
    ROLE_ARKM2,
];
const SEL_ARHO: usize = 13;
const SEL_AREG: usize = 14;
const SEL_BREG: usize = 15;
const SEL_AISS: usize = 16;
const SEL_AFRZ: usize = 17;
const SEL_ACRED: usize = 18;
const SEL_BALLOW: usize = 19;
const SEL_ARKM2: usize = 20;
const INJ_AISS: usize = 7;
const INJ_AFRZ: usize = 8;
const INJ_ACRED: usize = 9;

/// Registry `flags` bit 0: holders may redeem without the issuer key.
pub const FLAG_REDEEM_OPEN: u64 = 1;

/// Public values: shape S's 100, then `vPublic` per balance row: `s` (sign,
/// 1 = redeem), `m` (4 × 16-bit chunks), `vpa` (the asset id, bound when
/// `m ≠ 0`, 0 by convention otherwise).
pub const PV_VP1: usize = 100;
pub const PV_VP2: usize = 106;
pub const PV_LEN: usize = 112;
const fn pv_vp_sign(k: usize) -> usize {
    PV_VP1 + 6 * k
}
const fn pv_vp_chunk(k: usize, j: usize) -> usize {
    PV_VP1 + 6 * k + 1 + j
}
const fn pv_vp_asset(k: usize) -> usize {
    PV_VP1 + 6 * k + 5
}

/// One row's public `vPublic` term.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VPublic {
    /// `true` = redeem (`−amount`), `false` = mint (`+amount`).
    pub redeem: bool,
    pub amount: u64,
}

impl VPublic {
    pub const NONE: VPublic = VPublic { redeem: false, amount: 0 };
    pub fn mint(amount: u64) -> Self {
        Self { redeem: false, amount }
    }
    pub fn redeem(amount: u64) -> Self {
        Self { redeem: true, amount }
    }
}

/// Build the full public-value vector for a shape-P instance. `vpa[k]` is the
/// asset revealed on row k (0 when that row's `vPublic` is 0).
#[allow(clippy::too_many_arguments)]
pub fn pv_vec_l2p(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm1: &[u64; 4],
    cm2: &[u64; 4],
    fee: u64,
    registry_root: &[u64; 4],
    vp: &[VPublic; 2],
    vpa: &[u64; 2],
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, nf1, nf2, cm1, cm2] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    out.extend_from_slice(&pv_chunks(registry_root));
    for k in 0..2 {
        out.push(vp[k].redeem as u32);
        for j in 0..4 {
            out.push(((vp[k].amount >> (16 * j)) & 0xffff) as u32);
        }
        out.push(vpa[k] as u32);
    }
    debug_assert_eq!(out.len(), PV_LEN);
    out
}

/// Freeze-tree depth (l2-own-circuit-decision §3.2; an L2 parameter).
pub const FREEZE_DEPTH: usize = 20;
/// Allowlist depth (§3.4; an L2 parameter).
pub const ALLOW_DEPTH: usize = 20;
/// Policy-tree depth: both are 20 in W3, one witness type serves both.
pub const POLICY_DEPTH: usize = 20;

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

/// Per-perm-slot witness: 15 generic 64-bit lanes plus the merkle path bit.
#[derive(Clone, Copy)]
pub struct L2PSlotWitness {
    pub w: [u64; NW],
    pub pbit: bool,
}

impl Default for L2PSlotWitness {
    fn default() -> Self {
        Self { w: [0; NW], pbit: false }
    }
}

/// Shape P of the L2 circuit family.
pub struct L2ShapePAir {
    pub log_height: usize,
    pub program: [u32; PROGRAM_SLOTS],
    pub slot_witness: Vec<L2PSlotWitness>,
    pub fee: u64,
    pub dv: bool,
    pub sel_o1a: bool,
    pub sel_o2a: bool,
    pub sel_f1: bool,
    pub sel_q: bool,
    /// Per input: the leaf's mode read as flags (bound bit by bit to the
    /// `mode` lane at `AREG`), and `redeem_open` (bound to `flags` bit 0).
    pub hy: [bool; 2],
    pub rg: [bool; 2],
    pub ropen: [bool; 2],
    /// Per row: the public `vPublic` (the trace needs it for the carries and
    /// for `nz`/`vpinv`).
    pub vp: [VPublic; 2],
}

impl L2ShapePAir {
    /// Every perm slot dummy, pure chaining — the geometry probe / canary.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
            fee: 0,
            dv: false,
            sel_o1a: true,
            sel_o2a: true,
            sel_f1: true,
            sel_q: true,
            hy: [false; 2],
            rg: [false; 2],
            ropen: [false; 2],
            vp: [VPublic::NONE; 2],
        }
    }

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

const NPERIODIC: usize = 40;
const PER_LO16: usize = 39;

impl<F: Field> BaseAir<F> for L2ShapePAir {
    fn width(&self) -> usize {
        L2P_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PV_LEN
    }

    fn num_periodic_columns(&self) -> usize {
        NPERIODIC
    }

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
            cols[PER_LO16].push(F::from_bool(z < ASSET_BITS));
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
