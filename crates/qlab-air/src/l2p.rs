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
    ROLE_BNF2, ROLE_BREG, ROLE_DUMMY, ROLE_END, ROLE_MERKLE, ROLE_NF,
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

impl<AB: AirBuilder> Air<AB> for L2ShapePAir
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
        let lo16 = per[PER_LO16].clone();
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

        // --- Same-row constraints: the Keccak engine (verbatim) ---
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

        // --- Program machinery (5-bit codes, 53-limb ring) ---
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
        builder.assert_eq(
            local[INJ_OFF].clone(),
            bnd.clone() * (sel_role(0) + sel_role(1)),
        );
        builder.assert_eq(local[INJ_OFF + 1].clone(), bnd.clone() * sel_role(2));
        // ARKM and ARKM2 share the injection class (the message is the same);
        // only ARKM carries bank-1 legs.
        builder.assert_eq(
            local[INJ_OFF + 2].clone(),
            bnd.clone() * (sel_role(3) + sel_role(SEL_ARKM2)),
        );
        for i in 3..5 {
            builder.assert_eq(
                local[INJ_OFF + i].clone(),
                bnd.clone() * sel_role(i + 1),
            );
        }
        builder.assert_eq(local[INJ_OFF + 5].clone(), bnd.clone() * sel_role(SEL_ARHO));
        builder.assert_eq(local[INJ_OFF + 6].clone(), bnd.clone() * sel_role(SEL_AREG));
        builder.assert_eq(local[INJ_OFF + INJ_AISS].clone(), bnd.clone() * sel_role(SEL_AISS));
        builder.assert_eq(local[INJ_OFF + INJ_AFRZ].clone(), bnd.clone() * sel_role(SEL_AFRZ));
        builder.assert_eq(local[INJ_OFF + INJ_ACRED].clone(), bnd.clone() * sel_role(SEL_ACRED));
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );
        builder.assert_bool(local[PBIT_COL].clone());
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
            let msg_ank: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(0),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_arkm: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(1),
                5 => w(5),
                6 => w(6),
                7 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_acm: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => a(l - 2),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_acmout: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => w(l - 2),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_arho: AB::Expr = match l {
                0..=3 => w(l + 5),
                4 => sel(2),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_areg: AB::Expr = match l {
                0 => w(13),
                1..=4 => w(l - 1),
                5 => w(4),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => w(14),
                15 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // AISS: isk = W0..4, D_I = lane 4 bit 7, pad at lane 5.
            let msg_aiss: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(3),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // AFRZ: the low leaf `key_lo ‖ key_hi`, leaf marker lane 8 bit 3.
            let msg_afrz: AB::Expr = match l {
                0..=3 => w(l),
                4..=7 => w(l + 1),
                8 => sel(2),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // ACRED: rkm chained, D_CRED = lane 4 bit 15, pad at lane 5.
            let msg_acred: AB::Expr = match l {
                0..=3 => a(l),
                4 => sel(4),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let expr = a(l)
                + inj(0) * (msg_mrk - a(l))
                + inj(1) * (msg_ank - a(l))
                + inj(2) * (msg_arkm - a(l))
                + inj(3) * (msg_acm - a(l))
                + inj(4) * (msg_acmout - a(l))
                + inj(5) * (msg_arho - a(l))
                + inj(6) * (msg_areg - a(l))
                + inj(INJ_AISS) * (msg_aiss - a(l))
                + inj(INJ_AFRZ) * (msg_afrz - a(l))
                + inj(INJ_ACRED) * (msg_acred - a(l));
            builder.assert_eq(eff(l), expr);
        }

        // --- Equality banks 1 and 2 (the S gates verbatim) ---
        let gperm = blast.clone() * local[PB_OFF + 1].clone();
        builder.assert_eq(local[EG_OFF].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 1].clone(),
            bnd.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 2].clone(),
            gperm.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(local[EG_OFF + 3].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 4].clone(),
            bnd.clone() * local[SE_OFF + 2].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 5].clone(),
            gperm.clone() * local[SE_OFF + 2].clone(),
        );
        for j in 0..16 {
            builder.assert_zero(local[EG_OFF + 2].clone() * local[EQ_OFF + j].clone());
            builder
                .assert_zero(local[EG_OFF + 5].clone() * local[EQ_OFF + 16 + j].clone());
        }
        for j in 0..32 {
            builder.when_first_row().assert_zero(local[EQ_OFF + j].clone());
        }

        // --- Epoch, ep-gated selectors, bind bank ---
        let ep = local[EP_COL].clone();
        builder.when_first_row().assert_eq(ep.clone(), AB::Expr::ONE);
        builder.assert_eq(
            local[GWRAP_COL].clone(),
            gperm.clone() * sel_role(12),
        );
        let se_src: [usize; 4] = [1, 3, 4, 5]; // nf, arkm, acm, acmout
        for (i, si) in se_src.iter().enumerate() {
            builder.assert_eq(local[SE_OFF + i].clone(), sel_role(*si) * ep.clone());
        }
        let bindsum = sel_role(6)
            + sel_role(7)
            + sel_role(8)
            + sel_role(9)
            + sel_role(10)
            + sel_role(SEL_BREG);
        builder.assert_eq(local[SE_OFF + 4].clone(), bindsum * ep.clone());
        builder.assert_eq(local[SE_OFF + 5].clone(), sel_role(11) * ep.clone());
        builder.assert_eq(
            local[SE_OFF + SE_RHO].clone(),
            (sel_role(SEL_ARHO) + sel_role(5)) * ep.clone(),
        );
        builder.assert_eq(
            local[SE_OFF + SE_AREG].clone(),
            sel_role(SEL_AREG) * ep.clone(),
        );
        builder.assert_eq(
            local[BGCAP_COL].clone(),
            bnd.clone() * local[SE_OFF + 4].clone(),
        );
        builder.assert_eq(
            local[BGRST_COL].clone(),
            gperm.clone() * local[SE_OFF + 4].clone(),
        );
        for (i, si) in [6usize, 7, 8, 9, 10, SEL_BREG].iter().enumerate() {
            builder.assert_eq(
                local[BGC_OFF + i].clone(),
                gperm.clone() * sel_role(*si),
            );
        }
        let pvs: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv = |i: usize| -> AB::Expr { pvs[i].clone() };
        let pv_base: [usize; NBGC] = [PV_ANCHOR, PV_NF1, PV_NF2, PV_CM1, PV_CM2, PV_REGROOT];
        for (x, base) in pv_base.iter().enumerate() {
            for j in 0..16 {
                let close = local[BGC_OFF + x].clone()
                    * (local[BQ_OFF + j].clone() - pv(base + j) * ep.clone());
                let close = if x == 0 {
                    (AB::Expr::ONE - local[LDV_COL].clone()) * close
                } else {
                    close
                };
                builder.assert_zero(close);
            }
        }
        for j in 0..16 {
            builder.when_first_row().assert_zero(local[BQ_OFF + j].clone());
        }

        // --- The third bank (#215 option 4, verbatim gates) ---
        {
            builder.assert_eq(
                local[EG3_OFF].clone(),
                bnd.clone() * local[SE_OFF + SE_RHO].clone(),
            );
            builder.assert_eq(
                local[EG3_OFF + 1].clone(),
                bnd.clone() * local[SE_OFF + 3].clone() * local[OM_COL].clone(),
            );
            builder.assert_eq(
                local[EG3_OFF + 2].clone(),
                gperm.clone() * local[SE_OFF + SE_RHO].clone(),
            );
            builder.assert_bool(local[OM_COL].clone());
            builder.when_first_row().assert_zero(local[OM_COL].clone());
            for j in 0..16 {
                builder.assert_zero(
                    local[EG3_OFF + 2].clone()
                        * (local[EQ3_OFF + j].clone()
                            - (AB::Expr::ONE - local[OM_COL].clone())
                                * pv(PV_NF1 + j)
                                * ep.clone()),
                );
                builder.when_first_row().assert_zero(local[EQ3_OFF + j].clone());
            }
        }

        // --- Balance gates ---
        builder.assert_eq(local[INJ3E_COL].clone(), inj(3) * ep.clone());
        builder.assert_eq(local[INJ4E_COL].clone(), inj(4) * ep.clone());
        builder.assert_eq(local[INJRE_COL].clone(), inj(6) * ep.clone());
        builder.assert_eq(
            local[BLCLOSE_COL].clone(),
            gperm.clone() * local[SE_OFF + 5].clone(),
        );
        for k in 0..9 {
            builder.assert_bool(local[BLC_OFF + k].clone());
            builder.assert_bool(local[BLC2_OFF + k].clone());
        }
        for j in 0..4 {
            builder.when_first_row().assert_zero(local[BL_OFF + j].clone());
            builder.when_first_row().assert_zero(local[BL2_OFF + j].clone());
        }

        // --- Shape S: the latch and the marker as the "which slot" signals ---
        let latch = local[LATCH_COL].clone();
        let om = local[OM_COL].clone();
        builder.assert_eq(
            local[AG_OFF + AG_IN1].clone(),
            local[INJ3E_COL].clone() * (AB::Expr::ONE - latch.clone()),
        );
        builder.assert_eq(
            local[AG_OFF + AG_IN2].clone(),
            local[INJ3E_COL].clone() * latch.clone(),
        );
        builder.assert_eq(
            local[AG_OFF + AG_O1].clone(),
            local[INJ4E_COL].clone() * (AB::Expr::ONE - om.clone()),
        );
        builder.assert_eq(
            local[AG_OFF + AG_O2].clone(),
            local[INJ4E_COL].clone() * om.clone(),
        );
        builder.assert_eq(
            local[AG_OFF + AG_R1].clone(),
            local[INJRE_COL].clone() * (AB::Expr::ONE - latch.clone()),
        );
        builder.assert_eq(
            local[AG_OFF + AG_R2].clone(),
            local[INJRE_COL].clone() * latch.clone(),
        );
        for k in 0..4 {
            builder.assert_bool(local[SEL2_OFF + k].clone());
        }
        {
            let close = local[BLCLOSE_COL].clone();
            let q = local[SEL2_OFF + S2_Q].clone();
            builder.assert_eq(local[CQ_OFF].clone(), close.clone() * q.clone());
            builder.assert_eq(local[CQ_OFF + 1].clone(), close * (AB::Expr::ONE - q));
        }
        builder.assert_eq(
            local[SG_OFF].clone(),
            local[AG_OFF + AG_O1].clone() * local[SEL2_OFF + S2_O1A].clone(),
        );
        builder.assert_eq(
            local[SG_OFF + 1].clone(),
            local[AG_OFF + AG_O2].clone() * local[SEL2_OFF + S2_O2A].clone(),
        );
        for k in 0..6 {
            builder.when_first_row().assert_zero(local[AC_OFF + k].clone());
        }
        let hi = AB::Expr::ONE - lo16.clone();
        builder.assert_zero(local[INJ3E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJ4E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJRE_COL].clone() * hi * w(13));

        // --- Shape P: the policy constants and their bindings ---
        let pol = |k: usize| local[POL_OFF + k].clone();
        for k in 0..2 {
            builder.assert_bool(pol(POL_HY + k));
            builder.assert_bool(pol(POL_RG + k));
            builder.assert_bool(pol(POL_ROPEN + k));
            builder.assert_bool(pol(POL_NZ + k));
            // Hybrid and Regulated are exclusive.
            builder.assert_zero(pol(POL_HY + k) * pol(POL_RG + k));
        }
        // `mode` lane at AREG: bit 0 = hy, bit 1 = rg, everything else 0;
        // `flags` lane: bit 0 = redeem_open, everything else 0. `AG_R1`/`AG_R2`
        // are `INJRE·(1−L)` / `INJRE·L` — input 0's and input 1's AREG rows.
        for (k, g) in [AG_R1, AG_R2].iter().enumerate() {
            let gate = local[AG_OFF + g].clone();
            builder.assert_zero(
                gate.clone() * (w(4) - pol(POL_HY + k) * sel(0) - pol(POL_RG + k) * sel(1)),
            );
            builder.assert_zero(gate.clone() * (w(14) - pol(POL_ROPEN + k) * sel(0)));
            // Freeze non-membership, the root: on AREG's boundary rows the
            // chained digest is the depth-20 fold of the low leaf; when the
            // asset has a freeze tree (hy ∨ rg) it equals the leaf's
            // `freeze_root` lanes W5..8, bit by bit. Zero columns.
            let frz = pol(POL_HY + k) + pol(POL_RG + k);
            for l in 0..4 {
                builder.assert_zero(gate.clone() * frz.clone() * (a(l) - w(5 + l)));
            }
        }
        // `nz_k` ⇔ `Σm_k ≠ 0` (the chunks are 16-bit public values; their sum
        // is nonzero iff the amount is).
        let sum_m = |k: usize| -> AB::Expr {
            (0..4)
                .map(|j| pv(pv_vp_chunk(k, j)))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        for k in 0..2 {
            builder.assert_zero(pol(POL_NZ + k) * (pol(POL_VPINV + k) * sum_m(k) - AB::Expr::ONE));
            builder.assert_zero((AB::Expr::ONE - pol(POL_NZ + k)) * sum_m(k));
            // A Cloaked asset (neither flag) carries vPublic = 0.
            builder.assert_zero(sum_m(k) * (AB::Expr::ONE - pol(POL_HY + k) - pol(POL_RG + k)));
            // REQ_k = nz_k · (1 − s_k · ropen_k): the issuer key is required to
            // mint, and to redeem an asset that is not redeem_open.
            builder.assert_eq(
                pol(POL_REQ + k),
                pol(POL_NZ + k) - pol(POL_NZ + k) * pv(pv_vp_sign(k)) * pol(POL_ROPEN + k),
            );
        }
        // The two "current input" muxes.
        builder.assert_eq(
            pol(POL_RQ),
            pol(POL_REQ) + latch.clone() * (pol(POL_REQ + 1) - pol(POL_REQ)),
        );
        builder.assert_eq(
            pol(POL_ALW),
            pol(POL_RG) + latch.clone() * (pol(POL_RG + 1) - pol(POL_RG)),
        );
        // Shape-P gate columns.
        builder.assert_eq(local[INJ_AFRZE_COL].clone(), inj(INJ_AFRZ) * ep.clone());
        builder.assert_eq(local[INJ_ACREDE_COL].clone(), inj(INJ_ACRED) * ep.clone());
        builder.assert_eq(
            local[CLOSE_CRED_COL].clone(),
            gperm.clone() * sel_role(SEL_ACRED) * ep.clone(),
        );
        builder.assert_eq(local[EGB_COL].clone(), bnd.clone() * sel_role(SEL_BALLOW) * ep.clone());
        builder.assert_eq(
            local[EGBC_COL].clone(),
            gperm.clone() * sel_role(SEL_BALLOW) * ep.clone(),
        );
        builder.assert_eq(
            local[AREGE_COL].clone(),
            gperm.clone() * local[SE_OFF + SE_AREG].clone(),
        );
        builder.assert_eq(local[CRQ_COL].clone(), local[AREGE_COL].clone() * pol(POL_RQ));
        // Bank closes: the third bank's rkm window at ACRED's end; the bind
        // bank's rkm′ window at ACM's end (EG[5] = gperm·SE[acm]); the bind
        // bank's AISS window at AREG's end, gated by REQ; bank 1's allowlist
        // window at BALLOW's end (its legs are gated by ALW, so an off
        // allowlist accumulates nothing).
        for j in 0..16 {
            builder.assert_zero(local[CLOSE_CRED_COL].clone() * local[EQ3_OFF + j].clone());
            builder.assert_zero(local[EG_OFF + 5].clone() * local[BQ_OFF + j].clone());
            builder.assert_zero(local[CRQ_COL].clone() * local[BQ_OFF + j].clone());
            builder.assert_zero(local[EGBC_COL].clone() * local[EQ_OFF + j].clone());
        }

        // --- The two 256-bit comparisons, bit-serial (LSB → MSB over z) ---
        // Block 0: key_lo (W0..3) < rkm (a); block 1: rkm (a) < key_hi (W5..8).
        // Per lane: LT_z = (1−x)·y + (1 − x − y + 2xy)·LT_{z−1}, EQ_z = EQ_{z−1}·(1 − x − y + 2xy),
        // seeded at z = 0 (same-row, `sel(0)`), advanced on M rows z < 63
        // (transition), free on T rows and at the M → T edge. The lane
        // combines C1..C3 are same-row everywhere; C3 at AFRZ's z = 63 is the
        // verdict.
        let cmp = |blk: usize, k: usize| local[CMP_OFF + CMP_BLOCK * blk + k].clone();
        let cmp_next = |blk: usize, k: usize| next[CMP_OFF + CMP_BLOCK * blk + k].clone();
        let xy = |blk: usize, l: usize, row: &[AB::Expr]| -> (AB::Expr, AB::Expr) {
            if blk == 0 {
                (row[W_OFF + l].clone(), row[A_OFF + l].clone())
            } else {
                (row[A_OFF + l].clone(), row[W_OFF + 5 + l].clone())
            }
        };
        for blk in 0..2 {
            for l in 0..4 {
                let (x, y) = xy(blk, l, &local);
                let same = AB::Expr::ONE - x.clone() - y.clone() + two.clone() * x.clone() * y.clone();
                builder.assert_zero(sel(0) * (cmp(blk, CMP_LT + l) - (AB::Expr::ONE - x.clone()) * y.clone()));
                builder.assert_zero(sel(0) * (cmp(blk, CMP_EQ + l) - same));
            }
            let c1 = cmp(blk, CMP_LT + 1) + cmp(blk, CMP_EQ + 1) * cmp(blk, CMP_LT);
            builder.assert_eq(cmp(blk, CMP_C), c1);
            let c2 = cmp(blk, CMP_LT + 2) + cmp(blk, CMP_EQ + 2) * cmp(blk, CMP_C);
            builder.assert_eq(cmp(blk, CMP_C + 1), c2);
            let c3 = cmp(blk, CMP_LT + 3) + cmp(blk, CMP_EQ + 3) * cmp(blk, CMP_C + 1);
            builder.assert_eq(cmp(blk, CMP_C + 2), c3);
            // The verdict on AFRZ's last boundary row.
            builder.assert_zero(
                local[INJ_AFRZE_COL].clone() * u63.clone() * (cmp(blk, CMP_C + 2) - AB::Expr::ONE),
            );
        }

        // Balance closes with vPublic. Under `¬q` (CQ[1]): row 1 pays `f1·fee`
        // and carries vPublic₁, row 2 pays `(1 − f1)·fee` and carries
        // vPublic₂, each on its own chain. Under `q` (CQ[0]): the rows are
        // summed, pay the whole fee once and carry vPublic₁ (vPublic₂ = 0).
        // Carry offset −3: c ∈ [−3, 4] (the signed term widens the L1 range).
        let carry = |off: usize, j: usize| -> AB::Expr {
            local[off + 3 * j].clone()
                + local[off + 3 * j + 1].clone() * two.clone()
                + local[off + 3 * j + 2].clone() * two.clone() * two.clone()
                - two.clone()
                - AB::Expr::ONE
        };
        let close = local[BLCLOSE_COL].clone();
        let close_q = local[CQ_OFF].clone();
        let close_nq = local[CQ_OFF + 1].clone();
        let w16 = AB::Expr::from_u32(1 << 16);
        let f1 = local[SEL2_OFF + S2_F1].clone();
        let acc = |bl: usize, j: usize| local[bl + j].clone();
        let summed = |j: usize| local[BL_OFF + j].clone() + local[BL2_OFF + j].clone();
        // (gate, accumulator at chunk j, carry block, fee selector, vPublic row)
        type Chain<'a, E> = (E, Box<dyn Fn(usize) -> E + 'a>, usize, E, usize);
        let chains: [Chain<'_, AB::Expr>; 3] = [
            (close_nq.clone(), Box::new(move |j| acc(BL_OFF, j)), BLC_OFF, f1.clone(), 0),
            (close_nq.clone(), Box::new(move |j| acc(BL2_OFF, j)), BLC2_OFF, AB::Expr::ONE - f1.clone(), 1),
            (close_q.clone(), Box::new(summed), BLC_OFF, AB::Expr::ONE, 0),
        ];
        for (gate, bl, blc, fsel, k) in chains.iter() {
            // in − out − fee + (1 − 2s)·m = 0  ⇔  bl = fee − (1 − 2s)·m
            let sgn = AB::Expr::ONE - two.clone() * pv(pv_vp_sign(*k));
            let feev = |j: usize| {
                fsel.clone() * pv(PV_FEE + j) * ep.clone() - sgn.clone() * pv(pv_vp_chunk(*k, j)) * ep.clone()
            };
            builder.assert_zero(gate.clone() * (bl(0) - feev(0) - w16.clone() * carry(*blc, 0)));
            for j in 1..3 {
                builder.assert_zero(
                    gate.clone()
                        * (bl(j) + carry(*blc, j - 1) - feev(j) - w16.clone() * carry(*blc, j)),
                );
            }
            builder.assert_zero(gate.clone() * (bl(3) + carry(*blc, 2) - feev(3)));
        }
        let ac = |k: usize| local[AC_OFF + k].clone();
        builder.assert_zero(close_q.clone() * (ac(AG_IN1) - ac(AG_IN2)));
        builder.assert_zero(
            close_nq * (local[QINV_COL].clone() * (ac(AG_IN1) - ac(AG_IN2)) - AB::Expr::ONE),
        );
        let o1a = local[SEL2_OFF + S2_O1A].clone();
        let o2a = local[SEL2_OFF + S2_O2A].clone();
        builder.assert_zero(close.clone() * o1a.clone() * (ac(AG_O1) - ac(AG_IN1)));
        builder.assert_zero(
            close.clone() * (AB::Expr::ONE - o1a) * (ac(AG_O1) - ac(AG_IN2)),
        );
        builder.assert_zero(close.clone() * o2a.clone() * (ac(AG_O2) - ac(AG_IN1)));
        builder.assert_zero(
            close.clone() * (AB::Expr::ONE - o2a) * (ac(AG_O2) - ac(AG_IN2)),
        );
        builder.assert_zero(close.clone() * f1.clone() * ac(AG_IN1));
        builder.assert_zero(close.clone() * (AB::Expr::ONE - f1) * ac(AG_IN2));
        builder.assert_zero(close.clone() * (ac(AG_R1) - ac(AG_IN1)));
        builder.assert_zero(close.clone() * (ac(AG_R2) - ac(AG_IN2)));
        // vPublic's public surface: the sign is a bool; the revealed asset is
        // the row's when the amount is nonzero; one distinct asset ⇒ vPublic₂ = 0.
        for k in 0..2 {
            let s = pv(pv_vp_sign(k));
            builder.assert_zero(close.clone() * s.clone() * (AB::Expr::ONE - s));
            let row_asset = if k == 0 { ac(AG_IN1) } else { ac(AG_IN2) };
            builder.assert_zero(close.clone() * sum_m(k) * (pv(pv_vp_asset(k)) - row_asset));
        }
        builder.assert_zero(close_q.clone() * sum_m(1));
        builder.assert_zero(close_q * pv(pv_vp_sign(1)));

        // --- The #219 latch (verbatim) + the dummy slot's asset ---
        {
            let dv = local[DV_COL].clone();
            builder.assert_bool(latch.clone());
            builder.assert_bool(dv.clone());
            builder.when_first_row().assert_zero(latch.clone());
            builder.assert_eq(local[LDV_COL].clone(), latch.clone() * dv);
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 4].clone(),
            );
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 13].clone(),
            );
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
        let g = blast.clone() * local[PB_OFF + 1].clone();
        for i in 0..4 {
            t.assert_eq(
                next[PH_OFF + i].clone(),
                (AB::Expr::ONE - g.clone()) * local[PH_OFF + i].clone()
                    + g.clone() * local[PH_OFF + (i + 1) % 4].clone(),
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
            (AB::Expr::ONE - g.clone())
                * (next[PBIT_COL].clone() - local[PBIT_COL].clone()),
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
        t.assert_eq(next[u_col(65)].clone(), (mrow.clone() - u63.clone()) * hi_c);

        t.assert_eq(
            next[EP_COL].clone(),
            local[EP_COL].clone() * (AB::Expr::ONE - local[GWRAP_COL].clone()),
        );
        // The bind bank: S's capture/reset, plus the AISS window (+a at ARKM's
        // boundary, −W0..3 at AREG's; reset at AREG's end) and the rkm′ window
        // (+a at ACRED's boundary, −a at ACM's; asserted 0 at ACM's end).
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - local[BGRST_COL].clone() - local[AREGE_COL].clone())
                        * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone()
                        + local[EG_OFF + 1].clone() * per[35 + j].clone() * local[A_OFF + l].clone()
                        - local[INJRE_COL].clone() * per[35 + j].clone() * local[W_OFF + l].clone()
                        + local[INJ_ACREDE_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone()
                        - local[INJ3E_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone(),
                );
            }
        }
        for j in 0..4 {
            let pw = per[35 + j].clone();
            let v = local[W_OFF + 4].clone();
            t.assert_eq(
                next[BL_OFF + j].clone(),
                local[BL_OFF + j].clone()
                    + local[AG_OFF + AG_IN1].clone() * pw.clone() * v.clone()
                    - local[SG_OFF].clone() * pw.clone() * v.clone()
                    - local[SG_OFF + 1].clone() * pw.clone() * v.clone(),
            );
            t.assert_eq(
                next[BL2_OFF + j].clone(),
                local[BL2_OFF + j].clone()
                    + local[AG_OFF + AG_IN2].clone() * pw.clone() * v.clone()
                    - (local[AG_OFF + AG_O1].clone() - local[SG_OFF].clone())
                        * pw.clone()
                        * v.clone()
                    - (local[AG_OFF + AG_O2].clone() - local[SG_OFF + 1].clone())
                        * pw
                        * v,
            );
        }
        for k in 0..6 {
            t.assert_eq(
                next[AC_OFF + k].clone(),
                local[AC_OFF + k].clone()
                    + local[AG_OFF + k].clone() * per[35].clone() * local[W_OFF + 13].clone(),
            );
        }
        for k in 0..4 {
            t.assert_eq(next[SEL2_OFF + k].clone(), local[SEL2_OFF + k].clone());
        }
        t.assert_eq(next[QINV_COL].clone(), local[QINV_COL].clone());
        // The policy constants are per-transaction declarations.
        for k in [POL_HY, POL_HY + 1, POL_RG, POL_RG + 1, POL_ROPEN, POL_ROPEN + 1, POL_NZ, POL_NZ + 1, POL_VPINV, POL_VPINV + 1] {
            t.assert_eq(next[POL_OFF + k].clone(), local[POL_OFF + k].clone());
        }
        {
            t.assert_eq(
                next[LATCH_COL].clone(),
                local[LATCH_COL].clone() * (AB::Expr::ONE - local[BGC_OFF].clone())
                    + local[BGC_OFF + 2].clone(),
            );
            t.assert_eq(next[DV_COL].clone(), local[DV_COL].clone());
        }
        // The output-1 marker and the third bank: S's legs, plus the rkm
        // window (+a at AFRZ's boundary, −a at ACRED's; reset at ACRED's end).
        {
            let arho_close =
                local[EG3_OFF + 2].clone() * local[SEL_OFF + SEL_ARHO].clone();
            t.assert_eq(
                next[OM_COL].clone(),
                local[OM_COL].clone() * (AB::Expr::ONE - local[BGC_OFF + 4].clone())
                    + arho_close,
            );
            for l in 0..4 {
                for j in 0..4 {
                    let idx = 4 * l + j;
                    t.assert_eq(
                        next[EQ3_OFF + idx].clone(),
                        (AB::Expr::ONE - local[EG3_OFF + 2].clone() - local[CLOSE_CRED_COL].clone())
                            * local[EQ3_OFF + idx].clone()
                            + local[EG3_OFF].clone()
                                * per[35 + j].clone()
                                * local[W_OFF + 5 + l].clone()
                            - local[EG3_OFF + 1].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone()
                            + local[INJ_AFRZE_COL].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone()
                            - local[INJ_ACREDE_COL].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone(),
                    );
                }
            }
        }
        // Banks 1 and 2: S's legs, plus bank 1's allowlist window (−W9..12 at
        // AREG's boundary, +a at BALLOW's, both gated by ALW).
        let pwk = |j: usize| per[35 + j].clone();
        let alw = local[POL_OFF + POL_ALW].clone();
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[EQ_OFF + idx].clone(),
                    local[EQ_OFF + idx].clone()
                        + local[EG_OFF].clone() * pwk(j) * local[A_OFF + l].clone()
                        - local[EG_OFF + 1].clone() * pwk(j) * local[W_OFF + l].clone()
                        + local[EGB_COL].clone() * alw.clone() * pwk(j) * local[A_OFF + l].clone()
                        - local[INJRE_COL].clone() * alw.clone() * pwk(j) * local[W_OFF + 9 + l].clone(),
                );
                t.assert_eq(
                    next[EQ_OFF + 16 + idx].clone(),
                    local[EQ_OFF + 16 + idx].clone()
                        + local[EG_OFF + 3].clone() * pwk(j) * local[W_OFF + l].clone()
                        - local[EG_OFF + 4].clone() * pwk(j) * local[W_OFF + 5 + l].clone(),
                );
            }
        }
        // The comparison flags advance on M rows below z = 63.
        let adv = mrow.clone() * (AB::Expr::ONE - u63.clone());
        for blk in 0..2 {
            for l in 0..4 {
                let (x, y) = xy(blk, l, &next);
                let same = AB::Expr::ONE - x.clone() - y.clone() + two.clone() * x.clone() * y.clone();
                t.assert_zero(
                    adv.clone()
                        * (cmp_next(blk, CMP_LT + l)
                            - (AB::Expr::ONE - x.clone()) * y.clone()
                            - same.clone() * cmp(blk, CMP_LT + l)),
                );
                t.assert_zero(
                    adv.clone() * (cmp_next(blk, CMP_EQ + l) - same * cmp(blk, CMP_EQ + l)),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Host mirrors of the shape-P hashes and the policy trees
// ---------------------------------------------------------------------------

/// `issuer_key = H(isk ‖ D_I)` — the `ROLE_AISS` block (D_I = lane 4 bit 7).
pub fn issuer_key_of(isk: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(isk);
    st[4] = 1 << 7;
    st[5] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// `cred = H(rkm ‖ D_CRED)` — the `ROLE_ACRED` block (D_CRED = lane 4 bit 15;
/// the derivation domain is W3's placeholder, an L2 parameter).
pub fn cred_of(rkm: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(rkm);
    st[4] = 1 << 15;
    st[5] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// The indexed-Merkle low leaf `H(key_lo ‖ key_hi)` — the `ROLE_AFRZ` block
/// (leaf marker at lane 8 bit 3, distinct from the interior node's pad).
pub fn freeze_leaf_hash(key_lo: &[u64; 4], key_hi: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(key_lo);
    st[4..8].copy_from_slice(key_hi);
    st[8] = 1 << 3;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// `rkm = H(nk ‖ D ‖ d)` for one input — the `ROLE_ARKM` block, host side
/// (`l2::derive_input_l2` returns `nk`, `nf`, `cm`; the policy gadgets need
/// the intermediate).
pub fn derive_rkm_l2(inp: &L2TxInput) -> [u64; 4] {
    let (nk, _, _) = derive_input_l2(inp);
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&nk);
    st[4] = 1 << 1;
    st[5] = inp.d[0];
    st[6] = inp.d[1];
    st[7] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// 256-bit keys are four little-endian lanes (lane 3 most significant) —
/// the order the bit-serial comparison combines them in.
pub fn key_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for l in (0..4).rev() {
        if a[l] != b[l] {
            return a[l] < b[l];
        }
    }
    false
}

/// The indexed tree's "no successor" sentinel: `key_hi = 2^256 − 1`. Strict
/// `rkm < key_hi` then only excludes `rkm = MAX` (a hash output; negligible).
pub const KEY_MAX: [u64; 4] = [u64::MAX; 4];

/// A depth-20 authentication path (freeze tree and allowlist share the shape).
#[derive(Clone, Copy)]
pub struct PolicyWitness {
    pub siblings: [[u64; 4]; POLICY_DEPTH],
    pub path_bits: [bool; POLICY_DEPTH],
}

impl PolicyWitness {
    pub fn fold_root(&self, leaf: &[u64; 4]) -> [u64; 4] {
        let mut d = *leaf;
        for (sib, bit) in self.siblings.iter().zip(self.path_bits.iter()) {
            let st = if *bit {
                crate::reference::merkle_node_state(sib, &d)
            } else {
                crate::reference::merkle_node_state(&d, sib)
            };
            d = st[..4].try_into().unwrap();
        }
        d
    }
}

/// The real levels at the bottom of a fabricated policy tree: 2^3 = 8 leaf
/// slots hashed for real, 17 upper levels of shared pseudo-random siblings
/// (the house pattern of `narrow::fabricated_shared_tree` /
/// `l2::fabricated_registry_tree`, with a wider genuine subtree so a sorted
/// list of up to 7 frozen keys fits). Bench/self-test only.
pub const POLICY_SUB_LEVELS: usize = 3;

/// Fabricate a depth-20 policy tree over `leaves` (≤ 8; empty slots hold the
/// zero digest, which no leaf hash equals) and return every leaf's witness
/// and the root.
pub fn fabricated_policy_tree(leaves: &[[u64; 4]], seed: u64) -> (Vec<PolicyWitness>, [u64; 4]) {
    let slots = 1usize << POLICY_SUB_LEVELS;
    assert!(leaves.len() <= slots, "fabricated policy tree holds at most {slots} leaves");
    let mut x = seed | 1;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let upper: Vec<[u64; 4]> = (POLICY_SUB_LEVELS..POLICY_DEPTH)
        .map(|_| [rnd(), rnd(), rnd(), rnd()])
        .collect();
    // Levels of the genuine subtree: level 0 = the 8 leaf digests.
    let mut levels: Vec<Vec<[u64; 4]>> = Vec::new();
    let mut cur: Vec<[u64; 4]> = (0..slots)
        .map(|i| leaves.get(i).copied().unwrap_or([0; 4]))
        .collect();
    levels.push(cur.clone());
    while cur.len() > 1 {
        cur = cur
            .chunks(2)
            .map(|p| crate::reference::merkle_node_state(&p[0], &p[1])[..4].try_into().unwrap())
            .collect();
        levels.push(cur.clone());
    }
    let mut root = levels[POLICY_SUB_LEVELS][0];
    for sib in &upper {
        root = crate::reference::merkle_node_state(&root, sib)[..4].try_into().unwrap();
    }
    let witnesses = (0..leaves.len())
        .map(|i| {
            let mut siblings = [[0u64; 4]; POLICY_DEPTH];
            let mut path_bits = [false; POLICY_DEPTH];
            let mut pos = i;
            for (lvl, sibs) in siblings.iter_mut().enumerate().take(POLICY_SUB_LEVELS) {
                *sibs = levels[lvl][pos ^ 1];
                path_bits[lvl] = pos & 1 == 1;
                pos >>= 1;
            }
            for (lvl, sib) in upper.iter().enumerate() {
                siblings[POLICY_SUB_LEVELS + lvl] = *sib;
            }
            PolicyWitness { siblings, path_bits }
        })
        .collect();
    (witnesses, root)
}

/// One non-membership opening: the low leaf and its path.
#[derive(Clone, Copy)]
pub struct FreezeOpening {
    pub key_lo: [u64; 4],
    pub key_hi: [u64; 4],
    pub witness: PolicyWitness,
}

/// An issuer's freeze tree (l2-own-circuit-decision §3.2), indexed/sorted:
/// leaves `(k_i, k_{i+1})` over the sorted frozen keys with a `(0, k_1)` head
/// and a `(k_n, MAX)` tail; the empty tree is the single leaf `(0, MAX)`.
#[derive(Clone)]
pub struct FreezeTree {
    pub leaves: Vec<([u64; 4], [u64; 4])>,
    pub witnesses: Vec<PolicyWitness>,
    pub root: [u64; 4],
}

impl FreezeTree {
    pub fn new(frozen: &[[u64; 4]], seed: u64) -> Self {
        let mut keys: Vec<[u64; 4]> = frozen.to_vec();
        keys.sort_by(|a, b| {
            if key_lt(a, b) {
                core::cmp::Ordering::Less
            } else if a == b {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        });
        keys.dedup();
        assert!(!keys.contains(&[0; 4]) && !keys.contains(&KEY_MAX), "0 and MAX are the sentinels");
        let mut bounds = vec![[0u64; 4]];
        bounds.extend(keys.iter().copied());
        bounds.push(KEY_MAX);
        let leaves: Vec<([u64; 4], [u64; 4])> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
        let digests: Vec<[u64; 4]> = leaves.iter().map(|(lo, hi)| freeze_leaf_hash(lo, hi)).collect();
        let (witnesses, root) = fabricated_policy_tree(&digests, seed);
        Self { leaves, witnesses, root }
    }

    /// The empty tree — what a non-freeze asset's dummy path is over.
    pub fn empty() -> Self {
        Self::new(&[], 0x0f7e_e2e0_0000_0001)
    }

    /// The low leaf for `rkm`, or `None` when `rkm` is frozen (a key).
    pub fn opening_for(&self, rkm: &[u64; 4]) -> Option<FreezeOpening> {
        for (i, (lo, hi)) in self.leaves.iter().enumerate() {
            if key_lt(lo, rkm) && key_lt(rkm, hi) {
                return Some(FreezeOpening { key_lo: *lo, key_hi: *hi, witness: self.witnesses[i] });
            }
        }
        None
    }

    /// Leaf `i`'s opening regardless of `rkm` — for the negatives.
    pub fn opening_at(&self, i: usize) -> FreezeOpening {
        let (lo, hi) = self.leaves[i];
        FreezeOpening { key_lo: lo, key_hi: hi, witness: self.witnesses[i] }
    }
}

/// An issuer's allowlist (§3.4): a plain tree of credential commitments.
#[derive(Clone)]
pub struct AllowTree {
    pub creds: Vec<[u64; 4]>,
    pub witnesses: Vec<PolicyWitness>,
    pub root: [u64; 4],
}

impl AllowTree {
    pub fn new(creds: &[[u64; 4]], seed: u64) -> Self {
        let (witnesses, root) = fabricated_policy_tree(creds, seed);
        Self { creds: creds.to_vec(), witnesses, root }
    }

    pub fn witness_for(&self, cred: &[u64; 4]) -> Option<PolicyWitness> {
        self.creds.iter().position(|c| c == cred).map(|i| self.witnesses[i])
    }
}

/// The dummy allowlist path a non-Regulated input spends its trace on.
pub fn dummy_allow_witness() -> PolicyWitness {
    AllowTree::new(&[[0xd0, 0xd1, 0xd2, 0xd3]], 0xa110_0000_0000_0d0d).witnesses[0]
}

/// One asset as the registry and the prover see it: the leaf plus the trees
/// behind its roots. Bench/self-test fixture.
#[derive(Clone)]
pub struct PolicyAsset {
    pub asset: u64,
    pub mode: u64,
    pub redeem_open: bool,
    /// `None` = no issuer (Cloaked).
    pub isk: Option<[u64; 4]>,
    pub freeze: FreezeTree,
    pub allow: AllowTree,
}

impl PolicyAsset {
    /// A Cloaked asset — what shape S opens; carries the empty trees.
    pub fn cloaked(asset: u64) -> Self {
        Self {
            asset,
            mode: MODE_CLOAKED,
            redeem_open: false,
            isk: None,
            freeze: FreezeTree::empty(),
            allow: AllowTree::new(&[], 0xa110_0000_0000_0000 ^ asset),
        }
    }

    /// A Hybrid stablecoin: issuer, freeze tree over `frozen`.
    pub fn hybrid(asset: u64, isk: [u64; 4], redeem_open: bool, frozen: &[[u64; 4]]) -> Self {
        Self {
            asset,
            mode: MODE_HYBRID,
            redeem_open,
            isk: Some(isk),
            freeze: FreezeTree::new(frozen, 0xf7ee_0000_0000_0000 ^ asset),
            allow: AllowTree::new(&[], 0xa110_0000_0000_0000 ^ asset),
        }
    }

    /// A Regulated asset: Hybrid plus an allowlist over `allowed` (rkm values —
    /// the tree holds their credential commitments).
    pub fn regulated(
        asset: u64,
        isk: [u64; 4],
        redeem_open: bool,
        frozen: &[[u64; 4]],
        allowed_rkm: &[[u64; 4]],
    ) -> Self {
        let creds: Vec<[u64; 4]> = allowed_rkm.iter().map(cred_of).collect();
        Self {
            asset,
            mode: MODE_REGULATED,
            redeem_open,
            isk: Some(isk),
            freeze: FreezeTree::new(frozen, 0xf7ee_0000_0000_0000 ^ asset),
            allow: AllowTree::new(&creds, 0xa110_0000_0000_0000 ^ asset),
        }
    }

    pub fn leaf(&self) -> RegistryLeaf {
        RegistryLeaf {
            asset: self.asset,
            issuer_key: self.isk.map(|k| issuer_key_of(&k)).unwrap_or([0; 4]),
            mode: self.mode,
            freeze_root: if self.mode == MODE_CLOAKED { [0; 4] } else { self.freeze.root },
            allow_root: if self.mode == MODE_REGULATED { self.allow.root } else { [0; 4] },
            flags: if self.redeem_open { FLAG_REDEEM_OPEN } else { 0 },
        }
    }

    /// The honest policy inputs for a note with `rkm` in this asset. A frozen
    /// `rkm` has no opening — the caller's negative supplies one by hand.
    pub fn policy_input_for(&self, rkm: &[u64; 4], reg_witness: RegistryWitness) -> Option<L2PolicyInput> {
        let freeze = if self.mode == MODE_CLOAKED {
            FreezeTree::empty().opening_for(rkm)?
        } else {
            self.freeze.opening_for(rkm)?
        };
        let allow = if self.mode == MODE_REGULATED {
            self.allow.witness_for(&cred_of(rkm))?
        } else {
            dummy_allow_witness()
        };
        Some(L2PolicyInput {
            leaf: self.leaf(),
            reg_witness,
            freeze,
            allow,
            isk: self.isk.unwrap_or([0; 4]),
        })
    }
}

/// Everything shape P needs per input beyond the note itself.
#[derive(Clone, Copy)]
pub struct L2PolicyInput {
    pub leaf: RegistryLeaf,
    pub reg_witness: RegistryWitness,
    pub freeze: FreezeOpening,
    pub allow: PolicyWitness,
    /// The issuer secret when this row mints / redeems-closed; zeros otherwise.
    pub isk: [u64; 4],
}

/// Everything a prover/verifier pair needs for one shape-P instance.
pub struct L2PBucketInstance {
    pub air: L2ShapePAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub registry_root: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm_out: [[u64; 4]; 2],
}

/// Perm slots used by the shape-P program, INCLUDING the leading dummy
/// warm-up slot: 1 + 2 × 102 + 7 = **212**, at 3072 rows each = 651,264 rows
/// → 2^20 (1,048,576), 129 spare perm slots (62 % used).
pub const SHAPE_P_PERMS: usize = 1
    + 2 * (3 + 1 + 1 + 1 + FREEZE_DEPTH + 1 + REGISTRY_DEPTH + 1 + 1 + 1 + ALLOW_DEPTH + 1 + 1 + 1 + MERKLE_DEPTH + 1)
    + 2 * 2
    + 1
    + 2;
/// log2 of the shape-P trace height.
pub const SHAPE_P_LOG_HEIGHT: usize = 20;

/// Build shape P from caller-supplied commitment-tree witnesses + anchor, the
/// per-input policy openings, the registry root and the two `vPublic` terms.
/// Selectors are computed honestly from the assets; balance is NOT asserted.
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2p_with_witnesses(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    let (nk1, nf1, _cm1) = derive_input_l2(&inputs[0]);
    let (nk2, nf2, _cm2) = derive_input_l2(&inputs[1]);

    let out_rho = [derive_output_rho(&nf1, 0), derive_output_rho(&nf1, 1)];
    let cmo1 = l2_cm(outputs[0].value, outputs[0].asset, &outputs[0].rkm, &out_rho[0], &outputs[0].rseed);
    let cmo2 = l2_cm(outputs[1].value, outputs[1].asset, &outputs[1].rkm, &out_rho[1], &outputs[1].rseed);

    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![L2PSlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut input_chain = |inp: &L2TxInput,
                           nk: &[u64; 4],
                           witness: &MerkleWitness,
                           pol: &L2PolicyInput,
                           bnf_role: u32| {
        let arkm = |program: &mut [u32; PROGRAM_SLOTS], sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, role: u32| {
            program[*slot] = role;
            sw[*slot].w[..4].copy_from_slice(nk);
            sw[*slot].w[5] = inp.d[0];
            sw[*slot].w[6] = inp.d[1];
            *slot += 1;
        };
        let path = |program: &mut [u32; PROGRAM_SLOTS], sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, sibs: &[[u64; 4]], bits: &[bool]| {
            for (sib, bit) in sibs.iter().zip(bits.iter()) {
                program[*slot] = ROLE_MERKLE;
                sw[*slot].w[..4].copy_from_slice(sib);
                sw[*slot].pbit = *bit;
                *slot += 1;
            }
        };
        program[slot] = ROLE_ANK;
        sw[slot].w[..4].copy_from_slice(&inp.sk);
        slot += 1;
        program[slot] = ROLE_NF;
        sw[slot].w[..4].copy_from_slice(&inp.rho);
        slot += 1;
        program[slot] = bnf_role;
        slot += 1;
        program[slot] = ROLE_AISS;
        sw[slot].w[..4].copy_from_slice(&pol.isk);
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM);
        program[slot] = ROLE_AFRZ;
        sw[slot].w[..4].copy_from_slice(&pol.freeze.key_lo);
        sw[slot].w[5..9].copy_from_slice(&pol.freeze.key_hi);
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.freeze.witness.siblings, &pol.freeze.witness.path_bits);
        program[slot] = ROLE_AREG;
        sw[slot].w[..4].copy_from_slice(&pol.leaf.issuer_key);
        sw[slot].w[4] = pol.leaf.mode;
        sw[slot].w[5..9].copy_from_slice(&pol.leaf.freeze_root);
        sw[slot].w[9..13].copy_from_slice(&pol.leaf.allow_root);
        sw[slot].w[13] = pol.leaf.asset;
        sw[slot].w[14] = pol.leaf.flags;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.reg_witness.siblings, &pol.reg_witness.path_bits);
        program[slot] = ROLE_BREG;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM2);
        program[slot] = ROLE_ACRED;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.allow.siblings, &pol.allow.path_bits);
        program[slot] = ROLE_BALLOW;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM2);
        program[slot] = ROLE_ACM;
        sw[slot].w[4] = inp.value;
        sw[slot].w[5..9].copy_from_slice(&inp.rho);
        sw[slot].w[9..13].copy_from_slice(&inp.rseed);
        sw[slot].w[13] = inp.asset;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &witness.siblings, &witness.path_bits);
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    };
    input_chain(&inputs[0], &nk1, &witnesses[0], &policy[0], ROLE_BNF1);
    input_chain(&inputs[1], &nk2, &witnesses[1], &policy[1], ROLE_BNF2);
    for (j, (o, bcm)) in outputs.iter().zip([ROLE_BCM1, ROLE_BCM2]).enumerate() {
        if j == 1 {
            program[slot] = ROLE_ARHO;
            sw[slot].w[5..9].copy_from_slice(&nf1);
            slot += 1;
        }
        program[slot] = ROLE_ACMOUT;
        sw[slot].w[4] = o.value;
        sw[slot].w[..4].copy_from_slice(&o.rkm);
        sw[slot].w[5..9].copy_from_slice(&out_rho[j]);
        sw[slot].w[9..13].copy_from_slice(&o.rseed);
        sw[slot].w[13] = o.asset;
        slot += 1;
        program[slot] = bcm;
        slot += 1;
    }
    program[slot] = ROLE_BAL;
    slot += 1;
    program[slot] = ROLE_END;
    slot += 1;
    assert_eq!(slot, SHAPE_P_PERMS, "program layout drifted");

    let a1 = inputs[0].asset;
    let sel_o1a = outputs[0].asset == a1;
    let sel_o2a = outputs[1].asset == a1;
    let sel_f1 = a1 == 0;
    let sel_q = a1 == inputs[1].asset;
    let hy = [policy[0].leaf.mode == MODE_HYBRID, policy[1].leaf.mode == MODE_HYBRID];
    let rg = [policy[0].leaf.mode == MODE_REGULATED, policy[1].leaf.mode == MODE_REGULATED];
    let ropen = [
        policy[0].leaf.flags & FLAG_REDEEM_OPEN != 0,
        policy[1].leaf.flags & FLAG_REDEEM_OPEN != 0,
    ];
    let vpa = [
        if vp[0].amount != 0 { inputs[0].asset } else { 0 },
        if vp[1].amount != 0 { inputs[1].asset } else { 0 },
    ];
    let pvs = pv_vec_l2p(&anchor, &nf1, &nf2, &cmo1, &cmo2, fee, &registry_root, &vp, &vpa);
    L2PBucketInstance {
        air: L2ShapePAir {
            log_height,
            program,
            slot_witness: sw,
            fee,
            dv: false,
            sel_o1a,
            sel_o2a,
            sel_f1,
            sel_q,
            hy,
            rg,
            ropen,
            vp,
        },
        pvs,
        anchor,
        registry_root,
        nf: [nf1, nf2],
        cm_out: [cmo1, cmo2],
    }
}

/// Build shape P against **fabricated** trees: the commitment tree holds both
/// inputs at leaves 0/1, the registry holds the two assets' leaves, and each
/// input's policy openings come from its asset's trees. Panics if an input's
/// `rkm` is frozen or (Regulated) not allowlisted — the negatives build those
/// by hand through `build_bucket_l2p_with_witnesses`.
pub fn build_bucket_l2p(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    assets: &[PolicyAsset; 2],
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    let (_, _, cm1) = derive_input_l2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0]
            .policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0])
            .expect("input 0: rkm frozen or not allowlisted"),
        assets[1]
            .policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1])
            .expect("input 1: rkm frozen or not allowlisted"),
    ];
    build_bucket_l2p_with_witnesses(
        log_height, inputs, outputs, fee, &witnesses, anchor, &policy, registry_root, vp,
    )
}

/// Shape P with **input slot 1 a dummy** (#219 on L2): `dv = true`, the dummy
/// carries value 0 and asset 0 (Cloaked, the empty trees).
pub fn build_bucket_l2p_dummy1_fabricated(
    log_height: usize,
    real: &L2TxInput,
    real_asset: &PolicyAsset,
    dummy: &L2TxInput,
    outputs: &[L2TxOutput; 2],
    fee: u64,
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    assert_eq!(dummy.value, 0, "a dummy input slot contributes 0 to the balance");
    assert_eq!(dummy.asset, 0, "a dummy input slot carries asset 0 (#700)");
    let (_, _, cm_real) = derive_input_l2(real);
    let (w_real, anchor) = fabricated_single_tree(&cm_real);
    let assets = [real_asset.clone(), PolicyAsset::cloaked(0)];
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&derive_rkm_l2(real), rw[0]).expect("real input"),
        assets[1].policy_input_for(&derive_rkm_l2(dummy), rw[1]).expect("dummy input"),
    ];
    let mut inst = build_bucket_l2p_with_witnesses(
        log_height,
        &[real.clone(), dummy.clone()],
        outputs,
        fee,
        &[w_real, off_tree_witness()],
        anchor,
        &policy,
        registry_root,
        vp,
    );
    inst.air.dv = true;
    inst
}

// ---------------------------------------------------------------------------
// Trace generation — l2.rs's fill, mirrored constraint for constraint, plus
// the shape-P columns.
// ---------------------------------------------------------------------------

impl L2ShapePAir {
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * L2P_WIDTH;
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
        let wit = |p: usize| -> L2PSlotWitness {
            if self.slot_witness.is_empty() {
                L2PSlotWitness::default()
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);
        let mut eq = [0i64; 32];
        let mut ep: u32 = 1;
        let mut bq = [0i64; 16];
        let mut bl = [0i64; 4];
        let mut bl2 = [0i64; 4];
        let mut latch: u32 = 0;
        let dvv: u32 = self.dv as u32;
        let mut eq3 = [0i64; 16];
        let mut om: u32 = 0;
        let mut ac = [0i64; 6];
        let sel2: [u32; 4] = [
            self.sel_o1a as u32,
            self.sel_o2a as u32,
            self.sel_f1 as u32,
            self.sel_q as u32,
        ];
        let qinv: F = {
            let mut assets = self
                .program
                .iter()
                .enumerate()
                .filter(|(_, r)| **r == ROLE_ACM)
                .map(|(i, _)| (wit(i).w[13] & 0xffff) as u32);
            let a1 = assets.next().unwrap_or(0);
            let a2 = assets.next().unwrap_or(0);
            let d = F::from_u32(a1) - F::from_u32(a2);
            if self.sel_q || d == F::ZERO {
                F::ZERO
            } else {
                d.inverse()
            }
        };
        // Policy constants.
        let hy: [u32; 2] = [self.hy[0] as u32, self.hy[1] as u32];
        let rg: [u32; 2] = [self.rg[0] as u32, self.rg[1] as u32];
        let ropen: [u32; 2] = [self.ropen[0] as u32, self.ropen[1] as u32];
        let sum_m = |k: usize| -> u32 {
            (0..4).map(|j| ((self.vp[k].amount >> (16 * j)) & 0xffff) as u32).sum()
        };
        let nz: [u32; 2] = [(sum_m(0) != 0) as u32, (sum_m(1) != 0) as u32];
        let vpinv: [F; 2] = core::array::from_fn(|k| {
            let sm = F::from_u32(sum_m(k));
            if sm == F::ZERO {
                F::ZERO
            } else {
                sm.inverse()
            }
        });
        let sgn: [u32; 2] = [self.vp[0].redeem as u32, self.vp[1].redeem as u32];
        let req: [u32; 2] = core::array::from_fn(|k| nz[k] * (1 - sgn[k] * ropen[k]));
        // Running comparison flags [block][lane].
        let mut cmp_lt = [[0u32; 4]; 2];
        let mut cmp_eq = [[0u32; 4]; 2];

        let bit = |w: u32, i: usize| (w >> i) & 1;

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
            let z1 = (z == 1) as u32;
            let z63 = (z == 63) as u32;
            let eff: [u32; 25] = core::array::from_fn(|l| {
                if !bnd_now {
                    return a[l];
                }
                match role_now {
                    ROLE_MERKLE | ROLE_NF => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * a[l],
                        4..=7 => pbv * a[l - 4] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ANK => match l {
                        0..=3 => wbit[l],
                        4 => z0,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARKM | ROLE_ARKM2 => match l {
                        0..=3 => wbit[l],
                        4 => z1,
                        5 => wbit[5],
                        6 => wbit[6],
                        7 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARHO => match l {
                        0..=3 => wbit[l + 5],
                        4 => (z == 3) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACM | ROLE_ACMOUT => match l {
                        0 => wbit[4],
                        1 => wbit[13],
                        2..=5 => {
                            if role_now == ROLE_ACM {
                                a[l - 2]
                            } else {
                                wbit[l - 2]
                            }
                        }
                        6..=9 => wbit[l - 1],
                        10..=13 => wbit[l - 1],
                        14 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AREG => match l {
                        0 => wbit[13],
                        1..=4 => wbit[l - 1],
                        5 => wbit[4],
                        6..=9 => wbit[l - 1],
                        10..=13 => wbit[l - 1],
                        14 => wbit[14],
                        15 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AISS => match l {
                        0..=3 => wbit[l],
                        4 => (z == 7) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AFRZ => match l {
                        0..=3 => wbit[l],
                        4..=7 => wbit[l + 1],
                        8 => (z == 3) as u32,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACRED => match l {
                        0..=3 => a[l],
                        4 => (z == 15) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    _ => a[l],
                }
            });
            let g_e1pos = (bnd_now && role_now == ROLE_NF) as i64;
            let g_e1neg = (bnd_now && role_now == ROLE_ARKM) as i64;
            let g_e2pos = g_e1pos;
            let g_e2neg = (bnd_now && role_now == ROLE_ACM) as i64;
            let c: [u32; 5] = core::array::from_fn(|x| {
                eff[x] ^ eff[x + 5] ^ eff[x + 10] ^ eff[x + 15] ^ eff[x + 20]
            });
            let ap: [u32; 25] = core::array::from_fn(|l| {
                let x = l % 5;
                uv[l] ^ uu[(x + 4) % 5] ^ uu[5 + (x + 1) % 5]
            });

            // Comparison flags for this row (M rows only; T rows hold 0).
            if mrow {
                for blk in 0..2 {
                    for l in 0..4 {
                        let (x, y) = if blk == 0 { (wbit[l], a[l]) } else { (a[l], wbit[5 + l]) };
                        let same = 1 - x - y + 2 * x * y; // 1 iff x == y
                        let lt_bit = (1 - x) * y;
                        if z == 0 {
                            cmp_lt[blk][l] = lt_bit;
                            cmp_eq[blk][l] = same;
                        } else {
                            cmp_lt[blk][l] = lt_bit + same * cmp_lt[blk][l];
                            cmp_eq[blk][l] *= same;
                        }
                    }
                }
            } else {
                cmp_lt = [[0; 4]; 2];
                cmp_eq = [[0; 4]; 2];
            }

            let base = values.len();
            values.resize(base + L2P_WIDTH, F::ZERO);
            let row = &mut values[base..];
            for l in 0..25 {
                row[A_OFF + l] = F::from_u32(a[l]);
                row[US_OFF + l] = F::from_u32(us[l]);
                row[AP_OFF + l] = F::from_u32(ap[l]);
                row[UV_OFF + l] = F::from_u32(uv[l]);
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
            row[INJ_OFF] = F::from_u32(bndv * (selv[0] + selv[1]));
            row[INJ_OFF + 1] = F::from_u32(bndv * selv[2]);
            row[INJ_OFF + 2] = F::from_u32(bndv * (selv[3] + selv[SEL_ARKM2]));
            row[INJ_OFF + 3] = F::from_u32(bndv * selv[4]);
            row[INJ_OFF + 4] = F::from_u32(bndv * selv[5]);
            row[INJ_OFF + 5] = F::from_u32(bndv * selv[SEL_ARHO]);
            row[INJ_OFF + 6] = F::from_u32(bndv * selv[SEL_AREG]);
            row[INJ_OFF + INJ_AISS] = F::from_u32(bndv * selv[SEL_AISS]);
            row[INJ_OFF + INJ_AFRZ] = F::from_u32(bndv * selv[SEL_AFRZ]);
            row[INJ_OFF + INJ_ACRED] = F::from_u32(bndv * selv[SEL_ACRED]);
            let g4 = ((t % 128 == 127) as u32) * pb[1] * ph[1];
            row[G4_COL] = F::from_u32(g4);
            let gpermv = ((t % 128 == 127) as u32) * pb[1];
            let bindsum = selv[6] + selv[7] + selv[8] + selv[9] + selv[10] + selv[SEL_BREG];
            let mut se = [0u32; NSE];
            se[..6].copy_from_slice(&[
                selv[1] * ep,
                selv[3] * ep,
                selv[4] * ep,
                selv[5] * ep,
                bindsum * ep,
                selv[11] * ep,
            ]);
            se[SE_RHO] = (selv[SEL_ARHO] + selv[5]) * ep;
            se[SE_AREG] = selv[SEL_AREG] * ep;
            for (i, vv) in se.iter().enumerate() {
                row[SE_OFF + i] = F::from_u32(*vv);
            }
            row[EP_COL] = F::from_u32(ep);
            let gwrap = gpermv * selv[12];
            row[GWRAP_COL] = F::from_u32(gwrap);
            let eg1 = bndv * se[1];
            row[EG_OFF] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 1] = F::from_u32(eg1);
            row[EG_OFF + 2] = F::from_u32(gpermv * se[1]);
            row[EG_OFF + 3] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 4] = F::from_u32(bndv * se[2]);
            row[EG_OFF + 5] = F::from_u32(gpermv * se[2]);
            let bgcap = bndv * se[4];
            let bgrst = gpermv * se[4];
            row[BGCAP_COL] = F::from_u32(bgcap);
            row[BGRST_COL] = F::from_u32(bgrst);
            for (i, si) in [6usize, 7, 8, 9, 10, SEL_BREG].iter().enumerate() {
                row[BGC_OFF + i] = F::from_u32(gpermv * selv[*si]);
            }
            let (bgc_banchor, bgc_bnf2) = (gpermv * selv[6], gpermv * selv[8]);
            row[LATCH_COL] = F::from_u32(latch);
            row[DV_COL] = F::from_u32(dvv);
            row[LDV_COL] = F::from_u32(latch * dvv);
            let (g3pos, g3neg, g3close) = (
                bndv * se[SE_RHO],
                bndv * se[3] * om,
                gpermv * se[SE_RHO],
            );
            row[OM_COL] = F::from_u32(om);
            row[EG3_OFF] = F::from_u32(g3pos);
            row[EG3_OFF + 1] = F::from_u32(g3neg);
            row[EG3_OFF + 2] = F::from_u32(g3close);
            let inj3e = bndv * se[2];
            let inj4e = bndv * se[3];
            let injre = bndv * se[SE_AREG];
            row[INJ3E_COL] = F::from_u32(inj3e);
            row[INJ4E_COL] = F::from_u32(inj4e);
            row[INJRE_COL] = F::from_u32(injre);
            row[BLCLOSE_COL] = F::from_u32(gpermv * se[5]);
            let ag: [u32; 6] = [
                inj3e * (1 - latch),
                inj3e * latch,
                inj4e * (1 - om),
                inj4e * om,
                injre * (1 - latch),
                injre * latch,
            ];
            for (k, vv) in ag.iter().enumerate() {
                row[AG_OFF + k] = F::from_u32(*vv);
            }
            let sg: [u32; 2] = [ag[AG_O1] * sel2[S2_O1A], ag[AG_O2] * sel2[S2_O2A]];
            row[SG_OFF] = F::from_u32(sg[0]);
            row[SG_OFF + 1] = F::from_u32(sg[1]);
            for (k, vv) in sel2.iter().enumerate() {
                row[SEL2_OFF + k] = F::from_u32(*vv);
            }
            row[QINV_COL] = qinv;
            let closev = gpermv * se[5];
            row[CQ_OFF] = F::from_u32(closev * sel2[S2_Q]);
            row[CQ_OFF + 1] = F::from_u32(closev * (1 - sel2[S2_Q]));
            // Shape-P gates and constants.
            let inj_afrze = bndv * selv[SEL_AFRZ] * ep;
            let inj_acrede = bndv * selv[SEL_ACRED] * ep;
            let close_cred = gpermv * selv[SEL_ACRED] * ep;
            let egb = bndv * selv[SEL_BALLOW] * ep;
            let egbc = gpermv * selv[SEL_BALLOW] * ep;
            let arege = gpermv * se[SE_AREG];
            let rq = req[0] + latch * (req[1] + 4 - req[0]) - latch * 4; // req[0] + latch·(req[1] − req[0]) without underflow
            let alw = rg[0] + latch * (rg[1] + 4 - rg[0]) - latch * 4;
            let crq = arege * rq;
            row[INJ_AFRZE_COL] = F::from_u32(inj_afrze);
            row[INJ_ACREDE_COL] = F::from_u32(inj_acrede);
            row[CLOSE_CRED_COL] = F::from_u32(close_cred);
            row[EGB_COL] = F::from_u32(egb);
            row[EGBC_COL] = F::from_u32(egbc);
            row[AREGE_COL] = F::from_u32(arege);
            row[CRQ_COL] = F::from_u32(crq);
            for blk in 0..2 {
                for l in 0..4 {
                    row[CMP_OFF + CMP_BLOCK * blk + CMP_LT + l] = F::from_u32(cmp_lt[blk][l]);
                    row[CMP_OFF + CMP_BLOCK * blk + CMP_EQ + l] = F::from_u32(cmp_eq[blk][l]);
                }
                let c1 = cmp_lt[blk][1] + cmp_eq[blk][1] * cmp_lt[blk][0];
                let c2 = cmp_lt[blk][2] + cmp_eq[blk][2] * c1;
                let c3 = cmp_lt[blk][3] + cmp_eq[blk][3] * c2;
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C] = F::from_u32(c1);
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C + 1] = F::from_u32(c2);
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C + 2] = F::from_u32(c3);
            }
            for k in 0..2 {
                row[POL_OFF + POL_HY + k] = F::from_u32(hy[k]);
                row[POL_OFF + POL_RG + k] = F::from_u32(rg[k]);
                row[POL_OFF + POL_ROPEN + k] = F::from_u32(ropen[k]);
                row[POL_OFF + POL_NZ + k] = F::from_u32(nz[k]);
                row[POL_OFF + POL_VPINV + k] = vpinv[k];
                row[POL_OFF + POL_REQ + k] = F::from_u32(req[k]);
            }
            row[POL_OFF + POL_RQ] = F::from_u32(rq);
            row[POL_OFF + POL_ALW] = F::from_u32(alw);
            let sgnf = |vv: i64| -> F {
                if vv >= 0 {
                    F::from_u32(vv as u32)
                } else {
                    -F::from_u32((-vv) as u32)
                }
            };
            for (i, acc) in bq.iter().enumerate() {
                row[BQ_OFF + i] = sgnf(*acc);
            }
            for (j, acc) in bl.iter().enumerate() {
                row[BL_OFF + j] = sgnf(*acc);
            }
            for (j, acc) in bl2.iter().enumerate() {
                row[BL2_OFF + j] = sgnf(*acc);
            }
            for (k, acc) in ac.iter().enumerate() {
                row[AC_OFF + k] = sgnf(*acc);
            }
            // Carry encodings (offset −3). Each chain owes `fee_row − (1 − 2s)·m`
            // per chunk: under ¬q row 1 carries vPublic₁ and f1·fee, row 2
            // vPublic₂ and (1 − f1)·fee; under q the summed chain carries
            // vPublic₁ and the whole fee on row 1's block.
            {
                let chunk = |x: u64, j: usize| ((x >> (16 * j)) & 0xffff) as i64;
                let signed_m = |k: usize, j: usize| -> i64 {
                    let m = chunk(self.vp[k].amount, j);
                    if self.vp[k].redeem {
                        -m
                    } else {
                        m
                    }
                };
                let (fee1, chain1): (u64, [i64; 4]) = if self.sel_q {
                    (self.fee, core::array::from_fn(|j| bl[j] + bl2[j]))
                } else if self.sel_f1 {
                    (self.fee, bl)
                } else {
                    (0, bl)
                };
                let fee2 = if self.sel_f1 { 0 } else { self.fee };
                for (accs, off, rf, k) in [(chain1, BLC_OFF, fee1, 0usize), (bl2, BLC2_OFF, fee2, 1)] {
                    let mut cc = [0i64; 3];
                    let mut prev = 0i64;
                    for j in 0..3 {
                        let tj = accs[j] + prev - chunk(rf, j) + signed_m(k, j);
                        cc[j] = tj >> 16;
                        prev = cc[j];
                    }
                    for (j, cj) in cc.iter().enumerate() {
                        let enc = (cj + 3).clamp(0, 7) as u32;
                        for bb in 0..3 {
                            row[off + 3 * j + bb] = F::from_u32((enc >> bb) & 1);
                        }
                    }
                }
            }
            row[PBIT_COL] = F::from_u32(pbv);
            for i in 0..NW {
                row[W_OFF + i] = F::from_u32(wbit[i]);
            }
            for (i, acc) in eq.iter().enumerate() {
                row[EQ_OFF + i] = sgnf(*acc);
            }
            for (i, acc) in eq3.iter().enumerate() {
                row[EQ3_OFF + i] = sgnf(*acc);
            }
            for l in 0..25 {
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            // Advance the accumulators.
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let epi = ep as i64;
                let alwi = alw as i64;
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq[idx] += epi
                        * (g_e1pos * wgt * a[l] as i64 - g_e1neg * wgt * wbit[l] as i64)
                        + (egb as i64) * alwi * wgt * a[l] as i64
                        - (injre as i64) * alwi * wgt * wbit[9 + l] as i64;
                    eq[16 + idx] += epi
                        * (g_e2pos * wgt * wbit[l] as i64
                            - g_e2neg * wgt * wbit[5 + l] as i64);
                    bq[idx] += (bgcap as i64) * wgt * a[l] as i64
                        + (eg1 as i64) * wgt * a[l] as i64
                        - (injre as i64) * wgt * wbit[l] as i64
                        + (inj_acrede as i64) * wgt * a[l] as i64
                        - (inj3e as i64) * wgt * a[l] as i64;
                }
                let vb = wbit[4] as i64;
                bl[jc] += (ag[AG_IN1] as i64) * wgt * vb
                    - (sg[0] as i64) * wgt * vb
                    - (sg[1] as i64) * wgt * vb;
                bl2[jc] += (ag[AG_IN2] as i64) * wgt * vb
                    - ((ag[AG_O1] - sg[0]) as i64) * wgt * vb
                    - ((ag[AG_O2] - sg[1]) as i64) * wgt * vb;
                if jc == 0 {
                    for k in 0..6 {
                        ac[k] += (ag[k] as i64) * wgt * wbit[13] as i64;
                    }
                }
                if bgrst == 1 || arege == 1 {
                    bq = [0i64; 16];
                }
                if g3close == 1 || close_cred == 1 {
                    eq3 = [0i64; 16];
                }
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq3[idx] += g3pos as i64 * wgt * wbit[5 + l] as i64
                        - g3neg as i64 * wgt * a[l] as i64
                        + inj_afrze as i64 * wgt * a[l] as i64
                        - inj_acrede as i64 * wgt * a[l] as i64;
                }
                om = om * (1 - gpermv * selv[10]) + g3close * selv[SEL_ARHO];
                ep *= 1 - gwrap;
                latch = latch * (1 - bgc_banchor) + bgc_bnf2;
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

        RowMajorMatrix::new(values, L2P_WIDTH)
    }

    /// The state materialized at block `q` (the round-q input).
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * L2P_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}
