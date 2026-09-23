//! W3 — the L2 transaction circuit family, **shape S** (sovereign assets).
//!
//! Design source: `qumbra-design/l2-own-circuit-decision.md` §2–§3 (DECIDED
//! 2026-09-22). Lab task book: issue #700. This module is a **new AIR type
//! beside [`crate::narrow::NarrowKeccakAir`]**, never an edit to it — the
//! frozen L1 circuit and its six locks do not move (the one law of #700).
//!
//! It is deliberately a *fork* of `narrow.rs`'s pipeline (the 371-column
//! Keccak-f[1600] engine, the M3 program machinery, the banks, the #219 latch
//! and the #215 option-4 derivation are reproduced here verbatim in structure)
//! rather than a shared abstraction: extracting the column-offset chain /
//! `SlotWitness` / `SEL_CODES` pattern into something both circuits import is
//! a lock-touching refactor and a stage boundary under #700, and this baton did
//! not take it. Pure helpers that `narrow.rs` already exports and whose
//! semantics are identical here — [`crate::narrow::MerkleWitness`],
//! [`crate::narrow::derive_output_rho`], [`crate::narrow::pv_chunks`], the
//! fabricated-tree helpers — are imported, not copied.
//!
//! ## The statement, in the terms of `narrow.rs`
//!
//! **L2 note** = `(value u64, asset u64, rkm, ρ, rseed)` = 112 B, one Keccak
//! block: `st[0]=value, st[1]=asset, st[2..6]=rkm, st[6..10]=ρ,
//! st[10..14]=rseed, pad st[14]=1, st[16]=1≪63`. `asset 0` is the fee asset.
//!
//! **Shape S** = the 84-perm L1 program with the note block carrying `asset`,
//! plus per input a **registry opening** (`ROLE_AREG` + 16 × `ROLE_MERKLE` +
//! `ROLE_BREG`, bound to the new public value `PV_REGROOT`), a **two-asset
//! balance** on two 16-bit-limb borrow chains, and `mode = Cloaked` read off
//! the registry leaf. 120 perms → 2^19 rows.
//!
//! ### Program order (per input `k`, then outputs, then close)
//!
//! ```text
//! [DUMMY]
//! ANK → NF → BNF_k → AREG → 16×MERKLE → BREG → ARKM → ACM → 32×MERKLE → BANCHOR   (×2)
//! ACMOUT_0 → BCM1 → ARHO → ACMOUT_1 → BCM2 → BAL → END
//! ```
//!
//! The registry chain sits **inside** input `k`'s chain, between `BNF_k` and
//! `ARKM`. Both `AREG` (a full-state override) and `ARKM` (also a full-state
//! override) sever the Keccak chain, so inserting the registry opening there
//! changes nothing the two equality banks read: bank 1 (nk) accumulates
//! `+a[0..4]` at `NF` and `−W0..3` at `ARKM`, bank 2 (ρ) `+W0..3` at `NF` and
//! `−W5..8` at `ACM`; the 18 registry perms in between fire neither gate. The
//! placement buys one thing: the #219 latch `L` — program-driven, high across
//! exactly chain 1's `BNF2`-close → `BANCHOR`-close span — now covers chain
//! 1's `AREG` too, so `L` alone tells the two inputs' `ACM`s AND the two
//! registry openings apart. No new marker column.
//!
//! ### Two-asset balance (l2-own-circuit-decision §2.2, as built)
//!
//! Two balance rows. Row 1 is *input 1's asset* `A₁`, row 2 is `A₂`. Four
//! prover-chosen selector bits, constant for the whole trace like `dv`:
//!
//! - `o1a`, `o2a` — output `j` is accounted in row 1 (`=1`) or row 2 (`=0`);
//! - `f1` — the fee is charged to row 1 (`=1`) or row 2 (`=0`);
//! - `q` — the two inputs carry the same asset.
//!
//! Bound at `BAL`'s close row against the captured 16-bit asset ids:
//! `o_ja ⇒ O_j = A₁`, `¬o_ja ⇒ O_j = A₂`, `f1 ⇒ A₁ = 0`, `¬f1 ⇒ A₂ = 0`, and
//! `q` both ways — `q ⇒ A₁ = A₂`, `¬q ⇒ A₁ ≠ A₂` via one nonzero-inverse
//! witness (`qinv · (A₁ − A₂) = 1`; asset ids are one field element, so one
//! inverse suffices). When `¬q` each row closes on its own borrow chain; when
//! `q` the two rows are **summed** and close once against the whole fee.
//! Every output is in exactly one row and the fee in exactly one, so for any
//! asset `X`: `Σ_{A_k=X} v_k = Σ_{O_j=X} O_j + [X=0]·fee` — per-asset
//! conservation for every `X`, an output asset outside `{A₁,A₂}` is
//! unassignable, and "≥ 1 asset-0 input" is implied by the fee assignment. The
//! sum under `q` is what keeps this *complete*: with `A₁ = A₂` an honest spend
//! (60 + 40 = 70 + 25 + 5) has no per-row partition, only a per-asset one.
//! Recorded as a stage-0 position in `docs/w3-build-notes.md`.
//!
//! **Asset ids are 16-bit registry indices** (registry depth 16, §2.4): the
//! note lane is `u64` on the wire, and the circuit forces bits 16..63 of every
//! absorbed asset lane to zero (`ACM`, `ACMOUT`, `AREG`), so one field element
//! per note carries the whole id and the six bindings above are same-row.
//!
//! ### Column accounting over `NARROW_WIDTH = 643` (+59 → 702) — see
//! `l2_trace_width_is_read_off_the_matrix`, every column named.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::narrow::{
    derive_output_rho, fabricated_shared_tree, fabricated_single_tree, off_tree_witness,
    pv_chunks, MerkleWitness, MERKLE_DEPTH,
};
use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — the narrow engine verbatim, then the M3 machinery widened for
// 5-bit role codes and 15 witness lanes, then the L2 additions.
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
// --- M3 program machinery, widened: 5-bit role codes, 32-limb ring ---
const PB_OFF: usize = B_OFF + 7; // 402: 24: perm-boundary ring [1,0,..,0]
const PH_OFF: usize = PB_OFF + 24; // 426: 4: perm-phase ring (mod-4 counter)
/// Program-ring limbs. 4 slots × 5 bits = 20 bits per limb; 32 limbs = 128
/// program slots (shape S uses 120). `narrow.rs` has 24 limbs × 4 slots × 4
/// bits — 15 role codes fit 4 bits, and shape S's 17 do not.
const PR_LIMBS: usize = 32;
const PR_OFF: usize = PH_OFF + 4; // 430: 32: program ring, 4 slots x 5 bits/limb
/// Role-code width in bits.
const ROLE_BITS: usize = 5;
const D_OFF: usize = PR_OFF + PR_LIMBS; // 462: 20: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 4 * ROLE_BITS; // 482: 5: current perm's role bits
/// The four materialized low half-selectors `pair(r0, r1, j)`, so a 5-bit
/// selector `lo · pair(r2, r3) · bit(r4)` stays at degree 4 — the ceiling the
/// 13 L1 selectors already set. Without them the selector would be degree 5.
const LO_OFF: usize = RB_OFF + ROLE_BITS; // 487: 4
const NSEL: usize = 16; // materialized role selectors, order = SEL_CODES
const SEL_OFF: usize = LO_OFF + 4; // 491
const NINJ: usize = 7; // injection flags [mrk+nf, ank, arkm, acm, acmout, arho, areg]
const INJ_OFF: usize = SEL_OFF + NSEL; // 507
const G4_COL: usize = INJ_OFF + NINJ; // 514: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 515: merkle path bit (constant per perm)
/// Witness lanes: the L1's 13 plus `W13 = asset` and `W14 = flags`.
const NW: usize = 15;
const W_OFF: usize = PBIT_COL + 1; // 516: 15 witness lanes (role-multiplexed)
const EQ_OFF: usize = W_OFF + NW; // 531: 32: two equality banks, 4 lanes x 4 chunks
const EG_OFF: usize = EQ_OFF + 32; // 563: 6: eq gates
const EP_COL: usize = EG_OFF + 6; // 569: epoch flag
const GWRAP_COL: usize = EP_COL + 1; // 570: epoch-kill gate (gperm * sel_end)
/// 8 ep-gated selectors [nf, arkm, acm, acmout, bindsum, bal, arho+acmout, areg].
const NSE: usize = 8;
const SE_OFF: usize = GWRAP_COL + 1; // 571
const SE_RHO: usize = 6;
const SE_AREG: usize = 7;
const BQ_OFF: usize = SE_OFF + NSE; // 579: 16: bind bank
const BGCAP_COL: usize = BQ_OFF + 16; // 595: bind capture gate
const BGRST_COL: usize = BGCAP_COL + 1; // 596: bind reset gate
/// 6 bind close gates [banchor, bnf1, bnf2, bcm1, bcm2, breg].
const NBGC: usize = 6;
const BGC_OFF: usize = BGRST_COL + 1; // 597
const BL_OFF: usize = BGC_OFF + NBGC; // 603: 4: balance row 1 accumulators
const BLC_OFF: usize = BL_OFF + 4; // 607: 9: row-1 carry encodings
const BLCLOSE_COL: usize = BLC_OFF + 9; // 616: balance close gate
const INJ3E_COL: usize = BLCLOSE_COL + 1; // 617: inj(acm) * ep
const INJ4E_COL: usize = INJ3E_COL + 1; // 618: inj(acmout) * ep
const EFF_OFF: usize = INJ4E_COL + 1; // 619: 25: effective round input
const LATCH_COL: usize = EFF_OFF + 25; // 644: the #219 latch L
const DV_COL: usize = LATCH_COL + 1; // 645: dv
const LDV_COL: usize = DV_COL + 1; // 646: L·dv
const OM_COL: usize = LDV_COL + 1; // 647: the #215 output-1 span marker
const EQ3_OFF: usize = OM_COL + 1; // 648: 16: the third bank
const EG3_OFF: usize = EQ3_OFF + 16; // 664: 3: [pos, neg, close]
// --- L2 additions ---
/// `inj(areg) · ep` — materialized like `INJ3E`/`INJ4E`.
const INJRE_COL: usize = EG3_OFF + 3; // 667
/// Six materialized capture gates [in1, in2, o1, o2, r1, r2]:
/// `INJ3E·(1−L)`, `INJ3E·L`, `INJ4E·(1−M)`, `INJ4E·M`, `INJRE·(1−L)`, `INJRE·L`.
const AG_OFF: usize = INJRE_COL + 1; // 668
const AG_IN1: usize = 0;
const AG_IN2: usize = 1;
const AG_O1: usize = 2;
const AG_O2: usize = 3;
const AG_R1: usize = 4;
const AG_R2: usize = 5;
/// Six capture-and-hold asset accumulators (16-bit chunk 0 of `W13`), same
/// order as the gates: `A₁, A₂, O₁, O₂, R₁, R₂`.
const AC_OFF: usize = AG_OFF + 6; // 674
/// The four balance selectors [o1a, o2a, f1, q] — bool, constant for the trace.
const SEL2_OFF: usize = AC_OFF + 6; // 680
const S2_O1A: usize = 0;
const S2_O2A: usize = 1;
const S2_F1: usize = 2;
const S2_Q: usize = 3;
/// `qinv` — the nonzero-inverse witness for `¬q ⇒ A₁ ≠ A₂`; constant.
const QINV_COL: usize = SEL2_OFF + 4; // 684
/// `close·q`, `close·(1 − q)` — materialized so the gated chains stay degree 3.
const CQ_OFF: usize = QINV_COL + 1; // 685
/// `AG[o1]·o1a`, `AG[o2]·o2a` — materialized so the row legs stay degree 3.
const SG_OFF: usize = CQ_OFF + 2; // 687
const BL2_OFF: usize = SG_OFF + 2; // 689: 4: balance row 2 accumulators
const BLC2_OFF: usize = BL2_OFF + 4; // 693: 9: row-2 carry encodings

/// The shape-S trace width.
pub const L2_WIDTH: usize = BLC2_OFF + 9; // 702

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 4 * PR_LIMBS; // 128

// Role codes. 0..=14 are `narrow.rs`'s, kept identical so a reader of one file
// reads the other; 15 and 16 are shape S's. 5-bit codes leave 17..=31 for
// shape P (stage 2).
pub const ROLE_DUMMY: u32 = 0;
pub const ROLE_MERKLE: u32 = 1;
pub const ROLE_NF: u32 = 2;
pub const ROLE_ANK: u32 = 3;
pub const ROLE_ARKM: u32 = 4;
/// L2 `cm = H(value ‖ asset ‖ rkm ‖ rho ‖ rseed)`: value = W4, asset = W13,
/// rkm = chained digest a[0..4] at lanes 2..6, rho = W5..9 (bank 2), rseed =
/// W9..13, pad at bit 896 (lane 14 z0).
pub const ROLE_ACM: u32 = 5;
/// Output cm' with the same lane layout, rkm' = W0..4 (all witness).
pub const ROLE_ACMOUT: u32 = 6;
pub const ROLE_BANCHOR: u32 = 7;
pub const ROLE_BNF1: u32 = 8;
pub const ROLE_BNF2: u32 = 9;
pub const ROLE_BCM1: u32 = 10;
pub const ROLE_BCM2: u32 = 11;
pub const ROLE_BAL: u32 = 12;
pub const ROLE_END: u32 = 13;
pub const ROLE_ARHO: u32 = 14;
/// Registry leaf opening: `leaf = H(asset ‖ issuer_key ‖ mode ‖ freeze_root ‖
/// allow_root ‖ flags)` as a full-state override — asset = W13 at lane 0,
/// issuer_key = W0..4 at lanes 1..5, mode = W4 at lane 5, freeze_root = W5..9
/// at lanes 6..10, allow_root = W9..13 at lanes 10..14, flags = W14 at lane 14,
/// pad10*1 from bit 960 (lane 15 z0) and at bit 1087. 120 B, one block.
pub const ROLE_AREG: u32 = 15;
/// Registry-root bind: no injection; the bind bank captures `a[0..4]` (the
/// depth-16 fold's root) on its boundary rows and closes against `PV_REGROOT`.
pub const ROLE_BREG: u32 = 16;

/// Role codes in materialized-selector order. One list, read by both the AIR
/// and the trace generator.
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
];
const SEL_ARHO: usize = 13;
const SEL_AREG: usize = 14;
const SEL_BREG: usize = 15;

/// Registry leaf `mode` values (l2-own-circuit-decision §3.6).
pub const MODE_CLOAKED: u64 = 0;
pub const MODE_HYBRID: u64 = 1;
pub const MODE_REGULATED: u64 = 2;

/// Public-value layout: the L1's 84 (anchor, nf1, nf2, cm1, cm2 as 16 chunks
/// each, fee as 4) followed by `registry_root` as 16 chunks.
pub const PV_ANCHOR: usize = 0;
pub const PV_NF1: usize = 16;
pub const PV_NF2: usize = 32;
pub const PV_CM1: usize = 48;
pub const PV_CM2: usize = 64;
pub const PV_FEE: usize = 80;
pub const PV_REGROOT: usize = 84;
pub const PV_LEN: usize = 100;

/// Build the full public-value vector for a shape-S instance.
pub fn pv_vec_l2(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm1: &[u64; 4],
    cm2: &[u64; 4],
    fee: u64,
    registry_root: &[u64; 4],
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, nf1, nf2, cm1, cm2] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    out.extend_from_slice(&pv_chunks(registry_root));
    debug_assert_eq!(out.len(), PV_LEN);
    out
}

/// Rows per 24-round permutation: 24 rounds x 128 rows.
pub const ROWS_PER_PERM: usize = 24 * 128;

/// Registry tree depth (l2-own-circuit-decision §2.4; an L2 parameter, W3's
/// value).
pub const REGISTRY_DEPTH: usize = 16;
/// Asset ids are registry indices: `< 2^REGISTRY_DEPTH`. The circuit forces
/// bits 16..63 of every absorbed asset lane to zero.
pub const ASSET_BITS: usize = 16;

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
pub struct L2SlotWitness {
    pub w: [u64; NW],
    pub pbit: bool,
}

impl Default for L2SlotWitness {
    fn default() -> Self {
        Self { w: [0; NW], pbit: false }
    }
}

/// Shape S of the L2 circuit family.
#[cfg_attr(test, derive(Clone))] // the test fan-out needs owned copies; non-test build unchanged
pub struct L2ShapeSAir {
    pub log_height: usize,
    /// 5-bit role code per program slot (period 128 perms).
    pub program: [u32; PROGRAM_SLOTS],
    pub slot_witness: Vec<L2SlotWitness>,
    /// Public fee (needed to witness the balance carry encodings).
    pub fee: u64,
    /// The #219 liveness bool: `true` declares input slot 1 a dummy (anchor
    /// bind relaxed, Merkle fold unconstrained, value AND asset forced to 0).
    pub dv: bool,
    /// Balance selectors (witness, not constraint constants): output 0 / 1 is
    /// accounted in row 1 (`true`) or row 2 (`false`); the fee is charged to
    /// row 1 (`true`) or row 2 (`false`). Bound in-circuit to the assets.
    pub sel_o1a: bool,
    pub sel_o2a: bool,
    pub sel_f1: bool,
    /// `q` — the two inputs carry the same asset (bound both ways in-circuit).
    pub sel_q: bool,
}

impl L2ShapeSAir {
    /// Every perm slot dummy, pure chaining — the geometry probe.
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

/// Number of periodic columns: the narrow engine's 39 plus `lo16`.
const NPERIODIC: usize = 40;
/// Periodic index of `lo16 = [z < 16]` (1 on rows whose z-slice is below 16,
/// on both M and T rows).
const PER_LO16: usize = 39;

impl<F: Field> BaseAir<F> for L2ShapeSAir {
    fn width(&self) -> usize {
        L2_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PV_LEN
    }

    fn num_periodic_columns(&self) -> usize {
        NPERIODIC
    }

    /// The narrow engine's 39 period-128 columns ([mrow, u63, e1_0..e1_24,
    /// blast, sel_0..sel_6, pwk_0..pwk_3]) plus `lo16`.
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

impl<AB: AirBuilder> Air<AB> for L2ShapeSAir
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

        // --- Program machinery ---
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
        // PR[0] = 20 bool bits (4 slots x 5 bits).
        for k in 0..4 * ROLE_BITS {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 4 * ROLE_BITS, &local), local[PR_OFF].clone());
        // Active role bits: phase phi of perm p is p mod 4; the left-rotating
        // phase ring exposes phi via ph[(4 - phi) % 4].
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
        // The four low half-selectors, materialized (degree 2).
        for j in 0..4u32 {
            builder.assert_eq(local[LO_OFF + j as usize].clone(), pair(r(0), r(1), j));
        }
        // Role selectors: lo (col) · pair(r2, r3) · bit(r4) — degree 4.
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
        for i in 1..5 {
            builder.assert_eq(
                local[INJ_OFF + i].clone(),
                bnd.clone() * sel_role(i + 1),
            );
        }
        builder.assert_eq(
            local[INJ_OFF + 5].clone(),
            bnd.clone() * sel_role(SEL_ARHO),
        );
        // Shape S: ROLE_AREG is its own injection class (full-state override).
        builder.assert_eq(
            local[INJ_OFF + 6].clone(),
            bnd.clone() * sel_role(SEL_AREG),
        );
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
            // L2 note block: value W4 | asset W13 | rkm = chained digest
            // a[0..4] at lanes 2..6 | rho = W5..9 at lanes 6..10 | rseed =
            // W9..13 at lanes 10..14 | pad10*1 from bit 896 (lane 14 z0).
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
            // Registry leaf: asset W13 | issuer_key W0..4 | mode W4 |
            // freeze_root W5..9 | allow_root W9..13 | flags W14 | pad from
            // bit 960 (lane 15 z0).
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
            let expr = a(l)
                + inj(0) * (msg_mrk - a(l))
                + inj(1) * (msg_ank - a(l))
                + inj(2) * (msg_arkm - a(l))
                + inj(3) * (msg_acm - a(l))
                + inj(4) * (msg_acmout - a(l))
                + inj(5) * (msg_arho - a(l))
                + inj(6) * (msg_areg - a(l));
            builder.assert_eq(eff(l), expr);
        }

        // --- Equality banks 1 and 2 (verbatim) ---
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
        // Shape S: BREG joins the bind roles.
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
                // #219: `L·dv` relaxes the ANCHOR close and nothing else — the
                // registry bind of a dummy slot still fires (it opens asset 0's
                // leaf, which is pinned at genesis).
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

        // --- The third bank (#215 option 4, verbatim) ---
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

        // --- Balance gates (row 1 = L1's, row 2 = shape S's) ---
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
        // Six materialized capture gates.
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
        // The four selectors: bool; constant (transition below); the two
        // selector-gates and the two q-gated closes materialized.
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
        // Asset ids are 16-bit registry indices: bits 16..63 of every absorbed
        // asset lane are zero. `INJ*E` fire only on boundary M rows, where
        // `1 − lo16` is exactly `[z ≥ 16]`.
        let hi = AB::Expr::ONE - lo16.clone();
        builder.assert_zero(local[INJ3E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJ4E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJRE_COL].clone() * hi * w(13));
        // Shape S reads `mode` off the registry leaf and requires Cloaked (0):
        // every bit of the mode lane is zero on AREG's boundary rows.
        builder.assert_zero(local[INJRE_COL].clone() * w(4));

        // Balance closes. Under `¬q` (CQ[1]): row 1 pays `f1·fee`, row 2 pays
        // `(1 − f1)·fee`, each on its own chain. Under `q` (CQ[0]): the two
        // rows are summed and pay the whole fee once, on row 1's carries.
        let carry = |off: usize, j: usize| -> AB::Expr {
            local[off + 3 * j].clone()
                + local[off + 3 * j + 1].clone() * two.clone()
                + local[off + 3 * j + 2].clone() * two.clone() * two.clone()
                - two.clone()
        };
        let close = local[BLCLOSE_COL].clone();
        let close_q = local[CQ_OFF].clone();
        let close_nq = local[CQ_OFF + 1].clone();
        let w16 = AB::Expr::from_u32(1 << 16);
        let f1 = local[SEL2_OFF + S2_F1].clone();
        let acc = |bl: usize, j: usize| local[bl + j].clone();
        let summed = |j: usize| local[BL_OFF + j].clone() + local[BL2_OFF + j].clone();
        // (gate, accumulator at chunk j, carry block, fee selector)
        type Chain<'a, E> = (E, Box<dyn Fn(usize) -> E + 'a>, usize, E);
        let chains: [Chain<'_, AB::Expr>; 3] = [
            (close_nq.clone(), Box::new(move |j| acc(BL_OFF, j)), BLC_OFF, f1.clone()),
            (close_nq.clone(), Box::new(move |j| acc(BL2_OFF, j)), BLC2_OFF, AB::Expr::ONE - f1.clone()),
            (close_q.clone(), Box::new(summed), BLC_OFF, AB::Expr::ONE),
        ];
        for (gate, bl, blc, fsel) in chains.iter() {
            let feev = |j: usize| fsel.clone() * pv(PV_FEE + j) * ep.clone();
            builder.assert_zero(gate.clone() * (bl(0) - feev(0) - w16.clone() * carry(*blc, 0)));
            for j in 1..3 {
                builder.assert_zero(
                    gate.clone()
                        * (bl(j) + carry(*blc, j - 1) - feev(j) - w16.clone() * carry(*blc, j)),
                );
            }
            builder.assert_zero(gate.clone() * (bl(3) + carry(*blc, 2) - feev(3)));
        }
        // The selector bindings, at the same close row, against the captured
        // asset ids. Public-fee/registry-independent: pure witness equations.
        let ac = |k: usize| local[AC_OFF + k].clone();
        // `q` both ways: q ⇒ A₁ = A₂; ¬q ⇒ qinv · (A₁ − A₂) = 1.
        builder.assert_zero(close_q * (ac(AG_IN1) - ac(AG_IN2)));
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
        // Each registry opening is for the asset the input actually carries.
        builder.assert_zero(close.clone() * (ac(AG_R1) - ac(AG_IN1)));
        builder.assert_zero(close * (ac(AG_R2) - ac(AG_IN2)));

        // --- The #219 latch (verbatim) + the dummy slot's asset ---
        {
            let dv = local[DV_COL].clone();
            builder.assert_bool(latch.clone());
            builder.assert_bool(dv.clone());
            builder.when_first_row().assert_zero(latch.clone());
            builder.assert_eq(local[LDV_COL].clone(), latch.clone() * dv);
            // The mint guard: a dummy slot's value is 0 bit by bit …
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 4].clone(),
            );
            // … and so is its asset (#700: dummies carry asset 0, value 0), so
            // the dummy's registry opening is asset 0's leaf and row 2 can
            // carry the fee for a one-input asset-0 spend.
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
        t.assert_eq(next[u_col(65)].clone(), (mrow - u63) * hi_c);

        t.assert_eq(
            next[EP_COL].clone(),
            local[EP_COL].clone() * (AB::Expr::ONE - local[GWRAP_COL].clone()),
        );
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - local[BGRST_COL].clone())
                        * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone()
                            * per[35 + j].clone()
                            * local[A_OFF + l].clone(),
                );
            }
        }
        // Two-asset balance accumulation. Row 1: +v at input 1, −v at the
        // outputs assigned to row 1. Row 2: +v at input 2, −v at the rest.
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
        // Asset capture-and-hold: chunk 0 of W13 under the six gates.
        for k in 0..6 {
            t.assert_eq(
                next[AC_OFF + k].clone(),
                local[AC_OFF + k].clone()
                    + local[AG_OFF + k].clone() * per[35].clone() * local[W_OFF + 13].clone(),
            );
        }
        // The selectors and the inverse witness are per-transaction
        // declarations: constant.
        for k in 0..4 {
            t.assert_eq(next[SEL2_OFF + k].clone(), local[SEL2_OFF + k].clone());
        }
        t.assert_eq(next[QINV_COL].clone(), local[QINV_COL].clone());
        // The latch and dv (verbatim).
        {
            t.assert_eq(
                next[LATCH_COL].clone(),
                local[LATCH_COL].clone() * (AB::Expr::ONE - local[BGC_OFF].clone())
                    + local[BGC_OFF + 2].clone(),
            );
            t.assert_eq(next[DV_COL].clone(), local[DV_COL].clone());
        }
        // The output-1 marker and the third bank (verbatim).
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
                        (AB::Expr::ONE - local[EG3_OFF + 2].clone())
                            * local[EQ3_OFF + idx].clone()
                            + local[EG3_OFF].clone()
                                * per[35 + j].clone()
                                * local[W_OFF + 5 + l].clone()
                            - local[EG3_OFF + 1].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone(),
                    );
                }
            }
        }
        let pwk = |j: usize| per[35 + j].clone();
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[EQ_OFF + idx].clone(),
                    local[EQ_OFF + idx].clone()
                        + local[EG_OFF].clone() * pwk(j) * local[A_OFF + l].clone()
                        - local[EG_OFF + 1].clone() * pwk(j) * local[W_OFF + l].clone(),
                );
                t.assert_eq(
                    next[EQ_OFF + 16 + idx].clone(),
                    local[EQ_OFF + 16 + idx].clone()
                        + local[EG_OFF + 3].clone() * pwk(j) * local[W_OFF + l].clone()
                        - local[EG_OFF + 4].clone() * pwk(j) * local[W_OFF + 5 + l].clone(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// One registry leaf (l2-own-circuit-decision §2.4), lane-aligned for the
/// circuit: `asset` (lane 0) ‖ `issuer_key` (1..5) ‖ `mode` (5) ‖ `freeze_root`
/// (6..10) ‖ `allow_root` (10..14) ‖ `flags` (14), pad10*1 at bit 960.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistryLeaf {
    pub asset: u64,
    pub issuer_key: [u64; 4],
    pub mode: u64,
    pub freeze_root: [u64; 4],
    pub allow_root: [u64; 4],
    pub flags: u64,
}

impl RegistryLeaf {
    /// A Cloaked leaf with no issuer and no policy roots — what shape S opens.
    pub fn cloaked(asset: u64) -> Self {
        Self {
            asset,
            issuer_key: [0; 4],
            mode: MODE_CLOAKED,
            freeze_root: [0; 4],
            allow_root: [0; 4],
            flags: 0,
        }
    }

    /// The sponge input state the `ROLE_AREG` perm absorbs.
    pub fn state(&self) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[0] = self.asset;
        st[1..5].copy_from_slice(&self.issuer_key);
        st[5] = self.mode;
        st[6..10].copy_from_slice(&self.freeze_root);
        st[10..14].copy_from_slice(&self.allow_root);
        st[14] = self.flags;
        st[15] = 1;
        st[16] = 1 << 63;
        st
    }

    /// `leaf = H(asset ‖ issuer_key ‖ mode ‖ freeze_root ‖ allow_root ‖ flags)`.
    pub fn hash(&self) -> [u64; 4] {
        crate::reference::keccak_f(&self.state())[..4].try_into().unwrap()
    }
}

/// A depth-16 registry authentication path, `MerkleWitness`'s convention.
#[derive(Clone, Copy)]
pub struct RegistryWitness {
    pub siblings: [[u64; 4]; REGISTRY_DEPTH],
    pub path_bits: [bool; REGISTRY_DEPTH],
}

impl RegistryWitness {
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

/// Fabricate a depth-16 registry holding the two leaves at positions 0/1 with
/// shared upper siblings. When the two leaves are the same (A₁ = A₂) both
/// openings are for position 0 and position 1 holds a filler, so the tree
/// never carries a duplicate leaf. Bench/self-test only — the live L2 supplies
/// real openings.
pub fn fabricated_registry_tree(
    leaf1: &[u64; 4],
    leaf2: &[u64; 4],
) -> ([RegistryWitness; 2], [u64; 4]) {
    let mut x = 0x7e61_5712_9a1e_af00u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let same = leaf1 == leaf2;
    let filler: [u64; 4] = [rnd(), rnd(), rnd(), rnd()];
    let upper: Vec<[u64; 4]> = (1..REGISTRY_DEPTH)
        .map(|_| [rnd(), rnd(), rnd(), rnd()])
        .collect();
    let build = |pos0: bool| {
        let mut siblings = [[0u64; 4]; REGISTRY_DEPTH];
        let mut path_bits = [false; REGISTRY_DEPTH];
        siblings[0] = if pos0 {
            if same {
                filler
            } else {
                *leaf2
            }
        } else {
            *leaf1
        };
        path_bits[0] = !pos0;
        for (i, sib) in upper.iter().enumerate() {
            siblings[i + 1] = *sib;
        }
        RegistryWitness { siblings, path_bits }
    };
    let w1 = build(true);
    let w2 = if same { w1 } else { build(false) };
    let root = w1.fold_root(leaf1);
    debug_assert_eq!(root, w2.fold_root(leaf2), "registry tree must have one root");
    ([w1, w2], root)
}

// ---------------------------------------------------------------------------
// Bucket instance builder
// ---------------------------------------------------------------------------

/// One L2 transaction input.
#[derive(Clone)]
pub struct L2TxInput {
    pub sk: [u64; 4],
    pub value: u64,
    /// Registry index of the note's asset; `0` is the fee asset.
    pub asset: u64,
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
    pub d: [u64; 2],
}

/// One L2 output note. `rho` is overridden by the option-4 derivation exactly
/// as on L1 — kept in the struct so callers can carry a note around.
#[derive(Clone, Copy)]
pub struct L2TxOutput {
    pub value: u64,
    pub asset: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

/// Everything a prover/verifier pair needs for one shape-S instance.
#[cfg_attr(test, derive(Clone))] // the test fan-out needs owned copies; non-test build unchanged
pub struct L2BucketInstance {
    pub air: L2ShapeSAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub registry_root: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm_out: [[u64; 4]; 2],
}

/// Perm slots used by the shape-S program, INCLUDING the leading dummy
/// warm-up slot: 1 + 2 × (5 + 32 + 1 + 18) + (2 + 3) + 2 = **120**, at 3072
/// rows each = 368,640 rows → 2^19 (524,288), 50.7 spare perm slots.
pub const SHAPE_S_PERMS: usize =
    1 + 2 * (5 + MERKLE_DEPTH + 1 + (1 + REGISTRY_DEPTH + 1)) + 2 * 2 + 1 + 2;
/// log2 of the shape-S trace height.
pub const SHAPE_S_LOG_HEIGHT: usize = 19;

/// The L2 note block, `H(value ‖ asset ‖ rkm ‖ rho ‖ rseed)`.
pub fn l2_cm(value: u64, asset: u64, rkm: &[u64; 4], rho: &[u64; 4], rseed: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[0] = value;
    st[1] = asset;
    st[2..6].copy_from_slice(rkm);
    st[6..10].copy_from_slice(rho);
    st[10..14].copy_from_slice(rseed);
    st[14] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// Derive `(nk, nf, cm)` for one L2 input — the L1 chain with the L2 note block.
pub fn derive_input_l2(inp: &L2TxInput) -> ([u64; 4], [u64; 4], [u64; 4]) {
    use crate::reference;
    let mut nk_in = [0u64; 25];
    nk_in[..4].copy_from_slice(&inp.sk);
    nk_in[4] = 1;
    nk_in[5] = 1;
    nk_in[16] = 1 << 63;
    let nk: [u64; 4] = reference::keccak_f(&nk_in)[..4].try_into().unwrap();
    let mut nf_in = [0u64; 25];
    nf_in[..4].copy_from_slice(&nk);
    nf_in[4..8].copy_from_slice(&inp.rho);
    nf_in[8] = 1;
    nf_in[16] = 1 << 63;
    let nf: [u64; 4] = reference::keccak_f(&nf_in)[..4].try_into().unwrap();
    let mut rkm_in = [0u64; 25];
    rkm_in[..4].copy_from_slice(&nk);
    rkm_in[4] = 1 << 1;
    rkm_in[5] = inp.d[0];
    rkm_in[6] = inp.d[1];
    rkm_in[7] = 1;
    rkm_in[16] = 1 << 63;
    let rkm: [u64; 4] = reference::keccak_f(&rkm_in)[..4].try_into().unwrap();
    let cm = l2_cm(inp.value, inp.asset, &rkm, &inp.rho, &inp.rseed);
    (nk, nf, cm)
}

/// Build shape S against **fabricated** trees: the commitment tree holds both
/// inputs at leaves 0/1 (`narrow::fabricated_shared_tree`), the registry holds
/// a Cloaked leaf per input asset. Selectors are computed honestly from the
/// assets; balance is NOT asserted (an unbalanced instance is simply
/// unprovable, which is what the negatives test).
pub fn build_bucket_l2(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
) -> L2BucketInstance {
    let (_, _, cm1) = derive_input_l2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [
        RegistryLeaf::cloaked(inputs[0].asset),
        RegistryLeaf::cloaked(inputs[1].asset),
    ];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_with_witnesses(
        log_height,
        inputs,
        outputs,
        fee,
        &witnesses,
        anchor,
        &leaves,
        &rw,
        registry_root,
    )
}

/// Build shape S from caller-supplied commitment-tree witnesses + anchor and
/// registry leaves + openings + root. The circuit folds both, so a witness
/// that does not resolve to its public root is an unprovable instance.
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2_with_witnesses(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    reg_leaves: &[RegistryLeaf; 2],
    reg_witnesses: &[RegistryWitness; 2],
    registry_root: [u64; 4],
) -> L2BucketInstance {
    let (nk1, nf1, _cm1) = derive_input_l2(&inputs[0]);
    let (nk2, nf2, _cm2) = derive_input_l2(&inputs[1]);

    let out_rho = [derive_output_rho(&nf1, 0), derive_output_rho(&nf1, 1)];
    let cmo1 = l2_cm(outputs[0].value, outputs[0].asset, &outputs[0].rkm, &out_rho[0], &outputs[0].rseed);
    let cmo2 = l2_cm(outputs[1].value, outputs[1].asset, &outputs[1].rkm, &out_rho[1], &outputs[1].rseed);

    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![L2SlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut input_chain = |inp: &L2TxInput,
                           nk: &[u64; 4],
                           witness: &MerkleWitness,
                           leaf: &RegistryLeaf,
                           rw: &RegistryWitness,
                           bnf_role: u32| {
        program[slot] = ROLE_ANK;
        sw[slot].w[..4].copy_from_slice(&inp.sk);
        slot += 1;
        program[slot] = ROLE_NF;
        sw[slot].w[..4].copy_from_slice(&inp.rho);
        slot += 1;
        program[slot] = bnf_role;
        slot += 1;
        // The registry opening, inside the input chain (see the module doc).
        program[slot] = ROLE_AREG;
        sw[slot].w[..4].copy_from_slice(&leaf.issuer_key);
        sw[slot].w[4] = leaf.mode;
        sw[slot].w[5..9].copy_from_slice(&leaf.freeze_root);
        sw[slot].w[9..13].copy_from_slice(&leaf.allow_root);
        sw[slot].w[13] = leaf.asset;
        sw[slot].w[14] = leaf.flags;
        slot += 1;
        for (sib, bit) in rw.siblings.iter().zip(rw.path_bits.iter()) {
            program[slot] = ROLE_MERKLE;
            sw[slot].w[..4].copy_from_slice(sib);
            sw[slot].pbit = *bit;
            slot += 1;
        }
        program[slot] = ROLE_BREG;
        slot += 1;
        program[slot] = ROLE_ARKM;
        sw[slot].w[..4].copy_from_slice(nk);
        sw[slot].w[5] = inp.d[0];
        sw[slot].w[6] = inp.d[1];
        slot += 1;
        program[slot] = ROLE_ACM;
        sw[slot].w[4] = inp.value;
        sw[slot].w[5..9].copy_from_slice(&inp.rho);
        sw[slot].w[9..13].copy_from_slice(&inp.rseed);
        sw[slot].w[13] = inp.asset;
        slot += 1;
        for (sib, bit) in witness.siblings.iter().zip(witness.path_bits.iter()) {
            program[slot] = ROLE_MERKLE;
            sw[slot].w[..4].copy_from_slice(sib);
            sw[slot].pbit = *bit;
            slot += 1;
        }
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    };
    input_chain(&inputs[0], &nk1, &witnesses[0], &reg_leaves[0], &reg_witnesses[0], ROLE_BNF1);
    input_chain(&inputs[1], &nk2, &witnesses[1], &reg_leaves[1], &reg_witnesses[1], ROLE_BNF2);
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
    assert_eq!(slot, SHAPE_S_PERMS, "program layout drifted");

    // Honest selectors. When an output's asset matches both inputs' (A₁ = A₂)
    // row 1 is chosen; when it matches neither the instance is unprovable
    // whatever is chosen, and row 2 is recorded so the negative test's
    // "both assignments refused" is exercised from the builder's side too.
    let a1 = inputs[0].asset;
    let sel_o1a = outputs[0].asset == a1;
    let sel_o2a = outputs[1].asset == a1;
    let sel_f1 = a1 == 0;
    let sel_q = a1 == inputs[1].asset;

    let pvs = pv_vec_l2(&anchor, &nf1, &nf2, &cmo1, &cmo2, fee, &registry_root);
    L2BucketInstance {
        air: L2ShapeSAir {
            log_height,
            program,
            slot_witness: sw,
            fee,
            dv: false,
            sel_o1a,
            sel_o2a,
            sel_f1,
            sel_q,
        },
        pvs,
        anchor,
        registry_root,
        nf: [nf1, nf2],
        cm_out: [cmo1, cmo2],
    }
}

/// Shape S with **input slot 1 a dummy** (#219's construction on L2): same
/// program, `dv = true`; the dummy carries value 0 AND asset 0 (both forced by
/// the AIR), so its registry opening is asset 0's leaf.
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2_dummy1(
    log_height: usize,
    real: &L2TxInput,
    real_witness: &MerkleWitness,
    dummy: &L2TxInput,
    dummy_witness: &MerkleWitness,
    outputs: &[L2TxOutput; 2],
    fee: u64,
    anchor: [u64; 4],
    reg_leaves: &[RegistryLeaf; 2],
    reg_witnesses: &[RegistryWitness; 2],
    registry_root: [u64; 4],
) -> L2BucketInstance {
    assert_eq!(dummy.value, 0, "a dummy input slot contributes 0 to the balance");
    assert_eq!(dummy.asset, 0, "a dummy input slot carries asset 0 (#700)");
    let inputs = [real.clone(), dummy.clone()];
    let mut inst = build_bucket_l2_with_witnesses(
        log_height,
        &inputs,
        outputs,
        fee,
        &[*real_witness, *dummy_witness],
        anchor,
        reg_leaves,
        reg_witnesses,
        registry_root,
    );
    inst.air.dv = true;
    inst
}

/// Convenience for tests/benches: a one-real-input shape-S spend against
/// fabricated trees (the real note in a single-leaf commitment tree, the dummy
/// off-tree; a registry holding the real asset's leaf and asset 0's).
pub fn build_bucket_l2_dummy1_fabricated(
    log_height: usize,
    real: &L2TxInput,
    dummy: &L2TxInput,
    outputs: &[L2TxOutput; 2],
    fee: u64,
) -> L2BucketInstance {
    let (_, _, cm_real) = derive_input_l2(real);
    let (w_real, anchor) = fabricated_single_tree(&cm_real);
    let leaves = [RegistryLeaf::cloaked(real.asset), RegistryLeaf::cloaked(0)];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_dummy1(
        log_height,
        real,
        &w_real,
        dummy,
        &off_tree_witness(),
        outputs,
        fee,
        anchor,
        &leaves,
        &rw,
        registry_root,
    )
}

// ---------------------------------------------------------------------------
// Trace generation — narrow.rs's fill, mirrored constraint for constraint.
// ---------------------------------------------------------------------------

impl L2ShapeSAir {
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * L2_WIDTH;
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
        let wit = |p: usize| -> L2SlotWitness {
            if self.slot_witness.is_empty() {
                L2SlotWitness::default()
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
        // `qinv`: the inverse of (A₁ − A₂) in F when ¬q, else 0. The two input
        // assets are the first two ACM slots' W13 (chunk 0); a program without
        // two ACMs (chain-only, partial tests) gets 0/0 and never closes.
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
                    ROLE_ARKM => match l {
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

            let base = values.len();
            values.resize(base + L2_WIDTH, F::ZERO);
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
            for i in 1..5 {
                row[INJ_OFF + i] = F::from_u32(bndv * selv[i + 1]);
            }
            row[INJ_OFF + 5] = F::from_u32(bndv * selv[SEL_ARHO]);
            row[INJ_OFF + 6] = F::from_u32(bndv * selv[SEL_AREG]);
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
            row[EG_OFF] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 1] = F::from_u32(bndv * se[1]);
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
            // Shape S gates.
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
            let sgn = |vv: i64| -> F {
                if vv >= 0 {
                    F::from_u32(vv as u32)
                } else {
                    -F::from_u32((-vv) as u32)
                }
            };
            for (i, acc) in bq.iter().enumerate() {
                row[BQ_OFF + i] = sgn(*acc);
            }
            for (j, acc) in bl.iter().enumerate() {
                row[BL_OFF + j] = sgn(*acc);
            }
            for (j, acc) in bl2.iter().enumerate() {
                row[BL2_OFF + j] = sgn(*acc);
            }
            for (k, acc) in ac.iter().enumerate() {
                row[AC_OFF + k] = sgn(*acc);
            }
            // Carry encodings. Under ¬q: row 1 owes f1·fee, row 2 the rest.
            // Under q: row 1's carries serve the SUMMED chain against the
            // whole fee (row 2's chain is unchecked; encoded anyway).
            {
                let fee_row = |row_fee: u64, j: usize| ((row_fee >> (16 * j)) & 0xffff) as i64;
                let (fee1, chain1): (u64, [i64; 4]) = if self.sel_q {
                    (self.fee, core::array::from_fn(|j| bl[j] + bl2[j]))
                } else if self.sel_f1 {
                    (self.fee, bl)
                } else {
                    (0, bl)
                };
                let fee2 = if self.sel_f1 { 0 } else { self.fee };
                for (accs, off, rf) in [(chain1, BLC_OFF, fee1), (bl2, BLC2_OFF, fee2)] {
                    let mut cc = [0i64; 3];
                    let mut prev = 0i64;
                    for j in 0..3 {
                        let tj = accs[j] + prev - fee_row(rf, j);
                        cc[j] = tj >> 16;
                        prev = cc[j];
                    }
                    for (j, cj) in cc.iter().enumerate() {
                        let enc = (cj + 2).clamp(0, 7) as u32;
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
                row[EQ_OFF + i] = sgn(*acc);
            }
            for (i, acc) in eq3.iter().enumerate() {
                row[EQ3_OFF + i] = sgn(*acc);
            }
            for l in 0..25 {
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            // Advance the accumulators.
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let epi = ep as i64;
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq[idx] += epi
                        * (g_e1pos * wgt * a[l] as i64 - g_e1neg * wgt * wbit[l] as i64);
                    eq[16 + idx] += epi
                        * (g_e2pos * wgt * wbit[l] as i64
                            - g_e2neg * wgt * wbit[5 + l] as i64);
                    bq[idx] += (bgcap as i64) * wgt * a[l] as i64;
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
                if bgrst == 1 {
                    bq = [0i64; 16];
                }
                if g3close == 1 {
                    eq3 = [0i64; 16];
                }
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq3[idx] += g3pos as i64 * wgt * wbit[5 + l] as i64
                        - g3neg as i64 * wgt * a[l] as i64;
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

        RowMajorMatrix::new(values, L2_WIDTH)
    }

    /// The state materialized at block `q` (the round-q input).
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * L2_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use p3_air::{check_all_constraints, check_constraints};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;

    use super::*;
    use crate::reference;

    type F = KoalaBear;

    fn zero_pvs() -> Vec<F> {
        vec![F::ZERO; PV_LEN]
    }
    fn pvs_of(inst: &L2BucketInstance) -> Vec<F> {
        inst.pvs.iter().map(|v| F::from_u32(*v)).collect()
    }
    fn sat(inst: &L2BucketInstance) -> bool {
        let pvs = pvs_of(inst);
        let trace = inst.air.generate_trace::<F>(0);
        check_all_constraints(&inst.air, &trace, &pvs, Some(10)).is_ok()
    }
    fn digest(state: &[u64; 25]) -> [u64; 4] {
        state[..4].try_into().unwrap()
    }
    fn slot_of(program: &[u32; PROGRAM_SLOTS], role: u32, nth: usize) -> usize {
        program.iter().enumerate().filter(|(_, r)| **r == role).map(|(i, _)| i).nth(nth).unwrap()
    }

    /// A deterministic pseudo-random two-asset bucket: input 1 in asset `a1`,
    /// input 2 in asset `a2`, outputs in `oa1`/`oa2`. Balance is the caller's.
    #[allow(clippy::too_many_arguments)]
    fn bucket(
        v1: u64,
        a1: u64,
        v2: u64,
        a2: u64,
        o1: u64,
        oa1: u64,
        o2: u64,
        oa2: u64,
        fee: u64,
    ) -> L2BucketInstance {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mk_in = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxInput {
            sk: [rnd(), rnd(), rnd(), rnd()],
            value,
            asset,
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
            d: [rnd(), rnd()],
        };
        let mk_out = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxOutput {
            value,
            asset,
            rkm: [rnd(), rnd(), rnd(), rnd()],
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
        };
        let inputs = [mk_in(v1, a1, &mut rnd), mk_in(v2, a2, &mut rnd)];
        let outputs = [mk_out(o1, oa1, &mut rnd), mk_out(o2, oa2, &mut rnd)];
        build_bucket_l2(SHAPE_S_LOG_HEIGHT, &inputs, &outputs, fee)
    }

    /// The canonical honest instance: asset 0 (fee) + asset 7 (a stablecoin),
    /// 100 + 50 in, 90 (asset 0) + 50 (asset 7) out, fee 10 in asset 0.
    fn honest() -> L2BucketInstance {
        bucket(100, 0, 50, 7, 90, 0, 50, 7, 10)
    }

    #[test]
    fn l2_chain_only_satisfies_constraints() {
        let air = L2ShapeSAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());
    }

    /// The engine is the L1's: materialized states advance by the reference
    /// rounds through padding.
    #[test]
    fn l2_chain_matches_reference_rounds() {
        let air = L2ShapeSAir::chain_only(13);
        let trace = air.generate_trace::<F>(0);
        let blocks = (1usize << air.log_height) / 128;
        for q in 0..blocks - 1 {
            let cur = L2ShapeSAir::extract_state(&trace, q);
            let nxt = L2ShapeSAir::extract_state(&trace, q + 1);
            assert_eq!(nxt, reference::round(&cur, reference::RC[q % 24]), "block {q}");
        }
    }

    /// The registry opening chain — `AREG → 16 × MERKLE` — advances exactly
    /// like the reference leaf hash and fold, read off the trace.
    #[test]
    fn l2_registry_chain_matches_reference() {
        let leaf = RegistryLeaf {
            asset: 7,
            issuer_key: [1, 2, 3, 4],
            mode: MODE_CLOAKED,
            freeze_root: [5, 6, 7, 8],
            allow_root: [9, 10, 11, 12],
            flags: 0,
        };
        let (rw, root) = fabricated_registry_tree(&leaf.hash(), &RegistryLeaf::cloaked(3).hash());
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        let mut sw = vec![L2SlotWitness::default(); PROGRAM_SLOTS];
        program[1] = ROLE_AREG;
        sw[1].w[..4].copy_from_slice(&leaf.issuer_key);
        sw[1].w[4] = leaf.mode;
        sw[1].w[5..9].copy_from_slice(&leaf.freeze_root);
        sw[1].w[9..13].copy_from_slice(&leaf.allow_root);
        sw[1].w[13] = leaf.asset;
        sw[1].w[14] = leaf.flags;
        for i in 0..REGISTRY_DEPTH {
            program[2 + i] = ROLE_MERKLE;
            sw[2 + i].w[..4].copy_from_slice(&rw[0].siblings[i]);
            sw[2 + i].pbit = rw[0].path_bits[i];
        }
        let air = L2ShapeSAir {
            log_height: 16, // 21 perms >= 18 used
            program,
            slot_witness: sw,
            ..L2ShapeSAir::chain_only(16)
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());
        assert_eq!(
            L2ShapeSAir::extract_state(&trace, 24 * 2),
            reference::keccak_f(&leaf.state()),
            "AREG output must be keccak_f(leaf block)"
        );
        let mut d = leaf.hash();
        for i in 0..REGISTRY_DEPTH {
            let (sib, bit) = (rw[0].siblings[i], rw[0].path_bits[i]);
            let expect = if bit {
                reference::merkle_node_state(&sib, &d)
            } else {
                reference::merkle_node_state(&d, &sib)
            };
            assert_eq!(L2ShapeSAir::extract_state(&trace, 24 * (3 + i)), expect, "step {i}");
            d = digest(&expect);
        }
        assert_eq!(d, root, "the fold resolves to the fabricated root");
    }

    /// The L2 note block: the ACM perm absorbs `value ‖ asset ‖ rkm ‖ rho ‖
    /// rseed` in the module-doc packing, checked against the reference.
    #[test]
    fn l2_acm_block_matches_reference() {
        let inp = L2TxInput {
            sk: [11, 22, 33, 44],
            value: 0xdead_beef,
            asset: 0x1234,
            rho: [55, 66, 77, 88],
            rseed: [99, 111, 222, 333],
            d: [0xd1, 0xd2],
        };
        let (nk, nf, cm) = derive_input_l2(&inp);
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        program[1] = ROLE_ANK;
        program[2] = ROLE_NF;
        program[3] = ROLE_ARKM;
        program[4] = ROLE_ACM;
        let mut sw = vec![L2SlotWitness::default(); PROGRAM_SLOTS];
        sw[1].w[..4].copy_from_slice(&inp.sk);
        sw[2].w[..4].copy_from_slice(&inp.rho);
        sw[3].w[..4].copy_from_slice(&nk);
        sw[3].w[5] = inp.d[0];
        sw[3].w[6] = inp.d[1];
        sw[4].w[4] = inp.value;
        sw[4].w[5..9].copy_from_slice(&inp.rho);
        sw[4].w[9..13].copy_from_slice(&inp.rseed);
        sw[4].w[13] = inp.asset;
        let air = L2ShapeSAir {
            log_height: 15,
            program,
            slot_witness: sw,
            ..L2ShapeSAir::chain_only(15)
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());
        assert_eq!(digest(&L2ShapeSAir::extract_state(&trace, 24 * 3)), nf);
        assert_eq!(digest(&L2ShapeSAir::extract_state(&trace, 24 * 5)), cm);
        // And `cm` really is the 112-B block of the design: st[1] = asset.
        let rkm = digest(&L2ShapeSAir::extract_state(&trace, 24 * 4));
        assert_eq!(cm, l2_cm(inp.value, inp.asset, &rkm, &inp.rho, &inp.rseed));
        let mut st = [0u64; 25];
        st[0] = inp.value;
        st[1] = inp.asset;
        st[2..6].copy_from_slice(&rkm);
        st[6..10].copy_from_slice(&inp.rho);
        st[10..14].copy_from_slice(&inp.rseed);
        st[14] = 1;
        st[16] = 1 << 63;
        assert_eq!(cm, digest(&reference::keccak_f(&st)));
    }

    /// The complete shape S — two inputs in two assets, both registry
    /// openings, two outputs, the two-asset balance, every public binding —
    /// satisfies the AIR with the real public values at 2^19.
    #[test]
    fn l2_shape_s_satisfies_constraints() {
        let inst = honest();
        assert_eq!(inst.air.program.iter().filter(|r| **r != ROLE_DUMMY).count(), SHAPE_S_PERMS - 1);
        let pvs = pvs_of(&inst);
        let trace = inst.air.generate_trace::<F>(0);
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// Same-asset spend (both inputs asset 0) and a two-asset spend where the
    /// fee asset is input 2 — the selector assignment's other corners.
    #[test]
    fn l2_shape_s_selector_corners_satisfy() {
        // Both asset 0: 60 + 40 = 70 + 25 + 5.
        let a = bucket(60, 0, 40, 0, 70, 0, 25, 0, 5);
        assert!(a.air.sel_o1a && a.air.sel_o2a && a.air.sel_f1 && a.air.sel_q);
        assert!(sat(&a), "same-asset spend: no per-row partition exists, only the sum");
        // Fee asset on input 2: asset 7 (100) + asset 0 (50) → 100 (7) + 40 (0) + fee 10.
        let b = bucket(100, 7, 50, 0, 100, 7, 40, 0, 10);
        assert!(b.air.sel_o1a && !b.air.sel_o2a && !b.air.sel_f1 && !b.air.sel_q);
        assert!(sat(&b), "fee on input 2");
        // Both outputs in the fee asset, stablecoin fully burned to… no: a
        // stablecoin input with no stablecoin output is unbalanced. Instead:
        // asset 0 pays everything, asset 7 passes through 1:1.
        let c = bucket(100, 0, 50, 7, 50, 7, 90, 0, 10);
        assert!(!c.air.sel_o1a && c.air.sel_o2a && c.air.sel_f1);
        assert!(sat(&c), "outputs swapped");
    }

    /// 🔴 The `q` lie, both directions (stage-0 ruling, the corner test's
    /// negative twin). `q` is what makes the summed close reachable, so it is
    /// bound both ways: clearing it on equal assets leaves `qinv · 0 = 1`
    /// unsatisfiable, setting it on distinct assets fails `A₁ = A₂`. Each lie
    /// is tried with every other selector assignment, on a witness that is
    /// honest in every other respect.
    #[test]
    fn l2_neg_q_lie_is_unsat_both_ways() {
        // Equal assets, `q` cleared: the honest sum (60 + 40 = 70 + 25 + 5)
        // is only reachable through `q`.
        let mut a = bucket(60, 0, 40, 0, 70, 0, 25, 0, 5);
        assert!(sat(&a), "precondition: honest with q = 1");
        for bits in 0..8u32 {
            a.air.sel_o1a = bits & 1 == 1;
            a.air.sel_o2a = bits & 2 == 2;
            a.air.sel_f1 = bits & 4 == 4;
            a.air.sel_q = false;
            assert!(!sat(&a), "q = 0 on equal assets VERIFIED (assignment {bits})");
        }
        // Distinct assets, `q` set: the equality leg refuses, whatever the
        // rows would otherwise sum to (here they even balance as a sum:
        // 100 + 50 = 100 + 40 + 10).
        let mut b = bucket(100, 7, 50, 0, 100, 7, 40, 0, 10);
        assert!(sat(&b), "precondition: honest with q = 0");
        for bits in 0..8u32 {
            b.air.sel_o1a = bits & 1 == 1;
            b.air.sel_o2a = bits & 2 == 2;
            b.air.sel_f1 = bits & 4 == 4;
            b.air.sel_q = true;
            assert!(!sat(&b), "q = 1 on distinct assets VERIFIED (assignment {bits})");
        }
    }

    // -----------------------------------------------------------------------
    // The six tamper negatives (#700 stage 1).
    // -----------------------------------------------------------------------

    /// `cm` off an ACMOUT slot's own witness — so a forgery can publish the
    /// commitment that MATCHES it and only the L2 bindings can refuse.
    fn cm_of_slot(w: &L2SlotWitness) -> [u64; 4] {
        let rkm: [u64; 4] = w.w[..4].try_into().unwrap();
        let rho: [u64; 4] = w.w[5..9].try_into().unwrap();
        let rseed: [u64; 4] = w.w[9..13].try_into().unwrap();
        l2_cm(w.w[4], w.w[13], &rkm, &rho, &rseed)
    }

    /// Republish output `j`'s commitment from its (possibly forged) witness.
    fn republish(inst: &mut L2BucketInstance, j: usize) {
        let s = slot_of(&inst.air.program, ROLE_ACMOUT, j);
        let cm = cm_of_slot(&inst.air.slot_witness[s]);
        let base = if j == 0 { PV_CM1 } else { PV_CM2 };
        for (k, c) in pv_chunks(&cm).iter().enumerate() {
            inst.pvs[base + k] = *c;
        }
    }

    /// Every selector assignment the prover could try, for a fixed witness:
    /// the eight `(o1a, o2a, f1)` combinations at the witness's honest `q`.
    /// `q` is deliberately NOT iterated here: its two constraints read only
    /// the captured `A₁`/`A₂` (`close·q·(A₁−A₂)`, `close·(1−q)·(qinv·(A₁−A₂)−1)`)
    /// and no other column, so a lying `q` is refused whatever the rest of the
    /// witness says — `l2_neg_q_lie_is_unsat_both_ways` proves both lies on
    /// their own, and iterating them here would double every negative's cost
    /// (a 2^19 `check_all_constraints` per assignment) for no extra coverage.
    /// The stage-1 scoped run executed the 16-way form; this is its subset.
    fn any_assignment_satisfies(inst: &mut L2BucketInstance) -> bool {
        let q = inst.air.sel_q;
        for bits in 0..8u32 {
            inst.air.sel_o1a = bits & 1 == 1;
            inst.air.sel_o2a = bits & 2 == 2;
            inst.air.sel_f1 = bits & 4 == 4;
            inst.air.sel_q = q;
            if sat(inst) {
                return true;
            }
        }
        false
    }

    /// 🔴 Negative 1 — **asset from nowhere**: output 0's asset is neither
    /// input's. The forgery is complete (commitment republished, balance rows
    /// arranged so the value arithmetic holds under either assignment) and it
    /// is refused under all eight selector assignments.
    #[test]
    fn l2_neg_output_asset_from_nowhere() {
        // Honest: asset 0 (100) + asset 7 (50) → 90 (asset 0) + 50 (asset 7), fee 10.
        let mut inst = honest();
        assert!(sat(&inst), "the honest instance verifies — else the negative is vacuous");
        let s = slot_of(&inst.air.program, ROLE_ACMOUT, 1);
        inst.air.slot_witness[s].w[13] = 9; // a third asset, value unchanged (50)
        republish(&mut inst, 1);
        assert!(
            !any_assignment_satisfies(&mut inst),
            "an output in an asset neither input carries VERIFIED"
        );
    }

    /// 🔴 Negative 2 — **cross-asset balance**: value moved from asset 0 to
    /// asset 7. Totals balance (150 = 140 + 10) but per-asset they do not.
    #[test]
    fn l2_neg_cross_asset_balance() {
        // asset 0: 100 in, 80 out, fee 10 (10 short); asset 7: 50 in, 60 out.
        let mut inst = bucket(100, 0, 50, 7, 80, 0, 60, 7, 10);
        assert!(!any_assignment_satisfies(&mut inst), "cross-asset value movement VERIFIED");
        // …and the same numbers balanced per asset DO verify, so the refusal
        // above is the per-asset rows' doing.
        let ok = bucket(100, 0, 50, 7, 90, 0, 50, 7, 10);
        assert!(sat(&ok));
    }

    /// 🔴 Negative 3 — **fee charged in the wrong asset**: the fee is public in
    /// asset 0, but the prover's outputs take it out of asset 7.
    #[test]
    fn l2_neg_fee_in_wrong_asset() {
        // asset 0: 100 in, 100 out (fee unpaid); asset 7: 50 in, 40 out (fee "paid" here).
        let mut inst = bucket(100, 0, 50, 7, 100, 0, 40, 7, 10);
        assert!(!any_assignment_satisfies(&mut inst), "a fee paid in asset 7 VERIFIED");
    }

    /// 🔴 Negative 4 — **no asset-0 note**: two policy-free stablecoin inputs,
    /// balanced per asset, fee 0 — still refused, because the fee assignment
    /// `f1 ⇒ A₁ = 0`, `¬f1 ⇒ A₂ = 0` has no satisfying value.
    #[test]
    fn l2_neg_no_fee_asset_note() {
        let mut inst = bucket(100, 3, 50, 7, 100, 3, 50, 7, 0);
        assert!(!any_assignment_satisfies(&mut inst), "a transaction with no asset-0 note VERIFIED");
        // The same shape with input 2 in asset 0 verifies.
        let ok = bucket(100, 3, 50, 0, 100, 3, 50, 0, 0);
        assert!(sat(&ok));
    }

    /// 🔴 Negative 5 — **registry leaf under the wrong root**, two ways: (a) a
    /// forged `PV_REGROOT`; (b) a genuine opening under the genuine root, but
    /// of the WRONG asset's leaf (asset 5's leaf while spending asset 7).
    #[test]
    fn l2_neg_registry_leaf_under_wrong_root() {
        // (a)
        let mut inst = honest();
        inst.pvs[PV_REGROOT + 3] += 1;
        assert!(!any_assignment_satisfies(&mut inst), "a forged registry root VERIFIED");

        // (b) Build a registry holding asset 0 and asset 5, then spend asset 7
        //     while opening asset 5's leaf: the path is genuine, the root is
        //     genuine, the leaf's asset is not the input's.
        let mut x = 0x5eed_0b5e_55ed_0007u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let inputs = [
            L2TxInput { sk: [rnd(); 4], value: 100, asset: 0, rho: [rnd(); 4], rseed: [rnd(); 4], d: [0, 0] },
            L2TxInput { sk: [rnd(); 4], value: 50, asset: 7, rho: [rnd(); 4], rseed: [rnd(); 4], d: [0, 0] },
        ];
        let outputs = [
            L2TxOutput { value: 90, asset: 0, rkm: [1; 4], rho: [0; 4], rseed: [2; 4] },
            L2TxOutput { value: 50, asset: 7, rkm: [3; 4], rho: [0; 4], rseed: [4; 4] },
        ];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(5)];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        assert_eq!(rw[1].fold_root(&leaves[1].hash()), root, "precondition: asset 5's opening is genuine");
        let mut bad = build_bucket_l2_with_witnesses(
            SHAPE_S_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &leaves, &rw, root,
        );
        assert!(!any_assignment_satisfies(&mut bad), "opening another asset's registry leaf VERIFIED");
    }

    /// 🔴 Negative 6 — **`mode ≠ Cloaked` under shape S**: asset 7's leaf is
    /// Hybrid, genuinely in the registry, genuinely opened. Shape S refuses.
    #[test]
    fn l2_neg_mode_not_cloaked() {
        let inst = honest();
        let inputs_asset = [0u64, 7];
        let mut leaves = [RegistryLeaf::cloaked(inputs_asset[0]), RegistryLeaf::cloaked(inputs_asset[1])];
        leaves[1].mode = MODE_HYBRID;
        leaves[1].issuer_key = [0xa, 0xb, 0xc, 0xd];
        leaves[1].flags = 1;
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        // Rebuild the honest instance's inputs/outputs from the same fixture.
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mk_in = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxInput {
            sk: [rnd(), rnd(), rnd(), rnd()],
            value,
            asset,
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
            d: [rnd(), rnd()],
        };
        let mk_out = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxOutput {
            value,
            asset,
            rkm: [rnd(), rnd(), rnd(), rnd()],
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
        };
        let inputs = [mk_in(100, 0, &mut rnd), mk_in(50, 7, &mut rnd)];
        let outputs = [mk_out(90, 0, &mut rnd), mk_out(50, 7, &mut rnd)];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        assert_eq!(anchor, inst.anchor, "same fixture as `honest()`");
        let mut bad = build_bucket_l2_with_witnesses(
            SHAPE_S_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &leaves, &rw, root,
        );
        assert!(!any_assignment_satisfies(&mut bad), "a Hybrid leaf VERIFIED under shape S");
        // The Cloaked twin of the same registry verifies, so the refusal is
        // the mode constraint's.
        leaves[1].mode = MODE_CLOAKED;
        let (rw2, root2) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let ok = build_bucket_l2_with_witnesses(
            SHAPE_S_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &leaves, &rw2, root2,
        );
        assert!(sat(&ok), "a Cloaked leaf with issuer_key + flags set still verifies");
    }

    /// Wrong public values are still caught: nf1, fee, anchor (the L1 set).
    #[test]
    fn l2_public_value_negatives() {
        let inst = honest();
        let trace = inst.air.generate_trace::<F>(0);
        for (idx, name) in [(PV_NF1 + 3, "nf1"), (PV_FEE, "fee"), (PV_ANCHOR, "anchor"), (PV_CM2 + 1, "cm2")] {
            let mut pvs = pvs_of(&inst);
            pvs[idx] += F::ONE;
            assert!(!check_all_constraints(&inst.air, &trace, &pvs, Some(10)).is_ok(), "wrong {name} not caught");
        }
    }

    /// An asset id above 2^16 is refused at the absorb, on every note lane
    /// that carries one (input, output, registry leaf).
    #[test]
    fn l2_asset_id_is_a_16_bit_registry_index() {
        let big = 1u64 << ASSET_BITS;
        // Input.
        let mut a = bucket(100, big, 50, 0, 100, big, 40, 0, 10);
        assert!(!any_assignment_satisfies(&mut a), "a 2^16 input asset VERIFIED");
        // Output (commitment republished).
        let mut b = honest();
        let s = slot_of(&b.air.program, ROLE_ACMOUT, 0);
        b.air.slot_witness[s].w[13] = big;
        republish(&mut b, 0);
        assert!(!any_assignment_satisfies(&mut b), "a 2^16 output asset VERIFIED");
        // The largest legal id verifies (both inputs in it, fee asset on… no
        // fee asset would be refused; so asset 0 + 0xffff).
        let ok = bucket(100, 0, 50, 0xffff, 90, 0, 50, 0xffff, 10);
        assert!(sat(&ok));
    }

    // -----------------------------------------------------------------------
    // Column accounting and degree, in the q69 style.
    // -----------------------------------------------------------------------

    /// The trace width `prove` is handed: **698**, accounted column by column
    /// over the minted L1 width 643. The sum is asserted against the matrix,
    /// so a future column has to add its row here to stay green.
    #[test]
    fn l2_trace_width_is_read_off_the_matrix() {
        let air = L2ShapeSAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        assert_eq!(trace.width(), L2_WIDTH, "width must be the matrix's own");

        const L1_MINTED: usize = 643;
        let roles_5bit = 8 // PR ring 24 → 32 limbs (4 slots × 5 bits; 128 program slots)
            + 4 // D: PR[0] decomposition 16 → 20 bits
            + 1 // RB: role bits 4 → 5
            + 4; // LO: the four materialized low half-selectors (degree stays 4)
        let shape_s_roles = 2 // sel(AREG), sel(BREG)          — NSEL 14 → 16
            + 1 // inj(AREG)                                    — NINJ 6 → 7
            + 1 // SE[areg] = sel(areg)·ep                      — NSE 7 → 8
            + 1 // BGC[breg] = gperm·sel(breg)                  — NBGC 5 → 6
            + 1; // INJRE = inj(areg)·ep
        let witness = 2; // W13 = asset, W14 = flags            — NW 13 → 15
        let assets = 6 // AG: capture gates [in1, in2, o1, o2, r1, r2]
            + 6 // AC: capture-and-hold asset accumulators (16-bit chunk 0)
            + 4 // SEL2: o1a, o2a, f1, q
            + 1 // QINV: the nonzero-inverse witness for ¬q
            + 2 // CQ: close·q, close·(1 − q)
            + 2; // SG: AG[o1]·o1a, AG[o2]·o2a
        let balance_row_2 = 4 // BL2 accumulators
            + 9; // BLC2 carry encodings
        assert_eq!(roles_5bit, 17);
        assert_eq!(shape_s_roles, 6);
        assert_eq!(assets, 21);
        assert_eq!(balance_row_2, 13);
        assert_eq!(
            trace.width(),
            L1_MINTED + roles_5bit + shape_s_roles + witness + assets + balance_row_2,
            "width must be 643 plus exactly the columns named above"
        );
        assert_eq!(trace.width(), 702, "the shape-S width");
        assert_eq!(crate::narrow::NARROW_WIDTH, L1_MINTED, "the L1 width this accounts over");
    }

    /// The quotient degree does not move: max constraint degree **4** (the 16
    /// materialized role selectors, `lo · pair · bit`), 4 quotient chunks —
    /// the L1's ceiling exactly, read off Plonky3's symbolic evaluation.
    #[test]
    fn l2_quotient_degree_matches_the_l1() {
        use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
        let air = L2ShapeSAir::chain_only(SHAPE_S_LOG_HEIGHT);
        let layout = AirLayout::from_air::<F>(&air);
        let deg = get_max_constraint_degree::<F, _>(&air, layout);
        assert_eq!(deg, 4, "max constraint degree");
        assert_eq!((deg - 1).next_power_of_two(), 4, "quotient chunks");
        let cs = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
        let mut hist = std::collections::BTreeMap::new();
        for c in &cs {
            *hist.entry(c.degree_multiple()).or_insert(0usize) += 1;
        }
        assert_eq!(hist.keys().max(), Some(&4), "nothing above degree 4");
        // The deg-4 population is exactly the 16 role selectors: the L1's 15
        // (14 selectors + EG3[1]) becomes 16 selectors + EG3[1] = 17.
        assert_eq!(hist.get(&4).copied().unwrap_or(0), 17, "deg-4 constraints");
    }

    /// Program geometry: 120 perms, fits 2^19, the warm-up severing holds
    /// (perm 0 dummy, perm 1 the ANK override, perm 2 the first reader).
    #[test]
    fn l2_program_geometry() {
        let inst = honest();
        assert_eq!(SHAPE_S_PERMS, 120);
        assert!(SHAPE_S_PERMS * ROWS_PER_PERM <= 1 << SHAPE_S_LOG_HEIGHT);
        assert!(SHAPE_S_PERMS <= PROGRAM_SLOTS);
        let p = &inst.air.program;
        assert_eq!(p[0], ROLE_DUMMY);
        assert_eq!(p[1], ROLE_ANK);
        assert_eq!(p[2], ROLE_NF);
        // Per input: ANK NF BNF AREG 16×MERKLE BREG ARKM ACM 32×MERKLE BANCHOR.
        let mut want = vec![ROLE_ANK, ROLE_NF, ROLE_BNF1, ROLE_AREG];
        want.extend(std::iter::repeat(ROLE_MERKLE).take(REGISTRY_DEPTH));
        want.extend([ROLE_BREG, ROLE_ARKM, ROLE_ACM]);
        want.extend(std::iter::repeat(ROLE_MERKLE).take(MERKLE_DEPTH));
        want.push(ROLE_BANCHOR);
        assert_eq!(&p[1..1 + want.len()], &want[..], "input chain 1");
        want[2] = ROLE_BNF2;
        assert_eq!(&p[1 + want.len()..1 + 2 * want.len()], &want[..], "input chain 2");
        let tail = [ROLE_ACMOUT, ROLE_BCM1, ROLE_ARHO, ROLE_ACMOUT, ROLE_BCM2, ROLE_BAL, ROLE_END];
        assert_eq!(&p[1 + 2 * want.len()..SHAPE_S_PERMS], &tail[..]);
        assert!(p[SHAPE_S_PERMS..].iter().all(|r| *r == ROLE_DUMMY));
    }

    /// The latch `L` is high across exactly chain 1's `AREG … BANCHOR` span —
    /// it now starts at the registry opening, which is what lets it serve as
    /// the "which input" signal for both the note asset and the leaf asset.
    #[test]
    fn l2_latch_span_covers_chain_1_including_its_registry_opening() {
        let inst = honest();
        let p = &inst.air.program;
        let bnf2 = slot_of(p, ROLE_BNF2, 0);
        let areg2 = slot_of(p, ROLE_AREG, 1);
        let banchor2 = slot_of(p, ROLE_BANCHOR, 1);
        assert_eq!(areg2, bnf2 + 1, "chain 1's AREG follows its BNF2");
        let trace = inst.air.generate_trace::<F>(0);
        let lo = areg2 * ROWS_PER_PERM;
        let hi = (banchor2 + 1) * ROWS_PER_PERM;
        for row in 0..(1usize << inst.air.log_height) {
            let l = trace.values[row * L2_WIDTH + LATCH_COL];
            let want = if (lo..hi).contains(&row) { F::ONE } else { F::ZERO };
            assert_eq!(l, want, "latch at row {row} (span {lo}..{hi})");
        }
    }

    /// The captured asset ids are exactly the notes' and leaves', read off the
    /// trace at the balance close row.
    #[test]
    fn l2_asset_captures_read_the_right_lanes() {
        // asset 3: 100 in, 100 out; asset 0: 50 in, nothing out — deliberately
        // unbalanced, because the captures are witness-only and this reads
        // them off the trace regardless of SAT.
        let inst = bucket(100, 3, 50, 0, 60, 3, 40, 3, 0);
        let trace = inst.air.generate_trace::<F>(0);
        let bal = slot_of(&inst.air.program, ROLE_BAL, 0);
        let row = (bal + 1) * ROWS_PER_PERM - 1;
        let at = |k: usize| trace.values[row * L2_WIDTH + AC_OFF + k];
        assert_eq!(at(AG_IN1), F::from_u32(3), "A₁");
        assert_eq!(at(AG_IN2), F::from_u32(0), "A₂");
        assert_eq!(at(AG_O1), F::from_u32(3), "O₁");
        assert_eq!(at(AG_O2), F::from_u32(3), "O₂");
        assert_eq!(at(AG_R1), F::from_u32(3), "R₁");
        assert_eq!(at(AG_R2), F::from_u32(0), "R₂");
    }

    // -----------------------------------------------------------------------
    // The #219 dummy slot on L2.
    // -----------------------------------------------------------------------

    fn dummy_parts() -> (L2TxInput, L2TxInput, [L2TxOutput; 2]) {
        let real = L2TxInput {
            sk: [0x11, 0x22, 0x33, 0x44],
            value: 1_000,
            asset: 0,
            rho: [0x55, 0x66, 0x77, 0x88],
            rseed: [0x99, 0xaa, 0xbb, 0xcc],
            d: [0xd1, 0xd2],
        };
        let dummy = L2TxInput {
            sk: [0xf00d, 0xf00e, 0xf00f, 0xf010],
            value: 0,
            asset: 0,
            rho: [0xbeef01, 0xbeef02, 0xbeef03, 0xbeef04],
            rseed: [0xcafe01, 0xcafe02, 0xcafe03, 0xcafe04],
            d: [0, 0],
        };
        let outputs = [
            L2TxOutput { value: 600, asset: 0, rkm: [2; 4], rho: [3; 4], rseed: [4; 4] },
            L2TxOutput { value: 399, asset: 0, rkm: [5; 4], rho: [6; 4], rseed: [7; 4] },
        ];
        (real, dummy, outputs)
    }

    /// A one-real-input asset-0 spend with a dummy slot satisfies the AIR; the
    /// dummy slot's witness is genuinely off the commitment tree.
    #[test]
    fn l2_dummy1_satisfies_constraints() {
        let (real, dummy, outputs) = dummy_parts();
        let inst = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        assert!(inst.air.dv);
        let (_, _, cm_dummy) = derive_input_l2(&dummy);
        assert_ne!(off_tree_witness().fold_root(&cm_dummy), inst.anchor, "precondition: dummy off-tree");
        let pvs = pvs_of(&inst);
        let trace = inst.air.generate_trace::<F>(0);
        check_constraints(&inst.air, &trace, &pvs);
        // And with dv = 0 the same instance is refused (the latch is doing it).
        let mut inert = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        inert.air.dv = false;
        assert!(!sat(&inert));
    }

    /// A stablecoin one-input spend with a dummy: asset 7 in, asset 7 out,
    /// fee 0 — the dummy IS the asset-0 note. And with a nonzero fee it is
    /// refused: nothing in asset 0 can pay it.
    #[test]
    fn l2_dummy1_stablecoin_spend() {
        let (mut real, dummy, mut outputs) = dummy_parts();
        real.asset = 7;
        outputs[0].asset = 7;
        outputs[1].asset = 7;
        outputs[1].value = 400;
        let inst = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 0);
        assert!(sat(&inst), "a fee-less stablecoin spend with a dummy asset-0 slot");
        outputs[1].value = 399;
        let mut bad = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        assert!(!any_assignment_satisfies(&mut bad), "a fee with no real asset-0 input VERIFIED");
    }

    /// 🔴 The dummy's value AND asset are forced to 0 by the AIR, not the
    /// builder: a dummy carrying 500 of asset 0, or 0 of asset 7, is refused.
    #[test]
    fn l2_dummy_slot_value_and_asset_must_be_zero() {
        let (real, dummy, outputs) = dummy_parts();
        let (_, _, cm_real) = derive_input_l2(&real);
        let (w_real, anchor) = fabricated_single_tree(&cm_real);
        let build = |d: &L2TxInput, fee: u64, leaf2: RegistryLeaf| {
            let leaves = [RegistryLeaf::cloaked(0), leaf2];
            let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
            let mut inst = build_bucket_l2_with_witnesses(
                SHAPE_S_LOG_HEIGHT,
                &[real.clone(), d.clone()],
                &outputs,
                fee,
                &[w_real, off_tree_witness()],
                anchor,
                &leaves,
                &rw,
                root,
            );
            inst.air.dv = true;
            inst
        };
        let mut minted = dummy.clone();
        minted.value = 500;
        let mut a = build(&minted, 501, RegistryLeaf::cloaked(0));
        assert!(!any_assignment_satisfies(&mut a), "a nonzero dummy value is a mint");
        let mut wrong_asset = dummy.clone();
        wrong_asset.asset = 7;
        let mut b = build(&wrong_asset, 1, RegistryLeaf::cloaked(7));
        assert!(!any_assignment_satisfies(&mut b), "a dummy in a non-fee asset VERIFIED");
    }

    /// `dv` cannot make slot 0 the dummy (the latch's span is chain 1's).
    #[test]
    fn l2_dv_cannot_make_slot_0_a_dummy() {
        let (real, dummy, outputs) = dummy_parts();
        let (_, _, cm_real) = derive_input_l2(&real);
        let (w_real, anchor) = fabricated_single_tree(&cm_real);
        let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(0)];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let mut inst = build_bucket_l2_with_witnesses(
            SHAPE_S_LOG_HEIGHT,
            &[dummy.clone(), real.clone()],
            &outputs,
            1,
            &[off_tree_witness(), w_real],
            anchor,
            &leaves,
            &rw,
            root,
        );
        inst.air.dv = true;
        assert!(!any_assignment_satisfies(&mut inst), "slot 0's anchor bind must fire regardless of dv");
    }

    /// 🔴 The option-4 forgery shape on the **latch** (stage-0 ruling): under
    /// the dummy shape (`dv = 1`, slot 1 off-tree, anchor relaxed) both seeds
    /// still derive from the REAL slot 0's nullifier, and a forged seed with
    /// its commitment republished is refused — the latch's relaxation must not
    /// reach the third bank. `narrow.rs`'s
    /// `q215_dummy_composition_keeps_both_seeds_on_the_real_nullifier`, on L2.
    #[test]
    fn l2_dummy_shape_forged_seed_is_refused() {
        let (real, dummy, outputs) = dummy_parts();
        let inst = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        assert!(inst.air.dv && sat(&inst), "precondition: the honest dummy shape verifies");
        let p = &inst.air.program;
        let out0 = slot_of(p, ROLE_ACMOUT, 0);
        let out1 = slot_of(p, ROLE_ACMOUT, 1);
        let arho = slot_of(p, ROLE_ARHO, 0);
        let seed = |sl: usize| -> [u64; 4] { inst.air.slot_witness[sl].w[5..9].try_into().unwrap() };
        assert_eq!(seed(out0), derive_output_rho(&inst.nf[0], 0), "ρ′₀ = nf₀");
        assert_eq!(seed(out1), derive_output_rho(&inst.nf[0], 1), "ρ′₁ = H(nf₀ ‖ D_P)");
        assert_eq!(seed(arho), inst.nf[0], "ARHO absorbs slot 0's nullifier");
        assert_ne!(seed(arho), inst.nf[1], "the dummy's invented nullifier feeds no seed");
        // The forgery: output 1's seed is the prover's, the commitment is
        // republished to open at it — every bind but the third bank holds.
        let mut forged = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        forged.air.slot_witness[out1].w[5..9].copy_from_slice(&[0xbad_5eed, 1, 2, 3]);
        republish(&mut forged, 1);
        assert!(!any_assignment_satisfies(&mut forged), "a forged seed under the dummy shape VERIFIED");
        // And output 0 the same way.
        let mut forged0 = build_bucket_l2_dummy1_fabricated(SHAPE_S_LOG_HEIGHT, &real, &dummy, &outputs, 1);
        forged0.air.slot_witness[out0].w[5..9].copy_from_slice(&[0xdead_beef, 4, 5, 6]);
        republish(&mut forged0, 0);
        assert!(!any_assignment_satisfies(&mut forged0), "a forged ρ′₀ under the dummy shape VERIFIED");
    }

    /// The option-4 seed binding carries over: a prover-chosen ρ′₀ with the
    /// matching commitment republished is refused on L2 too.
    #[test]
    fn l2_output_rho_is_still_bound() {
        let mut inst = honest();
        let s = slot_of(&inst.air.program, ROLE_ACMOUT, 0);
        inst.air.slot_witness[s].w[5..9].copy_from_slice(&[0xdead_beef, 1, 2, 3]);
        republish(&mut inst, 0);
        assert!(!sat(&inst), "a free output seed VERIFIED on L2");
        // The published commitments are openings at the derived seeds.
        let inst = honest();
        let s0 = slot_of(&inst.air.program, ROLE_ACMOUT, 0);
        let seed: [u64; 4] = inst.air.slot_witness[s0].w[5..9].try_into().unwrap();
        assert_eq!(seed, derive_output_rho(&inst.nf[0], 0));
    }
}
