//! A2 — the L2 circuit family's **shape R** (registry writes), lab issue #724.
//!
//! A **new AIR type beside [`crate::l2::L2ShapeSAir`] and
//! [`crate::l2p::L2ShapePAir`]** — S and P are measured, digest-pinned and
//! frozen as goldens, so R is a third fork of the narrow engine (structure for
//! structure, the discipline `l2.rs` applied to `narrow.rs`), never an edit to
//! either. Pure helpers with identical semantics are imported from `l2`, `l2p`
//! and `narrow`.
//!
//! ## The statement (lab #724 stage-0 ruling)
//!
//! One transaction writes **one registry slot** and pays for it:
//!
//! - **the write**: the registry root moves `old_root → new_root` by replacing
//!   the leaf at slot `i` — `old_leaf` (or the empty digest) becomes
//!   `new_leaf`, every sibling unchanged. `i` is the new leaf's `asset` lane:
//!   the path bits of **both** folds are bound to its 16 bits, so R keeps the
//!   registry invariant "slot `i` holds the empty digest or a leaf whose asset
//!   lane is `i`" that S and P rely on (they prove *a* path and trust the lane).
//! - **registration** (`REG = 1`): permissionless, into an **empty** slot — the
//!   old fold starts from the zero digest.
//! - **update** (`REG = 0`): the old leaf is opened, its `asset` must equal the
//!   new one's, and the writer proves knowledge of `isk` with
//!   `H(isk ‖ D_I) = old_leaf.issuer_key` (the `AISS` block of shape P).
//! - **asset 0 is never writable** (a nonzero-inverse witness on the asset).
//! - **`mode ⇒ roots`** on the new leaf: Cloaked ⇒ `freeze_root`,
//!   `allow_root` zero and `flags` clear; Hybrid ⇒ `allow_root` zero;
//!   Regulated ⇒ either may be nonzero. `mode ∈ {0, 1, 2}`.
//! - **the fee** (ruling option (c)): R carries its own 1-in / 1-out spend in
//!   the fee asset — S's input chain once, one output, balance `in = out + fee`
//!   on one borrow chain, both notes asset 0. The output's `ρ` is the input's
//!   nullifier (option 4's `ρ′₀ = nf₀`; the third bank, one window).
//!
//! Public values: `anchor ‖ nf ‖ cm ‖ fee ‖ old_root ‖ new_root ‖ asset`.
//!
//! ### Program order (79 perms → 2^18)
//!
//! ```text
//! [DUMMY]
//! ANK → NF → BNF1 → ARKM → ACM → 32×MERKLE → BANCHOR          the fee input
//! ACMOUT → BCM1                                               the fee output
//! AISS → AREG_OLD → AREG_NEW                                  isk, both leaves
//! (MO_i → MN_i) for i = 1..15 → MO_16 → BREG_OLD → MN_16 → BREG_NEW
//! BAL
//! ```
//!
//! ### The two folds share one set of siblings
//!
//! The old and new folds are **interleaved** level by level: `MO_i` folds the
//! old chain's level `i`, `MN_i` the new chain's, over the same sibling. Both
//! read their running digest from witness lanes `W4..7` (a new injection
//! class, `MERKLE_W`: the node block is `W0..3`/`W4..7` muxed on the path
//! bit), because the Keccak chain carries only one digest and here two chains
//! alternate. Three banks of 16 accumulators each bind the witnesses to the
//! chain:
//!
//! - `C_old`: `+a` at `MN_i`'s boundary (the chained digest there is `MO_i`'s
//!   output) and at `AREG_NEW`'s when `REG = 0` (`AREG_OLD`'s output, the old
//!   leaf hash), `−W4..7` at `MO_{i+1}`'s; closed at every `MO`'s last row.
//! - `C_new`: `+a` at `MO_i`'s boundary (`AREG_NEW`'s output for `i = 1`,
//!   `MN_{i−1}`'s after), `−W4..7` at `MN_i`'s; closed at every `MN`.
//! - `SIB`: `+W0..3` at `MO_i`, `−W0..3` at `MN_i`; closed at every `MN`.
//!
//! The path bit of `MN_i` is `MO_i`'s (a transition on `MO`'s last row; across
//! `BREG_OLD` for level 16), and `MO`'s 16 bits are accumulated into `PACC`
//! and closed against the new leaf's asset. This is option (i) of the ruling's
//! sibling-sharing question — 48 accumulator columns; option (ii), a separate
//! 16 × 16 equality per level, is 256. `REG = 1` gates the `C_old` seed off,
//! so the old fold's first digest must be zero: the empty slot.
//!
//! ### No epoch
//!
//! 79 perms fit one period of the 128-slot program ring at 2^18 (85.3 perms),
//! so there is no wrapped second program for S's epoch column to switch off —
//! R has no `EP`, `GWRAP`, `SE` or `ROLE_END`. A taller trace only adds rows
//! whose gates re-fire against the same public values: more constraints on
//! the prover, never fewer.
//!
//! ### Column accounting: 726 — see `l2r_trace_width_is_read_off_the_matrix`.

use std::collections::BTreeMap;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::l2::{
    derive_input_l2, l2_cm, L2TxInput, L2TxOutput, RegistryLeaf, RegistryWitness, ASSET_BITS,
    REGISTRY_DEPTH, ROLE_ACM, ROLE_ACMOUT, ROLE_ANK, ROLE_AREG, ROLE_ARKM, ROLE_BAL,
    ROLE_BANCHOR, ROLE_BCM1, ROLE_BNF1, ROLE_BREG, ROLE_DUMMY, ROLE_MERKLE, ROLE_NF,
    ROWS_PER_PERM,
};
use crate::l2p::ROLE_AISS;
use crate::narrow::{fabricated_single_tree, pv_chunks, MerkleWitness, MERKLE_DEPTH};
use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — the narrow engine verbatim, the M3 machinery at 5-bit codes (as
// `l2.rs`), then shape R's gates, banks and declarations.
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
// --- M3 program machinery (as l2.rs: 5-bit role codes, 32-limb ring) ---
const PB_OFF: usize = B_OFF + 7; // 402: 24: perm-boundary ring [1,0,..,0]
const PH_OFF: usize = PB_OFF + 24; // 426: 4: perm-phase ring (mod-4 counter)
const PR_LIMBS: usize = 32;
const PR_OFF: usize = PH_OFF + 4; // 430: 32: program ring, 4 slots x 5 bits/limb
const ROLE_BITS: usize = 5;
const D_OFF: usize = PR_OFF + PR_LIMBS; // 462: 20: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 4 * ROLE_BITS; // 482: 5: current perm's role bits
const LO_OFF: usize = RB_OFF + ROLE_BITS; // 487: 4: materialized low half-selectors
const NSEL: usize = 17; // materialized role selectors, order = SEL_CODES
const SEL_OFF: usize = LO_OFF + 4; // 491
/// Injection flags [mrk+nf, ank, arkm, acm, acmout, aiss] (the two leaf and the
/// two `MERKLE_W` classes are carried by the four split flags below).
const NINJ: usize = 6;
const INJ_OFF: usize = SEL_OFF + NSEL; // 508
const INJOLD_COL: usize = INJ_OFF + NINJ; // 514: bnd·sel(AREG_OLD)
const INJNEW_COL: usize = INJOLD_COL + 1; // 515: bnd·sel(AREG_NEW)
const MOB_COL: usize = INJNEW_COL + 1; // 516: bnd·sel(MO)
const MNB_COL: usize = MOB_COL + 1; // 517: bnd·sel(MN)
const G4_COL: usize = MNB_COL + 1; // 518: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 519: merkle path bit (constant per perm)
const NW: usize = 15;
const W_OFF: usize = PBIT_COL + 1; // 520: 15 witness lanes (role-multiplexed)
const NFB_COL: usize = W_OFF + NW; // 535: bnd·sel(NF) — banks 1 and 2's pos gate
/// Close gates `gperm·sel(role)` [arkm, acm, acmout, bal, mo, mn, areg_old].
const NCL: usize = 7;
const CL_OFF: usize = NFB_COL + 1; // 536
const CL_ARKM: usize = 0;
const CL_ACM: usize = 1;
const CL_ACMOUT: usize = 2;
const CL_BAL: usize = 3;
const CL_MO: usize = 4;
const CL_MN: usize = 5;
const CL_AOLD: usize = 6;
const BGCAP_COL: usize = CL_OFF + NCL; // 543: bind capture gate
/// Bind close gates [banchor, bnf1, bcm1, breg_old, breg_new]; the last is
/// also R's registry close row (`RCLOSE`).
const NBGC: usize = 5;
const BGC_OFF: usize = BGCAP_COL + 1; // 544
const BGC_BREG_NEW: usize = 4;
const BQ_OFF: usize = BGC_OFF + NBGC; // 549: 16: bind bank
const EQ_OFF: usize = BQ_OFF + 16; // 565: 32: banks 1 (nk) and 2 (rho)
const EQ3_OFF: usize = EQ_OFF + 32; // 597: 16: bank 3 (output rho = nf)
const BL_OFF: usize = EQ3_OFF + 16; // 613: 4: balance accumulators
const BLC_OFF: usize = BL_OFF + 4; // 617: 9: carry encodings
const EFF_OFF: usize = BLC_OFF + 9; // 626: 25: effective round input
const CO_OFF: usize = EFF_OFF + 25; // 651: 16: C_old — old-chain carry
const CN_OFF: usize = CO_OFF + 16; // 667: 16: C_new — new-chain carry
const SB_OFF: usize = CN_OFF + 16; // 683: 16: SIB — shared siblings
const IS_OFF: usize = SB_OFF + 16; // 699: 16: ISS — H(isk ‖ D_I) = old issuer_key
const POW_COL: usize = IS_OFF + 16; // 715: 2^level at MO's first row
const PACC_COL: usize = POW_COL + 1; // 716: Σ pbit_i·2^i over MO
const AC_OLD_COL: usize = PACC_COL + 1; // 717: old leaf asset (chunk 0 of W13)
const AC_NEW_COL: usize = AC_OLD_COL + 1; // 718: new leaf asset
const MC_COL: usize = AC_NEW_COL + 1; // 719: new leaf mode (chunk 0 of W4)
/// Per-transaction declarations, constant for the trace.
const REG_COL: usize = MC_COL + 1; // 720: 1 = registration, 0 = update
const DC_COL: usize = REG_COL + 1; // 721: [mode = Cloaked]
const DR_COL: usize = DC_COL + 1; // 722: [mode = Regulated]
const MINV_COL: usize = DR_COL + 1; // 723: mode⁻¹ when mode ≠ 0
const RINV_COL: usize = MINV_COL + 1; // 724: (mode − 2)⁻¹ when mode ≠ 2
const AINV_COL: usize = RINV_COL + 1; // 725: asset⁻¹ (asset 0 unwritable)

/// The shape-R trace width.
pub const L2R_WIDTH: usize = AINV_COL + 1; // 726

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 4 * PR_LIMBS; // 128

/// The new leaf block: `ROLE_AREG`'s injection, the second leaf.
pub const ROLE_AREG_NEW: u32 = 23;
/// `MERKLE_W`, old chain: `H(node)` with the running digest from `W4..7`.
pub const ROLE_MO: u32 = 24;
/// `MERKLE_W`, new chain.
pub const ROLE_MN: u32 = 25;
/// New-root bind; also the row where R's registry closes are checked.
pub const ROLE_BREG_NEW: u32 = 26;
/// The old leaf block — shape S's `ROLE_AREG`, same code, same injection.
pub const ROLE_AREG_OLD: u32 = ROLE_AREG;
/// The old-root bind — shape S's `ROLE_BREG`.
pub const ROLE_BREG_OLD: u32 = ROLE_BREG;

/// Role codes in materialized-selector order.
const SEL_CODES: [u32; NSEL] = [
    ROLE_MERKLE,
    ROLE_NF,
    ROLE_ANK,
    ROLE_ARKM,
    ROLE_ACM,
    ROLE_ACMOUT,
    ROLE_BANCHOR,
    ROLE_BNF1,
    ROLE_BCM1,
    ROLE_BAL,
    ROLE_AISS,
    ROLE_AREG_OLD,
    ROLE_AREG_NEW,
    ROLE_MO,
    ROLE_MN,
    ROLE_BREG_OLD,
    ROLE_BREG_NEW,
];
const SEL_MERKLE: usize = 0;
const SEL_NF: usize = 1;
const SEL_ANK: usize = 2;
const SEL_ARKM: usize = 3;
const SEL_ACM: usize = 4;
const SEL_ACMOUT: usize = 5;
const SEL_BANCHOR: usize = 6;
const SEL_BNF1: usize = 7;
const SEL_BCM1: usize = 8;
const SEL_BAL: usize = 9;
const SEL_AISS: usize = 10;
const SEL_AOLD: usize = 11;
const SEL_ANEW: usize = 12;
const SEL_MO: usize = 13;
const SEL_MN: usize = 14;
const SEL_BROLD: usize = 15;
const SEL_BRNEW: usize = 16;
/// The bind roles, in `BGC` order.
const BIND_SELS: [usize; NBGC] = [SEL_BANCHOR, SEL_BNF1, SEL_BCM1, SEL_BROLD, SEL_BRNEW];

/// Public-value layout: anchor, nf, cm (16 chunks each), fee (4), old and new
/// registry root (16 each), the written asset id (one element).
pub const PV_ANCHOR: usize = 0;
pub const PV_NF: usize = 16;
pub const PV_CM: usize = 32;
pub const PV_FEE: usize = 48;
pub const PV_OLD_ROOT: usize = 52;
pub const PV_NEW_ROOT: usize = 68;
pub const PV_ASSET: usize = 84;
pub const PV_LEN: usize = 85;
const PV_BIND: [usize; NBGC] = [PV_ANCHOR, PV_NF, PV_CM, PV_OLD_ROOT, PV_NEW_ROOT];

/// Build the full public-value vector for a shape-R instance.
pub fn pv_vec_r(
    anchor: &[u64; 4],
    nf: &[u64; 4],
    cm: &[u64; 4],
    fee: u64,
    old_root: &[u64; 4],
    new_root: &[u64; 4],
    asset: u64,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, nf, cm] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    out.extend_from_slice(&pv_chunks(old_root));
    out.extend_from_slice(&pv_chunks(new_root));
    out.push(asset as u32);
    debug_assert_eq!(out.len(), PV_LEN);
    out
}

/// Perm slots used by the shape-R program, INCLUDING the leading dummy slot:
/// 1 + (5 + 32 + 1) + 2 + 3 + 2 × 16 + 2 + 1 = **79**, at 3072 rows each =
/// 242,688 rows → 2^18 (262,144), 6.3 spare perm slots.
pub const SHAPE_R_PERMS: usize = 1 + (5 + MERKLE_DEPTH + 1) + 2 + 3 + 2 * REGISTRY_DEPTH + 2 + 1;
/// log2 of the shape-R trace height.
pub const SHAPE_R_LOG_HEIGHT: usize = 18;
const _: () = assert!(SHAPE_R_PERMS * ROWS_PER_PERM <= 1 << SHAPE_R_LOG_HEIGHT);
// One program period covers the whole trace — the "no epoch" premise.
const _: () = assert!((1 << SHAPE_R_LOG_HEIGHT) / ROWS_PER_PERM < PROGRAM_SLOTS);

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
pub struct L2RSlotWitness {
    pub w: [u64; NW],
    pub pbit: bool,
}

impl Default for L2RSlotWitness {
    fn default() -> Self {
        Self { w: [0; NW], pbit: false }
    }
}

/// Shape R of the L2 circuit family.
#[cfg_attr(test, derive(Clone))] // the tests tamper owned copies; non-test build unchanged
pub struct L2ShapeRAir {
    pub log_height: usize,
    /// 5-bit role code per program slot.
    pub program: [u32; PROGRAM_SLOTS],
    pub slot_witness: Vec<L2RSlotWitness>,
    /// Public fee (needed to witness the balance carry encodings).
    pub fee: u64,
    /// `true` = registration into an empty slot, `false` = update of a leaf.
    pub reg: bool,
}

impl L2ShapeRAir {
    /// Every perm slot dummy, pure chaining — the geometry probe.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
            fee: 0,
            reg: true,
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

/// Number of periodic columns: the narrow engine's 39, `lo16` and `lo2`.
const NPERIODIC: usize = 41;
/// `lo16 = [z < 16]` — asset lanes are 16-bit registry indices.
const PER_LO16: usize = 39;
/// `lo2 = [z < 2]` — the mode lane is two bits.
const PER_LO2: usize = 40;

impl<F: Field> BaseAir<F> for L2ShapeRAir {
    fn width(&self) -> usize {
        L2R_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PV_LEN
    }

    fn num_periodic_columns(&self) -> usize {
        NPERIODIC
    }

    /// The narrow engine's 39 period-128 columns ([mrow, u63, e1_0..e1_24,
    /// blast, sel_0..sel_6, pwk_0..pwk_3]) plus `lo16` and `lo2`.
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
            cols[PER_LO2].push(F::from_bool(z < 2));
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

impl<AB: AirBuilder> Air<AB> for L2ShapeRAir
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
        let lo2 = per[PER_LO2].clone();
        let pwk = |j: usize| per[35 + j].clone();
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

        // --- Program machinery (as l2.rs) ---
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
        builder.assert_eq(
            local[INJ_OFF].clone(),
            bnd.clone() * (sel_role(SEL_MERKLE) + sel_role(SEL_NF)),
        );
        for (i, s) in [SEL_ANK, SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_AISS].iter().enumerate() {
            builder.assert_eq(local[INJ_OFF + 1 + i].clone(), bnd.clone() * sel_role(*s));
        }
        for (col, s) in [
            (INJOLD_COL, SEL_AOLD),
            (INJNEW_COL, SEL_ANEW),
            (MOB_COL, SEL_MO),
            (MNB_COL, SEL_MN),
            (NFB_COL, SEL_NF),
        ] {
            builder.assert_eq(local[col].clone(), bnd.clone() * sel_role(s));
        }
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
        let injold = local[INJOLD_COL].clone();
        let injnew = local[INJNEW_COL].clone();
        let mob = local[MOB_COL].clone();
        let mnb = local[MNB_COL].clone();
        let nfb = local[NFB_COL].clone();
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
            // AISS (shape P's): isk = W0..4, D_I = lane 4 bit 7, pad at lane 5.
            let msg_aiss: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(3),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // Registry leaf (shape S's AREG block), old and new alike.
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
            // MERKLE_W: the running digest is W4..7, the sibling W0..3; the
            // node block is `sib ‖ digest` when pbit, else `digest ‖ sib`.
            let msg_mw: AB::Expr = match l {
                0..=3 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * w(l + 4),
                4..=7 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * w(l - 4),
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let expr = a(l)
                + inj(0) * (msg_mrk - a(l))
                + inj(1) * (msg_ank - a(l))
                + inj(2) * (msg_arkm - a(l))
                + inj(3) * (msg_acm - a(l))
                + inj(4) * (msg_acmout - a(l))
                + inj(5) * (msg_aiss - a(l))
                + (injold.clone() + injnew.clone()) * (msg_areg - a(l))
                + (mob.clone() + mnb.clone()) * (msg_mw - a(l));
            builder.assert_eq(eff(l), expr);
        }

        // --- Close gates ---
        let cl = |k: usize| local[CL_OFF + k].clone();
        for (k, s) in [SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_BAL, SEL_MO, SEL_MN, SEL_AOLD]
            .iter()
            .enumerate()
        {
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

        // --- Bind bank: five closes, each against its public digest ---
        for (x, base) in PV_BIND.iter().enumerate() {
            for j in 0..16 {
                builder.assert_zero(
                    local[BGC_OFF + x].clone() * (local[BQ_OFF + j].clone() - pv(base + j)),
                );
            }
        }

        // --- Bank closes ---
        for j in 0..16 {
            builder.assert_zero(cl(CL_ARKM) * local[EQ_OFF + j].clone());
            builder.assert_zero(cl(CL_ACM) * local[EQ_OFF + 16 + j].clone());
            // Output ρ = the input's nullifier (option 4's ρ′₀ = nf₀).
            builder.assert_zero(cl(CL_ACMOUT) * (local[EQ3_OFF + j].clone() - pv(PV_NF + j)));
            builder.assert_zero(cl(CL_MO) * local[CO_OFF + j].clone());
            builder.assert_zero(cl(CL_MN) * local[CN_OFF + j].clone());
            builder.assert_zero(cl(CL_MN) * local[SB_OFF + j].clone());
            builder.assert_zero(cl(CL_AOLD) * local[IS_OFF + j].clone());
        }
        for off in [BQ_OFF, EQ_OFF, EQ_OFF + 16, EQ3_OFF, CO_OFF, CN_OFF, SB_OFF, IS_OFF] {
            for j in 0..16 {
                builder.when_first_row().assert_zero(local[off + j].clone());
            }
        }

        // --- The fee spend: asset 0 in and out, one borrow chain ---
        builder.assert_zero(inj(3) * w(13));
        builder.assert_zero(inj(4) * w(13));
        for k in 0..9 {
            builder.assert_bool(local[BLC_OFF + k].clone());
        }
        for j in 0..4 {
            builder.when_first_row().assert_zero(local[BL_OFF + j].clone());
        }
        {
            let carry = |j: usize| -> AB::Expr {
                local[BLC_OFF + 3 * j].clone()
                    + local[BLC_OFF + 3 * j + 1].clone() * two.clone()
                    + local[BLC_OFF + 3 * j + 2].clone() * two.clone() * two.clone()
                    - two.clone()
            };
            let bl = |j: usize| local[BL_OFF + j].clone();
            let w16 = AB::Expr::from_u32(1 << 16);
            let close = cl(CL_BAL);
            builder.assert_zero(close.clone() * (bl(0) - pv(PV_FEE) - w16.clone() * carry(0)));
            for j in 1..3 {
                builder.assert_zero(
                    close.clone() * (bl(j) + carry(j - 1) - pv(PV_FEE + j) - w16.clone() * carry(j)),
                );
            }
            builder.assert_zero(close * (bl(3) + carry(2) - pv(PV_FEE + 3)));
        }

        // --- The registry write ---
        let reg = local[REG_COL].clone();
        let dc = local[DC_COL].clone();
        let dr = local[DR_COL].clone();
        builder.assert_bool(reg.clone());
        builder.assert_bool(dc.clone());
        builder.assert_bool(dr.clone());
        builder.when_first_row().assert_eq(local[POW_COL].clone(), AB::Expr::ONE);
        for col in [PACC_COL, AC_OLD_COL, AC_NEW_COL, MC_COL] {
            builder.when_first_row().assert_zero(local[col].clone());
        }
        // Both leaves' asset lanes are 16-bit; the mode lane is 2-bit.
        let hi16 = AB::Expr::ONE - lo16;
        builder.assert_zero(injold.clone() * hi16.clone() * w(13));
        builder.assert_zero(injnew.clone() * hi16 * w(13));
        builder.assert_zero(injnew.clone() * (AB::Expr::ONE - lo2) * w(4));
        // mode ⇒ roots, bit by bit on the new leaf's boundary rows.
        for l in 0..4 {
            builder.assert_zero(injnew.clone() * dc.clone() * w(5 + l));
            builder.assert_zero(injnew.clone() * (AB::Expr::ONE - dr.clone()) * w(9 + l));
        }
        builder.assert_zero(injnew.clone() * dc.clone() * w(14));
        // The closes, on BREG_NEW's last row — every capture is behind it.
        {
            let rclose = local[BGC_OFF + BGC_BREG_NEW].clone();
            let ac_old = local[AC_OLD_COL].clone();
            let ac_new = local[AC_NEW_COL].clone();
            let mc = local[MC_COL].clone();
            // The written slot IS the new leaf's asset: both folds' path bits.
            builder.assert_zero(rclose.clone() * (local[PACC_COL].clone() - ac_new.clone()));
            // An update keeps the asset.
            builder.assert_zero(
                rclose.clone() * (AB::Expr::ONE - reg.clone()) * (ac_old - ac_new.clone()),
            );
            // Asset 0 is never writable.
            builder.assert_zero(
                rclose.clone() * (local[AINV_COL].clone() * ac_new.clone() - AB::Expr::ONE),
            );
            builder.assert_zero(rclose.clone() * (ac_new - pv(PV_ASSET)));
            // mode ∈ {0, 1, 2}, and the two declarations are its indicators.
            builder.assert_zero(
                rclose.clone() * mc.clone() * (mc.clone() - AB::Expr::ONE) * (mc.clone() - two.clone()),
            );
            builder.assert_zero(rclose.clone() * dc.clone() * mc.clone());
            builder.assert_zero(
                rclose.clone()
                    * (AB::Expr::ONE - dc.clone())
                    * (mc.clone() * local[MINV_COL].clone() - AB::Expr::ONE),
            );
            builder.assert_zero(rclose.clone() * dr.clone() * (mc.clone() - two.clone()));
            builder.assert_zero(
                rclose
                    * (AB::Expr::ONE - dr.clone())
                    * ((mc - two.clone()) * local[RINV_COL].clone() - AB::Expr::ONE),
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
        let dpbit = next[PBIT_COL].clone() - local[PBIT_COL].clone();
        t.assert_zero((AB::Expr::ONE - gperm.clone()) * dpbit.clone());
        // MN_i's path bit is MO_i's: carried across MO's last row, and across
        // BREG_OLD's for level 16 (MO_16 → BREG_OLD → MN_16).
        t.assert_zero(
            gperm.clone() * (sel_role(SEL_MO) + sel_role(SEL_BROLD)) * dpbit,
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
        let not_reg = AB::Expr::ONE - reg.clone();
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - bgc_any.clone()) * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone() * pwk(j) * a(l),
                );
                // Bank 1 (nk): +a at NF, −W0..3 at ARKM.
                t.assert_eq(
                    next[EQ_OFF + idx].clone(),
                    local[EQ_OFF + idx].clone() + nfb.clone() * pwk(j) * a(l)
                        - inj(2) * pwk(j) * w(l),
                );
                // Bank 2 (ρ): +W0..3 at NF, −W5..8 at ACM.
                t.assert_eq(
                    next[EQ_OFF + 16 + idx].clone(),
                    local[EQ_OFF + 16 + idx].clone() + nfb.clone() * pwk(j) * w(l)
                        - inj(3) * pwk(j) * w(5 + l),
                );
                // Bank 3: the output's ρ lanes W5..8.
                t.assert_eq(
                    next[EQ3_OFF + idx].clone(),
                    local[EQ3_OFF + idx].clone() + inj(4) * pwk(j) * w(5 + l),
                );
                // C_old: +a at MN (MO's output) and at AREG_NEW when updating
                // (the old leaf hash), −W4..7 at MO.
                t.assert_eq(
                    next[CO_OFF + idx].clone(),
                    local[CO_OFF + idx].clone()
                        + (mnb.clone() + injnew.clone() * not_reg.clone()) * pwk(j) * a(l)
                        - mob.clone() * pwk(j) * w(4 + l),
                );
                // C_new: +a at MO (AREG_NEW's or MN's output), −W4..7 at MN.
                t.assert_eq(
                    next[CN_OFF + idx].clone(),
                    local[CN_OFF + idx].clone() + mob.clone() * pwk(j) * a(l)
                        - mnb.clone() * pwk(j) * w(4 + l),
                );
                // SIB: one sibling per level, read twice.
                t.assert_eq(
                    next[SB_OFF + idx].clone(),
                    local[SB_OFF + idx].clone() + (mob.clone() - mnb.clone()) * pwk(j) * w(l),
                );
                // ISS: AISS's output (the chained digest at AREG_OLD) is the
                // old leaf's issuer_key lanes W0..3 — on an update.
                t.assert_eq(
                    next[IS_OFF + idx].clone(),
                    local[IS_OFF + idx].clone()
                        + injold.clone() * not_reg.clone() * pwk(j) * (a(l) - w(l)),
                );
            }
        }
        // Balance: +v at the input, −v at the output.
        for j in 0..4 {
            t.assert_eq(
                next[BL_OFF + j].clone(),
                local[BL_OFF + j].clone() + (inj(3) - inj(4)) * pwk(j) * w(4),
            );
        }
        // The path-bit accumulator: at each MO's first row, PACC += pbit·POW,
        // POW doubles.
        let pg = mob.clone() * sel(0);
        t.assert_eq(
            next[POW_COL].clone(),
            local[POW_COL].clone() + pg.clone() * local[POW_COL].clone(),
        );
        t.assert_eq(
            next[PACC_COL].clone(),
            local[PACC_COL].clone() + pg * pbit * local[POW_COL].clone(),
        );
        // Captures: chunk 0 of the two asset lanes and of the new mode lane.
        t.assert_eq(
            next[AC_OLD_COL].clone(),
            local[AC_OLD_COL].clone() + injold * pwk(0) * w(13),
        );
        t.assert_eq(
            next[AC_NEW_COL].clone(),
            local[AC_NEW_COL].clone() + injnew.clone() * pwk(0) * w(13),
        );
        t.assert_eq(
            next[MC_COL].clone(),
            local[MC_COL].clone() + injnew * pwk(0) * w(4),
        );
        // The declarations are per-transaction: constant.
        for col in [REG_COL, DC_COL, DR_COL, MINV_COL, RINV_COL, AINV_COL] {
            t.assert_eq(next[col].clone(), local[col].clone());
        }
    }
}

// ---------------------------------------------------------------------------
// The registry as the circuit opens it
// ---------------------------------------------------------------------------

/// `zeros[l]` = the root of an all-empty registry subtree of height `l`
/// (`zeros[0]` = the empty slot's zero digest).
pub fn registry_zeros() -> [[u64; 4]; REGISTRY_DEPTH + 1] {
    let mut z = [[0u64; 4]; REGISTRY_DEPTH + 1];
    for l in 1..=REGISTRY_DEPTH {
        z[l] = crate::reference::merkle_node_state(&z[l - 1], &z[l - 1])[..4]
            .try_into()
            .unwrap();
    }
    z
}

/// The opening of `slot` in the registry holding `leaves` — each at its own
/// asset index — and that registry's root. Works for an **empty** slot too
/// (a registration opens one). Bench/test support; the node's registry is
/// `qlab-cbserver`'s `RegistryTree`.
pub fn registry_opening(leaves: &[RegistryLeaf], slot: u64) -> (RegistryWitness, [u64; 4]) {
    let z = registry_zeros();
    let mut level: BTreeMap<u64, [u64; 4]> = leaves.iter().map(|l| (l.asset, l.hash())).collect();
    let mut siblings = [[0u64; 4]; REGISTRY_DEPTH];
    let mut path_bits = [false; REGISTRY_DEPTH];
    for lvl in 0..REGISTRY_DEPTH {
        let i = slot >> lvl;
        siblings[lvl] = *level.get(&(i ^ 1)).unwrap_or(&z[lvl]);
        path_bits[lvl] = i & 1 == 1;
        let mut up = BTreeMap::new();
        for &k in level.keys() {
            let p = k >> 1;
            if up.contains_key(&p) {
                continue;
            }
            let left = *level.get(&(k & !1)).unwrap_or(&z[lvl]);
            let right = *level.get(&(k | 1)).unwrap_or(&z[lvl]);
            let d: [u64; 4] = crate::reference::merkle_node_state(&left, &right)[..4]
                .try_into()
                .unwrap();
            up.insert(p, d);
        }
        level = up;
    }
    let root = *level.get(&0).unwrap_or(&z[REGISTRY_DEPTH]);
    (RegistryWitness { siblings, path_bits }, root)
}

// ---------------------------------------------------------------------------
// Instance builder
// ---------------------------------------------------------------------------

/// One registry write: the slot's current leaf (`None` = empty, a
/// registration), the leaf that replaces it, the slot's opening and — for an
/// update — the issuer secret behind the current leaf's `issuer_key`.
#[derive(Clone, Copy)]
pub struct RegistryWrite {
    pub isk: [u64; 4],
    pub old_leaf: Option<RegistryLeaf>,
    pub new_leaf: RegistryLeaf,
    pub opening: RegistryWitness,
}

/// Everything a prover/verifier pair needs for one shape-R instance.
#[cfg_attr(test, derive(Clone))]
pub struct L2ShapeRInstance {
    pub air: L2ShapeRAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub nf: [u64; 4],
    pub cm_out: [u64; 4],
    pub old_root: [u64; 4],
    pub new_root: [u64; 4],
}

/// Shape R against a **fabricated** commitment tree holding the fee input
/// alone (`narrow::fabricated_single_tree`).
pub fn build_shape_r(
    log_height: usize,
    fee_in: &L2TxInput,
    fee_out: &L2TxOutput,
    fee: u64,
    write: &RegistryWrite,
) -> L2ShapeRInstance {
    let (_, _, cm) = derive_input_l2(fee_in);
    let (witness, anchor) = fabricated_single_tree(&cm);
    build_shape_r_with_witnesses(log_height, fee_in, &witness, anchor, fee_out, fee, write)
}

/// Shape R from a caller-supplied commitment-tree witness + anchor. Both roots
/// are the folds of the write's opening — over the old leaf's hash (or the
/// zero digest) and the new leaf's; a write whose opening does not resolve to
/// the registry's current root is an unprovable instance against that root.
/// Nothing is asserted: an unbalanced or ill-formed write is simply
/// unprovable, which is what the negatives test.
pub fn build_shape_r_with_witnesses(
    log_height: usize,
    fee_in: &L2TxInput,
    fee_witness: &MerkleWitness,
    anchor: [u64; 4],
    fee_out: &L2TxOutput,
    fee: u64,
    write: &RegistryWrite,
) -> L2ShapeRInstance {
    let (nk, nf, _) = derive_input_l2(fee_in);
    let cm_out = l2_cm(fee_out.value, fee_out.asset, &fee_out.rkm, &nf, &fee_out.rseed);

    let old_digest = write.old_leaf.map_or([0u64; 4], |l| l.hash());
    let new_digest = write.new_leaf.hash();
    let old_root = write.opening.fold_root(&old_digest);
    let new_root = write.opening.fold_root(&new_digest);

    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![L2RSlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut put = |role: u32, w: L2RSlotWitness| {
        program[slot] = role;
        sw[slot] = w;
        slot += 1;
    };
    let lanes = |f: &dyn Fn(&mut [u64; NW])| {
        let mut w = L2RSlotWitness::default();
        f(&mut w.w);
        w
    };
    // The fee input: S's input chain without the registry opening.
    put(ROLE_ANK, lanes(&|w| w[..4].copy_from_slice(&fee_in.sk)));
    put(ROLE_NF, lanes(&|w| w[..4].copy_from_slice(&fee_in.rho)));
    put(ROLE_BNF1, L2RSlotWitness::default());
    put(
        ROLE_ARKM,
        lanes(&|w| {
            w[..4].copy_from_slice(&nk);
            w[5] = fee_in.d[0];
            w[6] = fee_in.d[1];
        }),
    );
    put(
        ROLE_ACM,
        lanes(&|w| {
            w[4] = fee_in.value;
            w[5..9].copy_from_slice(&fee_in.rho);
            w[9..13].copy_from_slice(&fee_in.rseed);
            w[13] = fee_in.asset;
        }),
    );
    for (sib, bit) in fee_witness.siblings.iter().zip(fee_witness.path_bits.iter()) {
        let mut w = lanes(&|w| w[..4].copy_from_slice(sib));
        w.pbit = *bit;
        put(ROLE_MERKLE, w);
    }
    put(ROLE_BANCHOR, L2RSlotWitness::default());
    // The fee output, ρ = nf.
    put(
        ROLE_ACMOUT,
        lanes(&|w| {
            w[..4].copy_from_slice(&fee_out.rkm);
            w[4] = fee_out.value;
            w[5..9].copy_from_slice(&nf);
            w[9..13].copy_from_slice(&fee_out.rseed);
            w[13] = fee_out.asset;
        }),
    );
    put(ROLE_BCM1, L2RSlotWitness::default());
    // The write: isk, the two leaves.
    put(ROLE_AISS, lanes(&|w| w[..4].copy_from_slice(&write.isk)));
    let leaf_lanes = |l: &RegistryLeaf| {
        lanes(&|w| {
            w[..4].copy_from_slice(&l.issuer_key);
            w[4] = l.mode;
            w[5..9].copy_from_slice(&l.freeze_root);
            w[9..13].copy_from_slice(&l.allow_root);
            w[13] = l.asset;
            w[14] = l.flags;
        })
    };
    put(
        ROLE_AREG_OLD,
        write.old_leaf.as_ref().map_or_else(L2RSlotWitness::default, leaf_lanes),
    );
    put(ROLE_AREG_NEW, leaf_lanes(&write.new_leaf));
    // The two folds, interleaved; BREG_OLD between MO_16 and MN_16.
    let (mut d_old, mut d_new) = (old_digest, new_digest);
    for lvl in 0..REGISTRY_DEPTH {
        let (sib, bit) = (write.opening.siblings[lvl], write.opening.path_bits[lvl]);
        let fold_w = |d: &[u64; 4]| {
            let mut w = lanes(&|w| {
                w[..4].copy_from_slice(&sib);
                w[4..8].copy_from_slice(d);
            });
            w.pbit = bit;
            w
        };
        let node = |d: &[u64; 4]| -> [u64; 4] {
            let st = if bit {
                crate::reference::merkle_node_state(&sib, d)
            } else {
                crate::reference::merkle_node_state(d, &sib)
            };
            st[..4].try_into().unwrap()
        };
        put(ROLE_MO, fold_w(&d_old));
        if lvl == REGISTRY_DEPTH - 1 {
            put(ROLE_BREG_OLD, L2RSlotWitness::default());
        }
        put(ROLE_MN, fold_w(&d_new));
        d_old = node(&d_old);
        d_new = node(&d_new);
    }
    debug_assert_eq!((d_old, d_new), (old_root, new_root));
    put(ROLE_BREG_NEW, L2RSlotWitness::default());
    put(ROLE_BAL, L2RSlotWitness::default());
    assert_eq!(slot, SHAPE_R_PERMS, "program layout drifted");

    let pvs = pv_vec_r(&anchor, &nf, &cm_out, fee, &old_root, &new_root, write.new_leaf.asset);
    L2ShapeRInstance {
        air: L2ShapeRAir {
            log_height,
            program,
            slot_witness: sw,
            fee,
            reg: write.old_leaf.is_none(),
        },
        pvs,
        anchor,
        nf,
        cm_out,
        old_root,
        new_root,
    }
}

// ---------------------------------------------------------------------------
// Trace generation — l2.rs's fill, mirrored constraint for constraint.
// ---------------------------------------------------------------------------

impl L2ShapeRAir {
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * L2R_WIDTH;
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
        let wit = |p: usize| -> L2RSlotWitness {
            if self.slot_witness.is_empty() {
                L2RSlotWitness::default()
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);
        let mut eq = [0i64; 32];
        let mut eq3 = [0i64; 16];
        let mut bq = [0i64; 16];
        let mut bl = [0i64; 4];
        let mut co = [0i64; 16];
        let mut cn = [0i64; 16];
        let mut sb = [0i64; 16];
        let mut is = [0i64; 16];
        let mut pow: i64 = 1;
        let mut pacc: i64 = 0;
        let (mut ac_old, mut ac_new, mut mc) = (0i64, 0i64, 0i64);

        // The declarations, off the new leaf's witness (chunk 0 of the lanes
        // the circuit captures). A program without AREG_NEW gets 0s.
        let reg = self.reg as u32;
        let (mode16, asset16) = self
            .program
            .iter()
            .position(|r| *r == ROLE_AREG_NEW)
            .map_or((0u32, 0u32), |i| {
                let w = wit(i).w;
                ((w[4] & 0xffff) as u32, (w[13] & 0xffff) as u32)
            });
        let inv_or_zero = |x: F| if x == F::ZERO { F::ZERO } else { x.inverse() };
        let mode_f = F::from_u32(mode16);
        let dcv = (mode16 == 0) as u32;
        let drv = (mode16 == 2) as u32;
        let minv = inv_or_zero(mode_f);
        let rinv = inv_or_zero(mode_f - F::TWO);
        let ainv = inv_or_zero(F::from_u32(asset16));

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
                    ROLE_AISS => match l {
                        0..=3 => wbit[l],
                        4 => (z == 7) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AREG_OLD | ROLE_AREG_NEW => match l {
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
                    ROLE_MO | ROLE_MN => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * wbit[l + 4],
                        4..=7 => pbv * wbit[l] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
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
            values.resize(base + L2R_WIDTH, F::ZERO);
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
            let injv: [u32; NINJ] = [
                bndv * (selv[SEL_MERKLE] + selv[SEL_NF]),
                bndv * selv[SEL_ANK],
                bndv * selv[SEL_ARKM],
                bndv * selv[SEL_ACM],
                bndv * selv[SEL_ACMOUT],
                bndv * selv[SEL_AISS],
            ];
            for (i, vv) in injv.iter().enumerate() {
                row[INJ_OFF + i] = F::from_u32(*vv);
            }
            let (injold, injnew) = (bndv * selv[SEL_AOLD], bndv * selv[SEL_ANEW]);
            let (mob, mnb, nfb) = (bndv * selv[SEL_MO], bndv * selv[SEL_MN], bndv * selv[SEL_NF]);
            row[INJOLD_COL] = F::from_u32(injold);
            row[INJNEW_COL] = F::from_u32(injnew);
            row[MOB_COL] = F::from_u32(mob);
            row[MNB_COL] = F::from_u32(mnb);
            row[NFB_COL] = F::from_u32(nfb);
            row[G4_COL] = F::from_u32(gpermv * ph[1]);
            let clv: [u32; NCL] = core::array::from_fn(|k| {
                gpermv
                    * selv[[SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_BAL, SEL_MO, SEL_MN, SEL_AOLD][k]]
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
            for (i, acc) in bq.iter().enumerate() {
                row[BQ_OFF + i] = sgn(*acc);
            }
            for (i, acc) in eq.iter().enumerate() {
                row[EQ_OFF + i] = sgn(*acc);
            }
            for (i, acc) in eq3.iter().enumerate() {
                row[EQ3_OFF + i] = sgn(*acc);
            }
            for (j, acc) in bl.iter().enumerate() {
                row[BL_OFF + j] = sgn(*acc);
            }
            for (off, bank) in [(CO_OFF, &co), (CN_OFF, &cn), (SB_OFF, &sb), (IS_OFF, &is)] {
                for (i, acc) in bank.iter().enumerate() {
                    row[off + i] = sgn(*acc);
                }
            }
            // Carry encodings of the one chain against the fee.
            {
                let mut cc = [0i64; 3];
                let mut prev = 0i64;
                for j in 0..3 {
                    let tj = bl[j] + prev - ((self.fee >> (16 * j)) & 0xffff) as i64;
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
            row[POW_COL] = sgn(pow);
            row[PACC_COL] = sgn(pacc);
            row[AC_OLD_COL] = sgn(ac_old);
            row[AC_NEW_COL] = sgn(ac_new);
            row[MC_COL] = sgn(mc);
            row[REG_COL] = F::from_u32(reg);
            row[DC_COL] = F::from_u32(dcv);
            row[DR_COL] = F::from_u32(drv);
            row[MINV_COL] = minv;
            row[RINV_COL] = rinv;
            row[AINV_COL] = ainv;

            // Advance the accumulators.
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let (nfb, mob, mnb) = (nfb as i64, mob as i64, mnb as i64);
                let (injold, injnew) = (injold as i64, injnew as i64);
                let not_reg = 1 - reg as i64;
                let wb = |i: usize| wbit[i] as i64;
                if bgc_any == 1 {
                    bq = [0i64; 16];
                }
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    let al = a[l] as i64;
                    bq[idx] += bgcap as i64 * wgt * al;
                    eq[idx] += nfb * wgt * al - injv[2] as i64 * wgt * wb(l);
                    eq[16 + idx] += nfb * wgt * wb(l) - injv[3] as i64 * wgt * wb(5 + l);
                    eq3[idx] += injv[4] as i64 * wgt * wb(5 + l);
                    co[idx] += (mnb + injnew * not_reg) * wgt * al - mob * wgt * wb(4 + l);
                    cn[idx] += mob * wgt * al - mnb * wgt * wb(4 + l);
                    sb[idx] += (mob - mnb) * wgt * wb(l);
                    is[idx] += injold * not_reg * wgt * (al - wb(l));
                }
                bl[jc] += (injv[3] as i64 - injv[4] as i64) * wgt * wb(4);
                if jc == 0 {
                    ac_old += injold * wgt * wb(13);
                    ac_new += injnew * wgt * wb(13);
                    mc += injnew * wgt * wb(4);
                }
                if mob == 1 && z == 0 {
                    pacc += pbv as i64 * pow;
                    pow *= 2;
                }
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

        RowMajorMatrix::new(values, L2R_WIDTH)
    }

    /// The state materialized at block `q` (the round-q input).
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * L2R_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}
