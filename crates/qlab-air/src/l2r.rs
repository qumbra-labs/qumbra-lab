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
//! - **the seed** (A3, lab #731, ruled on #730): every write — registration
//!   and update alike, no `REG` mux — also creates a **0-value note of the
//!   written asset** to the writer. A mint rides an input row of its asset and
//!   no transaction can create an asset's first note otherwise, so without it a
//!   runtime-registered asset could never be minted (and an issuer who spent
//!   every note of an asset could never mint it again). The seed's `ρ` is S's
//!   output-1 derivation `H(nf ‖ D_P|1)` (`ARHO`, its `nf` tied to the public
//!   one through bank 3), injected from the chain into `ACMOUT2`; its value is
//!   zero bit by bit, its asset equals the new leaf's at the registry close,
//!   and its commitment is bound to a public value by `BCM2`.
//!
//! Public values: `anchor ‖ nf ‖ cm ‖ fee ‖ old_root ‖ new_root ‖ asset ‖
//! cm_seed`.
//!
//! ### Program order (82 perms → 2^18)
//!
//! ```text
//! [DUMMY]
//! ANK → NF → BNF1 → ARKM → ACM → 32×MERKLE → BANCHOR          the fee input
//! ACMOUT → BCM1                                               the fee output
//! ARHO → ACMOUT2 → BCM2                                       the seed output
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
//! 82 perms fit one period of the 128-slot program ring at 2^18 (85.3 perms),
//! so there is no wrapped second program for S's epoch column to switch off —
//! R has no `EP`, `GWRAP`, `SE` or `ROLE_END`. A taller trace only adds rows
//! whose gates re-fire against the same public values: more constraints on
//! the prover, never fewer.
//!
//! ### Column accounting: 734 — see `l2r_trace_width_is_read_off_the_matrix`.

use std::collections::BTreeMap;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::l2::{
    derive_input_l2, l2_cm, L2TxInput, L2TxOutput, RegistryLeaf, RegistryWitness, ASSET_BITS,
    REGISTRY_DEPTH, ROLE_ACM, ROLE_ACMOUT, ROLE_ANK, ROLE_AREG, ROLE_ARHO, ROLE_ARKM, ROLE_BAL,
    ROLE_BANCHOR, ROLE_BCM1, ROLE_BCM2, ROLE_BNF1, ROLE_BREG, ROLE_DUMMY, ROLE_MERKLE, ROLE_NF,
    ROWS_PER_PERM,
};
use crate::l2p::ROLE_AISS;
use crate::narrow::{derive_output_rho, fabricated_single_tree, pv_chunks, MerkleWitness, MERKLE_DEPTH};
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
const NSEL: usize = 20; // materialized role selectors, order = SEL_CODES
const SEL_OFF: usize = LO_OFF + 4; // 491
/// Injection flags [mrk+nf, ank, arkm, acm, acmout, aiss, arho, acmout2] (the
/// two leaf and the two `MERKLE_W` classes are carried by the four split flags
/// below).
const NINJ: usize = 8;
const INJ_OFF: usize = SEL_OFF + NSEL; // 511
const INJOLD_COL: usize = INJ_OFF + NINJ; // 519: bnd·sel(AREG_OLD)
const INJNEW_COL: usize = INJOLD_COL + 1; // 520: bnd·sel(AREG_NEW)
const MOB_COL: usize = INJNEW_COL + 1; // 521: bnd·sel(MO)
const MNB_COL: usize = MOB_COL + 1; // 522: bnd·sel(MN)
const G4_COL: usize = MNB_COL + 1; // 523: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 524: merkle path bit (constant per perm)
const NW: usize = 15;
const W_OFF: usize = PBIT_COL + 1; // 525: 15 witness lanes (role-multiplexed)
const NFB_COL: usize = W_OFF + NW; // 540: bnd·sel(NF) — banks 1 and 2's pos gate
/// Close gates `gperm·sel(role)` [arkm, acm, acmout, bal, mo, mn, areg_old,
/// arho].
const NCL: usize = 8;
const CL_OFF: usize = NFB_COL + 1; // 541
const CL_ARKM: usize = 0;
const CL_ACM: usize = 1;
const CL_ACMOUT: usize = 2;
const CL_BAL: usize = 3;
const CL_MO: usize = 4;
const CL_MN: usize = 5;
const CL_AOLD: usize = 6;
const CL_ARHO: usize = 7;
const BGCAP_COL: usize = CL_OFF + NCL; // 549: bind capture gate
/// Bind close gates [banchor, bnf1, bcm1, breg_old, breg_new, bcm2]; index 4
/// (`BREG_NEW`) is also R's registry close row (`RCLOSE`).
const NBGC: usize = 6;
const BGC_OFF: usize = BGCAP_COL + 1; // 550
const BGC_BREG_NEW: usize = 4;
const BQ_OFF: usize = BGC_OFF + NBGC; // 556: 16: bind bank
const EQ_OFF: usize = BQ_OFF + 16; // 572: 32: banks 1 (nk) and 2 (rho)
const EQ3_OFF: usize = EQ_OFF + 32; // 604: 16: bank 3 (output rho = nf; ARHO's nf)
const BL_OFF: usize = EQ3_OFF + 16; // 620: 4: balance accumulators
const BLC_OFF: usize = BL_OFF + 4; // 624: 9: carry encodings
const EFF_OFF: usize = BLC_OFF + 9; // 633: 25: effective round input
const CO_OFF: usize = EFF_OFF + 25; // 658: 16: C_old — old-chain carry
const CN_OFF: usize = CO_OFF + 16; // 674: 16: C_new — new-chain carry
const SB_OFF: usize = CN_OFF + 16; // 690: 16: SIB — shared siblings
const IS_OFF: usize = SB_OFF + 16; // 706: 16: ISS — H(isk ‖ D_I) = old issuer_key
const POW_COL: usize = IS_OFF + 16; // 722: 2^level at MO's first row
const PACC_COL: usize = POW_COL + 1; // 723: Σ pbit_i·2^i over MO
const AC_OLD_COL: usize = PACC_COL + 1; // 724: old leaf asset (chunk 0 of W13)
const AC_NEW_COL: usize = AC_OLD_COL + 1; // 725: new leaf asset
const MC_COL: usize = AC_NEW_COL + 1; // 726: new leaf mode (chunk 0 of W4)
const AC_SEED_COL: usize = MC_COL + 1; // 727: seed note asset (chunk 0 of W13 at ACMOUT2)
/// Per-transaction declarations, constant for the trace.
const REG_COL: usize = AC_SEED_COL + 1; // 728: 1 = registration, 0 = update
const DC_COL: usize = REG_COL + 1; // 729: [mode = Cloaked]
const DR_COL: usize = DC_COL + 1; // 730: [mode = Regulated]
const MINV_COL: usize = DR_COL + 1; // 731: mode⁻¹ when mode ≠ 0
const RINV_COL: usize = MINV_COL + 1; // 732: (mode − 2)⁻¹ when mode ≠ 2
const AINV_COL: usize = RINV_COL + 1; // 733: asset⁻¹ (asset 0 unwritable)

/// The shape-R trace width.
pub const L2R_WIDTH: usize = AINV_COL + 1; // 734

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
/// The seed output (A3): shape S's output commitment block with its `ρ`
/// lanes taken from the chain (`ARHO`'s output) instead of the witness. The
/// seed's `ρ` derivation is shape S's own `ROLE_ARHO`; its bind is S's
/// `ROLE_BCM2`.
pub const ROLE_ACMOUT2: u32 = 27;

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
    ROLE_ARHO,
    ROLE_ACMOUT2,
    ROLE_BCM2,
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
const SEL_ARHO: usize = 17;
const SEL_ACMOUT2: usize = 18;
const SEL_BCM2: usize = 19;
/// The bind roles, in `BGC` order.
const BIND_SELS: [usize; NBGC] = [SEL_BANCHOR, SEL_BNF1, SEL_BCM1, SEL_BROLD, SEL_BRNEW, SEL_BCM2];

/// Public-value layout: anchor, nf, cm (16 chunks each), fee (4), old and new
/// registry root (16 each), the written asset id (one element), the seed
/// note's commitment (16 — A3, appended so every earlier offset holds).
pub const PV_ANCHOR: usize = 0;
pub const PV_NF: usize = 16;
pub const PV_CM: usize = 32;
pub const PV_FEE: usize = 48;
pub const PV_OLD_ROOT: usize = 52;
pub const PV_NEW_ROOT: usize = 68;
pub const PV_ASSET: usize = 84;
pub const PV_CM_SEED: usize = 85;
pub const PV_LEN: usize = 101;
const PV_BIND: [usize; NBGC] = [PV_ANCHOR, PV_NF, PV_CM, PV_OLD_ROOT, PV_NEW_ROOT, PV_CM_SEED];

/// Build the full public-value vector for a shape-R instance.
#[allow(clippy::too_many_arguments)]
pub fn pv_vec_r(
    anchor: &[u64; 4],
    nf: &[u64; 4],
    cm: &[u64; 4],
    fee: u64,
    old_root: &[u64; 4],
    new_root: &[u64; 4],
    asset: u64,
    cm_seed: &[u64; 4],
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
    out.extend_from_slice(&pv_chunks(cm_seed));
    debug_assert_eq!(out.len(), PV_LEN);
    out
}

/// Perm slots used by the shape-R program, INCLUDING the leading dummy slot:
/// 1 + (5 + 32 + 1) + 2 + 3 + 3 + 2 × 16 + 2 + 1 = **82**, at 3072 rows each =
/// 251,904 rows → 2^18 (262,144), 3.3 spare perm slots.
pub const SHAPE_R_PERMS: usize = 1 + (5 + MERKLE_DEPTH + 1) + 2 + 3 + 3 + 2 * REGISTRY_DEPTH + 2 + 1;
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
        for (i, s) in [SEL_ANK, SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_AISS, SEL_ARHO, SEL_ACMOUT2].iter().enumerate() {
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
            // ARHO (shape S's): nf = W0..4, D_P = lane 4 bit 3, pad at lane 5
            // — `narrow::derive_output_rho(nf, 1)`.
            let msg_arho: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(2),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // ACMOUT2 (A3's seed): ACMOUT's block with ρ from the chain —
            // ARHO's output, the perm right before it.
            let msg_acmout2: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => w(l - 2),
                6..=9 => a(l - 6),
                10..=13 => w(l - 1),
                14 => sel(0),
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
                + inj(6) * (msg_arho - a(l))
                + inj(7) * (msg_acmout2 - a(l))
                + (injold.clone() + injnew.clone()) * (msg_areg - a(l))
                + (mob.clone() + mnb.clone()) * (msg_mw - a(l));
            builder.assert_eq(eff(l), expr);
        }

        // --- Close gates ---
        let cl = |k: usize| local[CL_OFF + k].clone();
        for (k, s) in [SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_BAL, SEL_MO, SEL_MN, SEL_AOLD, SEL_ARHO]
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
            // A3: ARHO absorbs the same nf — bank 3 held `pv(nf)` after
            // ACMOUT's close, ARHO subtracts its W0..3, and it closes at zero.
            builder.assert_zero(cl(CL_ARHO) * local[EQ3_OFF + j].clone());
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
        for col in [PACC_COL, AC_OLD_COL, AC_NEW_COL, MC_COL, AC_SEED_COL] {
            builder.when_first_row().assert_zero(local[col].clone());
        }
        // Both leaves' asset lanes are 16-bit; the mode lane is 2-bit.
        let hi16 = AB::Expr::ONE - lo16;
        builder.assert_zero(injold.clone() * hi16.clone() * w(13));
        builder.assert_zero(injnew.clone() * hi16.clone() * w(13));
        // A3's seed: value zero, bit by bit; asset lane 16-bit (so its chunk
        // 0, captured in AC_SEED, is the whole asset — closed at RCLOSE).
        builder.assert_zero(inj(7) * w(4));
        builder.assert_zero(inj(7) * hi16 * w(13));
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
            builder.assert_zero(rclose.clone() * (ac_new.clone() - pv(PV_ASSET)));
            // A3: the seed note is of the written asset.
            builder.assert_zero(rclose.clone() * (local[AC_SEED_COL].clone() - ac_new));
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
                // Bank 3: the output's ρ lanes W5..8; ARHO's nf W0..3 back out.
                t.assert_eq(
                    next[EQ3_OFF + idx].clone(),
                    local[EQ3_OFF + idx].clone() + inj(4) * pwk(j) * w(5 + l)
                        - inj(6) * pwk(j) * w(l),
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
        t.assert_eq(
            next[AC_SEED_COL].clone(),
            local[AC_SEED_COL].clone() + inj(7) * pwk(0) * w(13),
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

/// The seed output's free fields (A3): whose it is and its blinding. Its
/// value is 0, its asset the written one and its `ρ` `H(nf ‖ D_P|1)` — all
/// fixed by the circuit, so the builder takes none of them.
#[derive(Clone, Copy, Debug)]
pub struct SeedOutput {
    pub rkm: [u64; 4],
    pub rseed: [u64; 4],
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
    /// The seed note's commitment (A3).
    pub cm_seed: [u64; 4],
}

/// Shape R against a **fabricated** commitment tree holding the fee input
/// alone (`narrow::fabricated_single_tree`).
pub fn build_shape_r(
    log_height: usize,
    fee_in: &L2TxInput,
    fee_out: &L2TxOutput,
    fee: u64,
    write: &RegistryWrite,
    seed: &SeedOutput,
) -> L2ShapeRInstance {
    let (_, _, cm) = derive_input_l2(fee_in);
    let (witness, anchor) = fabricated_single_tree(&cm);
    build_shape_r_with_witnesses(log_height, fee_in, &witness, anchor, fee_out, fee, write, seed)
}

/// Shape R from a caller-supplied commitment-tree witness + anchor. Both roots
/// are the folds of the write's opening — over the old leaf's hash (or the
/// zero digest) and the new leaf's; a write whose opening does not resolve to
/// the registry's current root is an unprovable instance against that root.
/// Nothing is asserted: an unbalanced or ill-formed write is simply
/// unprovable, which is what the negatives test.
#[allow(clippy::too_many_arguments)]
pub fn build_shape_r_with_witnesses(
    log_height: usize,
    fee_in: &L2TxInput,
    fee_witness: &MerkleWitness,
    anchor: [u64; 4],
    fee_out: &L2TxOutput,
    fee: u64,
    write: &RegistryWrite,
    seed: &SeedOutput,
) -> L2ShapeRInstance {
    let (nk, nf, _) = derive_input_l2(fee_in);
    let cm_out = l2_cm(fee_out.value, fee_out.asset, &fee_out.rkm, &nf, &fee_out.rseed);
    let seed_rho = derive_output_rho(&nf, 1);
    let cm_seed = l2_cm(0, write.new_leaf.asset, &seed.rkm, &seed_rho, &seed.rseed);

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
    // The seed (A3): ρ = H(nf ‖ D_P|1), then the 0-value note of the written
    // asset, its ρ lanes read from the chain (W5..8 stay empty).
    put(ROLE_ARHO, lanes(&|w| w[..4].copy_from_slice(&nf)));
    put(
        ROLE_ACMOUT2,
        lanes(&|w| {
            w[..4].copy_from_slice(&seed.rkm);
            w[9..13].copy_from_slice(&seed.rseed);
            w[13] = write.new_leaf.asset;
        }),
    );
    put(ROLE_BCM2, L2RSlotWitness::default());
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
            // BREG_OLD carries level 16's path bit across to MN_16.
            put(ROLE_BREG_OLD, L2RSlotWitness { pbit: bit, ..Default::default() });
        }
        put(ROLE_MN, fold_w(&d_new));
        d_old = node(&d_old);
        d_new = node(&d_new);
    }
    debug_assert_eq!((d_old, d_new), (old_root, new_root));
    put(ROLE_BREG_NEW, L2RSlotWitness::default());
    put(ROLE_BAL, L2RSlotWitness::default());
    assert_eq!(slot, SHAPE_R_PERMS, "program layout drifted");

    let pvs = pv_vec_r(&anchor, &nf, &cm_out, fee, &old_root, &new_root, write.new_leaf.asset, &cm_seed);
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
        cm_seed,
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
        let (mut ac_old, mut ac_new, mut mc, mut ac_seed) = (0i64, 0i64, 0i64, 0i64);

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
                    ROLE_ARHO => match l {
                        0..=3 => wbit[l],
                        4 => (z == 3) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACMOUT2 => match l {
                        0 => wbit[4],
                        1 => wbit[13],
                        2..=5 => wbit[l - 2],
                        6..=9 => a[l - 6],
                        10..=13 => wbit[l - 1],
                        14 => z0,
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
                bndv * selv[SEL_ARHO],
                bndv * selv[SEL_ACMOUT2],
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
                    * selv[[SEL_ARKM, SEL_ACM, SEL_ACMOUT, SEL_BAL, SEL_MO, SEL_MN, SEL_AOLD, SEL_ARHO][k]]
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
            row[AC_SEED_COL] = sgn(ac_seed);
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
                    eq3[idx] += injv[4] as i64 * wgt * wb(5 + l) - injv[6] as i64 * wgt * wb(l);
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
                    ac_seed += injv[7] as i64 * wgt * wb(13);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use p3_air::check_constraints;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;

    use super::*;
    use crate::l2::{MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED};
    use crate::l2p::issuer_key_of;
    use crate::l2test::{self, Violation};
    use crate::reference;

    type F = KoalaBear;

    fn pvs_of(inst: &L2ShapeRInstance) -> Vec<F> {
        inst.pvs.iter().map(|v| F::from_u32(*v)).collect()
    }
    fn digest(state: &[u64; 25]) -> [u64; 4] {
        state[..4].try_into().unwrap()
    }
    fn slot_of(program: &[u32; PROGRAM_SLOTS], role: u32, nth: usize) -> usize {
        program.iter().enumerate().filter(|(_, r)| **r == role).map(|(i, _)| i).nth(nth).unwrap()
    }

    // -----------------------------------------------------------------------
    // The cost model is `l2::tests`' (lab #700 baton 3): the two honest
    // instances are generated and scanned once for the module; every UNSAT
    // claim stops at its first violation, the scan starting at the perm the
    // tamper targets. Each negative also PINS that perm: a refusal anywhere
    // else would be a different claim than the one the test names.
    // -----------------------------------------------------------------------

    /// The first violation, visiting the program tail-first up to and
    /// including perm `slot` — a scheduling hint only (`l2test::scan`).
    fn first_violation_near(inst: &L2ShapeRInstance, trace: &RowMajorMatrix<F>, pvs: &[F], slot: usize) -> Option<Violation> {
        l2test::first_violation(&inst.air, trace, pvs, (slot + 1) * ROWS_PER_PERM)
    }
    /// An UNSAT claim refused **at perm `slot`**.
    fn assert_refused_at(inst: &L2ShapeRInstance, slot: usize, what: &str) {
        let trace = inst.air.generate_trace::<F>(0);
        assert_trace_refused_at(inst, &trace, &pvs_of(inst), slot, what);
    }
    fn assert_trace_refused_at(inst: &L2ShapeRInstance, trace: &RowMajorMatrix<F>, pvs: &[F], slot: usize, what: &str) {
        match first_violation_near(inst, trace, pvs, slot) {
            None => panic!("{what} VERIFIED"),
            Some(v) => assert_eq!(
                v.row / ROWS_PER_PERM,
                slot,
                "{what}: refused, but at {v} (perm {}), not at perm {slot}",
                v.row / ROWS_PER_PERM
            ),
        }
    }

    struct Fixture {
        inst: L2ShapeRInstance,
        trace: RowMajorMatrix<F>,
        pvs: Vec<F>,
        verdict: Result<(), Violation>,
    }
    impl Fixture {
        fn new(inst: L2ShapeRInstance) -> Self {
            let pvs = pvs_of(&inst);
            let trace = inst.air.generate_trace::<F>(0);
            let verdict = l2test::satisfied(&inst.air, &trace, &pvs);
            Fixture { inst, trace, pvs, verdict }
        }
        fn assert_sat(&self, what: &str) {
            if let Err(v) = &self.verdict {
                panic!("{what}: constraints not satisfied on {v}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // The registry and the fee spend every instance shares.
    // -----------------------------------------------------------------------

    const ISK0: [u64; 4] = [0x1500, 0x1501, 0x1502, 0x1503];
    const ISK7: [u64; 4] = [0x7a11, 0x7a12, 0x7a13, 0x7a14];
    const ISK7B: [u64; 4] = [0x7b21, 0x7b22, 0x7b23, 0x7b24];
    const ISK9: [u64; 4] = [0x9c31, 0x9c32, 0x9c33, 0x9c34];
    /// Any 256 bits — a registration's isk is never checked.
    const ISK_NONE: [u64; 4] = [0xdead, 0xbeef, 0xf00d, 0xcafe];

    fn leaf(asset: u64, isk: &[u64; 4], mode: u64, freeze_root: [u64; 4], allow_root: [u64; 4], flags: u64) -> RegistryLeaf {
        RegistryLeaf { asset, issuer_key: issuer_key_of(isk), mode, freeze_root, allow_root, flags }
    }
    /// The registry before every write: asset 0 (Cloaked, with an issuer so
    /// the asset-0 negative has a key to prove), asset 7 (Hybrid, a freeze
    /// root published), asset 8 (Cloaked). Slot 9 is empty and its level-0
    /// sibling (slot 8) is not.
    fn registry() -> Vec<RegistryLeaf> {
        vec![
            leaf(0, &ISK0, MODE_CLOAKED, [0; 4], [0; 4], 0),
            leaf(7, &ISK7, MODE_HYBRID, [0xf1, 0xf2, 0xf3, 0xf4], [0; 4], 1),
            leaf(8, &ISK_NONE, MODE_CLOAKED, [0; 4], [0; 4], 0),
        ]
    }
    fn leaf_of(asset: u64) -> RegistryLeaf {
        *registry().iter().find(|l| l.asset == asset).unwrap()
    }

    const FEE: u64 = 7;
    /// The fee spend: 100 in asset 0 → 93 out in asset 0 + fee 7.
    fn fee_parts() -> (L2TxInput, L2TxOutput) {
        let input = L2TxInput {
            sk: [0x5a1, 0x5a2, 0x5a3, 0x5a4],
            value: 100,
            asset: 0,
            rho: [0x6b1, 0x6b2, 0x6b3, 0x6b4],
            rseed: [0x7c1, 0x7c2, 0x7c3, 0x7c4],
            d: [0x8d1, 0x8d2],
        };
        let output = L2TxOutput {
            value: 100 - FEE,
            asset: 0,
            rkm: [0x9e1, 0x9e2, 0x9e3, 0x9e4],
            rho: [0; 4], // overridden: ρ = nf
            rseed: [0xaf1, 0xaf2, 0xaf3, 0xaf4],
        };
        (input, output)
    }

    /// The seed's owner and blinding (A3).
    const SEED: SeedOutput = SeedOutput { rkm: [0xb01, 0xb02, 0xb03, 0xb04], rseed: [0xc01, 0xc02, 0xc03, 0xc04] };

    /// A write at `slot` of the shared registry.
    fn write_at(slot: u64, isk: [u64; 4], old_leaf: Option<RegistryLeaf>, new_leaf: RegistryLeaf) -> RegistryWrite {
        RegistryWrite { isk, old_leaf, new_leaf, opening: registry_opening(&registry(), slot).0 }
    }
    fn instance(write: &RegistryWrite) -> L2ShapeRInstance {
        let (fin, fout) = fee_parts();
        build_shape_r(SHAPE_R_LOG_HEIGHT, &fin, &fout, FEE, write, &SEED)
    }
    /// A registration of `new` into its own (empty) slot.
    fn register(new: RegistryLeaf) -> L2ShapeRInstance {
        instance(&write_at(new.asset, ISK_NONE, None, new))
    }
    /// An update of asset 7 with `isk`.
    fn update7(isk: [u64; 4], new: RegistryLeaf) -> L2ShapeRInstance {
        instance(&write_at(7, isk, Some(leaf_of(7)), new))
    }

    /// Registration: asset 9 as Regulated, both policy roots and a flag set.
    fn register_leaf() -> RegistryLeaf {
        leaf(9, &ISK9, MODE_REGULATED, [1, 2, 3, 4], [5, 6, 7, 8], 3)
    }
    /// Update: asset 7 rotates its issuer_key and publishes a new freeze root.
    fn update_leaf() -> RegistryLeaf {
        leaf(7, &ISK7B, MODE_HYBRID, [0xa1, 0xa2, 0xa3, 0xa4], [0; 4], 1)
    }

    static REGISTER: OnceLock<Fixture> = OnceLock::new();
    fn register_fixture() -> &'static Fixture {
        REGISTER.get_or_init(|| Fixture::new(register(register_leaf())))
    }
    static UPDATE: OnceLock<Fixture> = OnceLock::new();
    fn update_fixture() -> &'static Fixture {
        UPDATE.get_or_init(|| Fixture::new(update7(ISK7, update_leaf())))
    }

    /// Program slots of the roles the negatives pin.
    fn at(role: u32) -> usize {
        slot_of(&register_fixture().inst.air.program, role, 0)
    }

    // -----------------------------------------------------------------------
    // Geometry
    // -----------------------------------------------------------------------

    #[test]
    fn l2r_chain_only_satisfies_constraints() {
        let air = L2ShapeRAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &vec![F::ZERO; PV_LEN]);
    }

    /// Width 734, every column named. Engine and M3 machinery as `l2.rs`
    /// (491 up to the selectors), then shape R's own. A3's seed output added 8:
    /// three selectors (ARHO, ACMOUT2, BCM2), two injection flags, ARHO's close
    /// gate, BCM2's bind close and the seed-asset capture.
    #[test]
    fn l2r_trace_width_is_read_off_the_matrix() {
        let air = L2ShapeRAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        assert_eq!(trace.width(), L2R_WIDTH, "width must be the matrix's own");
        let engine = 402; // narrow's Keccak-f engine, verbatim
        let machinery = 24 + 4 + 32 + 20 + 5 + 4; // PB, PH, PR (32 limbs), D, RB, LO
        let roles = 20 // SEL: 11 of S's roles + AISS, AREG_OLD/NEW, MO, MN, BREG_OLD/NEW, ARHO, ACMOUT2, BCM2
            + 8 // INJ: mrk+nf, ank, arkm, acm, acmout, aiss, arho, acmout2
            + 4 // INJOLD, INJNEW, MOB, MNB (the split leaf / MERKLE_W flags)
            + 1 // G4
            + 1 // NFB
            + 8 // CL: arkm, acm, acmout, bal, mo, mn, areg_old, arho
            + 1 // BGCAP
            + 6; // BGC: banchor, bnf1, bcm1, breg_old, breg_new, bcm2
        let witness = 1 + 15 + 25; // PBIT, W, EFF
        let banks = 16 // BQ
            + 32 // EQ: banks 1 (nk) and 2 (ρ)
            + 16 // EQ3: output ρ = nf, and ARHO's nf
            + 4 + 9; // BL + BLC: the one balance chain
        let registry = 16 * 4 // C_old, C_new, SIB, ISS
            + 2 // POW, PACC
            + 4 // AC_OLD, AC_NEW, MC, AC_SEED
            + 6; // REG, DC, DR, MINV, RINV, AINV
        assert_eq!(machinery, 89);
        assert_eq!(roles, 49);
        assert_eq!(registry, 76);
        assert_eq!(trace.width(), engine + machinery + roles + witness + banks + registry);
        assert_eq!(trace.width(), 734, "the shape-R width (A2's 726 + A3's 8)");
        // Sibling sharing, option (ii) — a 16-accumulator equality per level
        // instead of the one SIB bank closed at every MN — would be 15 × 16 =
        // 240 columns more: 974.
        assert_eq!(trace.width() + 15 * 16, 974);
    }

    /// Max constraint degree 4 (the ruling's ceiling), 4 quotient chunks. The
    /// degree-4 population: the 20 role selectors (A3 added three), the two REG-gated banks
    /// (C_old's seed, ISS: 16 each), the path-bit tie, the PACC step and the
    /// three mode closes (the cubic and the two nonzero-inverse legs).
    #[test]
    fn l2r_quotient_degree_is_4() {
        use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
        let air = L2ShapeRAir::chain_only(SHAPE_R_LOG_HEIGHT);
        let deg = get_max_constraint_degree::<F, _>(&air, AirLayout::from_air::<F>(&air));
        assert_eq!(deg, 4, "max constraint degree — degree 5 is a stop-point (lab #724)");
        assert_eq!((deg - 1).next_power_of_two(), 4, "quotient chunks");
        let cs = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
        let deg4 = cs.iter().filter(|c| c.degree_multiple() == 4).count();
        assert_eq!(deg4, 20 + 16 + 16 + 1 + 1 + 3, "deg-4 constraints");
    }

    /// 82 perms in 2^18, one ring period (no epoch), the program as documented.
    #[test]
    fn l2r_program_geometry() {
        // (Fits 2^18 and one ring period: the module's const asserts.)
        assert_eq!(SHAPE_R_PERMS, 82);
        let p = &register_fixture().inst.air.program;
        let mut want = vec![ROLE_DUMMY, ROLE_ANK, ROLE_NF, ROLE_BNF1, ROLE_ARKM, ROLE_ACM];
        want.extend(std::iter::repeat_n(ROLE_MERKLE, MERKLE_DEPTH));
        want.extend([ROLE_BANCHOR, ROLE_ACMOUT, ROLE_BCM1]);
        want.extend([ROLE_ARHO, ROLE_ACMOUT2, ROLE_BCM2]);
        want.extend([ROLE_AISS, ROLE_AREG_OLD, ROLE_AREG_NEW]);
        for _ in 0..REGISTRY_DEPTH - 1 {
            want.extend([ROLE_MO, ROLE_MN]);
        }
        want.extend([ROLE_MO, ROLE_BREG_OLD, ROLE_MN, ROLE_BREG_NEW, ROLE_BAL]);
        assert_eq!(want.len(), SHAPE_R_PERMS);
        assert_eq!(&p[..SHAPE_R_PERMS], &want[..]);
        assert!(p[SHAPE_R_PERMS..].iter().all(|r| *r == ROLE_DUMMY));
        // Role codes stay unique across the family: R's five new ones are
        // above shape P's 17..=22; ARHO and BCM2 are shape S's own.
        for code in [ROLE_AREG_NEW, ROLE_MO, ROLE_MN, ROLE_BREG_NEW, ROLE_ACMOUT2] {
            assert!(code > 22 && code < 32);
        }
        let mut codes = SEL_CODES.to_vec();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), NSEL, "no two selectors share a role code");
    }

    // -----------------------------------------------------------------------
    // Positives
    // -----------------------------------------------------------------------

    /// Registration into an empty slot: asset 9, Regulated, both policy roots
    /// and a flag set. The public roots are the registry's before and after.
    #[test]
    fn l2r_registration_satisfies_constraints() {
        let fx = register_fixture();
        assert!(fx.inst.air.reg);
        let before = registry();
        let mut after = before.clone();
        after.push(register_leaf());
        assert_eq!(fx.inst.old_root, registry_opening(&before, 9).1, "old root = the registry's");
        assert_eq!(fx.inst.new_root, registry_opening(&after, 9).1, "new root = the registry with the leaf");
        assert_ne!(fx.inst.old_root, fx.inst.new_root);
        fx.assert_sat("registration of asset 9 (Regulated, both roots) at 2^18");
    }

    /// Update: asset 7 rotates its issuer_key (isk proven for the OLD key) and
    /// publishes a new freeze root.
    #[test]
    fn l2r_update_satisfies_constraints() {
        let fx = update_fixture();
        assert!(!fx.inst.air.reg);
        let before = registry();
        let after: Vec<RegistryLeaf> =
            before.iter().map(|l| if l.asset == 7 { update_leaf() } else { *l }).collect();
        assert_eq!(fx.inst.old_root, registry_opening(&before, 7).1);
        assert_eq!(fx.inst.new_root, registry_opening(&after, 7).1);
        fx.assert_sat("update of asset 7 (key rotation + new freeze root) at 2^18");
    }

    /// The chain the AIR advances is the reference one, read off the
    /// registration fixture's trace: AISS, both leaf blocks, both roots.
    #[test]
    fn l2r_registry_chain_matches_reference() {
        let fx = register_fixture();
        let out_of = |role: u32| digest(&L2ShapeRAir::extract_state(&fx.trace, 24 * (at(role) + 1)));
        assert_eq!(out_of(ROLE_AISS), issuer_key_of(&ISK_NONE), "AISS = H(isk ‖ D_I)");
        assert_eq!(out_of(ROLE_AREG_OLD), RegistryLeaf { asset: 0, issuer_key: [0; 4], mode: 0, freeze_root: [0; 4], allow_root: [0; 4], flags: 0 }.hash());
        assert_eq!(out_of(ROLE_AREG_NEW), register_leaf().hash(), "the new leaf block");
        // Slot 9 is odd: MO_1 folds the empty slot as the right child.
        let w = registry_opening(&registry(), 9).0;
        assert!(w.path_bits[0]);
        assert_eq!(out_of(ROLE_MO), digest(&reference::merkle_node_state(&w.siblings[0], &[0; 4])));
        let breg_old = at(ROLE_BREG_OLD);
        let breg_new = at(ROLE_BREG_NEW);
        assert_eq!(digest(&L2ShapeRAir::extract_state(&fx.trace, 24 * breg_old)), fx.inst.old_root);
        assert_eq!(digest(&L2ShapeRAir::extract_state(&fx.trace, 24 * breg_new)), fx.inst.new_root);
        // The fee output's ρ is the input's nullifier.
        let (fin, fout) = fee_parts();
        let (_, nf, _) = derive_input_l2(&fin);
        assert_eq!(fx.inst.nf, nf);
        assert_eq!(fx.inst.cm_out, l2_cm(fout.value, 0, &fout.rkm, &nf, &fout.rseed));
        // A3's seed: ARHO is S's output-1 ρ derivation over this nf, and
        // ACMOUT2 commits the 0-value note of the written asset with it.
        let rho = derive_output_rho(&nf, 1);
        assert_eq!(out_of(ROLE_ARHO), rho, "ARHO = H(nf ‖ D_P|1)");
        let cm_seed = l2_cm(0, 9, &SEED.rkm, &rho, &SEED.rseed);
        assert_eq!(out_of(ROLE_ACMOUT2), cm_seed, "the seed commitment");
        assert_eq!(fx.inst.cm_seed, cm_seed);
        assert_eq!(&fx.inst.pvs[PV_CM_SEED..PV_LEN], &pv_chunks(&cm_seed)[..]);
    }

    /// A3: the update's seed is of the updated asset — the ruling's "every
    /// write", which re-arms minting for an issuer holding no note of it.
    #[test]
    fn l2r_update_seeds_the_updated_asset() {
        let fx = update_fixture();
        fx.assert_sat("precondition");
        let (fin, _) = fee_parts();
        let (_, nf, _) = derive_input_l2(&fin);
        assert_eq!(fx.inst.cm_seed, l2_cm(0, 7, &SEED.rkm, &derive_output_rho(&nf, 1), &SEED.rseed));
    }

    // -----------------------------------------------------------------------
    // Negatives — the ruling's list. Each is a complete forgery where one
    // exists (public values republished to match), refused at a pinned perm.
    // -----------------------------------------------------------------------

    /// 🔴 Registration over a live leaf: "register" asset 7 into slot 7. The
    /// builder folds the zero digest, so its old root is not the registry's;
    /// published against the registry's real root, the old-root bind refuses.
    #[test]
    fn l2r_neg_register_over_a_live_leaf() {
        let mut inst = register(leaf(7, &ISK9, MODE_CLOAKED, [0; 4], [0; 4], 0));
        let real = registry_opening(&registry(), 7).1;
        assert_ne!(inst.old_root, real, "slot 7 is live: the empty-slot fold is another root");
        for (k, c) in pv_chunks(&real).iter().enumerate() {
            inst.pvs[PV_OLD_ROOT + k] = *c;
        }
        assert_refused_at(&inst, at(ROLE_BREG_OLD), "a registration over a live leaf");
    }

    /// 🔴 Update without the issuer's secret: a wrong isk for asset 7.
    #[test]
    fn l2r_neg_update_with_a_wrong_isk() {
        update_fixture().assert_sat("precondition: the right isk verifies");
        let inst = update7(ISK7B, update_leaf());
        assert_refused_at(&inst, at(ROLE_AREG_OLD), "an update with the NEW key's isk");
        let inst = update7(ISK_NONE, update_leaf());
        assert_refused_at(&inst, at(ROLE_AREG_OLD), "an update with an unrelated isk");
    }

    /// 🔴 Update that skips the isk by claiming a registration: REG = 1 on a
    /// live slot needs the old fold to start from the empty digest — the
    /// same refusal as registering over a live leaf, reached from the trace.
    #[test]
    fn l2r_neg_update_disguised_as_registration() {
        let fx = update_fixture();
        let mut inst = fx.inst.clone();
        inst.air.reg = true;
        assert_refused_at(&inst, at(ROLE_MO), "an update with REG = 1");
    }

    /// 🔴 mode ⇒ roots, each leg, with the declarations honest (refused on
    /// AREG_NEW's rows) and lied (refused at the registry close).
    #[test]
    fn l2r_neg_mode_implies_roots() {
        let anew = at(ROLE_AREG_NEW);
        let rclose = at(ROLE_BREG_NEW);
        let cases: [(&str, RegistryLeaf, usize, u64); 3] = [
            ("Cloaked with a freeze root", leaf(9, &ISK9, MODE_CLOAKED, [1, 0, 0, 0], [0; 4], 0), DC_COL, 0),
            ("Cloaked with a flag", leaf(9, &ISK9, MODE_CLOAKED, [0; 4], [0; 4], 1), DC_COL, 0),
            ("Hybrid with an allow root", leaf(9, &ISK9, MODE_HYBRID, [0; 4], [0, 0, 0, 1 << 63], 0), DR_COL, 1),
        ];
        for (what, bad, col, lie) in cases {
            let inst = register(bad);
            let trace = inst.air.generate_trace::<F>(0);
            let pvs = pvs_of(&inst);
            assert_trace_refused_at(&inst, &trace, &pvs, anew, what);
            // The declaration lied so the per-row leg is off: the close refuses.
            let mut lied = trace;
            for row in 0..lied.height() {
                lied.values[row * L2R_WIDTH + col] = F::from_u64(lie);
            }
            assert_trace_refused_at(&inst, &lied, &pvs, rclose, &format!("{what}, declaration lied"));
        }
        // Regulated takes both roots — the registration fixture.
        register_fixture().assert_sat("Regulated with both roots");
    }

    /// 🔴 The mode lane is 0, 1 or 2: 3 fails the cubic at the close, 4 (a
    /// bit above the two) fails on AREG_NEW's rows.
    #[test]
    fn l2r_neg_mode_out_of_range() {
        let inst = register(leaf(9, &ISK9, 3, [0; 4], [0; 4], 0));
        assert_refused_at(&inst, at(ROLE_BREG_NEW), "mode 3");
        let inst = register(leaf(9, &ISK9, 4, [0; 4], [0; 4], 0));
        assert_refused_at(&inst, at(ROLE_AREG_NEW), "mode 4");
    }

    /// 🔴 Asset 0 is never writable — even by the holder of its isk.
    #[test]
    fn l2r_neg_asset_0_is_not_writable() {
        let new0 = leaf(0, &ISK7B, MODE_CLOAKED, [0; 4], [0; 4], 0);
        let inst = instance(&write_at(0, ISK0, Some(leaf_of(0)), new0));
        assert_refused_at(&inst, at(ROLE_BREG_NEW), "an update of asset 0 with its isk");
    }

    /// 🔴 The planting registration: asset 9's leaf into the EMPTY slot 10 —
    /// a complete, consistent write of a tree that would break the registry
    /// invariant S and P rely on. Only path = asset refuses it.
    #[test]
    fn l2r_neg_planting_registration() {
        let planted = register_leaf();
        let inst = instance(&write_at(10, ISK_NONE, None, planted));
        assert_eq!(inst.old_root, registry_opening(&registry(), 10).1, "honest old root: slot 10 is empty");
        assert_refused_at(&inst, at(ROLE_BREG_NEW), "asset 9's leaf planted at slot 10");
    }

    /// 🔴 An update cannot move an asset: in a (planted, invariant-breaking)
    /// tree holding asset 9's leaf at slot 7, rewriting slot 7 as asset 7
    /// with 9's isk is refused by `AC_OLD = AC_NEW`.
    #[test]
    fn l2r_neg_update_changes_the_asset() {
        let squatter = leaf(9, &ISK9, MODE_CLOAKED, [0; 4], [0; 4], 0);
        let mut tree = registry();
        tree.retain(|l| l.asset != 7);
        let (mut opening, _) = registry_opening(&tree, 7);
        opening.path_bits = core::array::from_fn(|l| (7u64 >> l) & 1 == 1);
        let write = RegistryWrite {
            isk: ISK9,
            old_leaf: Some(squatter),
            new_leaf: leaf(7, &ISK9, MODE_CLOAKED, [0; 4], [0; 4], 0),
            opening,
        };
        assert_refused_at(&instance(&write), at(ROLE_BREG_NEW), "an update from asset 9 to asset 7");
    }

    /// Recompute the new chain from AREG_NEW's leaf through every MN's own
    /// (path bit, sibling), rewrite the MN digests and republish the new root
    /// — a tamper of MN's witness leaves the new fold internally consistent.
    fn republish_new_chain(inst: &mut L2ShapeRInstance) {
        let p = inst.air.program;
        let anew = slot_of(&p, ROLE_AREG_NEW, 0);
        let w = inst.air.slot_witness[anew].w;
        let mut d = RegistryLeaf {
            asset: w[13],
            issuer_key: w[..4].try_into().unwrap(),
            mode: w[4],
            freeze_root: w[5..9].try_into().unwrap(),
            allow_root: w[9..13].try_into().unwrap(),
            flags: w[14],
        }
        .hash();
        for lvl in 0..REGISTRY_DEPTH {
            let s = slot_of(&p, ROLE_MN, lvl);
            let sw = &mut inst.air.slot_witness[s];
            sw.w[4..8].copy_from_slice(&d);
            let sib: [u64; 4] = sw.w[..4].try_into().unwrap();
            let st = if sw.pbit {
                reference::merkle_node_state(&sib, &d)
            } else {
                reference::merkle_node_state(&d, &sib)
            };
            d = digest(&st);
        }
        inst.new_root = d;
        for (k, c) in pv_chunks(&d).iter().enumerate() {
            inst.pvs[PV_NEW_ROOT + k] = *c;
        }
    }

    /// 🔴 The new fold on another path than the old: MN_4's path bit flipped
    /// (the new root republished) — refused by the MO → MN path-bit tie.
    /// Level 16's tie runs across BREG_OLD, so it is tampered too.
    #[test]
    fn l2r_neg_new_fold_on_another_path() {
        for lvl in [3usize, REGISTRY_DEPTH - 1] {
            let mut inst = update_fixture().inst.clone();
            let s = slot_of(&inst.air.program, ROLE_MN, lvl);
            inst.air.slot_witness[s].pbit ^= true;
            republish_new_chain(&mut inst);
            // The tie fires on the last row of the perm before MN.
            assert_refused_at(&inst, s - 1, &format!("MN level {} on another path", lvl + 1));
        }
    }

    /// 🔴 Reordered siblings: MN_3 and MN_4 swap siblings (the new root
    /// republished) — the SIB bank refuses at MN_3's close.
    #[test]
    fn l2r_neg_reordered_siblings() {
        let mut inst = update_fixture().inst.clone();
        let (s3, s4) = (slot_of(&inst.air.program, ROLE_MN, 2), slot_of(&inst.air.program, ROLE_MN, 3));
        let a3: [u64; 4] = inst.air.slot_witness[s3].w[..4].try_into().unwrap();
        let a4: [u64; 4] = inst.air.slot_witness[s4].w[..4].try_into().unwrap();
        assert_ne!(a3, a4);
        inst.air.slot_witness[s3].w[..4].copy_from_slice(&a4);
        inst.air.slot_witness[s4].w[..4].copy_from_slice(&a3);
        republish_new_chain(&mut inst);
        assert_refused_at(&inst, s3, "the new fold with levels 3/4's siblings swapped");
    }

    /// 🔴 A published asset id that is not the written slot's.
    #[test]
    fn l2r_neg_asset_public_value_lie() {
        let fx = register_fixture();
        let mut pvs = fx.pvs.clone();
        pvs[PV_ASSET] = F::from_u32(10);
        assert_trace_refused_at(&fx.inst, &fx.trace, &pvs, at(ROLE_BREG_NEW), "PV_ASSET = 10 for a write of 9");
    }

    /// 🔴 The fee spend: an output worth more than the input minus the fee;
    /// a fee paid in asset 7; an output ρ that is not the nullifier (the
    /// commitment republished to match it).
    #[test]
    fn l2r_neg_fee_spend() {
        let write = write_at(9, ISK_NONE, None, register_leaf());
        let (fin, mut fout) = fee_parts();
        fout.value += 1;
        let inst = build_shape_r(SHAPE_R_LOG_HEIGHT, &fin, &fout, FEE, &write, &SEED);
        assert_refused_at(&inst, at(ROLE_BAL), "100 in, 94 out + fee 7");

        let (mut fin, mut fout) = fee_parts();
        fin.asset = 7;
        fout.asset = 7;
        let inst = build_shape_r(SHAPE_R_LOG_HEIGHT, &fin, &fout, FEE, &write, &SEED);
        assert_refused_at(&inst, at(ROLE_ACM), "the fee paid in asset 7");

        let mut inst = register_fixture().inst.clone();
        let s = at(ROLE_ACMOUT);
        let rho = [0x1111, 0x2222, 0x3333, 0x4444];
        inst.air.slot_witness[s].w[5..9].copy_from_slice(&rho);
        let (_, fout) = fee_parts();
        let cm = l2_cm(fout.value, 0, &fout.rkm, &rho, &fout.rseed);
        for (k, c) in pv_chunks(&cm).iter().enumerate() {
            inst.pvs[PV_CM + k] = *c;
        }
        assert_refused_at(&inst, s, "an output ρ that is not the nullifier");
    }

    // -----------------------------------------------------------------------
    // A3 — the seed output (lab #731, ruled on #730). Complete forgeries: the
    // seed's commitment is republished to match each tamper, so only the
    // constraint the test names can refuse it.
    // -----------------------------------------------------------------------

    /// Rewrite the seed slot's witness with `f`, recompute its commitment from
    /// the lanes the circuit hashes (ρ from `rho`), and republish it.
    fn republish_seed(inst: &mut L2ShapeRInstance, rho: [u64; 4], f: impl Fn(&mut [u64; NW])) {
        let s = slot_of(&inst.air.program, ROLE_ACMOUT2, 0);
        f(&mut inst.air.slot_witness[s].w);
        let w = inst.air.slot_witness[s].w;
        let cm = l2_cm(w[4], w[13], &w[..4].try_into().unwrap(), &rho, &w[9..13].try_into().unwrap());
        inst.cm_seed = cm;
        for (k, c) in pv_chunks(&cm).iter().enumerate() {
            inst.pvs[PV_CM_SEED + k] = *c;
        }
    }
    fn seed_rho(inst: &L2ShapeRInstance) -> [u64; 4] {
        derive_output_rho(&inst.nf, 1)
    }

    /// 🔴 A nonzero seed: value 5 minted out of nothing — refused on
    /// ACMOUT2's own rows (the value lane is zero bit by bit).
    #[test]
    fn l2r_neg_seed_with_a_value() {
        register_fixture().assert_sat("precondition");
        for (what, v) in [("value 5", 5u64), ("value 2^63", 1 << 63)] {
            let mut inst = register_fixture().inst.clone();
            let rho = seed_rho(&inst);
            republish_seed(&mut inst, rho, |w| w[4] = v);
            assert_refused_at(&inst, at(ROLE_ACMOUT2), &format!("a seed of {what}"));
        }
        let mut inst = update_fixture().inst.clone();
        let rho = seed_rho(&inst);
        republish_seed(&mut inst, rho, |w| w[4] = 1);
        assert_refused_at(&inst, at(ROLE_ACMOUT2), "an update's seed of value 1");
    }

    /// 🔴 A seed of another asset than the one written: 8 for a write of 9
    /// (refused at the registry close), 0 — a free fee-unit note — and one
    /// above 16 bits whose chunk 0 matches (refused on ACMOUT2's rows).
    #[test]
    fn l2r_neg_seed_of_a_wrong_asset() {
        let rclose = at(ROLE_BREG_NEW);
        for (what, asset) in [("asset 8 for a write of 9", 8u64), ("asset 0 for a write of 9", 0)] {
            let mut inst = register_fixture().inst.clone();
            let rho = seed_rho(&inst);
            republish_seed(&mut inst, rho, |w| w[13] = asset);
            assert_refused_at(&inst, rclose, what);
        }
        let mut inst = register_fixture().inst.clone();
        let rho = seed_rho(&inst);
        republish_seed(&mut inst, rho, |w| w[13] = 9 + (1 << 16));
        assert_refused_at(&inst, at(ROLE_ACMOUT2), "asset 9 + 2^16 (chunk 0 = 9)");
        let mut inst = update_fixture().inst.clone();
        let rho = seed_rho(&inst);
        republish_seed(&mut inst, rho, |w| w[13] = 9);
        assert_refused_at(&inst, rclose, "an update of 7 seeding asset 9");
    }

    /// 🔴 The seed's ρ off another nullifier: ARHO absorbs a made-up nf (so
    /// the seed could collide with, or shadow, another note's ρ); the
    /// commitment republished — refused at ARHO's close (bank 3).
    #[test]
    fn l2r_neg_seed_rho_off_another_nf() {
        let mut inst = register_fixture().inst.clone();
        let arho = at(ROLE_ARHO);
        let fake = [0x1234, 0x5678, 0x9abc, 0xdef0];
        inst.air.slot_witness[arho].w[..4].copy_from_slice(&fake);
        republish_seed(&mut inst, derive_output_rho(&fake, 1), |_| {});
        assert_refused_at(&inst, arho, "ARHO over a nullifier that is not the public one");
    }

    /// 🔴 A published seed commitment that is not the one committed: BCM2
    /// refuses.
    #[test]
    fn l2r_neg_seed_commitment_lie() {
        let fx = register_fixture();
        let mut pvs = fx.pvs.clone();
        pvs[PV_CM_SEED + 5] += F::ONE;
        assert_trace_refused_at(&fx.inst, &fx.trace, &pvs, at(ROLE_BCM2), "a republished seed cm");
    }
}
