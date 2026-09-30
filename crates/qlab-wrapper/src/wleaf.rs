//! Lab #775 F4 — **W, the wrapper leaf AIR**: F3's state leaf
//! (qlab-bench's `f3::leaf`), extended with the claim slot, the L1-anchor
//! accumulator, CH, the supply tree, the exit list and the sequencer fee
//! note. It proves qlab-bench's `f4::native::check_wrapper_leaf`.
//!
//! **The program.** A prologue, `k` slots, an epilogue, then `PAD`:
//!
//! ```text
//!   prologue (127 perms):
//!     absorb   H(a0,a1), H(a2,a3), their parent; one pair path over AA's
//!              levels 2..31 (60): the four roots as one aligned subtree,
//!              its old side the empty subtree zeros[2] (aa_next ≡ 0 mod 4)
//!     history  C_in appended to CH (64)
//!   slot ×k (662 perms):
//!     F3's slot    SD 6 | inserts 3 × 131 | appends 2 × 64 | registry 33
//!     vPublic ×2   old leaf, new leaf, supply pair path (34 each; P only)
//!     exits ×2     the exit chain's steps (P redeems on asset 0)
//!     anchor       32: a transaction's anchor opened in CH, a claim's in AA
//!   epilogue (67 perms): ρ(prev), rseed(prev), the fee note, its append to C
//! ```
//!
//! **The claim slot** (tag `C`, SD word 0 = `0x04`): insert 0 is its `cnf`,
//! committed to `K` (not `N`); append 0 is its `cm2`; its anchor opens in
//! `AA` (`A ≠ 0`); its fee chunks add into the fee accumulator. Inserts 1–2,
//! append 1, SD blocks 4–5, the registry and the `vPublic` segments are off for
//! a claim.
//!
//! **The fee note** is appended in every wrapper (value 0 with no claims):
//! `cm = H(value ‖ 0 ‖ rkm_seq ‖ ρ ‖ rseed)` with `value` the accumulator
//! normalized to four 16-bit limbs (carries ≤ 5 bits: at most 31 claims per
//! leaf), `ρ`/`rseed` the two domain-tagged perms over the `prev` PV.
//!
//! **D/E**: `D_out = D_in + D_batch` (FeeRho row) and `E_out = E_in + Σ
//! exits` (FeeRseed row), u64 limbs with 6-bit carries and no carry out.
//! `D_batch` is a W public value; the deposit-sum proof ([`super::dep`])
//! binds it to the claims' `Cv`s at the verifier (V9).
//!
//! Degree 3 throughout, by the same device as F3: every flag a data
//! constraint needs is a materialized column.
use std::ops::Range;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use qlab_consensus::Val;

use crate::hash::{fee_domain_lanes, WTag, M_ABS};
use crate::cmp::{self, limbs, LT_WIDTH};
use crate::hash::{keccak_idx, KeccakIdx};
use crate::hash::{sd_domain_lanes, sd_perms, Digest, EMPTY, N_DEPTH, SD_BLOCK_WORDS, SD_LANE_DOMAIN, SD_LANE_FINAL, SD_LANE_INDEX, SD_LANE_MSG};
use crate::lane::LaneBuilder;

// ---------------------------------------------------------------------------
// The program
// ---------------------------------------------------------------------------

/// SD blocks per slot: the most any shape needs (S 5, P 6, R 4, C 1) —
/// P's exit recipient (lab #785 F5-4d) took it from 5 to 6.
pub const SD_BLOCKS: usize = 6;
const _: () = assert!(SD_BLOCKS == sd_perms(qlab_air::l2p::PV_LEN));
pub const INSERTS: usize = 3;
pub const APPENDS: usize = 2;
pub const R_DEPTH: usize = qlab_air::l2::REGISTRY_DEPTH;
/// Claims per leaf the fee carries' 5-bit width covers: a limb sum of
/// `MAX_CLAIMS` 16-bit chunks plus a carry-in keeps its carry-out < 2^5.
pub const MAX_CLAIMS: usize = 31;
const _: () = assert!(MAX_CLAIMS * 0xffff + 31 < 32 << 16);
/// The widest `k` any wrapper version proves (`verify::VERSIONS`).
pub const MAX_K: usize = 16;
const _: () = assert!(MAX_K <= MAX_CLAIMS);
/// E's 6-bit carries: a limb of `E_in`, two exit chunks per slot and a
/// carry-in keep the carry-out < 2^6 for every `k ≤ MAX_K` (sound to k = 31;
/// past that the honest wrapper is unsatisfiable, never unsound). D adds one
/// chunk per limb.
const _: () = assert!((1 + 2 * MAX_K) * 0xffff + 63 < 64 << 16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathId {
    Mid(usize),
    New(usize),
    C(usize),
    R,
    /// The absorbed L1 roots' depth-2 subtree appended to AA (levels 2..31).
    Abs,
    /// `C_in` appended to CH.
    Hist,
    /// A `vPublic` row's supply-leaf replacement (old, new).
    Sup(usize),
    /// The fee note appended to C.
    Fee,
}

impl PathId {
    pub const fn depth(self) -> usize {
        match self {
            PathId::R | PathId::Sup(_) => R_DEPTH,
            _ => N_DEPTH,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Bulk,
    L30,
    LastA,
    LastB,
}

/// The anchor path's parts: levels 0..29, level 30, level 31 (bits 30/31 zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum APart {
    Low,
    L30,
    Last,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seg {
    /// The absorbed roots' subtree: `H(a0, a1)`, `H(a2, a3)`, their parent.
    AbsNode(usize),
    Sd(usize),
    LeafOld(usize),
    LeafMid(usize),
    LeafNew(usize),
    Pair(PathId, Part),
    RegLeaf,
    /// A `vPublic` row's old and new supply leaves.
    SupOld(usize),
    SupNew(usize),
    /// A `vPublic` row's exit-chain step.
    Exit(usize),
    Anch(APart),
    FeeRho,
    FeeRseed,
    FeeNote,
    Pad,
}

/// The prologue: the subtree's 3 nodes, its pair path (4 parts), CH's (4 parts).
pub const PRO: usize = 3 + 4 + 4;
/// The absorbed roots form one aligned depth-2 subtree of AA.
pub const ABS_LEVELS: usize = 2;
const _: () = assert!(M_ABS == 1 << ABS_LEVELS);
/// The slot's segments after the SD blocks: inserts 3 × 11, appends 2 × 4,
/// the registry 4, `vPublic` 2 × 5, exits 2, anchor 3.
const SLOT_TAIL: usize = 3 * 11 + 2 * 4 + 4 + 2 * 5 + 2 + 3;
pub const SLOT_SEGS: usize = SD_BLOCKS + SLOT_TAIL;
pub const SLOT_BASE: usize = PRO;
pub const EPI_BASE: usize = SLOT_BASE + SLOT_SEGS;
pub const EPI: usize = 7;
pub const PAD: usize = EPI_BASE + EPI;
pub const NSEG_COLS: usize = PAD + 1;
pub const SLOT_LAST: usize = EPI_BASE - 1;

const fn part_off(p: Part) -> usize {
    match p {
        Part::Bulk => 0,
        Part::L30 => 1,
        Part::LastA => 2,
        Part::LastB => 3,
    }
}

impl Seg {
    /// The segment's ring position.
    pub const fn idx(self) -> usize {
        let b = SLOT_BASE;
        // The slot's segments after its SD blocks.
        let l = SLOT_BASE + SD_BLOCKS;
        match self {
            Seg::AbsNode(j) => j,
            Seg::Pair(PathId::Abs, p) => 3 + part_off(p),
            Seg::Pair(PathId::Hist, p) => 7 + part_off(p),
            Seg::Sd(k) => b + k,
            Seg::LeafOld(i) => l + 11 * i,
            Seg::LeafMid(i) => l + 11 * i + 1,
            Seg::Pair(PathId::Mid(i), p) => l + 11 * i + 2 + part_off(p),
            Seg::LeafNew(i) => l + 11 * i + 6,
            Seg::Pair(PathId::New(i), p) => l + 11 * i + 7 + part_off(p),
            Seg::Pair(PathId::C(j), p) => l + 33 + 4 * j + part_off(p),
            Seg::RegLeaf => l + 41,
            Seg::Pair(PathId::R, Part::Bulk) => l + 42,
            Seg::Pair(PathId::R, Part::LastA) => l + 43,
            Seg::Pair(PathId::R, _) => l + 44,
            Seg::SupOld(k) => l + 45 + 5 * k,
            Seg::SupNew(k) => l + 46 + 5 * k,
            Seg::Pair(PathId::Sup(k), Part::Bulk) => l + 47 + 5 * k,
            Seg::Pair(PathId::Sup(k), Part::LastA) => l + 48 + 5 * k,
            Seg::Pair(PathId::Sup(k), _) => l + 49 + 5 * k,
            Seg::Exit(k) => l + 55 + k,
            Seg::Anch(APart::Low) => l + 57,
            Seg::Anch(APart::L30) => l + 58,
            Seg::Anch(APart::Last) => l + 59,
            Seg::FeeRho => EPI_BASE,
            Seg::FeeRseed => EPI_BASE + 1,
            Seg::FeeNote => EPI_BASE + 2,
            Seg::Pair(PathId::Fee, p) => EPI_BASE + 3 + part_off(p),
            Seg::Pad => PAD,
        }
    }

    // A segment's permutation count, never empty; widened from pub(crate) by the move.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(self) -> usize {
        match self {
            Seg::Pair(PathId::R | PathId::Sup(_), Part::Bulk) => 30,
            Seg::Pair(PathId::Abs, Part::Bulk) => 2 * (30 - ABS_LEVELS),
            Seg::Pair(_, Part::Bulk) => 60,
            Seg::Pair(_, Part::L30) => 2,
            Seg::Anch(APart::Low) => 30,
            _ => 1,
        }
    }

    /// Whether the segment acts for a slot of tag `t` (prologue and epilogue
    /// always act; `PAD` never).
    pub fn active(self, t: WTag) -> bool {
        let (r, c) = (t == WTag::R, t == WTag::C);
        match self {
            Seg::Sd(b) => b < sd_perms(t.pv_len()),
            Seg::LeafOld(i) | Seg::LeafMid(i) | Seg::LeafNew(i) | Seg::Pair(PathId::Mid(i) | PathId::New(i), _) => {
                i == 0 || !(r || c)
            }
            Seg::Pair(PathId::C(j), _) => j == 0 || !c,
            Seg::RegLeaf | Seg::Pair(PathId::R, _) => r,
            Seg::SupOld(_) | Seg::SupNew(_) | Seg::Exit(_) | Seg::Pair(PathId::Sup(_), _) => t == WTag::P,
            Seg::Anch(_) => true,
            Seg::AbsNode(_) | Seg::Pair(PathId::Abs | PathId::Hist | PathId::Fee, _) | Seg::FeeRho | Seg::FeeRseed | Seg::FeeNote => true,
            Seg::Pad => false,
        }
    }

    fn in_slot(self) -> bool {
        (SLOT_BASE..EPI_BASE).contains(&self.idx())
    }

    pub fn is_pair_bulk(self) -> bool {
        matches!(self, Seg::Pair(_, Part::Bulk | Part::L30))
    }

}

const PARTS: [Part; 4] = [Part::Bulk, Part::L30, Part::LastA, Part::LastB];

/// Every segment in ring order (without `PAD`).
pub fn program() -> Vec<Seg> {
    let mut v: Vec<Seg> = (0..3).map(Seg::AbsNode).collect();
    v.extend(PARTS.map(|p| Seg::Pair(PathId::Abs, p)));
    v.extend(PARTS.map(|p| Seg::Pair(PathId::Hist, p)));
    v.extend((0..SD_BLOCKS).map(Seg::Sd));
    for i in 0..INSERTS {
        v.push(Seg::LeafOld(i));
        v.push(Seg::LeafMid(i));
        v.extend(PARTS.map(|p| Seg::Pair(PathId::Mid(i), p)));
        v.push(Seg::LeafNew(i));
        v.extend(PARTS.map(|p| Seg::Pair(PathId::New(i), p)));
    }
    for j in 0..APPENDS {
        v.extend(PARTS.map(|p| Seg::Pair(PathId::C(j), p)));
    }
    v.push(Seg::RegLeaf);
    v.extend([Part::Bulk, Part::LastA, Part::LastB].map(|p| Seg::Pair(PathId::R, p)));
    for k in 0..2 {
        v.push(Seg::SupOld(k));
        v.push(Seg::SupNew(k));
        v.extend([Part::Bulk, Part::LastA, Part::LastB].map(|p| Seg::Pair(PathId::Sup(k), p)));
    }
    v.extend([Seg::Exit(0), Seg::Exit(1)]);
    v.extend([APart::Low, APart::L30, APart::Last].map(Seg::Anch));
    v.extend([Seg::FeeRho, Seg::FeeRseed, Seg::FeeNote]);
    v.extend(PARTS.map(|p| Seg::Pair(PathId::Fee, p)));
    debug_assert!(v.iter().enumerate().all(|(i, s)| s.idx() == i));
    v
}

/// The slot's segments.
pub fn slot_program() -> Vec<Seg> {
    program()[SLOT_BASE..EPI_BASE].to_vec()
}

pub const PRO_PERMS: usize = 127;
pub const SLOT_PERMS: usize = 662;

/// Lab #785 F5-4d: the SD bump moves no height — the rows `(127 + 662k +
/// 67)·24` for k = 1, 2, 4, 8, 16 round to the same powers of two as before.
const fn w_rows(k: usize) -> usize {
    (PRO_PERMS + k * SLOT_PERMS + EPI_PERMS) * NUM_ROUNDS
}
const _: () = assert!(w_rows(1).next_power_of_two() == 1 << 15);
const _: () = assert!(w_rows(2).next_power_of_two() == 1 << 16);
const _: () = assert!(w_rows(4).next_power_of_two() == 1 << 17);
const _: () = assert!(w_rows(8).next_power_of_two() == 1 << 18);
const _: () = assert!(w_rows(MAX_K).next_power_of_two() == 1 << 18);
pub const EPI_PERMS: usize = 67;

/// The perm index of segment `seg`'s `i`-th perm (`slot` ignored outside a slot).
pub fn perm_at(slot: usize, seg: Seg, i: usize) -> usize {
    let prog = program();
    let before: usize = prog.iter().take(seg.idx()).map(|s| s.len()).sum();
    if seg.in_slot() {
        before + SLOT_PERMS * slot + i
    } else if seg.idx() >= EPI_BASE {
        let k_minus_1_slots = slot;
        before + SLOT_PERMS * k_minus_1_slots + i
    } else {
        before + i
    }
}

pub fn row_of(perm: usize, r: usize) -> usize {
    NUM_ROUNDS * perm + r
}

pub fn w_height(k: usize) -> usize {
    w_rows(k).next_power_of_two()
}

/// Tag column order.
pub const TAGS: [WTag; 4] = WTag::ALL;
const T_P: usize = 1;
const T_R: usize = 2;
const T_C: usize = 3;

pub fn sd_final(b: usize, t: WTag) -> bool {
    b + 1 == sd_perms(t.pv_len())
}

/// `(register column, chunks, [(tag index, PV offset)])`.
type Capture = (usize, usize, Vec<(usize, usize)>);

fn captures() -> Vec<Capture> {
    use qlab_air::{claim, l2, l2p, l2r};
    let (s, p, r, c) = (0, 1, 2, 3);
    vec![
        (NF_OFF, 16, vec![(s, l2::PV_NF1), (p, l2::PV_NF1), (r, l2r::PV_NF), (c, claim::PV_CNF)]),
        (NF_OFF + 16, 16, vec![(s, l2::PV_NF2), (p, l2::PV_NF2)]),
        (NF_OFF + 32, 16, vec![(s, l2::PV_NF3), (p, l2p::PV_NF3)]),
        (CM_OFF, 16, vec![(s, l2::PV_CM1), (p, l2::PV_CM1), (r, l2r::PV_CM), (c, claim::PV_CM2)]),
        (CM_OFF + 16, 16, vec![(s, l2::PV_CM2), (p, l2::PV_CM2), (r, l2r::PV_CM_SEED)]),
        (RT_OFF, 16, vec![(s, l2::PV_REGROOT), (p, l2::PV_REGROOT), (r, l2r::PV_OLD_ROOT)]),
        (NRT_OFF, 16, vec![(r, l2r::PV_NEW_ROOT)]),
        (ASSET, 1, vec![(r, l2r::PV_ASSET)]),
        (ANC_OFF, 16, vec![(s, l2::PV_ANCHOR), (p, l2::PV_ANCHOR), (r, l2r::PV_ANCHOR), (c, claim::PV_A)]),
        (VS_OFF, 1, vec![(p, l2p::PV_VP1)]),
        (VS_OFF + 1, 1, vec![(p, l2p::PV_VP2)]),
        (VM_OFF, 4, vec![(p, l2p::PV_VP1 + 1)]),
        (VM_OFF + 4, 4, vec![(p, l2p::PV_VP2 + 1)]),
        (VA_OFF, 1, vec![(p, l2p::PV_VP1 + 5)]),
        (VA_OFF + 1, 1, vec![(p, l2p::PV_VP2 + 5)]),
    ]
}

fn pv_pos(p: usize) -> (usize, usize, usize) {
    let w = 2 + p;
    let (b, o) = (w / SD_BLOCK_WORDS, w % SD_BLOCK_WORDS);
    (b, SD_LANE_MSG + o / 2, 2 * (o % 2))
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

pub const CMP_OFF: usize = NUM_KECCAK_COLS;
pub const SEG_OFF: usize = CMP_OFF + LT_WIDTH;
pub const REM: usize = SEG_OFF + NSEG_COLS;
pub const Z: usize = REM + 1;
pub const ZINV: usize = Z + 1;
pub const LEFT: usize = ZINV + 1;
pub const ZL: usize = LEFT + 1;
pub const ZLINV: usize = ZL + 1;
pub const SIDE: usize = ZLINV + 1;
pub const TAG_OFF: usize = SIDE + 1;
pub const N_OFF: usize = TAG_OFF + 4;
pub const NN: usize = N_OFF + 16;
pub const C_OFF: usize = NN + 1;
pub const CN: usize = C_OFF + 16;
pub const R_OFF: usize = CN + 1;
pub const SD_OFF: usize = R_OFF + 16;
pub const K_OFF: usize = SD_OFF + 16;
pub const KN: usize = K_OFF + 16;
pub const AA_OFF: usize = KN + 1;
pub const AAN: usize = AA_OFF + 16;
pub const NF_OFF: usize = AAN + 1;
pub const CM_OFF: usize = NF_OFF + 16 * INSERTS;
pub const RT_OFF: usize = CM_OFF + 16 * APPENDS;
pub const NRT_OFF: usize = RT_OFF + 16;
pub const ASSET: usize = NRT_OFF + 16;
pub const ANC_OFF: usize = ASSET + 1;
pub const HI_OFF: usize = ANC_OFF + 16;
pub const NA_OFF: usize = HI_OFF + 16;
pub const NB_OFF: usize = NA_OFF + 16;
pub const SIB_OFF: usize = NB_OFF + 16;
pub const BIT: usize = SIB_OFF + 16;
pub const ACC: usize = BIT + 1;
pub const PW: usize = ACC + 1;
pub const BP: usize = PW + 1;
pub const AINV: usize = BP + 1;
pub const ANINV: usize = AINV + 1;
pub const RCNT: usize = ANINV + 1;
/// The fee accumulator: four unnormalized 16-bit-chunk sums.
pub const FE_OFF: usize = RCNT + 1;
/// The fee note's ρ and rseed.
pub const RHO_OFF: usize = FE_OFF + 4;
pub const RSD_OFF: usize = RHO_OFF + 16;
/// The value's three carries, five bits each.
pub const FCB_OFF: usize = RSD_OFF + 16;
/// CH (the C-root history) and its next index; the supply tree's root.
pub const CH_OFF: usize = FCB_OFF + 15;
pub const CHN: usize = CH_OFF + 16;
pub const SUP_OFF: usize = CHN + 1;
/// A P slot's two `vPublic` rows (captured): sign, amount (4 chunks), asset.
pub const VS_OFF: usize = SUP_OFF + 16;
pub const VM_OFF: usize = VS_OFF + 2;
pub const VA_OFF: usize = VM_OFF + 8;
/// `[asset == 0]` per row and its inverse witness.
pub const ZV_OFF: usize = VA_OFF + 2;
pub const ZVINV_OFF: usize = ZV_OFF + 2;
/// The old outstanding (SupOld → SupNew) and the supply addition's carries.
pub const OLDV_OFF: usize = ZVINV_OFF + 2;
pub const SCB_OFF: usize = OLDV_OFF + 4;
/// The exit accumulator (unnormalized chunk sums) and the exit chain.
pub const EA_OFF: usize = SCB_OFF + 3;
pub const EXC_OFF: usize = EA_OFF + 4;
/// D/E normalization carries (six bits each; D on FeeRho, E on FeeRseed).
pub const ECB_OFF: usize = EXC_OFF + 16;
pub const ON: usize = ECB_OFF + 18;
pub const KPA: usize = ON + 1;
pub const KPB: usize = KPA + 1;
pub const KCMP: usize = KPB + 1;
pub const KNC: usize = KCMP + 1;
pub const KNI: usize = KNC + 1;
pub const KKC: usize = KNI + 1;
pub const KKI: usize = KKC + 1;
pub const KCC: usize = KKI + 1;
pub const KR: usize = KCC + 1;
pub const KAN: usize = KR + 1;
pub const KFE: usize = KAN + 1;
pub const W: usize = KFE + 1;
pub const SDC: usize = W + 1;
pub const SDF: usize = SDC + 1;
/// Transaction-anchor (CH) check; per-row exit flag, exit perm, supply
/// SupNew and LastB flags, asset-0 mint flag.
pub const KCH: usize = SDF + 1;
pub const XF_OFF: usize = KCH + 1;
pub const KX_OFF: usize = XF_OFF + 2;
pub const KSN_OFF: usize = KX_OFF + 2;
pub const KSU_OFF: usize = KSN_OFF + 2;
pub const MZ_OFF: usize = KSU_OFF + 2;
pub const W_WIDTH: usize = MZ_OFF + 2;
/// Lab #785 F5-4d-1: one SD block more (3,470 → 3,471); 4d-2 moves it again.
const _: () = assert!(W_WIDTH == 3_471);

// ---------------------------------------------------------------------------
// Public values
// ---------------------------------------------------------------------------

/// One side of the threading surface (16-bit chunks): `N` 16, `n_next` 2,
/// `C` 16, `c_next` 2, `R` 16, `SD` 16, `K` 16, `k_next` 2, `AA` 16, `aa_next` 2.
pub const PV_N: usize = 0;
pub const PV_NN: usize = 16;
pub const PV_C: usize = 18;
pub const PV_CN: usize = 34;
pub const PV_R: usize = 36;
pub const PV_SD: usize = 52;
pub const PV_K: usize = 68;
pub const PV_KN: usize = 84;
pub const PV_AA: usize = 86;
pub const PV_AAN: usize = 102;
/// F4-2: `CH` 16, `ch_next` 2, the supply root 16, `D_cum` 4, `E_cum` 4.
pub const PV_CH: usize = 104;
pub const PV_CHN: usize = 120;
pub const PV_SUP: usize = 122;
pub const PV_D: usize = 138;
pub const PV_E: usize = 142;
pub const PV_SIDE: usize = 146;
/// After in and out: `prev` 16, `rkm_seq` 16, the absorbed roots 4 × 16, the
/// fee note's value 4, `D_batch` 4, the batch's `exit_cmt` 16.
pub const PV_PREV: usize = 2 * PV_SIDE;
pub const PV_RKMS: usize = PV_PREV + 16;
pub const PV_ABS: usize = PV_RKMS + 16;
pub const PV_FEE: usize = PV_ABS + 16 * M_ABS;
pub const PV_DB: usize = PV_FEE + 4;
pub const PV_EXC: usize = PV_DB + 4;
pub const W_PV_LEN: usize = PV_EXC + 16;

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

/// W for `k` slots.
pub struct WAir {
    pub k: usize,
    kc: KeccakIdx,
}

impl WAir {
    pub fn new(k: usize) -> Self {
        assert!(k >= 1);
        Self { k, kc: keccak_idx() }
    }
}

pub const PHASES: &[&str] = &[
    "keccak",
    "cmp",
    "cmp_idle",
    "seg",
    "seg_step",
    "first",
    "last",
    "tag",
    "flags",
    "sd",
    "sd_capture",
    "sd_out",
    "surface_hold",
    "leaf_struct",
    "leaf_lo",
    "leaf_hi",
    "leaf_key",
    "node",
    "path_regs",
    "bit_cap",
    "index",
    "root_n",
    "root_k",
    "root_c",
    "root_aa",
    "abs_sub",
    "root_r",
    "reg_read",
    "rleaf",
    "rcount",
    "anchor",
    "fee_acc",
    "fee_seed",
    "fee_note",
    "root_ch",
    "vp",
    "supply",
    "root_sup",
    "exits",
    "de",
];

impl BaseAir<Val> for WAir {
    fn width(&self) -> usize {
        W_WIDTH
    }
    fn num_public_values(&self) -> usize {
        W_PV_LEN
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for WAir {
    fn eval(&self, builder: &mut AB) {
        for p in 0..PHASES.len() {
            self.eval_phase(p, builder);
        }
    }
}

pub fn phase_ranges(air: &WAir) -> Vec<Range<usize>> {
    let layout = AirLayout::from_air::<Val>(air);
    let mut start = 0;
    (0..PHASES.len())
        .map(|phase| {
            let mut builder = SymbolicAirBuilder::<Val>::new(layout);
            air.eval_phase(phase, &mut builder);
            let end = start + builder.base_constraints().len();
            let r = start..end;
            start = end;
            r
        })
        .collect()
}

pub fn phase_of(ranges: &[Range<usize>], constraint: usize) -> &'static str {
    PHASES[ranges.iter().position(|r| r.contains(&constraint)).expect("a constraint of W")]
}

/// What SD block `b`'s preimage limb `(lane, m)` must be, per tag (`None` =
/// message data or the chaining value).
pub fn sd_expect(b: usize, lane: usize, m: usize) -> [Option<u32>; 4] {
    let dom = sd_domain_lanes();
    core::array::from_fn(|t| {
        let tag = TAGS[t];
        if b >= sd_perms(tag.pv_len()) {
            return Some(0);
        }
        match lane {
            0..=3 => None,
            4..=16 => {
                let w = SD_BLOCK_WORDS * b + 2 * (lane - SD_LANE_MSG) + m / 2;
                let low = m.is_multiple_of(2);
                match w {
                    0 => Some(if low { u32::from(tag.byte()) } else { 0 }),
                    1 => Some(if low { tag.pv_len() as u32 } else { 0 }),
                    w if w < 2 + tag.pv_len() => None,
                    _ => Some(0),
                }
            }
            l if l == SD_LANE_DOMAIN || l == SD_LANE_DOMAIN + 1 => Some(((dom[l - SD_LANE_DOMAIN] >> (16 * m)) & 0xffff) as u32),
            l if l == SD_LANE_INDEX => Some(if m == 0 { b as u32 } else { 0 }),
            l if l == SD_LANE_FINAL => Some(if m == 0 { u32::from(sd_final(b, tag)) } else { 0 }),
            _ => Some(0),
        }
    })
}

/// A fee chunk's SD position: the claim PV `PV_FEE + j`.
pub fn fee_pos(j: usize) -> (usize, usize, usize) {
    pv_pos(qlab_air::claim::PV_FEE + j)
}

impl WAir {
    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let main = builder.main();
        let (cur, nxt) = (main.current_slice(), main.next_slice());
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { nxt[i].into() };
        let k = &self.kc;
        let pre = |l: usize, m: usize| c(k.pre[l][m]);
        let npre = |l: usize, m: usize| n(k.pre[l][m]);
        let out = |l: usize, m: usize| c(k.out[l][m]);
        let seg = |s: Seg| c(SEG_OFF + s.idx());
        let segs = |ss: &[Seg]| ss.iter().fold(AB::Expr::ZERO, |a, s| a + seg(*s));
        let tag = |t: usize| c(TAG_OFF + t);
        let act = |s: Seg| -> AB::Expr {
            if !s.in_slot() {
                return AB::Expr::ONE;
            }
            (0..4).filter(|t| s.active(TAGS[*t])).fold(AB::Expr::ZERO, |a, t| a + tag(t))
        };
        let act_tx = |s: Seg| (0..3).filter(|t| s.active(TAGS[*t])).fold(AB::Expr::ZERO, |a, t| a + tag(t));
        let fin = c(k.fin);
        let step0 = c(k.step0);
        let konst = |v: u32| AB::Expr::from(Val::from_u32(v));
        let one = AB::Expr::ONE;
        let prog = program();
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let radix = Val::from_u32(1 << 16);
        let all_last_a: Vec<Seg> = prog.iter().copied().filter(|s| matches!(s, Seg::Pair(_, Part::LastA))).collect();
        let all_last_b: Vec<Seg> = prog.iter().copied().filter(|s| matches!(s, Seg::Pair(_, Part::LastB))).collect();
        let anch = [Seg::Anch(APart::Low), Seg::Anch(APart::L30), Seg::Anch(APart::Last)];
        let leaf_old: Vec<Seg> = (0..INSERTS).map(Seg::LeafOld).collect();
        let leaf_mid: Vec<Seg> = (0..INSERTS).map(Seg::LeafMid).collect();
        let leaf_new: Vec<Seg> = (0..INSERTS).map(Seg::LeafNew).collect();
        let ka = || c(KPA) + segs(&all_last_a);
        let kb = || c(KPB) + segs(&all_last_b);
        let to_c0 = Seg::Pair(PathId::New(INSERTS - 1), Part::LastB);
        let to_c1 = Seg::Pair(PathId::C(0), Part::LastB);
        let r_last = Seg::Pair(PathId::R, Part::LastB);
        let abs_last = Seg::Pair(PathId::Abs, Part::LastB);
        let an = |j: usize| seg(Seg::AbsNode(j));
        let z2l = limbs(&abs_old_side());
        let z2 = |j: usize| konst(z2l[j]);
        let hist_last = Seg::Pair(PathId::Hist, Part::LastB);
        let sup_old = [Seg::SupOld(0), Seg::SupOld(1)];
        let sup_new = [Seg::SupNew(0), Seg::SupNew(1)];
        let sup_last = |k: usize| Seg::Pair(PathId::Sup(k), Part::LastB);
        let pv_abs = |i: usize, j: usize| pvs[PV_ABS + 16 * i + j].clone();

        match PHASES[phase] {
            "keccak" => {
                let mut lane = LaneBuilder { inner: builder, off: 0, width: NUM_KECCAK_COLS };
                KeccakAir {}.eval(&mut lane);
            }
            "cmp" => {
                let gate = c(KCMP) * step0;
                let x: [AB::Expr; 16] = core::array::from_fn(|j| pre(j / 4, j % 4));
                let y: [AB::Expr; 16] = core::array::from_fn(|j| pre(4 + j / 4, j % 4));
                cmp::eval_lt(builder, gate, &x, &y, &cur[CMP_OFF..CMP_OFF + LT_WIDTH]);
            }
            "cmp_idle" => {
                let gate = c(KCMP) * step0;
                for i in 0..LT_WIDTH {
                    builder.assert_zero((one.clone() - gate.clone()) * c(CMP_OFF + i));
                }
            }
            "seg" => {
                for i in 0..NSEG_COLS {
                    builder.assert_bool(cur[SEG_OFF + i]);
                }
                builder.assert_one((0..NSEG_COLS).fold(AB::Expr::ZERO, |a, i| a + c(SEG_OFF + i)));
                builder.assert_bool(cur[Z]);
                builder.assert_zero(c(REM) * c(ZINV) - (one.clone() - c(Z)));
                builder.assert_zero(c(REM) * c(Z));
                builder.assert_bool(cur[ZL]);
                builder.assert_zero(c(LEFT) * c(ZLINV) - (one.clone() - c(ZL)));
                builder.assert_zero(c(LEFT) * c(ZL));
                builder.assert_bool(cur[SIDE]);
                builder.assert_zero(c(W) - c(Z) * c(SEG_OFF + SLOT_LAST));
            }
            "seg_step" => {
                let nf = one.clone() - fin.clone();
                let z = c(Z);
                let nz = one.clone() - z.clone();
                let mut t = builder.when_transition();
                for i in 0..NSEG_COLS {
                    t.assert_zero(nf.clone() * (n(SEG_OFF + i) - c(SEG_OFF + i)));
                }
                t.assert_zero(nf.clone() * (n(REM) - c(REM)));
                for i in 0..NSEG_COLS {
                    let enter: AB::Expr = match i {
                        0 => AB::Expr::ZERO,
                        i if i == SLOT_BASE => z.clone() * c(SEG_OFF + i - 1) + c(W) * (one.clone() - c(ZL)),
                        i if i == EPI_BASE => c(W) * c(ZL),
                        i => z.clone() * c(SEG_OFF + i - 1),
                    };
                    let stay = if i == PAD { c(SEG_OFF + i) } else { nz.clone() * c(SEG_OFF + i) };
                    t.assert_zero(fin.clone() * (n(SEG_OFF + i) - stay - enter));
                }
                let next_len = (0..PAD).fold(AB::Expr::ZERO, |a, i| {
                    let succ = if i == SLOT_LAST { prog[SLOT_BASE] } else if i + 1 < PAD { prog[i + 1] } else { Seg::Pad };
                    a + c(SEG_OFF + i) * konst(succ.len() as u32 - 1)
                });
                t.assert_zero(fin.clone() * (n(REM) - nz * (c(REM) - one.clone()) - z * next_len));
                t.assert_zero(n(LEFT) - c(LEFT) + fin.clone() * c(W));
                t.assert_zero(n(SIDE) - c(SIDE) - fin * (c(KPA) - c(SIDE)));
            }
            "first" => {
                let mut f = builder.when_first_row();
                f.assert_one(c(SEG_OFF));
                f.assert_zero(c(REM) - konst(prog[0].len() as u32 - 1));
                f.assert_zero(c(LEFT) - konst(self.k as u32 - 1));
                f.assert_zero(c(RCNT));
                f.assert_zero(c(SIDE));
                f.assert_zero(c(ACC));
                f.assert_one(c(PW));
                for j in 0..16 {
                    f.assert_zero(c(NA_OFF + j));
                }
                for j in 0..4 {
                    f.assert_zero(c(FE_OFF + j));
                    f.assert_zero(c(EA_OFF + j));
                }
                for j in 0..16 {
                    f.assert_zero(c(EXC_OFF + j));
                }
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD), (K_OFF, PV_K), (AA_OFF, PV_AA), (CH_OFF, PV_CH), (SUP_OFF, PV_SUP)] {
                    for j in 0..16 {
                        f.assert_zero(c(col + j) - pvs[at + j].clone());
                    }
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN), (KN, PV_KN), (AAN, PV_AAN), (CHN, PV_CHN)] {
                    f.assert_zero(c(col) - pvs[at].clone() - pvs[at + 1].clone() * radix);
                }
            }
            "last" => {
                let mut l = builder.when_last_row();
                l.assert_one(c(SEG_OFF + PAD));
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD), (K_OFF, PV_K), (AA_OFF, PV_AA), (CH_OFF, PV_CH), (SUP_OFF, PV_SUP)] {
                    for j in 0..16 {
                        l.assert_zero(c(col + j) - pvs[PV_SIDE + at + j].clone());
                    }
                }
                for j in 0..16 {
                    l.assert_zero(c(EXC_OFF + j) - pvs[PV_EXC + j].clone());
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN), (KN, PV_KN), (AAN, PV_AAN), (CHN, PV_CHN)] {
                    l.assert_zero(c(col) - pvs[PV_SIDE + at].clone() - pvs[PV_SIDE + at + 1].clone() * radix);
                }
            }
            "tag" => {
                for t in 0..4 {
                    builder.assert_bool(cur[TAG_OFF + t]);
                }
                builder.assert_one(tag(0) + tag(1) + tag(2) + tag(3));
                let free = fin.clone() * c(W);
                let mut t = builder.when_transition();
                for i in 0..4 {
                    t.assert_zero((one.clone() - free.clone()) * (n(TAG_OFF + i) - c(TAG_OFF + i)));
                }
            }
            "flags" => {
                let on = prog.iter().fold(AB::Expr::ZERO, |a, s| a + seg(*s) * act(*s));
                builder.assert_zero(c(ON) - on);
                let bulk = prog.iter().filter(|s| s.is_pair_bulk()).fold(AB::Expr::ZERO, |a, s| a + seg(*s));
                builder.assert_zero(c(KPA) - bulk.clone() * (one.clone() - c(SIDE)));
                builder.assert_zero(c(KPB) - bulk * c(SIDE));
                let cmpf = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| {
                    a + seg(Seg::LeafMid(i)) * act(Seg::LeafMid(i)) + seg(Seg::LeafNew(i)) * act(Seg::LeafNew(i))
                });
                builder.assert_zero(c(KCMP) - cmpf);
                let ml = |i: usize| Seg::Pair(PathId::Mid(i), Part::LastB);
                let nl = |i: usize| Seg::Pair(PathId::New(i), Part::LastB);
                let nc = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| a + seg(ml(i)) * act_tx(ml(i)) + seg(nl(i)) * act_tx(nl(i)));
                builder.assert_zero(c(KNC) - nc);
                let ni = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| a + seg(nl(i)) * act_tx(nl(i)));
                builder.assert_zero(c(KNI) - ni);
                builder.assert_zero(c(KKC) - (seg(ml(0)) + seg(nl(0))) * tag(T_C));
                builder.assert_zero(c(KKI) - seg(nl(0)) * tag(T_C));
                let c1 = Seg::Pair(PathId::C(1), Part::LastB);
                builder.assert_zero(c(KCC) - seg(to_c1) - seg(c1) * act(c1) - seg(Seg::Pair(PathId::Fee, Part::LastB)));
                builder.assert_zero(c(KR) - seg(r_last) * tag(T_R));
                builder.assert_zero(c(KAN) - seg(Seg::Anch(APart::Last)) * tag(T_C));
                builder.assert_zero(c(KFE) - seg(Seg::Sd(fee_pos(0).0)) * tag(T_C));
                let sdc = (0..SD_BLOCKS - 1).fold(AB::Expr::ZERO, |a, b| a + seg(Seg::Sd(b)) * act(Seg::Sd(b + 1)));
                builder.assert_zero(c(SDC) - sdc);
                let sdf = (0..SD_BLOCKS).fold(AB::Expr::ZERO, |a, b| {
                    let f = (0..4).filter(|t| sd_final(b, TAGS[*t])).fold(AB::Expr::ZERO, |x, t| x + tag(t));
                    a + seg(Seg::Sd(b)) * f
                });
                builder.assert_zero(c(SDF) - sdf);
                builder.assert_zero(c(BP) - c(BIT) * c(PW));
                builder.assert_zero(c(KCH) - seg(Seg::Anch(APart::Last)) * (tag(0) + tag(1) + tag(2)));
                for k in 0..2 {
                    builder.assert_zero(c(XF_OFF + k) - tag(T_P) * c(ZV_OFF + k) * c(VS_OFF + k));
                    builder.assert_zero(c(KX_OFF + k) - seg(Seg::Exit(k)) * c(XF_OFF + k));
                    builder.assert_zero(c(KSN_OFF + k) - seg(Seg::SupNew(k)) * tag(T_P));
                    builder.assert_zero(c(KSU_OFF + k) - seg(sup_last(k)) * tag(T_P));
                    builder.assert_zero(c(MZ_OFF + k) - c(ZV_OFF + k) * (one.clone() - c(VS_OFF + k)));
                }
            }
            "sd" => {
                for l in 0..4 {
                    for m in 0..4 {
                        builder.assert_zero(seg(Seg::Sd(0)) * (pre(l, m) - c(SD_OFF + 4 * l + m)));
                    }
                }
                {
                    let mut t = builder.when_transition();
                    for l in 0..4 {
                        for m in 0..4 {
                            t.assert_zero(fin.clone() * c(SDC) * (npre(l, m) - out(l, m)));
                        }
                    }
                }
                for b in 0..SD_BLOCKS {
                    for l in 0..25 {
                        for m in 0..4 {
                            let e = sd_expect(b, l, m);
                            if e.iter().all(Option::is_none) {
                                continue;
                            }
                            let sum = (0..4).fold(AB::Expr::ZERO, |a, t| match e[t] {
                                Some(v) => a + tag(t) * (pre(l, m) - konst(v)),
                                None => a,
                            });
                            builder.assert_zero(seg(Seg::Sd(b)) * sum);
                        }
                    }
                }
            }
            "sd_capture" => {
                for (col, chunks, at) in captures() {
                    for ch in 0..chunks {
                        for b in 0..SD_BLOCKS {
                            let here: Vec<(usize, usize, usize)> = at
                                .iter()
                                .filter_map(|(t, off)| {
                                    let (bb, l, m) = pv_pos(off + ch);
                                    (bb == b).then_some((*t, l, m))
                                })
                                .collect();
                            if here.is_empty() {
                                continue;
                            }
                            let lo = here.iter().fold(AB::Expr::ZERO, |a, (t, l, m)| a + tag(*t) * (c(col + ch) - pre(*l, *m)));
                            let hi = here.iter().fold(AB::Expr::ZERO, |a, (t, l, m)| a + tag(*t) * pre(*l, *m + 1));
                            builder.assert_zero(seg(Seg::Sd(b)) * lo);
                            builder.assert_zero(seg(Seg::Sd(b)) * hi);
                        }
                    }
                }
                // A claim's fee words are 16-bit chunks too.
                for j in 0..4 {
                    let (b, l, m) = fee_pos(j);
                    builder.assert_zero(seg(Seg::Sd(b)) * tag(T_C) * pre(l, m + 1));
                }
            }
            "sd_out" => {
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(SD_OFF + j) - c(SD_OFF + j) - fin.clone() * c(SDF) * (out(j / 4, j % 4) - c(SD_OFF + j)));
                }
            }
            "surface_hold" => {
                let free = fin.clone() * c(W);
                let mut t = builder.when_transition();
                for col in (NF_OFF..=ASSET).chain(ANC_OFF..ANC_OFF + 16).chain(VS_OFF..VA_OFF + 2) {
                    t.assert_zero((one.clone() - free.clone()) * (n(col) - c(col)));
                }
            }
            "leaf_struct" => {
                let kl = segs(&leaf_old) + segs(&leaf_mid) + segs(&leaf_new);
                for l in 8..25 {
                    for m in 0..4 {
                        let v = match (l, m) {
                            (8, 0) => 1 << 4,
                            (16, 3) => 0x8000,
                            _ => 0,
                        };
                        builder.assert_zero(kl.clone() * (pre(l, m) - konst(v)));
                    }
                }
            }
            "leaf_lo" => {
                let lo = segs(&leaf_old);
                let mut t = builder.when_transition();
                for l in 0..4 {
                    for m in 0..4 {
                        t.assert_zero(fin.clone() * lo.clone() * (npre(l, m) - pre(l, m)));
                    }
                }
            }
            "leaf_hi" => {
                let (lo, ln) = (segs(&leaf_old), segs(&leaf_new));
                for j in 0..16 {
                    builder.assert_zero(lo.clone() * (c(HI_OFF + j) - pre(4 + j / 4, j % 4)));
                    builder.assert_zero(ln.clone() * (pre(4 + j / 4, j % 4) - c(HI_OFF + j)));
                }
                let fh = segs(&[Seg::Sd(SD_BLOCKS - 1), Seg::Pair(PathId::New(0), Part::LastB), Seg::Pair(PathId::New(1), Part::LastB)]);
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero((one.clone() - fin.clone() * fh.clone()) * (n(HI_OFF + j) - c(HI_OFF + j)));
                }
            }
            "leaf_key" => {
                for i in 0..INSERTS {
                    for j in 0..16 {
                        let key = c(NF_OFF + 16 * i + j);
                        builder.assert_zero(seg(Seg::LeafMid(i)) * c(ON) * (pre(4 + j / 4, j % 4) - key.clone()));
                        builder.assert_zero(seg(Seg::LeafNew(i)) * c(ON) * (pre(j / 4, j % 4) - key));
                    }
                }
            }
            "node" => {
                // A-kind perms read NA (pairs' A side and the anchor path); B-kind read NB.
                let kpa = ka() + segs(&anch);
                for (kk, node) in [(kpa.clone(), NA_OFF), (kb(), NB_OFF)] {
                    for j in 0..16 {
                        let (l, m) = (j / 4, j % 4);
                        let (x, s) = (c(node + j), c(SIB_OFF + j));
                        let left = x.clone() + c(BIT) * (s.clone() - x.clone());
                        let right = s.clone() + c(BIT) * (x - s);
                        builder.assert_zero(kk.clone() * (pre(l, m) - left));
                        builder.assert_zero(kk.clone() * (pre(4 + l, m) - right));
                    }
                }
                let kn = kpa + kb();
                for l in 8..25 {
                    for m in 0..4 {
                        let v = match (l, m) {
                            (8, 0) => 1,
                            (16, 3) => 0x8000,
                            _ => 0,
                        };
                        builder.assert_zero(kn.clone() * (pre(l, m) - konst(v)));
                    }
                }
            }
            "path_regs" => {
                builder.assert_bool(cur[BIT]);
                let fao = ka() + segs(&leaf_old) + segs(&anch) + segs(&sup_old) + an(1);
                let faz = segs(&leaf_new) + seg(to_c0) + seg(to_c1) + seg(abs_last) + seg(Seg::FeeNote);
                let fanc = seg(Seg::Exit(1));
                let free = seg(Seg::RegLeaf);
                let fbo = kb() - seg(to_c0) - seg(to_c1) - seg(abs_last)
                    + an(0)
                    + an(2)
                    + segs(&leaf_mid)
                    + segs(&leaf_new)
                    + seg(Seg::RegLeaf)
                    + seg(Seg::FeeNote)
                    + segs(&sup_new);
                let hold_ab = one.clone() - fin.clone() + fin.clone() * ka();
                let mut t = builder.when_transition();
                for j in 0..16 {
                    let (l, m) = (j / 4, j % 4);
                    let (a, na) = (c(NA_OFF + j), n(NA_OFF + j));
                    t.assert_zero(
                        na.clone() - a.clone()
                            - fin.clone()
                                * (fao.clone() * (out(l, m) - a.clone()) - faz.clone() * a.clone()
                                    + fanc.clone() * (c(ANC_OFF + j) - a.clone())
                                    + an(2) * (z2(j) - a.clone())
                                    + free.clone() * (na - a)),
                    );
                    let (b, nb) = (c(NB_OFF + j), n(NB_OFF + j));
                    let abs_next = seg(abs_last) * (c(C_OFF + j) - b.clone());
                    t.assert_zero(
                        nb - b.clone()
                            - fin.clone()
                                * (fbo.clone() * (out(l, m) - b.clone())
                                    + seg(to_c0) * (c(CM_OFF + j) - b.clone())
                                    + seg(to_c1) * (c(CM_OFF + 16 + j) - b)
                                    + abs_next),
                    );
                    t.assert_zero(hold_ab.clone() * (n(SIB_OFF + j) - c(SIB_OFF + j)));
                }
                t.assert_zero(hold_ab * (n(BIT) - c(BIT)));
            }
            "bit_cap" => {
                let capped = prog
                    .iter()
                    .filter(|s| {
                        matches!(s, Seg::Pair(p, Part::L30 | Part::LastA | Part::LastB) if !matches!(p, PathId::R | PathId::Sup(_)))
                            || matches!(s, Seg::Anch(APart::L30 | APart::Last))
                    })
                    .fold(AB::Expr::ZERO, |a, s| a + seg(*s));
                builder.assert_zero(capped * c(BIT));
            }
            "index" => {
                let fi = segs(&leaf_mid) + segs(&leaf_new) + seg(to_c0) + seg(to_c1) + seg(Seg::RegLeaf) + seg(abs_last) + seg(Seg::FeeNote) + segs(&sup_new);
                let mut t = builder.when_transition();
                t.assert_zero(n(ACC) - c(ACC) - fin.clone() * (c(KPB) * c(BP) - fi.clone() * c(ACC)));
                t.assert_zero(n(PW) - c(PW) - fin * (fi * (one.clone() - c(PW)) + c(KPB) * c(PW)));
            }
            "root_n" => {
                for j in 0..16 {
                    builder.assert_zero(c(KNC) * (c(NA_OFF + j) - c(N_OFF + j)));
                }
                builder.assert_zero(c(KNI) * (c(ACC) + c(BP) - c(NN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(N_OFF + j) - c(N_OFF + j) - fin.clone() * c(KNC) * (out(j / 4, j % 4) - c(N_OFF + j)));
                }
                t.assert_zero(n(NN) - c(NN) - fin * c(KNI));
            }
            "root_k" => {
                for j in 0..16 {
                    builder.assert_zero(c(KKC) * (c(NA_OFF + j) - c(K_OFF + j)));
                }
                builder.assert_zero(c(KKI) * (c(ACC) + c(BP) - c(KN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(K_OFF + j) - c(K_OFF + j) - fin.clone() * c(KKC) * (out(j / 4, j % 4) - c(K_OFF + j)));
                }
                t.assert_zero(n(KN) - c(KN) - fin * c(KKI));
            }
            "root_c" => {
                for j in 0..16 {
                    builder.assert_zero(c(KCC) * (c(NA_OFF + j) - c(C_OFF + j)));
                }
                builder.assert_zero(c(KCC) * (c(ACC) + c(BP) - c(CN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(C_OFF + j) - c(C_OFF + j) - fin.clone() * c(KCC) * (out(j / 4, j % 4) - c(C_OFF + j)));
                }
                t.assert_zero(n(CN) - c(CN) - fin * c(KCC));
            }
            "root_aa" => {
                // The subtree's slot: its path index counts from level 2, so
                // AA's next index is 4 × it (aa_next ≡ 0 mod 4 is forced).
                let kab = seg(abs_last);
                let m = konst(M_ABS as u32);
                for j in 0..16 {
                    builder.assert_zero(kab.clone() * (c(NA_OFF + j) - c(AA_OFF + j)));
                }
                builder.assert_zero(kab.clone() * ((c(ACC) + c(BP)) * m.clone() - c(AAN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(AA_OFF + j) - c(AA_OFF + j) - fin.clone() * kab.clone() * (out(j / 4, j % 4) - c(AA_OFF + j)));
                }
                t.assert_zero(n(AAN) - c(AAN) - fin * kab * m);
            }
            "abs_sub" => {
                // H(a0, a1), H(a2, a3) from the absorbed-root PVs; their parent
                // from the two registers (NB, NA) they were left in.
                for (jn, (x, y)) in [(0usize, (0usize, 1usize)), (1, (2, 3))] {
                    for j in 0..16 {
                        let (l, mm) = (j / 4, j % 4);
                        builder.assert_zero(an(jn) * (pre(l, mm) - pv_abs(x, j)));
                        builder.assert_zero(an(jn) * (pre(4 + l, mm) - pv_abs(y, j)));
                    }
                }
                for j in 0..16 {
                    let (l, mm) = (j / 4, j % 4);
                    builder.assert_zero(an(2) * (pre(l, mm) - c(NB_OFF + j)));
                    builder.assert_zero(an(2) * (pre(4 + l, mm) - c(NA_OFF + j)));
                }
                let kn = an(0) + an(1) + an(2);
                for l in 8..25 {
                    for mm in 0..4 {
                        let v = match (l, mm) {
                            (8, 0) => 1,
                            (16, 3) => 0x8000,
                            _ => 0,
                        };
                        builder.assert_zero(kn.clone() * (pre(l, mm) - konst(v)));
                    }
                }
            }
            "root_r" => {
                for j in 0..16 {
                    builder.assert_zero(c(KR) * (c(NA_OFF + j) - c(R_OFF + j)));
                    builder.assert_zero(fin.clone() * c(KR) * (out(j / 4, j % 4) - c(NRT_OFF + j)));
                }
                builder.assert_zero(c(KR) * (c(ACC) + c(BP) - c(ASSET)));
                builder.assert_zero(c(KR) * (c(ASSET) * c(AINV) - one.clone()));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(R_OFF + j) - c(R_OFF + j) - fin.clone() * c(KR) * (out(j / 4, j % 4) - c(R_OFF + j)));
                }
            }
            "reg_read" => {
                for j in 0..16 {
                    builder.assert_zero(seg(r_last) * (act_tx(r_last) + tag(0) + tag(1)) * (c(RT_OFF + j) - c(R_OFF + j)));
                }
            }
            "rleaf" => {
                let g = seg(Seg::RegLeaf) * tag(T_R);
                builder.assert_zero(g.clone() * (pre(0, 0) - c(ASSET)));
                for l in [0, 15, 16].into_iter().chain(17..25) {
                    for m in 0..4 {
                        if (l, m) == (0, 0) {
                            continue;
                        }
                        let v = match (l, m) {
                            (15, 0) => 1,
                            (16, 3) => 0x8000,
                            _ => 0,
                        };
                        builder.assert_zero(g.clone() * (pre(l, m) - konst(v)));
                    }
                }
            }
            "rcount" => {
                builder.assert_bool(cur[RCNT]);
                builder.when_transition().assert_zero(n(RCNT) - c(RCNT) - fin * c(W) * tag(T_R));
            }
            "anchor" => {
                // A claim's anchor opens in AA: the path's last output is AA's root.
                // …and a transaction's anchor opens in CH (post-prologue).
                for j in 0..16 {
                    builder.assert_zero(fin.clone() * c(KAN) * (out(j / 4, j % 4) - c(AA_OFF + j)));
                    builder.assert_zero(fin.clone() * c(KCH) * (out(j / 4, j % 4) - c(CH_OFF + j)));
                }
                // A ≠ 0: its limbs' sum (< 2^20) has an inverse.
                let sum = (0..16).fold(AB::Expr::ZERO, |a, j| a + c(ANC_OFF + j));
                builder.assert_zero((c(KAN) + c(KCH)) * (sum * c(ANINV) - one.clone()));
            }
            "fee_acc" => {
                let mut t = builder.when_transition();
                for j in 0..4 {
                    let (_, l, m) = fee_pos(j);
                    t.assert_zero(n(FE_OFF + j) - c(FE_OFF + j) - fin.clone() * c(KFE) * pre(l, m));
                }
            }
            "fee_seed" => {
                // ρ and rseed: `native::fee_seed_state(prev, kind)`.
                let dom = fee_domain_lanes();
                for (s, kind) in [(Seg::FeeRho, 1u64), (Seg::FeeRseed, 2)] {
                    for l in 0..25 {
                        for m in 0..4 {
                            let e: AB::Expr = match l {
                                0..=3 => pvs[PV_PREV + 4 * l + m].clone(),
                                _ => {
                                    let lane = match l {
                                        4 => kind,
                                        8 => 1,
                                        16 => 1 << 63,
                                        21..=23 => dom[l - 21],
                                        _ => 0,
                                    };
                                    konst(((lane >> (16 * m)) & 0xffff) as u32)
                                }
                            };
                            builder.assert_zero(seg(s) * (pre(l, m) - e));
                        }
                    }
                }
                let mut t = builder.when_transition();
                for j in 0..16 {
                    let o = out(j / 4, j % 4);
                    t.assert_zero(n(RHO_OFF + j) - c(RHO_OFF + j) - fin.clone() * seg(Seg::FeeRho) * (o.clone() - c(RHO_OFF + j)));
                    t.assert_zero(n(RSD_OFF + j) - c(RSD_OFF + j) - fin.clone() * seg(Seg::FeeRseed) * (o - c(RSD_OFF + j)));
                }
            }
            "fee_note" => {
                for b in 0..15 {
                    builder.assert_bool(cur[FCB_OFF + b]);
                }
                let carry = |j: usize| -> AB::Expr {
                    if j == 0 || j == 4 {
                        AB::Expr::ZERO
                    } else {
                        (0..5).fold(AB::Expr::ZERO, |a, i| a + c(FCB_OFF + 5 * (j - 1) + i) * Val::from_u32(1 << i))
                    }
                };
                let fnote = seg(Seg::FeeNote);
                for j in 0..4 {
                    // value limb j = FE_j + c_j − 2^16 c_{j+1}; the fee PV is the value.
                    builder.assert_zero(fnote.clone() * (pre(0, j) - c(FE_OFF + j) - carry(j) + carry(j + 1) * radix));
                    builder.assert_zero(fnote.clone() * (pre(0, j) - pvs[PV_FEE + j].clone()));
                }
                for l in 1..25 {
                    for m in 0..4 {
                        let e: AB::Expr = match l {
                            2..=5 => pvs[PV_RKMS + 4 * (l - 2) + m].clone(),
                            6..=9 => c(RHO_OFF + 4 * (l - 6) + m),
                            10..=13 => c(RSD_OFF + 4 * (l - 10) + m),
                            14 => konst(u32::from(m == 0)),
                            16 => konst(if m == 3 { 0x8000 } else { 0 }),
                            _ => AB::Expr::ZERO,
                        };
                        builder.assert_zero(fnote.clone() * (pre(l, m) - e));
                    }
                }
            }
            "root_ch" => {
                let kh = seg(hist_last);
                for j in 0..16 {
                    builder.assert_zero(kh.clone() * (c(NA_OFF + j) - c(CH_OFF + j)));
                }
                builder.assert_zero(kh.clone() * (c(ACC) + c(BP) - c(CHN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(CH_OFF + j) - c(CH_OFF + j) - fin.clone() * kh.clone() * (out(j / 4, j % 4) - c(CH_OFF + j)));
                }
                t.assert_zero(n(CHN) - c(CHN) - fin * kh);
            }
            "vp" => {
                let dom = crate::hash::supply_domain_lanes();
                for k in 0..2 {
                    builder.assert_bool(cur[VS_OFF + k]);
                    builder.assert_bool(cur[ZV_OFF + k]);
                    builder.assert_zero(c(VA_OFF + k) * c(ZVINV_OFF + k) - (one.clone() - c(ZV_OFF + k)));
                    builder.assert_zero(c(VA_OFF + k) * c(ZV_OFF + k));
                    // The old and new supply leaves H(asset ‖ outstanding).
                    for s in [Seg::SupOld(k), Seg::SupNew(k)] {
                        let g = seg(s) * tag(T_P);
                        for l in 0..25 {
                            if l == 1 {
                                continue;
                            }
                            for m in 0..4 {
                                let e: AB::Expr = match (l, m) {
                                    (0, 0) => c(VA_OFF + k),
                                    (8, 0) => AB::Expr::ONE,
                                    (16, 3) => konst(0x8000),
                                    (21..=23, m) => konst(((dom[l - 21] >> (16 * m)) & 0xffff) as u32),
                                    _ => AB::Expr::ZERO,
                                };
                                builder.assert_zero(g.clone() * (pre(l, m) - e));
                            }
                        }
                    }
                    for j in 0..4 {
                        builder.assert_zero(seg(Seg::SupOld(k)) * tag(T_P) * (c(OLDV_OFF + j) - pre(1, j)));
                    }
                }
                // OLDV holds from each SupOld to its SupNew; free entering a SupOld.
                let fold = seg(r_last) + seg(sup_last(0));
                let mut t = builder.when_transition();
                for j in 0..4 {
                    t.assert_zero((one.clone() - fin.clone() * fold.clone()) * (n(OLDV_OFF + j) - c(OLDV_OFF + j)));
                }
            }
            "supply" => {
                for b in 0..3 {
                    builder.assert_bool(cur[SCB_OFF + b]);
                }
                let carry = |j: usize| -> AB::Expr {
                    if j == 0 || j == 4 {
                        AB::Expr::ZERO
                    } else {
                        c(SCB_OFF + j - 1)
                    }
                };
                for k in 0..2 {
                    let g = c(KSN_OFF + k);
                    let (sg, zv) = (c(VS_OFF + k), c(ZV_OFF + k));
                    for j in 0..4 {
                        // mint (s = 0): old + m = new; redeem (s = 1): new + m = old;
                        // asset 0 moves nothing (m counts as 0).
                        let (old, new) = (c(OLDV_OFF + j), pre(1, j));
                        let a = old.clone() + sg.clone() * (new.clone() - old.clone());
                        let r = new.clone() + sg.clone() * (old - new);
                        let mm = (one.clone() - zv.clone()) * c(VM_OFF + 4 * k + j);
                        builder.assert_zero(g.clone() * (a + mm + carry(j) - r - carry(j + 1) * radix));
                        // No vPublic mint on asset 0.
                        builder.assert_zero(g.clone() * c(MZ_OFF + k) * c(VM_OFF + 4 * k + j));
                    }
                }
            }
            "root_sup" => {
                for k in 0..2 {
                    let g = c(KSU_OFF + k);
                    for j in 0..16 {
                        builder.assert_zero(g.clone() * (c(NA_OFF + j) - c(SUP_OFF + j)));
                    }
                    builder.assert_zero(g * (c(ACC) + c(BP) - c(VA_OFF + k)));
                }
                let ks = c(KSU_OFF) + c(KSU_OFF + 1);
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(SUP_OFF + j) - c(SUP_OFF + j) - fin.clone() * ks.clone() * (out(j / 4, j % 4) - c(SUP_OFF + j)));
                }
            }
            "exits" => {
                let dom = crate::hash::exit_domain_lanes();
                let kx = c(KX_OFF) + c(KX_OFF + 1);
                for l in 0..25 {
                    if (4..8).contains(&l) {
                        continue; // rkm: a free witness, bound only through the chain (Q3 = (c))
                    }
                    for m in 0..4 {
                        let e: AB::Expr = match (l, m) {
                            (0..=3, m) => c(EXC_OFF + 4 * l + m),
                            (8, m) => c(KX_OFF) * c(VM_OFF + m) + c(KX_OFF + 1) * c(VM_OFF + 4 + m),
                            (9, 0) => AB::Expr::ONE,
                            (16, 3) => konst(0x8000),
                            (21..=23, m) => konst(((dom[l - 21] >> (16 * m)) & 0xffff) as u32),
                            _ => AB::Expr::ZERO,
                        };
                        if l == 8 {
                            builder.assert_zero(kx.clone() * pre(l, m) - e);
                        } else {
                            builder.assert_zero(kx.clone() * (pre(l, m) - e));
                        }
                    }
                }
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(EXC_OFF + j) - c(EXC_OFF + j) - fin.clone() * kx.clone() * (out(j / 4, j % 4) - c(EXC_OFF + j)));
                }
                for j in 0..4 {
                    t.assert_zero(n(EA_OFF + j) - c(EA_OFF + j) - fin.clone() * (c(KX_OFF) * c(VM_OFF + j) + c(KX_OFF + 1) * c(VM_OFF + 4 + j)));
                }
            }
            "de" => {
                for b in 0..18 {
                    builder.assert_bool(cur[ECB_OFF + b]);
                }
                let carry = |j: usize| -> AB::Expr {
                    if j == 0 || j == 4 {
                        AB::Expr::ZERO
                    } else {
                        (0..6).fold(AB::Expr::ZERO, |a, i| a + c(ECB_OFF + 6 * (j - 1) + i) * Val::from_u32(1 << i))
                    }
                };
                for j in 0..4 {
                    // D_out = D_in + D_batch (FeeRho); E_out = E_in + Σ exits (FeeRseed).
                    let rest = carry(j) - carry(j + 1) * radix;
                    builder.assert_zero(
                        seg(Seg::FeeRho) * (pvs[PV_SIDE + PV_D + j].clone() - pvs[PV_D + j].clone() - pvs[PV_DB + j].clone() - rest.clone()),
                    );
                    builder.assert_zero(seg(Seg::FeeRseed) * (pvs[PV_SIDE + PV_E + j].clone() - pvs[PV_E + j].clone() - c(EA_OFF + j) - rest));
                }
            }
            other => unreachable!("phase {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The checker (p3's row loop)
// ---------------------------------------------------------------------------

/// The empty depth-2 subtree (`zeros[2]`): the old side of the absorb.
pub fn abs_old_side() -> Digest {
    let z1 = crate::hash::node_pub(&EMPTY, &EMPTY);
    crate::hash::node_pub(&z1, &z1)
}
