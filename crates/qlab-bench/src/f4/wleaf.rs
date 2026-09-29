//! Lab #775 F4-1 — **W, the wrapper leaf AIR**: F3's state leaf
//! (`crate::f3::leaf`), extended with the claim slot, the L1-anchor
//! accumulator and the sequencer fee note. It proves
//! [`super::native::check_wrapper_leaf`].
//!
//! **The program.** A prologue, `k` slots, an epilogue, then `PAD`:
//!
//! ```text
//!   prologue:  4 × absorb (an F3 append of one absorbed L1 root to AA, 64 perms)
//!   slot ×k:   F3's 559-perm slot (SD 5 | inserts 3 × 131 | appends 2 × 64 | registry 33)
//!              + an anchor path (32 perms: a claim's anchor A opened in AA)
//!   epilogue:  ρ(prev), rseed(prev), the fee note's commitment, its append to C (67 perms)
//! ```
//!
//! **The claim slot** (tag `C`, SD word 0 = `0x04`): insert 0 is its `cnf`,
//! committed to `K` (not `N`); append 0 is its `cm2`; the anchor path opens
//! its `A` against `AA` (`A ≠ 0`); its fee chunks add into the fee
//! accumulator. Inserts 1–2, append 1, SD block 4 and the registry segment
//! are off for a claim, as for R; the anchor path is on only for a claim.
//!
//! **The fee note** is appended in every wrapper (value 0 with no claims):
//! `cm = H(value ‖ 0 ‖ rkm_seq ‖ ρ ‖ rseed)` with `value` the accumulator
//! normalized to four 16-bit limbs (carries ≤ 5 bits: at most 31 claims per
//! leaf), `ρ`/`rseed` the two domain-tagged perms over the `prev` PV.
//!
//! Degree 3 throughout, by the same device as F3: every flag a data
//! constraint needs is a materialized column.
#![cfg_attr(not(test), allow(dead_code))]
use std::ops::Range;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use qlab_consensus::Val;

use super::native::{fee_domain_lanes, fee_seed_state, Member, SlotWitness, WInputs, WRoots, WTag, WWitness, CLAIM_TAG, M_ABS};
use crate::f3::cmp::{self, limbs, LT_WIDTH};
use crate::f3::leaf::{inv_or_zero, keccak_idx, mux, nf_leaf_state, node_state, out4, pv_digest, KeccakIdx};
use crate::f3::native::{sd_chain_byte, sd_domain_lanes, sd_perms, Digest, EMPTY, N_DEPTH, SD_BLOCK_WORDS, SD_LANE_DOMAIN, SD_LANE_FINAL, SD_LANE_INDEX, SD_LANE_MSG};
use crate::m4skel::LaneBuilder;

// ---------------------------------------------------------------------------
// The program
// ---------------------------------------------------------------------------

pub(crate) const SD_BLOCKS: usize = 5;
pub(crate) const INSERTS: usize = 3;
pub(crate) const APPENDS: usize = 2;
pub(crate) const R_DEPTH: usize = qlab_air::l2::REGISTRY_DEPTH;
/// Claims per leaf the fee carries' 5-bit width covers: a limb sum of
/// `MAX_CLAIMS` 16-bit chunks plus a carry-in keeps its carry-out < 2^5.
pub(crate) const MAX_CLAIMS: usize = 31;
const _: () = assert!(MAX_CLAIMS * 0xffff + 31 < 32 << 16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathId {
    Mid(usize),
    New(usize),
    C(usize),
    R,
    /// An absorbed L1 root appended to AA.
    Abs(usize),
    /// The fee note appended to C.
    Fee,
}

impl PathId {
    pub(crate) const fn depth(self) -> usize {
        match self {
            PathId::R => R_DEPTH,
            _ => N_DEPTH,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    Bulk,
    L30,
    LastA,
    LastB,
}

/// The anchor path's parts: levels 0..29, level 30, level 31 (bits 30/31 zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum APart {
    Low,
    L30,
    Last,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Sd(usize),
    LeafOld(usize),
    LeafMid(usize),
    LeafNew(usize),
    Pair(PathId, Part),
    RegLeaf,
    Anch(APart),
    FeeRho,
    FeeRseed,
    FeeNote,
    Pad,
}

pub(crate) const PRO: usize = 4 * M_ABS;
pub(crate) const SLOT_SEGS: usize = 53;
pub(crate) const SLOT_BASE: usize = PRO;
pub(crate) const EPI_BASE: usize = SLOT_BASE + SLOT_SEGS;
pub(crate) const EPI: usize = 7;
pub(crate) const PAD: usize = EPI_BASE + EPI;
pub(crate) const NSEG_COLS: usize = PAD + 1;
pub(crate) const SLOT_LAST: usize = EPI_BASE - 1;

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
    pub(crate) const fn idx(self) -> usize {
        let b = SLOT_BASE;
        match self {
            Seg::Pair(PathId::Abs(i), p) => 4 * i + part_off(p),
            Seg::Sd(k) => b + k,
            Seg::LeafOld(i) => b + 5 + 11 * i,
            Seg::LeafMid(i) => b + 5 + 11 * i + 1,
            Seg::Pair(PathId::Mid(i), p) => b + 5 + 11 * i + 2 + part_off(p),
            Seg::LeafNew(i) => b + 5 + 11 * i + 6,
            Seg::Pair(PathId::New(i), p) => b + 5 + 11 * i + 7 + part_off(p),
            Seg::Pair(PathId::C(j), p) => b + 38 + 4 * j + part_off(p),
            Seg::RegLeaf => b + 46,
            Seg::Pair(PathId::R, Part::Bulk) => b + 47,
            Seg::Pair(PathId::R, Part::LastA) => b + 48,
            Seg::Pair(PathId::R, _) => b + 49,
            Seg::Anch(APart::Low) => b + 50,
            Seg::Anch(APart::L30) => b + 51,
            Seg::Anch(APart::Last) => b + 52,
            Seg::FeeRho => EPI_BASE,
            Seg::FeeRseed => EPI_BASE + 1,
            Seg::FeeNote => EPI_BASE + 2,
            Seg::Pair(PathId::Fee, p) => EPI_BASE + 3 + part_off(p),
            Seg::Pad => PAD,
        }
    }

    pub(crate) const fn len(self) -> usize {
        match self {
            Seg::Pair(PathId::R, Part::Bulk) => 30,
            Seg::Pair(_, Part::Bulk) => 60,
            Seg::Pair(_, Part::L30) => 2,
            Seg::Anch(APart::Low) => 30,
            _ => 1,
        }
    }

    /// Whether the segment acts for a slot of tag `t` (prologue and epilogue
    /// always act; `PAD` never).
    pub(crate) fn active(self, t: WTag) -> bool {
        let (r, c) = (t == WTag::R, t == WTag::C);
        match self {
            Seg::Sd(b) => b < sd_perms(t.pv_len()),
            Seg::LeafOld(i) | Seg::LeafMid(i) | Seg::LeafNew(i) | Seg::Pair(PathId::Mid(i) | PathId::New(i), _) => {
                i == 0 || !(r || c)
            }
            Seg::Pair(PathId::C(j), _) => j == 0 || !c,
            Seg::RegLeaf | Seg::Pair(PathId::R, _) => r,
            Seg::Anch(_) => c,
            Seg::Pair(PathId::Abs(_) | PathId::Fee, _) | Seg::FeeRho | Seg::FeeRseed | Seg::FeeNote => true,
            Seg::Pad => false,
        }
    }

    fn in_slot(self) -> bool {
        (SLOT_BASE..EPI_BASE).contains(&self.idx())
    }

    fn is_pair_bulk(self) -> bool {
        matches!(self, Seg::Pair(_, Part::Bulk | Part::L30))
    }

}

const PARTS: [Part; 4] = [Part::Bulk, Part::L30, Part::LastA, Part::LastB];

/// Every segment in ring order (without `PAD`).
pub(crate) fn program() -> Vec<Seg> {
    let mut v = Vec::new();
    for i in 0..M_ABS {
        v.extend(PARTS.map(|p| Seg::Pair(PathId::Abs(i), p)));
    }
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
    v.extend([APart::Low, APart::L30, APart::Last].map(Seg::Anch));
    v.extend([Seg::FeeRho, Seg::FeeRseed, Seg::FeeNote]);
    v.extend(PARTS.map(|p| Seg::Pair(PathId::Fee, p)));
    debug_assert!(v.iter().enumerate().all(|(i, s)| s.idx() == i));
    v
}

/// The slot's segments.
pub(crate) fn slot_program() -> Vec<Seg> {
    program()[SLOT_BASE..EPI_BASE].to_vec()
}

pub(crate) const PRO_PERMS: usize = 256;
pub(crate) const SLOT_PERMS: usize = 591;
pub(crate) const EPI_PERMS: usize = 67;

/// The perm index of segment `seg`'s `i`-th perm (`slot` ignored outside a slot).
pub(crate) fn perm_at(slot: usize, seg: Seg, i: usize) -> usize {
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

pub(crate) fn row_of(perm: usize, r: usize) -> usize {
    NUM_ROUNDS * perm + r
}

pub(crate) fn w_height(k: usize) -> usize {
    ((PRO_PERMS + k * SLOT_PERMS + EPI_PERMS) * NUM_ROUNDS).next_power_of_two()
}

/// Tag column order.
pub(crate) const TAGS: [WTag; 4] = WTag::ALL;
const T_R: usize = 2;
const T_C: usize = 3;

fn sd_final(b: usize, t: WTag) -> bool {
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
        (ANC_OFF, 16, vec![(c, claim::PV_A)]),
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

pub(crate) const CMP_OFF: usize = NUM_KECCAK_COLS;
pub(crate) const SEG_OFF: usize = CMP_OFF + LT_WIDTH;
pub(crate) const REM: usize = SEG_OFF + NSEG_COLS;
pub(crate) const Z: usize = REM + 1;
pub(crate) const ZINV: usize = Z + 1;
pub(crate) const LEFT: usize = ZINV + 1;
pub(crate) const ZL: usize = LEFT + 1;
pub(crate) const ZLINV: usize = ZL + 1;
pub(crate) const SIDE: usize = ZLINV + 1;
pub(crate) const TAG_OFF: usize = SIDE + 1;
pub(crate) const N_OFF: usize = TAG_OFF + 4;
pub(crate) const NN: usize = N_OFF + 16;
pub(crate) const C_OFF: usize = NN + 1;
pub(crate) const CN: usize = C_OFF + 16;
pub(crate) const R_OFF: usize = CN + 1;
pub(crate) const SD_OFF: usize = R_OFF + 16;
pub(crate) const K_OFF: usize = SD_OFF + 16;
pub(crate) const KN: usize = K_OFF + 16;
pub(crate) const AA_OFF: usize = KN + 1;
pub(crate) const AAN: usize = AA_OFF + 16;
pub(crate) const NF_OFF: usize = AAN + 1;
pub(crate) const CM_OFF: usize = NF_OFF + 16 * INSERTS;
pub(crate) const RT_OFF: usize = CM_OFF + 16 * APPENDS;
pub(crate) const NRT_OFF: usize = RT_OFF + 16;
pub(crate) const ASSET: usize = NRT_OFF + 16;
pub(crate) const ANC_OFF: usize = ASSET + 1;
pub(crate) const HI_OFF: usize = ANC_OFF + 16;
pub(crate) const NA_OFF: usize = HI_OFF + 16;
pub(crate) const NB_OFF: usize = NA_OFF + 16;
pub(crate) const SIB_OFF: usize = NB_OFF + 16;
pub(crate) const BIT: usize = SIB_OFF + 16;
pub(crate) const ACC: usize = BIT + 1;
pub(crate) const PW: usize = ACC + 1;
pub(crate) const BP: usize = PW + 1;
pub(crate) const AINV: usize = BP + 1;
pub(crate) const ANINV: usize = AINV + 1;
pub(crate) const RCNT: usize = ANINV + 1;
/// The fee accumulator: four unnormalized 16-bit-chunk sums.
pub(crate) const FE_OFF: usize = RCNT + 1;
/// The fee note's ρ and rseed.
pub(crate) const RHO_OFF: usize = FE_OFF + 4;
pub(crate) const RSD_OFF: usize = RHO_OFF + 16;
/// The value's three carries, five bits each.
pub(crate) const FCB_OFF: usize = RSD_OFF + 16;
pub(crate) const ON: usize = FCB_OFF + 15;
pub(crate) const KPA: usize = ON + 1;
pub(crate) const KPB: usize = KPA + 1;
pub(crate) const KCMP: usize = KPB + 1;
pub(crate) const KNC: usize = KCMP + 1;
pub(crate) const KNI: usize = KNC + 1;
pub(crate) const KKC: usize = KNI + 1;
pub(crate) const KKI: usize = KKC + 1;
pub(crate) const KCC: usize = KKI + 1;
pub(crate) const KR: usize = KCC + 1;
pub(crate) const KAN: usize = KR + 1;
pub(crate) const KFE: usize = KAN + 1;
pub(crate) const W: usize = KFE + 1;
pub(crate) const SDC: usize = W + 1;
pub(crate) const SDF: usize = SDC + 1;
pub(crate) const W_WIDTH: usize = SDF + 1;
const PLAN_BASE: usize = SEG_OFF;
const PLAN_WIDTH: usize = W_WIDTH - PLAN_BASE;

// ---------------------------------------------------------------------------
// Public values
// ---------------------------------------------------------------------------

/// One side of the threading surface (16-bit chunks): `N` 16, `n_next` 2,
/// `C` 16, `c_next` 2, `R` 16, `SD` 16, `K` 16, `k_next` 2, `AA` 16, `aa_next` 2.
pub(crate) const PV_N: usize = 0;
pub(crate) const PV_NN: usize = 16;
pub(crate) const PV_C: usize = 18;
pub(crate) const PV_CN: usize = 34;
pub(crate) const PV_R: usize = 36;
pub(crate) const PV_SD: usize = 52;
pub(crate) const PV_K: usize = 68;
pub(crate) const PV_KN: usize = 84;
pub(crate) const PV_AA: usize = 86;
pub(crate) const PV_AAN: usize = 102;
pub(crate) const PV_SIDE: usize = 104;
/// After in and out: `prev` 16, `rkm_seq` 16, the absorbed roots 4 × 16, the
/// fee note's value 4.
pub(crate) const PV_PREV: usize = 2 * PV_SIDE;
pub(crate) const PV_RKMS: usize = PV_PREV + 16;
pub(crate) const PV_ABS: usize = PV_RKMS + 16;
pub(crate) const PV_FEE: usize = PV_ABS + 16 * M_ABS;
pub(crate) const W_PV_LEN: usize = PV_FEE + 4;

/// W's public values.
pub(crate) fn w_pvs(rin: &WRoots, rout: &WRoots, inp: &WInputs, fee: u64) -> Vec<Val> {
    let mut v = Vec::with_capacity(W_PV_LEN);
    let d = |v: &mut Vec<Val>, x: &Digest| v.extend(limbs(x).iter().map(|l| Val::from_u32(*l)));
    let i = |v: &mut Vec<Val>, x: u64| v.extend([Val::from_u32((x & 0xffff) as u32), Val::from_u32((x >> 16) as u32)]);
    for r in [rin, rout] {
        d(&mut v, &r.f3.n);
        i(&mut v, r.f3.n_next);
        d(&mut v, &r.f3.c);
        i(&mut v, r.f3.c_next);
        d(&mut v, &r.f3.r);
        d(&mut v, &r.f3.sd);
        d(&mut v, &r.k);
        i(&mut v, r.k_next);
        d(&mut v, &r.aa);
        i(&mut v, r.aa_next);
    }
    d(&mut v, &inp.prev);
    d(&mut v, &inp.rkm_seq);
    for a in &inp.absorbed {
        d(&mut v, a);
    }
    v.extend((0..4).map(|j| Val::from_u32(((fee >> (16 * j)) & 0xffff) as u32)));
    debug_assert_eq!(v.len(), W_PV_LEN);
    v
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

/// W for `k` slots.
pub(crate) struct WAir {
    pub k: usize,
    kc: KeccakIdx,
}

impl WAir {
    pub(crate) fn new(k: usize) -> Self {
        assert!(k >= 1);
        Self { k, kc: keccak_idx() }
    }
}

pub(crate) const PHASES: &[&str] = &[
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
    "root_r",
    "reg_read",
    "rleaf",
    "rcount",
    "anchor",
    "fee_acc",
    "fee_seed",
    "fee_note",
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

pub(crate) fn phase_ranges(air: &WAir) -> Vec<Range<usize>> {
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

pub(crate) fn phase_of(ranges: &[Range<usize>], constraint: usize) -> &'static str {
    PHASES[ranges.iter().position(|r| r.contains(&constraint)).expect("a constraint of W")]
}

/// What SD block `b`'s preimage limb `(lane, m)` must be, per tag (`None` =
/// message data or the chaining value).
pub(crate) fn sd_expect(b: usize, lane: usize, m: usize) -> [Option<u32>; 4] {
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
fn fee_pos(j: usize) -> (usize, usize, usize) {
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
        let abs_last = |i: usize| Seg::Pair(PathId::Abs(i), Part::LastB);
        let to_abs: Vec<Seg> = (0..M_ABS - 1).map(abs_last).collect();
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
                    f.assert_zero(c(NB_OFF + j) - pv_abs(0, j));
                }
                for j in 0..4 {
                    f.assert_zero(c(FE_OFF + j));
                }
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD), (K_OFF, PV_K), (AA_OFF, PV_AA)] {
                    for j in 0..16 {
                        f.assert_zero(c(col + j) - pvs[at + j].clone());
                    }
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN), (KN, PV_KN), (AAN, PV_AAN)] {
                    f.assert_zero(c(col) - pvs[at].clone() - pvs[at + 1].clone() * radix);
                }
            }
            "last" => {
                let mut l = builder.when_last_row();
                l.assert_one(c(SEG_OFF + PAD));
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD), (K_OFF, PV_K), (AA_OFF, PV_AA)] {
                    for j in 0..16 {
                        l.assert_zero(c(col + j) - pvs[PV_SIDE + at + j].clone());
                    }
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN), (KN, PV_KN), (AAN, PV_AAN)] {
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
                for col in (NF_OFF..=ASSET).chain(ANC_OFF..ANC_OFF + 16) {
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
                let fao = ka() + segs(&leaf_old) + segs(&anch);
                let faz = segs(&leaf_new) + seg(to_c0) + seg(to_c1) + segs(&to_abs) + seg(Seg::FeeNote);
                let fanc = seg(r_last);
                let free = seg(Seg::RegLeaf);
                let fbo = kb() - seg(to_c0) - seg(to_c1) - segs(&to_abs)
                    + segs(&leaf_mid)
                    + segs(&leaf_new)
                    + seg(Seg::RegLeaf)
                    + seg(Seg::FeeNote);
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
                                    + free.clone() * (na - a)),
                    );
                    let (b, nb) = (c(NB_OFF + j), n(NB_OFF + j));
                    let abs_next = (0..M_ABS - 1).fold(AB::Expr::ZERO, |acc, i| acc + seg(abs_last(i)) * (pv_abs(i + 1, j) - b.clone()));
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
                        matches!(s, Seg::Pair(p, Part::L30 | Part::LastA | Part::LastB) if *p != PathId::R)
                            || matches!(s, Seg::Anch(APart::L30 | APart::Last))
                    })
                    .fold(AB::Expr::ZERO, |a, s| a + seg(*s));
                builder.assert_zero(capped * c(BIT));
            }
            "index" => {
                let fi = segs(&leaf_mid) + segs(&leaf_new) + seg(to_c0) + seg(to_c1) + seg(Seg::RegLeaf) + segs(&to_abs) + seg(Seg::FeeNote);
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
                let kab = (0..M_ABS).fold(AB::Expr::ZERO, |a, i| a + seg(abs_last(i)));
                for j in 0..16 {
                    builder.assert_zero(kab.clone() * (c(NA_OFF + j) - c(AA_OFF + j)));
                }
                builder.assert_zero(kab.clone() * (c(ACC) + c(BP) - c(AAN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(AA_OFF + j) - c(AA_OFF + j) - fin.clone() * kab.clone() * (out(j / 4, j % 4) - c(AA_OFF + j)));
                }
                t.assert_zero(n(AAN) - c(AAN) - fin * kab);
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
                for j in 0..16 {
                    builder.assert_zero(fin.clone() * c(KAN) * (out(j / 4, j % 4) - c(AA_OFF + j)));
                }
                // A ≠ 0: its limbs' sum (< 2^20) has an inverse.
                let sum = (0..16).fold(AB::Expr::ZERO, |a, j| a + c(ANC_OFF + j));
                builder.assert_zero(c(KAN) * (sum * c(ANINV) - one.clone()));
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
            other => unreachable!("phase {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct PermPlan {
    pub pre: [u64; 25],
    pub cols: Vec<Val>,
}

impl PermPlan {
    pub(crate) fn get(&self, col: usize) -> Val {
        self.cols[col - PLAN_BASE]
    }
    pub(crate) fn set(&mut self, col: usize, v: Val) {
        self.cols[col - PLAN_BASE] = v;
    }
}

#[derive(Clone)]
pub(crate) struct Plan {
    pub perms: Vec<PermPlan>,
    pub pad: PermPlan,
}

#[derive(Clone)]
struct Regs {
    n: Digest,
    nn: u64,
    c: Digest,
    cn: u64,
    r: Digest,
    sd: Digest,
    k: Digest,
    kn: u64,
    aa: Digest,
    aan: u64,
    nf: [Digest; INSERTS],
    cm: [Digest; APPENDS],
    rt: Digest,
    nrt: Digest,
    asset: u64,
    anc: Digest,
    hi: Digest,
    na: Digest,
    nb: Digest,
    sib: Digest,
    bit: bool,
    acc: Val,
    pw: Val,
    rcnt: u64,
    tag: WTag,
    left: i64,
    fe: [u64; 4],
    rho: Digest,
    rsd: Digest,
    fcb: [u32; 3],
}

fn put_digest(cols: &mut [Val], at: usize, d: &Digest) {
    for (j, l) in limbs(d).iter().enumerate() {
        cols[at - PLAN_BASE + j] = Val::from_u32(*l);
    }
}

/// One slot's witness view, uniform over transactions and claims.
struct SlotView<'a> {
    member: &'a Member,
    inserts: Vec<crate::f3::native::InsertWitness>,
    appends: Vec<crate::f3::native::AppendWitness>,
    write: Option<crate::f3::native::RegistryWrite>,
    anchor: Option<qlab_air::narrow::MerkleWitness>,
}

fn slot_view<'a>(m: &'a Member, w: &'a SlotWitness) -> SlotView<'a> {
    match w {
        SlotWitness::Tx(t) => SlotView { member: m, inserts: t.inserts.clone(), appends: t.appends.clone(), write: t.write, anchor: None },
        SlotWitness::Claim(c) => SlotView { member: m, inserts: vec![c.insert], appends: vec![c.append], write: None, anchor: Some(c.anchor_path) },
    }
}

/// Build W's plan from a witness, without validating it.
pub(crate) fn build_plan(rin: &WRoots, inp: &WInputs, members: &[Member], w: &WWitness) -> Plan {
    let k = members.len();
    assert!(k >= 1 && w.slots.len() == k);
    let prog = program();
    let mut g = Regs {
        n: rin.f3.n,
        nn: rin.f3.n_next,
        c: rin.f3.c,
        cn: rin.f3.c_next,
        r: rin.f3.r,
        sd: rin.f3.sd,
        k: rin.k,
        kn: rin.k_next,
        aa: rin.aa,
        aan: rin.aa_next,
        nf: [EMPTY; INSERTS],
        cm: [EMPTY; APPENDS],
        rt: EMPTY,
        nrt: EMPTY,
        asset: 0,
        anc: EMPTY,
        hi: EMPTY,
        na: EMPTY,
        nb: inp.absorbed[0],
        sib: EMPTY,
        bit: false,
        acc: Val::ZERO,
        pw: Val::ONE,
        rcnt: 0,
        tag: members[0].tag,
        left: k as i64 - 1,
        fe: [0; 4],
        rho: EMPTY,
        rsd: EMPTY,
        fcb: [0; 3],
    };
    let mut perms: Vec<PermPlan> = Vec::new();
    let views: Vec<SlotView> = members.iter().zip(&w.slots).map(|(m, s)| slot_view(m, s)).collect();
    let run = |s: Seg, g: &mut Regs, view: Option<&SlotView>, blocks: &[[u64; 25]], perms: &mut Vec<PermPlan>| {
        for i in 0..s.len() {
            let side = if s.is_pair_bulk() { i % 2 } else { 0 };
            let (level, path_a) = pair_level(s, i);
            if let Some(lvl) = level {
                if path_a {
                    let (sib, bit) = path_at(s, view, w, lvl);
                    g.sib = sib;
                    g.bit = bit;
                }
            }
            if let Seg::FeeNote = s {
                // Normalize the accumulator into the value limbs; the carries.
                let mut c = 0u64;
                for j in 0..3 {
                    let t = g.fe[j] + c;
                    c = t >> 16;
                    g.fcb[j] = c as u32;
                }
            }
            let pre = perm_input(s, i, g, view, blocks, perms, inp);
            if let Seg::LeafOld(_) = s {
                g.hi = pre[4..8].try_into().expect("four lanes");
            }
            let rem = s.len() - 1 - i;
            perms.push(PermPlan { pre, cols: snapshot(s, rem, side, g) });
            let out = out4(&pre);
            step(s, side, out, g, inp, &pre);
        }
    };
    // Slot 0's surface registers hold from the first row (they change only
    // at a slot boundary), so they are set before the prologue.
    set_surface(&mut g, &members[0]);
    for s in &prog[..SLOT_BASE] {
        run(*s, &mut g, None, &[], &mut perms);
    }
    for view in &views {
        let m = view.member;
        set_surface(&mut g, m);
        let pvs = &m.pvs;
        let (blocks, _) = sd_chain_byte(&g.sd, m.tag.byte(), pvs);
        for s in &prog[SLOT_BASE..EPI_BASE] {
            run(*s, &mut g, Some(view), &blocks, &mut perms);
        }
    }
    for s in &prog[EPI_BASE..] {
        run(*s, &mut g, None, &[], &mut perms);
    }
    let pad = PermPlan { pre: [0; 25], cols: snapshot(Seg::Pad, 0, 0, &g) };
    Plan { perms, pad }
}

/// A slot's surface registers and tag, from its member's PVs (unvalidated).
fn set_surface(g: &mut Regs, m: &Member) {
    use qlab_air::{claim, l2, l2p, l2r};
    {
        g.tag = m.tag;
        let pvs = &m.pvs;
        g.nf = [EMPTY; INSERTS];
        g.cm = [EMPTY; APPENDS];
        g.rt = EMPTY;
        g.nrt = EMPTY;
        g.asset = 0;
        g.anc = EMPTY;
        match m.tag {
            WTag::R => {
                g.nf[0] = pv_digest(pvs, l2r::PV_NF);
                g.cm = [pv_digest(pvs, l2r::PV_CM), pv_digest(pvs, l2r::PV_CM_SEED)];
                g.rt = pv_digest(pvs, l2r::PV_OLD_ROOT);
                g.nrt = pv_digest(pvs, l2r::PV_NEW_ROOT);
                g.asset = u64::from(pvs.get(l2r::PV_ASSET).copied().unwrap_or(0) & 0xffff);
            }
            WTag::C => {
                g.nf[0] = pv_digest(pvs, claim::PV_CNF);
                g.cm[0] = pv_digest(pvs, claim::PV_CM2);
                g.anc = pv_digest(pvs, claim::PV_A);
                g.rt = g.r;
            }
            t => {
                let nf3 = if t == WTag::S { l2::PV_NF3 } else { l2p::PV_NF3 };
                g.nf = [pv_digest(pvs, l2::PV_NF1), pv_digest(pvs, l2::PV_NF2), pv_digest(pvs, nf3)];
                g.cm = [pv_digest(pvs, l2::PV_CM1), pv_digest(pvs, l2::PV_CM2)];
                g.rt = pv_digest(pvs, l2::PV_REGROOT);
            }
        }
    }
}

fn pair_level(s: Seg, i: usize) -> (Option<usize>, bool) {
    match s {
        Seg::Pair(_, Part::Bulk) => (Some(i / 2), i.is_multiple_of(2)),
        Seg::Pair(_, Part::L30) => (Some(30 + i / 2), i.is_multiple_of(2)),
        Seg::Pair(p, Part::LastA) => (Some(p.depth() - 1), true),
        Seg::Pair(p, Part::LastB) => (Some(p.depth() - 1), false),
        Seg::Anch(APart::Low) => (Some(i), true),
        Seg::Anch(APart::L30) => (Some(30), true),
        Seg::Anch(APart::Last) => (Some(31), true),
        _ => (None, false),
    }
}

fn path_at(s: Seg, view: Option<&SlotView>, w: &WWitness, lvl: usize) -> (Digest, bool) {
    let get = |p: &qlab_air::narrow::MerkleWitness| (p.siblings[lvl], p.path_bits[lvl]);
    let r = match s {
        Seg::Pair(PathId::Mid(i), _) => view.and_then(|v| v.inserts.get(i)).map(|x| get(&x.low_path)),
        Seg::Pair(PathId::New(i), _) => view.and_then(|v| v.inserts.get(i)).map(|x| get(&x.new_path)),
        Seg::Pair(PathId::C(j), _) => view.and_then(|v| v.appends.get(j)).map(|x| get(&x.path)),
        Seg::Pair(PathId::R, _) => view.and_then(|v| v.write.as_ref()).map(|x| (x.path.siblings[lvl], x.path.path_bits[lvl])),
        Seg::Pair(PathId::Abs(i), _) => Some(get(&w.absorbs[i].path)),
        Seg::Pair(PathId::Fee, _) => Some(get(&w.fee.path)),
        Seg::Anch(_) => view.and_then(|v| v.anchor.as_ref()).map(get),
        _ => None,
    };
    r.unwrap_or((EMPTY, false))
}

fn perm_input(s: Seg, i: usize, g: &Regs, view: Option<&SlotView>, blocks: &[[u64; 25]], perms: &[PermPlan], inp: &WInputs) -> [u64; 25] {
    let on = s.active(g.tag);
    let ins = |i: usize| view.and_then(|v| v.inserts.get(i)).filter(|_| on);
    match s {
        Seg::Sd(b) => {
            if on {
                blocks.get(b).copied().unwrap_or([0; 25])
            } else {
                [0; 25]
            }
        }
        Seg::LeafOld(i) => ins(i).map_or(nf_leaf_state(&EMPTY, &EMPTY), |x| nf_leaf_state(&x.low.0, &x.low.1)),
        Seg::LeafMid(i) => {
            let lo: Digest = perms.last().expect("LEAF_OLD precedes").pre[..4].try_into().expect("four lanes");
            nf_leaf_state(&lo, &ins(i).map_or(EMPTY, |x| x.key))
        }
        Seg::LeafNew(i) => nf_leaf_state(&ins(i).map_or(EMPTY, |x| x.key), &g.hi),
        Seg::Pair(_, _) => {
            let (_, a) = pair_level(s, i);
            let x = if a { &g.na } else { &g.nb };
            let (l, r) = mux(g.bit, x, &g.sib);
            node_state(&l, &r)
        }
        Seg::Anch(_) => {
            let (l, r) = mux(g.bit, &g.na, &g.sib);
            node_state(&l, &r)
        }
        Seg::RegLeaf => match (view.and_then(|v| v.write.as_ref()), g.tag) {
            (Some(rw), WTag::R) => rw.leaf.state(),
            _ => [0; 25],
        },
        Seg::FeeRho => fee_seed_state(&inp.prev, 1),
        Seg::FeeRseed => fee_seed_state(&inp.prev, 2),
        Seg::FeeNote => {
            let mut st = [0u64; 25];
            st[0] = fee_value(g);
            st[1] = 0;
            st[2..6].copy_from_slice(&inp.rkm_seq);
            st[6..10].copy_from_slice(&g.rho);
            st[10..14].copy_from_slice(&g.rsd);
            st[14] = 1;
            st[16] = 1 << 63;
            st
        }
        Seg::Pad => [0; 25],
    }
}

/// The accumulator as a u64 (the normalized value; wraps past 2^64 — the AIR refuses that).
fn fee_value(g: &Regs) -> u64 {
    (0..4).fold(0u128, |a, j| a + (u128::from(g.fe[j]) << (16 * j))) as u64
}

fn snapshot(s: Seg, rem: usize, side: usize, g: &Regs) -> Vec<Val> {
    let mut cols = vec![Val::ZERO; PLAN_WIDTH];
    let put = |cols: &mut Vec<Val>, col: usize, v: Val| cols[col - PLAN_BASE] = v;
    put(&mut cols, SEG_OFF + s.idx(), Val::ONE);
    let rv = Val::from_u32(rem as u32);
    put(&mut cols, REM, rv);
    put(&mut cols, Z, Val::from_bool(rem == 0));
    put(&mut cols, ZINV, inv_or_zero(rv));
    let lv = if g.left >= 0 { Val::from_u32(g.left as u32) } else { -Val::from_u32((-g.left) as u32) };
    put(&mut cols, LEFT, lv);
    put(&mut cols, ZL, Val::from_bool(g.left == 0));
    put(&mut cols, ZLINV, inv_or_zero(lv));
    put(&mut cols, SIDE, Val::from_u32(side as u32));
    let t = TAGS.iter().position(|x| *x == g.tag).expect("a tag");
    put(&mut cols, TAG_OFF + t, Val::ONE);
    put_digest(&mut cols, N_OFF, &g.n);
    put(&mut cols, NN, Val::from_u32(g.nn as u32));
    put_digest(&mut cols, C_OFF, &g.c);
    put(&mut cols, CN, Val::from_u32(g.cn as u32));
    put_digest(&mut cols, R_OFF, &g.r);
    put_digest(&mut cols, SD_OFF, &g.sd);
    put_digest(&mut cols, K_OFF, &g.k);
    put(&mut cols, KN, Val::from_u32(g.kn as u32));
    put_digest(&mut cols, AA_OFF, &g.aa);
    put(&mut cols, AAN, Val::from_u32(g.aan as u32));
    for i in 0..INSERTS {
        put_digest(&mut cols, NF_OFF + 16 * i, &g.nf[i]);
    }
    for j in 0..APPENDS {
        put_digest(&mut cols, CM_OFF + 16 * j, &g.cm[j]);
    }
    put_digest(&mut cols, RT_OFF, &g.rt);
    put_digest(&mut cols, NRT_OFF, &g.nrt);
    let av = Val::from_u32(g.asset as u32);
    put(&mut cols, ASSET, av);
    put(&mut cols, AINV, inv_or_zero(av));
    put_digest(&mut cols, ANC_OFF, &g.anc);
    let asum: u32 = limbs(&g.anc).iter().sum();
    put(&mut cols, ANINV, inv_or_zero(Val::from_u32(asum)));
    put_digest(&mut cols, HI_OFF, &g.hi);
    put_digest(&mut cols, NA_OFF, &g.na);
    put_digest(&mut cols, NB_OFF, &g.nb);
    put_digest(&mut cols, SIB_OFF, &g.sib);
    put(&mut cols, BIT, Val::from_bool(g.bit));
    put(&mut cols, ACC, g.acc);
    put(&mut cols, PW, g.pw);
    put(&mut cols, BP, if g.bit { g.pw } else { Val::ZERO });
    put(&mut cols, RCNT, Val::from_u32(g.rcnt as u32));
    for j in 0..4 {
        put(&mut cols, FE_OFF + j, Val::from_u32(g.fe[j] as u32));
    }
    put_digest(&mut cols, RHO_OFF, &g.rho);
    put_digest(&mut cols, RSD_OFF, &g.rsd);
    if s == Seg::FeeNote {
        for j in 0..3 {
            for b in 0..5 {
                put(&mut cols, FCB_OFF + 5 * j + b, Val::from_u32((g.fcb[j] >> b) & 1));
            }
        }
    }
    let on = s.active(g.tag);
    let tx = matches!(g.tag, WTag::S | WTag::P | WTag::R);
    let cl = g.tag == WTag::C;
    put(&mut cols, ON, Val::from_bool(on));
    put(&mut cols, KPA, Val::from_bool(s.is_pair_bulk() && side == 0));
    put(&mut cols, KPB, Val::from_bool(s.is_pair_bulk() && side == 1));
    put(&mut cols, KCMP, Val::from_bool(on && matches!(s, Seg::LeafMid(_) | Seg::LeafNew(_))));
    put(&mut cols, KNC, Val::from_bool(on && tx && matches!(s, Seg::Pair(PathId::Mid(_) | PathId::New(_), Part::LastB))));
    put(&mut cols, KNI, Val::from_bool(on && tx && matches!(s, Seg::Pair(PathId::New(_), Part::LastB))));
    put(&mut cols, KKC, Val::from_bool(cl && matches!(s, Seg::Pair(PathId::Mid(0) | PathId::New(0), Part::LastB))));
    put(&mut cols, KKI, Val::from_bool(cl && s == Seg::Pair(PathId::New(0), Part::LastB)));
    let kcc = s == Seg::Pair(PathId::C(0), Part::LastB) || (s == Seg::Pair(PathId::C(1), Part::LastB) && on) || s == Seg::Pair(PathId::Fee, Part::LastB);
    put(&mut cols, KCC, Val::from_bool(kcc));
    put(&mut cols, KR, Val::from_bool(g.tag == WTag::R && s == Seg::Pair(PathId::R, Part::LastB)));
    put(&mut cols, KAN, Val::from_bool(cl && s == Seg::Anch(APart::Last)));
    put(&mut cols, KFE, Val::from_bool(cl && s == Seg::Sd(fee_pos(0).0)));
    put(&mut cols, W, Val::from_bool(rem == 0 && s.idx() == SLOT_LAST));
    let sdc = matches!(s, Seg::Sd(b) if b + 1 < SD_BLOCKS && Seg::Sd(b + 1).active(g.tag));
    put(&mut cols, SDC, Val::from_bool(sdc));
    put(&mut cols, SDF, Val::from_bool(matches!(s, Seg::Sd(b) if sd_final(b, g.tag))));
    cols
}

/// The perm's last-row transition.
fn step(s: Seg, side: usize, out: Digest, g: &mut Regs, inp: &WInputs, pre: &[u64; 25]) {
    let on = s.active(g.tag);
    let tx = matches!(g.tag, WTag::S | WTag::P | WTag::R);
    let to_c0 = Seg::Pair(PathId::New(INSERTS - 1), Part::LastB);
    let to_c1 = Seg::Pair(PathId::C(0), Part::LastB);
    let reset = |g: &mut Regs| {
        g.acc = Val::ZERO;
        g.pw = Val::ONE;
    };
    match s {
        Seg::Sd(b) => {
            if sd_final(b, g.tag) {
                g.sd = out;
            }
            if g.tag == WTag::C && b == fee_pos(0).0 {
                for j in 0..4 {
                    let (_, l, m) = fee_pos(j);
                    g.fe[j] += (pre[l] >> (16 * m)) & 0xffff;
                }
            }
        }
        Seg::LeafOld(_) => g.na = out,
        Seg::LeafMid(_) => {
            g.nb = out;
            reset(g);
        }
        Seg::LeafNew(_) => {
            g.na = EMPTY;
            g.nb = out;
            reset(g);
        }
        Seg::Anch(_) => g.na = out,
        Seg::Pair(p, part) => {
            let a = match part {
                Part::Bulk | Part::L30 => side == 0,
                Part::LastA => true,
                Part::LastB => false,
            };
            let to_abs = matches!(p, PathId::Abs(i) if i + 1 < M_ABS) && part == Part::LastB;
            if a {
                g.na = out;
            } else if s != to_c0 && s != to_c1 && !to_abs {
                g.nb = out;
            }
            if matches!(part, Part::Bulk | Part::L30) && !a {
                if g.bit {
                    g.acc += g.pw;
                }
                g.pw = g.pw.double();
            }
            if part == Part::LastB {
                match p {
                    PathId::Mid(_) if on && tx => g.n = out,
                    PathId::New(_) if on && tx => {
                        g.n = out;
                        g.nn += 1;
                    }
                    PathId::Mid(0) if g.tag == WTag::C => g.k = out,
                    PathId::New(0) if g.tag == WTag::C => {
                        g.k = out;
                        g.kn += 1;
                    }
                    PathId::C(j) if j == 0 || on => {
                        g.c = out;
                        g.cn += 1;
                    }
                    PathId::Fee => {
                        g.c = out;
                        g.cn += 1;
                    }
                    PathId::Abs(_) => {
                        g.aa = out;
                        g.aan += 1;
                    }
                    PathId::R if g.tag == WTag::R => g.r = out,
                    _ => {}
                }
                if s == to_c0 {
                    g.na = EMPTY;
                    g.nb = g.cm[0];
                    reset(g);
                }
                if s == to_c1 {
                    g.na = EMPTY;
                    g.nb = g.cm[1];
                    reset(g);
                }
                if let PathId::Abs(i) = p {
                    if i + 1 < M_ABS {
                        g.na = EMPTY;
                        g.nb = inp.absorbed[i + 1];
                        reset(g);
                    }
                }
                if p == PathId::R {
                    // The slot boundary; the anchor path starts from A.
                    g.na = g.anc;
                }
            }
        }
        Seg::RegLeaf => {
            g.nb = out;
            g.na = EMPTY;
            reset(g);
        }
        Seg::FeeRho => g.rho = out,
        Seg::FeeRseed => g.rsd = out,
        Seg::FeeNote => {
            g.na = EMPTY;
            g.nb = out;
            reset(g);
        }
        Seg::Pad => {}
    }
    if s == Seg::Anch(APart::Last) {
        g.rcnt += u64::from(g.tag == WTag::R);
        g.left -= 1;
    }
}

/// Render the plan.
pub(crate) fn render(plan: &Plan) -> RowMajorMatrix<Val> {
    let inputs: Vec<[u64; 25]> = plan.perms.iter().map(|p| p.pre).collect();
    let keccak = generate_trace_rows::<Val>(inputs, 0);
    let height = keccak.values.len() / NUM_KECCAK_COLS;
    let mut values = Val::zero_vec(height * W_WIDTH);
    for (r, row) in values.chunks_exact_mut(W_WIDTH).enumerate() {
        row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
        let p = plan.perms.get(r / NUM_ROUNDS).unwrap_or(&plan.pad);
        row[PLAN_BASE..].copy_from_slice(&p.cols);
        if r % NUM_ROUNDS == 0 && p.get(KCMP) == Val::ONE {
            let (x, y): (Digest, Digest) = (p.pre[..4].try_into().expect("four lanes"), p.pre[4..8].try_into().expect("four lanes"));
            cmp::fill(&mut row[CMP_OFF..CMP_OFF + LT_WIDTH], &cmp::lt_raw(&limbs(&x), &limbs(&y)));
        }
    }
    RowMajorMatrix::new(values, W_WIDTH)
}

/// The fee note's value the witness implies (Σ fee over claims).
pub(crate) fn fee_of(members: &[Member]) -> u64 {
    members
        .iter()
        .filter(|m| m.tag == WTag::C)
        .map(|m| (0..4).map(|j| u64::from(m.pvs[qlab_air::claim::PV_FEE + j] & 0xffff) << (16 * j)).sum::<u64>())
        .fold(0u64, |a, f| a.wrapping_add(f))
}

const _: () = assert!(CLAIM_TAG == 0x04);

// ---------------------------------------------------------------------------
// The checker (p3's row loop)
// ---------------------------------------------------------------------------

pub(crate) fn failures_at(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize) -> Vec<usize> {
    use p3_air::DebugConstraintBuilder;
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::ViewPair;
    use p3_matrix::Matrix;
    let height = trace.height();
    let next = (row + 1) % height;
    let local = trace.row_slice(row).expect("a row");
    let nxt = trace.row_slice(next).expect("a row");
    let main = ViewPair::new(RowMajorMatrixView::new_row(&*local), RowMajorMatrixView::new_row(&*nxt));
    let prep = ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0));
    let mut builder = DebugConstraintBuilder::new(
        row,
        main,
        prep,
        pvs,
        Val::from_bool(row == 0),
        Val::from_bool(row == height - 1),
        Val::from_bool(row != height - 1),
        &[],
    );
    air.eval(&mut builder);
    builder.into_failures().into_iter().map(|f| f.constraint).collect()
}

pub(crate) fn phases_at(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize, ranges: &[Range<usize>]) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = failures_at(air, trace, pvs, row).into_iter().map(|c| phase_of(ranges, c)).collect();
    v.dedup();
    v
}

pub(crate) fn first_violation(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val]) -> Option<(usize, Vec<&'static str>)> {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use p3_matrix::Matrix;
    use p3_maybe_rayon::prelude::*;
    const CHUNK: usize = 1024;
    let height = trace.height();
    let best = AtomicUsize::new(usize::MAX);
    (0..height.div_ceil(CHUNK)).into_par_iter().for_each(|ch| {
        for row in ch * CHUNK..((ch + 1) * CHUNK).min(height) {
            if row >= best.load(Ordering::Relaxed) {
                return;
            }
            if !failures_at(air, trace, pvs, row).is_empty() {
                best.fetch_min(row, Ordering::Relaxed);
                return;
            }
        }
    });
    let row = best.into_inner();
    (row != usize::MAX).then(|| (row, phases_at(air, trace, pvs, row, &phase_ranges(air))))
}
