//! Lab #767 F3-2b — **the state-transition leaf AIR** on the wide lane.
//!
//! One leaf proves [`super::native::check_leaf`] for a batch of `k`
//! transactions: from the public `(N, n_next, C, c_next, R, SD)` in to the
//! public ones out, every nullifier inserted into the indexed tree, every
//! commitment appended, the registry read or replaced, and every
//! transaction's full surface chained into `SD`.
//!
//! **Lane.** Stock p3-keccak-air (24 rows per perm, 2,633 columns) at column
//! 0, evaluated through [`LaneBuilder`]; every hash the leaf computes is one
//! perm whose 16-bit preimage limbs and output limbs are the data. Degree 3,
//! so b2 is a lane.
//!
//! **The program** (approved on #767, deviation 4). Every transaction owns a
//! fixed **slot** of [`SLOT_PERMS`] = 560 perms, the same for S, P and R, so
//! one leaf AIR per `k` covers every shape mix:
//!
//! ```text
//!   SD blocks ×6 | insert ×3 (131 each) | append ×2 (64 each) | registry (33)
//!   insert i:  LEAF_OLD (lo,hi) · LEAF_MID (lo,K) · 32 levels of (OLD, MID)
//!              · LEAF_NEW (K,hi) · 32 levels of (EMPTY, NEW)
//!   append j:  32 levels of (EMPTY, cm)
//!   registry:  REG_LEAF (new leaf) · 16 levels of (OLD, NEW)
//! ```
//!
//! The two paths an update opens share their siblings and path bits, so they
//! are **interleaved level by level** (A/B perm pairs): a sibling and a bit
//! are held for two perms, not a whole path. The shape tag — a one-hot
//! register bound to `SD`'s word 0 — gates activity: inserts 2 and 3 and SD
//! blocks 4–5 are off for R, the registry segment is off for S/P. An inactive
//! segment's perms still hash (anything), but no running root, index or `SD`
//! moves and its comparator cells are zero.
//!
//! The program is driven by a one-hot **segment ring** ([`slot_program`], 50
//! segments + `PAD`) with a down-counter and its zero test, and a slot
//! counter that sends the ring to `PAD` after `k` slots. Every per-perm flag
//! a data constraint needs is a materialized column defined from the ring
//! and the tag, which keeps every constraint at degree ≤ 3.
//!
//! **The binding rows.** Each §5 / ruling-(d) negative is refused at a named
//! constraint group ([`PHASES`]) on the row that binds it:
//!
//! - the strict gap `lo < K < hi` — the [`super::cmp`] gadget on `LEAF_MID`'s
//!   and `LEAF_NEW`'s step-0 rows, comparing each row's own preimage lanes
//!   0..4 < 4..8 (so both inputs are Keccak preimage limbs, 16-bit by
//!   p3-keccak-air's recomposition); `LEAF_MID`'s `lo` is `LEAF_OLD`'s (an
//!   adjacent-row transition), `LEAF_NEW`'s `hi` is `LEAF_OLD`'s (a held
//!   register), and `K` is the nullifier chunk `SD` absorbed (`leaf_key`);
//! - an opened root against the running root — the last level's B perm
//!   (`root_n`, `root_c`, `root_r`); the append index against the running
//!   next index there too;
//! - the surface — `SD`'s block preimages (`sd`, `sd_capture`): the tag, the
//!   length, every PV word, and each register the leaf acts on;
//! - threading — every running register's hold/update constraint.
//!
//! **Limits** (approved deviations 1–2): `SD` is the Merkle–Damgård chain of
//! [`super::native::sd_chain`]; both append trees stop at
//! [`INDEX_CAP`] = 2^30, the path bits 30 and 31 forced to zero.
// The bench modes (F3-2c) are this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use std::ops::Range;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use qlab_consensus::Val;
use qlab_devnet::annulet::L2ShapeTag;

use super::cmp::{self, limbs, LT_WIDTH};
use super::native::{
    sd_chain, sd_domain_lanes, sd_perms, Digest, Roots, TxSurface, TxWitness, EMPTY, INDEX_CAP, N_DEPTH,
    SD_BLOCK_WORDS, SD_LANE_DOMAIN, SD_LANE_FINAL, SD_LANE_INDEX, SD_LANE_MSG,
};
use crate::m4skel::LaneBuilder;

// Lab #785 F5-1: the Keccak-lane helpers moved to qlab-wrapper.
pub(crate) use qlab_wrapper::hash::{keccak_idx, out4, pv_digest, KeccakIdx};

// Lab #785 F5-4a (review Y2 on PR #787): the prover's trace helpers came
// back from qlab-wrapper, where nothing used them.
pub(crate) fn nf_leaf_state(lo: &Digest, hi: &Digest) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(lo);
    st[4..8].copy_from_slice(hi);
    st[8] = 1 << 4;
    st[16] = 1 << 63;
    st
}

pub(crate) fn node_state(l: &Digest, r: &Digest) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(l);
    st[4..8].copy_from_slice(r);
    st[8] = 1;
    st[16] = 1 << 63;
    st
}

pub(crate) fn inv_or_zero(v: Val) -> Val {
    p3_field::Field::try_inverse(&v).unwrap_or(Val::ZERO)
}

pub(crate) fn mux(bit: bool, x: &Digest, sib: &Digest) -> (Digest, Digest) {
    if bit {
        (*sib, *x)
    } else {
        (*x, *sib)
    }
}

// ---------------------------------------------------------------------------
// The slot program
// ---------------------------------------------------------------------------

/// SD blocks per slot: the most any shape needs (S 5, P 6, R 4) — P's exit
/// recipient (lab #785 F5-4d) took it from 5 to 6.
pub(crate) const SD_BLOCKS: usize = 6;
const _: () = assert!(SD_BLOCKS == sd_perms(qlab_air::l2p::PV_LEN));
/// Nullifier inserts per slot (S/P 3, R 1).
pub(crate) const INSERTS: usize = 3;
/// Commitment appends per slot (every shape 2).
pub(crate) const APPENDS: usize = 2;
/// The registry's depth.
pub(crate) const R_DEPTH: usize = qlab_air::l2::REGISTRY_DEPTH;

/// Which update path a pair segment walks. The A perm of a level is the
/// first path, the B perm the second: `Mid` = (OLD, MID), `New` =
/// (EMPTY, NEW), `C` = (EMPTY, cm), `R` = (OLD, NEW).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathId {
    Mid(usize),
    New(usize),
    C(usize),
    R,
}

impl PathId {
    pub(crate) const fn depth(self) -> usize {
        match self {
            PathId::R => R_DEPTH,
            _ => N_DEPTH,
        }
    }
}

/// The levels a pair segment covers: `Bulk` all but the last one (N/C: all
/// but the last two), `L30` level 30 (N/C only; bit forced 0), `LastA` /
/// `LastB` the last level's two perms, one segment each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    Bulk,
    L30,
    LastA,
    LastB,
}

/// One segment of the slot program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Sd(usize),
    LeafOld(usize),
    LeafMid(usize),
    LeafNew(usize),
    Pair(PathId, Part),
    RegLeaf,
    Pad,
}

/// Segments per slot; `PAD` is ring position [`NSEG`].
pub(crate) const NSEG: usize = SD_BLOCKS + 3 * 11 + 2 * 4 + 4;
/// The ring's columns: the slot's segments and `PAD`.
pub(crate) const NSEG_COLS: usize = NSEG + 1;
/// The slot's last segment (its end is the slot boundary).
pub(crate) const LAST_SEG: usize = NSEG - 1;

impl Seg {
    /// The segment's ring position.
    pub(crate) const fn idx(self) -> usize {
        // The slot's segments after its SD blocks.
        let l = SD_BLOCKS;
        match self {
            Seg::Sd(b) => b,
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
            Seg::Pad => NSEG,
        }
    }

    /// Perms in the segment.
    pub(crate) const fn len(self) -> usize {
        match self {
            Seg::Pair(p, Part::Bulk) => 2 * (p.depth() - if matches!(p, PathId::R) { 1 } else { 2 }),
            Seg::Pair(_, Part::L30) => 2,
            _ => 1,
        }
    }

    /// Whether the segment acts for a transaction of shape `tag`.
    pub(crate) fn active(self, tag: L2ShapeTag) -> bool {
        let r = tag == L2ShapeTag::R;
        match self {
            Seg::Sd(b) => b < sd_perms(pv_len(tag)),
            Seg::LeafOld(i) | Seg::LeafMid(i) | Seg::LeafNew(i) | Seg::Pair(PathId::Mid(i) | PathId::New(i), _) => {
                i == 0 || !r
            }
            Seg::Pair(PathId::C(_), _) => true,
            Seg::RegLeaf | Seg::Pair(PathId::R, _) => r,
            Seg::Pad => false,
        }
    }

    fn is_pair_bulk(self) -> bool {
        matches!(self, Seg::Pair(_, Part::Bulk | Part::L30))
    }
}

const fn part_off(p: Part) -> usize {
    match p {
        Part::Bulk => 0,
        Part::L30 => 1,
        Part::LastA => 2,
        Part::LastB => 3,
    }
}

/// The slot's segments in ring order.
pub(crate) fn slot_program() -> Vec<Seg> {
    let mut v: Vec<Seg> = (0..SD_BLOCKS).map(Seg::Sd).collect();
    for i in 0..INSERTS {
        v.push(Seg::LeafOld(i));
        v.push(Seg::LeafMid(i));
        for p in [Part::Bulk, Part::L30, Part::LastA, Part::LastB] {
            v.push(Seg::Pair(PathId::Mid(i), p));
        }
        v.push(Seg::LeafNew(i));
        for p in [Part::Bulk, Part::L30, Part::LastA, Part::LastB] {
            v.push(Seg::Pair(PathId::New(i), p));
        }
    }
    for j in 0..APPENDS {
        for p in [Part::Bulk, Part::L30, Part::LastA, Part::LastB] {
            v.push(Seg::Pair(PathId::C(j), p));
        }
    }
    v.push(Seg::RegLeaf);
    for p in [Part::Bulk, Part::LastA, Part::LastB] {
        v.push(Seg::Pair(PathId::R, p));
    }
    debug_assert!(v.iter().enumerate().all(|(i, s)| s.idx() == i));
    v
}

/// Perms per slot.
pub(crate) const SLOT_PERMS: usize = 560;

/// Lab #785 F5-4d: the SD bump moves no height — `560·24·k` for k = 4, 8,
/// 16 rounds to the same powers of two as before.
const _: () = assert!((4 * SLOT_PERMS * NUM_ROUNDS).next_power_of_two() == 1 << 16);
const _: () = assert!((8 * SLOT_PERMS * NUM_ROUNDS).next_power_of_two() == 1 << 17);
const _: () = assert!((16 * SLOT_PERMS * NUM_ROUNDS).next_power_of_two() == 1 << 18);

/// The first perm of segment `seg` within its slot.
pub(crate) fn seg_start(seg: Seg) -> usize {
    slot_program().iter().take(seg.idx()).map(|s| s.len()).sum()
}

/// The three shapes in tag-column order.
pub(crate) const TAGS: [L2ShapeTag; 3] = [L2ShapeTag::S, L2ShapeTag::P, L2ShapeTag::R];

/// A shape's public-value count.
pub(crate) fn pv_len(tag: L2ShapeTag) -> usize {
    match tag {
        L2ShapeTag::S => qlab_air::l2::PV_LEN,
        L2ShapeTag::P => qlab_air::l2p::PV_LEN,
        L2ShapeTag::R => qlab_air::l2r::PV_LEN,
    }
}

/// Whether SD block `b` is the last for `tag`.
fn sd_final(b: usize, tag: L2ShapeTag) -> bool {
    b + 1 == sd_perms(pv_len(tag))
}

/// The surface registers and where each shape's PV vector holds them: `(tag,
/// PV offset)` per shape that carries the field (16 chunks each; `ASSET` one
/// word).
/// `(register column, chunks, [(tag index, PV offset)])`.
type Capture = (usize, usize, Vec<(usize, usize)>);

fn captures() -> Vec<Capture> {
    use qlab_air::{l2, l2p, l2r};
    let (s, p, r) = (0, 1, 2);
    vec![
        (NF_OFF, 16, vec![(s, l2::PV_NF1), (p, l2::PV_NF1), (r, l2r::PV_NF)]),
        (NF_OFF + 16, 16, vec![(s, l2::PV_NF2), (p, l2::PV_NF2)]),
        (NF_OFF + 32, 16, vec![(s, l2::PV_NF3), (p, l2p::PV_NF3)]),
        (CM_OFF, 16, vec![(s, l2::PV_CM1), (p, l2::PV_CM1), (r, l2r::PV_CM)]),
        (CM_OFF + 16, 16, vec![(s, l2::PV_CM2), (p, l2::PV_CM2), (r, l2r::PV_CM_SEED)]),
        (RT_OFF, 16, vec![(s, l2::PV_REGROOT), (p, l2::PV_REGROOT), (r, l2r::PV_OLD_ROOT)]),
        (NRT_OFF, 16, vec![(r, l2r::PV_NEW_ROOT)]),
        (ASSET, 1, vec![(r, l2r::PV_ASSET)]),
    ]
}

/// PV `p`'s word position: `(block, lane, low limb)`.
fn pv_pos(p: usize) -> (usize, usize, usize) {
    let w = 2 + p;
    let (b, o) = (w / SD_BLOCK_WORDS, w % SD_BLOCK_WORDS);
    (b, SD_LANE_MSG + o / 2, 2 * (o % 2))
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/// The comparator gadget's cells (F3-2a), live only on the gate rows.
pub(crate) const CMP_OFF: usize = NUM_KECCAK_COLS;
/// The segment ring (one-hot).
pub(crate) const SEG_OFF: usize = CMP_OFF + LT_WIDTH;
/// Perms left in the segment after this one, its zero flag and inverse.
pub(crate) const REM: usize = SEG_OFF + NSEG_COLS;
pub(crate) const Z: usize = REM + 1;
pub(crate) const ZINV: usize = Z + 1;
/// Slots left after this one, its zero flag and inverse.
pub(crate) const LEFT: usize = ZINV + 1;
pub(crate) const ZL: usize = LEFT + 1;
pub(crate) const ZLINV: usize = ZL + 1;
/// Within a pair segment, 0 on A perms and 1 on B perms.
pub(crate) const SIDE: usize = ZLINV + 1;
/// The shape tag, one-hot `[S, P, R]`.
pub(crate) const TAG_OFF: usize = SIDE + 1;
/// Running state: `N` (16 limbs), `n_next`, `C`, `c_next`, `R`, `SD`.
pub(crate) const N_OFF: usize = TAG_OFF + 3;
pub(crate) const NN: usize = N_OFF + 16;
pub(crate) const C_OFF: usize = NN + 1;
pub(crate) const CN: usize = C_OFF + 16;
pub(crate) const R_OFF: usize = CN + 1;
pub(crate) const SD_OFF: usize = R_OFF + 16;
/// The slot's surface: three nullifiers, two commitments, the registry root
/// it reads (S/P) or replaces (R), the new root and the asset (R).
pub(crate) const NF_OFF: usize = SD_OFF + 16;
pub(crate) const CM_OFF: usize = NF_OFF + 16 * INSERTS;
pub(crate) const RT_OFF: usize = CM_OFF + 16 * APPENDS;
pub(crate) const NRT_OFF: usize = RT_OFF + 16;
pub(crate) const ASSET: usize = NRT_OFF + 16;
/// `LEAF_OLD`'s `hi`, held to `LEAF_NEW`.
pub(crate) const HI_OFF: usize = ASSET + 1;
/// The two paths' running nodes, the level's sibling and bit, the index
/// accumulator, `2^level`, and `bit · 2^level`.
pub(crate) const NA_OFF: usize = HI_OFF + 16;
pub(crate) const NB_OFF: usize = NA_OFF + 16;
pub(crate) const SIB_OFF: usize = NB_OFF + 16;
pub(crate) const BIT: usize = SIB_OFF + 16;
pub(crate) const ACC: usize = BIT + 1;
pub(crate) const PW: usize = ACC + 1;
pub(crate) const BP: usize = PW + 1;
/// `1 / asset` (R: the asset is nonzero).
pub(crate) const AINV: usize = BP + 1;
/// R transactions in earlier slots (at most one per leaf).
pub(crate) const RCNT: usize = AINV + 1;
/// Materialized per-perm flags, each defined from the ring and the tag.
pub(crate) const ON: usize = RCNT + 1;
pub(crate) const KPA: usize = ON + 1;
pub(crate) const KPB: usize = KPA + 1;
pub(crate) const KCMP: usize = KPB + 1;
pub(crate) const KNC: usize = KCMP + 1;
pub(crate) const KNI: usize = KNC + 1;
pub(crate) const KR: usize = KNI + 1;
pub(crate) const W: usize = KR + 1;
pub(crate) const SDC: usize = W + 1;
pub(crate) const SDF: usize = SDC + 1;
/// The leaf's width.
pub(crate) const LEAF_WIDTH: usize = SDF + 1;
/// Lab #785 F5-4d: one SD block more (3,224 → 3,225).
const _: () = assert!(LEAF_WIDTH == 3_225);
/// Per-perm columns start here (the ring onward).
const PLAN_BASE: usize = SEG_OFF;
const PLAN_WIDTH: usize = LEAF_WIDTH - PLAN_BASE;

// ---------------------------------------------------------------------------
// Public values
// ---------------------------------------------------------------------------

/// One side of the leaf's surface, as 16-bit chunks: `N` 16, `n_next` 2,
/// `C` 16, `c_next` 2, `R` 16, `SD` 16.
pub(crate) const PV_N: usize = 0;
pub(crate) const PV_NN: usize = 16;
pub(crate) const PV_C: usize = 18;
pub(crate) const PV_CN: usize = 34;
pub(crate) const PV_R: usize = 36;
pub(crate) const PV_SD: usize = 52;
pub(crate) const PV_SIDE: usize = 68;
/// In at 0, out at [`PV_SIDE`].
pub(crate) const LEAF_PV_LEN: usize = 2 * PV_SIDE;

/// The leaf's public values: `rin` then `rout`.
pub(crate) fn leaf_pvs(rin: &Roots, rout: &Roots) -> Vec<Val> {
    let mut v = Vec::with_capacity(LEAF_PV_LEN);
    for r in [rin, rout] {
        let d = |v: &mut Vec<Val>, x: &Digest| v.extend(limbs(x).iter().map(|l| Val::from_u32(*l)));
        let i = |v: &mut Vec<Val>, x: u64| v.extend([Val::from_u32((x & 0xffff) as u32), Val::from_u32((x >> 16) as u32)]);
        d(&mut v, &r.n);
        i(&mut v, r.n_next);
        d(&mut v, &r.c);
        i(&mut v, r.c_next);
        d(&mut v, &r.r);
        d(&mut v, &r.sd);
    }
    v
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

/// The leaf for `k` transactions.
pub(crate) struct LeafAir {
    pub k: usize,
    kc: KeccakIdx,
}

impl LeafAir {
    pub(crate) fn new(k: usize) -> Self {
        assert!(k >= 1);
        Self { k, kc: keccak_idx() }
    }
}

/// The constraint groups, in emission order; a violated constraint's index
/// maps back to its group ([`phase_of`]).
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
    "root_c",
    "root_r",
    "reg_read",
    "rleaf",
    "rcount",
];

impl BaseAir<Val> for LeafAir {
    fn width(&self) -> usize {
        LEAF_WIDTH
    }
    fn num_public_values(&self) -> usize {
        LEAF_PV_LEN
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for LeafAir {
    fn eval(&self, builder: &mut AB) {
        for p in 0..PHASES.len() {
            self.eval_phase(p, builder);
        }
    }
}

/// Constraint-index range of every phase, counted on the symbolic builder
/// (which numbers constraints exactly as the debug scanner does).
pub(crate) fn phase_ranges(air: &LeafAir) -> Vec<Range<usize>> {
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

/// The phase a constraint index belongs to.
pub(crate) fn phase_of(ranges: &[Range<usize>], constraint: usize) -> &'static str {
    PHASES[ranges.iter().position(|r| r.contains(&constraint)).expect("a constraint of the leaf")]
}

impl LeafAir {
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
        // A segment's activity as a linear form in the tag.
        let act = |s: Seg| (0..3).filter(|t| s.active(TAGS[*t])).fold(AB::Expr::ZERO, |a, t| a + tag(t));
        let fin = c(k.fin);
        let step0 = c(k.step0);
        let konst = |v: u32| AB::Expr::from(Val::from_u32(v));
        let one = AB::Expr::ONE;
        let prog = slot_program();
        let all_last_a: Vec<Seg> = prog.iter().copied().filter(|s| matches!(s, Seg::Pair(_, Part::LastA))).collect();
        let all_last_b: Vec<Seg> = prog.iter().copied().filter(|s| matches!(s, Seg::Pair(_, Part::LastB))).collect();
        let leaf_old: Vec<Seg> = (0..INSERTS).map(Seg::LeafOld).collect();
        let leaf_mid: Vec<Seg> = (0..INSERTS).map(Seg::LeafMid).collect();
        let leaf_new: Vec<Seg> = (0..INSERTS).map(Seg::LeafNew).collect();
        let ka = || c(KPA) + segs(&all_last_a);
        let kb = || c(KPB) + segs(&all_last_b);
        let to_c0 = Seg::Pair(PathId::New(INSERTS - 1), Part::LastB);
        let to_c1 = Seg::Pair(PathId::C(0), Part::LastB);
        let r_last = Seg::Pair(PathId::R, Part::LastB);
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let radix = Val::from_u32(1 << 16);

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
                builder.assert_zero(c(W) - c(Z) * c(SEG_OFF + LAST_SEG));
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
                for i in 1..NSEG {
                    t.assert_zero(
                        fin.clone() * (n(SEG_OFF + i) - nz.clone() * c(SEG_OFF + i) - z.clone() * c(SEG_OFF + i - 1)),
                    );
                }
                t.assert_zero(
                    fin.clone() * (n(SEG_OFF) - nz.clone() * c(SEG_OFF) - c(W) * (one.clone() - c(ZL))),
                );
                t.assert_zero(fin.clone() * (n(SEG_OFF + NSEG) - c(SEG_OFF + NSEG) - c(W) * c(ZL)));
                let next_len = (0..NSEG).fold(AB::Expr::ZERO, |a, i| {
                    let succ = prog[(i + 1) % NSEG];
                    a + c(SEG_OFF + i) * konst(succ.len() as u32 - 1)
                });
                t.assert_zero(fin.clone() * (n(REM) - nz * (c(REM) - one.clone()) - z * next_len));
                t.assert_zero(n(LEFT) - c(LEFT) + fin.clone() * c(W));
                t.assert_zero(n(SIDE) - c(SIDE) - fin * (c(KPA) - c(SIDE)));
            }
            "first" => {
                let mut f = builder.when_first_row();
                f.assert_one(c(SEG_OFF));
                f.assert_zero(c(REM));
                f.assert_zero(c(LEFT) - konst(self.k as u32 - 1));
                f.assert_zero(c(RCNT));
                f.assert_zero(c(SIDE));
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD)] {
                    for j in 0..16 {
                        f.assert_zero(c(col + j) - pvs[at + j].clone());
                    }
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN)] {
                    f.assert_zero(c(col) - pvs[at].clone() - pvs[at + 1].clone() * radix);
                }
            }
            "last" => {
                let mut l = builder.when_last_row();
                l.assert_one(c(SEG_OFF + NSEG));
                for (col, at) in [(N_OFF, PV_N), (C_OFF, PV_C), (R_OFF, PV_R), (SD_OFF, PV_SD)] {
                    for j in 0..16 {
                        l.assert_zero(c(col + j) - pvs[PV_SIDE + at + j].clone());
                    }
                }
                for (col, at) in [(NN, PV_NN), (CN, PV_CN)] {
                    l.assert_zero(c(col) - pvs[PV_SIDE + at].clone() - pvs[PV_SIDE + at + 1].clone() * radix);
                }
            }
            "tag" => {
                for t in 0..3 {
                    builder.assert_bool(cur[TAG_OFF + t]);
                }
                builder.assert_one(tag(0) + tag(1) + tag(2));
                let free = fin.clone() * c(W);
                let mut t = builder.when_transition();
                for i in 0..3 {
                    t.assert_zero((one.clone() - free.clone()) * (n(TAG_OFF + i) - c(TAG_OFF + i)));
                }
            }
            "flags" => {
                let on = prog.iter().fold(AB::Expr::ZERO, |a, s| a + seg(*s) * act(*s));
                builder.assert_zero(c(ON) - on);
                let bulk = prog.iter().filter(|s| s.is_pair_bulk()).fold(AB::Expr::ZERO, |a, s| a + seg(*s));
                builder.assert_zero(c(KPA) - bulk.clone() * (one.clone() - c(SIDE)));
                builder.assert_zero(c(KPB) - bulk * c(SIDE));
                let cmp = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| {
                    a + seg(Seg::LeafMid(i)) * act(Seg::LeafMid(i)) + seg(Seg::LeafNew(i)) * act(Seg::LeafNew(i))
                });
                builder.assert_zero(c(KCMP) - cmp);
                let nc = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| {
                    let (m, w) = (Seg::Pair(PathId::Mid(i), Part::LastB), Seg::Pair(PathId::New(i), Part::LastB));
                    a + seg(m) * act(m) + seg(w) * act(w)
                });
                builder.assert_zero(c(KNC) - nc);
                let ni = (0..INSERTS).fold(AB::Expr::ZERO, |a, i| {
                    let w = Seg::Pair(PathId::New(i), Part::LastB);
                    a + seg(w) * act(w)
                });
                builder.assert_zero(c(KNI) - ni);
                builder.assert_zero(c(KR) - seg(r_last) * tag(2));
                let sdc = (0..SD_BLOCKS - 1).fold(AB::Expr::ZERO, |a, b| a + seg(Seg::Sd(b)) * act(Seg::Sd(b + 1)));
                builder.assert_zero(c(SDC) - sdc);
                let sdf = (0..SD_BLOCKS).fold(AB::Expr::ZERO, |a, b| {
                    let f = (0..3).filter(|t| sd_final(b, TAGS[*t])).fold(AB::Expr::ZERO, |x, t| x + tag(t));
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
                            let sum = (0..3).fold(AB::Expr::ZERO, |a, t| match e[t] {
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
                for col in NF_OFF..=ASSET {
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
                for (kk, node) in [(ka(), NA_OFF), (kb(), NB_OFF)] {
                    for j in 0..16 {
                        let (l, m) = (j / 4, j % 4);
                        let (x, s) = (c(node + j), c(SIB_OFF + j));
                        let left = x.clone() + c(BIT) * (s.clone() - x.clone());
                        let right = s.clone() + c(BIT) * (x - s);
                        builder.assert_zero(kk.clone() * (pre(l, m) - left));
                        builder.assert_zero(kk.clone() * (pre(4 + l, m) - right));
                    }
                }
                let kn = ka() + kb();
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
                let fao = ka() + segs(&leaf_old);
                let faz = segs(&leaf_new) + seg(to_c0) + seg(to_c1);
                let free = seg(Seg::RegLeaf);
                let fbo = kb() - seg(to_c0) - seg(to_c1) + segs(&leaf_mid) + segs(&leaf_new) + seg(Seg::RegLeaf);
                let hold_ab = one.clone() - fin.clone() + fin.clone() * ka();
                let mut t = builder.when_transition();
                for j in 0..16 {
                    let (l, m) = (j / 4, j % 4);
                    let (a, na) = (c(NA_OFF + j), n(NA_OFF + j));
                    t.assert_zero(
                        na.clone() - a.clone()
                            - fin.clone() * (fao.clone() * (out(l, m) - a.clone()) - faz.clone() * a.clone() + free.clone() * (na - a)),
                    );
                    let (b, nb) = (c(NB_OFF + j), n(NB_OFF + j));
                    t.assert_zero(
                        nb - b.clone()
                            - fin.clone()
                                * (fbo.clone() * (out(l, m) - b.clone())
                                    + seg(to_c0) * (c(CM_OFF + j) - b.clone())
                                    + seg(to_c1) * (c(CM_OFF + 16 + j) - b)),
                    );
                    t.assert_zero(hold_ab.clone() * (n(SIB_OFF + j) - c(SIB_OFF + j)));
                }
                t.assert_zero(hold_ab * (n(BIT) - c(BIT)));
            }
            "bit_cap" => {
                let capped = prog
                    .iter()
                    .filter(|s| matches!(s, Seg::Pair(p, Part::L30 | Part::LastA | Part::LastB) if *p != PathId::R))
                    .fold(AB::Expr::ZERO, |a, s| a + seg(*s));
                builder.assert_zero(capped * c(BIT));
            }
            "index" => {
                let fi = segs(&leaf_mid) + segs(&leaf_new) + seg(to_c0) + seg(to_c1) + seg(Seg::RegLeaf);
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
            "root_c" => {
                let kc = segs(&[Seg::Pair(PathId::C(0), Part::LastB), Seg::Pair(PathId::C(1), Part::LastB)]);
                for j in 0..16 {
                    builder.assert_zero(kc.clone() * (c(NA_OFF + j) - c(C_OFF + j)));
                }
                builder.assert_zero(kc.clone() * (c(ACC) + c(BP) - c(CN)));
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(C_OFF + j) - c(C_OFF + j) - fin.clone() * kc.clone() * (out(j / 4, j % 4) - c(C_OFF + j)));
                }
                t.assert_zero(n(CN) - c(CN) - fin * kc);
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
                    builder.assert_zero(seg(r_last) * (c(RT_OFF + j) - c(R_OFF + j)));
                }
            }
            "rleaf" => {
                let g = seg(Seg::RegLeaf) * tag(2);
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
                builder.when_transition().assert_zero(n(RCNT) - c(RCNT) - fin * c(W) * tag(2));
            }
            other => unreachable!("phase {other}"),
        }
    }
}

/// What SD block `b`'s preimage limb `(lane, m)` must be, per shape (`None`
/// = message data or the chaining value, bound elsewhere).
pub(crate) fn sd_expect(b: usize, lane: usize, m: usize) -> [Option<u32>; 3] {
    let dom = sd_domain_lanes();
    core::array::from_fn(|t| {
        let tag = TAGS[t];
        let nb = sd_perms(pv_len(tag));
        if b >= nb {
            return Some(0);
        }
        match lane {
            0..=3 => None,
            4..=16 => {
                let w = SD_BLOCK_WORDS * b + 2 * (lane - SD_LANE_MSG) + m / 2;
                let low = m.is_multiple_of(2);
                match w {
                    0 => Some(if low { u32::from(tag.byte()) } else { 0 }),
                    1 => Some(if low { pv_len(tag) as u32 } else { 0 }),
                    w if w < 2 + pv_len(tag) => None,
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

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// One perm of the plan: its Keccak-f input and its per-perm columns
/// (`[PLAN_BASE, LEAF_WIDTH)`).
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

/// The leaf's plan: every program perm, then the `PAD` perm repeated.
#[derive(Clone)]
pub(crate) struct Plan {
    pub perms: Vec<PermPlan>,
    pub pad: PermPlan,
}

/// The perm index of segment `seg`'s `i`-th perm in slot `slot`.
pub(crate) fn perm_at(slot: usize, seg: Seg, i: usize) -> usize {
    SLOT_PERMS * slot + seg_start(seg) + i
}

/// The row of a perm's round `r` (0 = step 0, 23 = its last row).
pub(crate) fn row_of(perm: usize, r: usize) -> usize {
    NUM_ROUNDS * perm + r
}

/// The registers the machine threads, native-typed.
#[derive(Clone)]
struct Regs {
    n: Digest,
    nn: u64,
    c: Digest,
    cn: u64,
    r: Digest,
    sd: Digest,
    nf: [Digest; INSERTS],
    cm: [Digest; APPENDS],
    rt: Digest,
    nrt: Digest,
    asset: u64,
    hi: Digest,
    na: Digest,
    nb: Digest,
    sib: Digest,
    bit: bool,
    acc: Val,
    pw: Val,
    rcnt: u64,
    tag: L2ShapeTag,
    left: i64,
}

fn put_digest(cols: &mut [Val], at: usize, d: &Digest) {
    for (j, l) in limbs(d).iter().enumerate() {
        cols[at - PLAN_BASE + j] = Val::from_u32(*l);
    }
}

/// Build the plan: the machine the AIR constrains, run on the witness
/// **without validating it** — a malicious witness yields the trace a
/// prover would submit, refused where the AIR binds it.
pub(crate) fn build_plan(rin: &Roots, txs: &[TxSurface], wits: &[TxWitness]) -> Plan {
    use qlab_air::l2r;
    let k = txs.len();
    assert!(k >= 1 && wits.len() == k);
    let prog = slot_program();
    let mut g = Regs {
        n: rin.n,
        nn: rin.n_next,
        c: rin.c,
        cn: rin.c_next,
        r: rin.r,
        sd: rin.sd,
        nf: [EMPTY; INSERTS],
        cm: [EMPTY; APPENDS],
        rt: EMPTY,
        nrt: EMPTY,
        asset: 0,
        hi: EMPTY,
        na: EMPTY,
        nb: EMPTY,
        sib: EMPTY,
        bit: false,
        acc: Val::ZERO,
        pw: Val::ONE,
        rcnt: 0,
        tag: txs[0].tag,
        left: k as i64 - 1,
    };
    let mut perms = Vec::with_capacity(k * SLOT_PERMS);
    for (tx, w) in txs.iter().zip(wits) {
        // The slot's surface registers (free at the slot boundary).
        g.tag = tx.tag;
        let r = tx.tag == L2ShapeTag::R;
        let pvs = &tx.pvs;
        g.nf = [EMPTY; INSERTS];
        g.cm = [EMPTY; APPENDS];
        g.nrt = EMPTY;
        g.asset = 0;
        if r {
            g.nf[0] = pv_digest(pvs, l2r::PV_NF);
            g.cm = [pv_digest(pvs, l2r::PV_CM), pv_digest(pvs, l2r::PV_CM_SEED)];
            g.rt = pv_digest(pvs, l2r::PV_OLD_ROOT);
            g.nrt = pv_digest(pvs, l2r::PV_NEW_ROOT);
            g.asset = u64::from(pvs.get(l2r::PV_ASSET).copied().unwrap_or(0) & 0xffff);
        } else {
            let nf3 = if tx.tag == L2ShapeTag::S { qlab_air::l2::PV_NF3 } else { qlab_air::l2p::PV_NF3 };
            g.nf = [pv_digest(pvs, qlab_air::l2::PV_NF1), pv_digest(pvs, qlab_air::l2::PV_NF2), pv_digest(pvs, nf3)];
            g.cm = [pv_digest(pvs, qlab_air::l2::PV_CM1), pv_digest(pvs, qlab_air::l2::PV_CM2)];
            g.rt = pv_digest(pvs, qlab_air::l2::PV_REGROOT);
        }
        let (blocks, _) = sd_chain(&g.sd, tx.tag, pvs);
        for s in &prog {
            for i in 0..s.len() {
                let side = if s.is_pair_bulk() { i % 2 } else { 0 };
                // Registers free on entry to this perm.
                let (level, path_a) = pair_level(*s, i);
                if let Some(lvl) = level {
                    if path_a {
                        let (sib, bit) = path_at(*s, w, lvl);
                        g.sib = sib;
                        g.bit = bit;
                    }
                }
                let pre = perm_input(*s, i, &g, w, &blocks, &perms);
                if let Seg::LeafOld(_) = s {
                    g.hi = pre[4..8].try_into().expect("four lanes");
                }
                let rem = s.len() - 1 - i;
                perms.push(PermPlan { pre, cols: snapshot(*s, rem, side, &g) });
                let out = out4(&pre);
                // The perm's last-row transition.
                step(*s, side, out, &mut g, w);
            }
        }
    }
    let pad = PermPlan { pre: [0; 25], cols: snapshot(Seg::Pad, 0, 0, &g) };
    Plan { perms, pad }
}

/// For a pair segment's `i`-th perm: its level, and whether it is the A perm.
fn pair_level(s: Seg, i: usize) -> (Option<usize>, bool) {
    match s {
        Seg::Pair(_, Part::Bulk) => (Some(i / 2), i.is_multiple_of(2)),
        Seg::Pair(_, Part::L30) => (Some(30 + i / 2), i.is_multiple_of(2)),
        Seg::Pair(p, Part::LastA) => (Some(p.depth() - 1), true),
        Seg::Pair(p, Part::LastB) => (Some(p.depth() - 1), false),
        _ => (None, false),
    }
}

/// The sibling and bit at `lvl` of the path segment `s` walks (zeros where
/// the witness has none: an inactive segment).
fn path_at(s: Seg, w: &TxWitness, lvl: usize) -> (Digest, bool) {
    let Seg::Pair(p, _) = s else { unreachable!() };
    let mw = match p {
        PathId::Mid(i) => w.inserts.get(i).map(|x| (x.low_path.siblings[lvl], x.low_path.path_bits[lvl])),
        PathId::New(i) => w.inserts.get(i).map(|x| (x.new_path.siblings[lvl], x.new_path.path_bits[lvl])),
        PathId::C(j) => w.appends.get(j).map(|x| (x.path.siblings[lvl], x.path.path_bits[lvl])),
        PathId::R => w.write.as_ref().map(|x| (x.path.siblings[lvl], x.path.path_bits[lvl])),
    };
    mw.unwrap_or((EMPTY, false))
}

/// The perm's Keccak-f input.
fn perm_input(s: Seg, i: usize, g: &Regs, w: &TxWitness, blocks: &[[u64; 25]], perms: &[PermPlan]) -> [u64; 25] {
    let ins = |i: usize| w.inserts.get(i).filter(|_| s.active(g.tag));
    match s {
        Seg::Sd(b) => {
            if s.active(g.tag) {
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
        Seg::RegLeaf => match (&w.write, g.tag) {
            (Some(rw), L2ShapeTag::R) => rw.leaf.state(),
            _ => [0; 25],
        },
        Seg::Pad => [0; 25],
    }
}

/// The per-perm columns while the perm runs (registers before its last-row update).
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
    put_digest(&mut cols, HI_OFF, &g.hi);
    put_digest(&mut cols, NA_OFF, &g.na);
    put_digest(&mut cols, NB_OFF, &g.nb);
    put_digest(&mut cols, SIB_OFF, &g.sib);
    put(&mut cols, BIT, Val::from_bool(g.bit));
    put(&mut cols, ACC, g.acc);
    put(&mut cols, PW, g.pw);
    put(&mut cols, BP, if g.bit { g.pw } else { Val::ZERO });
    put(&mut cols, RCNT, Val::from_u32(g.rcnt as u32));
    // The flags, as the AIR defines them.
    let on = s.active(g.tag);
    let r = g.tag == L2ShapeTag::R;
    put(&mut cols, ON, Val::from_bool(on));
    put(&mut cols, KPA, Val::from_bool(s.is_pair_bulk() && side == 0));
    put(&mut cols, KPB, Val::from_bool(s.is_pair_bulk() && side == 1));
    put(&mut cols, KCMP, Val::from_bool(on && matches!(s, Seg::LeafMid(_) | Seg::LeafNew(_))));
    put(&mut cols, KNC, Val::from_bool(on && matches!(s, Seg::Pair(PathId::Mid(_) | PathId::New(_), Part::LastB))));
    put(&mut cols, KNI, Val::from_bool(on && matches!(s, Seg::Pair(PathId::New(_), Part::LastB))));
    put(&mut cols, KR, Val::from_bool(r && s == Seg::Pair(PathId::R, Part::LastB)));
    put(&mut cols, W, Val::from_bool(rem == 0 && s.idx() == LAST_SEG));
    let sdc = matches!(s, Seg::Sd(b) if b + 1 < SD_BLOCKS && Seg::Sd(b + 1).active(g.tag));
    put(&mut cols, SDC, Val::from_bool(sdc));
    put(&mut cols, SDF, Val::from_bool(matches!(s, Seg::Sd(b) if sd_final(b, g.tag))));
    cols
}

/// The perm's last-row transition: what the AIR's update constraints write.
fn step(s: Seg, side: usize, out: Digest, g: &mut Regs, w: &TxWitness) {
    let on = s.active(g.tag);
    let to_c0 = Seg::Pair(PathId::New(INSERTS - 1), Part::LastB);
    let to_c1 = Seg::Pair(PathId::C(0), Part::LastB);
    match s {
        Seg::Sd(b) => {
            if sd_final(b, g.tag) {
                g.sd = out;
            }
        }
        Seg::LeafOld(_) => g.na = out,
        Seg::LeafMid(_) => {
            g.nb = out;
            g.acc = Val::ZERO;
            g.pw = Val::ONE;
        }
        Seg::LeafNew(_) => {
            g.na = EMPTY;
            g.nb = out;
            g.acc = Val::ZERO;
            g.pw = Val::ONE;
        }
        Seg::Pair(p, part) => {
            let a = match part {
                Part::Bulk | Part::L30 => side == 0,
                Part::LastA => true,
                Part::LastB => false,
            };
            if a {
                g.na = out;
            } else if s != to_c0 && s != to_c1 {
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
                    PathId::Mid(_) if on => g.n = out,
                    PathId::New(_) if on => {
                        g.n = out;
                        g.nn += 1;
                    }
                    PathId::C(_) => {
                        g.c = out;
                        g.cn += 1;
                    }
                    PathId::R if g.tag == L2ShapeTag::R => g.r = out,
                    _ => {}
                }
                if s == to_c0 {
                    g.na = EMPTY;
                    g.nb = g.cm[0];
                    g.acc = Val::ZERO;
                    g.pw = Val::ONE;
                }
                if s == to_c1 {
                    g.na = EMPTY;
                    g.nb = g.cm[1];
                    g.acc = Val::ZERO;
                    g.pw = Val::ONE;
                }
                if p == PathId::R {
                    // The slot boundary.
                    g.rcnt += u64::from(g.tag == L2ShapeTag::R);
                    g.left -= 1;
                }
            }
        }
        Seg::RegLeaf => {
            g.nb = out;
            g.na = match (&w.write, g.tag) {
                (Some(rw), L2ShapeTag::R) => rw.old_digest,
                _ => EMPTY,
            };
            g.acc = Val::ZERO;
            g.pw = Val::ONE;
        }
        Seg::Pad => {}
    }
}

/// Render the plan: the Keccak lane, the comparator on its gate rows, the
/// per-perm columns on every row of their perm.
pub(crate) fn render(plan: &Plan) -> RowMajorMatrix<Val> {
    let inputs: Vec<[u64; 25]> = plan.perms.iter().map(|p| p.pre).collect();
    let keccak = generate_trace_rows::<Val>(inputs, 0);
    let height = keccak.values.len() / NUM_KECCAK_COLS;
    let mut values = Val::zero_vec(height * LEAF_WIDTH);
    for (r, row) in values.chunks_exact_mut(LEAF_WIDTH).enumerate() {
        row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
        let p = plan.perms.get(r / NUM_ROUNDS).unwrap_or(&plan.pad);
        row[PLAN_BASE..].copy_from_slice(&p.cols);
        if r % NUM_ROUNDS == 0 && p.get(KCMP) == Val::ONE {
            let (x, y): (Digest, Digest) = (p.pre[..4].try_into().expect("four lanes"), p.pre[4..8].try_into().expect("four lanes"));
            let (x, y) = (limbs(&x), limbs(&y));
            cmp::fill(&mut row[CMP_OFF..CMP_OFF + LT_WIDTH], &cmp::lt_raw(&x, &y));
        }
    }
    RowMajorMatrix::new(values, LEAF_WIDTH)
}

/// The leaf's height for `k` transactions.
pub(crate) fn leaf_height(k: usize) -> usize {
    (k * SLOT_PERMS * NUM_ROUNDS).next_power_of_two()
}

/// Whether `INDEX_CAP` is what the bit cap enforces (levels 30, 31 zero).
const _: () = assert!(INDEX_CAP == 1 << 30);

// ---------------------------------------------------------------------------
// The checker: p3's `check_constraints` row loop, reporting where
// ---------------------------------------------------------------------------

/// The constraints violated on `row` (p3-air 0.6.1's debug builder, exactly
/// as `check_constraints` evaluates a row).
pub(crate) fn failures_at(air: &LeafAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize) -> Vec<usize> {
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

/// The phases violated on `row`, deduplicated, in emission order.
pub(crate) fn phases_at(air: &LeafAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize, ranges: &[Range<usize>]) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = failures_at(air, trace, pvs, row).into_iter().map(|c| phase_of(ranges, c)).collect();
    v.dedup();
    v
}

/// The **lowest** violated row and its phases, or `None` when every row
/// holds (every row evaluated, in parallel).
pub(crate) fn first_violation(air: &LeafAir, trace: &RowMajorMatrix<Val>, pvs: &[Val]) -> Option<(usize, Vec<&'static str>)> {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use p3_maybe_rayon::prelude::*;
    use p3_matrix::Matrix;
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
