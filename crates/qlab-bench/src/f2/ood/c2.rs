//! F2b composition, slice C2 (issue #750, "two proofs per leaf"): F2b-2b-ii's
//! input openings and F2b-2b-iii's FRI query phase as ONE AIR on ONE
//! overwrite-mode Keccak lane (L4), one segment per query, with levers L2
//! (incremental fri_alpha powers) and L3 (the reduced opening and the index
//! bits handed from the opening part to the fold part as registers).
//! Scanned row by row by its tests (toy leaf, two-query S3); built at full
//! size for all queries of a real leaf, then scanned or proved under a
//! non-hiding outer config, by F2b-4's `qlab-bench f2wrap` ([`honest`]).
//!
//! **Segment.** Per covered query: the input-batch leaf sponges and Merkle
//! paths exactly as `open.rs` lays them out (randomizer, trace, quotient),
//! immediately followed by the commit-phase rounds exactly as `fold.rs` lays
//! them out (leaf, path, per round), then the next query. At S3 that is
//! 82 + 44 perms per query; 43 queries fill 130,032 of 2^17 rows.
//!
//! **Scheduling from the main trace** (as C1 does, no periodic column at
//! all): Keccak's own period-24 `step_flags` give each perm's step-0 and last
//! rows; a one-hot POSITION ring (one main column per segment position, 1 on
//! all 24 rows of the perm at that position) advances on each perm's last row
//! and wraps to position 0 at a segment end unless the segment was the last;
//! a one-hot QUERY ring (one column per covered query) advances at each
//! segment end. Both are fully determined by the Keccak flags. A binding
//! gated by a position cell holds on all 24 rows of that perm, so the prover
//! replicates the perm's message bits and canonicity witnesses there (the
//! replicated rows include step 0, where `absorb` ties the bits to the
//! permutation input). Bindings that compare a perm's output with the next
//! perm's input, and the cap checks, need the last row alone: their gates
//! (last-row flag × position cell) are materialized cells, one per index bit
//! a path level reads and one per cap check, so the bindings stay degree 3.
//!
//! **Consuming C1's seam.** No z-value and no opened value appears here. The
//! public values ARE the seam (`seam::Seam`): every cap, ζ, fri_alpha, Az,
//! Bz, the betas, the final polynomial and the covered queries' indices.
//! ζ, fri_alpha, Az, Bz, the betas and the final polynomial are held cells
//! bound on row 0 (`seam_in`); the caps are read by the cap checks; the
//! indices pin the index bits through the query ring (`index`). The reduced
//! opening is ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x), with Ax, Bx
//! accumulated from the Merkle-authenticated row values in native
//! `open_input` order — the order C1 absorbed and weighted Az, Bz in, read
//! from the same `seam::open_order` list (`Layout::new` checks every block's
//! terms against it).
//!
//! **L2: incremental fri_alpha powers.** 2b-ii held one power per opened
//! term (5,912 columns at S3). Here: a held table α^1..α^34 (a block's 34
//! words carry at most 34 row values), α^w (w the trace width) and per row a
//! running power p = α^{k0}, k0 the term of the current input block's first
//! row value. The block's row values are consecutive terms (checked at
//! build), so blk = Σ_i α^i v_i uses the table, Ax += p·blk and, on trace
//! blocks, Bx += (p·α^w)·blk (the ζ·g_N term of trace column c is term
//! D + w + c). p is 1 on each segment's first block (`alpha_pow` anchor),
//! steps by α^{n} over a block of n row values (by α^{n}·α^w after the last
//! trace block, which skips the w ζ·g_N terms), holds across path perms, and
//! resets to 1 at the segment end. α^w is pinned where the trace blocks end:
//! p·α^{n} = α^{D}·α^w on the last trace block.
//!
//! **L3: hand-off.** The index bits and ro are ONE set of register cells,
//! held over the whole segment (`handoff`): the same bit cells drive x, the
//! input paths, the cap one-hot, the commit-phase paths (bit S_{r+1} + t at
//! round r level t), the fold positions, s^-1 and the final x; the reduced
//! opening computed on the opening part (`reduce`, on the last input perm's
//! rows, where Ax and Bx are complete) is the value the fold chain starts
//! from (`select`, round 0). Nothing is duplicated between the parts.
//!
//! **Degree.** Every constraint has degree ≤ 3 (the honest tests check the
//! symbolic builder).
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, FriCfg, CAP_HEIGHT};

use super::fold;
use super::lane::{Lane, Phased, RATE_BITS, RATE_LANES, RATE_WORDS};
use super::open::{self, Word, QUOTIENT, RANDOM, TRACE};
use super::seam::{open_order, Open, Seam, SeamShape};
use super::{require, Dims, Result, Val, E};

/// Constraint groups, in evaluation order. A negative names the group(s)
/// its violation must land in, on named rows.
const PHASES: [&str; 32] = [
    "keccak",
    "bits",
    "absorb",
    "ring",
    "gate",
    "capacity",
    "bind_zero",
    "bind_carry",
    "bind_child",
    "cap",
    "canonical",
    "leaf_bind",
    "index",
    "cap_select",
    "x_point",
    "inverse",
    "alpha_pow",
    "blk",
    "accumulate",
    "reduce",
    "position",
    "select",
    "s_inv",
    "fold_pow",
    "fold",
    "final_x",
    "horner",
    "final",
    "seam_in",
    "hold",
    "handoff",
    "ctx_hold",
];

/// Extension limbs.
const D: usize = 4;
/// Rate words a compression's two children occupy (2 x 4 u64).
const CHILD_WORDS: usize = 16;
/// Held fri_alpha powers α^1..α^TAB: a block holds at most 34 row values.
const TAB: usize = RATE_WORDS;

/// One perm of a query segment: the opening part, then the fold part.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Step {
    In(open::Step),
    Fri(fold::Step),
}

/// An input leaf block's term bookkeeping, derived from `seam::open_order`.
#[derive(Clone, Debug)]
struct InBlock {
    /// Segment position of the block's perm.
    pos: usize,
    batch: usize,
    /// Term of the block's first row value: the running power is α^{k0}.
    k0: usize,
    /// (slot, i) of every row value: its term is k0 + i.
    rows: Vec<(usize, usize)>,
}

impl InBlock {
    fn n(&self) -> usize {
        self.rows.len()
    }
}

/// Static layout: shape constants, the covered query slots, nothing read
/// from a proof.
#[derive(Clone)]
struct Layout {
    /// 2b-ii's input-opening geometry and segment (its query count unused).
    ig: open::Layout,
    /// 2b-iii's query-phase geometry and segment.
    fg: fold::Layout,
    segment: Vec<Step>,
    /// Position of the last opening-part perm.
    open_last: usize,
    /// Covered query slots (ascending): a static property of the instance.
    slots: Vec<usize>,
    blocks: Vec<InBlock>,
    /// Index in `blocks` of the last trace block.
    last_trace: usize,
    /// k0 of the first trace block (= D).
    trace_k0: usize,
    /// (segment position, seam cap block) of every cap check.
    caps: Vec<(usize, usize)>,
    seam: SeamShape,
}

impl Layout {
    fn new(dims: Dims, chunks: usize, cfg: &FriCfg, slots: Vec<usize>) -> Result<Self> {
        require(!slots.is_empty(), "no covered query")?;
        require(
            slots.windows(2).all(|w| w[0] < w[1]) && slots.iter().all(|&s| s < cfg.num_queries),
            "covered slots must ascend inside the query count",
        )?;
        let ig = open::Layout::new(open::Geom::new(dims, chunks, cfg)?, 1);
        let fg = fold::Layout::new(fold::Geom::new(dims.log_height, cfg)?, 1);
        require(ig.geom.lde == fg.geom.lde, "one LDE height")?;
        let mut segment: Vec<Step> = ig.segment.iter().map(|&s| Step::In(s)).collect();
        let open_last = segment.len() - 1;
        segment.extend(fg.segment.iter().map(|&s| Step::Fri(s)));
        // L2's bookkeeping, from the shared term order and checked against
        // it: a block's row values are consecutive terms, a trace column's
        // ζ·g_N term is its ζ term + w, and blocks follow each other term
        // by term except across the w ζ·g_N terms after the trace.
        let order = open_order(dims.width, chunks);
        let term = |o: Open| -> Result<usize> {
            order
                .iter()
                .position(|&x| x == o)
                .ok_or_else(|| format!("{o:?} missing from the term order"))
        };
        let w = dims.width;
        let mut blocks = Vec::new();
        for (pos, step) in segment.iter().enumerate() {
            let Step::In(open::Step::Leaf(b, k)) = *step else {
                continue;
            };
            let words = &ig.leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)];
            let (mut rows, mut k0) = (Vec::new(), None);
            for (slot, &word) in words.iter().enumerate() {
                if let Word::Row(m, c) = word {
                    let open = match b {
                        RANDOM => Open::Random(c),
                        TRACE => Open::Local(c),
                        _ => Open::Quotient(m, c),
                    };
                    let kk = term(open)?;
                    let first = *k0.get_or_insert(kk);
                    require(
                        kk == first + rows.len(),
                        "a block's row values are not consecutive terms",
                    )?;
                    if b == TRACE {
                        require(
                            term(Open::Next(c))? == kk + w,
                            "a trace column's ζ·g_N term is not its ζ term + w",
                        )?;
                    }
                    rows.push((slot, rows.len()));
                }
            }
            let k0 = k0.ok_or("an input leaf block without row values")?;
            require(rows.len() <= TAB, "more row values than the power table")?;
            blocks.push(InBlock {
                pos,
                batch: b,
                k0,
                rows,
            });
        }
        require(
            blocks[0].pos == 0 && blocks[0].k0 == 0,
            "the segment opens on term 0",
        )?;
        let last_trace = blocks
            .iter()
            .rposition(|b| b.batch == TRACE)
            .ok_or("no trace block")?;
        for i in 0..blocks.len() - 1 {
            let jump = if i == last_trace { w } else { 0 };
            require(
                blocks[i + 1].k0 == blocks[i].k0 + blocks[i].n() + jump,
                "the power step does not follow the term order",
            )?;
        }
        let last = &blocks[blocks.len() - 1];
        require(last.k0 + last.n() == order.len(), "terms left unweighted")?;
        let trace_k0 = blocks.iter().find(|b| b.batch == TRACE).unwrap().k0;
        let lt = &blocks[last_trace];
        require(
            (1..=TAB).contains(&trace_k0) && lt.k0 + lt.n() == trace_k0 + w,
            "the α^w pin needs the trace terms to end at k0 + w",
        )?;
        let mut caps = Vec::new();
        for b in [RANDOM, TRACE, QUOTIENT] {
            let at = segment
                .iter()
                .position(|&s| s == Step::In(open::Step::Node(b, ig.geom.path - 1)))
                .unwrap();
            caps.push((at, open::Geom::cap_block(b)));
        }
        for r in 0..fg.geom.rounds() {
            let at = segment
                .iter()
                .position(|&s| s == Step::Fri(fold::Step::Node(r, fg.geom.path[r] - 1)))
                .unwrap();
            caps.push((at, 3 + r));
        }
        let seam = SeamShape {
            rounds: fg.geom.rounds(),
            final_len: fg.geom.final_len,
        };
        Ok(Self {
            ig,
            fg,
            segment,
            open_last,
            slots,
            blocks,
            last_trace,
            trace_k0,
            caps,
            seam,
        })
    }

    fn len(&self) -> usize {
        self.segment.len()
    }
    fn queries(&self) -> usize {
        self.slots.len()
    }
    fn perms(&self) -> usize {
        self.queries() * self.len()
    }
    fn lde(&self) -> usize {
        self.ig.geom.lde
    }
    /// Input path levels = index bits any path level reads (0..lde − 3).
    fn path_bits(&self) -> usize {
        self.ig.geom.path
    }
    #[cfg(test)]
    fn at(&self, step: Step) -> usize {
        self.segment.iter().position(|&s| s == step).unwrap()
    }
    /// The leaf words of the perm at `pos`, if it is a leaf block.
    fn leaf_words(&self, pos: usize) -> Option<&[Word]> {
        match self.segment[pos] {
            Step::In(open::Step::Leaf(b, k)) => {
                Some(&self.ig.leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)])
            }
            Step::Fri(fold::Step::Leaf(r, k)) => {
                Some(&self.fg.leaves[r][RATE_WORDS * k..RATE_WORDS * (k + 1)])
            }
            _ => None,
        }
    }
    fn is_node(&self, pos: usize) -> bool {
        self.leaf_words(pos).is_none()
    }
    /// A later block of a multi-block leaf: its capacity carries.
    fn is_interior(&self, pos: usize) -> bool {
        matches!(
            self.segment[pos],
            Step::In(open::Step::Leaf(_, k)) | Step::Fri(fold::Step::Leaf(_, k)) if k > 0
        )
    }
    /// Rate lanes of the leaf block at `pos` that carry the previous output.
    fn carry_lanes(&self, pos: usize) -> Vec<usize> {
        match self.leaf_words(pos) {
            Some(words) if self.is_interior(pos) => (0..RATE_LANES)
                .filter(|&ln| words[2 * ln] == Word::Carry)
                .collect(),
            _ => vec![],
        }
    }
    /// The index bit a path level at `pos` reads.
    fn reads_bit(&self, pos: usize) -> Option<usize> {
        match self.segment[pos] {
            Step::In(open::Step::Node(_, t)) => Some(t),
            Step::Fri(fold::Step::Node(r, t)) => Some(self.fg.geom.shift[r + 1] + t),
            _ => None,
        }
    }
    /// Index in `blocks` of the input leaf block at `pos`.
    fn block_at(&self, pos: usize) -> Option<usize> {
        self.blocks.iter().position(|b| b.pos == pos)
    }
    /// Positions whose successor in the segment satisfies `f` (the last
    /// position's successor is the next segment's first block: a fresh
    /// randomizer leaf, never interior, never a path level).
    fn before(&self, f: impl Fn(usize) -> bool) -> Vec<usize> {
        (0..self.len() - 1).filter(|&s| f(s + 1)).collect()
    }
    fn num_public_values(&self) -> usize {
        self.seam.len(self.queries())
    }
}

/// The values the circuit takes as given: the seam, held.
#[derive(Clone)]
struct Held {
    zeta: E,
    fri_alpha: E,
    az: E,
    bz: E,
    betas: Vec<E>,
    final_poly: Vec<E>,
}

/// A claim the outer prover assembles: per covered query the input and
/// commit-phase openings and the claimed index, the held seam values, and
/// everything derived from them. `settle` derives; tests edit before it
/// (forger's inputs, re-derived consistently) or after it (a poked value).
#[derive(Clone)]
struct Build {
    in_ops: Vec<open::Opening>,
    fri_ops: Vec<fold::QOpening>,
    index: Vec<usize>,
    /// Input-path child on the wrong side at (batch, level).
    flips: Vec<Option<(usize, usize)>>,
    knobs: Vec<fold::Knobs>,
    held: Held,
    /// Forgery knob: (query, block, factor) multiplies the running power of
    /// that input block and of every later block of the query.
    skew: Option<(usize, usize, E)>,
    // Derived.
    /// tab[i] = fri_alpha^i, i = 0..=TAB (tab[0] = 1 is a constant).
    tab: Vec<E>,
    aw: E,
    /// Per query, per input block: the running power p.
    powers: Vec<Vec<E>>,
    ab: Vec<(E, E)>,
    ictx: Vec<open::Ctx>,
    fctx: Vec<fold::Ctx>,
    in_walks: Vec<open::Walk>,
    fri_walks: Vec<fold::Walk>,
}

impl Build {
    fn honest(layout: &Layout, seam: &Seam, proof: &Proof<Config>) -> Result<Self> {
        require(
            seam.indices.iter().map(|&(s, _)| s).collect::<Vec<_>>() == layout.slots,
            "the seam carries the covered slots",
        )?;
        let in_ops = layout
            .slots
            .iter()
            .map(|&q| open::Opening::from_proof(proof, q, &layout.ig.geom))
            .collect::<Result<Vec<_>>>()?;
        let fri_ops = layout
            .slots
            .iter()
            .map(|&q| fold::QOpening::from_proof(proof, q, &layout.fg.geom))
            .collect::<Result<Vec<_>>>()?;
        let qn = layout.queries();
        let mut b = Self {
            in_ops,
            fri_ops,
            index: seam.indices.iter().map(|&(_, i)| i).collect(),
            flips: vec![None; qn],
            knobs: vec![fold::Knobs::honest(&layout.fg.geom); qn],
            held: Held {
                zeta: seam.zeta,
                fri_alpha: seam.fri_alpha,
                az: seam.az,
                bz: seam.bz,
                betas: seam.betas.clone(),
                final_poly: seam.final_poly.clone(),
            },
            skew: None,
            tab: vec![],
            aw: E::ZERO,
            powers: vec![],
            ab: vec![],
            ictx: vec![],
            fctx: vec![],
            in_walks: vec![],
            fri_walks: vec![],
        };
        b.settle(layout)?;
        Ok(b)
    }

    /// blk = Σ_i α^i · v_i over the block's row values (from its preimage).
    fn block_sum(block: &InBlock, pre: &[u64; 25], tab: &[E], rinv: Val) -> E {
        block.rows.iter().fold(E::ZERO, |acc, &(slot, i)| {
            let word = (pre[slot / 2] >> (32 * (slot % 2))) as u32;
            acc + tab[i] * (Val::from_u32(word) * rinv)
        })
    }

    /// Re-derive everything from the openings, claimed indices and the held
    /// seam values.
    fn settle(&mut self, layout: &Layout) -> Result<()> {
        let alpha = self.held.fri_alpha;
        self.tab = (0..=TAB).map(|i| alpha.exp_u64(i as u64)).collect();
        self.aw = alpha.exp_u64(layout.ig.geom.width as u64);
        let rinv = Val::from_u32(Val::ONE.to_unique_u32()).inverse();
        let open_held = open::Held {
            zeta: self.held.zeta,
            zvals: vec![],
            fri_alpha: alpha,
            apow: vec![],
            az: self.held.az,
            bz: self.held.bz,
            ro: vec![],
        };
        let fold_held = fold::Held {
            betas: self.held.betas.clone(),
            final_poly: self.held.final_poly.clone(),
        };
        (self.powers, self.ab, self.ictx, self.fctx) = (vec![], vec![], vec![], vec![]);
        (self.in_walks, self.fri_walks) = (vec![], vec![]);
        for q in 0..layout.queries() {
            let walk = open::Walk::new(&layout.ig, &self.in_ops[q], self.index[q], self.flips[q]);
            let mut powers = Vec::with_capacity(layout.blocks.len());
            let mut p = E::ONE;
            for (i, block) in layout.blocks.iter().enumerate() {
                powers.push(p);
                p *= self.tab[block.n()];
                if i == layout.last_trace {
                    p *= self.aw;
                }
            }
            if let Some((sq, from, factor)) = self.skew {
                if sq == q {
                    for x in &mut powers[from..] {
                        *x *= factor;
                    }
                }
            }
            let (mut ax, mut bx) = (E::ZERO, E::ZERO);
            for (block, &p) in layout.blocks.iter().zip(&powers) {
                let blk = Self::block_sum(block, &walk.perms[block.pos], &self.tab, rinv);
                ax += p * blk;
                if block.batch == TRACE {
                    bx += p * self.aw * blk;
                }
            }
            let ictx = open::Ctx::new(
                &layout.ig.geom,
                self.index[q],
                self.index[q],
                &open_held,
                (ax, bx),
            )?;
            let (fctx, fwalk) = fold::derive(
                &layout.fg,
                &self.fri_ops[q],
                self.index[q],
                ictx.ro,
                &fold_held,
                &self.knobs[q],
            )?;
            require(
                fctx.bits == ictx.bits && fctx.u == ictx.u && fctx.e == ictx.e,
                "one index, one set of bits",
            )?;
            self.powers.push(powers);
            self.ab.push((ax, bx));
            self.ictx.push(ictx);
            self.fctx.push(fctx);
            self.in_walks.push(walk);
            self.fri_walks.push(fwalk);
        }
        Ok(())
    }

    /// Re-derive query `q`'s fold part from its (edited) reduced opening:
    /// a forger whose fold chain starts from the forged ro.
    #[cfg(test)]
    fn refold(&mut self, layout: &Layout, q: usize) -> Result<()> {
        let fold_held = fold::Held {
            betas: self.held.betas.clone(),
            final_poly: self.held.final_poly.clone(),
        };
        let (fctx, fwalk) = fold::derive(
            &layout.fg,
            &self.fri_ops[q],
            self.index[q],
            self.ictx[q].ro,
            &fold_held,
            &self.knobs[q],
        )?;
        self.fctx[q] = fctx;
        self.fri_walks[q] = fwalk;
        Ok(())
    }
}

/// C2: one overwrite-mode Keccak lane, per query the input openings and the
/// reduced opening, then the commit-phase openings, folds and final check.
#[derive(Clone)]
pub(super) struct C2Air {
    layout: Layout,
    lane: Lane,
    height: usize,
    canon_col: usize,
    ring_col: usize,
    qring_col: usize,
    lvl_col: usize,
    capg_col: usize,
    // Query registers, held over the segment. The hand-off block first.
    bits_col: usize,
    ro_col: usize,
    handoff_end: usize,
    u_col: usize,
    e_col: usize,
    x_col: usize,
    inv_a_col: usize,
    inv_b_col: usize,
    group: Vec<usize>,
    pos: Vec<usize>,
    sinv: Vec<usize>,
    tpow: Vec<usize>,
    fr_col: usize,
    xf_col: usize,
    horner_col: usize,
    reg_end: usize,
    // Running cells (change within a segment).
    p_col: usize,
    pn_col: usize,
    pw_col: usize,
    blk_col: usize,
    ax_col: usize,
    bx_col: usize,
    // Held cells (constant over every row).
    held_col: usize,
    zeta_col: usize,
    tab_col: usize,
    aw_col: usize,
    az_col: usize,
    bz_col: usize,
    beta_col: usize,
    final_col: usize,
    width: usize,
    rinv: Val,
    /// (e_i * e_j) in basis limbs: extension multiplication as base terms.
    mul: [[[Val; D]; D]; D],
    x_factors: Vec<Val>,
    g_n: Val,
}

impl C2Air {
    fn new(layout: Layout, max_cells: usize) -> Result<Self> {
        let lane = Lane::new();
        let (lde, rounds) = (layout.lde(), layout.fg.geom.rounds());
        let fgeom = layout.fg.geom.clone();
        let mut at = lane.m_col + RATE_BITS;
        let mut take = |n: usize| {
            let s = at;
            at += n;
            s
        };
        // No S bits: the MMCS sponge overwrites, so M is the rate preimage.
        let canon_col = take(2 * RATE_WORDS);
        let ring_col = take(layout.len());
        let qring_col = take(layout.queries());
        let lvl_col = take(layout.path_bits());
        let capg_col = take(layout.caps.len());
        let bits_col = take(lde);
        let ro_col = take(D);
        let handoff_end = take(0);
        let u_col = take(4);
        let e_col = take(8);
        let x_col = take(lde);
        let inv_a_col = take(D);
        let inv_b_col = take(D);
        let (mut group, mut pos, mut sinv, mut tpow) = (vec![], vec![], vec![], vec![]);
        for r in 0..rounds {
            let n = fgeom.arity(r);
            group.push(take(D * n));
            pos.push(take(2 * n - 2));
            sinv.push(take(fgeom.folded[r]));
            tpow.push(take(D * (n - 1)));
        }
        let fr_col = take(D * rounds);
        let xf_col = take(fgeom.final_bits);
        let horner_col = take(D * fgeom.final_len);
        let reg_end = take(0);
        let p_col = take(D);
        let pn_col = take(D);
        let pw_col = take(D);
        let blk_col = take(D);
        let ax_col = take(D);
        let bx_col = take(D);
        let held_col = take(0);
        let zeta_col = take(D);
        let tab_col = take(D * TAB);
        let aw_col = take(D);
        let az_col = take(D);
        let bz_col = take(D);
        let beta_col = take(D * rounds);
        let final_col = take(D * fgeom.final_len);
        let width = take(0);
        let height = (layout.perms() * NUM_ROUNDS).next_power_of_two();
        let cells = height.checked_mul(width).ok_or("C2 allocation overflow")?;
        require(cells <= max_cells, "C2 exceeds materialization budget")?;
        let basis = |i: usize| <E as BasedVectorSpace<Val>>::ith_basis_element(i).unwrap();
        let mul = core::array::from_fn(|i| {
            core::array::from_fn(|j| {
                let p = basis(i) * basis(j);
                core::array::from_fn(|k| p.as_basis_coefficients_slice()[k])
            })
        });
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            x_factors: open::x_factors(&layout.ig.geom),
            g_n: layout.ig.geom.g_n,
            layout,
            lane,
            height,
            canon_col,
            ring_col,
            qring_col,
            lvl_col,
            capg_col,
            bits_col,
            ro_col,
            handoff_end,
            u_col,
            e_col,
            x_col,
            inv_a_col,
            inv_b_col,
            group,
            pos,
            sinv,
            tpow,
            fr_col,
            xf_col,
            horner_col,
            reg_end,
            p_col,
            pn_col,
            pw_col,
            blk_col,
            ax_col,
            bx_col,
            held_col,
            zeta_col,
            tab_col,
            aw_col,
            az_col,
            bz_col,
            beta_col,
            final_col,
            width,
            rinv: r.inverse(),
            mul,
        })
    }

    fn g_col(&self, r: usize, i: usize) -> usize {
        self.group[r] + D * i
    }
    /// Cell `j` of level `l` (1..=a) of round r's position one-hot.
    fn pos_col(&self, r: usize, l: usize, j: usize) -> usize {
        self.pos[r] + (1 << l) - 2 + j
    }
    fn top_col(&self, r: usize, j: usize) -> usize {
        self.pos_col(r, self.layout.fg.geom.arities[r], j)
    }
    /// u^k of round r, k >= 1.
    fn t_col(&self, r: usize, k: usize) -> usize {
        self.tpow[r] + D * (k - 1)
    }
    /// The value entering round r: ro for r = 0 (the hand-off), then folds.
    fn f_col(&self, r: usize) -> usize {
        if r == 0 {
            self.ro_col
        } else {
            self.fr_col + D * (r - 1)
        }
    }
    fn h_col(&self, k: usize) -> usize {
        self.horner_col + D * k
    }
    /// fri_alpha^i, i = 1..=TAB.
    fn tab(&self, i: usize) -> usize {
        self.tab_col + D * (i - 1)
    }
    fn beta(&self, r: usize) -> usize {
        self.beta_col + D * r
    }
    fn final_c(&self, c: usize) -> usize {
        self.final_col + D * c
    }
    #[cfg(test)]
    fn fri_rows(&self) -> usize {
        NUM_ROUNDS * (self.layout.open_last + 1)
    }

    /// One query's registers, laid out from `bits_col`.
    fn regs(&self, b: &Build, q: usize) -> Vec<Val> {
        let base = self.bits_col;
        let mut v = vec![Val::ZERO; self.reg_end - base];
        let mut put =
            |col: usize, xs: &[Val]| v[col - base..col - base + xs.len()].copy_from_slice(xs);
        let limbs = |x: &E| x.as_basis_coefficients_slice().to_vec();
        let (i, f) = (&b.ictx[q], &b.fctx[q]);
        put(self.bits_col, &i.bits);
        put(self.ro_col, &limbs(&i.ro));
        put(self.u_col, &i.u);
        put(self.e_col, &i.e);
        put(self.x_col, &i.xs);
        put(self.inv_a_col, &limbs(&i.inv_a));
        put(self.inv_b_col, &limbs(&i.inv_b));
        for r in 0..self.layout.fg.geom.rounds() {
            for (j, x) in f.groups[r].iter().enumerate() {
                put(self.g_col(r, j), &limbs(x));
            }
            put(self.pos[r], &f.pos[r]);
            put(self.sinv[r], &f.sinv[r]);
            for (k, x) in f.t[r].iter().enumerate() {
                put(self.t_col(r, k + 1), &limbs(x));
            }
        }
        for (r, x) in f.f.iter().enumerate().skip(1) {
            put(self.f_col(r), &limbs(x));
        }
        put(self.xf_col, &f.xf);
        for (k, x) in f.horner.iter().enumerate() {
            put(self.h_col(k), &limbs(x));
        }
        v
    }

    fn trace(&self, b: &Build) -> Result<RowMajorMatrix<Val>> {
        let l = &self.layout;
        let (h, w, len, qn) = (self.height, self.width, l.len(), l.queries());
        require(b.in_walks.len() == qn && b.fri_walks.len() == qn, "walks")?;
        let mut perms: Vec<[u64; 25]> = Vec::with_capacity(l.perms());
        for q in 0..qn {
            perms.extend(&b.in_walks[q].perms);
            perms.extend(&b.fri_walks[q].perms);
        }
        require(perms.len() == l.perms(), "walk perm count")?;
        let mut values = self.lane.trace(&perms, h, w)?;
        let mut held = vec![Val::ZERO; w - self.held_col];
        {
            let mut put = |col: usize, v: &E| {
                let at = col - self.held_col;
                held[at..at + D].copy_from_slice(v.as_basis_coefficients_slice());
            };
            put(self.zeta_col, &b.held.zeta);
            for i in 1..=TAB {
                put(self.tab(i), &b.tab[i]);
            }
            put(self.aw_col, &b.aw);
            put(self.az_col, &b.held.az);
            put(self.bz_col, &b.held.bz);
            for (r, x) in b.held.betas.iter().enumerate() {
                put(self.beta(r), x);
            }
            for (c, x) in b.held.final_poly.iter().enumerate() {
                put(self.final_c(c), x);
            }
        }
        let regs: Vec<Vec<Val>> = (0..qn).map(|q| self.regs(b, q)).collect();
        let lvl_before: Vec<Option<usize>> = (0..len)
            .map(|s| (s + 1 < len).then(|| l.reads_bit(s + 1)).flatten())
            .collect();
        let (mut carried, mut ax, mut bx) = (E::ONE, E::ZERO, E::ZERO);
        // The height is a power of two, not a multiple of 24: the last perm
        // is partial (8 rows at 2^11 and 2^13), and its rows must carry the
        // held, register and running cells like every other padding row.
        for perm in 0..h.div_ceil(NUM_ROUNDS) {
            let real = perm < perms.len();
            let (q, pos) = (perm / len, perm % len);
            let pre = if real { perms[perm] } else { [0; 25] };
            let block = if real { l.block_at(pos) } else { None };
            let p = block.map_or(carried, |i| b.powers[q][i]);
            let is_trace = block.is_some_and(|i| l.blocks[i].batch == TRACE);
            let pw = if is_trace { p * b.aw } else { E::ZERO };
            let blk = block.map_or(E::ZERO, |i| {
                Build::block_sum(&l.blocks[i], &pre, &b.tab, self.rinv)
            });
            let pn = match block {
                Some(i) if i == l.last_trace => pw * b.tab[l.blocks[i].n()],
                Some(i) => p * b.tab[l.blocks[i].n()],
                None if real && pos == len - 1 => E::ONE,
                None => p,
            };
            let words = if real { l.leaf_words(pos) } else { None };
            for round in 0..NUM_ROUNDS {
                let row = NUM_ROUNDS * perm + round;
                if row == h {
                    break;
                }
                let cells = &mut values[row * w..(row + 1) * w];
                let mut set = |col: usize, v: &E| {
                    cells[col..col + D].copy_from_slice(v.as_basis_coefficients_slice())
                };
                set(self.p_col, &p);
                set(self.pn_col, &pn);
                set(self.pw_col, &pw);
                set(self.blk_col, &blk);
                set(self.ax_col, &ax);
                set(self.bx_col, &bx);
                cells[self.held_col..].copy_from_slice(&held);
                cells[self.bits_col..self.reg_end].copy_from_slice(&regs[q.min(qn - 1)]);
                if real {
                    // Message bits and canonicity, replicated on all 24 rows.
                    for ln in 0..RATE_LANES {
                        for bit in 0..64 {
                            cells[self.lane.m_col + 64 * ln + bit] =
                                Val::from_u64((pre[ln] >> bit) & 1);
                        }
                    }
                    if let Some(words) = words {
                        for (slot, &word) in words.iter().enumerate() {
                            if matches!(word, Word::Row(..)) {
                                let v = (pre[slot / 2] >> (32 * (slot % 2))) as u32;
                                Lane::fill_canonical(cells, self.canon_col + 2 * slot, v);
                            }
                        }
                    }
                    cells[self.ring_col + pos] = Val::ONE;
                    cells[self.qring_col + q] = Val::ONE;
                    if round == NUM_ROUNDS - 1 {
                        if let Some(t) = lvl_before[pos] {
                            cells[self.lvl_col + t] = Val::ONE;
                        }
                        if let Some(c) = l.caps.iter().position(|&(at, _)| at == pos) {
                            cells[self.capg_col + c] = Val::ONE;
                        }
                    }
                }
                if round == 0 && block.is_some() {
                    ax += p * blk;
                    bx += pw * blk;
                }
                if real && round == NUM_ROUNDS - 1 && pos == len - 1 {
                    (ax, bx) = (E::ZERO, E::ZERO);
                }
            }
            carried = pn;
        }
        Ok(RowMajorMatrix::new(values, w))
    }

    /// Public values: the seam, with the covered slots' indices.
    fn public_values(&self, seam: &Seam) -> Result<Vec<Val>> {
        require(
            seam.indices.iter().map(|&(s, _)| s).collect::<Vec<_>>() == self.layout.slots,
            "the seam carries the covered slots",
        )?;
        require(seam.shape() == self.layout.seam, "seam shape")?;
        Ok(seam.encode())
    }

    fn ext_mul<AB: AirBuilder<F = Val>>(
        &self,
        a: &[AB::Expr; D],
        b: &[AB::Expr; D],
    ) -> [AB::Expr; D] {
        core::array::from_fn(|k| {
            let mut acc = AB::Expr::ZERO;
            for (ai, row) in a.iter().zip(&self.mul) {
                for (bj, t) in b.iter().zip(row) {
                    if t[k] != Val::ZERO {
                        acc += ai.clone() * bj.clone() * t[k];
                    }
                }
            }
            acc
        })
    }
}

/// An honest C2 for a real leaf proof: the trace, its public values (C1's
/// seam, with the covered slots' indices) and the seam read back from them.
pub(super) struct Honest {
    pub(super) air: C2Air,
    pub(super) trace: RowMajorMatrix<Val>,
    pub(super) pvs: Vec<Val>,
    pub(super) seam: Seam,
}

/// Build [`Honest`] from C1's seam for the same proof, covering `slots`
/// (ascending). F2b-4's `f2wrap` covers every one of the `cfg.num_queries`
/// slots, so `check_coverage` can hold; a test may cover fewer. `max_cells`
/// bounds the materialization before the trace is allocated (`C2Air::new`).
pub(super) fn honest(
    dims: Dims,
    chunks: usize,
    cfg: &FriCfg,
    c1_seam: &Seam,
    slots: Vec<usize>,
    proof: &Proof<Config>,
    max_cells: usize,
) -> Result<Honest> {
    require(
        slots.iter().all(|&s| s < c1_seam.indices.len()),
        "a covered slot C1 did not draw",
    )?;
    let seam = Seam {
        indices: slots.iter().map(|&s| c1_seam.indices[s]).collect(),
        ..c1_seam.clone()
    };
    let layout = Layout::new(dims, chunks, cfg, slots)?;
    let air = C2Air::new(layout, max_cells)?;
    let build = Build::honest(&air.layout, &seam, proof)?;
    let trace = air.trace(&build)?;
    let pvs = air.public_values(&seam)?;
    let seam = Seam::decode(air.layout.seam, &air.layout.slots, &pvs)?;
    Ok(Honest {
        air,
        trace,
        pvs,
        seam,
    })
}

impl Phased for C2Air {
    fn phases(&self) -> &'static [&'static str] {
        &PHASES
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let (lane, l) = (&self.lane, &self.layout);
        let fg = &l.fg.geom;
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { next[i].into() };
        let ext = |col: usize| -> [AB::Expr; D] { core::array::from_fn(|i| c(col + i)) };
        let ring = |s: usize| c(self.ring_col + s);
        let ring_sum =
            |ps: &mut dyn Iterator<Item = usize>| ps.fold(AB::Expr::ZERO, |acc, s| acc + ring(s));
        let k = &lane.kc;
        let fin = c(k.fin);
        let one = || AB::Expr::ONE;
        let one_limb = |m: usize| if m == 0 { one() } else { AB::Expr::ZERO };
        let (len, qn, lde, rounds) = (l.len(), l.queries(), l.lde(), fg.rounds());
        // The segment end: last row of the last position's perm.
        let keep = || one() - fin.clone() * ring(len - 1);
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let ps: Vec<usize> = (0..len)
                        .filter(|&s| {
                            l.leaf_words(s)
                                .is_some_and(|w| matches!(w[slot], Word::Row(..)))
                        })
                        .collect();
                    if ps.is_empty() {
                        continue;
                    }
                    let gate = ring_sum(&mut ps.into_iter());
                    lane.eval_canonical(builder, slot, gate, self.canon_col);
                }
                return;
            }
            _ => {}
        }
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        match PHASES[phase] {
            "bits" => {
                for i in 0..RATE_BITS {
                    builder.assert_bool(cur[lane.m_col + i]);
                }
            }
            "absorb" => {
                // Overwrite sponge: the rate preimage IS the message.
                let s0 = c(k.step0);
                for ln in 0..RATE_LANES {
                    for li in 0..4 {
                        let bits = (0..16).fold(AB::Expr::ZERO, |acc, t| {
                            acc + c(lane.m_col + 64 * ln + 16 * li + t) * lane.pow2[t]
                        });
                        builder.assert_zero(s0.clone() * (c(k.pre[ln][li]) - bits));
                    }
                }
            }
            "ring" => {
                // Position ring: first row position 0; each perm's last row
                // hands the token on; the last position wraps to 0 unless the
                // segment was the last query's (then the ring empties).
                let last_q = c(self.qring_col + qn - 1);
                for s in 0..len {
                    let start = if s == 0 { one() } else { AB::Expr::ZERO };
                    builder.when_first_row().assert_zero(ring(s) - start);
                    let prev = if s == 0 {
                        ring(len - 1) * (one() - last_q.clone())
                    } else {
                        ring(s - 1)
                    };
                    builder.when_transition().assert_zero(
                        n(self.ring_col + s) - ring(s) - fin.clone() * (prev - ring(s)),
                    );
                }
                // Query ring: first row query 0, advances at a segment end.
                let end = fin.clone() * ring(len - 1);
                for q in 0..qn {
                    let cell = c(self.qring_col + q);
                    let start = if q == 0 { one() } else { AB::Expr::ZERO };
                    builder.when_first_row().assert_zero(cell.clone() - start);
                    let prev = if q == 0 {
                        AB::Expr::ZERO
                    } else {
                        c(self.qring_col + q - 1)
                    };
                    builder.when_transition().assert_zero(
                        n(self.qring_col + q) - cell.clone() - end.clone() * (prev - cell),
                    );
                }
            }
            "gate" => {
                // Last-row gates, materialized so the bindings they gate stay
                // at degree 3: one per index bit a path level reads (on the
                // row feeding that level), one per cap check.
                for t in 0..l.path_bits() {
                    let before = ring_sum(&mut l.before(|s| l.reads_bit(s) == Some(t)).into_iter());
                    builder.assert_zero(c(self.lvl_col + t) - fin.clone() * before);
                }
                for (i, &(at, _)) in l.caps.iter().enumerate() {
                    builder.assert_zero(c(self.capg_col + i) - fin.clone() * ring(at));
                }
            }
            "capacity" => {
                // Carried into an interior leaf block, zero into every other
                // perm (a fresh leaf sponge, a fresh compression).
                let inter = ring_sum(&mut l.before(|s| l.is_interior(s)).into_iter());
                for ln in RATE_LANES..25 {
                    for li in 0..4 {
                        builder.when_transition().assert_zero(
                            fin.clone() * (n(k.pre[ln][li]) - inter.clone() * c(k.out[ln][li])),
                        );
                        builder.when_first_row().assert_zero(c(k.pre[ln][li]));
                    }
                }
            }
            "bind_zero" => {
                let nodes: Vec<usize> = (0..len).filter(|&s| l.is_node(s)).collect();
                for slot in 0..RATE_WORDS {
                    let mut ps: Vec<usize> = (0..len)
                        .filter(|&s| l.leaf_words(s).is_some_and(|w| w[slot] == Word::Zero))
                        .collect();
                    if slot >= CHILD_WORDS {
                        ps.extend(&nodes);
                    }
                    if ps.is_empty() {
                        continue;
                    }
                    let gate = ring_sum(&mut ps.into_iter());
                    for half in 0..2 {
                        builder.assert_zero(gate.clone() * lane.half::<AB>(cur, slot, half));
                    }
                }
            }
            "bind_carry" => {
                // A short interior block keeps the previous output in its
                // tail lanes (`sponge.rs:186-194`).
                for s in l.before(|s| !l.carry_lanes(s).is_empty()) {
                    let gate = fin.clone() * ring(s);
                    for ln in l.carry_lanes(s + 1) {
                        for li in 0..4 {
                            builder
                                .when_transition()
                                .assert_zero(gate.clone() * (n(k.pre[ln][li]) - c(k.out[ln][li])));
                        }
                    }
                }
            }
            "bind_child" => {
                // A level reading index bit t: the digest just produced sits
                // left when the bit is 0, right when it is 1. Input and
                // commit-phase levels at bit t share its gate and its cell.
                for t in 0..l.path_bits() {
                    let gate = c(self.lvl_col + t);
                    let b = c(self.bits_col + t);
                    for j in 0..4 {
                        for li in 0..4 {
                            let out = c(k.out[j][li]);
                            let left = n(k.pre[j][li]) - out.clone();
                            let right = n(k.pre[4 + j][li]) - out;
                            builder.when_transition().assert_zero(
                                gate.clone() * ((one() - b.clone()) * left + b.clone() * right),
                            );
                        }
                    }
                }
            }
            "cap" => {
                // Each batch's and each round's root equals the entry of its
                // seam cap that the top index bits select.
                for (i, &(_, block)) in l.caps.iter().enumerate() {
                    let gate = c(self.capg_col + i);
                    for ln in 0..4 {
                        for li in 0..4 {
                            let sum = (0..8).fold(AB::Expr::ZERO, |acc, j| {
                                acc + c(self.e_col + j)
                                    * (c(k.out[ln][li]) - pv[l.seam.cap(block, j, ln, li)].clone())
                            });
                            builder.assert_zero(gate.clone() * sum);
                        }
                    }
                }
            }
            "leaf_bind" => {
                // Commit-phase leaves: the hashed Monty word is R * v, the
                // group limb is v.
                for s in 0..len {
                    let Step::Fri(fold::Step::Leaf(r, _)) = l.segment[s] else {
                        continue;
                    };
                    for (slot, &word) in l.leaf_words(s).unwrap().iter().enumerate() {
                        if let Word::Row(_, cc) = word {
                            builder.assert_zero(
                                ring(s)
                                    * (lane.full::<AB>(cur, slot) * self.rinv
                                        - c(self.g_col(r, cc / D) + cc % D)),
                            );
                        }
                    }
                }
            }
            "index" => {
                for t in 0..lde {
                    builder.assert_bool(cur[self.bits_col + t]);
                }
                let index = (0..lde).fold(AB::Expr::ZERO, |acc, t| {
                    acc + c(self.bits_col + t) * lane.pow2[t]
                });
                let pinned = (0..qn).fold(AB::Expr::ZERO, |acc, q| {
                    acc + c(self.qring_col + q) * (index.clone() - pv[l.seam.index(q)].clone())
                });
                builder.assert_zero(pinned);
            }
            "cap_select" => {
                // One-hot of the cap entry = the top CAP_HEIGHT index bits,
                // shared by every batch and every round.
                let p = |u: usize| c(self.bits_col + lde - CAP_HEIGHT + u);
                let f = |set: bool, x: AB::Expr| if set { x } else { one() - x };
                for j in 0..4 {
                    builder
                        .assert_zero(c(self.u_col + j) - f(j & 1 != 0, p(0)) * f(j & 2 != 0, p(1)));
                }
                for j in 0..8 {
                    builder.assert_zero(
                        c(self.e_col + j) - c(self.u_col + (j & 3)) * f(j & 4 != 0, p(2)),
                    );
                }
            }
            "x_point" => {
                // x = GENERATOR * prod_t (omega^{2^{lde-1-t}})^{bit_t}.
                let factor =
                    |t: usize| one() + c(self.bits_col + t) * (self.x_factors[t] - Val::ONE);
                builder.assert_zero(c(self.x_col) - factor(0) * Val::GENERATOR);
                for t in 1..lde {
                    builder.assert_zero(c(self.x_col + t) - c(self.x_col + t - 1) * factor(t));
                }
            }
            "inverse" => {
                let x = c(self.x_col + lde - 1);
                let z = ext(self.zeta_col);
                let mut za = z.clone();
                za[0] = za[0].clone() - x.clone();
                let mut zb: [AB::Expr; D] = core::array::from_fn(|i| z[i].clone() * self.g_n);
                zb[0] = zb[0].clone() - x;
                for (lhs, inv) in [(za, self.inv_a_col), (zb, self.inv_b_col)] {
                    let prod = self.ext_mul::<AB>(&lhs, &ext(inv));
                    for (m, p) in prod.into_iter().enumerate() {
                        builder.assert_zero(p - one_limb(m));
                    }
                }
            }
            "alpha_pow" => {
                // The held table: tab_{i+1} = tab_i * tab_1 (tab_1 = fri_alpha).
                let alpha = ext(self.tab(1));
                for i in 1..TAB {
                    let prod = self.ext_mul::<AB>(&ext(self.tab(i)), &alpha);
                    for (m, p) in prod.into_iter().enumerate() {
                        builder
                            .when_first_row()
                            .assert_zero(c(self.tab(i + 1) + m) - p);
                    }
                }
                let p = ext(self.p_col);
                // Anchor: every segment's first block weights from term 0.
                for (m, pm) in p.iter().enumerate() {
                    builder.assert_zero(ring(0) * (pm.clone() - one_limb(m)));
                }
                // pn: p after this perm. A block of n row values steps by
                // α^n; the last trace block by α^w·α^n (from pw); the last
                // position resets to 1; every other perm keeps p.
                let mut by_n: Vec<(usize, Vec<usize>)> = Vec::new();
                for (i, b) in l.blocks.iter().enumerate() {
                    if i == l.last_trace {
                        continue;
                    }
                    match by_n.iter_mut().find(|(nn, _)| *nn == b.n()) {
                        Some((_, ps)) => ps.push(b.pos),
                        None => by_n.push((b.n(), vec![b.pos])),
                    }
                }
                let lt = &l.blocks[l.last_trace];
                let mut pn: [AB::Expr; D] = p.clone();
                for (nn, ps) in &by_n {
                    let gate = ring_sum(&mut ps.iter().copied());
                    let step = self.ext_mul::<AB>(&p, &ext(self.tab(*nn)));
                    for m in 0..D {
                        pn[m] += gate.clone() * (step[m].clone() - p[m].clone());
                    }
                }
                let jump = self.ext_mul::<AB>(&ext(self.pw_col), &ext(self.tab(lt.n())));
                for m in 0..D {
                    pn[m] += ring(lt.pos) * (jump[m].clone() - p[m].clone());
                    pn[m] += ring(len - 1) * (one_limb(m) - p[m].clone());
                    builder.assert_zero(c(self.pn_col + m) - pn[m].clone());
                    // p moves to pn on a perm's last row, holds otherwise.
                    builder.when_transition().assert_zero(
                        n(self.p_col + m)
                            - p[m].clone()
                            - fin.clone() * (c(self.pn_col + m) - p[m].clone()),
                    );
                }
                // pw = α^w · p on trace blocks, 0 elsewhere.
                let trace_blocks =
                    ring_sum(&mut l.blocks.iter().filter(|b| b.batch == TRACE).map(|b| b.pos));
                let paw = self.ext_mul::<AB>(&p, &ext(self.aw_col));
                for (m, x) in paw.into_iter().enumerate() {
                    builder.assert_zero(c(self.pw_col + m) - trace_blocks.clone() * x);
                }
                // α^w pinned where the trace terms end: p·α^n = α^{k0_T}·α^w.
                let lhs = self.ext_mul::<AB>(&p, &ext(self.tab(lt.n())));
                let rhs = self.ext_mul::<AB>(&ext(self.tab(l.trace_k0)), &ext(self.aw_col));
                for m in 0..D {
                    builder.assert_zero(ring(lt.pos) * (lhs[m].clone() - rhs[m].clone()));
                }
            }
            "blk" => {
                // blk = Σ_i α^i v_i over the current input block's row values
                // (v = R^-1 * word), zero on every other perm.
                let mut blk: [AB::Expr; D] = core::array::from_fn(|_| AB::Expr::ZERO);
                for slot in 0..RATE_WORDS {
                    let mut by_i: Vec<(usize, Vec<usize>)> = Vec::new();
                    for b in &l.blocks {
                        for &(s, i) in &b.rows {
                            if s != slot {
                                continue;
                            }
                            match by_i.iter_mut().find(|(ii, _)| *ii == i) {
                                Some((_, ps)) => ps.push(b.pos),
                                None => by_i.push((i, vec![b.pos])),
                            }
                        }
                    }
                    if by_i.is_empty() {
                        continue;
                    }
                    let v = lane.full::<AB>(cur, slot) * self.rinv;
                    for (m, acc) in blk.iter_mut().enumerate() {
                        let weight = by_i.iter().fold(AB::Expr::ZERO, |w, (i, ps)| {
                            let gate = ring_sum(&mut ps.iter().copied());
                            w + if *i == 0 {
                                gate * one_limb(m)
                            } else {
                                gate * c(self.tab(*i) + m)
                            }
                        });
                        *acc += v.clone() * weight;
                    }
                }
                for (m, x) in blk.into_iter().enumerate() {
                    builder.assert_zero(c(self.blk_col + m) - x);
                }
            }
            "accumulate" => {
                // Ax' = Ax (reset at a segment end) + [step 0] p·blk;
                // Bx' likewise from pw (nonzero on trace blocks only).
                let s0 = c(k.step0);
                let blk = ext(self.blk_col);
                for (acc, pcol) in [(self.ax_col, self.p_col), (self.bx_col, self.pw_col)] {
                    let prod = self.ext_mul::<AB>(&ext(pcol), &blk);
                    for (m, x) in prod.into_iter().enumerate() {
                        builder.when_first_row().assert_zero(c(acc + m));
                        builder
                            .when_transition()
                            .assert_zero(n(acc + m) - keep() * c(acc + m) - s0.clone() * x);
                    }
                }
            }
            "reduce" => {
                // ro = (Az - Ax)/(ζ - x) + (Bz - Bx)/(ζ·g_N - x), on the last
                // input perm's rows, where Ax and Bx are complete.
                let gate = ring(l.open_last);
                let diff = |held: usize, acc: usize| -> [AB::Expr; D] {
                    core::array::from_fn(|i| c(held + i) - c(acc + i))
                };
                let ta = self.ext_mul::<AB>(&diff(self.az_col, self.ax_col), &ext(self.inv_a_col));
                let tb = self.ext_mul::<AB>(&diff(self.bz_col, self.bx_col), &ext(self.inv_b_col));
                for (m, (a, b)) in ta.into_iter().zip(tb).enumerate() {
                    builder.assert_zero(gate.clone() * (c(self.ro_col + m) - a - b));
                }
            }
            "position" => {
                // Round r's position = index bits S_r..S_r+a, one level of
                // the one-hot per bit.
                for r in 0..rounds {
                    let s = fg.shift[r];
                    let b = |lv: usize| c(self.bits_col + s + lv);
                    builder.assert_zero(c(self.pos_col(r, 1, 0)) - (one() - b(0)));
                    builder.assert_zero(c(self.pos_col(r, 1, 1)) - b(0));
                    for lv in 1..fg.arities[r] {
                        let half = 1 << lv;
                        for j in 0..half {
                            let prev = c(self.pos_col(r, lv, j));
                            builder.assert_zero(
                                c(self.pos_col(r, lv + 1, j)) - prev.clone() * (one() - b(lv)),
                            );
                            builder
                                .assert_zero(c(self.pos_col(r, lv + 1, j + half)) - prev * b(lv));
                        }
                    }
                }
            }
            "select" => {
                // The running value IS the committed entry at the position;
                // round 0's running value is the handed-off ro.
                for r in 0..rounds {
                    for m in 0..D {
                        let sel = (0..fg.arity(r)).fold(AB::Expr::ZERO, |acc, j| {
                            acc + c(self.top_col(r, j)) * c(self.g_col(r, j) + m)
                        });
                        builder.assert_zero(sel - c(self.f_col(r) + m));
                    }
                }
            }
            "s_inv" => {
                for r in 0..rounds {
                    let base = fg.shift[r + 1];
                    let factor = |t: usize| {
                        one() + c(self.bits_col + base + t) * (fg.sinv_f[r][t] - Val::ONE)
                    };
                    builder.assert_zero(c(self.sinv[r]) - factor(0));
                    for t in 1..fg.folded[r] {
                        builder
                            .assert_zero(c(self.sinv[r] + t) - c(self.sinv[r] + t - 1) * factor(t));
                    }
                }
            }
            "fold_pow" => {
                // u = beta_r * s^-1, then u^k by successive products.
                for r in 0..rounds {
                    let s = c(self.sinv[r] + fg.folded[r] - 1);
                    for m in 0..D {
                        builder
                            .assert_zero(c(self.t_col(r, 1) + m) - c(self.beta(r) + m) * s.clone());
                    }
                    for kk in 2..fg.arity(r) {
                        let prod =
                            self.ext_mul::<AB>(&ext(self.t_col(r, kk - 1)), &ext(self.t_col(r, 1)));
                        for (m, p) in prod.into_iter().enumerate() {
                            builder.assert_zero(c(self.t_col(r, kk) + m) - p);
                        }
                    }
                }
            }
            "fold" => {
                // f_{r+1} = sum_k d_k u^k (`fold_row`), d_k linear in the group.
                for r in 0..rounds {
                    let nn = fg.arity(r);
                    let d = |kk: usize| -> [AB::Expr; D] {
                        core::array::from_fn(|m| {
                            (0..nn).fold(AB::Expr::ZERO, |acc, i| {
                                acc + c(self.g_col(r, i) + m) * fg.idft[r][kk][i]
                            })
                        })
                    };
                    let mut acc = d(0);
                    for kk in 1..nn {
                        let prod = self.ext_mul::<AB>(&ext(self.t_col(r, kk)), &d(kk));
                        for (a, p) in acc.iter_mut().zip(prod) {
                            *a += p;
                        }
                    }
                    for (m, a) in acc.into_iter().enumerate() {
                        builder.assert_zero(c(self.f_col(r + 1) + m) - a);
                    }
                }
            }
            "final_x" => {
                let base = fg.shift[rounds];
                let factor =
                    |t: usize| one() + c(self.bits_col + base + t) * (fg.final_f[t] - Val::ONE);
                builder.assert_zero(c(self.xf_col) - factor(0));
                for t in 1..fg.final_bits {
                    builder.assert_zero(c(self.xf_col + t) - c(self.xf_col + t - 1) * factor(t));
                }
            }
            "horner" => {
                let x = c(self.xf_col + fg.final_bits - 1);
                let last = fg.final_len - 1;
                for m in 0..D {
                    builder.assert_zero(c(self.h_col(last) + m) - c(self.final_c(last) + m));
                    for kk in 0..last {
                        builder.assert_zero(
                            c(self.h_col(kk) + m)
                                - c(self.h_col(kk + 1) + m) * x.clone()
                                - c(self.final_c(kk) + m),
                        );
                    }
                }
            }
            "final" => {
                for m in 0..D {
                    builder.assert_zero(c(self.h_col(0) + m) - c(self.f_col(rounds) + m));
                }
            }
            "seam_in" => {
                // C1's exports, taken as given: the same values, not a
                // second supply (`check_seams` states the equality).
                let s = &l.seam;
                let mut bind = |col: usize, at: usize| {
                    for m in 0..D {
                        builder
                            .when_first_row()
                            .assert_zero(c(col + m) - pv[at + m].clone());
                    }
                };
                bind(self.zeta_col, s.zeta());
                bind(self.tab(1), s.fri_alpha());
                bind(self.az_col, s.az());
                bind(self.bz_col, s.bz());
                for r in 0..rounds {
                    bind(self.beta(r), s.beta(r));
                }
                for cc in 0..fg.final_len {
                    bind(self.final_c(cc), s.final_coeff(cc));
                }
            }
            "hold" => {
                for col in self.held_col..self.width {
                    builder.when_transition().assert_zero(n(col) - c(col));
                }
            }
            "handoff" => {
                // The index bits and ro: one set of cells over the segment,
                // read by the opening part and the fold part alike.
                for col in self.bits_col..self.handoff_end {
                    builder
                        .when_transition()
                        .assert_zero(keep() * (n(col) - c(col)));
                }
            }
            "ctx_hold" => {
                for col in self.handoff_end..self.reg_end {
                    builder
                        .when_transition()
                        .assert_zero(keep() * (n(col) - c(col)));
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for C2Air {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        self.layout.num_public_values()
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for C2Air {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::OnceLock;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
    use p3_field::TwoAdicField;
    use p3_maybe_rayon::prelude::*;
    use p3_util::reverse_bits_len;
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_l2::{Shape, L2_CFG_PROVISIONAL};

    use super::super::c1::tests::{honest_seam, native_sums};
    use super::super::fold::tests::native_query_of;
    use super::super::fri_fs::tests::{shared, Shared};
    use super::super::lane::phase_ranges;
    use super::super::lane::toy::{copy, native_through_f2, regrind, violation_set, Toy};
    use super::super::open::tests::reduced_opening;
    use super::super::open::BATCHES;
    use super::super::seam::{check_coverage, check_seams, GROUPS};
    use super::super::{proof_inputs_dims, Program};
    use super::*;
    use crate::f2::price::composed_c2_layout;

    type Groups = BTreeSet<(usize, &'static str)>;

    struct Fixture {
        sh: Shared,
        dims: Dims,
        /// C1's honest public values and seam for the same proof.
        c1_pvs: Vec<Val>,
        c1: Seam,
        /// C2's seam: C1's, with the covered slots' indices.
        seam: Seam,
        air: C2Air,
        ranges: Vec<Range<usize>>,
        honest: Build,
    }

    /// The seeded log-8 toy proof 2b-i/2b-ii/2b-iii/C1 share, C1's honest
    /// seam for it, and a C2 instance covering two queries whose cap
    /// entries differ (2b-ii's choice).
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let sh = shared();
            let (c1_pvs, c1) = honest_seam();
            let dims = Dims {
                width: 2,
                pv_len: 2,
                log_height: sh.log_height,
            };
            let chunks = sh.proof.opened_values.quotient_chunks.len();
            let cfg = L2_CFG_PROVISIONAL;
            let path = open::Geom::new(dims, chunks, &cfg).unwrap().path;
            let cap_of = |i: usize| sh.indices[i] >> path;
            let other = (1..sh.indices.len())
                .find(|&i| cap_of(i) != cap_of(0))
                .unwrap();
            let slots = vec![0, other];
            let layout = Layout::new(dims, chunks, &cfg, slots.clone()).unwrap();
            let air = C2Air::new(layout, 64 << 20).unwrap();
            let seam = Seam {
                indices: slots.iter().map(|&s| c1.indices[s]).collect(),
                ..c1.clone()
            };
            let honest = Build::honest(&air.layout, &seam, sh.proof).unwrap();
            let ranges = phase_ranges(&air);
            Fixture {
                sh,
                dims,
                c1_pvs,
                c1,
                seam,
                air,
                ranges,
                honest,
            }
        })
    }

    fn phase_in(ranges: &[Range<usize>], constraint: usize) -> &'static str {
        PHASES[ranges.iter().position(|r| r.contains(&constraint)).unwrap()]
    }

    /// Every (row, group) violated anywhere in `trace`.
    fn scan(
        air: &C2Air,
        ranges: &[Range<usize>],
        trace: &RowMajorMatrix<Val>,
        pvs: &[Val],
    ) -> Groups {
        (0..air.height)
            .into_par_iter()
            .flat_map_iter(|row| {
                violations_at(air, trace, pvs, row)
                    .into_iter()
                    .map(move |v| (row, phase_in(ranges, v.constraint)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect()
    }

    struct Claim {
        build: Build,
        trace: RowMajorMatrix<Val>,
        pvs: Vec<Val>,
    }

    /// `before` edits the forger's inputs, which `settle` re-derives
    /// consistently; `after` pokes derived values. Public values: `seam`.
    fn claim_with(
        fx: &Fixture,
        seam: &Seam,
        before: impl FnOnce(&mut Build),
        after: impl FnOnce(&mut Build),
    ) -> Claim {
        let mut build = fx.honest.clone();
        before(&mut build);
        build.settle(&fx.air.layout).unwrap();
        after(&mut build);
        let trace = fx.air.trace(&build).unwrap();
        let pvs = fx.air.public_values(seam).unwrap();
        Claim { build, trace, pvs }
    }

    /// Public values stay C1's honest exports.
    fn claim(
        fx: &Fixture,
        before: impl FnOnce(&mut Build),
        after: impl FnOnce(&mut Build),
    ) -> Claim {
        claim_with(fx, &fx.seam, before, after)
    }

    fn refused_exactly(fx: &Fixture, c: &Claim, expected: &Groups) {
        let v = scan(&fx.air, &fx.ranges, &c.trace, &c.pvs);
        assert!(!v.is_empty(), "forgery accepted");
        assert_eq!(&v, expected);
    }

    fn rows(r: Range<usize>, group: &'static str) -> Groups {
        r.map(|row| (row, group)).collect()
    }

    fn seg(fx: &Fixture, q: usize) -> Range<usize> {
        seg_in(&fx.air, q)
    }
    fn seg_in(air: &C2Air, q: usize) -> Range<usize> {
        let s = NUM_ROUNDS * air.layout.len();
        q * s..(q + 1) * s
    }

    /// Rows carrying query `q`'s registers: its segment, and for the last
    /// query the padding rows after it.
    fn ctx_rows(fx: &Fixture, q: usize) -> Range<usize> {
        ctx_rows_in(&fx.air, q)
    }
    fn ctx_rows_in(air: &C2Air, q: usize) -> Range<usize> {
        let r = seg_in(air, q);
        if q + 1 == air.layout.queries() {
            r.start..air.height
        } else {
            r
        }
    }

    /// Query `q`'s fold-part rows (inside its segment).
    fn fri_rows(fx: &Fixture, q: usize) -> Range<usize> {
        let s = seg(fx, q);
        s.start + fx.air.fri_rows()..s.end
    }

    fn last_row(fx: &Fixture, q: usize, pos: usize) -> usize {
        last_row_in(&fx.air, q, pos)
    }
    fn last_row_in(air: &C2Air, q: usize, pos: usize) -> usize {
        NUM_ROUNDS * (q * air.layout.len() + pos) + NUM_ROUNDS - 1
    }

    fn perm_rows(fx: &Fixture, q: usize, pos: usize, group: &'static str) -> Groups {
        let first = NUM_ROUNDS * (q * fx.air.layout.len() + pos);
        rows(first..first + NUM_ROUNDS, group)
    }

    fn in_cap_row(fx: &Fixture, q: usize, b: usize) -> usize {
        in_cap_row_in(&fx.air, q, b)
    }
    fn in_cap_row_in(air: &C2Air, q: usize, b: usize) -> usize {
        let l = &air.layout;
        last_row_in(
            air,
            q,
            l.at(Step::In(open::Step::Node(b, l.ig.geom.path - 1))),
        )
    }

    fn fri_cap_row(fx: &Fixture, q: usize, r: usize) -> usize {
        fri_cap_row_in(&fx.air, q, r)
    }
    fn fri_cap_row_in(air: &C2Air, q: usize, r: usize) -> usize {
        let l = &air.layout;
        last_row_in(
            air,
            q,
            l.at(Step::Fri(fold::Step::Node(r, l.fg.geom.path[r] - 1))),
        )
    }

    /// The row feeding `step` (a path level).
    fn feed_row(fx: &Fixture, q: usize, step: Step) -> usize {
        last_row(fx, q, fx.air.layout.at(step) - 1)
    }

    fn basis(i: usize) -> E {
        <E as BasedVectorSpace<Val>>::ith_basis_element(i).unwrap()
    }

    /// What a consistently re-derived claim cannot hide, from the native
    /// replay alone: every root that misses the seam cap entry its index
    /// selects (`cap` on that check's row), and every query whose last
    /// fold misses the final polynomial (`final` on its register rows).
    fn consequences(fx: &Fixture, b: &Build) -> Groups {
        consequences_in(&fx.air, &fx.seam.caps, b)
    }
    fn consequences_in(air: &C2Air, caps: &[Vec<[u64; 4]>], b: &Build) -> Groups {
        let l = &air.layout;
        let top = |q: usize| b.index[q] >> (l.lde() - CAP_HEIGHT);
        let mut out = Groups::new();
        for q in 0..l.queries() {
            for bt in 0..BATCHES {
                let cap = &caps[open::Geom::cap_block(bt)];
                if b.in_walks[q].roots[bt] != cap[top(q)] {
                    out.insert((in_cap_row_in(air, q, bt), "cap"));
                }
            }
            for r in 0..l.fg.geom.rounds() {
                if b.fri_walks[q].roots[r] != caps[3 + r][top(q)] {
                    out.insert((fri_cap_row_in(air, q, r), "cap"));
                }
            }
            let f = &b.fctx[q];
            if f.f[f.f.len() - 1] != f.horner[0] {
                out.extend(rows(ctx_rows_in(air, q), "final"));
            }
        }
        out
    }

    fn assert_degree_three(air: &C2Air, ranges: &[Range<usize>]) {
        let constraints = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
        assert_eq!(ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "C2 degree {max} > 3");
    }

    /// x of `index` as `open_input` computes it (bit-reversed, shifted).
    fn native_x(index: usize, lde: usize) -> E {
        E::from(
            Val::GENERATOR
                * Val::two_adic_generator(lde).exp_u64(reverse_bits_len(index, lde) as u64),
        )
    }

    #[test]
    fn c2_releases_at_the_segment_end_and_fills_the_trace_tail() {
        // Two places where a per-segment hold must change hands, pinned on
        // the honest trace. (1) The segment end: the last row of query 0's
        // last perm is the one row where the last-row flag meets the last
        // position cell, so the register holds release there and nowhere
        // else; query 1's registers differ from query 0's across it.
        // (2) The trace tail: 2^11 is not a multiple of 24, so the last perm
        // is partial (8 rows); those rows carry the held, register and
        // running cells of the padding like every row before them (a tail
        // left at zero broke `hold`, `handoff`, `ctx_hold` and `alpha_pow`
        // on the last full row, run 36358638145).
        let fx = fixture();
        let (air, l) = (&fx.air, &fx.air.layout);
        let (h, w) = (air.height, air.width);
        assert_eq!(h % NUM_ROUNDS, 8, "a partial last perm");
        let c = claim(fx, |_| {}, |_| {});
        let v = &c.trace.values;
        let cell = |row: usize, col: usize| v[row * w + col];
        let end = seg(fx, 0).end - 1;
        let fin = air.lane.kc.fin;
        let ring_last = air.ring_col + l.len() - 1;
        for row in 0..h {
            let release = cell(row, fin) * cell(row, ring_last);
            assert_eq!(
                release,
                Val::from_bool(row == end || row == seg(fx, 1).end - 1),
                "segment end at row {row}"
            );
        }
        let regs = air.bits_col..air.reg_end;
        assert_ne!(
            v[end * w..][regs.clone()],
            v[(end + 1) * w..][regs.clone()],
            "the two queries' registers differ across the release row"
        );
        // Query 0's registers hold on every row of its segment, query 1's on
        // every later row (its segment and the padding, tail included).
        for row in 0..h {
            let q = usize::from(row > end);
            let first = if q == 0 { 0 } else { end + 1 };
            assert_eq!(
                v[row * w..][regs.clone()],
                v[first * w..][regs.clone()],
                "registers at row {row}"
            );
            assert_eq!(
                v[row * w..][air.held_col..w],
                v[..w][air.held_col..w],
                "held cells at row {row}"
            );
        }
        // The running power: 1 on each segment's first block and on every
        // padding row, tail included.
        let one = E::ONE;
        let p = |row: usize| E::from_basis_coefficients_fn(|i| cell(row, air.p_col + i));
        assert_eq!(p(0), one);
        assert_eq!(p(end + 1), one);
        for row in seg(fx, 1).end..h {
            assert_eq!(p(row), one, "padding p at row {row}");
        }
        // No constraint is violated around either place.
        for row in [end - 1, end, end + 1, h - 10, h - 9, h - 8, h - 2, h - 1] {
            let bad = violations_at(air, &c.trace, &c.pvs, row);
            assert!(
                bad.is_empty(),
                "row {row}: {}",
                phase_in(&fx.ranges, bad[0].constraint)
            );
        }
    }

    #[test]
    fn c2_accepts_honest_segments_at_degree_three() {
        let fx = fixture();
        let (air, l) = (&fx.air, &fx.air.layout);
        let proof = fx.sh.proof;
        // One segment per query: 2b-ii's 1 + 1 + 2 leaf perms and 3 x 8
        // levels, then 2b-iii's 2 + 1 leaf perms and 4 + 3 levels.
        assert_eq!((l.open_last + 1, l.len()), (28, 38));
        // L2 over the toy's 40 terms: randomizer 0..3, trace ζ 4..5 (its
        // ζ·g_N terms 6..7 ride on the same block), quotient 8..39 in two
        // blocks (16 + 2 row values, then 14).
        let k0: Vec<(usize, usize)> = l.blocks.iter().map(|b| (b.k0, b.n())).collect();
        assert_eq!(k0, vec![(0, 4), (4, 2), (8, 18), (26, 14)]);
        assert_eq!((l.last_trace, l.trace_k0), (1, 4));
        assert!(BaseAir::<Val>::periodic_columns(air).is_empty());
        let price = composed_c2_layout(2, fx.dims.log_height, 8, l.queries());
        assert_eq!(price["permutations_per_query"], l.len());
        assert_eq!(price["component_columns"], air.width);
        assert_eq!(price["padded_rows"], air.height);
        assert_eq!(price["periodic_columns"], 0);
        assert_eq!(price["public_values"], l.num_public_values());
        // Natively, for ALL 43 queries: the block form of Ax/Bx (running
        // powers from the held table) equals a source-order `open_input` sum,
        // and the split with C1's Az/Bz is 2b-ii's sequential reduced opening.
        let s = &fx.c1;
        let lde = l.lde();
        let g_n = l.ig.geom.g_n;
        let mut all = fx.honest.clone();
        for &(q, index) in &s.indices {
            all.in_ops[0] = open::Opening::from_proof(proof, q, &l.ig.geom).unwrap();
            all.index[0] = index;
            all.settle(l).unwrap();
            let (ax, bx) = native_sums(proof, s.fri_alpha, Some(q));
            assert_eq!(all.ab[0], (ax, bx), "Ax/Bx, query {q}");
            let ro = reduced_opening(
                proof,
                fx.sh.pvs,
                2,
                fx.dims.log_height,
                q,
                index,
                s.fri_alpha,
            );
            let x = native_x(index, lde);
            let split =
                (s.az - ax) * (s.zeta - x).inverse() + (s.bz - bx) * (s.zeta * g_n - x).inverse();
            assert_eq!(split, ro, "split, query {q}");
            assert_eq!(all.ictx[0].ro, ro, "the circuit's ro, query {q}");
        }
        // The running powers are α^{k0} for the shared term order.
        for (b, &p) in l.blocks.iter().zip(&fx.honest.powers[0]) {
            assert_eq!(p, s.fri_alpha.exp_u64(b.k0 as u64));
        }
        // The covered queries: ro is 2b-ii's native one, the fold chain and
        // final check are p3's (commit-phase MMCS, `fold_row`), every root
        // is the seam's cap entry.
        let h = &fx.honest;
        for (i, &(q, index)) in fx.seam.indices.iter().enumerate() {
            let ro = reduced_opening(
                proof,
                fx.sh.pvs,
                2,
                fx.dims.log_height,
                q,
                index,
                s.fri_alpha,
            );
            assert_eq!(h.ictx[i].ro, ro, "ro, query {q}");
            let (chain, eval) = native_query_of(proof, lde, q, index, ro, &s.betas);
            assert_eq!(eval, chain[chain.len() - 1], "p3's final check, query {q}");
            assert_eq!(h.fctx[i].f, chain, "folds, query {q}");
            assert_eq!(h.fctx[i].horner[0], eval, "final evaluation, query {q}");
        }
        assert!(consequences(fx, h).is_empty(), "honest roots and finals");
        let c = claim(fx, |_| {}, |_| {});
        satisfied(air, &c.trace, &c.pvs).unwrap_or_else(|v| {
            panic!(
                "honest C2 refused: {v} in {}",
                phase_in(&fx.ranges, v.constraint)
            )
        });
        // The seam: C2's public values read back are C1's exports on the
        // covered slots; the toy instance does not cover every query.
        let c2 = Seam::decode(l.seam, &l.slots, &c.pvs).unwrap();
        assert_eq!(c2, fx.seam);
        check_seams(&fx.c1, &c2).unwrap();
        assert!(check_coverage(&fx.c1, &c2).is_err());
        assert_degree_three(air, &fx.ranges);
    }

    #[test]
    fn c2_meets_c1_at_the_seam() {
        // Every group, tampered on either side, fails `check_seams` by name.
        let fx = fixture();
        let l = &fx.air.layout;
        let pv_len = fx.dims.pv_len;
        let c2_pvs = fx.air.public_values(&fx.seam).unwrap();
        let s = l.seam;
        let first_of = |g: &str| match g {
            "caps" => s.cap(4, 3, 1, 2),
            "zeta" => s.zeta() + 1,
            "fri_alpha" => s.fri_alpha(),
            "az" => s.az() + 2,
            "bz" => s.bz() + 3,
            "betas" => s.beta(1),
            "final_poly" => s.final_coeff(5) + 1,
            _ => s.index(1),
        };
        let c1_slots: Vec<usize> = (0..fx.c1.indices.len()).collect();
        for g in GROUPS {
            // C2's side: its public value moved.
            let mut bad = c2_pvs.clone();
            bad[first_of(g)] = Val::from_u32(bad[first_of(g)].as_canonical_u32() ^ 1);
            let c2 = Seam::decode(s, &l.slots, &bad).unwrap();
            let err = check_seams(&fx.c1, &c2).unwrap_err();
            assert!(err.contains(&format!("`{g}`")), "C2 side {g}: {err}");
            // C1's side: its export moved (for the index, a covered slot's).
            let mut bad = fx.c1_pvs.clone();
            let at = if g == "indices" {
                pv_len + s.index(l.slots[1])
            } else {
                pv_len + first_of(g)
            };
            bad[at] = Val::from_u32(bad[at].as_canonical_u32() ^ 1);
            let c1 = Seam::decode(s, &c1_slots, &bad[pv_len..]).unwrap();
            let err = check_seams(&c1, &fx.seam).unwrap_err();
            assert!(err.contains(&format!("`{g}`")), "C1 side {g}: {err}");
        }
        // Inside C2: a public Az that its held cell does not carry is
        // refused on row 0.
        let mut seam = fx.seam.clone();
        seam.az += basis(1);
        let c = claim_with(fx, &seam, |_| {}, |_| {});
        refused_exactly(fx, &c, &[(0, "seam_in")].into());
        // Az from C1 differs and C2 is consistent on it (held, public, Ax/Bx
        // and ro re-derived, every fold chain from that ro): only the seam
        // check names it, and C2 refuses it where the forged ro meets the
        // commit-phase Merkle binding and the final polynomial.
        let c = claim_with(fx, &seam, |b| b.held.az = seam.az, |_| {});
        assert_ne!(c.build.ictx[0].ro, fx.honest.ictx[0].ro);
        let err = check_seams(&fx.c1, &Seam::decode(s, &l.slots, &c.pvs).unwrap()).unwrap_err();
        assert!(err.contains("`az`"), "{err}");
        let expected = consequences(fx, &c.build);
        assert!(expected.contains(&(fri_cap_row(fx, 0, 0), "cap")));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn c2_rejects_input_opening_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        let g = &l.ig.geom;
        // A salt changed: the leaf moves, only that batch's cap refuses.
        let c = claim(fx, |b| b.in_ops[0].salts[TRACE][0][2] += Val::ONE, |_| {});
        refused_exactly(fx, &c, &[(in_cap_row(fx, 0, TRACE), "cap")].into());
        // A row value changed and a fresh salt chosen, Ax, ro and the fold
        // chain re-derived from it: the input cap refuses, and the forged
        // ro misses every commit-phase leaf and the final polynomial.
        let c = claim(
            fx,
            |b| {
                b.in_ops[1].rows[QUOTIENT][3][1] += Val::ONE;
                b.in_ops[1].salts[QUOTIENT][3] =
                    (0..SALT).map(|s| Val::from_usize(s + 7)).collect();
            },
            |_| {},
        );
        assert_ne!(c.build.ictx[1].ro, fx.honest.ictx[1].ro);
        let expected = consequences(fx, &c.build);
        assert!(expected.contains(&(in_cap_row(fx, 1, QUOTIENT), "cap")));
        assert!(expected.contains(&(fri_cap_row(fx, 1, 0), "cap")));
        refused_exactly(fx, &c, &expected);
        // Two siblings of the randomizer path swapped.
        let c = claim(fx, |b| b.in_ops[0].siblings[RANDOM].swap(2, 3), |_| {});
        refused_exactly(fx, &c, &[(in_cap_row(fx, 0, RANDOM), "cap")].into());
        // The child placed on the wrong side at trace level 4, the bit
        // untouched: refused where it is placed, and the root moves.
        let c = claim(fx, |b| b.flips[1] = Some((TRACE, 4)), |_| {});
        refused_exactly(
            fx,
            &c,
            &[
                (
                    feed_row(fx, 1, Step::In(open::Step::Node(TRACE, 4))),
                    "bind_child",
                ),
                (in_cap_row(fx, 1, TRACE), "cap"),
            ]
            .into(),
        );
        // Index bit 3 flipped for the whole segment — placement, x, ro and
        // the fold part all follow it: the public index refuses it on every
        // row of the segment, and every root it moves refuses.
        let c = claim(fx, |b| b.index[0] ^= 1 << 3, |_| {});
        let mut expected = rows(seg(fx, 0), "index");
        let moved = consequences(fx, &c.build);
        for b in 0..BATCHES {
            assert!(moved.contains(&(in_cap_row(fx, 0, b), "cap")));
        }
        expected.extend(moved);
        refused_exactly(fx, &c, &expected);
        // The wrong cap entry selected: the one-hot no longer matches the
        // top index bits, and no entry but the right one matches any root.
        let right = fx.seam.indices[1].1 >> g.path;
        let c = claim(
            fx,
            |_| {},
            |b| b.ictx[1].e = core::array::from_fn(|j| Val::from_bool(j == right ^ 1)),
        );
        let mut expected = rows(ctx_rows(fx, 1), "cap_select");
        for b in 0..BATCHES {
            expected.insert((in_cap_row(fx, 1, b), "cap"));
        }
        for r in 0..l.fg.geom.rounds() {
            expected.insert((fri_cap_row(fx, 1, r), "cap"));
        }
        refused_exactly(fx, &c, &expected);
        // x WITHOUT bit reversal (a verifier forgetting `reverse_bits_len`),
        // inverses, ro and the fold chain re-derived from it. The query
        // indices follow the proof's PoW witness (a parallel grind, not
        // seeded), so the slot is the first covered one whose index is not a
        // bit-reversal palindrome — on a palindrome the forgery is the honest
        // claim. All covered indices palindromic: this sub-case is skipped,
        // loudly.
        let indices = &fx.honest.index;
        match (0..l.queries()).find(|&q| reverse_bits_len(indices[q], g.lde) != indices[q]) {
            Some(q) => {
                let c = claim(
                    fx,
                    |_| {},
                    |b| {
                        let index = b.index[q];
                        let rev = reverse_bits_len(index, g.lde);
                        assert_ne!(rev, index, "a palindromic index hides the reversal");
                        let held = open::Held {
                            zeta: b.held.zeta,
                            zvals: vec![],
                            fri_alpha: b.held.fri_alpha,
                            apow: vec![],
                            az: b.held.az,
                            bz: b.held.bz,
                            ro: vec![],
                        };
                        b.ictx[q] = open::Ctx::new(g, index, rev, &held, b.ab[q]).unwrap();
                        b.refold(l, q).unwrap();
                    },
                );
                assert_ne!(c.build.ictx[q].ro, fx.honest.ictx[q].ro);
                let mut expected = rows(ctx_rows(fx, q), "x_point");
                expected.extend(consequences(fx, &c.build));
                refused_exactly(fx, &c, &expected);
            }
            None => eprintln!(
                "SKIP no-reversal forgery: every covered index {indices:?} is a {}-bit \
                 bit-reversal palindrome",
                g.lde
            ),
        }
        // A reduced opening poked for the whole segment: `reduce` on the
        // last input perm, and round 0's select on every register row.
        let c = claim(fx, |_| {}, |b| b.ictx[0].ro += E::ONE);
        let mut expected = perm_rows(fx, 0, l.open_last, "reduce");
        expected.extend(rows(ctx_rows(fx, 0), "select"));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn c2_rejects_fri_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        let g = &l.fg.geom;
        let last = l.queries() - 1;
        // A commit-phase salt changed: only round 1's cap refuses.
        let c = claim(fx, |b| b.fri_ops[1].salts[1][2] += Val::ONE, |_| {});
        refused_exactly(fx, &c, &[(fri_cap_row(fx, 1, 1), "cap")].into());
        // Two siblings of round 0 poked so that the fold is UNCHANGED (it is
        // linear in the group), a fresh salt: only round 0's cap refuses.
        let h = &fx.honest.fctx[0];
        let n = g.arity(0);
        let pos = fx.seam.indices[0].1 % n;
        let w = |i: usize| -> E {
            (0..n).fold(E::ZERO, |acc, k| {
                let tk = if k == 0 { E::ONE } else { h.t[0][k - 1] };
                acc + tk * g.idft[0][k][i]
            })
        };
        let slots: Vec<usize> = (0..n).filter(|&s| s != pos).take(2).collect();
        let (i, j) = (slots[0], slots[1]);
        let di = basis(1);
        let dj = -(w(i) * di) * w(j).inverse();
        let sib = |s: usize| if s < pos { s } else { s - 1 };
        let c = claim(
            fx,
            |b| {
                b.fri_ops[0].sibs[0][sib(i)] += di;
                b.fri_ops[0].sibs[0][sib(j)] += dj;
                b.fri_ops[0].salts[0] = (0..SALT).map(|s| Val::from_usize(s + 11)).collect();
            },
            |_| {},
        );
        assert_eq!(c.build.fctx[0].f, h.f, "the fold does not move");
        refused_exactly(fx, &c, &[(fri_cap_row(fx, 0, 0), "cap")].into());
        // Two siblings of round 0 swapped, the chain re-derived.
        let c = claim(fx, |b| b.fri_ops[0].sibs[0].swap(0, 1), |_| {});
        assert_ne!(c.build.fctx[0].f[1], h.f[1]);
        let expected = consequences(fx, &c.build);
        assert!(expected.contains(&(fri_cap_row(fx, 0, 1), "cap")));
        refused_exactly(fx, &c, &expected);
        // Round 1 folded with round 0's beta, powers and fold consistent.
        let c = claim(fx, |b| b.knobs[last].beta_of[1] = 0, |_| {});
        let mut expected = rows(ctx_rows(fx, last), "fold_pow");
        expected.extend(consequences(fx, &c.build));
        assert!(expected.contains(&(ctx_rows(fx, last).start, "final")));
        refused_exactly(fx, &c, &expected);
        // The value between rounds poked.
        let c = claim(fx, |_| {}, |b| b.fctx[last].f[1] += E::ONE);
        let mut expected = rows(ctx_rows(fx, last), "fold");
        expected.extend(rows(ctx_rows(fx, last), "select"));
        refused_exactly(fx, &c, &expected);
        // The final polynomial 2b-i's transcript test shows consistent
        // (coefficient 5 moved by e_1), public and held: every register row
        // misses it.
        let mut seam = fx.seam.clone();
        seam.final_poly[5] += basis(1);
        let forged = seam.final_poly.clone();
        let c = claim_with(fx, &seam, |b| b.held.final_poly = forged, |_| {});
        refused_exactly(fx, &c, &rows(0..fx.air.height, "final"));
        // A middle cell of the final-x chain poked.
        let c = claim(fx, |_| {}, |b| b.fctx[last].xf[2] += Val::ONE);
        refused_exactly(fx, &c, &rows(ctx_rows(fx, last), "final_x"));
    }

    #[test]
    fn c2_rejects_skipped_and_duplicated_alpha_powers() {
        let fx = fixture();
        let l = &fx.air.layout;
        let alpha = fx.seam.fri_alpha;
        // Duplicated: query 1's last quotient block reuses the previous
        // block's power (the running power not advanced), Ax, ro and the
        // fold chain consistent with it. Refused where p should have
        // stepped — the last row before that block — and downstream.
        let (qb, prev) = (3, 2);
        let n_prev = l.blocks[prev].n();
        let c = claim(
            fx,
            |b| b.skew = Some((1, qb, alpha.exp_u64(n_prev as u64).inverse())),
            |_| {},
        );
        assert_eq!(c.build.powers[1][qb], c.build.powers[1][prev]);
        assert_ne!(c.build.ictx[1].ro, fx.honest.ictx[1].ro);
        let mut expected: Groups = [(last_row(fx, 1, l.blocks[qb].pos - 1), "alpha_pow")].into();
        expected.extend(consequences(fx, &c.build));
        refused_exactly(fx, &c, &expected);
        // Skipped: query 0's trace block (also the last trace block) weights
        // from one power too far, every later block following it. Refused
        // on the step into it, and on its 24 rows by the α^w pin.
        let tb = l.last_trace;
        let c = claim(fx, |b| b.skew = Some((0, tb, alpha)), |_| {});
        assert_eq!(
            c.build.powers[0][tb],
            alpha.exp_u64(l.blocks[tb].k0 as u64 + 1)
        );
        let mut expected: Groups = [(last_row(fx, 0, l.blocks[tb].pos - 1), "alpha_pow")].into();
        expected.extend(perm_rows(fx, 0, l.blocks[tb].pos, "alpha_pow"));
        expected.extend(consequences(fx, &c.build));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn c2_rejects_hand_off_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        let w = fx.air.width;
        let fri = fri_rows(fx, 0);
        // ro handed off poked between the parts: the opening part reduces
        // to the honest ro, the fold part starts from ro + 1. The hold on
        // the hand-off cells refuses at the boundary; round 0's select sees
        // the poked value on every fold row.
        let mut c = claim(fx, |_| {}, |_| {});
        for row in fri.clone() {
            c.trace.values[row * w + fx.air.ro_col] += Val::ONE;
        }
        let mut expected = rows(fri.clone(), "select");
        expected.insert((fri.start - 1, "handoff"));
        refused_exactly(fx, &c, &expected);
        // The fold part's index bits differ from the opening part's: bit
        // S_R (the final x's first bit) flipped on the fold rows only. The
        // hand-off hold refuses at the boundary; on the fold rows the public
        // index, the x chain, both s^-1 chains and the final x read the
        // flip, and so do the two commit-phase levels that read that bit.
        let g = &l.fg.geom;
        let b5 = g.shift[g.rounds()];
        assert_eq!(b5, 5);
        let mut c = claim(fx, |_| {}, |_| {});
        for row in fri.clone() {
            let cell = &mut c.trace.values[row * w + fx.air.bits_col + b5];
            *cell = Val::ONE - *cell;
        }
        let mut expected: Groups = [(fri.start - 1, "handoff")].into();
        for group in ["index", "x_point", "s_inv", "final_x"] {
            expected.extend(rows(fri.clone(), group));
        }
        expected.insert((
            feed_row(fx, 0, Step::Fri(fold::Step::Node(0, b5 - g.shift[1]))),
            "bind_child",
        ));
        expected.insert((
            feed_row(fx, 0, Step::Fri(fold::Step::Node(1, b5 - g.shift[2]))),
            "bind_child",
        ));
        refused_exactly(fx, &c, &expected);
    }

    /// C1's seam for a real leaf of `shape`, computed natively: p3's
    /// challenger through the query PoW (checked) and the query draws, and a
    /// source-order `open_input` sum. It carries the indices of `layout`'s
    /// covered slots, which must be the first ones.
    fn native_seam(proof: &Proof<Config>, pvs: &[Val], shape: Shape, layout: &Layout) -> Seam {
        let cfg = L2_CFG_PROVISIONAL;
        let fri = &proof.opening_proof.1;
        let mut ch = native_through_f2(proof, pvs, shape.log_height());
        let fri_alpha: E = ch.sample_algebra_element();
        let mut betas = vec![];
        for (cm, &wit) in fri
            .commit_phase_commits
            .iter()
            .zip(&fri.commit_pow_witnesses)
        {
            ch.observe(cm.clone());
            assert!(ch.check_witness(0, wit));
            betas.push(ch.sample_algebra_element());
        }
        ch.observe_algebra_slice(&fri.final_poly);
        for &a in &layout.fg.geom.arities {
            ch.observe(Val::from_usize(a));
        }
        assert!(ch.check_witness(cfg.grind_bits, fri.query_pow_witness));
        let n = layout.queries();
        assert_eq!(layout.slots, (0..n).collect::<Vec<_>>(), "the first slots");
        let indices = (0..n).map(|q| (q, ch.sample_bits(layout.lde()))).collect();
        let (az, bz) = native_sums(proof, fri_alpha, None);
        let c = &proof.commitments;
        let mut caps = vec![
            c.trace.roots().to_vec(),
            c.quotient_chunks.roots().to_vec(),
            c.random.as_ref().unwrap().roots().to_vec(),
        ];
        caps.extend(fri.commit_phase_commits.iter().map(|x| x.roots().to_vec()));
        Seam {
            caps,
            zeta: proof_inputs_dims(Dims::from(shape), proof, pvs)
                .unwrap()
                .zeta,
            fri_alpha,
            az,
            bz,
            betas,
            final_poly: fri.final_poly.clone(),
            indices,
        }
    }

    /// The production schedule on a real hiding S3 proof — 25 input leaf
    /// perms and 3 x 19 input levels, then four arity-16 rounds with paths
    /// 15/11/7/3 — for two queries. The proof is the census test's (shared
    /// per test binary); the seam is computed natively (p3's challenger, a
    /// source-order `open_input` sum), and the reduced openings and folds are
    /// checked against 2b-ii's and p3's native verifier code.
    #[test]
    fn c2_accepts_a_real_s3_production_schedule() {
        let (proof, pvs) = crate::f2::s3_proof();
        let shape = Shape::S;
        let cfg = L2_CFG_PROVISIONAL;
        let dims = Dims::from(shape);
        let layout = Layout::new(dims, 8, &cfg, vec![0, 1]).unwrap();
        let seam = native_seam(&proof, &pvs, shape, &layout);
        let (fri_alpha, betas) = (seam.fri_alpha, seam.betas.clone());
        let indices: Vec<usize> = seam.indices.iter().map(|&(_, i)| i).collect();
        let lde = layout.lde();
        assert_eq!(
            (lde, layout.open_last + 1, layout.len(), layout.blocks.len()),
            (22, 82, 126, 25)
        );
        let air = C2Air::new(layout, 64 << 20).unwrap();
        let l = &air.layout;
        let honest = Build::honest(l, &seam, &proof).unwrap();
        for (q, &index) in indices.iter().enumerate() {
            let ro = reduced_opening(
                &proof,
                &pvs,
                dims.width,
                dims.log_height,
                q,
                index,
                fri_alpha,
            );
            assert_eq!(
                honest.ab[q],
                native_sums(&proof, fri_alpha, Some(q)),
                "Ax/Bx {q}"
            );
            assert_eq!(honest.ictx[q].ro, ro, "ro, query {q}");
            let (chain, eval) = native_query_of(&proof, lde, q, index, ro, &betas);
            assert_eq!(eval, chain[chain.len() - 1], "p3's final check, query {q}");
            assert_eq!(honest.fctx[q].f, chain, "folds, query {q}");
            for bt in 0..BATCHES {
                assert_eq!(
                    honest.in_walks[q].roots[bt],
                    seam.caps[open::Geom::cap_block(bt)][index >> (lde - CAP_HEIGHT)]
                );
            }
        }
        let ranges = phase_ranges(&air);
        let pv = air.public_values(&seam).unwrap();
        let trace = air.trace(&honest).unwrap();
        satisfied(&air, &trace, &pv).unwrap_or_else(|v| {
            panic!(
                "honest S3 C2 refused: {v} in {}",
                phase_in(&ranges, v.constraint)
            )
        });
        assert_degree_three(&air, &ranges);
        let price = composed_c2_layout(dims.width, dims.log_height, 8, 2);
        assert_eq!(price["component_columns"], air.width);
        assert_eq!(price["padded_rows"], air.height);
    }

    /// F2b-5 (stage-0's "g_N versus the doubled-domain shift", C2's side):
    /// query 1's reduced opening taken with ζ·g_2N — the committed
    /// domain's generator — in the (Bz − Bx) term. The forger's inv_b, ro and
    /// fold chain are all consistent with it; C2's `inverse` pins
    /// inv_b·(ζ·g_N − x) = 1 with g_N a constant, so it refuses on every
    /// row carrying query 1's registers, and the forged ro misses the
    /// commit-phase leaves and the final polynomial (consequences).
    #[test]
    fn c2_refuses_the_next_point_on_the_doubled_domain() {
        let fx = fixture();
        let l = &fx.air.layout;
        let mut doubled = l.ig.geom.clone();
        doubled.g_n = Val::two_adic_generator(fx.dims.log_height + qlab_consensus::IS_ZK);
        assert_ne!(doubled.g_n, l.ig.geom.g_n);
        let c = claim(
            fx,
            |_| {},
            |b| {
                let held = open::Held {
                    zeta: b.held.zeta,
                    zvals: vec![],
                    fri_alpha: b.held.fri_alpha,
                    apow: vec![],
                    az: b.held.az,
                    bz: b.held.bz,
                    ro: vec![],
                };
                b.ictx[1] =
                    open::Ctx::new(&doubled, b.index[1], b.index[1], &held, b.ab[1]).unwrap();
                b.refold(l, 1).unwrap();
            },
        );
        assert_eq!(c.build.ictx[1].inv_a, fx.honest.ictx[1].inv_a);
        assert_ne!(c.build.ictx[1].ro, fx.honest.ictx[1].ro);
        let mut expected = rows(ctx_rows(fx, 1), "inverse");
        expected.extend(consequences(fx, &c.build));
        refused_exactly(fx, &c, &expected);
    }

    /// F2b-5 (stage-0's "missing/altered randomizer"): a REAL leaf proof
    /// whose randomizer opening at ζ is altered, the query PoW re-ground for
    /// the moved transcript. p3's verifier refuses it. C1, built from it by
    /// `f2wrap`'s builder, is SAT: the machine never reads the randomizer,
    /// which enters only the transcript and Az — so C1 alone cannot see it.
    /// C2, built on that C1's seam (and so passing `check_seams`), refuses
    /// it: its Ax comes from the Merkle-authenticated randomizer rows, the
    /// split ro no longer matches the commit-phase leaves, and the moved
    /// query indices no longer match the openings' paths (consequences).
    #[test]
    fn c2_refuses_a_randomizer_opening_altered_in_the_proof() {
        let fx = fixture();
        let l = &fx.air.layout;
        let cfg = L2_CFG_PROVISIONAL;
        let (pvs, dims) = (fx.sh.pvs, fx.dims);
        let mut proof = copy(fx.sh.proof);
        proof.opened_values.random.as_mut().unwrap()[2] += basis(1);
        regrind(&mut proof, pvs, dims.log_height);
        assert!(p3_uni_stark::verify(&qlab_l2::make_config_l2(), &Toy, &proof, pvs).is_err());
        let program = Program::compile_dims(dims, &Toy).unwrap();
        let inputs = proof_inputs_dims(dims, &proof, pvs).unwrap();
        let c1 = super::super::c1::honest(&program, &inputs, &proof, pvs, &cfg, 64 << 20).unwrap();
        assert!(
            violation_set(&c1.air, &c1.trace, &c1.pvs).is_empty(),
            "C1 is SAT"
        );
        assert_ne!(c1.seam.az, fx.c1.az);
        let seam = Seam {
            indices: l.slots.iter().map(|&s| c1.seam.indices[s]).collect(),
            ..c1.seam.clone()
        };
        let build = Build::honest(l, &seam, &proof).unwrap();
        let c = Claim {
            trace: fx.air.trace(&build).unwrap(),
            pvs: fx.air.public_values(&seam).unwrap(),
            build,
        };
        check_seams(&c1.seam, &Seam::decode(l.seam, &l.slots, &c.pvs).unwrap()).unwrap();
        let expected = consequences(fx, &c.build);
        assert!(
            expected.contains(&(fri_cap_row(fx, 0, 0), "cap")),
            "{expected:?}"
        );
        refused_exactly(fx, &c, &expected);
    }

    /// F2b-5 (stage-0's "P3's additional fold"), called by the census test
    /// on the P3 proof it already proves, so no new prove: C2 for two
    /// queries on P3's production schedule — four arity-16 rounds, then the
    /// fifth, arity-2 round no shape but P3 has. Honest: the reduced
    /// openings and the fold chain are p3's, and the trace is SAT. Then two
    /// negatives on query 0's fifth round, each refused exactly: its salt
    /// changed (only that round's cap check), and its one sibling moved with
    /// the fold re-derived (that cap check, and the final polynomial on the
    /// query's register rows; rounds 0-3 unchanged).
    pub(in crate::f2::ood) fn p3_last_round_negatives(proof: &Proof<Config>, pvs: &[Val]) {
        let shape = Shape::P;
        let cfg = L2_CFG_PROVISIONAL;
        let layout = Layout::new(Dims::from(shape), 8, &cfg, vec![0, 1]).unwrap();
        assert_eq!(layout.fg.geom.arities, vec![4, 4, 4, 4, 1], "P3's schedule");
        let rounds = layout.fg.geom.rounds();
        let last = rounds - 1;
        let seam = native_seam(proof, pvs, shape, &layout);
        let air = C2Air::new(layout, 64 << 20).unwrap();
        let (l, ranges) = (&air.layout, phase_ranges(&air));
        let honest = Build::honest(l, &seam, proof).unwrap();
        for (q, &(_, index)) in seam.indices.iter().enumerate() {
            let ro = reduced_opening(
                proof,
                pvs,
                shape.width(),
                shape.log_height(),
                q,
                index,
                seam.fri_alpha,
            );
            assert_eq!(honest.ictx[q].ro, ro, "ro, query {q}");
            let (chain, eval) = native_query_of(proof, l.lde(), q, index, ro, &seam.betas);
            assert_eq!(eval, chain[chain.len() - 1], "p3's final check, query {q}");
            assert_eq!(honest.fctx[q].f, chain, "folds, query {q}");
        }
        assert!(consequences_in(&air, &seam.caps, &honest).is_empty());
        let pv = air.public_values(&seam).unwrap();
        let trace = air.trace(&honest).unwrap();
        satisfied(&air, &trace, &pv).unwrap_or_else(|v| {
            panic!(
                "honest P3 C2 refused: {v} in {}",
                phase_in(&ranges, v.constraint)
            )
        });
        let forged = |edit: &dyn Fn(&mut Build)| -> (Build, Groups) {
            let mut b = honest.clone();
            edit(&mut b);
            b.settle(l).unwrap();
            let v = scan(&air, &ranges, &air.trace(&b).unwrap(), &pv);
            (b, v)
        };
        let cap = fri_cap_row_in(&air, 0, last);
        let (b, v) = forged(&|b| b.fri_ops[0].salts[last][2] += Val::ONE);
        assert_eq!(b.fctx[0].f, honest.fctx[0].f, "a salt does not fold");
        let expected: Groups = [(cap, "cap")].into();
        assert_eq!(consequences_in(&air, &seam.caps, &b), expected);
        assert_eq!(v, expected, "fifth-round salt");
        assert_eq!(b.fri_ops[0].sibs[last].len(), 1, "arity 2: one sibling");
        let (b, v) = forged(&|b| b.fri_ops[0].sibs[last][0] += basis(1));
        assert_eq!(b.fctx[0].f[..rounds], honest.fctx[0].f[..rounds]);
        assert_ne!(b.fctx[0].f[rounds], honest.fctx[0].f[rounds]);
        let mut expected: Groups = [(cap, "cap")].into();
        expected.extend(rows(seg_in(&air, 0), "final"));
        assert_eq!(consequences_in(&air, &seam.caps, &b), expected);
        assert_eq!(v, expected, "fifth-round sibling");
    }

    const SALT: usize = qlab_consensus::SALT_ELEMS;
}
