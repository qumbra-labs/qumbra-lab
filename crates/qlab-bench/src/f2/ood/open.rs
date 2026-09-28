//! F2b-2b-ii (issue #750): the input-batch openings of the inner verifier's
//! FRI queries, in circuit — salted leaves, Merkle paths to the committed
//! caps, and the reduced opening each query hands to the fold. Test-only
//! component, scanned row by row, never proved.
//!
//! **Native semantics** (p3 0.6.1, the lab's hiding config, rc = 0):
//!
//! - **Batches.** uni-stark `verifier.rs:453-510` builds the opening claims
//!   as randomizer (one matrix, 4 columns, at zeta), trace (one matrix, w
//!   columns, at zeta and zeta * g_N), quotient (8 chunk matrices, 4 columns
//!   each, at zeta). Every matrix is committed at 2N rows (`hiding_pcs.rs`
//!   `commit` doubles the trace, `get_quotient_ldes` extends each chunk by
//!   `log_blowup + 1`, the randomizer is drawn on the 2N domain), so all
//!   three batches sit at ONE LDE height 2^lde, lde = log N + 1 + log_blowup.
//! - **Leaf.** `hiding_mmcs.rs:174-176` appends each matrix row's salt
//!   (`SALT_ELEMS` = 4 field elements); `batch.rs` `verify_batch` hashes all
//!   same-height rows as one stream (`hash_iter_slices`, row ‖ salt per
//!   matrix, in matrix order). The hasher is `SerializingHasher` over
//!   `PaddingFreeSponge<KeccakF, 25, 17, 4>`: field elements become their
//!   Monty words, packed two per u64 low word first, an odd last word alone
//!   (`p3-field integers.rs:494-507`); the sponge OVERWRITES the 17 rate
//!   lanes per block, a short last block keeps the previous output in its
//!   tail lanes, and the digest is lanes 0..3 (`sponge.rs:172-204`).
//! - **Path.** `CompressionFunctionFromHasher<_, 2, 4>`: one fresh sponge
//!   perm over left ‖ right (8 u64). Level t reads index bit t (`index % 2`,
//!   then `index /= 2`); the cap height strips the top 3 levels
//!   (`mod.rs:293-297`) and the cap entry is `index >> path`. With one height
//!   the reduced index is the query index itself (`verifier.rs:687-691`).
//! - **Reduced opening** (`verifier.rs:706-753`): x = GENERATOR *
//!   omega_lde^{rev_lde(index)}; per matrix, per point, per column,
//!   ro += alpha^k (p(z) - p(x)) / (z - x), k one running counter across all
//!   three batches (one height, one counter).
//!
//! **What is constrained**, on one Keccak lane (stock p3-keccak-air):
//!
//! - **Sponge, overwrite mode.** The M bits of a perm's step-0 row ARE its
//!   rate preimage (no S bits: nothing is xored in). Capacity carries on an
//!   interior leaf block and is zero otherwise. A leaf's words are row
//!   values (canonical Monty words, `R^-1 * word` accumulated), salts (free
//!   witness words: hashed, nothing else), zeros, and carried tail lanes
//!   (equal to the previous perm's output lanes).
//! - **Path.** A compression's child slot holds the previous perm's digest,
//!   left or right by the query's index bit; the other half is the sibling,
//!   free. The last digest equals the cap entry a one-hot of the top index
//!   bits selects, against the caps 2a already exports.
//! - **Reduced opening.** Row values accumulate `alpha^k * v` into two
//!   running sums (zeta terms, zeta_next terms) over the query's leaf rows;
//!   at the segment end ro = (Az - Ax)/(zeta - x) + (Bz - Bx)/(zeta_next - x)
//!   with Az, Bz = sum alpha^k z_k once per instance, inverses as
//!   `(z - x) * inv = 1`, and x from the index bits by a bit-reversed chain
//!   of constant factors.
//!
//! **Composition.** Each F2b piece is its own AIR joined by public values:
//! 2a exports zeta and every opened value from the machine's own cells, 2b-i
//! exports fri_alpha and the indices, and here they are PUBLIC INPUTS bound
//! to held cells on row 0 (`opened_in`, `index`). The z-values FRI reads are
//! therefore equal to the ones the machine read, as an equality on each
//! side of one public value; the seam test compares the three components'
//! public values slice by slice.
//!
//! **Uniform layout.** Every query runs the same perm segment; per-query data
//! (index bits, cap one-hot, x chain, inverses, ro) are per-row registers
//! bound to the query's public index by a segment selector, so periodic
//! columns grow with roles, levels and queries, never with perms.
//!
//! **NOT bound here:** the commit-phase openings, the folds and the
//! final-polynomial evaluation — 2b-iii's `fold.rs`, which takes the reduced
//! openings (held cells and public outputs here) as its public inputs.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, FriCfg, CAP_HEIGHT, IS_ZK, SALT_ELEMS};

use super::lane::{monty, Lane, Phased, CAP_WORDS, RATE_BITS, RATE_LANES, RATE_WORDS};
use super::{require, Dims, Result, Val, E};
use crate::m4gaterec::keccakf;

/// Constraint groups, in evaluation order. A negative names the group(s)
/// its violation must land in, on named rows.
const PHASES: [&str; 20] = [
    "keccak",
    "bits",
    "absorb",
    "capacity",
    "bind_zero",
    "bind_carry",
    "bind_child",
    "cap",
    "canonical",
    "accumulate",
    "opened_in",
    "index",
    "cap_select",
    "x_point",
    "inverse",
    "alpha_pow",
    "z_sum",
    "reduce",
    "hold",
    "ro_out",
];

/// Extension limbs.
const D: usize = 4;
/// Native batch order (`coms_to_verify`): randomizer, trace, quotient.
pub(super) const RANDOM: usize = 0;
pub(super) const TRACE: usize = 1;
pub(super) const QUOTIENT: usize = 2;
pub(super) const BATCHES: usize = 3;
/// Rate words a compression's two children occupy (2 x 4 u64).
const CHILD_WORDS: usize = 16;

/// Opening geometry: shape constants only, nothing read from a proof.
#[derive(Clone, Debug)]
pub(super) struct Geom {
    pub(super) width: usize,
    pub(super) chunks: usize,
    /// log2 of every input matrix's LDE height (= query index bits).
    pub(super) lde: usize,
    /// Merkle levels below the cap.
    pub(super) path: usize,
    /// (point, column) terms = opened extension values = fri_alpha powers.
    pub(super) terms: usize,
    /// Generator of the ORIGINAL trace domain: zeta_next = zeta * g_n.
    pub(super) g_n: Val,
}

impl Geom {
    pub(super) fn new(dims: Dims, chunks: usize, cfg: &FriCfg) -> Result<Self> {
        let lde = dims.log_height + IS_ZK + cfg.log_blowup;
        require(lde <= 30, "query index wider than 30 bits")?;
        require(CAP_HEIGHT == 3, "the cap mux is written for 2^3 entries")?;
        require(lde > CAP_HEIGHT, "LDE shorter than the cap")?;
        Ok(Self {
            width: dims.width,
            chunks,
            lde,
            path: lde - CAP_HEIGHT,
            terms: D + 2 * dims.width + D * chunks,
            g_n: Val::two_adic_generator(dims.log_height),
        })
    }

    /// (matrices, columns) of batch `b`.
    pub(super) fn mats(&self, b: usize) -> (usize, usize) {
        match b {
            RANDOM => (1, D),
            TRACE => (1, self.width),
            _ => (self.chunks, D),
        }
    }

    /// The fri_alpha power of column `c` of matrix `m` at point `pt`: the
    /// position of that (matrix, point, column) in `open_input`'s counter,
    /// which is also the position of its z-value in 2a's opened order.
    fn term(&self, b: usize, m: usize, pt: usize, c: usize) -> usize {
        match b {
            RANDOM => c,
            TRACE => D + pt * self.width + c,
            _ => D + 2 * self.width + D * m + c,
        }
    }

    /// 0 for a term opened at zeta, 1 at zeta_next (the trace's second point).
    fn point_of(&self, k: usize) -> usize {
        usize::from((D + self.width..D + 2 * self.width).contains(&k))
    }

    /// 2a exports the caps as trace, quotient, randomizer.
    pub(super) fn cap_block(b: usize) -> usize {
        match b {
            TRACE => 0,
            QUOTIENT => 1,
            _ => 2,
        }
    }
}

/// One 32-bit word of a leaf sponge's rate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Word {
    /// Column `c` of matrix `m`: a canonical Monty word, `R^-1 * word`
    /// accumulated into the reduced opening.
    Row(usize, usize),
    /// Salt element `s` of matrix `m`: a free witness word.
    Salt(usize, usize),
    /// The high word of an odd stream's last u64, or an untouched rate word
    /// of a single-block leaf (the sponge starts from zero).
    Zero,
    /// An untouched rate word of a later, short block: the previous output.
    Carry,
}

/// Leaf words of one batch: row ‖ salt per matrix, packed two words per
/// u64, padded to whole blocks of `RATE_WORDS`.
pub(super) fn leaf_words(mats: usize, cols: usize) -> Vec<Word> {
    let mut words = Vec::new();
    for m in 0..mats {
        words.extend((0..cols).map(|c| Word::Row(m, c)));
        words.extend((0..SALT_ELEMS).map(|s| Word::Salt(m, s)));
    }
    if words.len() % 2 == 1 {
        words.push(Word::Zero);
    }
    let blocks = words.len().div_ceil(RATE_WORDS);
    let fill = if blocks == 1 { Word::Zero } else { Word::Carry };
    words.resize(blocks * RATE_WORDS, fill);
    words
}

/// One perm of a query segment.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Step {
    /// Block `k` of batch `b`'s leaf sponge.
    Leaf(usize, usize),
    /// Path level `t` of batch `b`.
    Node(usize, usize),
}

/// Static layout: one segment of perms per covered query.
#[derive(Clone)]
pub(super) struct Layout {
    pub(super) geom: Geom,
    pub(super) leaves: [Vec<Word>; BATCHES],
    /// (batch, block) of every leaf-block role.
    pub(super) roles: Vec<(usize, usize)>,
    /// Roles whose block carries tail lanes from the previous output.
    pub(super) carry_roles: Vec<usize>,
    pub(super) segment: Vec<Step>,
    pub(super) queries: usize,
}

impl Layout {
    pub(super) fn new(geom: Geom, queries: usize) -> Self {
        let leaves: [Vec<Word>; BATCHES] = core::array::from_fn(|b| {
            let (mats, cols) = geom.mats(b);
            leaf_words(mats, cols)
        });
        let mut roles = Vec::new();
        let mut segment = Vec::new();
        for (b, leaf) in leaves.iter().enumerate() {
            for k in 0..leaf.len() / RATE_WORDS {
                roles.push((b, k));
                segment.push(Step::Leaf(b, k));
            }
            segment.extend((0..geom.path).map(|t| Step::Node(b, t)));
        }
        let carry_roles = (0..roles.len())
            .filter(|&r| {
                let (b, k) = roles[r];
                leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)].contains(&Word::Carry)
            })
            .collect();
        Self {
            geom,
            leaves,
            roles,
            carry_roles,
            segment,
            queries,
        }
    }

    fn role(&self, b: usize, k: usize) -> usize {
        self.roles.iter().position(|&x| x == (b, k)).unwrap()
    }
    pub(super) fn role_words(&self, r: usize) -> &[Word] {
        let (b, k) = self.roles[r];
        &self.leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)]
    }
    /// Rate lanes of role `r` that carry the previous output.
    pub(super) fn carry_lanes(&self, r: usize) -> Vec<usize> {
        let words = self.role_words(r);
        (0..RATE_LANES)
            .filter(|&ln| words[2 * ln] == Word::Carry)
            .collect()
    }
    fn perms(&self) -> usize {
        self.queries * self.segment.len()
    }
    fn step(&self, perm: usize) -> Step {
        self.segment[perm % self.segment.len()]
    }
    fn seg_rows(&self) -> usize {
        NUM_ROUNDS * self.segment.len()
    }
    /// Position of `step` in the segment.
    fn at(&self, step: Step) -> usize {
        self.segment.iter().position(|&s| s == step).unwrap()
    }

    // Public values: caps (2a's order and limbs), zeta, z-values (2a's
    // opened order), fri_alpha, covered indices; then the outputs.
    fn cap_pv(&self, block: usize, j: usize, lane: usize, l: usize) -> usize {
        2 * CAP_WORDS * block + 16 * j + 4 * lane + l
    }
    fn zeta_pv(&self) -> usize {
        6 * CAP_WORDS
    }
    fn zval_pv(&self, k: usize) -> usize {
        self.zeta_pv() + D + D * k
    }
    fn alpha_pv(&self) -> usize {
        self.zval_pv(self.geom.terms)
    }
    fn index_pv(&self, q: usize) -> usize {
        self.alpha_pv() + D + q
    }
    fn ro_pv(&self, q: usize) -> usize {
        self.index_pv(self.queries) + D * q
    }
    fn num_public_values(&self) -> usize {
        self.ro_pv(self.queries)
    }
}

/// One query's claimed input opening, as the proof carries it.
#[derive(Clone)]
pub(super) struct Opening {
    pub(super) rows: [Vec<Vec<Val>>; BATCHES],
    pub(super) salts: [Vec<Vec<Val>>; BATCHES],
    pub(super) siblings: [Vec<[u64; 4]>; BATCHES],
}

impl Opening {
    pub(super) fn from_proof(proof: &Proof<Config>, query: usize, geom: &Geom) -> Result<Self> {
        let qp = proof
            .opening_proof
            .1
            .query_proofs
            .get(query)
            .ok_or("query out of range")?;
        require(qp.input_proof.len() == BATCHES, "input batch count")?;
        let mut op = Self {
            rows: Default::default(),
            salts: Default::default(),
            siblings: Default::default(),
        };
        for b in 0..BATCHES {
            let batch = &qp.input_proof[b];
            let (salts, siblings) = &batch.opening_proof;
            let (mats, cols) = geom.mats(b);
            require(
                batch.opened_values.len() == mats
                    && batch.opened_values.iter().all(|r| r.len() == cols),
                "opened row shape",
            )?;
            require(
                salts.len() == mats && salts.iter().all(|s| s.len() == SALT_ELEMS),
                "salt shape",
            )?;
            require(siblings.len() == geom.path, "input path length")?;
            op.rows[b] = batch.opened_values.clone();
            op.salts[b] = salts.clone();
            op.siblings[b] = siblings.clone();
        }
        Ok(op)
    }

    /// The word a leaf slot absorbs; `None` for a carried tail word.
    fn word(&self, b: usize, w: Word) -> Option<u32> {
        match w {
            Word::Row(m, c) => Some(monty(self.rows[b][m][c])),
            Word::Salt(m, s) => Some(monty(self.salts[b][m][s])),
            Word::Zero => Some(0),
            Word::Carry => None,
        }
    }
}

/// The native Merkle replay of one opening: every perm's preimage, in
/// segment order, and each batch's root.
#[derive(Clone)]
pub(super) struct Walk {
    pub(super) perms: Vec<[u64; 25]>,
    pub(super) roots: [[u64; 4]; BATCHES],
}

impl Walk {
    /// `flip` puts the child on the wrong side at (batch, level) while the
    /// index bit stays: a forgery knob.
    pub(super) fn new(
        layout: &Layout,
        op: &Opening,
        index: usize,
        flip: Option<(usize, usize)>,
    ) -> Self {
        let mut perms = Vec::with_capacity(layout.segment.len());
        let mut roots = [[0u64; 4]; BATCHES];
        for (b, leaf) in layout.leaves.iter().enumerate() {
            let mut state = [0u64; 25];
            for block in leaf.chunks(RATE_WORDS) {
                for ln in 0..RATE_LANES {
                    if let (Some(lo), Some(hi)) =
                        (op.word(b, block[2 * ln]), op.word(b, block[2 * ln + 1]))
                    {
                        state[ln] = u64::from(lo) | (u64::from(hi) << 32);
                    }
                }
                perms.push(state);
                state = keccakf(&state);
            }
            let mut cur: [u64; 4] = state[..4].try_into().unwrap();
            for t in 0..layout.geom.path {
                let right = ((index >> t) & 1 == 1) ^ (flip == Some((b, t)));
                let sib = op.siblings[b][t];
                let (l, r) = if right { (sib, cur) } else { (cur, sib) };
                let mut st = [0u64; 25];
                st[..4].copy_from_slice(&l);
                st[4..8].copy_from_slice(&r);
                perms.push(st);
                cur = keccakf(&st)[..4].try_into().unwrap();
            }
            roots[b] = cur;
        }
        Self { perms, roots }
    }
}

/// What this component takes from 2a and 2b-i: its public inputs.
#[derive(Clone)]
struct Inbound {
    /// Input caps in native batch order (randomizer, trace, quotient).
    caps: [Vec<[u64; 4]>; BATCHES],
    zeta: E,
    /// z-values in 2a's opened order (= term order).
    zvals: Vec<E>,
    fri_alpha: E,
    /// The covered queries' indices.
    indices: Vec<usize>,
}

/// Held cells: constant over every row.
#[derive(Clone)]
pub(super) struct Held {
    pub(super) zeta: E,
    pub(super) zvals: Vec<E>,
    pub(super) fri_alpha: E,
    pub(super) apow: Vec<E>,
    pub(super) az: E,
    pub(super) bz: E,
    pub(super) ro: Vec<E>,
}

/// One covered query's registers, repeated on every row of its segment.
#[derive(Clone)]
pub(super) struct Ctx {
    pub(super) bits: Vec<Val>,
    pub(super) u: [Val; 4],
    pub(super) e: [Val; 8],
    pub(super) xs: Vec<Val>,
    pub(super) inv_a: E,
    pub(super) inv_b: E,
    pub(super) ro: E,
}

/// The x-chain factors: bit t of the index moves x by omega^{2^{lde-1-t}},
/// which is the bit-reversal `open_input` applies to the index.
pub(super) fn x_factors(geom: &Geom) -> Vec<Val> {
    let w = Val::two_adic_generator(geom.lde);
    (0..geom.lde)
        .map(|t| w.exp_power_of_2(geom.lde - 1 - t))
        .collect()
}

impl Ctx {
    /// Registers for bits of `index` and an x chain walked on `x_index`'s
    /// bits (the same index for an honest query).
    pub(super) fn new(
        geom: &Geom,
        index: usize,
        x_index: usize,
        held: &Held,
        ab: (E, E),
    ) -> Result<Self> {
        let bit = |i: usize, t: usize| Val::from_usize((i >> t) & 1);
        let bits: Vec<Val> = (0..geom.lde).map(|t| bit(index, t)).collect();
        let f = |set: bool, p: Val| if set { p } else { Val::ONE - p };
        let p = |u: usize| bits[geom.path + u];
        let u: [Val; 4] = core::array::from_fn(|j| f(j & 1 != 0, p(0)) * f(j & 2 != 0, p(1)));
        let e: [Val; 8] = core::array::from_fn(|j| u[j & 3] * f(j & 4 != 0, p(2)));
        let factors = x_factors(geom);
        let mut xs = Vec::with_capacity(geom.lde);
        let mut x = Val::GENERATOR;
        for (t, c) in factors.iter().enumerate() {
            x *= Val::ONE + bit(x_index, t) * (*c - Val::ONE);
            xs.push(x);
        }
        let inv_a = (held.zeta - E::from(x))
            .try_inverse()
            .ok_or("x equals zeta")?;
        let inv_b = (held.zeta * geom.g_n - E::from(x))
            .try_inverse()
            .ok_or("x equals zeta_next")?;
        let ro = (held.az - ab.0) * inv_a + (held.bz - ab.1) * inv_b;
        Ok(Self {
            bits,
            u,
            e,
            xs,
            inv_a,
            inv_b,
            ro,
        })
    }
}

/// A claim the outer prover assembles: openings, claimed indices, held
/// cells, and everything derived from them. `settle` derives; tests edit
/// before it (forger's inputs, re-derived consistently) or after it (a
/// single poked value).
#[derive(Clone)]
struct Build {
    ops: Vec<Opening>,
    /// The index each segment's registers and placement follow.
    index: Vec<usize>,
    flips: Vec<Option<(usize, usize)>>,
    held: Held,
    ctx: Vec<Ctx>,
    walks: Vec<Walk>,
}

impl Build {
    fn honest(layout: &Layout, inb: &Inbound, ops: Vec<Opening>) -> Result<Self> {
        require(ops.len() == layout.queries, "one opening per covered query")?;
        let mut b = Self {
            index: inb.indices.clone(),
            flips: vec![None; ops.len()],
            ops,
            held: Held {
                zeta: inb.zeta,
                zvals: inb.zvals.clone(),
                fri_alpha: inb.fri_alpha,
                apow: vec![],
                az: E::ZERO,
                bz: E::ZERO,
                ro: vec![],
            },
            ctx: vec![],
            walks: vec![],
        };
        b.settle(layout)?;
        Ok(b)
    }

    /// Accumulated sums (Ax, Bx) of one opening's row values.
    fn sums(layout: &Layout, op: &Opening, apow: &[E]) -> (E, E) {
        let g = &layout.geom;
        let (mut a, mut bx) = (E::ZERO, E::ZERO);
        for b in 0..BATCHES {
            for (m, row) in op.rows[b].iter().enumerate() {
                for (c, &v) in row.iter().enumerate() {
                    a += apow[g.term(b, m, 0, c)] * v;
                    if b == TRACE {
                        bx += apow[g.term(b, m, 1, c)] * v;
                    }
                }
            }
        }
        (a, bx)
    }

    /// Re-derive everything from the openings, claimed indices, zeta,
    /// z-values and fri_alpha.
    fn settle(&mut self, layout: &Layout) -> Result<()> {
        let g = &layout.geom;
        let h = &mut self.held;
        h.apow = (0..g.terms)
            .scan(E::ONE, |p, _| {
                let cur = *p;
                *p *= h.fri_alpha;
                Some(cur)
            })
            .collect();
        let (mut az, mut bz) = (E::ZERO, E::ZERO);
        for k in 0..g.terms {
            let t = h.apow[k] * h.zvals[k];
            if g.point_of(k) == 0 {
                az += t;
            } else {
                bz += t;
            }
        }
        (h.az, h.bz) = (az, bz);
        self.walks.clear();
        self.ctx.clear();
        for (q, op) in self.ops.iter().enumerate() {
            self.walks
                .push(Walk::new(layout, op, self.index[q], self.flips[q]));
            let ab = Self::sums(layout, op, &self.held.apow);
            self.ctx
                .push(Ctx::new(g, self.index[q], self.index[q], &self.held, ab)?);
        }
        self.held.ro = self.ctx.iter().map(|c| c.ro).collect();
        Ok(())
    }
}

/// The input-opening component: lane + Merkle/sponge binding + the reduced
/// opening. One segment of perms per covered query.
#[derive(Clone)]
struct OpenAir {
    layout: Layout,
    lane: Lane,
    height: usize,
    canon_col: usize,
    acc_col: usize,
    ctx_col: usize,
    held_col: usize,
    width: usize,
    // Periodic offsets.
    step0_per: usize,
    interior_per: usize,
    comp0_per: usize,
    segend_per: usize,
    leaf_per: usize,
    carry_per: usize,
    lvl_per: usize,
    capchk_per: usize,
    seg_per: usize,
    periodic: Vec<Vec<Val>>,
    rinv: Val,
    /// (e_i * e_j) in basis limbs: extension multiplication as base terms.
    mul: [[[Val; D]; D]; D],
    x_factors: Vec<Val>,
}

impl OpenAir {
    fn new(layout: Layout, max_cells: usize) -> Result<Self> {
        let g = layout.geom.clone();
        let lane = Lane::new();
        // No S bits: the MMCS sponge overwrites, so M is the rate preimage.
        let canon_col = lane.m_col + RATE_BITS;
        let acc_col = canon_col + 2 * RATE_WORDS;
        let ctx_col = acc_col + 2 * D;
        let held_col = ctx_col + 2 * g.lde + 24;
        let width = held_col + 4 * D + 2 * D * g.terms + D * layout.queries;
        let perms = layout.perms();
        let height = (perms * NUM_ROUNDS).next_power_of_two();
        let (step0_per, interior_per, comp0_per, segend_per) = (0, 1, 2, 3);
        let leaf_per = 4;
        let carry_per = leaf_per + layout.roles.len();
        let lvl_per = carry_per + layout.carry_roles.len();
        let capchk_per = lvl_per + g.path;
        let seg_per = capchk_per + BATCHES;
        let num_periodic = seg_per + layout.queries;
        let cells = height
            .checked_mul(width + num_periodic)
            .ok_or("input opening allocation overflow")?;
        require(
            cells <= max_cells,
            "input openings exceed materialization budget",
        )?;
        let mut periodic = vec![vec![Val::ZERO; height]; num_periodic];
        let last = |p: usize| NUM_ROUNDS * p + NUM_ROUNDS - 1;
        for p in 0..perms {
            periodic[step0_per][NUM_ROUNDS * p] = Val::ONE;
            match layout.step(p) {
                Step::Leaf(b, k) => {
                    periodic[leaf_per + layout.role(b, k)][NUM_ROUNDS * p] = Val::ONE;
                }
                Step::Node(b, t) => {
                    periodic[comp0_per][NUM_ROUNDS * p] = Val::ONE;
                    if t + 1 == g.path {
                        periodic[capchk_per + b][last(p)] = Val::ONE;
                    }
                }
            }
            if p + 1 < perms {
                match layout.step(p + 1) {
                    Step::Leaf(b, k) if k > 0 => {
                        periodic[interior_per][last(p)] = Val::ONE;
                        let r = layout.role(b, k);
                        if let Some(ci) = layout.carry_roles.iter().position(|&x| x == r) {
                            periodic[carry_per + ci][last(p)] = Val::ONE;
                        }
                    }
                    Step::Node(_, t) => periodic[lvl_per + t][last(p)] = Val::ONE,
                    Step::Leaf(..) => {}
                }
            }
        }
        let seg = layout.seg_rows();
        for q in 0..layout.queries {
            periodic[segend_per][(q + 1) * seg - 1] = Val::ONE;
            periodic[seg_per + q][q * seg..(q + 1) * seg].fill(Val::ONE);
        }
        let basis = |i: usize| <E as BasedVectorSpace<Val>>::ith_basis_element(i).unwrap();
        let mul = core::array::from_fn(|i| {
            core::array::from_fn(|j| {
                let p = basis(i) * basis(j);
                core::array::from_fn(|k| p.as_basis_coefficients_slice()[k])
            })
        });
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            x_factors: x_factors(&g),
            height,
            lane,
            canon_col,
            acc_col,
            ctx_col,
            held_col,
            width,
            step0_per,
            interior_per,
            comp0_per,
            segend_per,
            leaf_per,
            carry_per,
            lvl_per,
            capchk_per,
            seg_per,
            periodic,
            rinv: r.inverse(),
            mul,
            layout,
        })
    }

    // Register columns (per row, one query's context).
    fn bit_col(&self, t: usize) -> usize {
        self.ctx_col + t
    }
    fn u_col(&self, j: usize) -> usize {
        self.ctx_col + self.layout.geom.lde + j
    }
    fn e_col(&self, j: usize) -> usize {
        self.u_col(4) + j
    }
    fn x_col(&self, t: usize) -> usize {
        self.e_col(8) + t
    }
    fn inv_a_col(&self) -> usize {
        self.x_col(self.layout.geom.lde)
    }
    fn inv_b_col(&self) -> usize {
        self.inv_a_col() + D
    }
    fn ro_reg_col(&self) -> usize {
        self.inv_b_col() + D
    }
    // Held columns (constant over all rows).
    fn zeta_col(&self) -> usize {
        self.held_col
    }
    fn zval_col(&self, k: usize) -> usize {
        self.held_col + D + D * k
    }
    fn alpha_col(&self) -> usize {
        self.zval_col(self.layout.geom.terms)
    }
    fn apow_col(&self, k: usize) -> usize {
        self.alpha_col() + D + D * k
    }
    fn az_col(&self) -> usize {
        self.apow_col(self.layout.geom.terms)
    }
    fn bz_col(&self) -> usize {
        self.az_col() + D
    }
    fn ro_col(&self, q: usize) -> usize {
        self.bz_col() + D + D * q
    }

    /// Row-value contributions of one leaf step-0 row: (Ax, Bx) terms.
    fn contrib(&self, b: usize, k: usize, pre: &[u64; 25], apow: &[E]) -> (E, E) {
        let g = &self.layout.geom;
        let words = &self.layout.leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)];
        let (mut a, mut bx) = (E::ZERO, E::ZERO);
        for (slot, &w) in words.iter().enumerate() {
            if let Word::Row(m, c) = w {
                let word = (pre[slot / 2] >> (32 * (slot % 2))) as u32;
                let v = Val::from_u32(word) * self.rinv;
                a += apow[g.term(b, m, 0, c)] * v;
                if b == TRACE {
                    bx += apow[g.term(b, m, 1, c)] * v;
                }
            }
        }
        (a, bx)
    }

    fn trace(&self, build: &Build) -> Result<RowMajorMatrix<Val>> {
        let (h, w) = (self.height, self.width);
        let layout = &self.layout;
        let q_n = layout.queries;
        require(
            build.walks.len() == q_n && build.ctx.len() == q_n,
            "one walk and context per query",
        )?;
        require(
            build
                .walks
                .iter()
                .all(|x| x.perms.len() == layout.segment.len()),
            "walk perm count",
        )?;
        let perms: Vec<[u64; 25]> = build.walks.iter().flat_map(|x| x.perms.clone()).collect();
        let mut values = self.lane.trace(&perms, h, w)?;
        let mut contrib = vec![(E::ZERO, E::ZERO); h];
        for (p, pre) in perms.iter().enumerate() {
            let row = NUM_ROUNDS * p;
            for ln in 0..RATE_LANES {
                for bit in 0..64 {
                    values[row * w + self.lane.m_col + 64 * ln + bit] =
                        Val::from_u64((pre[ln] >> bit) & 1);
                }
            }
            if let Step::Leaf(b, k) = layout.step(p) {
                let words = &layout.leaves[b][RATE_WORDS * k..RATE_WORDS * (k + 1)];
                for (slot, &word) in words.iter().enumerate() {
                    if matches!(word, Word::Row(..)) {
                        let v = (pre[slot / 2] >> (32 * (slot % 2))) as u32;
                        Lane::fill_canonical(&mut values, row * w + self.canon_col + 2 * slot, v);
                    }
                }
                contrib[row] = self.contrib(b, k, pre, &build.held.apow);
            }
        }
        let hd = &build.held;
        let mut held = vec![Val::ZERO; w - self.held_col];
        let mut put = |col: usize, v: E| {
            let at = col - self.held_col;
            held[at..at + D].copy_from_slice(v.as_basis_coefficients_slice());
        };
        put(self.zeta_col(), hd.zeta);
        for (k, &z) in hd.zvals.iter().enumerate() {
            put(self.zval_col(k), z);
        }
        put(self.alpha_col(), hd.fri_alpha);
        for (k, &a) in hd.apow.iter().enumerate() {
            put(self.apow_col(k), a);
        }
        put(self.az_col(), hd.az);
        put(self.bz_col(), hd.bz);
        for (q, &r) in hd.ro.iter().enumerate() {
            put(self.ro_col(q), r);
        }
        let seg = layout.seg_rows();
        let (mut acc_a, mut acc_b) = (E::ZERO, E::ZERO);
        for row in 0..h {
            let cells = &mut values[row * w..(row + 1) * w];
            cells[self.held_col..].copy_from_slice(&held);
            let ctx = &build.ctx[(row / seg).min(q_n - 1)];
            let mut set = |col: usize, v: E| {
                cells[col..col + D].copy_from_slice(v.as_basis_coefficients_slice())
            };
            set(self.acc_col, acc_a);
            set(self.acc_col + D, acc_b);
            set(self.inv_a_col(), ctx.inv_a);
            set(self.inv_b_col(), ctx.inv_b);
            set(self.ro_reg_col(), ctx.ro);
            for t in 0..layout.geom.lde {
                cells[self.bit_col(t)] = ctx.bits[t];
                cells[self.x_col(t)] = ctx.xs[t];
            }
            for j in 0..4 {
                cells[self.u_col(j)] = ctx.u[j];
            }
            for j in 0..8 {
                cells[self.e_col(j)] = ctx.e[j];
            }
            let end = self.periodic[self.segend_per][row] == Val::ONE;
            if end {
                (acc_a, acc_b) = (E::ZERO, E::ZERO);
            }
            acc_a += contrib[row].0;
            acc_b += contrib[row].1;
        }
        Ok(RowMajorMatrix::new(values, w))
    }

    /// Public values: the inputs as 2a / 2b-i export them, then the claimed
    /// reduced openings.
    fn public_values(&self, inb: &Inbound, ro: &[E]) -> Vec<Val> {
        let mut pv = Vec::with_capacity(self.layout.num_public_values());
        for b in [TRACE, QUOTIENT, RANDOM] {
            for n in 0..CAP_WORDS {
                let word = (inb.caps[b][n / 8][(n % 8) / 2] >> (32 * (n % 2))) as u32;
                pv.extend([Val::from_u32(word & 0xffff), Val::from_u32(word >> 16)]);
            }
        }
        pv.extend_from_slice(inb.zeta.as_basis_coefficients_slice());
        for z in &inb.zvals {
            pv.extend_from_slice(z.as_basis_coefficients_slice());
        }
        pv.extend_from_slice(inb.fri_alpha.as_basis_coefficients_slice());
        pv.extend(inb.indices.iter().map(|&i| Val::from_usize(i)));
        for r in ro {
            pv.extend_from_slice(r.as_basis_coefficients_slice());
        }
        pv
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

impl Phased for OpenAir {
    fn phases(&self) -> &'static [&'static str] {
        &PHASES
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let (lane, layout, g) = (&self.lane, &self.layout, &self.layout.geom);
        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let leaf = |r: usize| per[self.leaf_per + r].clone();
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let roles: Vec<usize> = (0..layout.roles.len())
                        .filter(|&r| matches!(layout.role_words(r)[slot], Word::Row(..)))
                        .collect();
                    if roles.is_empty() {
                        continue;
                    }
                    let gate = roles.iter().fold(AB::Expr::ZERO, |acc, &r| acc + leaf(r));
                    lane.eval_canonical(builder, slot, gate, self.canon_col);
                }
                return;
            }
            _ => {}
        }
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { next[i].into() };
        let ext = |col: usize| -> [AB::Expr; D] { core::array::from_fn(|i| c(col + i)) };
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let k = &lane.kc;
        let one = || AB::Expr::ONE;
        let (lde, terms, queries) = (g.lde, g.terms, layout.queries);
        match PHASES[phase] {
            "bits" => {
                for i in 0..RATE_BITS {
                    builder.assert_bool(cur[lane.m_col + i]);
                }
            }
            "absorb" => {
                // Overwrite sponge: the rate preimage IS the message.
                let s0 = per[self.step0_per].clone();
                for ln in 0..RATE_LANES {
                    for l in 0..4 {
                        let bits = (0..16).fold(AB::Expr::ZERO, |acc, t| {
                            acc + c(lane.m_col + 64 * ln + 16 * l + t) * lane.pow2[t]
                        });
                        builder.assert_zero(s0.clone() * (c(k.pre[ln][l]) - bits));
                    }
                }
            }
            "capacity" => {
                // Carried into an interior leaf block, zero into every other
                // perm (a fresh leaf sponge, a fresh compression).
                let fin = c(k.fin);
                let inter = per[self.interior_per].clone();
                for ln in RATE_LANES..25 {
                    for l in 0..4 {
                        builder.when_transition().assert_zero(
                            fin.clone() * (n(k.pre[ln][l]) - inter.clone() * c(k.out[ln][l])),
                        );
                        builder.when_first_row().assert_zero(c(k.pre[ln][l]));
                    }
                }
            }
            "bind_zero" => {
                for slot in 0..RATE_WORDS {
                    let mut gate: Option<AB::Expr> =
                        (slot >= CHILD_WORDS).then(|| per[self.comp0_per].clone());
                    for r in 0..layout.roles.len() {
                        if layout.role_words(r)[slot] == Word::Zero {
                            gate = Some(gate.map_or(leaf(r), |x| x + leaf(r)));
                        }
                    }
                    if let Some(gate) = gate {
                        for h in 0..2 {
                            builder.assert_zero(gate.clone() * lane.half::<AB>(cur, slot, h));
                        }
                    }
                }
            }
            "bind_carry" => {
                // A short interior block keeps the previous output in its
                // tail lanes (`sponge.rs:186-194`).
                for (ci, &r) in layout.carry_roles.iter().enumerate() {
                    let gate = per[self.carry_per + ci].clone();
                    for ln in layout.carry_lanes(r) {
                        for l in 0..4 {
                            builder
                                .when_transition()
                                .assert_zero(gate.clone() * (n(k.pre[ln][l]) - c(k.out[ln][l])));
                        }
                    }
                }
            }
            "bind_child" => {
                // Level t: the digest just produced sits left when index bit
                // t is 0, right when it is 1; the other half is the sibling.
                for t in 0..g.path {
                    let gate = per[self.lvl_per + t].clone();
                    let b = c(self.bit_col(t));
                    for j in 0..4 {
                        for l in 0..4 {
                            let out = c(k.out[j][l]);
                            let left = n(k.pre[j][l]) - out.clone();
                            let right = n(k.pre[4 + j][l]) - out;
                            builder.when_transition().assert_zero(
                                gate.clone() * ((one() - b.clone()) * left + b.clone() * right),
                            );
                        }
                    }
                }
            }
            "cap" => {
                for b in 0..BATCHES {
                    let gate = per[self.capchk_per + b].clone();
                    let block = Geom::cap_block(b);
                    for ln in 0..4 {
                        for l in 0..4 {
                            let sum = (0..8).fold(AB::Expr::ZERO, |acc, j| {
                                acc + c(self.e_col(j))
                                    * (c(k.out[ln][l]) - pv[layout.cap_pv(block, j, ln, l)].clone())
                            });
                            builder.assert_zero(gate.clone() * sum);
                        }
                    }
                }
            }
            "accumulate" => {
                // acc' = acc (reset after a segment end) + alpha^k * v over
                // this row's leaf words: Ax on zeta terms, Bx on zeta_next.
                let keep = one() - per[self.segend_per].clone();
                for (which, base) in [(0, self.acc_col), (1, self.acc_col + D)] {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(c(base + limb));
                        let mut contrib = AB::Expr::ZERO;
                        for r in 0..layout.roles.len() {
                            let (b, _) = layout.roles[r];
                            if which == 1 && b != TRACE {
                                continue;
                            }
                            let mut inner = AB::Expr::ZERO;
                            for (slot, &w) in layout.role_words(r).iter().enumerate() {
                                if let Word::Row(m, col) = w {
                                    let kk = g.term(b, m, which, col);
                                    inner +=
                                        c(self.apow_col(kk) + limb) * lane.full::<AB>(cur, slot);
                                }
                            }
                            contrib += leaf(r) * inner * self.rinv;
                        }
                        builder
                            .when_transition()
                            .assert_zero(n(base + limb) - keep.clone() * c(base + limb) - contrib);
                    }
                }
            }
            "opened_in" => {
                // 2a's exports and 2b-i's fri_alpha: the same values, not a
                // second supply (this is the equality the seam rests on).
                let mut first = |col: usize, at: usize| {
                    for limb in 0..D {
                        builder
                            .when_first_row()
                            .assert_zero(c(col + limb) - pv[at + limb].clone());
                    }
                };
                first(self.zeta_col(), layout.zeta_pv());
                for kk in 0..terms {
                    first(self.zval_col(kk), layout.zval_pv(kk));
                }
                first(self.alpha_col(), layout.alpha_pv());
            }
            "index" => {
                for t in 0..lde {
                    builder.assert_bool(cur[self.bit_col(t)]);
                }
                let index = (0..lde).fold(AB::Expr::ZERO, |acc, t| {
                    acc + c(self.bit_col(t)) * lane.pow2[t]
                });
                for q in 0..queries {
                    builder.assert_zero(
                        per[self.seg_per + q].clone()
                            * (index.clone() - pv[layout.index_pv(q)].clone()),
                    );
                }
            }
            "cap_select" => {
                // One-hot of the cap index = index >> path.
                let p = |u: usize| c(self.bit_col(g.path + u));
                let f = |set: bool, x: AB::Expr| if set { x } else { one() - x };
                for j in 0..4 {
                    builder
                        .assert_zero(c(self.u_col(j)) - f(j & 1 != 0, p(0)) * f(j & 2 != 0, p(1)));
                }
                for j in 0..8 {
                    builder
                        .assert_zero(c(self.e_col(j)) - c(self.u_col(j & 3)) * f(j & 4 != 0, p(2)));
                }
            }
            "x_point" => {
                // x = GENERATOR * prod_t (omega^{2^{lde-1-t}})^{bit_t}: the
                // bit-reversed index, one constant factor per bit.
                let factor = |t: usize| one() + c(self.bit_col(t)) * (self.x_factors[t] - Val::ONE);
                builder.assert_zero(c(self.x_col(0)) - factor(0) * Val::GENERATOR);
                for t in 1..lde {
                    builder.assert_zero(c(self.x_col(t)) - c(self.x_col(t - 1)) * factor(t));
                }
            }
            "inverse" => {
                let x = c(self.x_col(lde - 1));
                let z = ext(self.zeta_col());
                let mut za = z.clone();
                za[0] = za[0].clone() - x.clone();
                let mut zb: [AB::Expr; D] = core::array::from_fn(|i| z[i].clone() * g.g_n);
                zb[0] = zb[0].clone() - x;
                for (lhs, inv) in [(za, self.inv_a_col()), (zb, self.inv_b_col())] {
                    let prod = self.ext_mul::<AB>(&lhs, &ext(inv));
                    for (limb, p) in prod.into_iter().enumerate() {
                        let target = if limb == 0 { one() } else { AB::Expr::ZERO };
                        builder.assert_zero(p - target);
                    }
                }
            }
            "alpha_pow" => {
                for limb in 0..D {
                    let target = if limb == 0 { one() } else { AB::Expr::ZERO };
                    builder
                        .when_first_row()
                        .assert_zero(c(self.apow_col(0) + limb) - target);
                }
                let alpha = ext(self.alpha_col());
                for kk in 0..terms - 1 {
                    let prod = self.ext_mul::<AB>(&ext(self.apow_col(kk)), &alpha);
                    for (limb, p) in prod.into_iter().enumerate() {
                        builder
                            .when_first_row()
                            .assert_zero(c(self.apow_col(kk + 1) + limb) - p);
                    }
                }
            }
            "z_sum" => {
                for (point, col) in [(0, self.az_col()), (1, self.bz_col())] {
                    let mut sum: [AB::Expr; D] = core::array::from_fn(|_| AB::Expr::ZERO);
                    for kk in (0..terms).filter(|&kk| g.point_of(kk) == point) {
                        let prod =
                            self.ext_mul::<AB>(&ext(self.apow_col(kk)), &ext(self.zval_col(kk)));
                        for (s, p) in sum.iter_mut().zip(prod) {
                            *s += p;
                        }
                    }
                    for (limb, s) in sum.into_iter().enumerate() {
                        builder.when_first_row().assert_zero(c(col + limb) - s);
                    }
                }
            }
            "reduce" => {
                // ro = (Az - Ax)/(zeta - x) + (Bz - Bx)/(zeta_next - x) on
                // the segment's last row, where the sums are complete.
                let end = per[self.segend_per].clone();
                let diff = |held: usize, acc: usize| -> [AB::Expr; D] {
                    core::array::from_fn(|i| c(held + i) - c(acc + i))
                };
                let ta =
                    self.ext_mul::<AB>(&diff(self.az_col(), self.acc_col), &ext(self.inv_a_col()));
                let tb = self.ext_mul::<AB>(
                    &diff(self.bz_col(), self.acc_col + D),
                    &ext(self.inv_b_col()),
                );
                for (limb, (a, b)) in ta.into_iter().zip(tb).enumerate() {
                    builder.assert_zero(end.clone() * (c(self.ro_reg_col() + limb) - a - b));
                }
                for q in 0..queries {
                    let gate = per[self.seg_per + q].clone() * end.clone();
                    for limb in 0..D {
                        builder.assert_zero(
                            gate.clone() * (c(self.ro_col(q) + limb) - c(self.ro_reg_col() + limb)),
                        );
                    }
                }
            }
            "hold" => {
                for col in self.held_col..self.width {
                    builder.when_transition().assert_zero(n(col) - c(col));
                }
            }
            "ro_out" => {
                for q in 0..queries {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(
                            c(self.ro_col(q) + limb) - pv[layout.ro_pv(q) + limb].clone(),
                        );
                    }
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for OpenAir {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        self.layout.num_public_values()
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic.len()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.periodic.clone()
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for OpenAir {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
    }
}

/// Native `open_input` (`verifier.rs:609-773`) for one query, from the
/// proof's own opened values arranged as uni-stark hands them to the PCS
/// (`verifier.rs:453-510`): the running alpha power over batches, matrices,
/// points, columns. Written from the source, independently of `Geom::term`
/// and of 2a's opened order, so the grouped in-circuit form is checked
/// against the sequential native one.
/// Per matrix, its (point, values at the point) claims.
#[cfg(test)]
type Claims<'a> = Vec<Vec<(E, &'a Vec<E>)>>;

#[cfg(test)]
fn native_reduced(
    geom: &Geom,
    proof: &Proof<Config>,
    op: &Opening,
    index: usize,
    zeta: E,
    alpha: E,
) -> Result<E> {
    let o = &proof.opened_values;
    let random = o.random.as_ref().ok_or("missing randomizer opening")?;
    let next = o.trace_next.as_ref().ok_or("missing next-row opening")?;
    let claims: [Claims<'_>; BATCHES] = [
        vec![vec![(zeta, random)]],
        vec![vec![(zeta, &o.trace_local), (zeta * geom.g_n, next)]],
        o.quotient_chunks
            .iter()
            .map(|ch| vec![(zeta, ch)])
            .collect(),
    ];
    let x = Val::GENERATOR
        * Val::two_adic_generator(geom.lde)
            .exp_u64(p3_util::reverse_bits_len(index, geom.lde) as u64);
    let (mut alpha_pow, mut ro) = (E::ONE, E::ZERO);
    for (b, mats) in claims.iter().enumerate() {
        require(mats.len() == op.rows[b].len(), "matrix count")?;
        for (row, points) in op.rows[b].iter().zip(mats) {
            for &(z, ps_at_z) in points {
                require(row.len() == ps_at_z.len(), "row width")?;
                let q = (z - E::from(x)).try_inverse().ok_or("z equals x")?;
                for (&p_at_x, &p_at_z) in row.iter().zip(ps_at_z) {
                    ro += alpha_pow * (p_at_z - E::from(p_at_x)) * q;
                    alpha_pow *= alpha;
                }
            }
        }
    }
    Ok(ro)
}

#[cfg(test)]
pub(in crate::f2::ood) mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::OnceLock;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
    use p3_keccak::KeccakF;
    use p3_matrix::Dimensions;
    use p3_maybe_rayon::prelude::*;
    use p3_merkle_tree::MerkleTreeHidingMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_consensus::ProverRng;
    use qlab_l2::L2_CFG_PROVISIONAL;

    use super::super::bind::tests::{exported, Exported};
    use super::super::fri_fs::tests::{shared, Shared};
    use super::super::lane::phase_ranges;
    use super::super::proof_inputs_dims;
    use super::*;

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    /// The consensus input MMCS, rebuilt from the same parts
    /// (`qlab-consensus` `ValMmcs`); verification never draws from the RNG.
    /// The commit-phase MMCS is `ExtensionMmcs` over this same hiding type.
    pub(in crate::f2::ood) type NativeMmcs = MerkleTreeHidingMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        SerializingHasher<U64Hash>,
        CompressionFunctionFromHasher<U64Hash, 2, 4>,
        ProverRng,
        2,
        4,
        SALT_ELEMS,
    >;

    pub(in crate::f2::ood) fn native_mmcs() -> NativeMmcs {
        let h = U64Hash::new(KeccakF {});
        NativeMmcs::new(
            SerializingHasher::new(h),
            CompressionFunctionFromHasher::new(h),
            CAP_HEIGHT,
            ProverRng::seeded(0),
        )
    }

    struct Fixture {
        sh: Shared,
        two_a: Exported,
        air: OpenAir,
        ranges: Vec<Range<usize>>,
        /// Every query's opening and native inbound values (all 43).
        all: Vec<Opening>,
        full: Inbound,
        /// Covered query slots, and the inbound restricted to them.
        covered: Vec<usize>,
        inb: Inbound,
        honest: Build,
    }

    /// The 2b-i fixture's proof (toy, log 8, seeded), its query indices and
    /// fri_alpha, 2a's exports of the same proof, and an instance covering
    /// two queries with different cap entries.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let sh = shared();
            let proof = sh.proof;
            let dims = Dims {
                width: 2,
                pv_len: 2,
                log_height: sh.log_height,
            };
            let chunks = proof.opened_values.quotient_chunks.len();
            let geom = Geom::new(dims, chunks, &L2_CFG_PROVISIONAL).unwrap();
            let inputs = proof_inputs_dims(dims, proof, sh.pvs).unwrap();
            let mut zvals = proof.opened_values.random.clone().unwrap();
            zvals.extend(&inputs.local);
            zvals.extend(&inputs.next);
            zvals.extend(inputs.chunks.iter().flatten());
            let c = &proof.commitments;
            let full = Inbound {
                caps: [
                    c.random.as_ref().unwrap().roots().to_vec(),
                    c.trace.roots().to_vec(),
                    c.quotient_chunks.roots().to_vec(),
                ],
                zeta: inputs.zeta,
                zvals,
                fri_alpha: sh.fri_alpha,
                indices: sh.indices.clone(),
            };
            let cap_of = |i: usize| sh.indices[i] >> geom.path;
            let other = (1..sh.indices.len())
                .find(|&i| cap_of(i) != cap_of(0))
                .unwrap();
            let covered = vec![0, other];
            let all: Vec<Opening> = (0..sh.indices.len())
                .map(|q| Opening::from_proof(proof, q, &geom).unwrap())
                .collect();
            let air = OpenAir::new(Layout::new(geom, covered.len()), 64 << 20).unwrap();
            let mut inb = full.clone();
            inb.indices = covered.iter().map(|&q| sh.indices[q]).collect();
            let honest = Build::honest(
                &air.layout,
                &inb,
                covered.iter().map(|&q| all[q].clone()).collect(),
            )
            .unwrap();
            let ranges = phase_ranges(&air);
            let two_a = exported(proof, sh.pvs, sh.log_height);
            Fixture {
                sh,
                two_a,
                air,
                ranges,
                all,
                full,
                covered,
                inb,
                honest,
            }
        })
    }

    /// What F2b-2b-iii's tests take from this fixture: the covered query
    /// slots, this component's honest public values and the positions of its
    /// reduced-opening outputs (the seam 2b-iii's inputs are compared
    /// against), those outputs, and the native reduced opening of every one
    /// of the 43 queries (sequential `open_input` replica).
    pub(in crate::f2::ood) struct Handoff {
        pub(in crate::f2::ood) covered: Vec<usize>,
        pub(in crate::f2::ood) ro: Vec<E>,
        pub(in crate::f2::ood) ro_all: Vec<E>,
        pub(in crate::f2::ood) public: Vec<Val>,
        pub(in crate::f2::ood) ro_at: Vec<usize>,
    }

    pub(in crate::f2::ood) fn handoff() -> Handoff {
        let fx = fixture();
        let (l, g) = (&fx.air.layout, &fx.air.layout.geom);
        let ro_all = (0..fx.all.len())
            .map(|q| {
                native_reduced(
                    g,
                    fx.sh.proof,
                    &fx.all[q],
                    fx.full.indices[q],
                    fx.full.zeta,
                    fx.full.fri_alpha,
                )
                .unwrap()
            })
            .collect();
        Handoff {
            covered: fx.covered.clone(),
            ro: fx.honest.held.ro.clone(),
            ro_all,
            public: fx.air.public_values(&fx.inb, &fx.honest.held.ro),
            ro_at: (0..l.queries).map(|q| l.ro_pv(q)).collect(),
        }
    }

    /// The native reduced opening of `query` of any hiding proof on the L2
    /// lane (the sequential `open_input` replica), for 2b-iii's production-
    /// schedule test on a real S3 proof.
    pub(in crate::f2::ood) fn reduced_opening(
        proof: &Proof<Config>,
        pvs: &[Val],
        width: usize,
        log_height: usize,
        query: usize,
        index: usize,
        fri_alpha: E,
    ) -> E {
        let dims = Dims {
            width,
            pv_len: pvs.len(),
            log_height,
        };
        let chunks = proof.opened_values.quotient_chunks.len();
        let geom = Geom::new(dims, chunks, &L2_CFG_PROVISIONAL).unwrap();
        let zeta = proof_inputs_dims(dims, proof, pvs).unwrap().zeta;
        let op = Opening::from_proof(proof, query, &geom).unwrap();
        native_reduced(&geom, proof, &op, index, zeta, fri_alpha).unwrap()
    }

    fn phase_of(fx: &Fixture, constraint: usize) -> &'static str {
        PHASES[fx
            .ranges
            .iter()
            .position(|r| r.contains(&constraint))
            .unwrap()]
    }

    struct Claim {
        build: Build,
        trace: RowMajorMatrix<Val>,
        pvs: Vec<Val>,
    }

    /// `before` edits the forger's inputs, which `settle` then re-derives
    /// consistently; `after` pokes derived values. Public inputs stay the
    /// honest exports of 2a / 2b-i; the reduced-opening outputs are the
    /// claim's own.
    fn claim(
        fx: &Fixture,
        before: impl FnOnce(&mut Build),
        after: impl FnOnce(&mut Build),
    ) -> Claim {
        let mut build = fx.honest.clone();
        before(&mut build);
        build.settle(&fx.air.layout).unwrap();
        after(&mut build);
        let trace = fx.air.trace(&build).unwrap();
        let pvs = fx.air.public_values(&fx.inb, &build.held.ro);
        Claim { build, trace, pvs }
    }

    /// Every (row, group) violated anywhere in the trace.
    fn violations(fx: &Fixture, c: &Claim) -> BTreeSet<(usize, &'static str)> {
        (0..fx.air.height)
            .into_par_iter()
            .flat_map_iter(|row| {
                violations_at(&fx.air, &c.trace, &c.pvs, row)
                    .into_iter()
                    .map(move |v| (row, phase_of(fx, v.constraint)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect()
    }

    /// Refused, and exactly by `expected` (row, group) pairs.
    fn refused_exactly(fx: &Fixture, c: &Claim, expected: &BTreeSet<(usize, &'static str)>) {
        let v = violations(fx, c);
        assert!(!v.is_empty(), "forgery accepted");
        assert_eq!(&v, expected);
    }

    fn rows(r: Range<usize>, group: &'static str) -> BTreeSet<(usize, &'static str)> {
        r.map(|row| (row, group)).collect()
    }

    fn seg(fx: &Fixture, q: usize) -> Range<usize> {
        let s = fx.air.layout.seg_rows();
        q * s..(q + 1) * s
    }

    /// Rows carrying covered query `q`'s registers: its segment, and for the
    /// last query also the padding rows after it (they repeat its context).
    fn ctx_rows(fx: &Fixture, q: usize) -> Range<usize> {
        let r = seg(fx, q);
        if q + 1 == fx.air.layout.queries {
            r.start..fx.air.height
        } else {
            r
        }
    }

    /// Last row of the perm at segment position `pos` of covered query `q`.
    fn last_row(fx: &Fixture, q: usize, pos: usize) -> usize {
        NUM_ROUNDS * (q * fx.air.layout.segment.len() + pos) + NUM_ROUNDS - 1
    }

    fn cap_row(fx: &Fixture, q: usize, b: usize) -> usize {
        let l = &fx.air.layout;
        last_row(fx, q, l.at(Step::Node(b, l.geom.path - 1)))
    }

    /// The row that feeds level `t`'s compression of batch `b`.
    fn feed_row(fx: &Fixture, q: usize, b: usize, t: usize) -> usize {
        last_row(fx, q, fx.air.layout.at(Step::Node(b, t)) - 1)
    }

    #[test]
    fn input_openings_accept_honest_queries_at_degree_three() {
        let fx = fixture();
        let (air, layout, g) = (&fx.air, &fx.air.layout, &fx.air.layout.geom);
        let proof = fx.sh.proof;
        // The geometry is the proof's: one LDE height 2^11 for all three
        // batches, 8 levels below a 2^3 cap, 1 + 1 + 2 leaf perms (8, 6 and
        // 64 elements), 40 opened terms.
        assert_eq!((g.lde, g.path, g.terms), (11, 8, 40));
        assert_eq!(layout.segment.len(), 1 + 1 + 2 + 3 * 8);
        assert_eq!(layout.carry_roles, vec![layout.role(QUOTIENT, 1)]);
        assert_eq!(
            layout.carry_lanes(layout.role(QUOTIENT, 1)),
            vec![15, 16],
            "32 u64 in 17 + 15: two tail lanes carried"
        );
        let price = crate::f2::price::input_openings(2, fx.sh.log_height, 8, layout.queries);
        assert_eq!(price["permutations_per_query"], layout.segment.len());
        assert_eq!(price["component_columns"], air.width);
        assert_eq!(price["periodic_columns"], air.periodic.len());
        assert_eq!(price["public_values"], layout.num_public_values());
        assert_eq!(price["padded_rows"], air.height);
        let mmcs = native_mmcs();
        let fri_mmcs = ExtensionMmcs::<Val, E, NativeMmcs>::new(native_mmcs());
        let commits = [
            proof.commitments.random.as_ref().unwrap(),
            &proof.commitments.trace,
            &proof.commitments.quotient_chunks,
        ];
        let fri = &proof.opening_proof.1;
        for (q, op) in fx.all.iter().enumerate() {
            let index = fx.full.indices[q];
            let qp = &fri.query_proofs[q];
            // p3's own MMCS accepts the opening at the full index (one
            // height: the reduced index is the index), and the lab's native
            // replay reaches the same cap entry.
            let walk = Walk::new(layout, op, index, None);
            for (b, commit) in commits.into_iter().enumerate() {
                let (mats, cols) = g.mats(b);
                let dims = vec![
                    Dimensions {
                        width: cols,
                        height: 1 << g.lde,
                    };
                    mats
                ];
                mmcs.verify_batch(commit, &dims, index, (&qp.input_proof[b]).into())
                    .unwrap_or_else(|e| panic!("query {q} batch {b}: {e:?}"));
                assert_eq!(walk.roots[b], fx.full.caps[b][index >> g.path], "{q}/{b}");
            }
            // The sequential native reduced opening equals the grouped form
            // the circuit computes, and it IS what FRI folds: inserted at
            // the index among round 0's siblings, p3's commit-phase MMCS
            // accepts the row.
            let ro = native_reduced(g, proof, op, index, fx.full.zeta, fx.full.fri_alpha).unwrap();
            let held = &fx.honest.held;
            let ab = Build::sums(layout, op, &held.apow);
            assert_eq!(Ctx::new(g, index, index, held, ab).unwrap().ro, ro, "{q}");
            let step = &qp.commit_phase_openings[0];
            let log_arity = step.log_arity as usize;
            let mut evals = step.sibling_values.clone();
            evals.insert(index % (1 << log_arity), ro);
            fri_mmcs
                .verify_batch(
                    &fri.commit_phase_commits[0],
                    &[Dimensions {
                        width: 1 << log_arity,
                        height: 1 << (g.lde - log_arity),
                    }],
                    index >> log_arity,
                    BatchOpeningRef::new(&[evals], &step.opening_proof),
                )
                .unwrap_or_else(|e| panic!("query {q}: reduced opening not folded: {e:?}"));
        }
        let c = claim(fx, |_| {}, |_| {});
        satisfied(air, &c.trace, &c.pvs).unwrap_or_else(|v| {
            panic!(
                "honest input openings refused: {v} in {}",
                phase_of(fx, v.constraint)
            )
        });
        for (i, &q) in fx.covered.iter().enumerate() {
            let native = native_reduced(
                g,
                proof,
                &fx.all[q],
                fx.full.indices[q],
                fx.full.zeta,
                fx.full.fri_alpha,
            )
            .unwrap();
            assert_eq!(c.build.held.ro[i], native, "held reduced opening {q}");
            let at = layout.ro_pv(i);
            assert_eq!(&c.pvs[at..at + D], native.as_basis_coefficients_slice());
        }
        let constraints = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
        assert_eq!(fx.ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "input opening degree {max} > 3");
    }

    #[test]
    fn input_openings_meet_2a_and_2b_i_at_the_seam() {
        // Each public input here is another component's public output: the
        // caps, zeta and z-values 2a exports (from the machine's own cells),
        // fri_alpha and the covered indices 2b-i exports.
        let fx = fixture();
        let l = &fx.air.layout;
        let pvs = fx.air.public_values(&fx.inb, &fx.honest.held.ro);
        let a = &fx.two_a;
        assert_eq!(&pvs[..6 * CAP_WORDS], &a.pvs[a.caps.clone()], "caps");
        assert_eq!(
            &pvs[l.zeta_pv()..l.zeta_pv() + D],
            &a.pvs[a.zeta.clone()],
            "zeta"
        );
        assert_eq!(
            &pvs[l.zval_pv(0)..l.alpha_pv()],
            &a.pvs[a.opened.clone()],
            "z-values"
        );
        let s = &fx.sh;
        assert_eq!(
            &pvs[l.alpha_pv()..l.alpha_pv() + D],
            &s.public[s.fri_alpha_at..s.fri_alpha_at + D],
            "fri_alpha"
        );
        for (i, &q) in fx.covered.iter().enumerate() {
            assert_eq!(pvs[l.index_pv(i)], s.public[s.index_at[q]], "index {q}");
        }
    }

    #[test]
    fn input_openings_reject_leaf_forgeries() {
        let fx = fixture();
        // A salt changed: the leaf moves, the path is honest, only the cap
        // comparison of that batch refuses it.
        let c = claim(fx, |b| b.ops[0].salts[TRACE][0][2] += Val::ONE, |_| {});
        refused_exactly(fx, &c, &[(cap_row(fx, 0, TRACE), "cap")].into());
        // A row value changed and a fresh salt chosen, the reduced opening
        // re-derived from the forged value: the leaf is canonical and
        // consistent, so nothing refuses it before the cap.
        let c = claim(
            fx,
            |b| {
                b.ops[1].rows[QUOTIENT][3][1] += Val::ONE;
                b.ops[1].salts[QUOTIENT][3] =
                    (0..SALT_ELEMS).map(|s| Val::from_usize(s + 7)).collect();
            },
            |_| {},
        );
        assert_ne!(c.build.held.ro[1], fx.honest.held.ro[1]);
        refused_exactly(fx, &c, &[(cap_row(fx, 1, QUOTIENT), "cap")].into());
    }

    #[test]
    fn input_openings_reject_path_forgeries() {
        let fx = fixture();
        let g = &fx.air.layout.geom;
        // Two siblings of the randomizer path swapped.
        let c = claim(fx, |b| b.ops[0].siblings[RANDOM].swap(2, 3), |_| {});
        refused_exactly(fx, &c, &[(cap_row(fx, 0, RANDOM), "cap")].into());
        // The child placed on the wrong side at level 4, the index bit
        // untouched: refused where it is placed, and the root moves.
        let c = claim(fx, |b| b.flips[1] = Some((TRACE, 4)), |_| {});
        refused_exactly(
            fx,
            &c,
            &[
                (feed_row(fx, 1, TRACE, 4), "bind_child"),
                (cap_row(fx, 1, TRACE), "cap"),
            ]
            .into(),
        );
        // Index bit 3 flipped in the registers, placement, x and the reduced
        // opening all following it: the public index refuses it on every
        // row of the segment, and every batch's root moves.
        let c = claim(fx, |b| b.index[0] ^= 1 << 3, |_| {});
        let mut expected = rows(seg(fx, 0), "index");
        for b in 0..BATCHES {
            expected.insert((cap_row(fx, 0, b), "cap"));
        }
        refused_exactly(fx, &c, &expected);
        // The wrong cap entry selected: the one-hot no longer matches the
        // top index bits, and no entry but the right one matches the root.
        let right = fx.inb.indices[1] >> g.path;
        let c = claim(
            fx,
            |_| {},
            |b| b.ctx[1].e = core::array::from_fn(|j| Val::from_bool(j == right ^ 1)),
        );
        let mut expected = rows(ctx_rows(fx, 1), "cap_select");
        for b in 0..BATCHES {
            expected.insert((cap_row(fx, 1, b), "cap"));
        }
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn input_openings_reject_reduced_opening_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        let g = &l.geom;
        // A different z-value handed to FRI than the one 2a exports (the
        // machine's), everything downstream re-derived from it: only the
        // equality to the export refuses it — for a trace value the machine
        // reads and for the randomizer, which it does not.
        for k in [g.term(TRACE, 0, 1, 1), g.term(RANDOM, 0, 0, 2)] {
            let c = claim(
                fx,
                |b| b.held.zvals[k] += <E as BasedVectorSpace<Val>>::ith_basis_element(1).unwrap(),
                |_| {},
            );
            assert_ne!(c.build.held.ro[0], fx.honest.held.ro[0]);
            refused_exactly(fx, &c, &[(0, "opened_in")].into());
        }
        // x from the index WITHOUT bit reversal (what a verifier forgetting
        // `reverse_bits_len` would use), inverses and ro re-derived.
        let c = claim(
            fx,
            |_| {},
            |b| {
                let index = b.index[1];
                let rev = p3_util::reverse_bits_len(index, g.lde);
                assert_ne!(rev, index, "a palindromic index hides the reversal");
                let ab = Build::sums(l, &b.ops[1], &b.held.apow);
                b.ctx[1] = Ctx::new(g, index, rev, &b.held, ab).unwrap();
                b.held.ro[1] = b.ctx[1].ro;
            },
        );
        assert_ne!(c.build.held.ro[1], fx.honest.held.ro[1]);
        refused_exactly(fx, &c, &rows(ctx_rows(fx, 1), "x_point"));
        // A different fri_alpha than 2b-i exports, the alpha powers, Az/Bz
        // and every reduced opening re-derived from it: only the equality to
        // the export refuses it.
        let c = claim(
            fx,
            |b| b.held.fri_alpha += <E as BasedVectorSpace<Val>>::ith_basis_element(2).unwrap(),
            |_| {},
        );
        assert_ne!(c.build.held.apow[1], fx.honest.held.apow[1]);
        assert_ne!(c.build.held.ro[0], fx.honest.held.ro[0]);
        refused_exactly(fx, &c, &[(0, "opened_in")].into());
        // A reduced opening poked, held cell and public output agreeing.
        let end = seg(fx, 0).end - 1;
        let c = claim(fx, |_| {}, |b| b.held.ro[0] += E::ONE);
        refused_exactly(fx, &c, &[(end, "reduce")].into());
    }
}
