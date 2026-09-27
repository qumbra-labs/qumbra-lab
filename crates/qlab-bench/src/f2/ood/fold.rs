//! F2b-2b-iii (issue #750): the FRI query phase of the inner verifier, in
//! circuit — per covered query, every commit round's salted leaf and Merkle
//! path to that round's cap, the running value at the query's position, the
//! fold, and the final polynomial's evaluation. Test-only component, scanned
//! row by row, never proved.
//!
//! **Native semantics** (p3-fri 0.6.1 `verifier.rs`, `TwoAdicFriFolding`,
//! the lab's hiding config, rc = 0):
//!
//! - **Start** (`verifier.rs:470-480`): the chain starts from the reduced
//!   opening at the global max height. All three input batches sit at ONE
//!   LDE height (2b-ii), so that is the only reduced opening: the roll-in at
//!   a folded height (`verifier.rs:562-565`, `beta^arity * ro`) never fires
//!   here — a second height would be a second `ro` public input.
//! - **Round r** (`verifier.rs:490-568`): arity n = 2^a from the fixed
//!   schedule (2b-i); `index_in_group = index % n` of the index already
//!   shifted by the earlier rounds, i.e. query-index bits S_r..S_r+a
//!   (`508`); evals = the n - 1 siblings with the running value inserted at
//!   that position (`509-517`); the index shifts by a (`529`); the
//!   commit-phase MMCS checks evals at the shifted index (`531-541`); then
//!   `fold_row` (`543-549`).
//! - **Leaf.** `ChallengeMmcs = ExtensionMmcs<Val, E, ValMmcs>`
//!   (qlab-consensus `lib.rs:90`): evals flatten to 4n base limbs
//!   (`extension_mmcs.rs:77-82`) and the HIDING `ValMmcs` appends
//!   `SALT_ELEMS` salt to the row (`hiding_mmcs.rs:175`) — commit-phase
//!   leaves are salted, exactly like the input leaves. Sponge, packing and
//!   path are the input MMCS's (see `open.rs`); level t of round r reads
//!   query-index bit S_{r+1} + t, and the cap entry is always the top
//!   `CAP_HEIGHT` index bits (S_{r+1} + path_r = lde - CAP_HEIGHT).
//! - **Fold** (`two_adic_pcs.rs:110-133`): Lagrange interpolation at beta of
//!   the n evals at xs[i] = s * w_n^{rev_a(i)}, s = w_{h+a}^{rev_h(index')}
//!   with index' the shifted index and h the folded log-height; barycentric
//!   (`two_adic_pcs.rs:221-258`, with an early return when beta hits an x,
//!   where the interpolant has the same value).
//! - **Final** (`verifier.rs:394-410`): x = w_lde^{rev_lde(index >> S_R)} —
//!   NO coset shift, unlike the input point — and Horner over the final
//!   polynomial must equal the last folded value.
//!
//! **What is constrained**, on one Keccak lane (stock p3-keccak-air), per
//! covered query:
//!
//! - **Leaves and paths.** As `open.rs` does for the input batches: the M
//!   bits of a perm's step-0 row are its rate preimage (overwrite sponge);
//!   a leaf's row words are canonical Monty words equal to `R * G` for the
//!   round's group registers G, its salt words are free; each level's child
//!   sits left or right by the SAME index-bit cells; the round's root equals
//!   the cap entry the top-bit one-hot selects, against the commit-phase caps
//!   2b-i binds (public inputs here).
//! - **Position.** A one-hot over bits S_r..S_r+a, built level by level
//!   (degree 2 per cell); the selected group entry equals the running value.
//! - **Fold, as an inverse DFT.** p(beta) = sum_k d_k u^k with
//!   d_k = n^-1 sum_i w_n^{-rev_a(i) k} G[i] (base constants, linear in G)
//!   and u = beta * s^-1. s^-1 is a product of CONSTANT factors
//!   w_{h+a}^{-2^{h-1-t}} selected by the index bits: no inverse witness
//!   exists anywhere in this component (1/n and s^-1 are both constants or
//!   constant chains). u^k are cells, u^{k+1} = u^k * u.
//! - **Final polynomial.** x by a constant-factor chain on bits S_R..lde,
//!   Horner cells h_k = h_{k+1} * x + c_k over 2b-i's final polynomial,
//!   h_0 = the last folded value.
//!
//! **Composition.** Public INPUTS, each another component's public output:
//! the commit-phase caps, every beta, the final polynomial and the covered
//! indices (2b-i), and the covered reduced openings (2b-ii). Betas and the
//! final polynomial are held cells bound on row 0 (`inbound`); the index
//! bits and the chain's start are pinned per row of the query's segment
//! (`index`, `ro_in`). The seam test compares the public values slice by
//! slice.
//!
//! **Uniform layout.** Every query runs the same perm segment; per-query
//! registers are constant over the segment (`ctx_hold`), so the group bound
//! on a leaf's step-0 rows is the group the fold reads on every row.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use p3_util::reverse_bits_len;
use qlab_consensus::{Config, FriCfg, CAP_HEIGHT, IS_ZK, SALT_ELEMS};

use super::lane::{monty, Lane, Phased, CAP_WORDS, RATE_BITS, RATE_LANES, RATE_WORDS};
use super::open::{leaf_words, Word};
use super::{require, Result, Val, E};
use crate::f2::price::fri_log_arities;
use crate::m4gaterec::keccakf;

/// Constraint groups, in evaluation order. A negative names the group(s)
/// its violation must land in, on named rows.
const PHASES: [&str; 24] = [
    "keccak",
    "bits",
    "absorb",
    "capacity",
    "bind_zero",
    "bind_carry",
    "bind_child",
    "cap",
    "canonical",
    "leaf_bind",
    "index",
    "cap_select",
    "position",
    "ro_in",
    "select",
    "s_inv",
    "fold_pow",
    "fold",
    "final_x",
    "horner",
    "final",
    "inbound",
    "hold",
    "ctx_hold",
];

/// Extension limbs.
const D: usize = 4;
/// Rate words a compression's two children occupy (2 x 4 u64).
const CHILD_WORDS: usize = 16;

/// Query-phase geometry: shape constants and the constant tables derived
/// from them. Nothing here is read from a proof.
#[derive(Clone, Debug)]
struct Geom {
    /// Query index bits = log2 of the LDE height.
    lde: usize,
    /// Per-round log-arity: the fixed schedule 2b-i binds.
    arities: Vec<usize>,
    /// Index bits shifted off before round r (`shift[R]` = all rounds).
    shift: Vec<usize>,
    /// Folded log-height after round r.
    folded: Vec<usize>,
    /// Merkle levels below the cap in round r.
    path: Vec<usize>,
    /// log2 of the final domain: `log_blowup + log_final_poly_len`.
    final_bits: usize,
    final_len: usize,
    /// idft[r][k][i] = n^-1 * w_n^{-rev_a(i) * k}.
    idft: Vec<Vec<Vec<Val>>>,
    /// Round r's s^-1 factor for bit t of the shifted index.
    sinv_f: Vec<Vec<Val>>,
    /// The final x's factor for bit t of `index >> S_R`.
    final_f: Vec<Val>,
}

impl Geom {
    fn new(log_height: usize, cfg: &FriCfg) -> Result<Self> {
        let lde = log_height + IS_ZK + cfg.log_blowup;
        require(lde <= 30, "query index wider than 30 bits")?;
        require(CAP_HEIGHT == 3, "the cap mux is written for 2^3 entries")?;
        let arities = fri_log_arities(lde, cfg);
        require(!arities.is_empty(), "no commit round")?;
        let (mut shift, mut folded, mut path) = (vec![0], vec![], vec![]);
        for &a in &arities {
            let s = shift[shift.len() - 1] + a;
            shift.push(s);
            let h = lde - s;
            require(h > CAP_HEIGHT, "a folded domain no taller than the cap")?;
            folded.push(h);
            path.push(h - CAP_HEIGHT);
        }
        let final_bits = cfg.log_blowup + cfg.log_final_poly_len;
        require(
            lde - shift[arities.len()] == final_bits,
            "fold schedule does not reach the final height",
        )?;
        let idft = arities
            .iter()
            .map(|&a| {
                let n = 1usize << a;
                let winv = Val::two_adic_generator(a).inverse();
                let ninv = Val::from_usize(n).inverse();
                (0..n)
                    .map(|k| {
                        (0..n)
                            .map(|i| ninv * winv.exp_u64(((reverse_bits_len(i, a) * k) % n) as u64))
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let sinv_f = (0..arities.len())
            .map(|r| {
                let h = folded[r];
                let winv = Val::two_adic_generator(h + arities[r]).inverse();
                (0..h).map(|t| winv.exp_power_of_2(h - 1 - t)).collect()
            })
            .collect();
        let w = Val::two_adic_generator(lde);
        let final_f = (0..final_bits)
            .map(|t| w.exp_power_of_2(lde - 1 - t))
            .collect();
        Ok(Self {
            lde,
            arities,
            shift,
            folded,
            path,
            final_bits,
            final_len: 1 << cfg.log_final_poly_len,
            idft,
            sinv_f,
            final_f,
        })
    }

    fn rounds(&self) -> usize {
        self.arities.len()
    }
    fn arity(&self, r: usize) -> usize {
        1 << self.arities[r]
    }
}

/// One perm of a query segment.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Step {
    /// Block `k` of round `r`'s leaf sponge.
    Leaf(usize, usize),
    /// Path level `t` of round `r`.
    Node(usize, usize),
}

/// Static layout: one segment of perms per covered query.
#[derive(Clone)]
struct Layout {
    geom: Geom,
    /// Leaf words of every round: 4n extension limbs ‖ salt.
    leaves: Vec<Vec<Word>>,
    /// (round, block) of every leaf-block role.
    roles: Vec<(usize, usize)>,
    /// Roles whose block carries tail lanes from the previous output.
    carry_roles: Vec<usize>,
    segment: Vec<Step>,
    queries: usize,
}

impl Layout {
    fn new(geom: Geom, queries: usize) -> Self {
        let leaves: Vec<Vec<Word>> = (0..geom.rounds())
            .map(|r| leaf_words(1, D * geom.arity(r)))
            .collect();
        let mut roles = Vec::new();
        let mut segment = Vec::new();
        for (r, leaf) in leaves.iter().enumerate() {
            for k in 0..leaf.len() / RATE_WORDS {
                roles.push((r, k));
                segment.push(Step::Leaf(r, k));
            }
            segment.extend((0..geom.path[r]).map(|t| Step::Node(r, t)));
        }
        let carry_roles = (0..roles.len())
            .filter(|&ro| {
                let (r, k) = roles[ro];
                leaves[r][RATE_WORDS * k..RATE_WORDS * (k + 1)].contains(&Word::Carry)
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

    fn role(&self, r: usize, k: usize) -> usize {
        self.roles.iter().position(|&x| x == (r, k)).unwrap()
    }
    fn role_words(&self, ro: usize) -> &[Word] {
        let (r, k) = self.roles[ro];
        &self.leaves[r][RATE_WORDS * k..RATE_WORDS * (k + 1)]
    }
    fn carry_lanes(&self, ro: usize) -> Vec<usize> {
        let words = self.role_words(ro);
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
    fn at(&self, step: Step) -> usize {
        self.segment.iter().position(|&s| s == step).unwrap()
    }
    /// Level selector of the path level that reads index bit `bit`: every
    /// round's levels read bits shift[r+1].., all inside round 0's range.
    fn lvl(&self, bit: usize) -> usize {
        bit - self.geom.shift[1]
    }

    // Public values (all inputs): commit-phase caps (2b-i's order and
    // limbs), betas, final polynomial, covered indices, reduced openings.
    fn cap_pv(&self, r: usize, j: usize, lane: usize, l: usize) -> usize {
        2 * CAP_WORDS * r + 16 * j + 4 * lane + l
    }
    fn beta_pv(&self, r: usize) -> usize {
        2 * CAP_WORDS * self.geom.rounds() + D * r
    }
    fn final_pv(&self, c: usize) -> usize {
        self.beta_pv(self.geom.rounds()) + D * c
    }
    fn index_pv(&self, q: usize) -> usize {
        self.final_pv(self.geom.final_len) + q
    }
    fn ro_pv(&self, q: usize) -> usize {
        self.index_pv(self.queries) + D * q
    }
    fn num_public_values(&self) -> usize {
        self.ro_pv(self.queries)
    }
}

/// One query's commit-phase openings, as the proof carries them.
#[derive(Clone)]
struct QOpening {
    /// Per round: the n - 1 sibling values, the leaf salt, the Merkle path.
    sibs: Vec<Vec<E>>,
    salts: Vec<Vec<Val>>,
    paths: Vec<Vec<[u64; 4]>>,
}

impl QOpening {
    fn from_proof(proof: &Proof<Config>, query: usize, g: &Geom) -> Result<Self> {
        let qp = proof
            .opening_proof
            .1
            .query_proofs
            .get(query)
            .ok_or("query out of range")?;
        require(
            qp.commit_phase_openings.len() == g.rounds(),
            "commit round count",
        )?;
        let mut op = Self {
            sibs: vec![],
            salts: vec![],
            paths: vec![],
        };
        for (r, step) in qp.commit_phase_openings.iter().enumerate() {
            // The fixed schedule: a proof folded on another legal schedule is
            // refused (completeness restriction, as in 2b-i).
            require(
                step.log_arity as usize == g.arities[r],
                "log arity differs from the fixed schedule",
            )?;
            require(step.sibling_values.len() == g.arity(r) - 1, "sibling count")?;
            let (salts, path) = &step.opening_proof;
            require(
                salts.len() == 1 && salts[0].len() == SALT_ELEMS,
                "commit-phase salt shape",
            )?;
            require(path.len() == g.path[r], "commit-phase path length")?;
            op.sibs.push(step.sibling_values.clone());
            op.salts.push(salts[0].clone());
            op.paths.push(path.clone());
        }
        Ok(op)
    }
}

/// evals of a round: the siblings with `value` at `pos`
/// (`verifier.rs:509-517`).
fn insert(sibs: &[E], pos: usize, value: E) -> Vec<E> {
    let mut v = sibs.to_vec();
    v.insert(pos, value);
    v
}

/// What this component takes from 2b-i and 2b-ii: its public inputs.
#[derive(Clone)]
struct Inbound {
    /// Commit-phase caps, per round.
    caps: Vec<Vec<[u64; 4]>>,
    betas: Vec<E>,
    final_poly: Vec<E>,
    /// The covered queries' indices and reduced openings.
    indices: Vec<usize>,
    ro: Vec<E>,
}

/// Held cells: constant over every row.
#[derive(Clone)]
struct Held {
    betas: Vec<E>,
    final_poly: Vec<E>,
}

/// Forgery knobs of one query's chain; `honest` is the native verifier.
#[derive(Clone)]
struct Knobs {
    /// The round whose beta round r's fold uses.
    beta_of: Vec<usize>,
    /// Bits shifted off before round r's position; its path and s^-1 use
    /// this plus the round's arity.
    shift: Vec<usize>,
    /// Round after whose fold `beta^arity * ro` is rolled in again.
    roll_in: Option<usize>,
}

impl Knobs {
    fn honest(g: &Geom) -> Self {
        Self {
            beta_of: (0..g.rounds()).collect(),
            shift: g.shift[..g.rounds()].to_vec(),
            roll_in: None,
        }
    }
}

/// One covered query's registers, repeated on every row of its segment.
#[derive(Clone)]
struct Ctx {
    bits: Vec<Val>,
    u: [Val; 4],
    e: [Val; 8],
    /// Per round: the n evals (the committed group).
    groups: Vec<Vec<E>>,
    /// Per round: the position one-hot, levels 1..=a concatenated.
    pos: Vec<Vec<Val>>,
    /// The value entering round r; f[R] is the last fold.
    f: Vec<E>,
    /// Per round: the s^-1 chain.
    sinv: Vec<Vec<Val>>,
    /// Per round: u^1..u^{n-1}, u = beta * s^-1.
    t: Vec<Vec<E>>,
    /// The final x chain.
    xf: Vec<Val>,
    /// Horner cells h_0..h_{L-1}.
    horner: Vec<E>,
}

/// The native Merkle replay of one query's commit-phase openings: every
/// perm's preimage in segment order, and each round's root.
#[derive(Clone)]
struct Walk {
    perms: Vec<[u64; 25]>,
    roots: Vec<[u64; 4]>,
}

/// The fold of one group at beta with s^-1 given, in the inverse-DFT form
/// the circuit constrains; `t` are u^1..u^{n-1}.
fn fold_idft(idft: &[Vec<Val>], evals: &[E], t: &[E]) -> E {
    let mut fold = E::ZERO;
    for (k, row) in idft.iter().enumerate() {
        let dk = evals
            .iter()
            .zip(row)
            .fold(E::ZERO, |acc, (&v, &c)| acc + v * c);
        fold += if k == 0 { dk } else { t[k - 1] * dk };
    }
    fold
}

/// Registers and Merkle replay of one query: the chain a verifier with
/// `kn` computes from the openings, the claimed index, the reduced opening
/// and the held betas / final polynomial.
fn derive(
    layout: &Layout,
    op: &QOpening,
    index: usize,
    ro: E,
    held: &Held,
    kn: &Knobs,
) -> Result<(Ctx, Walk)> {
    let g = &layout.geom;
    let bit = |i: usize, t: usize| Val::from_usize((i >> t) & 1);
    let bits: Vec<Val> = (0..g.lde).map(|t| bit(index, t)).collect();
    let f1 = |set: bool, p: Val| if set { p } else { Val::ONE - p };
    let p = |u: usize| bits[g.lde - CAP_HEIGHT + u];
    let u: [Val; 4] = core::array::from_fn(|j| f1(j & 1 != 0, p(0)) * f1(j & 2 != 0, p(1)));
    let e: [Val; 8] = core::array::from_fn(|j| u[j & 3] * f1(j & 4 != 0, p(2)));
    let mut ctx = Ctx {
        bits,
        u,
        e,
        groups: vec![],
        pos: vec![],
        f: vec![ro],
        sinv: vec![],
        t: vec![],
        xf: vec![],
        horner: vec![],
    };
    let mut walk = Walk {
        perms: vec![],
        roots: vec![],
    };
    for r in 0..g.rounds() {
        let (a, n) = (g.arities[r], g.arity(r));
        let pos = (index >> kn.shift[r]) % n;
        let evals = insert(&op.sibs[r], pos, ctx.f[r]);
        let idx2 = index >> (kn.shift[r] + a);
        let mut cells = Vec::with_capacity(2 * n - 2);
        let mut level = vec![Val::ONE];
        for l in 0..a {
            let b = bit(pos, l);
            let mut next = vec![Val::ZERO; 2 * level.len()];
            for (j, &v) in level.iter().enumerate() {
                next[j] = v * (Val::ONE - b);
                next[j + level.len()] = v * b;
            }
            cells.extend(&next);
            level = next;
        }
        let mut s = Val::ONE;
        let mut sinv = Vec::with_capacity(g.folded[r]);
        for (tt, &c) in g.sinv_f[r].iter().enumerate() {
            s *= Val::ONE + bit(idx2, tt) * (c - Val::ONE);
            sinv.push(s);
        }
        let beta = held.betas[kn.beta_of[r]];
        let u1 = beta * s;
        let mut t = vec![u1];
        for _ in 2..n {
            let last = t[t.len() - 1];
            t.push(last * u1);
        }
        let mut fold = fold_idft(&g.idft[r], &evals, &t);
        if kn.roll_in == Some(r) {
            fold += beta.exp_power_of_2(a) * ro;
        }
        // Leaf sponge (overwrite; carried tail lanes keep the last output),
        // then the path by the shifted index's bits.
        let word = |w: Word| -> Option<u64> {
            match w {
                Word::Row(_, c) => Some(u64::from(monty(
                    evals[c / D].as_basis_coefficients_slice()[c % D],
                ))),
                Word::Salt(_, s) => Some(u64::from(monty(op.salts[r][s]))),
                Word::Zero => Some(0),
                Word::Carry => None,
            }
        };
        let mut state = [0u64; 25];
        for block in layout.leaves[r].chunks(RATE_WORDS) {
            for ln in 0..RATE_LANES {
                if let (Some(lo), Some(hi)) = (word(block[2 * ln]), word(block[2 * ln + 1])) {
                    state[ln] = lo | (hi << 32);
                }
            }
            walk.perms.push(state);
            state = keccakf(&state);
        }
        let mut cur: [u64; 4] = state[..4].try_into().unwrap();
        for (tt, &sib) in op.paths[r].iter().enumerate() {
            let (l, rr) = if (idx2 >> tt) & 1 == 1 {
                (sib, cur)
            } else {
                (cur, sib)
            };
            let mut st = [0u64; 25];
            st[..4].copy_from_slice(&l);
            st[4..8].copy_from_slice(&rr);
            walk.perms.push(st);
            cur = keccakf(&st)[..4].try_into().unwrap();
        }
        walk.roots.push(cur);
        ctx.groups.push(evals);
        ctx.pos.push(cells);
        ctx.sinv.push(sinv);
        ctx.t.push(t);
        ctx.f.push(fold);
    }
    let d = index >> g.shift[g.rounds()];
    let mut x = Val::ONE;
    for (tt, &c) in g.final_f.iter().enumerate() {
        x *= Val::ONE + bit(d, tt) * (c - Val::ONE);
        ctx.xf.push(x);
    }
    require(held.final_poly.len() == g.final_len, "final-poly length")?;
    let mut h = vec![E::ZERO; g.final_len];
    h[g.final_len - 1] = held.final_poly[g.final_len - 1];
    for k in (0..g.final_len - 1).rev() {
        h[k] = h[k + 1] * x + held.final_poly[k];
    }
    ctx.horner = h;
    Ok((ctx, walk))
}

/// A claim the outer prover assembles. `settle` derives; tests edit before
/// it (forger's inputs, re-derived consistently) or after it (a single
/// poked value).
#[derive(Clone)]
struct Build {
    ops: Vec<QOpening>,
    index: Vec<usize>,
    ro: Vec<E>,
    held: Held,
    knobs: Vec<Knobs>,
    ctx: Vec<Ctx>,
    walks: Vec<Walk>,
}

impl Build {
    fn honest(layout: &Layout, inb: &Inbound, ops: Vec<QOpening>) -> Result<Self> {
        require(ops.len() == layout.queries, "one opening per covered query")?;
        let mut b = Self {
            index: inb.indices.clone(),
            ro: inb.ro.clone(),
            held: Held {
                betas: inb.betas.clone(),
                final_poly: inb.final_poly.clone(),
            },
            knobs: vec![Knobs::honest(&layout.geom); ops.len()],
            ops,
            ctx: vec![],
            walks: vec![],
        };
        b.settle(layout)?;
        Ok(b)
    }

    fn settle(&mut self, layout: &Layout) -> Result<()> {
        self.ctx.clear();
        self.walks.clear();
        for q in 0..self.ops.len() {
            let (ctx, walk) = derive(
                layout,
                &self.ops[q],
                self.index[q],
                self.ro[q],
                &self.held,
                &self.knobs[q],
            )?;
            self.ctx.push(ctx);
            self.walks.push(walk);
        }
        Ok(())
    }
}

/// Register column bases (per row, one query's context).
#[derive(Clone)]
struct Cols {
    bits: usize,
    u: usize,
    e: usize,
    group: Vec<usize>,
    pos: Vec<usize>,
    sinv: Vec<usize>,
    t: Vec<usize>,
    f: usize,
    xf: usize,
    horner: usize,
    end: usize,
}

impl Cols {
    fn new(g: &Geom, start: usize) -> Self {
        let mut at = start;
        let mut take = |n: usize| {
            let s = at;
            at += n;
            s
        };
        let bits = take(g.lde);
        let u = take(4);
        let e = take(8);
        let (mut group, mut pos, mut sinv, mut t) = (vec![], vec![], vec![], vec![]);
        for r in 0..g.rounds() {
            let n = g.arity(r);
            group.push(take(D * n));
            pos.push(take(2 * n - 2));
            sinv.push(take(g.folded[r]));
            t.push(take(D * (n - 1)));
        }
        let f = take(D * (g.rounds() + 1));
        let xf = take(g.final_bits);
        let horner = take(D * g.final_len);
        let end = take(0);
        Self {
            bits,
            u,
            e,
            group,
            pos,
            sinv,
            t,
            f,
            xf,
            horner,
            end,
        }
    }
}

/// The query-phase component: lane + commit-phase Merkle/sponge binding +
/// the folds + the final polynomial. One segment of perms per query.
#[derive(Clone)]
struct FoldAir {
    layout: Layout,
    lane: Lane,
    height: usize,
    canon_col: usize,
    cols: Cols,
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
}

impl FoldAir {
    fn new(layout: Layout, max_cells: usize) -> Result<Self> {
        let g = layout.geom.clone();
        let lane = Lane::new();
        // No S bits: the MMCS sponge overwrites, so M is the rate preimage.
        let canon_col = lane.m_col + RATE_BITS;
        let cols = Cols::new(&g, canon_col + 2 * RATE_WORDS);
        let held_col = cols.end;
        let width = held_col + D * g.rounds() + D * g.final_len;
        let perms = layout.perms();
        let height = (perms * NUM_ROUNDS).next_power_of_two();
        let (step0_per, interior_per, comp0_per, segend_per) = (0, 1, 2, 3);
        let leaf_per = 4;
        let carry_per = leaf_per + layout.roles.len();
        let lvl_per = carry_per + layout.carry_roles.len();
        let capchk_per = lvl_per + g.path[0];
        let seg_per = capchk_per + g.rounds();
        let num_periodic = seg_per + layout.queries;
        let cells = height
            .checked_mul(width + num_periodic)
            .ok_or("query phase allocation overflow")?;
        require(
            cells <= max_cells,
            "query phase exceeds materialization budget",
        )?;
        let mut periodic = vec![vec![Val::ZERO; height]; num_periodic];
        let last = |p: usize| NUM_ROUNDS * p + NUM_ROUNDS - 1;
        for p in 0..perms {
            periodic[step0_per][NUM_ROUNDS * p] = Val::ONE;
            match layout.step(p) {
                Step::Leaf(r, k) => {
                    periodic[leaf_per + layout.role(r, k)][NUM_ROUNDS * p] = Val::ONE;
                }
                Step::Node(r, t) => {
                    periodic[comp0_per][NUM_ROUNDS * p] = Val::ONE;
                    if t + 1 == g.path[r] {
                        periodic[capchk_per + r][last(p)] = Val::ONE;
                    }
                }
            }
            if p + 1 < perms {
                match layout.step(p + 1) {
                    Step::Leaf(r, k) if k > 0 => {
                        periodic[interior_per][last(p)] = Val::ONE;
                        let ro = layout.role(r, k);
                        if let Some(ci) = layout.carry_roles.iter().position(|&x| x == ro) {
                            periodic[carry_per + ci][last(p)] = Val::ONE;
                        }
                    }
                    Step::Node(r, t) => {
                        periodic[lvl_per + layout.lvl(g.shift[r + 1] + t)][last(p)] = Val::ONE;
                    }
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
            height,
            lane,
            canon_col,
            cols,
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

    // Register columns.
    fn bit_col(&self, t: usize) -> usize {
        self.cols.bits + t
    }
    fn u_col(&self, j: usize) -> usize {
        self.cols.u + j
    }
    fn e_col(&self, j: usize) -> usize {
        self.cols.e + j
    }
    fn g_col(&self, r: usize, i: usize) -> usize {
        self.cols.group[r] + D * i
    }
    /// Cell `j` of level `l` (1..=a) of round r's position one-hot.
    fn pos_col(&self, r: usize, l: usize, j: usize) -> usize {
        self.cols.pos[r] + (1 << l) - 2 + j
    }
    fn top_col(&self, r: usize, j: usize) -> usize {
        self.pos_col(r, self.layout.geom.arities[r], j)
    }
    fn sinv_col(&self, r: usize, t: usize) -> usize {
        self.cols.sinv[r] + t
    }
    /// u^k of round r, k >= 1.
    fn t_col(&self, r: usize, k: usize) -> usize {
        self.cols.t[r] + D * (k - 1)
    }
    fn f_col(&self, r: usize) -> usize {
        self.cols.f + D * r
    }
    fn xf_col(&self, t: usize) -> usize {
        self.cols.xf + t
    }
    fn h_col(&self, k: usize) -> usize {
        self.cols.horner + D * k
    }
    // Held columns.
    fn beta_col(&self, r: usize) -> usize {
        self.held_col + D * r
    }
    fn final_col(&self, c: usize) -> usize {
        self.held_col + D * self.layout.geom.rounds() + D * c
    }

    /// One query's registers, laid out from `cols.bits`.
    fn regs(&self, ctx: &Ctx) -> Vec<Val> {
        let base = self.cols.bits;
        let mut v = vec![Val::ZERO; self.cols.end - base];
        let mut put =
            |col: usize, xs: &[Val]| v[col - base..col - base + xs.len()].copy_from_slice(xs);
        let limbs = |x: &E| x.as_basis_coefficients_slice().to_vec();
        put(self.bit_col(0), &ctx.bits);
        put(self.u_col(0), &ctx.u);
        put(self.e_col(0), &ctx.e);
        for r in 0..self.layout.geom.rounds() {
            for (i, x) in ctx.groups[r].iter().enumerate() {
                put(self.g_col(r, i), &limbs(x));
            }
            put(self.cols.pos[r], &ctx.pos[r]);
            put(self.sinv_col(r, 0), &ctx.sinv[r]);
            for (k, x) in ctx.t[r].iter().enumerate() {
                put(self.t_col(r, k + 1), &limbs(x));
            }
        }
        for (r, x) in ctx.f.iter().enumerate() {
            put(self.f_col(r), &limbs(x));
        }
        put(self.xf_col(0), &ctx.xf);
        for (k, x) in ctx.horner.iter().enumerate() {
            put(self.h_col(k), &limbs(x));
        }
        v
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
        for (p, pre) in perms.iter().enumerate() {
            let row = NUM_ROUNDS * p;
            for ln in 0..RATE_LANES {
                for bit in 0..64 {
                    values[row * w + self.lane.m_col + 64 * ln + bit] =
                        Val::from_u64((pre[ln] >> bit) & 1);
                }
            }
            if let Step::Leaf(r, k) = layout.step(p) {
                let words = &layout.leaves[r][RATE_WORDS * k..RATE_WORDS * (k + 1)];
                for (slot, &word) in words.iter().enumerate() {
                    if matches!(word, Word::Row(..)) {
                        let v = (pre[slot / 2] >> (32 * (slot % 2))) as u32;
                        Lane::fill_canonical(&mut values, row * w + self.canon_col + 2 * slot, v);
                    }
                }
            }
        }
        let mut held = vec![Val::ZERO; w - self.held_col];
        let mut put = |col: usize, v: &E| {
            let at = col - self.held_col;
            held[at..at + D].copy_from_slice(v.as_basis_coefficients_slice());
        };
        for (r, b) in build.held.betas.iter().enumerate() {
            put(self.beta_col(r), b);
        }
        for (c, v) in build.held.final_poly.iter().enumerate() {
            put(self.final_col(c), v);
        }
        let regs: Vec<Vec<Val>> = build.ctx.iter().map(|c| self.regs(c)).collect();
        let seg = layout.seg_rows();
        for row in 0..h {
            let cells = &mut values[row * w..(row + 1) * w];
            cells[self.held_col..].copy_from_slice(&held);
            let q = (row / seg).min(q_n - 1);
            cells[self.cols.bits..self.cols.end].copy_from_slice(&regs[q]);
        }
        Ok(RowMajorMatrix::new(values, w))
    }

    /// Public values: every input as 2b-i / 2b-ii export it.
    fn public_values(&self, inb: &Inbound) -> Vec<Val> {
        let mut pv = Vec::with_capacity(self.layout.num_public_values());
        for cap in &inb.caps {
            for n in 0..CAP_WORDS {
                let word = (cap[n / 8][(n % 8) / 2] >> (32 * (n % 2))) as u32;
                pv.extend([Val::from_u32(word & 0xffff), Val::from_u32(word >> 16)]);
            }
        }
        for v in inb.betas.iter().chain(&inb.final_poly) {
            pv.extend_from_slice(v.as_basis_coefficients_slice());
        }
        pv.extend(inb.indices.iter().map(|&i| Val::from_usize(i)));
        for r in &inb.ro {
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

impl Phased for FoldAir {
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
        let leaf = |ro: usize| per[self.leaf_per + ro].clone();
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let roles: Vec<usize> = (0..layout.roles.len())
                        .filter(|&ro| matches!(layout.role_words(ro)[slot], Word::Row(..)))
                        .collect();
                    if roles.is_empty() {
                        continue;
                    }
                    let gate = roles.iter().fold(AB::Expr::ZERO, |acc, &ro| acc + leaf(ro));
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
        let rounds = g.rounds();
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
                    for ro in 0..layout.roles.len() {
                        if layout.role_words(ro)[slot] == Word::Zero {
                            gate = Some(gate.map_or(leaf(ro), |x| x + leaf(ro)));
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
                for (ci, &ro) in layout.carry_roles.iter().enumerate() {
                    let gate = per[self.carry_per + ci].clone();
                    for ln in layout.carry_lanes(ro) {
                        for l in 0..4 {
                            builder
                                .when_transition()
                                .assert_zero(gate.clone() * (n(k.pre[ln][l]) - c(k.out[ln][l])));
                        }
                    }
                }
            }
            "bind_child" => {
                // A level reading index bit p: the digest just produced sits
                // left when the bit is 0, right when it is 1. Every round's
                // level at bit p shares one selector (the same cell drives it).
                for p in g.shift[1]..g.lde - CAP_HEIGHT {
                    let gate = per[self.lvl_per + layout.lvl(p)].clone();
                    let b = c(self.bit_col(p));
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
                // Round r's root equals the entry of round r's commit-phase
                // cap that the top index bits select.
                for r in 0..rounds {
                    let gate = per[self.capchk_per + r].clone();
                    for ln in 0..4 {
                        for l in 0..4 {
                            let sum = (0..8).fold(AB::Expr::ZERO, |acc, j| {
                                acc + c(self.e_col(j))
                                    * (c(k.out[ln][l]) - pv[layout.cap_pv(r, j, ln, l)].clone())
                            });
                            builder.assert_zero(gate.clone() * sum);
                        }
                    }
                }
            }
            "leaf_bind" => {
                // Monty words: the hashed word is R * v, the group limb is v.
                for ro in 0..layout.roles.len() {
                    let (r, _) = layout.roles[ro];
                    for (slot, &w) in layout.role_words(ro).iter().enumerate() {
                        if let Word::Row(_, cc) = w {
                            builder.assert_zero(
                                leaf(ro)
                                    * (lane.full::<AB>(cur, slot) * self.rinv
                                        - c(self.g_col(r, cc / D) + cc % D)),
                            );
                        }
                    }
                }
            }
            "index" => {
                for t in 0..g.lde {
                    builder.assert_bool(cur[self.bit_col(t)]);
                }
                let index = (0..g.lde).fold(AB::Expr::ZERO, |acc, t| {
                    acc + c(self.bit_col(t)) * lane.pow2[t]
                });
                for q in 0..layout.queries {
                    builder.assert_zero(
                        per[self.seg_per + q].clone()
                            * (index.clone() - pv[layout.index_pv(q)].clone()),
                    );
                }
            }
            "cap_select" => {
                // One-hot of the cap entry = the top CAP_HEIGHT index bits.
                let p = |u: usize| c(self.bit_col(g.lde - CAP_HEIGHT + u));
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
            "position" => {
                // Round r's position = index bits S_r..S_r+a, one level of
                // the one-hot per bit.
                for r in 0..rounds {
                    let s = g.shift[r];
                    let b = |l: usize| c(self.bit_col(s + l));
                    builder.assert_zero(c(self.pos_col(r, 1, 0)) - (one() - b(0)));
                    builder.assert_zero(c(self.pos_col(r, 1, 1)) - b(0));
                    for l in 1..g.arities[r] {
                        let half = 1 << l;
                        for j in 0..half {
                            let prev = c(self.pos_col(r, l, j));
                            builder.assert_zero(
                                c(self.pos_col(r, l + 1, j)) - prev.clone() * (one() - b(l)),
                            );
                            builder.assert_zero(c(self.pos_col(r, l + 1, j + half)) - prev * b(l));
                        }
                    }
                }
            }
            "ro_in" => {
                // The chain starts from 2b-ii's reduced opening of this query.
                for q in 0..layout.queries {
                    for limb in 0..D {
                        builder.assert_zero(
                            per[self.seg_per + q].clone()
                                * (c(self.f_col(0) + limb) - pv[layout.ro_pv(q) + limb].clone()),
                        );
                    }
                }
            }
            "select" => {
                // The running value IS the committed entry at the position.
                for r in 0..rounds {
                    for limb in 0..D {
                        let sel = (0..g.arity(r)).fold(AB::Expr::ZERO, |acc, j| {
                            acc + c(self.top_col(r, j)) * c(self.g_col(r, j) + limb)
                        });
                        builder.assert_zero(sel - c(self.f_col(r) + limb));
                    }
                }
            }
            "s_inv" => {
                // s^-1 = prod_t (w_{h+a}^{-2^{h-1-t}})^{bit}: the bit-reversed
                // shifted index, one constant factor per bit.
                for r in 0..rounds {
                    let base = g.shift[r + 1];
                    let factor =
                        |t: usize| one() + c(self.bit_col(base + t)) * (g.sinv_f[r][t] - Val::ONE);
                    builder.assert_zero(c(self.sinv_col(r, 0)) - factor(0));
                    for t in 1..g.folded[r] {
                        builder.assert_zero(
                            c(self.sinv_col(r, t)) - c(self.sinv_col(r, t - 1)) * factor(t),
                        );
                    }
                }
            }
            "fold_pow" => {
                // u = beta_r * s^-1, then u^k by successive products.
                for r in 0..rounds {
                    let s = c(self.sinv_col(r, g.folded[r] - 1));
                    for limb in 0..D {
                        builder.assert_zero(
                            c(self.t_col(r, 1) + limb) - c(self.beta_col(r) + limb) * s.clone(),
                        );
                    }
                    for kk in 2..g.arity(r) {
                        let prod =
                            self.ext_mul::<AB>(&ext(self.t_col(r, kk - 1)), &ext(self.t_col(r, 1)));
                        for (limb, p) in prod.into_iter().enumerate() {
                            builder.assert_zero(c(self.t_col(r, kk) + limb) - p);
                        }
                    }
                }
            }
            "fold" => {
                // f_{r+1} = sum_k d_k u^k: the interpolant of the group at
                // beta (`fold_row`), d_k linear in the group with constants.
                for r in 0..rounds {
                    let nn = g.arity(r);
                    let d = |kk: usize| -> [AB::Expr; D] {
                        core::array::from_fn(|limb| {
                            (0..nn).fold(AB::Expr::ZERO, |acc, i| {
                                acc + c(self.g_col(r, i) + limb) * g.idft[r][kk][i]
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
                    for (limb, a) in acc.into_iter().enumerate() {
                        builder.assert_zero(c(self.f_col(r + 1) + limb) - a);
                    }
                }
            }
            "final_x" => {
                // x = prod_t (w_lde^{2^{lde-1-t}})^{bit S_R + t}: the
                // bit-reversed final index, no coset shift.
                let base = g.shift[rounds];
                let factor =
                    |t: usize| one() + c(self.bit_col(base + t)) * (g.final_f[t] - Val::ONE);
                builder.assert_zero(c(self.xf_col(0)) - factor(0));
                for t in 1..g.final_bits {
                    builder.assert_zero(c(self.xf_col(t)) - c(self.xf_col(t - 1)) * factor(t));
                }
            }
            "horner" => {
                let x = c(self.xf_col(g.final_bits - 1));
                let last = g.final_len - 1;
                for limb in 0..D {
                    builder
                        .assert_zero(c(self.h_col(last) + limb) - c(self.final_col(last) + limb));
                    for kk in 0..last {
                        builder.assert_zero(
                            c(self.h_col(kk) + limb)
                                - c(self.h_col(kk + 1) + limb) * x.clone()
                                - c(self.final_col(kk) + limb),
                        );
                    }
                }
            }
            "final" => {
                // `verifier.rs:403-410`: the final polynomial at x equals the
                // last folded value.
                for limb in 0..D {
                    builder.assert_zero(c(self.h_col(0) + limb) - c(self.f_col(rounds) + limb));
                }
            }
            "inbound" => {
                // 2b-i's betas and final polynomial: the same values, not a
                // second supply.
                for r in 0..rounds {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(
                            c(self.beta_col(r) + limb) - pv[layout.beta_pv(r) + limb].clone(),
                        );
                    }
                }
                for cc in 0..g.final_len {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(
                            c(self.final_col(cc) + limb) - pv[layout.final_pv(cc) + limb].clone(),
                        );
                    }
                }
            }
            "hold" => {
                for col in self.held_col..self.width {
                    builder.when_transition().assert_zero(n(col) - c(col));
                }
            }
            "ctx_hold" => {
                // A query's registers are one value over its segment: the
                // group a leaf row binds is the group every row folds.
                let keep = one() - per[self.segend_per].clone();
                for col in self.cols.bits..self.cols.end {
                    builder
                        .when_transition()
                        .assert_zero(keep.clone() * (n(col) - c(col)));
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for FoldAir {
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

impl<AB: AirBuilder<F = Val>> Air<AB> for FoldAir {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::marker::PhantomData;
    use std::ops::Range;
    use std::sync::OnceLock;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    use p3_matrix::Dimensions;
    use p3_maybe_rayon::prelude::*;
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_l2::L2_CFG_PROVISIONAL;

    use super::super::fri_fs::tests::{shared, Shared};
    use super::super::lane::phase_ranges;
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};

    use super::super::lane::toy::native_through_f2;
    use super::super::open::tests::{handoff, native_mmcs, reduced_opening, Handoff, NativeMmcs};
    use super::*;

    struct Fixture {
        sh: Shared,
        ho: Handoff,
        air: FoldAir,
        ranges: Vec<Range<usize>>,
        /// Every query's commit-phase openings (all 43).
        all: Vec<QOpening>,
        held: Held,
        inb: Inbound,
        honest: Build,
    }

    /// The 2b-i/2b-ii fixture's proof (toy, log 8, seeded): its indices,
    /// betas and final polynomial as 2b-i exports them, the reduced openings
    /// as 2b-ii exports them, and an instance covering 2b-ii's two queries.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let sh = shared();
            let ho = handoff();
            let proof = sh.proof;
            let geom = Geom::new(sh.log_height, &L2_CFG_PROVISIONAL).unwrap();
            let all: Vec<QOpening> = (0..sh.indices.len())
                .map(|q| QOpening::from_proof(proof, q, &geom).unwrap())
                .collect();
            let held = Held {
                betas: sh.betas.clone(),
                final_poly: sh.final_poly.clone(),
            };
            let inb = Inbound {
                caps: proof
                    .opening_proof
                    .1
                    .commit_phase_commits
                    .iter()
                    .map(|c| c.roots().to_vec())
                    .collect(),
                betas: sh.betas.clone(),
                final_poly: sh.final_poly.clone(),
                indices: ho.covered.iter().map(|&q| sh.indices[q]).collect(),
                ro: ho.ro.clone(),
            };
            let air = FoldAir::new(Layout::new(geom, ho.covered.len()), 64 << 20).unwrap();
            let honest = Build::honest(
                &air.layout,
                &inb,
                ho.covered.iter().map(|&q| all[q].clone()).collect(),
            )
            .unwrap();
            let ranges = phase_ranges(&air);
            Fixture {
                sh,
                ho,
                air,
                ranges,
                all,
                held,
                inb,
                honest,
            }
        })
    }

    fn phase_in(ranges: &[Range<usize>], constraint: usize) -> &'static str {
        PHASES[ranges.iter().position(|r| r.contains(&constraint)).unwrap()]
    }

    fn phase_of(fx: &Fixture, constraint: usize) -> &'static str {
        phase_in(&fx.ranges, constraint)
    }

    /// Every (row, group) violated anywhere in `trace`.
    fn scan(
        air: &FoldAir,
        ranges: &[Range<usize>],
        trace: &RowMajorMatrix<Val>,
        pvs: &[Val],
    ) -> BTreeSet<(usize, &'static str)> {
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
    /// consistently; `after` pokes derived values. Public inputs are `inb`.
    fn claim_with(
        fx: &Fixture,
        inb: &Inbound,
        before: impl FnOnce(&mut Build),
        after: impl FnOnce(&mut Build),
    ) -> Claim {
        let mut build = fx.honest.clone();
        before(&mut build);
        build.settle(&fx.air.layout).unwrap();
        after(&mut build);
        let trace = fx.air.trace(&build).unwrap();
        let pvs = fx.air.public_values(inb);
        Claim { build, trace, pvs }
    }

    /// Public inputs stay the honest exports of 2b-i / 2b-ii.
    fn claim(
        fx: &Fixture,
        before: impl FnOnce(&mut Build),
        after: impl FnOnce(&mut Build),
    ) -> Claim {
        claim_with(fx, &fx.inb, before, after)
    }

    /// Every (row, group) violated anywhere in the trace.
    fn violations(fx: &Fixture, c: &Claim) -> BTreeSet<(usize, &'static str)> {
        scan(&fx.air, &fx.ranges, &c.trace, &c.pvs)
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

    fn last_row(fx: &Fixture, q: usize, pos: usize) -> usize {
        NUM_ROUNDS * (q * fx.air.layout.segment.len() + pos) + NUM_ROUNDS - 1
    }

    fn cap_row(fx: &Fixture, q: usize, r: usize) -> usize {
        let l = &fx.air.layout;
        last_row(fx, q, l.at(Step::Node(r, l.geom.path[r] - 1)))
    }

    /// The row that feeds level `t`'s compression of round `r`.
    fn feed_row(fx: &Fixture, q: usize, r: usize, t: usize) -> usize {
        last_row(fx, q, fx.air.layout.at(Step::Node(r, t)) - 1)
    }

    fn basis(i: usize) -> E {
        <E as BasedVectorSpace<Val>>::ith_basis_element(i).unwrap()
    }

    /// Native `verify_query` (`verifier.rs:448-584`) and the final check
    /// (`verifier.rs:394-410`) for one query, written from the source with
    /// p3's own `fold_row` and commit-phase MMCS: the value entering every
    /// round, then the final polynomial at the final x. Panics where p3
    /// would return an error.
    fn native_query(fx: &Fixture, q: usize, ro: E) -> (Vec<E>, E) {
        native_query_of(
            fx.sh.proof,
            fx.air.layout.geom.lde,
            q,
            fx.sh.indices[q],
            ro,
            &fx.sh.betas,
        )
    }

    fn native_query_of(
        proof: &Proof<Config>,
        lde: usize,
        q: usize,
        index: usize,
        ro: E,
        betas: &[E],
    ) -> (Vec<E>, E) {
        let fri = &proof.opening_proof.1;
        let mmcs = ExtensionMmcs::<Val, E, NativeMmcs>::new(native_mmcs());
        let folding = TwoAdicFriFolding::<(), ()>(PhantomData);
        let (mut idx, mut h, mut folded) = (index, lde, ro);
        let mut chain = vec![ro];
        for (r, step) in fri.query_proofs[q].commit_phase_openings.iter().enumerate() {
            let a = step.log_arity as usize;
            let arity = 1 << a;
            let mut evals = step.sibling_values.clone();
            evals.insert(idx % arity, folded);
            h -= a;
            idx >>= a;
            mmcs.verify_batch(
                &fri.commit_phase_commits[r],
                &[Dimensions {
                    width: arity,
                    height: 1 << h,
                }],
                idx,
                BatchOpeningRef::new(&[evals.clone()], &step.opening_proof),
            )
            .unwrap_or_else(|e| panic!("query {q} round {r}: {e:?}"));
            folded = FriFoldingStrategy::<Val, E>::fold_row(
                &folding,
                idx,
                h,
                a,
                betas[r],
                evals.into_iter(),
            );
            chain.push(folded);
        }
        let x = Val::two_adic_generator(lde).exp_u64(reverse_bits_len(idx, lde) as u64);
        let eval = fri
            .final_poly
            .iter()
            .rev()
            .fold(E::ZERO, |acc, &c| acc * x + c);
        (chain, eval)
    }

    #[test]
    fn fri_folds_accept_honest_queries_at_degree_three() {
        let fx = fixture();
        let (air, layout, g) = (&fx.air, &fx.air.layout, &fx.air.layout.geom);
        // The toy's schedule: LDE 2^11 folds 16 then 2 down to 2^6 = the
        // final domain (blowup 4 x 16 coefficients). Round 0's leaf is 64
        // limbs + 4 salt = two full blocks; round 1's is 8 + 4 = one.
        assert_eq!(
            (g.lde, g.arities.clone(), g.path.clone(), g.final_bits),
            (11, vec![4, 1], vec![4, 3], 6)
        );
        assert_eq!(layout.segment.len(), 2 + 4 + 1 + 3);
        assert!(layout.carry_roles.is_empty());
        let price = crate::f2::price::query_phase(fx.sh.log_height, layout.queries);
        assert_eq!(price["permutations_per_query"], layout.segment.len());
        assert_eq!(price["component_columns"], air.width);
        assert_eq!(price["periodic_columns"], air.periodic.len());
        assert_eq!(price["public_values"], layout.num_public_values());
        assert_eq!(price["padded_rows"], air.height);
        // All 43 queries: p3's own chain (commit-phase MMCS at every round,
        // `fold_row`, the final check) accepts from 2b-ii's reduced opening,
        // and the circuit's replica — inverse-DFT folds, constant-chain s^-1
        // and x, the lab's Merkle replay — reaches the same values and roots.
        for q in 0..fx.sh.indices.len() {
            let index = fx.sh.indices[q];
            let ro = fx.ho.ro_all[q];
            let (chain, eval) = native_query(fx, q, ro);
            assert_eq!(eval, chain[chain.len() - 1], "p3's final check, query {q}");
            let (ctx, walk) =
                derive(layout, &fx.all[q], index, ro, &fx.held, &Knobs::honest(g)).unwrap();
            assert_eq!(ctx.f, chain, "folds, query {q}");
            assert_eq!(ctx.horner[0], eval, "final evaluation, query {q}");
            for r in 0..g.rounds() {
                assert_eq!(
                    walk.roots[r],
                    fx.inb.caps[r][index >> (g.lde - CAP_HEIGHT)],
                    "query {q} round {r}"
                );
            }
        }
        let c = claim(fx, |_| {}, |_| {});
        satisfied(air, &c.trace, &c.pvs).unwrap_or_else(|v| {
            panic!(
                "honest query phase refused: {v} in {}",
                phase_of(fx, v.constraint)
            )
        });
        for (i, &q) in fx.ho.covered.iter().enumerate() {
            let (chain, _) = native_query(fx, q, fx.ho.ro_all[q]);
            assert_eq!(
                fx.ho.ro[i], fx.ho.ro_all[q],
                "2b-ii's export is the native ro"
            );
            assert_eq!(c.build.ctx[i].f, chain, "covered query {q}");
        }
        let constraints = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
        assert_eq!(fx.ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "query phase degree {max} > 3");
    }

    #[test]
    fn fri_folds_meet_2b_i_and_2b_ii_at_the_seam() {
        // Every public input here is another component's public output: the
        // commit-phase caps (2b-i's inputs, the same limbs it absorbs), the
        // betas, the final polynomial and the indices 2b-i exports, and the
        // reduced openings 2b-ii exports.
        let fx = fixture();
        let l = &fx.air.layout;
        let (rounds, len) = (l.geom.rounds(), l.geom.final_len);
        let pvs = fx.air.public_values(&fx.inb);
        let s = &fx.sh;
        assert_eq!(&pvs[..l.beta_pv(0)], &s.public[s.caps_at.clone()], "caps");
        assert_eq!(
            &pvs[l.beta_pv(0)..l.final_pv(0)],
            &s.public[s.betas_at..s.betas_at + D * rounds],
            "betas"
        );
        assert_eq!(
            &pvs[l.final_pv(0)..l.index_pv(0)],
            &s.public[s.final_at..s.final_at + D * len],
            "final polynomial"
        );
        let ho = &fx.ho;
        for (i, &q) in ho.covered.iter().enumerate() {
            assert_eq!(pvs[l.index_pv(i)], s.public[s.index_at[q]], "index {q}");
            assert_eq!(
                &pvs[l.ro_pv(i)..l.ro_pv(i) + D],
                &ho.public[ho.ro_at[i]..ho.ro_at[i] + D],
                "reduced opening {q}"
            );
        }
    }

    #[test]
    fn fri_folds_reject_commit_leaf_forgeries() {
        let fx = fixture();
        let g = &fx.air.layout.geom;
        // A salt changed: the leaf moves, nothing else does; only round 1's
        // cap comparison refuses it.
        let c = claim(fx, |b| b.ops[1].salts[1][2] += Val::ONE, |_| {});
        refused_exactly(fx, &c, &[(cap_row(fx, 1, 1), "cap")].into());
        // Two sibling entries of round 0 poked so that the fold is UNCHANGED
        // (the fold is linear in the group: w_i d_i + w_j d_j = 0), a fresh
        // salt chosen. p3's fold_row agrees the fold does not move; the
        // chain, position and final check are all satisfied. Only the Merkle
        // binding stands between this and acceptance.
        let h = &fx.honest.ctx[0];
        let (r, n) = (0, g.arity(0));
        let pos = fx.inb.indices[0] % n;
        let w = |i: usize| -> E {
            (0..n).fold(E::ZERO, |acc, k| {
                let tk = if k == 0 { E::ONE } else { h.t[r][k - 1] };
                acc + tk * g.idft[r][k][i]
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
                b.ops[0].sibs[0][sib(i)] += di;
                b.ops[0].sibs[0][sib(j)] += dj;
                b.ops[0].salts[0] = (0..SALT_ELEMS).map(|s| Val::from_usize(s + 11)).collect();
            },
            |_| {},
        );
        let forged = &c.build.ctx[0].groups[0];
        assert_ne!(forged, &h.groups[0]);
        assert_eq!(c.build.ctx[0].f, h.f, "the fold does not move");
        let folding = TwoAdicFriFolding::<(), ()>(PhantomData);
        let fold = |ev: &[E]| {
            FriFoldingStrategy::<Val, E>::fold_row(
                &folding,
                fx.inb.indices[0] >> g.shift[1],
                g.folded[0],
                g.arities[0],
                fx.inb.betas[0],
                ev.iter().copied(),
            )
        };
        assert_eq!(fold(forged), fold(&h.groups[0]), "p3 agrees");
        refused_exactly(fx, &c, &[(cap_row(fx, 0, 0), "cap")].into());
    }

    #[test]
    fn fri_folds_reject_sibling_order_and_position_forgeries() {
        let fx = fixture();
        let g = &fx.air.layout.geom;
        // Two siblings of round 0 swapped, the chain re-derived: round 0's
        // leaf moves (cap), the fold moves, so round 1's leaf carries the
        // forged value (cap) and the last fold misses the final polynomial.
        let sibs = &fx.honest.ops[0].sibs[0];
        assert_ne!(sibs[0], sibs[1]);
        let c = claim(fx, |b| b.ops[0].sibs[0].swap(0, 1), |_| {});
        let h = &fx.honest.ctx[0];
        assert_ne!(c.build.ctx[0].f[1], h.f[1]);
        assert_ne!(c.build.ctx[0].f[2], h.f[2]);
        let mut expected = rows(ctx_rows(fx, 0), "final");
        expected.insert((cap_row(fx, 0, 0), "cap"));
        expected.insert((cap_row(fx, 0, 1), "cap"));
        refused_exactly(fx, &c, &expected);
        // Round 1 reads its position and index' with round 0's shift (the
        // shift lagging one round), path, s^-1, group and fold re-derived
        // from it. Every cell that reads a mis-shifted bit refuses: the
        // one-hot (`position`), s^-1 (`s_inv`), each path level whose side
        // differs (`bind_child`), the root (`cap`), and the final check.
        let r = 1;
        let a = g.arities[r];
        let wrong = g.shift[r - 1];
        let moved = |q: usize| {
            let index = fx.inb.indices[q];
            (0..a).any(|l| (index >> (wrong + l)) & 1 != (index >> (g.shift[r] + l)) & 1)
        };
        let q = (0..fx.air.layout.queries).find(|&q| moved(q)).unwrap_or(0);
        let index = fx.inb.indices[q];
        let bit = |i: usize| (index >> i) & 1;
        let c = claim(fx, |b| b.knobs[q].shift[r] = wrong, |_| {});
        let mut expected = BTreeSet::new();
        let pos_moved = (0..a).any(|l| bit(wrong + l) != bit(g.shift[r] + l));
        let s_moved = (0..g.folded[r]).any(|t| bit(wrong + a + t) != bit(g.shift[r + 1] + t));
        assert!(pos_moved || s_moved, "the lagging shift must move a bit");
        if pos_moved {
            expected.extend(rows(ctx_rows(fx, q), "position"));
        }
        if s_moved {
            expected.extend(rows(ctx_rows(fx, q), "s_inv"));
        }
        for t in 0..g.path[r] {
            if bit(wrong + a + t) != bit(g.shift[r + 1] + t) {
                expected.insert((feed_row(fx, q, r, t), "bind_child"));
            }
        }
        // The root moves iff the leaf or a side moved (native replay).
        if c.build.walks[q].roots[r] != fx.honest.walks[q].roots[r] {
            expected.insert((cap_row(fx, q, r), "cap"));
        }
        assert_ne!(c.build.ctx[q].f[r + 1], fx.honest.ctx[q].f[r + 1]);
        expected.extend(rows(ctx_rows(fx, q), "final"));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn fri_folds_reject_chain_forgeries() {
        let fx = fixture();
        let last = fx.air.layout.queries - 1;
        // Round 1 folded with round 0's beta, powers and fold consistent
        // with it: only u = beta_1 * s^-1 and the final check refuse.
        let c = claim(fx, |b| b.knobs[last].beta_of[1] = 0, |_| {});
        assert_ne!(c.build.ctx[last].f[2], fx.honest.ctx[last].f[2]);
        let mut expected = rows(ctx_rows(fx, last), "fold_pow");
        expected.extend(rows(ctx_rows(fx, last), "final"));
        refused_exactly(fx, &c, &expected);
        // The value between rounds poked: it is neither round 0's fold nor
        // round 1's committed entry.
        let c = claim(fx, |_| {}, |b| b.ctx[last].f[1] += E::ONE);
        let mut expected = rows(ctx_rows(fx, last), "fold");
        expected.extend(rows(ctx_rows(fx, last), "select"));
        refused_exactly(fx, &c, &expected);
        // The chain does not start from 2b-ii's reduced opening: the public
        // ro differs from the entry the chain starts from.
        let mut inb = fx.inb.clone();
        inb.ro[0] += E::ONE;
        let c = claim_with(fx, &inb, |_| {}, |_| {});
        refused_exactly(fx, &c, &rows(seg(fx, 0), "ro_in"));
        // ro rolled in again after round 0 (as native does for a second
        // input height, which this proof does not have): round 0's fold
        // refuses, round 1's leaf carries the forged value, the final check
        // misses.
        let c = claim(fx, |b| b.knobs[0].roll_in = Some(0), |_| {});
        assert_ne!(c.build.ctx[0].f[2], fx.honest.ctx[0].f[2]);
        let mut expected = rows(ctx_rows(fx, 0), "fold");
        expected.extend(rows(ctx_rows(fx, 0), "final"));
        expected.insert((cap_row(fx, 0, 1), "cap"));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn fri_folds_refuse_the_final_poly_forgery_2b_i_accepts() {
        // 2b-i's `fri_transcript_rejects_final_poly_forgeries` shows this
        // forgery transcript-consistent: coefficient 5 moved by e_1,
        // absorbed AND exported consistently. Here it arrives as the public
        // final polynomial, is held and evaluated consistently — and misses
        // the folded value of every covered query.
        let fx = fixture();
        let mut inb = fx.inb.clone();
        inb.final_poly[5] += basis(1);
        let forged = inb.final_poly.clone();
        let c = claim_with(fx, &inb, |b| b.held.final_poly = forged, |_| {});
        for q in 0..fx.air.layout.queries {
            assert_ne!(c.build.ctx[q].horner[0], fx.honest.ctx[q].horner[0]);
        }
        refused_exactly(fx, &c, &rows(0..fx.air.height, "final"));
    }

    #[test]
    fn fri_folds_reject_final_point_forgeries() {
        let fx = fixture();
        let g = &fx.air.layout.geom;
        let last = fx.air.layout.queries - 1;
        // The toy's bit roles: round 0 positions on bits 0..3, round 1 on
        // bit 4; the final x reads bits 5..10.
        assert_eq!(g.shift, vec![0, 4, 5]);
        // A middle cell of the final-x chain poked, the index untouched: its
        // own step and the next one refuse; Horner still reads the honest
        // last cell, so nothing else moves.
        let c = claim(fx, |_| {}, |b| b.ctx[last].xf[2] += Val::ONE);
        refused_exactly(fx, &c, &rows(ctx_rows(fx, last), "final_x"));
        // Bit S_R (= 5, the final x's first bit) flipped in query 0's
        // registers alone, independently of the public index: the index pin
        // refuses on the segment, and every other reader of that cell sees
        // the flip — the final-x chain, both rounds' s^-1 chains (round 0
        // reads it as its bit 1, round 1 as its bit 0) and the two path
        // levels that read bit 5 (round 0 level 1, round 1 level 0).
        let b5 = g.shift[g.rounds()];
        let c = claim(
            fx,
            |_| {},
            |b| b.ctx[0].bits[b5] = Val::ONE - b.ctx[0].bits[b5],
        );
        let mut expected = rows(seg(fx, 0), "index");
        expected.extend(rows(ctx_rows(fx, 0), "final_x"));
        expected.extend(rows(ctx_rows(fx, 0), "s_inv"));
        expected.insert((feed_row(fx, 0, 0, b5 - g.shift[1]), "bind_child"));
        expected.insert((feed_row(fx, 0, 1, b5 - g.shift[2]), "bind_child"));
        refused_exactly(fx, &c, &expected);
    }

    /// The production schedule on a real hiding S3 proof — four rounds of
    /// arity 16, paths 15/11/7/3 — for two queries. The proof is the census
    /// test's (`crate::f2::s3_fixture`, one S3 prove per test binary); the
    /// FRI transcript is replayed by p3's own challenger and the reduced
    /// openings by 2b-ii's sequential `open_input` replica.
    #[test]
    fn fri_folds_accept_a_real_s3_schedule() {
        let (proof, pvs) = crate::f2::s3_proof();
        let shape = qlab_l2::Shape::S;
        let cfg = L2_CFG_PROVISIONAL;
        let geom = Geom::new(shape.log_height(), &cfg).unwrap();
        assert_eq!(
            (geom.lde, geom.arities.clone(), geom.path.clone()),
            (22, vec![4, 4, 4, 4], vec![15, 11, 7, 3])
        );
        // p3's challenger through FRI: fri_alpha, every beta (commit PoW
        // bits are 0), final polynomial, arities, the query PoW, indices.
        let fri = &proof.opening_proof.1;
        let mut ch = native_through_f2(&proof, &pvs, shape.log_height());
        let fri_alpha: E = ch.sample_algebra_element();
        let mut betas = vec![];
        for (c, &w) in fri
            .commit_phase_commits
            .iter()
            .zip(&fri.commit_pow_witnesses)
        {
            ch.observe(c.clone());
            assert!(ch.check_witness(0, w));
            betas.push(ch.sample_algebra_element());
        }
        ch.observe_algebra_slice(&fri.final_poly);
        for &a in &geom.arities {
            ch.observe(Val::from_usize(a));
        }
        assert!(ch.check_witness(cfg.grind_bits, fri.query_pow_witness));
        let indices: Vec<usize> = (0..cfg.num_queries)
            .map(|_| ch.sample_bits(geom.lde))
            .collect();
        let covered = [0usize, 1];
        let ro: Vec<E> = covered
            .iter()
            .map(|&q| {
                reduced_opening(
                    &proof,
                    &pvs,
                    shape.width(),
                    shape.log_height(),
                    q,
                    indices[q],
                    fri_alpha,
                )
            })
            .collect();
        let inb = Inbound {
            caps: fri
                .commit_phase_commits
                .iter()
                .map(|c| c.roots().to_vec())
                .collect(),
            betas: betas.clone(),
            final_poly: fri.final_poly.clone(),
            indices: covered.iter().map(|&q| indices[q]).collect(),
            ro: ro.clone(),
        };
        let ops: Vec<QOpening> = covered
            .iter()
            .map(|&q| QOpening::from_proof(&proof, q, &geom).unwrap())
            .collect();
        let air = FoldAir::new(Layout::new(geom, covered.len()), 64 << 20).unwrap();
        let (layout, g) = (&air.layout, &air.layout.geom);
        let honest = Build::honest(layout, &inb, ops).unwrap();
        // p3's chain (commit-phase MMCS every round, `fold_row`, final
        // check) accepts, and the circuit replica matches it.
        for (i, &q) in covered.iter().enumerate() {
            let (chain, eval) = native_query_of(&proof, g.lde, q, indices[q], ro[i], &betas);
            assert_eq!(eval, chain[chain.len() - 1], "p3's final check, query {q}");
            assert_eq!(honest.ctx[i].f, chain, "folds, query {q}");
            assert_eq!(honest.ctx[i].horner[0], eval, "final evaluation, query {q}");
            for r in 0..g.rounds() {
                assert_eq!(
                    honest.walks[i].roots[r],
                    inb.caps[r][indices[q] >> (g.lde - CAP_HEIGHT)],
                    "query {q} round {r}"
                );
            }
        }
        let ranges = phase_ranges(&air);
        let pv = air.public_values(&inb);
        let trace = air.trace(&honest).unwrap();
        satisfied(&air, &trace, &pv).unwrap_or_else(|v| {
            panic!(
                "honest S3 query phase refused: {v} in {}",
                phase_in(&ranges, v.constraint)
            )
        });
        // The value between rounds 0 and 1 of the last query poked: round
        // 0's fold and round 1's select refuse, on the query's rows
        // (its segment and the padding after it).
        let mut forged = honest.clone();
        forged.ctx[1].f[1] += E::ONE;
        let trace = air.trace(&forged).unwrap();
        let from = layout.seg_rows();
        let mut expected = rows(from..air.height, "fold");
        expected.extend(rows(from..air.height, "select"));
        assert_eq!(scan(&air, &ranges, &trace, &pv), expected);
    }
}
