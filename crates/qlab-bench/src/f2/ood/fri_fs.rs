//! F2b-2b-i (issue #750): the FRI half of the inner verifier's Fiat–Shamir
//! transcript, continued in-circuit from F2b-2a's F2 digest D2. Fiat–Shamir
//! only: no Merkle path, no reduced opening, no fold is checked here.
//! Test-only component, scanned row by row, never proved.
//!
//! **Native order** (p3-fri 0.6.1, hiding config, rc = 0; the challenger is
//! `SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256, 32>>`):
//!
//! 1. `verifier.rs:195` fri_alpha = `sample_algebra_element` — the flush of
//!    F2 whose digest D2 is this component's public INPUT (F2b-2a's output).
//! 2. `verifier.rs:302-311` per round r: `observe(commit_r)` (the cap, u64
//!    digest words little-endian), `check_witness(commit_pow_bits, w_r)`, then
//!    beta_r. `make_config_from` pins commit_pow_bits = 0, and `check_witness`
//!    returns before observing anything at 0 bits
//!    (p3-challenger `grinding_challenger.rs:41-47`): the commit witnesses
//!    never enter the transcript. Flush G_r = D_{r-1} ‖ cap_r.
//! 3. `verifier.rs:323` the final polynomial's coefficients, four basis limbs
//!    each; `verifier.rs:334-336` every round's log-arity as a base element;
//!    `verifier.rs:339` `check_witness(query_pow_bits, w)` = observe(w), then
//!    `sample_bits(g) == 0`. No sample sits between these observations, so
//!    they are ONE flush: H = D_{R-1} ‖ final poly ‖ arities ‖ w.
//! 4. `verifier.rs:352-353` per query `sample_bits(log_global_max_height)`
//!    (TwoAdicFriFolding adds 0 extra bits, `two_adic_pcs.rs:106`).
//!
//! **`sample_bits` semantics** (`serializing_challenger.rs`): four popped
//! bytes, little-endian, masked to the low `bits` bits — no 31-bit mask, no
//! rejection. So the PoW condition is on the LOW g bits of draw 0 of H's
//! digest (trailing zeros, not leading), and every query index sits at a
//! fixed (digest, draw) position: query i is draw i + 1 of the stream that
//! starts at H's digest. When a digest's eight draws are spent the
//! challenger re-flushes its input buffer, which then holds exactly the last
//! digest (`hash_challenger.rs` `flush`): refill Q_w = hash(D_{w-1}), one
//! perm. A final unused refill carries the last window's digest bits.
//!
//! **What is constrained**, on one lane shared with F2b-2a (`lane.rs`):
//!
//! - **Sponge**: identical gadgets; the first flush's chaining prefix is
//!   pinned to the D2 public limbs (`seed`), every later one to the previous
//!   digest (`flush_chain`).
//! - **Words**: arities and padding are constants (the schedule is a shape
//!   constant, see below), caps are outer public limbs, final-poly limbs are
//!   canonical and equal `R^-1 * word` in held cells, the PoW witness is
//!   canonical.
//! - **Draws**: fri_alpha and every beta by 2a's reject + one-hot selection;
//!   PoW by g zero bits; query index bits by same-row equality with the draw
//!   bits. Held cells (constant over all rows) carry fri_alpha, every beta,
//!   the final polynomial and every index bit for 2b-ii/iii, and are equal to
//!   public outputs on row 0 for a component that sits outside this one.
//!
//! **Fixed schedule.** p3's verifier accepts any per-round log-arity in
//! 1..=max whose sum matches the input height; the layout here fixes the
//! schedule the p3 prover commits to (`price::fri_log_arities`). A proof
//! folded on another legal schedule is refused: a completeness restriction,
//! never a false accept, and the honest prover never produces one.
//!
//! **NOT bound here (2b-ii `open.rs`, 2b-iii `fold.rs`):** the input and
//! commit-phase Merkle paths, salted leaves, the reduced opening, the folds
//! and the final-polynomial evaluation. A final polynomial the transcript
//! absorbs AND exposes consistently is accepted by this component — only the
//! query phase can refuse it (`fri_transcript_rejects_final_poly_forgeries`
//! pins that boundary; `fri_folds_refuse_the_final_poly_forgery_2b_i_accepts`
//! is the other side). A draw window needing a refill for fri_alpha or a beta (more
//! than eight field draws, ~1e-9 per challenge) is unsatisfiable, as in 2a.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, FriCfg, CAP_HEIGHT, IS_ZK};

use super::lane::{
    absorb, accepted, challenge, digest_limbs, draw_words, monty, pad, sponge_selectors, Lane,
    Phased, CAP_WORDS, DRAWS, DRAW_COLS, P, RATE_WORDS,
};
use super::{require, Result, Val, E};
use crate::f2::price::fri_log_arities;
use crate::m4gaterec::keccakf;

/// Constraint groups, in evaluation order. A negative names the group its
/// violation must land in.
const PHASES: [&str; 17] = [
    "keccak",
    "bits",
    "absorb",
    "chain_state",
    "flush_chain",
    "seed",
    "bind_const",
    "bind_cap",
    "canonical",
    "fs_reject",
    "fs_select",
    "fs_bind",
    "bind_final",
    "pow",
    "fs_index",
    "hold",
    "cells_out",
];

/// Extension limbs.
const D: usize = 4;

/// The FRI geometry the transcript layout is built from. Shape constants
/// only — nothing here is read from a proof.
#[derive(Clone, Debug)]
struct Shape {
    arities: Vec<usize>,
    final_len: usize,
    queries: usize,
    pow_bits: usize,
    index_bits: usize,
}

impl Shape {
    /// The hiding config commits every input at 2N rows, so the LDE height
    /// is log_height + IS_ZK + log_blowup and the query index takes that many
    /// bits (= sum of arities + log_blowup + log_final_poly_len).
    fn new(log_height: usize, cfg: &FriCfg) -> Result<Self> {
        let lde = log_height + IS_ZK + cfg.log_blowup;
        let arities = fri_log_arities(lde, cfg);
        let index_bits = arities.iter().sum::<usize>() + cfg.log_blowup + cfg.log_final_poly_len;
        require(
            index_bits == lde,
            "fold schedule does not reach the LDE height",
        )?;
        // Both read one u32 draw; 30 bits keeps the index sum exact in Val.
        require(index_bits <= 30, "query index wider than 30 bits")?;
        require(cfg.grind_bits <= 30, "PoW wider than 30 bits")?;
        require(cfg.num_queries > 0, "zero queries")?;
        Ok(Self {
            arities,
            final_len: 1 << cfg.log_final_poly_len,
            queries: cfg.num_queries,
            pow_bits: cfg.grind_bits,
            index_bits,
        })
    }

    fn rounds(&self) -> usize {
        self.arities.len()
    }

    /// Digests the query phase draws from: draw 0 is the PoW sample.
    fn windows(&self) -> usize {
        (1 + self.queries).div_ceil(DRAWS)
    }
}

/// Where a transcript word comes from, which decides how it is bound.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Word {
    /// Arities and sponge padding: limb-exact constants.
    Const(u32),
    /// Word `w` of the previous digest (D2 for the first flush): bound by
    /// state equality, not word by word.
    Chain(usize),
    /// Word `n` of round `r`'s commit-phase cap: outer public limbs.
    Cap(usize, usize),
    /// Limb `k` of final-poly coefficient `c`: canonical, R^-1 * word = cell.
    Final(usize, usize),
    /// The query-phase PoW witness: canonical; the PoW group reads its effect.
    Witness,
}

impl Word {
    fn is_field(self) -> bool {
        matches!(self, Self::Final(..) | Self::Witness)
    }
}

/// Static transcript layout: flushes G_0..G_{R-1}, H, Q_1..Q_W.
#[derive(Clone)]
struct Layout {
    shape: Shape,
    flushes: Vec<Vec<Word>>,
    first: Vec<usize>,
    perms: usize,
}

impl Layout {
    fn new(shape: Shape) -> Self {
        let chain = || (0..8).map(Word::Chain).collect::<Vec<Word>>();
        let mut flushes = Vec::new();
        for r in 0..shape.rounds() {
            let mut g = chain();
            g.extend((0..CAP_WORDS).map(|n| Word::Cap(r, n)));
            flushes.push(g);
        }
        let mut h = chain();
        h.extend((0..shape.final_len).flat_map(|c| (0..D).map(move |k| Word::Final(c, k))));
        h.extend(
            shape
                .arities
                .iter()
                .map(|&a| Word::Const(monty(Val::from_usize(a)))),
        );
        h.push(Word::Witness);
        flushes.push(h);
        for _ in 0..shape.windows() {
            flushes.push(chain());
        }
        let flushes: Vec<Vec<Word>> = flushes.into_iter().map(|f| pad(f, Word::Const)).collect();
        let mut first = Vec::with_capacity(flushes.len());
        let mut perms = 0;
        for f in &flushes {
            first.push(perms);
            perms += f.len() / RATE_WORDS;
        }
        Self {
            shape,
            flushes,
            first,
            perms,
        }
    }

    fn rounds(&self) -> usize {
        self.shape.rounds()
    }
    fn flush_of(&self, perm: usize) -> usize {
        (0..self.first.len())
            .rev()
            .find(|&f| perm >= self.first[f])
            .unwrap_or(0)
    }
    fn is_interior(&self, perm: usize) -> bool {
        perm < self.perms && !self.first.contains(&perm)
    }
    /// Every (perm, slot, word) of the replayed transcript.
    fn words(&self) -> impl Iterator<Item = (usize, usize, Word)> + '_ {
        (0..self.flushes.len()).flat_map(move |f| {
            self.flushes[f]
                .iter()
                .enumerate()
                .map(move |(i, &w)| (self.first[f] + i / RATE_WORDS, i % RATE_WORDS, w))
        })
    }
    fn find(&self, word: Word) -> Option<(usize, usize)> {
        self.words()
            .find(|&(_, _, w)| w == word)
            .map(|(p, s, _)| (p, s))
    }
    /// Perm whose first block carries the digest challenge `c` draws from
    /// (0: fri_alpha from D2; r + 1: beta_r from G_r's digest).
    fn challenge_perm(&self, c: usize) -> usize {
        self.first[c]
    }
    /// Perm whose first block carries query window `w`'s digest (window 0
    /// is H's digest; window w >= 1 is refill Q_w's).
    fn window_perm(&self, w: usize) -> usize {
        self.first[self.rounds() + 1 + w]
    }
    /// (window, draw) of query `i`: draw 0 of window 0 is the PoW sample.
    fn query_draw(&self, i: usize) -> (usize, usize) {
        ((i + 1) / DRAWS, (i + 1) % DRAWS)
    }
    fn cap_base(&self) -> usize {
        16
    }
    fn out_base(&self) -> usize {
        16 + 2 * CAP_WORDS * self.rounds()
    }
    fn num_public_values(&self) -> usize {
        let s = &self.shape;
        self.out_base() + D * (s.rounds() + 1) + D * s.final_len + s.queries
    }
}

/// Everything the FRI transcript absorbs, as the outer prover claims it.
#[derive(Clone)]
struct Data {
    /// F2b-2a's output: the F2 digest.
    d2: [u8; 32],
    caps: Vec<Vec<[u64; 4]>>,
    final_poly: Vec<E>,
    witness: Val,
    /// Forgery knob: absorb round 1's cap in round 0 and vice versa.
    swap_rounds: bool,
    /// Forgery knob: replace word (flush, index) by its alias word + p.
    alias: Option<(usize, usize)>,
}

impl Data {
    fn from_proof(proof: &Proof<Config>, d2: [u8; 32]) -> Result<Self> {
        let fri = &proof.opening_proof.1;
        let caps: Vec<Vec<[u64; 4]>> = fri
            .commit_phase_commits
            .iter()
            .map(|c| c.roots().to_vec())
            .collect();
        require(
            caps.iter().all(|c| c.len() == 1 << CAP_HEIGHT),
            "commit-phase cap height",
        )?;
        Ok(Self {
            d2,
            caps,
            final_poly: fri.final_poly.clone(),
            witness: fri.query_pow_witness,
            swap_rounds: false,
            alias: None,
        })
    }

    /// Cap word `n` of round `r`; u64 digest elements are observed
    /// little-endian, so low word first.
    fn cap_word(&self, r: usize, n: usize) -> u32 {
        (self.caps[r][n / 8][(n % 8) / 2] >> (32 * (n % 2))) as u32
    }
}

/// The native replay of one claimed FRI transcript.
#[derive(Clone)]
struct Replay {
    words: Vec<Vec<u32>>,
    perms: Vec<[u64; 25]>,
    /// Digest of every flush, in layout order.
    digests: Vec<[u8; 32]>,
    fri_alpha: E,
    betas: Vec<E>,
    /// `sample_bits(g)` right after the witness: must be zero.
    pow_sample: u32,
    indices: Vec<usize>,
}

impl Replay {
    fn new(layout: &Layout, data: &Data) -> Result<Self> {
        let s = &layout.shape;
        let mut words = Vec::with_capacity(layout.flushes.len());
        let mut perms = Vec::with_capacity(layout.perms);
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(layout.flushes.len());
        for (f, flush) in layout.flushes.iter().enumerate() {
            let prev = if f == 0 { data.d2 } else { digests[f - 1] };
            let mut stream = Vec::with_capacity(flush.len());
            for &w in flush {
                stream.push(match w {
                    Word::Const(c) => c,
                    Word::Chain(i) => {
                        u32::from_le_bytes(prev[4 * i..4 * i + 4].try_into().unwrap())
                    }
                    Word::Cap(r, n) => {
                        let r = match (data.swap_rounds, r) {
                            (true, 0) => 1,
                            (true, 1) => 0,
                            _ => r,
                        };
                        data.cap_word(r, n)
                    }
                    Word::Final(c, k) => monty(data.final_poly[c].as_basis_coefficients_slice()[k]),
                    Word::Witness => monty(data.witness),
                });
            }
            if let Some((af, ai)) = data.alias {
                if af == f {
                    stream[ai] = stream[ai]
                        .checked_add(P)
                        .ok_or("alias word overflows 32 bits")?;
                }
            }
            digests.push(absorb(&stream, &mut perms));
            words.push(stream);
        }
        let mut betas = Vec::with_capacity(s.rounds());
        for d in &digests[..s.rounds()] {
            betas.push(challenge(d, accepted(d)?));
        }
        let raw = |d: usize| draw_words(&digests[s.rounds() + d / DRAWS])[d % DRAWS];
        let mask = |bits: usize| (1u32 << bits) - 1;
        Ok(Self {
            fri_alpha: challenge(&data.d2, accepted(&data.d2)?),
            betas,
            pow_sample: raw(0) & mask(s.pow_bits),
            indices: (0..s.queries)
                .map(|i| (raw(i + 1) & mask(s.index_bits)) as usize)
                .collect(),
            words,
            perms,
            digests,
        })
    }
}

/// What the component hands to 2b-ii/iii: held cells, and the same values as
/// public outputs. The honest cells come from the replay; forgeries edit them.
#[derive(Clone)]
struct Cells {
    /// fri_alpha, then beta_0..beta_{R-1}.
    challenges: Vec<E>,
    final_poly: Vec<E>,
    indices: Vec<usize>,
}

impl Cells {
    fn of(rep: &Replay, data: &Data) -> Self {
        let mut challenges = vec![rep.fri_alpha];
        challenges.extend(&rep.betas);
        Self {
            challenges,
            final_poly: data.final_poly.clone(),
            indices: rep.indices.clone(),
        }
    }
}

/// The FRI transcript component: lane + sponge/FS binding + held cells.
#[derive(Clone)]
struct FriFsAir {
    layout: Layout,
    lane: Lane,
    height: usize,
    canon_col: usize,
    draw_col: usize,
    held_col: usize,
    width: usize,
    periodic: Vec<Vec<Val>>,
    rinv: Val,
}

impl FriFsAir {
    fn new(layout: Layout, max_cells: usize) -> Result<Self> {
        let s = &layout.shape;
        let height = (layout.perms * NUM_ROUNDS).next_power_of_two();
        let lane = Lane::new();
        let canon_col = lane.end();
        let draw_col = canon_col + 2 * RATE_WORDS;
        let held_col = draw_col + DRAWS * DRAW_COLS;
        let held = D * (s.rounds() + 1) + D * s.final_len + s.queries * s.index_bits;
        let width = held_col + held;
        let cells = height
            .checked_mul(width + layout.perms + 2)
            .ok_or("FRI transcript allocation overflow")?;
        require(
            cells <= max_cells,
            "FRI transcript exceeds materialization budget",
        )?;
        let periodic = sponge_selectors(&layout.first, layout.perms, height);
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            height,
            lane,
            canon_col,
            draw_col,
            held_col,
            width,
            periodic,
            rinv: r.inverse(),
            layout,
        })
    }

    /// Held limb `k` of challenge `c` (0: fri_alpha, r + 1: beta_r).
    fn challenge_col(&self, c: usize, k: usize) -> usize {
        self.held_col + D * c + k
    }
    fn final_col(&self, c: usize, k: usize) -> usize {
        self.held_col + D * (self.layout.rounds() + 1) + D * c + k
    }
    /// Held bit `t` of query index `i`.
    fn qbit_col(&self, i: usize, t: usize) -> usize {
        let s = &self.layout.shape;
        self.held_col + D * (s.rounds() + 1) + D * s.final_len + s.index_bits * i + t
    }
    fn held_len(&self) -> usize {
        self.width - self.held_col
    }

    /// Build the whole trace. `pick` overrides the field-draw selection on
    /// challenge row `c` (forgeries).
    fn trace(
        &self,
        rep: &Replay,
        data: &Data,
        cells: &Cells,
        pick: &[Option<[usize; 4]>],
    ) -> Result<RowMajorMatrix<Val>> {
        let (h, w) = (self.height, self.width);
        let s = &self.layout.shape;
        require(rep.perms.len() == self.layout.perms, "replay perm count")?;
        require(cells.challenges.len() == s.rounds() + 1, "challenge cells")?;
        require(cells.final_poly.len() == s.final_len, "final-poly cells")?;
        require(cells.indices.len() == s.queries, "index cells")?;
        let mut values = self.lane.trace(&rep.perms, h, w)?;
        for (perm, input) in rep.perms.iter().enumerate() {
            let row = NUM_ROUNDS * perm * w;
            let prev = if self.layout.is_interior(perm) {
                keccakf(&rep.perms[perm - 1])
            } else {
                [0; 25]
            };
            self.lane.fill_block(&mut values, row, input, &prev);
            let flush = self.layout.flush_of(perm);
            let first_word = (perm - self.layout.first[flush]) * RATE_WORDS;
            for slot in 0..RATE_WORDS {
                if self.layout.flushes[flush][first_word + slot].is_field() {
                    let v = rep.words[flush][first_word + slot];
                    Lane::fill_canonical(&mut values, row + self.canon_col + 2 * slot, v);
                }
            }
        }
        for c in 0..=s.rounds() {
            let d = if c == 0 {
                &data.d2
            } else {
                &rep.digests[c - 1]
            };
            let pick = match pick.get(c).copied().flatten() {
                Some(p) => p,
                None => accepted(d)?,
            };
            let row = NUM_ROUNDS * self.layout.challenge_perm(c) * w + self.draw_col;
            Lane::fill_draws(&mut values[row..row + DRAWS * DRAW_COLS], d, pick);
        }
        let mut held = vec![Val::ZERO; self.held_len()];
        let at = |col: usize| col - self.held_col;
        for (c, v) in cells.challenges.iter().enumerate() {
            for (k, &limb) in v.as_basis_coefficients_slice().iter().enumerate() {
                held[at(self.challenge_col(c, k))] = limb;
            }
        }
        for (c, v) in cells.final_poly.iter().enumerate() {
            for (k, &limb) in v.as_basis_coefficients_slice().iter().enumerate() {
                held[at(self.final_col(c, k))] = limb;
            }
        }
        for (i, &idx) in cells.indices.iter().enumerate() {
            require(idx < 1 << s.index_bits, "index cell wider than the index")?;
            for t in 0..s.index_bits {
                held[at(self.qbit_col(i, t))] = Val::from_usize((idx >> t) & 1);
            }
        }
        for row in 0..h {
            values[row * w + self.held_col..(row + 1) * w].copy_from_slice(&held);
        }
        Ok(RowMajorMatrix::new(values, w))
    }

    /// Outer public values: D2 (input) and the caps as 16-bit limbs, then the
    /// outputs: challenges, final polynomial, query indices.
    fn public_values(&self, data: &Data, cells: &Cells) -> Vec<Val> {
        let mut pv = digest_limbs(&data.d2);
        for r in 0..self.layout.rounds() {
            for n in 0..CAP_WORDS {
                let w = data.cap_word(r, n);
                pv.extend([Val::from_u32(w & 0xffff), Val::from_u32(w >> 16)]);
            }
        }
        for v in cells.challenges.iter().chain(&cells.final_poly) {
            pv.extend_from_slice(v.as_basis_coefficients_slice());
        }
        pv.extend(cells.indices.iter().map(|&i| Val::from_usize(i)));
        pv
    }
}

impl Phased for FriFsAir {
    fn phases(&self) -> &'static [&'static str] {
        &PHASES
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let (lane, layout, s) = (&self.lane, &self.layout, &self.layout.shape);
        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let step0 = |perm: usize| per[perm].clone();
        // The field-draw rows: fri_alpha's (D2) and every beta's.
        let dr = || {
            (0..=s.rounds()).fold(AB::Expr::ZERO, |acc, c| {
                acc + step0(layout.challenge_perm(c))
            })
        };
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "bits" => return lane.eval_bits(builder),
            "absorb" => return lane.eval_absorb(builder),
            "chain_state" => return lane.eval_chain_state(builder, per[layout.perms].clone()),
            "flush_chain" => return lane.eval_flush_chain(builder, per[layout.perms + 1].clone()),
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let perms: Vec<usize> = layout
                        .words()
                        .filter(|&(_, sl, w)| sl == slot && w.is_field())
                        .map(|(p, _, _)| p)
                        .collect();
                    if perms.is_empty() {
                        continue;
                    }
                    let gate = perms.iter().fold(AB::Expr::ZERO, |acc, &p| acc + step0(p));
                    lane.eval_canonical(builder, slot, gate, self.canon_col);
                }
                return;
            }
            "fs_reject" => return lane.eval_fs_reject(builder, dr(), self.draw_col),
            "fs_select" => return lane.eval_fs_select(builder, dr(), self.draw_col),
            _ => {}
        }
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { next[i].into() };
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let k = &lane.kc;
        let half = |slot: usize, h: usize| lane.half::<AB>(cur, slot, h);
        match PHASES[phase] {
            "seed" => {
                // The first flush's chaining prefix is D2: S is zero there,
                // so these preimage limbs are the fri_alpha draw bits.
                for ln in 0..4 {
                    for l in 0..4 {
                        builder
                            .when_first_row()
                            .assert_zero(c(k.pre[ln][l]) - pv[4 * ln + l].clone());
                    }
                }
            }
            "bind_const" | "bind_cap" => {
                for (perm, slot, word) in layout.words() {
                    let sel = step0(perm);
                    match (PHASES[phase], word) {
                        ("bind_const", Word::Const(v)) => {
                            builder.assert_zero(
                                sel.clone() * (half(slot, 0) - Val::from_u32(v & 0xffff)),
                            );
                            builder.assert_zero(sel * (half(slot, 1) - Val::from_u32(v >> 16)));
                        }
                        ("bind_cap", Word::Cap(r, w)) => {
                            let at = layout.cap_base() + 2 * (CAP_WORDS * r + w);
                            builder.assert_zero(sel.clone() * (half(slot, 0) - pv[at].clone()));
                            builder.assert_zero(sel * (half(slot, 1) - pv[at + 1].clone()));
                        }
                        _ => {}
                    }
                }
            }
            "fs_bind" => {
                for ch in 0..=s.rounds() {
                    let sel = step0(layout.challenge_perm(ch));
                    for slot in 0..D {
                        let drawn = lane.selected::<AB>(cur, self.draw_col, slot);
                        builder
                            .assert_zero(sel.clone() * (drawn - c(self.challenge_col(ch, slot))));
                    }
                }
            }
            "bind_final" => {
                // Monty words: the absorbed word is R * v, the cell is v.
                for (perm, slot, word) in layout.words() {
                    if let Word::Final(coeff, limb) = word {
                        builder.assert_zero(
                            step0(perm)
                                * (lane.full::<AB>(cur, slot) * self.rinv
                                    - c(self.final_col(coeff, limb))),
                        );
                    }
                }
            }
            "pow" => {
                // check_witness(g, w): the g LOW bits of draw 0 of H's digest.
                let sel = step0(layout.window_perm(0));
                for t in 0..s.pow_bits {
                    builder.assert_zero(sel.clone() * c(lane.draw_bit(0, t)));
                }
            }
            "fs_index" => {
                // sample_bits(b): the b low bits of a fixed draw, unrejected.
                for i in 0..s.queries {
                    let (w, j) = layout.query_draw(i);
                    let sel = step0(layout.window_perm(w));
                    for t in 0..s.index_bits {
                        builder.assert_zero(
                            sel.clone() * (c(lane.draw_bit(j, t)) - c(self.qbit_col(i, t))),
                        );
                    }
                }
            }
            "hold" => {
                for q in self.held_col..self.width {
                    builder.when_transition().assert_zero(n(q) - c(q));
                }
            }
            "cells_out" => {
                let base = layout.out_base();
                for ch in 0..=s.rounds() {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(
                            c(self.challenge_col(ch, limb)) - pv[base + D * ch + limb].clone(),
                        );
                    }
                }
                let base = base + D * (s.rounds() + 1);
                for coeff in 0..s.final_len {
                    for limb in 0..D {
                        builder.when_first_row().assert_zero(
                            c(self.final_col(coeff, limb)) - pv[base + D * coeff + limb].clone(),
                        );
                    }
                }
                let base = base + D * s.final_len;
                for i in 0..s.queries {
                    let index = (0..s.index_bits).fold(AB::Expr::ZERO, |acc, t| {
                        acc + c(self.qbit_col(i, t)) * lane.pow2[t]
                    });
                    builder
                        .when_first_row()
                        .assert_zero(index - pv[base + i].clone());
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for FriFsAir {
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

impl<AB: AirBuilder<F = Val>> Air<AB> for FriFsAir {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
    }
}

#[cfg(test)]
pub(in crate::f2::ood) mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::OnceLock;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_l2::L2_CFG_PROVISIONAL;

    use super::super::bind;
    use super::super::lane::toy::{native_through_f2, toy_proof, Native};
    use super::super::lane::{draw_values, phase_ranges};
    use super::super::Dims;
    use super::*;

    /// log 8: LDE 2^11 on the L2 lane folds 16 then 2, so the transcript has
    /// two commit rounds (the 2a fixture's log 4 folds once).
    const LOG_HEIGHT: usize = 8;

    struct Fixture {
        proof: Proof<Config>,
        pvs: Vec<Val>,
        air: FriFsAir,
        ranges: Vec<Range<usize>>,
        data: Data,
        honest: Replay,
    }

    /// One real hiding proof (seeded) and its FRI transcript data; D2 comes
    /// from F2b-2a's own replay of the same proof — the seam between the
    /// two components.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let (proof, pvs) = toy_proof(LOG_HEIGHT, 0xf2b2b);
            let dims = Dims {
                width: 2,
                pv_len: 2,
                log_height: LOG_HEIGHT,
                zk: qlab_consensus::IS_ZK,
            };
            let chunks = proof.opened_values.quotient_chunks.len();
            let f2 = bind::Replay::new(
                &bind::Layout::new(dims, chunks),
                &bind::Data::from_proof(&proof, &pvs).unwrap(),
            )
            .unwrap();
            let shape = Shape::new(LOG_HEIGHT, &L2_CFG_PROVISIONAL).unwrap();
            let air = FriFsAir::new(Layout::new(shape), 64 << 20).unwrap();
            let data = Data::from_proof(&proof, f2.digests[2]).unwrap();
            let honest = Replay::new(&air.layout, &data).unwrap();
            let ranges = phase_ranges(&air);
            Fixture {
                proof,
                pvs,
                air,
                ranges,
                data,
                honest,
            }
        })
    }

    /// What F2b-2b-ii's (and 2b-iii's) tests take from this fixture: the same seeded proof
    /// (one proof and one 22-bit grind per test binary, not two), the query
    /// phase's inputs as this component derives them, and this component's
    /// honest public values with the positions of its fri_alpha and index
    /// outputs — the seam 2b-ii's public inputs are compared against.
    pub(in crate::f2::ood) struct Shared {
        pub(in crate::f2::ood) proof: &'static Proof<Config>,
        pub(in crate::f2::ood) pvs: &'static [Val],
        pub(in crate::f2::ood) log_height: usize,
        pub(in crate::f2::ood) fri_alpha: E,
        pub(in crate::f2::ood) indices: Vec<usize>,
        pub(in crate::f2::ood) public: Vec<Val>,
        pub(in crate::f2::ood) fri_alpha_at: usize,
        pub(in crate::f2::ood) index_at: Vec<usize>,
        /// For 2b-iii: every beta and the final polynomial as exported, and
        /// where the commit-phase caps (inputs), the betas and the final
        /// polynomial (outputs) sit in `public`.
        pub(in crate::f2::ood) betas: Vec<E>,
        pub(in crate::f2::ood) final_poly: Vec<E>,
        pub(in crate::f2::ood) caps_at: Range<usize>,
        pub(in crate::f2::ood) betas_at: usize,
        pub(in crate::f2::ood) final_at: usize,
    }

    pub(in crate::f2::ood) fn shared() -> Shared {
        let fx = fixture();
        let layout = &fx.air.layout;
        let s = &layout.shape;
        let cells = Cells::of(&fx.honest, &fx.data);
        let indices_at = layout.out_base() + D * (s.rounds() + 1) + D * s.final_len;
        Shared {
            proof: &fx.proof,
            pvs: &fx.pvs,
            log_height: LOG_HEIGHT,
            fri_alpha: fx.honest.fri_alpha,
            indices: fx.honest.indices.clone(),
            public: fx.air.public_values(&fx.data, &cells),
            fri_alpha_at: layout.out_base(),
            index_at: (0..s.queries).map(|i| indices_at + i).collect(),
            betas: cells.challenges[1..].to_vec(),
            final_poly: cells.final_poly.clone(),
            caps_at: layout.cap_base()..layout.out_base(),
            betas_at: layout.out_base() + D,
            final_at: layout.out_base() + D * (s.rounds() + 1),
        }
    }

    fn phase_of(fx: &Fixture, constraint: usize) -> &'static str {
        PHASES[fx
            .ranges
            .iter()
            .position(|r| r.contains(&constraint))
            .unwrap()]
    }

    fn step0_row(perm: usize) -> usize {
        NUM_ROUNDS * perm
    }

    /// The native challenger, driven through the FRI commit phase (the
    /// proof's commits observed in `order`) and the final polynomial, up to
    /// the query PoW check.
    fn native_to_pow(fx: &Fixture, order: &[usize], final_poly: &[E]) -> (Native, E, Vec<E>) {
        let mut ch = native_through_f2(&fx.proof, &fx.pvs, LOG_HEIGHT);
        let fri_alpha: E = ch.sample_algebra_element();
        let fri = &fx.proof.opening_proof.1;
        let mut betas = Vec::new();
        for (&r, &w) in order.iter().zip(&fri.commit_pow_witnesses) {
            ch.observe(fri.commit_phase_commits[r].clone());
            // Commit PoW bits are 0: check_witness observes nothing.
            assert!(ch.check_witness(0, w));
            betas.push(ch.sample_algebra_element());
        }
        ch.observe_algebra_slice(final_poly);
        for &a in &fx.air.layout.shape.arities {
            ch.observe(Val::from_usize(a));
        }
        (ch, fri_alpha, betas)
    }

    /// A claim assembled by the outer prover: transcript data, then cells
    /// edited by `edit`, and optional draw selections per challenge row.
    /// Caps and D2 in the public values stay honest.
    struct Claim {
        rep: Replay,
        trace: RowMajorMatrix<Val>,
        pvs: Vec<Val>,
    }

    fn claim(
        fx: &Fixture,
        data: &Data,
        edit: impl FnOnce(&Replay, &mut Cells),
        pick: &[Option<[usize; 4]>],
    ) -> Claim {
        let rep = Replay::new(&fx.air.layout, data).unwrap();
        let mut cells = Cells::of(&rep, data);
        edit(&rep, &mut cells);
        let trace = fx.air.trace(&rep, data, &cells, pick).unwrap();
        let pvs = fx.air.public_values(&fx.data, &cells);
        Claim { rep, trace, pvs }
    }

    /// Every (row, group) violated anywhere in the trace.
    fn violations(fx: &Fixture, c: &Claim) -> BTreeSet<(usize, &'static str)> {
        (0..fx.air.height)
            .flat_map(|row| {
                violations_at(&fx.air, &c.trace, &c.pvs, row)
                    .into_iter()
                    .map(move |v| (row, phase_of(fx, v.constraint)))
            })
            .collect()
    }

    /// The claim is refused, and only by `group`, only on `rows`.
    fn refused_only_by(fx: &Fixture, c: &Claim, group: &str, rows: &[usize]) {
        let v = violations(fx, c);
        assert!(!v.is_empty(), "{group}: forgery accepted");
        for &(row, g) in &v {
            assert!(
                g == group && rows.contains(&row),
                "{group}: {row} {g} in {v:?}"
            );
        }
    }

    #[test]
    fn fri_transcript_accepts_honest_proof_at_degree_three() {
        let fx = fixture();
        let (air, layout, s) = (&fx.air, &fx.air.layout, &fx.air.layout.shape);
        let fri = &fx.proof.opening_proof.1;
        // The layout's shape constants are the proof's: the p3 prover's fold
        // schedule, one commit and one (unobserved) witness per round, the
        // final-poly length.
        let proof_arities: Vec<usize> = fri.query_proofs[0]
            .commit_phase_openings
            .iter()
            .map(|o| o.log_arity as usize)
            .collect();
        assert_eq!(s.arities, vec![4, 1]);
        assert_eq!(proof_arities, s.arities);
        assert_eq!(fri.commit_phase_commits.len(), s.rounds());
        assert_eq!(fri.commit_pow_witnesses.len(), s.rounds());
        assert_eq!(fri.final_poly.len(), s.final_len);
        assert_eq!(fri.query_proofs.len(), s.queries);
        assert_eq!((s.index_bits, s.pow_bits, s.windows()), (11, 22, 6));
        assert_eq!(layout.perms, 3 + 3 + 3 + 6, "G0, G1, H, six refills");
        // The replay IS the native transcript: fri_alpha from 2a's D2, every
        // beta, a PoW witness the p3 check accepts (a 2^-22 coincidence on
        // any other message order through H), and every query index.
        let (mut ch, fri_alpha, betas) = native_to_pow(fx, &[0, 1], &fri.final_poly);
        assert_eq!(fx.honest.fri_alpha, fri_alpha, "fri_alpha from D2");
        assert_eq!(fx.honest.betas, betas, "betas");
        assert!(
            ch.check_witness(s.pow_bits, fri.query_pow_witness),
            "native PoW"
        );
        assert_eq!(fx.honest.pow_sample, 0, "replayed PoW");
        let native: Vec<usize> = (0..s.queries)
            .map(|_| ch.sample_bits(s.index_bits))
            .collect();
        assert_eq!(fx.honest.indices, native, "query indices");
        let c = claim(fx, &fx.data, |_, _| {}, &[]);
        satisfied(air, &c.trace, &c.pvs).unwrap_or_else(|v| {
            panic!(
                "honest FRI transcript refused: {v} in {}",
                phase_of(fx, v.constraint)
            )
        });
        let constraints = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
        assert_eq!(fx.ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "FRI transcript degree {max} > 3");
    }

    #[test]
    fn fri_transcript_rejects_challenge_forgeries() {
        let fx = fixture();
        let layout = &fx.air.layout;
        // Wrong fri_alpha limb, exposed consistently.
        let c = claim(
            fx,
            &fx.data,
            |_, cells| {
                cells.challenges[0] += <E as BasedVectorSpace<Val>>::ith_basis_element(2).unwrap()
            },
            &[],
        );
        refused_only_by(fx, &c, "fs_bind", &[step0_row(layout.challenge_perm(0))]);
        // Skip an accepted draw for beta_0: limb 3 takes the fifth accepted
        // draw of G_0's digest.
        let d = &fx.honest.digests[0];
        let ok: Vec<usize> = (0..DRAWS).filter(|&j| draw_values(d)[j] < P).collect();
        assert!(ok.len() >= 5, "G_0 window has five accepted draws");
        let skip = [ok[0], ok[1], ok[2], ok[4]];
        let c = claim(
            fx,
            &fx.data,
            |_, cells| cells.challenges[1] = challenge(d, skip),
            &[None, Some(skip)],
        );
        refused_only_by(fx, &c, "fs_select", &[step0_row(layout.challenge_perm(1))]);
    }

    #[test]
    fn fri_transcript_rejects_swapped_round_caps() {
        // Round 1's cap absorbed in round 0 and vice versa: a fully
        // consistent replay of the swapped transcript — its own betas, a
        // PoW witness re-ground by the p3 challenger on it, its own indices.
        // Only the cap binding stands between this and acceptance.
        let fx = fixture();
        let fri = &fx.proof.opening_proof.1;
        let (mut ch, _, betas) = native_to_pow(fx, &[1, 0], &fri.final_poly);
        let mut data = fx.data.clone();
        data.swap_rounds = true;
        data.witness = ch.grind(fx.air.layout.shape.pow_bits);
        let c = claim(fx, &data, |_, _| {}, &[]);
        assert_eq!(c.rep.betas, betas, "swapped replay is the native one");
        assert_ne!(c.rep.betas[0], fx.honest.betas[0]);
        assert_eq!(c.rep.pow_sample, 0, "re-ground PoW");
        let layout = &fx.air.layout;
        let rows: Vec<usize> = (0..2)
            .flat_map(|r| (layout.first[r]..layout.first[r + 1]).map(step0_row))
            .collect();
        refused_only_by(fx, &c, "bind_cap", &rows);
    }

    #[test]
    fn fri_transcript_rejects_final_poly_forgeries() {
        let fx = fixture();
        let layout = &fx.air.layout;
        let fri = &fx.proof.opening_proof.1;
        let (perm, _) = layout.find(Word::Final(5, 1)).unwrap();
        // The transcript absorbs a different coefficient than the one handed
        // to the query phase; PoW re-ground on the forged transcript, indices
        // replayed from it. Only bind_final sees the split.
        let mut forged = fri.final_poly.clone();
        forged[5] += <E as BasedVectorSpace<Val>>::ith_basis_element(1).unwrap();
        let (mut ch, _, _) = native_to_pow(fx, &[0, 1], &forged);
        let mut data = fx.data.clone();
        data.final_poly = forged;
        data.witness = ch.grind(layout.shape.pow_bits);
        let honest_poly = fx.data.final_poly.clone();
        let c = claim(fx, &data, |_, cells| cells.final_poly = honest_poly, &[]);
        assert_eq!(c.rep.pow_sample, 0, "re-ground PoW");
        assert_ne!(c.rep.indices, fx.honest.indices);
        refused_only_by(fx, &c, "bind_final", &[step0_row(perm)]);
        // The same forgery handed on consistently is FS-valid: nothing in the
        // transcript can refuse it. The query phase's final-poly evaluation
        // (2b-iii) is what must.
        let c = claim(fx, &data, |_, _| {}, &[]);
        assert!(
            satisfied(&fx.air, &c.trace, &c.pvs).is_ok(),
            "consistent final-poly forgery is transcript-consistent"
        );
        // A final-poly word encoded as word + p: R^-1 * word is unchanged, so
        // only the comparator sees it on its row. The PoW (not re-ground for
        // a word the native challenger cannot absorb) fails on its own row.
        let index = layout.flushes[layout.rounds()]
            .iter()
            .position(|&w| w == Word::Final(5, 1))
            .unwrap();
        let mut data = fx.data.clone();
        data.alias = Some((layout.rounds(), index));
        let c = claim(fx, &data, |_, _| {}, &[]);
        assert_ne!(c.rep.pow_sample, 0);
        let v = violations(fx, &c);
        let groups: BTreeSet<(usize, &str)> = [
            (step0_row(perm), "canonical"),
            (step0_row(layout.window_perm(0)), "pow"),
        ]
        .into();
        assert_eq!(v, groups);
    }

    #[test]
    fn fri_transcript_rejects_failed_pow() {
        // A witness that fails the grinding condition, the rest of the
        // transcript (indices) replayed consistently from it.
        let fx = fixture();
        let fri = &fx.proof.opening_proof.1;
        let s = &fx.air.layout.shape;
        let mut data = fx.data.clone();
        let mut w = fri.query_pow_witness;
        let rep = loop {
            w += Val::ONE;
            data.witness = w;
            let rep = Replay::new(&fx.air.layout, &data).unwrap();
            if rep.pow_sample != 0 {
                break rep;
            }
        };
        let (mut ch, _, _) = native_to_pow(fx, &[0, 1], &fri.final_poly);
        assert!(!ch.check_witness(s.pow_bits, w), "native refuses it too");
        assert_ne!(rep.indices, fx.honest.indices);
        let c = claim(fx, &data, |_, _| {}, &[]);
        refused_only_by(fx, &c, "pow", &[step0_row(fx.air.layout.window_perm(0))]);
    }

    #[test]
    fn fri_transcript_rejects_query_index_forgeries() {
        let fx = fixture();
        let layout = &fx.air.layout;
        let s = &layout.shape;
        let row_of = |i: usize| step0_row(layout.window_perm(layout.query_draw(i).0));
        // One index bit flipped, cells and public index consistent.
        let c = claim(fx, &fx.data, |_, cells| cells.indices[10] ^= 1 << 3, &[]);
        refused_only_by(fx, &c, "fs_index", &[row_of(10)]);
        // A different index of the prover's choosing (another query's), the
        // transcript untouched and consistent.
        let i = 20;
        let j = (0..s.queries)
            .find(|&j| fx.honest.indices[j] != fx.honest.indices[i])
            .unwrap();
        let c = claim(
            fx,
            &fx.data,
            |rep, cells| cells.indices[i] = rep.indices[j],
            &[],
        );
        refused_only_by(fx, &c, "fs_index", &[row_of(i)]);
        // Skip a draw: queries 7.. each take the draw after their own.
        let skip_from = 7;
        let c = claim(
            fx,
            &fx.data,
            |rep, cells| {
                for i in skip_from..s.queries {
                    let (w, j) = layout.query_draw(i + 1);
                    let raw = draw_words(&rep.digests[s.rounds() + w])[j];
                    cells.indices[i] = (raw & ((1 << s.index_bits) - 1)) as usize;
                }
            },
            &[],
        );
        let rows: Vec<usize> = (skip_from..s.queries).map(row_of).collect();
        refused_only_by(fx, &c, "fs_index", &rows);
    }
}
