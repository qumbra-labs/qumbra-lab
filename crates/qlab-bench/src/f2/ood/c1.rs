//! F2b composition, slice C1 (issue #750, "two proofs per leaf"): F2b-2a's
//! transcript-bound register machine and F2b-2b-i's FRI transcript as ONE
//! AIR on ONE duplex Keccak lane, plus lever L1 — the α-weighted opened-value
//! sums Az and Bz accumulated on the opened-value absorb rows. Test-only
//! component, scanned row by row, never proved.
//!
//! **One lane, one transcript.** The flushes run back to back: F0 (metadata,
//! trace cap, inner PVs) → α; F1 (D0, quotient cap, randomizer cap) → ζ; F2
//! (D1, the opened values) → fri_alpha; G_r (D, commit cap r) → β_r; H (D,
//! final polynomial, arities, PoW witness) → PoW and the query windows;
//! Q_1..Q_W (refills). Every word order is 2a's and 2b-i's, which their own
//! tests pinned against p3 0.6.1's source. D2 — the seam between 2a and 2b-i —
//! is now an INTERNAL chain value: F2's last perm hands its digest to G_0's
//! first block through the same `flush_chain` equality every other flush
//! uses, and nothing about D2 is public.
//!
//! **The machine** is 2a's, unchanged: held input columns, bound on their
//! transcript words (`bind_opened`), to the inner PVs (`in_public`) and to the
//! α/ζ draws (`fs_bind`); the residual pinned to zero and the next point to
//! g_N·ζ on the last row. Its ROM stays a full-period periodic table (L5,
//! deferred; `price::composed_c1` states its cost).
//!
//! **Scheduling without full-period selectors.** 2a and 2b-i gated every
//! binding with one full-period periodic column per perm. C1 uses main-trace
//! state instead, as m4gate does:
//!
//! - Keccak's own `step_flags` (the period-24 ring p3-keccak-air constrains)
//!   give the step-0 and last rows of every perm;
//! - a one-hot PERM RING (one main column per lane perm) is 1 on every row
//!   of the perm it names: first row = perm 0, and it advances on the last
//!   row of each perm (`ring`). It is fully determined by the keccak flags.
//!
//! A binding gated by ring cell P_p is enforced on all 24 rows of perm p, so
//! the prover REPLICATES the perm's message bits, S bits, canonicity and
//! draw witnesses on those rows. That is what keeps every gate at degree 1 —
//! the same degree the periodic selectors had — and it is sound for the same
//! reason as before: the replicated row set includes the step-0 row, where
//! `absorb` ties the bits to the permutation input. Chain gates add the
//! keccak `fin` flag (degree 2) where they compare a perm's output to the
//! next perm's input. The only full-period columns left are the machine ROM.
//!
//! **L1: Az and Bz.** Native `open_input` (p3-fri `verifier.rs:706-753`)
//! weights opened value k by fri_alpha^k with ONE counter across the
//! randomizer, trace (ζ, then ζ·g_N) and quotient claims — and that is
//! exactly F2's absorb order (2b-ii's `Geom::term` and its test pin it). So
//! Az = Σ α^k z_k over the ζ-point terms and Bz over the ζ·g_N terms are
//! running sums over F2's blocks:
//!
//! - a block's 34 words cover at most nine terms j = 0..8; F2 starts with
//!   eight chain words and 34 ≡ 2 (mod 4), so EVEN blocks start on a term
//!   boundary (slot s → term j = s/4, limb s%4) and ODD blocks start on limb 2
//!   of the term the previous block cut (j = (s+2)/4, limb (s+2)%4). Two slot
//!   maps cover every block; block 0 is the even map with term index −2 at
//!   j = 0 (its first eight words are D1's, which the masks drop);
//! - per row, q_j = α^{k0+j} (nine extension cells, q_{j+1} = q_j·α), and q_0
//!   steps on each F2 perm's last row to q_8 (even block: the next block
//!   resumes the cut term) or to q_8·α (odd block); the anchor q_2 = 1 on F2's
//!   first block fixes k0 = −2 there;
//! - pA_j / pB_j = q_j masked by the (static) point of term k0 + j — zero for
//!   D1's words, the padding and the other point. The masks are ring sums, so
//!   the pA/pB cells are degree-2 equalities;
//! - on each F2 step-0 row, Az += Σ_s pA_{j(s)}·e_{l(s)}·(R⁻¹·word_s), Bz
//!   likewise, under two materialized gates (step-0 ∧ even, step-0 ∧ odd).
//!
//! **fri_alpha after the fact.** fri_alpha is drawn from D2 — AFTER the
//! opened values are absorbed — yet the accumulation on F2's rows needs it.
//! α is a HELD cell: one value on every row (`hold`), equal to the draw on
//! G_0's first block (`fs_bind`). Holding makes "the α used on F2's rows" and
//! "the α drawn from D2" the same cell, so the running sums computed on
//! earlier rows use the drawn value. Nothing circular remains: the trace is
//! a static witness, and every constraint is a same-row or next-row equality
//! of cells the prover fixed at once. The draw is a function of D2, D2 of the
//! absorbed words, and Az/Bz of those same words and that same α. A prover
//! who puts α' on the F2 rows and α on the draw row breaks `hold` at the
//! row where the cell changes (`c1_rejects_challenge_forgeries`).
//!
//! **Exports (the C1 → C2 seam, [`Seam`]).** Inputs: the inner PVs and every
//! cap (trace, quotient, randomizer, commit rounds), which bind the absorbed
//! words. Outputs: ζ (from the machine's held cell), fri_alpha (the held
//! cell), Az, Bz (the accumulators on the last row), every β, the final
//! polynomial and the 43 query indices (each bound on its own draw or word
//! row). The opened values themselves are NOT exported: C2 needs only Az and
//! Bz for the reduced opening ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x).
//!
//! **Degree.** Every constraint has degree ≤ 3 (checked on the symbolic
//! builder by the honest test).
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, FriCfg, CAP_HEIGHT, IS_ZK};

use super::lane::{
    absorb, accepted, challenge, draw_words, monty, pad, Lane, Phased, CAP_WORDS, DRAWS, DRAW_COLS,
    P, RATE_WORDS,
};
use super::machine::{eval_machine, Schedule};
use super::{require, Dims, Input, Inputs, Program, Result, Val, E};
use crate::f2::price::fri_log_arities;
use crate::m4gaterec::keccakf;

/// Constraint groups, in evaluation order. A negative names the group(s) its
/// violation must land in, on named rows.
const PHASES: [&str; 27] = [
    "keccak",
    "bits",
    "absorb",
    "ring",
    "chain_state",
    "flush_chain",
    "bind_const",
    "bind_cap",
    "bind_inner_pv",
    "canonical",
    "fs_reject",
    "fs_select",
    "fs_bind",
    "bind_final",
    "pow",
    "fs_index",
    "bind_opened",
    "in_public",
    "hold",
    "machine",
    "machine_out",
    "alpha_chain",
    "mask",
    "gate",
    "accumulate",
    "cells_out",
    "az_out",
];

/// Extension limbs.
const D: usize = 4;
/// Terms a 34-word block can touch (j = 0..8).
const TERMS_PER_BLOCK: usize = 9;
/// Main columns L1 adds: q_j, T = q_8·α, pA_j, pB_j, the two step-0 parity
/// gates, Az and Bz. `price::composed_c1_layout` states the same count (the
/// honest test pins the two widths equal).
const L1_COLUMNS: usize = D * TERMS_PER_BLOCK * 3 + D + 2 + 2 * D;
/// Flush indices: F0, F1, F2, then G_r = FIRST_G + r, H, the refills.
const F2: usize = 2;
const FIRST_G: usize = 3;

/// The point a term is opened at.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Point {
    Zeta,
    Next,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Open {
    Random(usize),
    Local(usize),
    Next(usize),
    Quotient(usize, usize),
}

impl Open {
    fn point(self) -> Point {
        match self {
            Self::Next(_) => Point::Next,
            _ => Point::Zeta,
        }
    }
}

/// Where a transcript word comes from, which decides how it is bound.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Word {
    /// Metadata, arities and sponge padding: limb-exact constants.
    Const(u32),
    /// Word `w` of the previous flush's digest: bound by state equality.
    Chain(usize),
    /// Word `n` of cap block `b` (0 trace, 1 quotient, 2 randomizer, 3 + r
    /// commit round r): limb-exact against outer public limbs.
    Cap(usize, usize),
    /// Inner public value `j`: canonical, R^-1 * word = outer PV `j`.
    InnerPv(usize),
    /// Limb `l` of opened term `k` (F2 order = `open_input` order).
    Opened(usize, usize),
    /// Limb `l` of final-poly coefficient `c`: canonical, R^-1 * word = PV.
    Final(usize, usize),
    /// The query-phase PoW witness: canonical; `pow` reads its effect.
    Witness,
}

impl Word {
    fn is_field(self) -> bool {
        matches!(
            self,
            Self::InnerPv(_) | Self::Opened(..) | Self::Final(..) | Self::Witness
        )
    }
}

/// FRI shape constants, as 2b-i fixes them (`price::fri_log_arities`).
#[derive(Clone, Debug)]
struct Fri {
    arities: Vec<usize>,
    final_len: usize,
    queries: usize,
    pow_bits: usize,
    index_bits: usize,
}

impl Fri {
    fn new(log_height: usize, cfg: &FriCfg) -> Result<Self> {
        let lde = log_height + IS_ZK + cfg.log_blowup;
        let arities = fri_log_arities(lde, cfg);
        let index_bits = arities.iter().sum::<usize>() + cfg.log_blowup + cfg.log_final_poly_len;
        require(index_bits == lde, "fold schedule does not reach the LDE")?;
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

/// The two slot maps of an F2 block: slot `s` → (term j in the block, limb).
fn slot_map(parity: usize, s: usize) -> (usize, usize) {
    let o = s + 2 * parity;
    (o / 4, o % 4)
}

/// Term index at j = 0 of F2 block `b` (block 0: −2, D1's words).
fn block_k0(b: usize) -> isize {
    (RATE_WORDS as isize * b as isize - 8).div_euclid(4)
}

/// Static transcript layout, from the dimensions and FRI shape alone.
#[derive(Clone)]
struct Layout {
    dims: Dims,
    fri: Fri,
    /// Every opened value in F2 order = term order.
    opened: Vec<Open>,
    flushes: Vec<Vec<Word>>,
    first: Vec<usize>,
    perms: usize,
    /// Per F2 block, per j: the point of term k0 + j (None: not a term).
    classes: Vec<[Option<Point>; TERMS_PER_BLOCK]>,
}

impl Layout {
    fn new(dims: Dims, chunks: usize, fri: Fri) -> Result<Self> {
        let w = dims.width;
        let chain = || (0..8).map(Word::Chain).collect::<Vec<Word>>();
        let mut f0 = vec![
            Word::Const(monty(Val::from_usize(dims.log_height + IS_ZK))),
            Word::Const(monty(Val::from_usize(dims.log_height))),
            Word::Const(monty(Val::ZERO)),
        ];
        f0.extend((0..CAP_WORDS).map(|n| Word::Cap(0, n)));
        f0.extend((0..dims.pv_len).map(Word::InnerPv));
        let mut f1 = chain();
        f1.extend((0..CAP_WORDS).map(|n| Word::Cap(1, n)));
        f1.extend((0..CAP_WORDS).map(|n| Word::Cap(2, n)));
        let opened: Vec<Open> = (0..D)
            .map(Open::Random)
            .chain((0..w).map(Open::Local))
            .chain((0..w).map(Open::Next))
            .chain((0..chunks).flat_map(|c| (0..D).map(move |e| Open::Quotient(c, e))))
            .collect();
        let mut f2 = chain();
        for k in 0..opened.len() {
            f2.extend((0..D).map(|l| Word::Opened(k, l)));
        }
        let mut flushes = vec![f0, f1, f2];
        for r in 0..fri.rounds() {
            let mut g = chain();
            g.extend((0..CAP_WORDS).map(|n| Word::Cap(3 + r, n)));
            flushes.push(g);
        }
        let mut h = chain();
        h.extend((0..fri.final_len).flat_map(|c| (0..D).map(move |l| Word::Final(c, l))));
        h.extend(
            fri.arities
                .iter()
                .map(|&a| Word::Const(monty(Val::from_usize(a)))),
        );
        h.push(Word::Witness);
        flushes.push(h);
        for _ in 0..fri.windows() {
            flushes.push(chain());
        }
        let flushes: Vec<Vec<Word>> = flushes.into_iter().map(|f| pad(f, Word::Const)).collect();
        let mut first = Vec::with_capacity(flushes.len());
        let mut perms = 0;
        for f in &flushes {
            first.push(perms);
            perms += f.len() / RATE_WORDS;
        }
        // L1's slot maps, checked against the layout rather than trusted: a
        // term's words sit where the parity map says, and a slot the map
        // sends outside [0, terms) holds D1's words or padding.
        let terms = opened.len() as isize;
        require(
            block_k0(0) + 2 == 0,
            "F2 block 0 must start two terms early",
        )?;
        let blocks = flushes[F2].len() / RATE_WORDS;
        let mut classes = Vec::with_capacity(blocks);
        for b in 0..blocks {
            let k0 = block_k0(b);
            let mut class = [None; TERMS_PER_BLOCK];
            for (j, c) in class.iter_mut().enumerate() {
                let k = k0 + j as isize;
                if (0..terms).contains(&k) {
                    *c = Some(opened[k as usize].point());
                }
            }
            for s in 0..RATE_WORDS {
                let (j, l) = slot_map(b % 2, s);
                match flushes[F2][RATE_WORDS * b + s] {
                    Word::Opened(k, limb) => require(
                        k as isize == k0 + j as isize && limb == l,
                        "opened word off its slot map",
                    )?,
                    _ => require(class[j].is_none(), "non-term word under a term mask")?,
                }
            }
            classes.push(class);
        }
        Ok(Self {
            dims,
            fri,
            opened,
            flushes,
            first,
            perms,
            classes,
        })
    }

    fn rounds(&self) -> usize {
        self.fri.rounds()
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
    /// Field challenges in draw order: 0 alpha, 1 zeta, 2 fri_alpha, 3 + r
    /// beta_r. Challenge `c` draws from digest `c` (flush `c`'s), whose bits
    /// are the M bits of flush `c + 1`'s first block.
    fn challenges(&self) -> usize {
        3 + self.rounds()
    }
    fn draw_perm(&self, c: usize) -> usize {
        self.first[c + 1]
    }
    /// Perm whose first block carries query window `w`'s digest (window 0
    /// is H's digest, window w >= 1 refill Q_w's).
    fn window_perm(&self, w: usize) -> usize {
        self.first[FIRST_G + self.rounds() + 1 + w]
    }
    /// (window, draw) of query `i`: draw 0 of window 0 is the PoW sample.
    fn query_draw(&self, i: usize) -> (usize, usize) {
        ((i + 1) / DRAWS, (i + 1) % DRAWS)
    }
    fn f2_blocks(&self) -> usize {
        self.classes.len()
    }
    /// F2 perms of `parity` (block index parity); `with_successor` keeps
    /// only those followed by another F2 block (the q_0 step).
    fn f2_perms(&self, parity: usize, with_successor: bool) -> Vec<usize> {
        (0..self.f2_blocks())
            .filter(|&b| b % 2 == parity && (!with_successor || b + 1 < self.f2_blocks()))
            .map(|b| self.first[F2] + b)
            .collect()
    }

    // Public values: inner PVs, caps, then the seam outputs.
    fn cap_pv(&self, b: usize, n: usize) -> usize {
        self.dims.pv_len + 2 * (CAP_WORDS * b + n)
    }
    fn zeta_pv(&self) -> usize {
        self.cap_pv(3 + self.rounds(), 0)
    }
    fn fri_alpha_pv(&self) -> usize {
        self.zeta_pv() + D
    }
    fn az_pv(&self) -> usize {
        self.fri_alpha_pv() + D
    }
    fn bz_pv(&self) -> usize {
        self.az_pv() + D
    }
    fn beta_pv(&self, r: usize) -> usize {
        self.bz_pv() + D + D * r
    }
    fn final_pv(&self, c: usize) -> usize {
        self.beta_pv(self.rounds()) + D * c
    }
    fn index_pv(&self, i: usize) -> usize {
        self.final_pv(self.fri.final_len) + i
    }
    fn num_public_values(&self) -> usize {
        self.index_pv(self.fri.queries)
    }
}

/// Everything the transcript absorbs, as the outer prover claims it.
#[derive(Clone)]
struct Data {
    inner_pvs: Vec<Val>,
    /// Trace, quotient, randomizer, then every commit round's cap.
    caps: Vec<Vec<[u64; 4]>>,
    random: Vec<E>,
    local: Vec<E>,
    next: Vec<E>,
    chunks: Vec<Vec<E>>,
    final_poly: Vec<E>,
    witness: Val,
    /// Forgery knob: absorb the randomizer cap before the quotient cap.
    swap_f1_caps: bool,
    /// Forgery knob: absorb round 1's cap in round 0 and vice versa.
    swap_rounds: bool,
    /// Forgery knob: replace word (flush, index) by its alias word + p.
    alias: Option<(usize, usize)>,
}

impl Data {
    fn from_proof(proof: &Proof<Config>, pvs: &[Val]) -> Result<Self> {
        let o = &proof.opened_values;
        let fri = &proof.opening_proof.1;
        let c = &proof.commitments;
        let mut caps = vec![
            c.trace.roots().to_vec(),
            c.quotient_chunks.roots().to_vec(),
            c.random
                .as_ref()
                .ok_or("missing randomizer commitment")?
                .roots()
                .to_vec(),
        ];
        caps.extend(fri.commit_phase_commits.iter().map(|x| x.roots().to_vec()));
        require(
            caps.iter().all(|x| x.len() == 1 << CAP_HEIGHT),
            "cap height",
        )?;
        Ok(Self {
            inner_pvs: pvs.to_vec(),
            caps,
            random: o.random.clone().ok_or("missing randomizer opening")?,
            local: o.trace_local.clone(),
            next: o.trace_next.clone().ok_or("missing next-row opening")?,
            chunks: o.quotient_chunks.clone(),
            final_poly: fri.final_poly.clone(),
            witness: fri.query_pow_witness,
            swap_f1_caps: false,
            swap_rounds: false,
            alias: None,
        })
    }

    /// Cap word `n` of block `b`; u64 digest elements are observed
    /// little-endian, so low word first.
    fn cap_word(&self, b: usize, n: usize) -> u32 {
        (self.caps[b][n / 8][(n % 8) / 2] >> (32 * (n % 2))) as u32
    }

    fn opened(&self, o: Open) -> E {
        match o {
            Open::Random(i) => self.random[i],
            Open::Local(i) => self.local[i],
            Open::Next(i) => self.next[i],
            Open::Quotient(c, e) => self.chunks[c][e],
        }
    }
}

/// The native replay of one claimed transcript.
#[derive(Clone)]
struct Replay {
    words: Vec<Vec<u32>>,
    perms: Vec<[u64; 25]>,
    digests: Vec<[u8; 32]>,
    /// alpha, zeta, fri_alpha, beta_0..beta_{R-1}.
    challenges: Vec<E>,
    /// `sample_bits(g)` right after the witness: must be zero.
    pow_sample: u32,
    indices: Vec<usize>,
}

impl Replay {
    fn new(layout: &Layout, data: &Data) -> Result<Self> {
        let fri = &layout.fri;
        let mut words = Vec::with_capacity(layout.flushes.len());
        let mut perms = Vec::with_capacity(layout.perms);
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(layout.flushes.len());
        for (f, flush) in layout.flushes.iter().enumerate() {
            let mut stream = Vec::with_capacity(flush.len());
            for &w in flush {
                stream.push(match w {
                    Word::Const(c) => c,
                    Word::Chain(i) => {
                        let d = &digests[f - 1];
                        u32::from_le_bytes(d[4 * i..4 * i + 4].try_into().unwrap())
                    }
                    Word::Cap(b, n) => {
                        let b = match (b, data.swap_f1_caps, data.swap_rounds) {
                            (1, true, _) => 2,
                            (2, true, _) => 1,
                            (3, _, true) => 4,
                            (4, _, true) => 3,
                            _ => b,
                        };
                        data.cap_word(b, n)
                    }
                    Word::InnerPv(j) => monty(data.inner_pvs[j]),
                    Word::Opened(k, l) => {
                        monty(data.opened(layout.opened[k]).as_basis_coefficients_slice()[l])
                    }
                    Word::Final(c, l) => monty(data.final_poly[c].as_basis_coefficients_slice()[l]),
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
        let challenges = (0..layout.challenges())
            .map(|c| -> Result<E> { Ok(challenge(&digests[c], accepted(&digests[c])?)) })
            .collect::<Result<Vec<E>>>()?;
        let window0 = FIRST_G + fri.rounds();
        let raw = |d: usize| draw_words(&digests[window0 + d / DRAWS])[d % DRAWS];
        let mask = |bits: usize| (1u32 << bits) - 1;
        Ok(Self {
            challenges,
            pow_sample: raw(0) & mask(fri.pow_bits),
            indices: (0..fri.queries)
                .map(|i| (raw(i + 1) & mask(fri.index_bits)) as usize)
                .collect(),
            words,
            perms,
            digests,
        })
    }

    fn zeta(&self) -> E {
        self.challenges[1]
    }
    fn fri_alpha(&self) -> E {
        self.challenges[2]
    }
    fn betas(&self) -> &[E] {
        &self.challenges[3..]
    }
}

/// How a machine input is bound.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// Four transcript words (perm, slot), one per extension limb.
    Words([(usize, usize); 4]),
    /// Inner PV `j` as the base-field embedding.
    Public(usize),
    /// The selected draws of challenge `c` (0 alpha, 1 zeta).
    Draw(usize),
}

/// What the outer prover puts in the trace beyond the transcript: machine
/// inputs, the held fri_alpha, the exported FRI values, draw selections and
/// the L1 masks. `of` is honest; forgeries edit it.
#[derive(Clone)]
struct Claimed {
    inputs: Vec<E>,
    fri_alpha: E,
    /// Rows `< row` carry `value` in the held fri_alpha cell instead.
    alpha_before: Option<(usize, E)>,
    betas: Vec<E>,
    final_poly: Vec<E>,
    indices: Vec<usize>,
    /// Draw selection override per challenge.
    picks: Vec<Option<[usize; 4]>>,
    /// Put term j of this F2 perm under the wrong point's mask.
    mask_flip: Option<(usize, usize)>,
}

impl Claimed {
    fn of(rep: &Replay, data: &Data, inputs: Vec<E>) -> Self {
        Self {
            inputs,
            fri_alpha: rep.fri_alpha(),
            alpha_before: None,
            betas: rep.betas().to_vec(),
            final_poly: data.final_poly.clone(),
            indices: rep.indices.clone(),
            picks: vec![None; rep.challenges.len()],
            mask_flip: None,
        }
    }

    fn alpha_at(&self, row: usize) -> E {
        match self.alpha_before {
            Some((until, v)) if row < until => v,
            _ => self.fri_alpha,
        }
    }
}

/// C1: one Keccak lane replaying the whole hiding transcript, the register
/// machine, and the L1 accumulators, in one row space.
#[derive(Clone)]
struct C1Air {
    layout: Layout,
    schedule: Schedule,
    routes: Vec<Route>,
    zeta_input: usize,
    height: usize,
    lane: Lane,
    canon_col: usize,
    draw_col: usize,
    ring_col: usize,
    q_col: usize,
    t_col: usize,
    pa_col: usize,
    pb_col: usize,
    gate_col: usize,
    az_col: usize,
    bz_col: usize,
    /// Held region: fri_alpha, then the machine's input cells.
    alpha_col: usize,
    in_col: usize,
    mach_col: usize,
    width: usize,
    /// The machine ROM: the only periodic columns (full period, L5).
    periodic: Vec<Vec<Val>>,
    rinv: Val,
    g_n: Val,
    /// (e_i * e_j) in basis limbs: extension multiplication as base terms.
    mul: [[[Val; D]; D]; D],
}

fn basis(i: usize) -> E {
    <E as BasedVectorSpace<Val>>::ith_basis_element(i).expect("extension basis")
}

impl C1Air {
    fn new(program: &Program, cfg: &FriCfg, max_cells: usize) -> Result<Self> {
        let dims = Dims {
            width: program.leaves.local.len(),
            pv_len: program.leaves.public.len(),
            log_height: program.original.log_size(),
        };
        let fri = Fri::new(dims.log_height, cfg)?;
        let layout = Layout::new(dims, program.chunk_domains.len(), fri)?;
        let schedule = program.schedule.clone();
        require(
            schedule.outputs().len() == 2,
            "expected residual and next-point roots",
        )?;
        let mut routes = Vec::new();
        let mut zeta_input = None;
        for (i, &(_, input)) in schedule.inputs().iter().enumerate() {
            routes.push(match input {
                Input::Public(j) => Route::Public(j),
                Input::Alpha => Route::Draw(0),
                Input::Zeta => {
                    zeta_input = Some(i);
                    Route::Draw(1)
                }
                Input::Local(c) | Input::Next(c) | Input::Quotient(c, _) => {
                    let open = match input {
                        Input::Local(_) => Open::Local(c),
                        Input::Next(_) => Open::Next(c),
                        Input::Quotient(_, e) => Open::Quotient(c, e),
                        _ => unreachable!("matched above"),
                    };
                    let k = layout
                        .opened
                        .iter()
                        .position(|&x| x == open)
                        .ok_or("machine input missing from the opened values")?;
                    let mut at = [(0, 0); 4];
                    for (l, slot) in at.iter_mut().enumerate() {
                        *slot = layout
                            .find(Word::Opened(k, l))
                            .ok_or("machine input missing from the transcript")?;
                    }
                    Route::Words(at)
                }
            });
        }
        let zeta_input = zeta_input.ok_or("machine never reads zeta")?;
        let rows = layout.perms * NUM_ROUNDS;
        let height = schedule.height().max(rows.next_power_of_two());
        let lane = Lane::new();
        let canon_col = lane.end();
        let draw_col = canon_col + 2 * RATE_WORDS;
        let ring_col = draw_col + DRAWS * DRAW_COLS;
        let q_col = ring_col + layout.perms;
        let t_col = q_col + D * TERMS_PER_BLOCK;
        let pa_col = t_col + D;
        let pb_col = pa_col + D * TERMS_PER_BLOCK;
        let gate_col = pb_col + D * TERMS_PER_BLOCK;
        let az_col = gate_col + 2;
        let bz_col = az_col + D;
        let alpha_col = bz_col + D;
        require(alpha_col - q_col == L1_COLUMNS, "L1 column count")?;
        let in_col = alpha_col + D;
        let mach_col = in_col + D * routes.len();
        let width = mach_col + schedule.width();
        let cells = height
            .checked_mul(width + schedule.rom_width())
            .ok_or("C1 allocation overflow")?;
        require(cells <= max_cells, "C1 exceeds materialization budget")?;
        let periodic = schedule.rom(height)?;
        let mul = core::array::from_fn(|i| {
            core::array::from_fn(|j| {
                let p = basis(i) * basis(j);
                core::array::from_fn(|k| p.as_basis_coefficients_slice()[k])
            })
        });
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            layout,
            schedule,
            routes,
            zeta_input,
            height,
            lane,
            canon_col,
            draw_col,
            ring_col,
            q_col,
            t_col,
            pa_col,
            pb_col,
            gate_col,
            az_col,
            bz_col,
            alpha_col,
            in_col,
            mach_col,
            width,
            periodic,
            rinv: r.inverse(),
            g_n: program.original.subgroup_generator(),
            mul,
        })
    }

    fn q(&self, j: usize) -> usize {
        self.q_col + D * j
    }
    fn pa(&self, j: usize) -> usize {
        self.pa_col + D * j
    }
    fn pb(&self, j: usize) -> usize {
        self.pb_col + D * j
    }

    /// Build the trace for a replayed transcript and a claim. Returns the
    /// matrix and the accumulators' final values (Az, Bz).
    fn trace(&self, rep: &Replay, cl: &Claimed) -> Result<(RowMajorMatrix<Val>, E, E)> {
        let l = &self.layout;
        let (h, w) = (self.height, self.width);
        require(rep.perms.len() == l.perms, "replay perm count")?;
        require(cl.inputs.len() == self.routes.len(), "machine inputs")?;
        require(cl.picks.len() == l.challenges(), "draw selections")?;
        let mut values = self.lane.trace(&rep.perms, h, w)?;
        // Lane, ring and canonicity witnesses, replicated on all 24 rows.
        for (perm, input) in rep.perms.iter().enumerate() {
            let prev = if l.is_interior(perm) {
                keccakf(&rep.perms[perm - 1])
            } else {
                [0; 25]
            };
            let flush = l.flush_of(perm);
            let first_word = (perm - l.first[flush]) * RATE_WORDS;
            for round in 0..NUM_ROUNDS {
                let row = (NUM_ROUNDS * perm + round) * w;
                self.lane.fill_block(&mut values, row, input, &prev);
                values[row + self.ring_col + perm] = Val::ONE;
                for slot in 0..RATE_WORDS {
                    if l.flushes[flush][first_word + slot].is_field() {
                        let v = rep.words[flush][first_word + slot];
                        Lane::fill_canonical(&mut values, row + self.canon_col + 2 * slot, v);
                    }
                }
            }
        }
        for c in 0..l.challenges() {
            let d = &rep.digests[c];
            let pick = match cl.picks[c] {
                Some(p) => p,
                None => accepted(d)?,
            };
            for round in 0..NUM_ROUNDS {
                let row = (NUM_ROUNDS * l.draw_perm(c) + round) * w + self.draw_col;
                Lane::fill_draws(&mut values[row..row + DRAWS * DRAW_COLS], d, pick);
            }
        }
        // Machine and held cells.
        let machine = self.schedule.trace_values(&cl.inputs, h)?;
        let mw = self.schedule.width();
        // L1. q_0 starts at alpha^-2 (anchor: q_2 = 1 on F2's first block)
        // and steps on each F2 perm's last row that has an F2 successor.
        let alpha_f2 = cl.alpha_at(NUM_ROUNDS * l.first[F2]);
        let mut q0 = alpha_f2.try_inverse().ok_or("fri_alpha is zero")?.square();
        let (ev, od) = (l.f2_perms(0, true), l.f2_perms(1, true));
        let (mut az, mut bz) = (E::ZERO, E::ZERO);
        let put = |cells: &mut [Val], col: usize, v: E| {
            cells[col..col + D].copy_from_slice(v.as_basis_coefficients_slice())
        };
        for row in 0..h {
            let a = cl.alpha_at(row);
            let perm = row / NUM_ROUNDS;
            let block = (perm >= l.first[F2] && perm < l.first[F2] + l.f2_blocks())
                .then(|| perm - l.first[F2]);
            let mut q = [E::ZERO; TERMS_PER_BLOCK];
            q[0] = q0;
            for j in 1..TERMS_PER_BLOCK {
                q[j] = q[j - 1] * a;
            }
            let t = q[TERMS_PER_BLOCK - 1] * a;
            let mut pa = [E::ZERO; TERMS_PER_BLOCK];
            let mut pb = [E::ZERO; TERMS_PER_BLOCK];
            if let Some(b) = block {
                for j in 0..TERMS_PER_BLOCK {
                    let mut class = l.classes[b][j];
                    if cl.mask_flip == Some((perm, j)) {
                        class = match class {
                            Some(Point::Zeta) => Some(Point::Next),
                            Some(Point::Next) => Some(Point::Zeta),
                            None => None,
                        };
                    }
                    match class {
                        Some(Point::Zeta) => pa[j] = q[j],
                        Some(Point::Next) => pb[j] = q[j],
                        None => {}
                    }
                }
            }
            let step0 = row % NUM_ROUNDS == 0;
            {
                let cells = &mut values[row * w..(row + 1) * w];
                for j in 0..TERMS_PER_BLOCK {
                    put(cells, self.q(j), q[j]);
                    put(cells, self.pa(j), pa[j]);
                    put(cells, self.pb(j), pb[j]);
                }
                put(cells, self.t_col, t);
                if let (Some(b), true) = (block, step0) {
                    cells[self.gate_col + b % 2] = Val::ONE;
                }
                put(cells, self.az_col, az);
                put(cells, self.bz_col, bz);
                put(cells, self.alpha_col, a);
                for (i, v) in cl.inputs.iter().enumerate() {
                    put(cells, self.in_col + D * i, *v);
                }
                cells[self.mach_col..].copy_from_slice(&machine[row * mw..(row + 1) * mw]);
            }
            if let (Some(b), true) = (block, step0) {
                for s in 0..RATE_WORDS {
                    let (j, limb) = slot_map(b % 2, s);
                    let v = E::from(Val::from_u32(rep.words[F2][RATE_WORDS * b + s]) * self.rinv);
                    az += pa[j] * basis(limb) * v;
                    bz += pb[j] * basis(limb) * v;
                }
            }
            if row % NUM_ROUNDS == NUM_ROUNDS - 1 {
                if ev.contains(&perm) {
                    q0 = q[TERMS_PER_BLOCK - 1];
                } else if od.contains(&perm) {
                    q0 = t;
                }
            }
        }
        Ok((RowMajorMatrix::new(values, w), az, bz))
    }

    /// Outer public values: the declared instance (inner PVs, every cap as
    /// 16-bit limbs), then the claim's seam outputs.
    fn public_values(&self, declared: &Data, cl: &Claimed, az: E, bz: E) -> Vec<Val> {
        let l = &self.layout;
        let mut pv = declared.inner_pvs.clone();
        for b in 0..3 + l.rounds() {
            for n in 0..CAP_WORDS {
                let w = declared.cap_word(b, n);
                pv.extend([Val::from_u32(w & 0xffff), Val::from_u32(w >> 16)]);
            }
        }
        let outputs = [cl.inputs[self.zeta_input], cl.alpha_at(0), az, bz];
        for v in outputs.iter().chain(&cl.betas).chain(&cl.final_poly) {
            pv.extend_from_slice(v.as_basis_coefficients_slice());
        }
        pv.extend(cl.indices.iter().map(|&i| Val::from_usize(i)));
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

impl Phased for C1Air {
    fn phases(&self) -> &'static [&'static str] {
        &PHASES
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let (lane, l) = (&self.lane, &self.layout);
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { next[i].into() };
        let ext = |col: usize| -> [AB::Expr; D] { core::array::from_fn(|i| c(col + i)) };
        // Gate of perm p: its ring cell, 1 on all 24 of its rows.
        let ring = |p: usize| c(self.ring_col + p);
        let ring_sum =
            |ps: &mut dyn Iterator<Item = usize>| ps.fold(AB::Expr::ZERO, |acc, p| acc + ring(p));
        let k = &lane.kc;
        let fin = c(k.fin);
        // The field-draw perms: alpha, zeta, fri_alpha, every beta.
        let dr = || ring_sum(&mut (0..l.challenges()).map(|ch| l.draw_perm(ch)));
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "bits" => return lane.eval_bits(builder),
            "absorb" => return lane.eval_absorb(builder),
            "chain_state" => {
                let inter = ring_sum(&mut (0..l.perms).filter(|&p| l.is_interior(p + 1)));
                return lane.eval_chain_state(builder, inter);
            }
            "flush_chain" => {
                let last = ring_sum(&mut (0..l.perms).filter(|&p| l.first[1..].contains(&(p + 1))));
                return lane.eval_flush_chain(builder, fin * last);
            }
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let perms: Vec<usize> = l
                        .words()
                        .filter(|&(_, s, w)| s == slot && w.is_field())
                        .map(|(p, _, _)| p)
                        .collect();
                    if perms.is_empty() {
                        continue;
                    }
                    let gate = ring_sum(&mut perms.into_iter());
                    lane.eval_canonical(builder, slot, gate, self.canon_col);
                }
                return;
            }
            "fs_reject" => return lane.eval_fs_reject(builder, dr(), self.draw_col),
            "fs_select" => return lane.eval_fs_select(builder, dr(), self.draw_col),
            _ => {}
        }
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let half = |slot: usize, h: usize| lane.half::<AB>(cur, slot, h);
        let full = |slot: usize| lane.full::<AB>(cur, slot);
        let one_limb = |m: usize| {
            if m == 0 {
                AB::Expr::ONE
            } else {
                AB::Expr::ZERO
            }
        };
        match PHASES[phase] {
            "ring" => {
                // First row: perm 0. Each perm's last row hands the token on;
                // after the last perm the ring is empty (padding, machine).
                for p in 0..l.perms {
                    let (start, prev) = if p == 0 {
                        (AB::Expr::ONE, AB::Expr::ZERO)
                    } else {
                        (AB::Expr::ZERO, ring(p - 1))
                    };
                    builder.when_first_row().assert_zero(ring(p) - start);
                    builder.when_transition().assert_zero(
                        n(self.ring_col + p) - ring(p) - fin.clone() * (prev - ring(p)),
                    );
                }
            }
            "bind_const" | "bind_cap" | "bind_inner_pv" | "bind_final" => {
                for (perm, slot, word) in l.words() {
                    let sel = ring(perm);
                    match (PHASES[phase], word) {
                        ("bind_const", Word::Const(v)) => {
                            builder.assert_zero(
                                sel.clone() * (half(slot, 0) - Val::from_u32(v & 0xffff)),
                            );
                            builder.assert_zero(sel * (half(slot, 1) - Val::from_u32(v >> 16)));
                        }
                        ("bind_cap", Word::Cap(b, w)) => {
                            let at = l.cap_pv(b, w);
                            builder.assert_zero(sel.clone() * (half(slot, 0) - pv[at].clone()));
                            builder.assert_zero(sel * (half(slot, 1) - pv[at + 1].clone()));
                        }
                        ("bind_inner_pv", Word::InnerPv(j)) => {
                            builder.assert_zero(sel * (full(slot) * self.rinv - pv[j].clone()));
                        }
                        ("bind_final", Word::Final(coeff, limb)) => {
                            let at = l.final_pv(coeff) + limb;
                            builder.assert_zero(sel * (full(slot) * self.rinv - pv[at].clone()));
                        }
                        _ => {}
                    }
                }
            }
            "fs_bind" => {
                // alpha and zeta into the machine's held inputs, fri_alpha
                // into its held cell, each beta straight to its output.
                for ch in 0..l.challenges() {
                    let sel = ring(l.draw_perm(ch));
                    let target = |limb: usize| -> AB::Expr {
                        match ch {
                            0 | 1 => {
                                let i = self
                                    .routes
                                    .iter()
                                    .position(|r| matches!(r, Route::Draw(x) if *x == ch))
                                    .expect("the machine reads alpha and zeta");
                                c(self.in_col + D * i + limb)
                            }
                            2 => c(self.alpha_col + limb),
                            _ => pv[l.beta_pv(ch - 3) + limb].clone(),
                        }
                    };
                    for limb in 0..D {
                        let drawn = lane.selected::<AB>(cur, self.draw_col, limb);
                        builder.assert_zero(sel.clone() * (drawn - target(limb)));
                    }
                }
            }
            "pow" => {
                // check_witness(g, w): the g LOW bits of draw 0 of H's digest.
                let sel = ring(l.window_perm(0));
                for t in 0..l.fri.pow_bits {
                    builder.assert_zero(sel.clone() * c(lane.draw_bit(0, t)));
                }
            }
            "fs_index" => {
                // sample_bits(b): the b low bits of a fixed draw, unrejected,
                // straight to the index output.
                for i in 0..l.fri.queries {
                    let (win, j) = l.query_draw(i);
                    let index = (0..l.fri.index_bits).fold(AB::Expr::ZERO, |acc, t| {
                        acc + c(lane.draw_bit(j, t)) * lane.pow2[t]
                    });
                    builder.assert_zero(
                        ring(l.window_perm(win)) * (index - pv[l.index_pv(i)].clone()),
                    );
                }
            }
            "bind_opened" => {
                for (i, route) in self.routes.iter().enumerate() {
                    if let Route::Words(at) = *route {
                        for (limb, &(perm, slot)) in at.iter().enumerate() {
                            builder.assert_zero(
                                ring(perm)
                                    * (full(slot) * self.rinv - c(self.in_col + D * i + limb)),
                            );
                        }
                    }
                }
            }
            "in_public" => {
                for (i, route) in self.routes.iter().enumerate() {
                    if let Route::Public(j) = *route {
                        builder.assert_eq(c(self.in_col + D * i), pv[j].clone());
                        for limb in 1..D {
                            builder.assert_zero(c(self.in_col + D * i + limb));
                        }
                    }
                }
            }
            "hold" => {
                for col in self.alpha_col..self.mach_col {
                    builder.when_transition().assert_zero(n(col) - c(col));
                }
            }
            "machine" => {
                let inputs: Vec<[AB::Expr; 4]> = (0..self.routes.len())
                    .map(|i| core::array::from_fn(|limb| c(self.in_col + D * i + limb)))
                    .collect();
                let per: Vec<AB::Expr> = builder
                    .periodic_values()
                    .iter()
                    .map(|v| (*v).into())
                    .collect();
                eval_machine(builder, &self.schedule, self.mach_col, &per, &inputs);
            }
            "machine_out" => {
                let [residual, next_point] =
                    [self.schedule.outputs()[0], self.schedule.outputs()[1]];
                for limb in 0..D {
                    builder
                        .when_last_row()
                        .assert_zero(c(self.mach_col + 12 + D * residual + limb));
                    builder.when_last_row().assert_zero(
                        c(self.mach_col + 12 + D * next_point + limb)
                            - c(self.in_col + D * self.zeta_input + limb) * self.g_n,
                    );
                }
            }
            "alpha_chain" => {
                // q_{j+1} = q_j * alpha and T = q_8 * alpha on every row, with
                // alpha the HELD cell; q_2 = 1 on F2's first block; q_0 steps
                // on an F2 perm's last row to q_8 (even) or T (odd).
                let alpha = ext(self.alpha_col);
                for j in 0..TERMS_PER_BLOCK {
                    let target = if j + 1 < TERMS_PER_BLOCK {
                        self.q(j + 1)
                    } else {
                        self.t_col
                    };
                    let prod = self.ext_mul::<AB>(&ext(self.q(j)), &alpha);
                    for (m, p) in prod.into_iter().enumerate() {
                        builder.assert_zero(c(target + m) - p);
                    }
                }
                let anchor = ring(l.first[F2]);
                let ev = ring_sum(&mut l.f2_perms(0, true).into_iter());
                let od = ring_sum(&mut l.f2_perms(1, true).into_iter());
                let q8 = self.q(TERMS_PER_BLOCK - 1);
                for m in 0..D {
                    builder.assert_zero(anchor.clone() * (c(self.q(2) + m) - one_limb(m)));
                    let q0 = c(self.q_col + m);
                    builder.when_transition().assert_zero(
                        n(self.q_col + m)
                            - q0.clone()
                            - fin.clone() * ev.clone() * (c(q8 + m) - q0.clone())
                            - fin.clone() * od.clone() * (c(self.t_col + m) - q0),
                    );
                }
            }
            "mask" => {
                for j in 0..TERMS_PER_BLOCK {
                    for (point, col) in [(Point::Zeta, self.pa(j)), (Point::Next, self.pb(j))] {
                        let mask = ring_sum(
                            &mut (0..l.f2_blocks())
                                .filter(|&b| l.classes[b][j] == Some(point))
                                .map(|b| l.first[F2] + b),
                        );
                        for m in 0..D {
                            builder.assert_zero(c(col + m) - mask.clone() * c(self.q(j) + m));
                        }
                    }
                }
            }
            "gate" => {
                let step0 = c(k.step0);
                for parity in 0..2 {
                    let all = ring_sum(&mut l.f2_perms(parity, false).into_iter());
                    builder.assert_zero(c(self.gate_col + parity) - step0.clone() * all);
                }
            }
            "accumulate" => {
                // acc' = acc + gate_even * sum_s p_{jE(s)} e_{lE(s)} v_s
                //            + gate_odd  * sum_s p_{jO(s)} e_{lO(s)} v_s,
                // v_s = R^-1 * word_s: the ζ-point sum from pA, ζ·g_N from pB.
                let v: Vec<AB::Expr> = (0..RATE_WORDS).map(|s| full(s) * self.rinv).collect();
                for (acc, pcol) in [(self.az_col, self.pa_col), (self.bz_col, self.pb_col)] {
                    for m in 0..D {
                        builder.when_first_row().assert_zero(c(acc + m));
                        let mut total = AB::Expr::ZERO;
                        for parity in 0..2 {
                            let mut sum = AB::Expr::ZERO;
                            for (s, vs) in v.iter().enumerate() {
                                let (j, limb) = slot_map(parity, s);
                                for i in 0..D {
                                    let f = self.mul[i][limb][m];
                                    if f != Val::ZERO {
                                        sum += c(pcol + D * j + i) * vs.clone() * f;
                                    }
                                }
                            }
                            total += c(self.gate_col + parity) * sum;
                        }
                        builder
                            .when_transition()
                            .assert_zero(n(acc + m) - c(acc + m) - total);
                    }
                }
            }
            "cells_out" => {
                for limb in 0..D {
                    builder.when_first_row().assert_zero(
                        c(self.in_col + D * self.zeta_input + limb)
                            - pv[l.zeta_pv() + limb].clone(),
                    );
                    builder.when_first_row().assert_zero(
                        c(self.alpha_col + limb) - pv[l.fri_alpha_pv() + limb].clone(),
                    );
                }
            }
            "az_out" => {
                for limb in 0..D {
                    builder
                        .when_last_row()
                        .assert_zero(c(self.az_col + limb) - pv[l.az_pv() + limb].clone());
                    builder
                        .when_last_row()
                        .assert_zero(c(self.bz_col + limb) - pv[l.bz_pv() + limb].clone());
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for C1Air {
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

impl<AB: AirBuilder<F = Val>> Air<AB> for C1Air {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
    }
}

/// The C1 → C2 seam: what C1's public values say, as values. C2's public
/// inputs are read into the same struct, and `check_seams(c1, c2)` (native,
/// and in-circuit at the next level) is field-by-field equality of the two.
#[derive(Clone, Debug, PartialEq)]
struct Seam {
    inner_pvs: Vec<Val>,
    /// Trace, quotient, randomizer, then every commit round's cap.
    caps: Vec<Vec<[u64; 4]>>,
    zeta: E,
    fri_alpha: E,
    az: E,
    bz: E,
    betas: Vec<E>,
    final_poly: Vec<E>,
    indices: Vec<usize>,
}

impl Seam {
    /// The `check_seams`-ready accessor: C1's public values as a [`Seam`].
    fn read(layout: &Layout, pvs: &[Val]) -> Result<Self> {
        require(
            pvs.len() == layout.num_public_values(),
            "C1 public value count",
        )?;
        let ext = |at: usize| E::from_basis_coefficients_fn(|i| pvs[at + i]);
        let limb = |at: usize| -> Result<u64> {
            let v = pvs[at].as_canonical_u32();
            require(v < 1 << 16, "cap limb wider than 16 bits")?;
            Ok(u64::from(v))
        };
        let mut caps = Vec::with_capacity(3 + layout.rounds());
        for b in 0..3 + layout.rounds() {
            let mut cap = vec![[0u64; 4]; 1 << CAP_HEIGHT];
            for n in 0..CAP_WORDS {
                let at = layout.cap_pv(b, n);
                let word = limb(at)? | (limb(at + 1)? << 16);
                cap[n / 8][(n % 8) / 2] |= word << (32 * (n % 2));
            }
            caps.push(cap);
        }
        Ok(Self {
            inner_pvs: pvs[..layout.dims.pv_len].to_vec(),
            caps,
            zeta: ext(layout.zeta_pv()),
            fri_alpha: ext(layout.fri_alpha_pv()),
            az: ext(layout.az_pv()),
            bz: ext(layout.bz_pv()),
            betas: (0..layout.rounds())
                .map(|r| ext(layout.beta_pv(r)))
                .collect(),
            final_poly: (0..layout.fri.final_len)
                .map(|c| ext(layout.final_pv(c)))
                .collect(),
            indices: (0..layout.fri.queries)
                .map(|i| pvs[layout.index_pv(i)].as_canonical_u32() as usize)
                .collect(),
        })
    }
}

/// The machine's honest inputs for a DAG input assignment, in schedule order.
fn machine_inputs(program: &Program, inputs: &Inputs) -> Result<Vec<E>> {
    let values = program.evaluate(inputs)?;
    Ok(program
        .schedule
        .inputs()
        .iter()
        .map(|&(id, _)| values[id])
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::OnceLock;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
    use p3_field::TwoAdicField;
    use p3_maybe_rayon::prelude::*;
    use p3_uni_stark::StarkGenericConfig;
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_l2::L2_CFG_PROVISIONAL;

    use super::super::bind;
    use super::super::fri_fs::tests::shared;
    use super::super::lane::toy::{Native, Toy};
    use super::super::lane::{draw_values, phase_ranges};
    use super::super::open::tests::reduced_opening;
    use super::super::{compare_native, proof_inputs_dims};
    use super::*;
    use crate::f2::price::{composed_c1_layout, MachineDims};

    /// 2b-i's fixture proof: the toy at log 8 (LDE 2^11, folds 16 then 2).
    const LOG_HEIGHT: usize = 8;

    struct Fixture {
        proof: &'static Proof<Config>,
        pvs: &'static [Val],
        program: Program,
        air: C1Air,
        ranges: Vec<Range<usize>>,
        data: Data,
        inputs: Inputs,
        honest: Replay,
    }

    fn dims() -> Dims {
        Dims {
            width: 2,
            pv_len: 2,
            log_height: LOG_HEIGHT,
        }
    }

    /// The seeded log-8 toy proof 2b-i, 2b-ii and 2b-iii already share (one
    /// proof and one 22-bit grind per test binary), and everything derived.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let sh = shared();
            assert_eq!(sh.log_height, LOG_HEIGHT);
            let program = Program::compile_dims(dims(), &Toy).unwrap();
            let inputs = proof_inputs_dims(dims(), sh.proof, sh.pvs).unwrap();
            let values = compare_native(&program, &Toy, &inputs).unwrap();
            assert_eq!(values[program.residual], E::ZERO, "native OOD relation");
            let air = C1Air::new(&program, &L2_CFG_PROVISIONAL, 64 << 20).unwrap();
            let data = Data::from_proof(sh.proof, sh.pvs).unwrap();
            let honest = Replay::new(&air.layout, &data).unwrap();
            let ranges = phase_ranges(&air);
            Fixture {
                proof: sh.proof,
                pvs: sh.pvs,
                program,
                air,
                ranges,
                data,
                inputs,
                honest,
            }
        })
    }

    fn phase_of(fx: &Fixture, constraint: usize) -> &'static str {
        PHASES[fx
            .ranges
            .iter()
            .position(|r| r.contains(&constraint))
            .unwrap()]
    }

    /// The p3 challenger driven through the whole hiding transcript a claim
    /// absorbs (its F1 cap order, opened values, FRI cap order and final
    /// polynomial), up to the query PoW check.
    struct NativeRun {
        ch: Native,
        challenges: Vec<E>,
    }

    fn native_to_pow(fx: &Fixture, data: &Data) -> NativeRun {
        let proof = fx.proof;
        let c = &proof.commitments;
        let fri = &proof.opening_proof.1;
        let mut ch = qlab_l2::make_config_l2().initialise_challenger();
        ch.observe(Val::from_usize(proof.degree_bits));
        ch.observe(Val::from_usize(LOG_HEIGHT));
        ch.observe(Val::ZERO);
        ch.observe(c.trace.clone());
        ch.observe_slice(&data.inner_pvs);
        let mut challenges: Vec<E> = vec![ch.sample_algebra_element()];
        let (quotient, random) = (c.quotient_chunks.clone(), c.random.clone().unwrap());
        if data.swap_f1_caps {
            ch.observe(random);
            ch.observe(quotient);
        } else {
            ch.observe(quotient);
            ch.observe(random);
        }
        challenges.push(ch.sample_algebra_element());
        ch.observe_algebra_slice(&data.random);
        ch.observe_algebra_slice(&data.local);
        ch.observe_algebra_slice(&data.next);
        for chunk in &data.chunks {
            ch.observe_algebra_slice(chunk);
        }
        challenges.push(ch.sample_algebra_element());
        let order: Vec<usize> = if data.swap_rounds {
            vec![1, 0]
        } else {
            (0..fri.commit_phase_commits.len()).collect()
        };
        // Commit PoW bits are 0: check_witness observes nothing there.
        for r in order {
            ch.observe(fri.commit_phase_commits[r].clone());
            challenges.push(ch.sample_algebra_element());
        }
        ch.observe_algebra_slice(&data.final_poly);
        for &a in &fx.air.layout.fri.arities {
            ch.observe(Val::from_usize(a));
        }
        NativeRun { ch, challenges }
    }

    /// Native `open_input` claim order (uni-stark `verifier.rs:453-510`,
    /// p3-fri `verifier.rs:706-753`), written from the proof's structure and
    /// independently of the layout: batches randomizer, trace (ζ then ζ·g_N),
    /// quotient chunks; one running fri_alpha power. With `query = None` it
    /// sums the opened values (Az, Bz); with `Some(q)` query q's input-batch
    /// rows (Ax, Bx).
    /// Per batch, per matrix: (at zeta_next?, the values at that point).
    type Claims<'a> = [Vec<Vec<(bool, &'a Vec<E>)>>; 3];

    fn native_sums(proof: &Proof<Config>, fri_alpha: E, query: Option<usize>) -> (E, E) {
        let o = &proof.opened_values;
        let random = o.random.as_ref().unwrap();
        let next = o.trace_next.as_ref().unwrap();
        let claims: Claims<'_> = [
            vec![vec![(false, random)]],
            vec![vec![(false, &o.trace_local), (true, next)]],
            o.quotient_chunks.iter().map(|x| vec![(false, x)]).collect(),
        ];
        let (mut pw, mut a, mut b) = (E::ONE, E::ZERO, E::ZERO);
        for (batch, mats) in claims.iter().enumerate() {
            for (m, points) in mats.iter().enumerate() {
                for &(is_next, at_z) in points {
                    let row: Vec<E> = match query {
                        None => at_z.clone(),
                        Some(q) => proof.opening_proof.1.query_proofs[q].input_proof[batch]
                            .opened_values[m]
                            .iter()
                            .map(|&v| E::from(v))
                            .collect(),
                    };
                    for v in row {
                        if is_next {
                            b += pw * v;
                        } else {
                            a += pw * v;
                        }
                        pw *= fri_alpha;
                    }
                }
            }
        }
        (a, b)
    }

    struct Claim {
        rep: Replay,
        trace: RowMajorMatrix<Val>,
        pvs: Vec<Val>,
    }

    /// A claim: the replay of `data`, the machine on `inputs`, then `edit`
    /// on the claimed cells. Caps and inner PVs in the public values stay the
    /// declared (honest) instance; the seam outputs are the claim's own.
    fn claim(
        fx: &Fixture,
        data: &Data,
        inputs: &Inputs,
        edit: impl FnOnce(&Replay, &mut Claimed),
    ) -> Claim {
        let rep = Replay::new(&fx.air.layout, data).unwrap();
        let mut cl = Claimed::of(&rep, data, machine_inputs(&fx.program, inputs).unwrap());
        edit(&rep, &mut cl);
        let (trace, az, bz) = fx.air.trace(&rep, &cl).unwrap();
        let pvs = fx.air.public_values(&fx.data, &cl, az, bz);
        Claim { rep, trace, pvs }
    }

    fn honest(fx: &Fixture) -> Claim {
        claim(fx, &fx.data, &fx.inputs, |_, _| {})
    }

    type Groups = BTreeSet<(usize, &'static str)>;

    /// Every (row, group) violated anywhere in the trace.
    fn violations(fx: &Fixture, c: &Claim) -> Groups {
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

    /// Refused, and exactly by `expected`.
    fn refused_exactly(fx: &Fixture, c: &Claim, expected: &Groups) {
        let v = violations(fx, c);
        assert!(!v.is_empty(), "forgery accepted");
        assert_eq!(&v, expected);
    }

    /// All 24 rows of `perm`, in `group`.
    fn perm_rows(perm: usize, group: &'static str) -> Groups {
        (NUM_ROUNDS * perm..NUM_ROUNDS * (perm + 1))
            .map(|row| (row, group))
            .collect()
    }

    fn last(fx: &Fixture) -> usize {
        fx.air.height - 1
    }

    /// Re-solve quotient chunk (0, 0) so the residual vanishes at
    /// `inputs.zeta`: the residual is affine in that opening.
    fn zero_residual(fx: &Fixture, inputs: &mut Inputs) {
        let r0 = fx.program.evaluate(inputs).unwrap()[fx.program.residual];
        let mut bumped = inputs.clone();
        bumped.chunks[0][0] += E::ONE;
        let r1 = fx.program.evaluate(&bumped).unwrap()[fx.program.residual];
        inputs.chunks[0][0] += r0 * (r0 - r1).inverse();
        assert_eq!(
            fx.program.evaluate(inputs).unwrap()[fx.program.residual],
            E::ZERO
        );
    }

    fn with_openings(data: &Data, inputs: &Inputs) -> Data {
        let mut d = data.clone();
        d.local = inputs.local.clone();
        d.next = inputs.next.clone();
        d.chunks = inputs.chunks.clone();
        d
    }

    fn residual(fx: &Fixture, inputs: &Inputs) -> E {
        fx.program.evaluate(inputs).unwrap()[fx.program.residual]
    }

    /// Perms where a cap word the claim absorbs differs from the declared
    /// cap's word at that position.
    fn moved_cap_perms(fx: &Fixture, c: &Claim) -> Vec<usize> {
        let l = &fx.air.layout;
        let mut perms: Vec<usize> = l
            .words()
            .filter_map(|(perm, slot, w)| match w {
                Word::Cap(b, n) => {
                    let f = l.flush_of(perm);
                    let i = (perm - l.first[f]) * RATE_WORDS + slot;
                    (c.rep.words[f][i] != fx.data.cap_word(b, n)).then_some(perm)
                }
                _ => None,
            })
            .collect();
        perms.dedup();
        perms
    }

    #[test]
    fn c1_accepts_honest_hiding_transcript_at_degree_three() {
        let fx = fixture();
        let (air, l) = (&fx.air, &fx.air.layout);
        let proof = fx.proof;
        // One lane: 2a's 3 + 5 + 5 perms, then 2b-i's G0, G1, H and six
        // refills (3 + 3 + 3 + 6). 40 opened terms over five F2 blocks.
        assert_eq!(l.perms, 13 + 15);
        assert_eq!(l.first[..4], [0, 3, 8, 13]);
        assert_eq!((l.opened.len(), l.f2_blocks()), (40, 5));
        assert_eq!(l.fri.arities, vec![4, 1]);
        // Term 6 (trace-next column 0) is cut across F2 blocks 0 and 1.
        assert_eq!(l.classes[0][8], Some(Point::Next));
        assert_eq!(l.classes[1][0], Some(Point::Next));
        assert_eq!(l.classes[0][..2], [None, None], "D1's words");
        assert_eq!(l.classes[4][8], None, "padding");
        // The layout's shape constants are the proof's.
        let fri = &proof.opening_proof.1;
        assert_eq!(fri.commit_phase_commits.len(), l.rounds());
        assert_eq!(fri.final_poly.len(), l.fri.final_len);
        assert_eq!(fri.query_proofs.len(), l.fri.queries);
        // The pricing formula is this layout (toy dims, the toy machine).
        let m = MachineDims {
            width: air.schedule.width(),
            rom_width: air.schedule.rom_width(),
            inputs: air.routes.len(),
            height: air.schedule.height(),
        };
        let price = composed_c1_layout(2, 2, LOG_HEIGHT, 8, &m);
        assert_eq!(price["lane_permutations"], l.perms);
        assert_eq!(price["component_columns"], air.width);
        assert_eq!(price["padded_rows"], air.height);
        assert_eq!(price["periodic_columns"], air.periodic.len());
        assert_eq!(price["public_values"], l.num_public_values());
        // The replay IS the native transcript: every challenge from p3's own
        // challenger, a PoW the p3 check accepts, every query index.
        let mut run = native_to_pow(fx, &fx.data);
        let rep = &fx.honest;
        assert_eq!(rep.challenges, run.challenges);
        assert_eq!(
            (rep.challenges[0], rep.zeta()),
            (fx.inputs.alpha, fx.inputs.zeta)
        );
        assert!(run.ch.check_witness(l.fri.pow_bits, fri.query_pow_witness));
        assert_eq!(rep.pow_sample, 0);
        let native: Vec<usize> = (0..l.fri.queries)
            .map(|_| run.ch.sample_bits(l.fri.index_bits))
            .collect();
        assert_eq!(rep.indices, native, "query indices");
        // The seams the composition removes: D2 is 2a's, and the FRI values
        // are 2b-i's, for the same proof.
        let two_a = bind::Replay::new(
            &bind::Layout::new(dims(), proof.opened_values.quotient_chunks.len()),
            &bind::Data::from_proof(proof, fx.pvs).unwrap(),
        )
        .unwrap();
        assert_eq!(rep.digests[F2], two_a.digests[2], "D2");
        let sh = shared();
        assert_eq!(rep.fri_alpha(), sh.fri_alpha);
        assert_eq!(rep.betas(), &sh.betas[..]);
        assert_eq!(rep.indices, sh.indices);
        // SAT, and the seam read back from the public values equals the
        // native one: Az/Bz from the source-order sums, everything else
        // from p3's challenger and the proof.
        let c = honest(fx);
        satisfied(air, &c.trace, &c.pvs)
            .unwrap_or_else(|v| panic!("honest C1 refused: {v} in {}", phase_of(fx, v.constraint)));
        assert_eq!(residual(fx, &fx.inputs), E::ZERO);
        let (az, bz) = native_sums(proof, rep.fri_alpha(), None);
        let seam = Seam::read(l, &c.pvs).unwrap();
        assert_eq!(
            seam,
            Seam {
                inner_pvs: fx.pvs.to_vec(),
                caps: fx.data.caps.clone(),
                zeta: fx.inputs.zeta,
                fri_alpha: rep.fri_alpha(),
                az,
                bz,
                betas: rep.betas().to_vec(),
                final_poly: fri.final_poly.clone(),
                indices: native,
            }
        );
        // The split is the one C2 needs: for every query, 2b-ii's sequential
        // `open_input` replica equals (Az - Ax)/(ζ - x) + (Bz - Bx)/(ζ·g_N - x).
        let lde = l.fri.index_bits;
        let g_n = Val::two_adic_generator(LOG_HEIGHT);
        for (q, &index) in seam.indices.iter().enumerate() {
            let ro = reduced_opening(proof, fx.pvs, 2, LOG_HEIGHT, q, index, seam.fri_alpha);
            let x = E::from(
                Val::GENERATOR
                    * Val::two_adic_generator(lde)
                        .exp_u64(p3_util::reverse_bits_len(index, lde) as u64),
            );
            let (ax, bx) = native_sums(proof, seam.fri_alpha, Some(q));
            let split = (seam.az - ax) * (seam.zeta - x).inverse()
                + (seam.bz - bx) * (seam.zeta * g_n - x).inverse();
            assert_eq!(split, ro, "query {q}");
        }
        let constraints = get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
        assert_eq!(fx.ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "C1 degree {max} > 3");
    }

    #[test]
    fn c1_rejects_challenge_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        // Wrong zeta limb / wrong alpha limb, the machine recomputed on the
        // lie: the draw binding refuses on the draw perm, and the residual is
        // no longer zero.
        for (ch, limb) in [(1, 2), (0, 0)] {
            let mut inputs = fx.inputs.clone();
            if ch == 1 {
                inputs.zeta += basis(limb);
            } else {
                inputs.alpha += basis(limb);
            }
            assert_ne!(residual(fx, &inputs), E::ZERO);
            let c = claim(fx, &fx.data, &inputs, |_, _| {});
            let mut expected = perm_rows(l.draw_perm(ch), "fs_bind");
            expected.insert((last(fx), "machine_out"));
            refused_exactly(fx, &c, &expected);
        }
        // Wrong fri_alpha, held on every row, exported, and the running sums
        // recomputed with it: only its draw binding refuses.
        let c = claim(fx, &fx.data, &fx.inputs, |_, cl| cl.fri_alpha += basis(2));
        refused_exactly(fx, &c, &perm_rows(l.draw_perm(2), "fs_bind"));
        // The after-the-fact binding: F2's rows (and the export) use alpha',
        // the draw row and every later row the drawn alpha. The only thing
        // between the accumulators and alpha' is the hold on the cell, at the
        // row where it changes.
        let switch = NUM_ROUNDS * l.draw_perm(2);
        let c = claim(fx, &fx.data, &fx.inputs, |rep, cl| {
            cl.alpha_before = Some((switch, rep.fri_alpha() + E::ONE));
        });
        let (az, _) = native_sums(fx.proof, fx.honest.fri_alpha(), None);
        assert_ne!(Seam::read(l, &c.pvs).unwrap().az, az, "Az on alpha'");
        refused_exactly(fx, &c, &[(switch - 1, "hold")].into());
        // Skip an accepted draw for beta_0: limb 3 takes the fifth accepted
        // draw of G_0's digest, exported consistently.
        let d = &fx.honest.digests[3];
        let ok: Vec<usize> = (0..DRAWS).filter(|&j| draw_values(d)[j] < P).collect();
        assert!(ok.len() >= 5, "G_0 window has five accepted draws");
        let skip = [ok[0], ok[1], ok[2], ok[4]];
        let c = claim(fx, &fx.data, &fx.inputs, |_, cl| {
            cl.betas[0] = challenge(d, skip);
            cl.picks[3] = Some(skip);
        });
        refused_exactly(fx, &c, &perm_rows(l.draw_perm(3), "fs_select"));
    }

    #[test]
    fn c1_rejects_swapped_caps_on_a_consistent_replay() {
        let fx = fixture();
        let l = &fx.air.layout;
        let pow_bits = l.fri.pow_bits;
        // F1: randomizer cap absorbed before the quotient cap. The whole
        // transcript is replayed on the swap: its own zeta, the quotient
        // re-solved for a zero residual there, F2 and D2 rebuilt, its own
        // fri_alpha and betas, a PoW witness re-ground by p3's challenger,
        // its own indices and sums. Only the cap binding refuses.
        let mut data = fx.data.clone();
        data.swap_f1_caps = true;
        let swapped = Replay::new(l, &data).unwrap();
        assert_ne!(swapped.zeta(), fx.inputs.zeta);
        let mut inputs = fx.inputs.clone();
        inputs.zeta = swapped.zeta();
        zero_residual(fx, &mut inputs);
        let mut data = with_openings(&data, &inputs);
        let mut run = native_to_pow(fx, &data);
        data.witness = run.ch.grind(pow_bits);
        let c = claim(fx, &data, &inputs, |_, _| {});
        assert_eq!(c.rep.challenges, run.challenges, "the swap's native replay");
        assert_eq!(c.rep.pow_sample, 0, "re-ground PoW");
        let moved = moved_cap_perms(fx, &c);
        assert!(!moved.is_empty() && moved.iter().all(|p| l.flush_of(*p) == 1));
        let expected: Groups = moved
            .iter()
            .flat_map(|&p| perm_rows(p, "bind_cap"))
            .collect();
        refused_exactly(fx, &c, &expected);
        // FRI: round 1's cap absorbed in round 0 and vice versa, replayed the
        // same way (its own betas, PoW re-ground, indices).
        let mut data = fx.data.clone();
        data.swap_rounds = true;
        let mut run = native_to_pow(fx, &data);
        data.witness = run.ch.grind(pow_bits);
        let c = claim(fx, &data, &fx.inputs, |_, _| {});
        assert_eq!(c.rep.challenges, run.challenges);
        assert_ne!(c.rep.betas()[0], fx.honest.betas()[0]);
        assert_eq!(c.rep.pow_sample, 0);
        let moved = moved_cap_perms(fx, &c);
        assert!(!moved.is_empty() && moved.iter().all(|p| (3..5).contains(&l.flush_of(*p))));
        let expected: Groups = moved
            .iter()
            .flat_map(|&p| perm_rows(p, "bind_cap"))
            .collect();
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn c1_rejects_opened_value_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        // Term 4 is trace-local column 0, which the machine reads.
        assert_eq!(l.opened[4], Open::Local(0));
        let (perm, _) = l.find(Word::Opened(4, 0)).unwrap();
        // Poke it in the transcript, machine untouched; everything after F2
        // replayed on the poke (fri_alpha, betas, PoW re-ground, indices,
        // sums): only the machine's input binding refuses.
        let mut data = fx.data.clone();
        data.local[0] += E::ONE;
        let mut run = native_to_pow(fx, &data);
        data.witness = run.ch.grind(l.fri.pow_bits);
        let c = claim(fx, &data, &fx.inputs, |_, _| {});
        assert_eq!(c.rep.challenges, run.challenges);
        assert_ne!(c.rep.fri_alpha(), fx.honest.fri_alpha());
        refused_exactly(fx, &c, &perm_rows(perm, "bind_opened"));
        // The same poke in the Az accumulation only: transcript and machine
        // honest, the running sum (and the exported Az) moved by
        // fri_alpha^4 from that value's step-0 row on.
        let mut c = honest(fx);
        let delta: Vec<Val> = fx
            .honest
            .fri_alpha()
            .exp_u64(4)
            .as_basis_coefficients_slice()
            .to_vec();
        let row = NUM_ROUNDS * perm;
        let w = fx.air.width;
        for r in row + 1..fx.air.height {
            for (m, &d) in delta.iter().enumerate() {
                c.trace.values[r * w + fx.air.az_col + m] += d;
            }
        }
        for (m, &d) in delta.iter().enumerate() {
            c.pvs[l.az_pv() + m] += d;
        }
        refused_exactly(fx, &c, &[(row, "accumulate")].into());
        // A trace-next term (term 7, block 1) put under the ζ mask, both sums
        // recomputed and exported on the forgery: only the mask refuses.
        assert_eq!(l.opened[7], Open::Next(1));
        let block1 = l.first[F2] + 1;
        let c = claim(fx, &fx.data, &fx.inputs, |_, cl| {
            cl.mask_flip = Some((block1, 1));
        });
        let seam = Seam::read(l, &c.pvs).unwrap();
        let (az, bz) = native_sums(fx.proof, fx.honest.fri_alpha(), None);
        assert!(seam.az != az && seam.bz != bz, "the flip moves both sums");
        refused_exactly(fx, &c, &perm_rows(block1, "mask"));
        // The same value encoded as word + p: R^-1 * word is unchanged, so
        // only the comparator sees it on its perm. D2 moves with the word, so
        // the (not re-ground) PoW fails on its own perm.
        let index = l.flushes[F2]
            .iter()
            .position(|&w| w == Word::Opened(4, 0))
            .unwrap();
        let mut data = fx.data.clone();
        data.alias = Some((F2, index));
        let c = claim(fx, &data, &fx.inputs, |_, _| {});
        assert_eq!(c.rep.words[F2][index], fx.honest.words[F2][index] + P);
        assert_ne!(c.rep.pow_sample, 0);
        let mut expected = perm_rows(perm, "canonical");
        expected.extend(perm_rows(l.window_perm(0), "pow"));
        refused_exactly(fx, &c, &expected);
    }

    #[test]
    fn c1_rejects_pow_and_index_forgeries() {
        let fx = fixture();
        let l = &fx.air.layout;
        // A witness failing the grind, everything after it replayed.
        let fri = &fx.proof.opening_proof.1;
        let mut data = fx.data.clone();
        let mut w = fri.query_pow_witness;
        let rep = loop {
            w += Val::ONE;
            data.witness = w;
            let rep = Replay::new(l, &data).unwrap();
            if rep.pow_sample != 0 {
                break rep;
            }
        };
        let mut run = native_to_pow(fx, &data);
        assert!(
            !run.ch.check_witness(l.fri.pow_bits, w),
            "native refuses it too"
        );
        assert_ne!(rep.indices, fx.honest.indices);
        let c = claim(fx, &data, &fx.inputs, |_, _| {});
        refused_exactly(fx, &c, &perm_rows(l.window_perm(0), "pow"));
        // One exported index with a bit flipped.
        let c = claim(fx, &fx.data, &fx.inputs, |_, cl| cl.indices[10] ^= 1 << 3);
        let (win, _) = l.query_draw(10);
        refused_exactly(fx, &c, &perm_rows(l.window_perm(win), "fs_index"));
    }

    #[test]
    fn c1_refuses_seam_outputs_that_disagree_with_its_cells() {
        // Every seam output leaves from a cell C1 already binds: poking the
        // public value alone is refused on the one row it is tied on.
        let fx = fixture();
        let l = &fx.air.layout;
        let c = honest(fx);
        for (at, row, group) in [
            (l.az_pv() + 1, last(fx), "az_out"),
            (l.bz_pv(), last(fx), "az_out"),
            (l.zeta_pv() + 3, 0, "cells_out"),
            (l.fri_alpha_pv(), 0, "cells_out"),
        ] {
            let mut bad = Claim {
                rep: c.rep.clone(),
                trace: c.trace.clone(),
                pvs: c.pvs.clone(),
            };
            bad.pvs[at] += Val::ONE;
            refused_exactly(fx, &bad, &[(row, group)].into());
        }
        // A beta output: refused where it is drawn.
        let mut bad = Claim {
            rep: c.rep.clone(),
            trace: c.trace.clone(),
            pvs: c.pvs.clone(),
        };
        bad.pvs[l.beta_pv(1) + 2] += Val::ONE;
        refused_exactly(fx, &bad, &perm_rows(l.draw_perm(4), "fs_bind"));
    }
}
