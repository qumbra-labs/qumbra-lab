//! F2b-2a (issue #750): the register machine's inputs, bound in-circuit to a
//! replayed Fiat–Shamir transcript of a real HIDING uni-stark proof, up to and
//! including the opened-value absorption. Test-only component, like the
//! reference machine: scanned row by row, never proved.
//!
//! What one component constrains, on the same rows:
//!
//! - **Sponge.** Every lane perm is stock p3-keccak-air (via m4skel's
//!   `LaneBuilder`). The step-0 row of each perm carries the block's message
//!   bits `M` and the previous output's rate bits `S`; `preimage = M xor S`
//!   limb by limb. `S` is the previous perm's output on interior blocks and
//!   zero on a flush's first block; the capacity carries or starts at zero.
//!   Every rate word of every block is bound: metadata and padding to
//!   constants, caps to outer public limbs, inner PVs and opened values to
//!   field values, the chaining prefix by state equality at the flush seam.
//! - **Transcript.** uni-stark 0.6.1 hiding order: F0 = committed degree bits
//!   ‖ original degree bits ‖ preprocessed width 0 ‖ trace cap ‖ PVs, draw
//!   alpha; F1 = D0 ‖ quotient cap ‖ randomizer cap, draw zeta; F2 = D1 ‖
//!   randomizer opening ‖ trace local ‖ trace next ‖ quotient chunks. F2's
//!   digest D2 is an OUTPUT (public limbs): it seeds fri_alpha, which is
//!   F2b-2b's first consumer.
//! - **Fiat–Shamir.** Draw j reads digest bytes 31-4j..28-4j (the challenger
//!   pops its output buffer from the end), masks 31 bits, rejects >= p. The
//!   reject bit is determined (inverse-witness zero tests), and a one-hot
//!   selection assigns the k-th ACCEPTED draw to limb k — rejected draws
//!   advance nothing, exactly the native redraw.
//! - **Machine.** The reference register machine, with inputs read from held
//!   input columns instead of public limbs; the residual root is pinned to
//!   zero and the next-point root to g_N * zeta on the terminal row.
//!
//! The two traps, as constraints:
//!
//! 1. **Montgomery words.** The challenger serializes `to_unique_u32`, the
//!    raw Monty word R*v mod p. M4 could stay R-scaled because every identity
//!    it evaluates is linear in the opened values; the OOD identity is not
//!    (x*y*y is not R-homogeneous), so every opened value and inner PV is
//!    routed as R^-1 * word. Challenges come from `from_canonical_unchecked`
//!    and enter unscaled. The honest trace satisfies both only with this
//!    split; `bound_machine_rejects_opened_value_forgeries` checks that an
//!    R-scaled routing is refused and that the scaled DAG residual is nonzero.
//! 2. **No randomized equality.** Binding the machine inputs to the stream
//!    with a random linear combination would need a challenge the outer
//!    prover cannot predict; an inner-proof challenge is known before the
//!    outer trace is chosen, and p3-uni-stark 0.6.1 is single-phase. Every
//!    binding here is a deterministic same-row equality: held input columns
//!    (constant over all rows) equal R^-1 * word on the word's step-0 row,
//!    alpha/zeta inputs equal the selected draws on their digest rows, and
//!    the machine's input instructions read the same held columns.
//!
//! **Canonicity.** A word is 32 bits but a field element is < p: v and v + p
//! both satisfy `R^-1 * word = v` in the field. Every field word (inner PVs,
//! all opened values) therefore carries a < p comparator; caps, digests and
//! constants are compared as 16-bit limbs, which are exact.
//!
//! **Exported for F2b-2b-ii** (`opened_out`): zeta and every opened value
//! are public OUTPUTS, so the input-opening component reads the very values
//! the machine read. A value the machine reads is exported from its held
//! input cell (first row); the randomizer opening, which the machine never
//! reads, from its transcript word (`R^-1 * word` on its step-0 row). Either
//! way the export is an equality to what this component already binds —
//! there is no second copy a forger could make disagree with the machine.
//!
//! **NOT bound here (F2b-2b):** fri_alpha, the FRI betas and commit caps,
//! PoW, query indices, the reduced opening, salted input-Merkle leaves and
//! paths, and the final polynomial. Nothing here ties the opened values to
//! the committed caps — D2 is where that half starts: `fri_fs` (F2b-2b-i)
//! takes D2 as its public input and continues the transcript through the
//! query indices, and `open` (F2b-2b-ii) authenticates the queried rows
//! against the caps. The sponge gadgets both use live in `lane`. The
//! randomizer opening is hashed but never routed: it does not enter the OOD
//! identity. A draw
//! window needing more than eight draws (a refill, probability ~1e-9 per
//! challenge) is unsatisfiable, a completeness gap, never a false accept.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::NUM_ROUNDS;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, IS_ZK};

use super::lane::{
    absorb, accepted, challenge, digest_limbs, draw_values, monty, pad, sponge_selectors, Lane,
    Phased, CAP_WORDS, DRAWS, DRAW_COLS, P, RATE_WORDS,
};
use super::machine::{eval_machine, Schedule};
use super::{require, Dims, Input, Inputs, Program, Result, Val, E};
use crate::m4gaterec::keccakf;

/// Constraint groups, in evaluation order. A negative names the group its
/// violation must land in; `BoundAir::phase_of` maps an index to its name.
const PHASES: [&str; 19] = [
    "keccak",
    "bits",
    "absorb",
    "chain_state",
    "flush_chain",
    "bind_const",
    "bind_cap",
    "bind_inner_pv",
    "canonical",
    "digest_out",
    "fs_reject",
    "fs_select",
    "fs_bind",
    "bind_opened",
    "in_public",
    "in_hold",
    "machine",
    "machine_out",
    "opened_out",
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Open {
    Random(usize),
    Local(usize),
    Next(usize),
    Quotient(usize, usize),
}

/// Where a transcript word comes from, which decides how it is bound.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Word {
    /// Instance metadata and sponge padding: limb-exact constants.
    Const(u32),
    /// Word `w` of the previous flush's digest: bound by state equality at
    /// the flush seam, not word by word.
    Chain(usize),
    /// Cap word `n` (trace 0.., quotient CAP_WORDS.., randomizer
    /// 2*CAP_WORDS..): a byte string, limb-exact against outer public limbs.
    Cap(usize),
    /// Inner public value `j`: canonical, R^-1 * word = outer PV `j`.
    InnerPv(usize),
    /// Limb `k` of an opened extension value: canonical; routed to the
    /// machine as R^-1 * word when the DAG reads it.
    Opened(Open, usize),
}

impl Word {
    fn is_field(self) -> bool {
        matches!(self, Self::InnerPv(_) | Self::Opened(..))
    }
}

/// Static transcript layout: which word sits in which lane perm and slot.
/// Derived from the dimensions alone — the AIR never reads the proof.
#[derive(Clone)]
pub(super) struct Layout {
    dims: Dims,
    /// Every opened value in F2 order, which is also the export order.
    opened: Vec<Open>,
    /// Padded word stream per flush F0..F2, a whole number of rate blocks.
    flushes: [Vec<Word>; 3],
    /// First lane perm of each flush.
    first: [usize; 3],
    perms: usize,
}

impl Layout {
    pub(super) fn new(dims: Dims, chunks: usize) -> Self {
        let w = dims.width;
        let mut f0 = vec![
            Word::Const(monty(Val::from_usize(dims.log_height + IS_ZK))),
            Word::Const(monty(Val::from_usize(dims.log_height))),
            Word::Const(monty(Val::ZERO)),
        ];
        f0.extend((0..CAP_WORDS).map(Word::Cap));
        f0.extend((0..dims.pv_len).map(Word::InnerPv));
        let mut f1: Vec<Word> = (0..8).map(Word::Chain).collect();
        f1.extend((CAP_WORDS..3 * CAP_WORDS).map(Word::Cap));
        let mut f2: Vec<Word> = (0..8).map(Word::Chain).collect();
        // Hiding PCS round order: randomizer, trace (zeta then zeta_next),
        // quotient chunks; each extension value as four basis limbs.
        let opened: Vec<Open> = (0..4)
            .map(Open::Random)
            .chain((0..w).map(Open::Local))
            .chain((0..w).map(Open::Next))
            .chain((0..chunks).flat_map(|c| (0..4).map(move |e| Open::Quotient(c, e))))
            .collect();
        for &o in &opened {
            f2.extend((0..4).map(|k| Word::Opened(o, k)));
        }
        let flushes = [f0, f1, f2].map(|f| pad(f, Word::Const));
        let blocks: Vec<usize> = flushes.iter().map(|f| f.len() / RATE_WORDS).collect();
        Self {
            dims,
            opened,
            first: [0, blocks[0], blocks[0] + blocks[1]],
            perms: blocks.iter().sum(),
            flushes,
        }
    }

    fn flush_of(&self, perm: usize) -> usize {
        (0..3).rev().find(|&f| perm >= self.first[f]).unwrap_or(0)
    }
    fn is_interior(&self, perm: usize) -> bool {
        perm < self.perms && !self.first.contains(&perm)
    }
    /// Every (perm, slot, word) of the replayed transcript.
    fn words(&self) -> impl Iterator<Item = (usize, usize, Word)> + '_ {
        (0..3).flat_map(move |f| {
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
    fn cap_base(&self) -> usize {
        self.dims.pv_len
    }
    fn digest_base(&self) -> usize {
        self.dims.pv_len + 6 * CAP_WORDS
    }
    /// Exported zeta (four limbs), then every opened value in F2 order.
    fn zeta_base(&self) -> usize {
        self.digest_base() + 16
    }
    fn opened_base(&self) -> usize {
        self.zeta_base() + 4
    }
    fn num_public_values(&self) -> usize {
        self.opened_base() + 4 * self.opened.len()
    }
}

/// Everything the transcript absorbs, as the outer prover claims it. The
/// honest value comes from the proof; forgeries edit it and replay.
#[derive(Clone)]
pub(super) struct Data {
    inner_pvs: Vec<Val>,
    /// Trace, quotient, randomizer caps.
    caps: [Vec<[u64; 4]>; 3],
    random: Vec<E>,
    local: Vec<E>,
    next: Vec<E>,
    chunks: Vec<Vec<E>>,
    /// Forgery knob: absorb the randomizer cap before the quotient cap.
    swap_f1_caps: bool,
    /// Forgery knob: replace word (flush, index) by its alias word + p.
    alias: Option<(usize, usize)>,
    /// Forgery knob: replace word (flush, index) by an arbitrary value.
    poke: Option<(usize, usize, u32)>,
}

impl Data {
    pub(super) fn from_proof(proof: &Proof<Config>, pvs: &[Val]) -> Result<Self> {
        let o = &proof.opened_values;
        Ok(Self {
            inner_pvs: pvs.to_vec(),
            caps: [
                proof.commitments.trace.roots().to_vec(),
                proof.commitments.quotient_chunks.roots().to_vec(),
                proof
                    .commitments
                    .random
                    .as_ref()
                    .ok_or("missing randomizer commitment")?
                    .roots()
                    .to_vec(),
            ],
            random: o.random.clone().ok_or("missing randomizer opening")?,
            local: o.trace_local.clone(),
            next: o.trace_next.clone().ok_or("missing next-row opening")?,
            chunks: o.quotient_chunks.clone(),
            swap_f1_caps: false,
            alias: None,
            poke: None,
        })
    }

    /// Cap word `n` in the canonical (trace, quotient, randomizer) order;
    /// u64 digest elements are observed little-endian, so low word first.
    fn cap_word(&self, n: usize) -> u32 {
        let cap = &self.caps[n / CAP_WORDS];
        let i = n % CAP_WORDS;
        (cap[i / 8][(i % 8) / 2] >> (32 * (i % 2))) as u32
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

/// The native replay of one claimed transcript: sponge inputs in lane order,
/// padded word streams, digests and the natively drawn challenges.
#[derive(Clone)]
pub(super) struct Replay {
    words: [Vec<u32>; 3],
    perms: Vec<[u64; 25]>,
    pub(super) digests: [[u8; 32]; 3],
    alpha: E,
    zeta: E,
}

impl Replay {
    pub(super) fn new(layout: &Layout, data: &Data) -> Result<Self> {
        let mut words: [Vec<u32>; 3] = Default::default();
        let mut perms = Vec::with_capacity(layout.perms);
        let mut digests = [[0u8; 32]; 3];
        for f in 0..3 {
            let mut stream = Vec::with_capacity(layout.flushes[f].len());
            for &w in &layout.flushes[f] {
                stream.push(match w {
                    Word::Const(c) => c,
                    Word::Chain(i) => {
                        let d = &digests[f - 1];
                        u32::from_le_bytes([d[4 * i], d[4 * i + 1], d[4 * i + 2], d[4 * i + 3]])
                    }
                    Word::Cap(n) => {
                        let n = match (data.swap_f1_caps, n / CAP_WORDS) {
                            (true, 1) => n + CAP_WORDS,
                            (true, 2) => n - CAP_WORDS,
                            _ => n,
                        };
                        data.cap_word(n)
                    }
                    Word::InnerPv(j) => monty(data.inner_pvs[j]),
                    Word::Opened(o, k) => monty(data.opened(o).as_basis_coefficients_slice()[k]),
                });
            }
            if let Some((af, ai)) = data.alias {
                if af == f {
                    stream[ai] = stream[ai]
                        .checked_add(P)
                        .ok_or("alias word overflows 32 bits")?;
                }
            }
            if let Some((pf, pi, v)) = data.poke {
                if pf == f {
                    stream[pi] = v;
                }
            }
            digests[f] = absorb(&stream, &mut perms);
            words[f] = stream;
        }
        Ok(Self {
            alpha: challenge(&digests[0], accepted(&digests[0])?),
            zeta: challenge(&digests[1], accepted(&digests[1])?),
            words,
            perms,
            digests,
        })
    }
}

/// How a machine input is bound.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// Four transcript words (perm, slot), one per extension limb.
    Words([(usize, usize); 4]),
    /// Inner PV `j` as the base-field embedding (limbs 1..3 zero).
    Public(usize),
    /// Selected draws on the digest row of flush `f` (alpha: 0, zeta: 1).
    Draw(usize),
}

/// The transcript-bound component: Keccak lane + sponge/FS binding + the
/// register machine, one row space. Test-only; dense and scanned, not proved.
#[derive(Clone)]
struct BoundAir {
    layout: Layout,
    schedule: Schedule,
    routes: Vec<Route>,
    /// Per opened value (layout order): the machine input that reads it.
    open_route: Vec<Option<usize>>,
    zeta_input: usize,
    height: usize,
    /// Keccak lane at 0, then M and S bits.
    lane: Lane,
    // Main-trace column offsets after the lane.
    canon_col: usize,
    draw_col: usize,
    in_col: usize,
    mach_col: usize,
    width: usize,
    // Periodic offsets: machine ROM at 0, then one step-0 selector per perm.
    step0_per: usize,
    interior_per: usize,
    chain_per: usize,
    digest_per: usize,
    periodic: Vec<Vec<Val>>,
    rinv: Val,
    g_n: Val,
}

impl BoundAir {
    fn new(program: &Program, max_cells: usize) -> Result<Self> {
        let dims = Dims {
            width: program.leaves.local.len(),
            pv_len: program.leaves.public.len(),
            log_height: program.original.log_size(),
        };
        let layout = Layout::new(dims, program.chunk_domains.len());
        let schedule = program.schedule.clone();
        require(
            schedule.outputs().len() == 2,
            "expected residual and next-point roots",
        )?;
        let mut routes = Vec::new();
        let mut open_route = vec![None; layout.opened.len()];
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
                    let o = layout
                        .opened
                        .iter()
                        .position(|&x| x == open)
                        .ok_or("machine input missing from the opened values")?;
                    open_route[o] = Some(routes.len());
                    let mut at = [(0, 0); 4];
                    for (k, slot) in at.iter_mut().enumerate() {
                        *slot = layout
                            .find(Word::Opened(open, k))
                            .ok_or("machine input missing from the transcript")?;
                    }
                    Route::Words(at)
                }
            });
        }
        let zeta_input = zeta_input.ok_or("machine never reads zeta")?;
        let rounds = layout.perms * NUM_ROUNDS;
        let height = schedule.height().max(rounds.next_power_of_two());
        let lane = Lane::new();
        let canon_col = lane.end();
        let draw_col = canon_col + 2 * RATE_WORDS;
        let in_col = draw_col + DRAWS * DRAW_COLS;
        let mach_col = in_col + 4 * routes.len();
        let width = mach_col + schedule.width();
        let rom_width = schedule.rom_width();
        let step0_per = rom_width;
        let interior_per = step0_per + layout.perms;
        let chain_per = interior_per + 1;
        let digest_per = chain_per + 1;
        let cells = height
            .checked_mul(width + digest_per + 1)
            .ok_or("bound machine allocation overflow")?;
        require(
            cells <= max_cells,
            "bound machine exceeds materialization budget",
        )?;
        let mut periodic = schedule.rom(height)?;
        require(periodic.len() == rom_width, "machine ROM width")?;
        periodic.extend(sponge_selectors(&layout.first, layout.perms, height));
        let mut digest = vec![Val::ZERO; height];
        digest[NUM_ROUNDS * layout.perms - 1] = Val::ONE;
        periodic.push(digest);
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            layout,
            schedule,
            routes,
            open_route,
            zeta_input,
            height,
            lane,
            canon_col,
            draw_col,
            in_col,
            mach_col,
            width,
            step0_per,
            interior_per,
            chain_per,
            digest_per,
            periodic,
            rinv: r.inverse(),
            g_n: program.original.subgroup_generator(),
        })
    }

    /// Digest row of flush `f`'s successor: its first block's preimage lanes
    /// 0..3 ARE digest f (chaining), so the draw bits are that row's M bits.
    fn draw_perm(&self, f: usize) -> usize {
        self.layout.first[f + 1]
    }

    /// Build the whole trace for a replayed transcript and machine inputs.
    /// `pick` overrides the draw selection on the alpha/zeta rows (forgeries).
    fn trace(
        &self,
        rep: &Replay,
        inputs: &[E],
        pick: [Option<[usize; 4]>; 2],
    ) -> Result<RowMajorMatrix<Val>> {
        require(rep.perms.len() == self.layout.perms, "replay perm count")?;
        require(inputs.len() == self.routes.len(), "bound machine inputs")?;
        let (h, w) = (self.height, self.width);
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
                let word = self.layout.flushes[flush][first_word + slot];
                if word.is_field() {
                    let v = rep.words[flush][first_word + slot];
                    Lane::fill_canonical(&mut values, row + self.canon_col + 2 * slot, v);
                }
            }
        }
        for f in 0..2 {
            let d = &rep.digests[f];
            let pick = match pick[f] {
                Some(p) => p,
                None => accepted(d)?,
            };
            let row = NUM_ROUNDS * self.draw_perm(f) * w + self.draw_col;
            Lane::fill_draws(&mut values[row..row + DRAWS * DRAW_COLS], d, pick);
        }
        let machine = self.schedule.trace_values(inputs, h)?;
        let mw = self.schedule.width();
        for row in 0..h {
            let cells = &mut values[row * w..(row + 1) * w];
            for (i, v) in inputs.iter().enumerate() {
                cells[self.in_col + 4 * i..self.in_col + 4 * i + 4]
                    .copy_from_slice(v.as_basis_coefficients_slice());
            }
            cells[self.mach_col..].copy_from_slice(&machine[row * mw..(row + 1) * mw]);
        }
        Ok(RowMajorMatrix::new(values, w))
    }

    /// Outer public values: inner PVs, the three caps as 16-bit limbs in the
    /// canonical order (both from the declared instance), then the claim's
    /// outputs: the F2 digest as 16-bit limbs, zeta, every opened value.
    fn public_values(&self, declared: &Data, claimed: &Data, rep: &Replay) -> Vec<Val> {
        let mut pv = declared.inner_pvs.clone();
        for n in 0..3 * CAP_WORDS {
            let w = declared.cap_word(n);
            pv.extend([Val::from_u32(w & 0xffff), Val::from_u32(w >> 16)]);
        }
        pv.extend(digest_limbs(&rep.digests[2]));
        pv.extend_from_slice(rep.zeta.as_basis_coefficients_slice());
        for &o in &self.layout.opened {
            pv.extend_from_slice(claimed.opened(o).as_basis_coefficients_slice());
        }
        pv
    }
}

impl Phased for BoundAir {
    fn phases(&self) -> &'static [&'static str] {
        &PHASES
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let lane = &self.lane;
        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let step0 = |perm: usize| per[self.step0_per + perm].clone();
        // The field-draw rows: alpha's (F0 digest) and zeta's (F1 digest).
        let dr = || step0(self.draw_perm(0)) + step0(self.draw_perm(1));
        match PHASES[phase] {
            "keccak" => return lane.eval_keccak(builder),
            "bits" => return lane.eval_bits(builder),
            "absorb" => return lane.eval_absorb(builder),
            "chain_state" => return lane.eval_chain_state(builder, per[self.interior_per].clone()),
            "flush_chain" => return lane.eval_flush_chain(builder, per[self.chain_per].clone()),
            "canonical" => {
                for slot in 0..RATE_WORDS {
                    let perms: Vec<usize> = self
                        .layout
                        .words()
                        .filter(|&(_, s, w)| s == slot && w.is_field())
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
        let full = |slot: usize| lane.full::<AB>(cur, slot);
        match PHASES[phase] {
            "bind_const" | "bind_cap" | "bind_inner_pv" => {
                for (perm, slot, word) in self.layout.words() {
                    let sel = step0(perm);
                    match (PHASES[phase], word) {
                        ("bind_const", Word::Const(v)) => {
                            builder.assert_zero(
                                sel.clone() * (half(slot, 0) - Val::from_u32(v & 0xffff)),
                            );
                            builder.assert_zero(sel * (half(slot, 1) - Val::from_u32(v >> 16)));
                        }
                        ("bind_cap", Word::Cap(w)) => {
                            let at = self.layout.cap_base() + 2 * w;
                            builder.assert_zero(sel.clone() * (half(slot, 0) - pv[at].clone()));
                            builder.assert_zero(sel * (half(slot, 1) - pv[at + 1].clone()));
                        }
                        ("bind_inner_pv", Word::InnerPv(j)) => {
                            builder.assert_zero(sel * (full(slot) * self.rinv - pv[j].clone()));
                        }
                        _ => {}
                    }
                }
            }
            "digest_out" => {
                let base = self.layout.digest_base();
                for lane in 0..4 {
                    for l in 0..4 {
                        builder.assert_zero(
                            per[self.digest_per].clone()
                                * (c(k.out[lane][l]) - pv[base + 4 * lane + l].clone()),
                        );
                    }
                }
            }
            "fs_bind" => {
                for (i, route) in self.routes.iter().enumerate() {
                    let Route::Draw(f) = *route else { continue };
                    let sel = step0(self.draw_perm(f));
                    for slot in 0..4 {
                        let drawn = lane.selected::<AB>(cur, self.draw_col, slot);
                        builder.assert_zero(sel.clone() * (drawn - c(self.in_col + 4 * i + slot)));
                    }
                }
            }
            "bind_opened" => {
                for (i, route) in self.routes.iter().enumerate() {
                    if let Route::Words(at) = *route {
                        for (limb, &(perm, slot)) in at.iter().enumerate() {
                            builder.assert_zero(
                                step0(perm)
                                    * (full(slot) * self.rinv - c(self.in_col + 4 * i + limb)),
                            );
                        }
                    }
                }
            }
            "in_public" => {
                for (i, route) in self.routes.iter().enumerate() {
                    if let Route::Public(j) = *route {
                        builder.assert_eq(c(self.in_col + 4 * i), pv[j].clone());
                        for limb in 1..4 {
                            builder.assert_zero(c(self.in_col + 4 * i + limb));
                        }
                    }
                }
            }
            "in_hold" => {
                for q in 0..4 * self.routes.len() {
                    builder
                        .when_transition()
                        .assert_zero(n(self.in_col + q) - c(self.in_col + q));
                }
            }
            "machine" => {
                let inputs: Vec<[AB::Expr; 4]> = (0..self.routes.len())
                    .map(|i| core::array::from_fn(|limb| c(self.in_col + 4 * i + limb)))
                    .collect();
                eval_machine(
                    builder,
                    &self.schedule,
                    self.mach_col,
                    &per[..self.schedule.rom_width()],
                    &inputs,
                );
            }
            "machine_out" => {
                let [residual, next_point] =
                    [self.schedule.outputs()[0], self.schedule.outputs()[1]];
                for limb in 0..4 {
                    builder
                        .when_last_row()
                        .assert_zero(c(self.mach_col + 12 + 4 * residual + limb));
                    builder.when_last_row().assert_zero(
                        c(self.mach_col + 12 + 4 * next_point + limb)
                            - c(self.in_col + 4 * self.zeta_input + limb) * self.g_n,
                    );
                }
            }
            "opened_out" => {
                // The exports are the machine's own cells: zeta and every
                // routed opened value leave from the held input column the
                // machine reads (held constant, so row 0 is every row). The
                // randomizer has no machine cell; it leaves from its word.
                let zeta = self.layout.zeta_base();
                for limb in 0..4 {
                    builder.when_first_row().assert_zero(
                        c(self.in_col + 4 * self.zeta_input + limb) - pv[zeta + limb].clone(),
                    );
                }
                for (i, &o) in self.layout.opened.iter().enumerate() {
                    let at = self.layout.opened_base() + 4 * i;
                    for limb in 0..4 {
                        if let Some(r) = self.open_route[i] {
                            builder
                                .when_first_row()
                                .assert_zero(c(self.in_col + 4 * r + limb) - pv[at + limb].clone());
                        } else {
                            let (perm, slot) = self
                                .layout
                                .find(Word::Opened(o, limb))
                                .expect("every opened limb is a transcript word");
                            builder.assert_zero(
                                step0(perm) * (full(slot) * self.rinv - pv[at + limb].clone()),
                            );
                        }
                    }
                }
            }
            other => unreachable!("unknown phase {other}"),
        }
    }
}

impl BaseAir<Val> for BoundAir {
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

impl<AB: AirBuilder<F = Val>> Air<AB> for BoundAir {
    fn eval(&self, builder: &mut AB) {
        for phase in 0..PHASES.len() {
            self.eval_phase(phase, builder);
        }
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
pub(in crate::f2::ood) mod tests {
    use std::sync::OnceLock;

    use std::ops::Range;

    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_challenger::FieldChallenger;
    use qlab_air::l2test::{satisfied, violations_at};

    use super::super::lane::phase_ranges;
    use super::super::lane::toy::{native_through_f2, toy_proof, Toy};
    use super::super::{compare_native, proof_inputs_dims};
    use super::*;

    const TOY_LOG_HEIGHT: usize = 4;

    struct Fixture {
        program: Program,
        air: BoundAir,
        ranges: Vec<Range<usize>>,
        data: Data,
        inputs: Inputs,
        honest: Replay,
    }

    fn dims() -> Dims {
        Dims {
            width: 2,
            pv_len: 2,
            log_height: TOY_LOG_HEIGHT,
        }
    }

    /// One real hiding proof (seeded, so CI replays the same transcript) and
    /// everything derived from it, shared by every test in this module.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let (proof, pvs) = toy_proof(TOY_LOG_HEIGHT, 0xf2b2a);
            let program = Program::compile_dims(dims(), &Toy).unwrap();
            let inputs = proof_inputs_dims(dims(), &proof, &pvs).unwrap();
            let values = compare_native(&program, &Toy, &inputs).unwrap();
            assert_eq!(values[program.residual], E::ZERO, "native OOD relation");
            let air = BoundAir::new(&program, 64 << 20).unwrap();
            let data = Data::from_proof(&proof, &pvs).unwrap();
            let honest = Replay::new(&air.layout, &data).unwrap();
            // The replay IS the native transcript: same alpha/zeta as the p3
            // challenger, and F2's digest yields the verifier's fri_alpha.
            assert_eq!(honest.alpha, inputs.alpha, "replayed alpha");
            assert_eq!(honest.zeta, inputs.zeta, "replayed zeta");
            let mut ch = native_through_f2(&proof, &pvs, TOY_LOG_HEIGHT);
            let fri_alpha: E = ch.sample_algebra_element();
            let d2 = &honest.digests[2];
            assert_eq!(
                challenge(d2, accepted(d2).unwrap()),
                fri_alpha,
                "F2 message order"
            );
            let ranges = phase_ranges(&air);
            Fixture {
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

    /// A claim assembled by the outer prover: transcript data, machine
    /// inputs, and optional draw selections. The claimed D2 is the forger's
    /// own (D2 is an output of this component), caps and inner PVs honest.
    struct Claim {
        rep: Replay,
        trace: RowMajorMatrix<Val>,
        pvs: Vec<Val>,
    }

    fn claim(fx: &Fixture, data: &Data, inputs: &[E], pick: [Option<[usize; 4]>; 2]) -> Claim {
        let rep = Replay::new(&fx.air.layout, data).unwrap();
        let trace = fx.air.trace(&rep, inputs, pick).unwrap();
        let pvs = fx.air.public_values(&fx.data, data, &rep);
        Claim { rep, trace, pvs }
    }

    fn failing(fx: &Fixture, c: &Claim, row: usize) -> Vec<&'static str> {
        violations_at(&fx.air, &c.trace, &c.pvs, row)
            .into_iter()
            .map(|v| phase_of(fx, v.constraint))
            .collect()
    }

    fn step0_row(perm: usize) -> usize {
        NUM_ROUNDS * perm
    }

    /// Re-solve quotient chunk (0, 0) so the residual vanishes at `inputs.zeta`:
    /// the residual is affine in that opening with coefficient -weight_0.
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

    #[test]
    fn bound_machine_accepts_honest_hiding_transcript_at_degree_three() {
        let fx = fixture();
        let air = &fx.air;
        assert_eq!(
            air.layout.perms, 13,
            "3 + 5 + 5 lane perms for the toy transcript"
        );
        assert_eq!(air.draw_perm(0), 3);
        assert_eq!(air.draw_perm(1), 8);
        let honest = machine_inputs(&fx.program, &fx.inputs).unwrap();
        let c = claim(fx, &fx.data, &honest, [None, None]);
        satisfied(air, &c.trace, &c.pvs).unwrap_or_else(|v| {
            panic!(
                "honest bound machine refused: {v} in {}",
                phase_of(fx, v.constraint)
            )
        });
        // Every input source class is transcript-bound, none left public.
        let mut kinds = [false; 3];
        for r in &air.routes {
            kinds[match r {
                Route::Words(_) => 0,
                Route::Public(_) => 1,
                Route::Draw(_) => 2,
            }] = true;
        }
        assert_eq!(kinds, [true; 3]);
        let layout = AirLayout::from_air::<Val>(air);
        let constraints = get_symbolic_constraints::<Val, _>(air, layout);
        assert_eq!(fx.ranges.last().unwrap().end, constraints.len());
        let max = constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap();
        assert!(max <= 3, "bound component degree {max} > 3");
    }

    #[test]
    fn bound_machine_rejects_challenge_forgeries() {
        let fx = fixture();
        let (alpha_row, zeta_row) = (
            step0_row(fx.air.draw_perm(0)),
            step0_row(fx.air.draw_perm(1)),
        );
        let last = fx.air.height - 1;
        // Wrong zeta limb / wrong alpha, the machine recomputed on the lie.
        for (limb, row, is_zeta) in [(2, zeta_row, true), (0, alpha_row, false)] {
            let mut inputs = fx.inputs.clone();
            let bump = <E as BasedVectorSpace<Val>>::ith_basis_element(limb).unwrap();
            if is_zeta {
                inputs.zeta += bump;
            } else {
                inputs.alpha += bump;
            }
            let c = claim(
                fx,
                &fx.data,
                &machine_inputs(&fx.program, &inputs).unwrap(),
                [None, None],
            );
            assert!(
                failing(fx, &c, row).contains(&"fs_bind"),
                "limb {limb} zeta {is_zeta}"
            );
        }
        // Coordinated forgery: a different zeta, the quotient re-solved so the
        // residual vanishes there, F2 and D2 rebuilt. Only the zeta binding
        // stands between this and acceptance.
        let mut inputs = fx.inputs.clone();
        inputs.zeta += E::ONE;
        zero_residual(fx, &mut inputs);
        let data = with_openings(&fx.data, &inputs);
        let c = claim(
            fx,
            &data,
            &machine_inputs(&fx.program, &inputs).unwrap(),
            [None, None],
        );
        let f = failing(fx, &c, zeta_row);
        assert!(!f.is_empty() && f.iter().all(|&p| p == "fs_bind"), "{f:?}");
        assert!(
            failing(fx, &c, last).is_empty(),
            "forged machine is self-consistent"
        );
        // Skip an accepted draw: slot 3 takes the fifth accepted draw.
        let d1 = &fx.honest.digests[1];
        let ok: Vec<usize> = (0..DRAWS).filter(|&j| draw_values(d1)[j] < P).collect();
        let skip = [ok[0], ok[1], ok[2], ok[4]];
        let mut inputs = fx.inputs.clone();
        inputs.zeta = challenge(d1, skip);
        zero_residual(fx, &mut inputs);
        let data = with_openings(&fx.data, &inputs);
        let c = claim(
            fx,
            &data,
            &machine_inputs(&fx.program, &inputs).unwrap(),
            [None, Some(skip)],
        );
        let f = failing(fx, &c, zeta_row);
        assert!(f.contains(&"fs_select") && !f.contains(&"fs_bind"), "{f:?}");
        // Randomizer cap absorbed before the quotient cap: a fully consistent
        // replay of the swapped transcript (its own zeta, re-solved quotient,
        // rebuilt F2/D2) still fails the cap binding on F1's first block.
        let mut data = fx.data.clone();
        data.swap_f1_caps = true;
        let swapped = Replay::new(&fx.air.layout, &data).unwrap();
        assert_ne!(swapped.zeta, fx.inputs.zeta);
        let mut inputs = fx.inputs.clone();
        inputs.zeta = swapped.zeta;
        zero_residual(fx, &mut inputs);
        let mut data = with_openings(&data, &inputs);
        data.swap_f1_caps = true;
        let c = claim(
            fx,
            &data,
            &machine_inputs(&fx.program, &inputs).unwrap(),
            [None, None],
        );
        assert_eq!(c.rep.zeta, swapped.zeta);
        let f = failing(fx, &c, step0_row(fx.air.layout.first[1]));
        assert!(!f.is_empty() && f.iter().all(|&p| p == "bind_cap"), "{f:?}");
        assert!(
            failing(fx, &c, zeta_row).is_empty(),
            "swap replay is FS-consistent"
        );
        assert!(
            failing(fx, &c, last).is_empty(),
            "swap machine is self-consistent"
        );
    }

    #[test]
    fn bound_machine_rejects_opened_value_forgeries() {
        let fx = fixture();
        let last = fx.air.height - 1;
        let honest = machine_inputs(&fx.program, &fx.inputs).unwrap();
        let (perm, _) = fx.air.layout.find(Word::Opened(Open::Local(0), 0)).unwrap();
        // Poke one opened value in the transcript, machine untouched.
        let mut data = fx.data.clone();
        data.local[0] += E::ONE;
        let c = claim(fx, &data, &honest, [None, None]);
        assert_ne!(c.rep.digests[2], fx.honest.digests[2]);
        assert!(failing(fx, &c, step0_row(perm)).contains(&"bind_opened"));
        // Poke it with the machine recomputed to match: a trace-next value
        // and a quotient limb, each consistent end to end. The residual pin
        // is what refuses them.
        for which in 0..2 {
            let mut inputs = fx.inputs.clone();
            if which == 0 {
                inputs.next[1] += E::ONE;
            } else {
                inputs.chunks[3][1] += E::ONE;
            }
            let data = with_openings(&fx.data, &inputs);
            let c = claim(
                fx,
                &data,
                &machine_inputs(&fx.program, &inputs).unwrap(),
                [None, None],
            );
            let f = failing(fx, &c, last);
            assert!(
                !f.is_empty() && f.iter().all(|&p| p == "machine_out"),
                "{which}: {f:?}"
            );
            for p in fx.air.layout.first[2]..fx.air.layout.perms {
                assert!(
                    failing(fx, &c, step0_row(p)).is_empty(),
                    "case {which} perm {p}"
                );
            }
        }
        // Missing R^-1: route the raw Monty words (R * v) into the machine.
        // The OOD identity is not R-homogeneous, so the scaled residual is
        // nonzero, and the binding refuses the scaled routing.
        let r = E::from(Val::from_u32(Val::ONE.to_unique_u32()));
        let mut scaled = fx.inputs.clone();
        for v in scaled.local.iter_mut().chain(scaled.next.iter_mut()) {
            *v *= r;
        }
        for v in scaled.chunks.iter_mut().flatten() {
            *v *= r;
        }
        assert_ne!(
            fx.program.evaluate(&scaled).unwrap()[fx.program.residual],
            E::ZERO
        );
        let c = claim(
            fx,
            &fx.data,
            &machine_inputs(&fx.program, &scaled).unwrap(),
            [None, None],
        );
        assert!(failing(fx, &c, step0_row(perm)).contains(&"bind_opened"));
        // Alias: the same opened value encoded as word + p. R^-1 * word is
        // unchanged in the field, so only the canonicity comparator sees it.
        let index = fx.air.layout.flushes[2]
            .iter()
            .position(|&w| w == Word::Opened(Open::Local(0), 0))
            .unwrap();
        assert_eq!(fx.air.layout.first[2] + index / RATE_WORDS, perm);
        let mut data = fx.data.clone();
        data.alias = Some((2, index));
        let c = claim(fx, &data, &honest, [None, None]);
        assert_eq!(c.rep.words[2][index], fx.honest.words[2][index] + P);
        let f = failing(fx, &c, step0_row(perm));
        assert!(
            !f.is_empty() && f.iter().all(|&p| p == "canonical"),
            "{f:?}"
        );
    }

    /// A fully consistent forger for an F0 edit: alpha and zeta re-drawn from
    /// the edited transcript, the quotient re-solved for a zero residual
    /// there, F2/D2 rebuilt. Returns the claim and the rows that must stay
    /// clean (both digest rows and the terminal row).
    fn consistent_f0_forgery(fx: &Fixture, data: &Data) -> (Claim, [usize; 3]) {
        let edited = Replay::new(&fx.air.layout, data).unwrap();
        assert_ne!(edited.alpha, fx.inputs.alpha, "F0 edit must move alpha");
        let mut inputs = fx.inputs.clone();
        inputs.alpha = edited.alpha;
        inputs.zeta = edited.zeta;
        zero_residual(fx, &mut inputs);
        let data = with_openings(data, &inputs);
        let c = claim(
            fx,
            &data,
            &machine_inputs(&fx.program, &inputs).unwrap(),
            [None, None],
        );
        assert_eq!((c.rep.alpha, c.rep.zeta), (edited.alpha, edited.zeta));
        let clean = [
            step0_row(fx.air.draw_perm(0)),
            step0_row(fx.air.draw_perm(1)),
            fx.air.height - 1,
        ];
        (c, clean)
    }

    fn refused_only_by(fx: &Fixture, c: &Claim, row: usize, clean: [usize; 3], phase: &str) {
        let f = failing(fx, c, row);
        assert!(
            !f.is_empty() && f.iter().all(|&p| p == phase),
            "{phase}: {f:?}"
        );
        for r in clean {
            assert!(
                failing(fx, c, r).is_empty(),
                "{phase}: row {r} must be clean"
            );
        }
    }

    fn inner_pv_word(fx: &Fixture) -> (usize, usize) {
        let index = fx.air.layout.flushes[0]
            .iter()
            .position(|&w| w == Word::InnerPv(0))
            .unwrap();
        (index, fx.air.layout.first[0] + index / RATE_WORDS)
    }

    #[test]
    fn bound_machine_rejects_forged_f0_metadata() {
        // Claim a different original degree (word 1 = log_h) in F0.
        let fx = fixture();
        assert_eq!(
            fx.air.layout.flushes[0][1],
            Word::Const(monty(Val::from_usize(TOY_LOG_HEIGHT)))
        );
        let mut data = fx.data.clone();
        data.poke = Some((0, 1, monty(Val::from_usize(TOY_LOG_HEIGHT + 1))));
        let (c, clean) = consistent_f0_forgery(fx, &data);
        refused_only_by(fx, &c, step0_row(0), clean, "bind_const");
    }

    #[test]
    fn bound_machine_rejects_forged_inner_public_value() {
        // The transcript absorbs a different inner PV than the declared one;
        // the machine's Public input stays on the declared outer PV.
        let fx = fixture();
        let (_, perm) = inner_pv_word(fx);
        let mut data = fx.data.clone();
        data.inner_pvs[0] += Val::ONE;
        let (c, clean) = consistent_f0_forgery(fx, &data);
        assert_eq!(c.pvs[0], fx.data.inner_pvs[0], "declared PV stays honest");
        refused_only_by(fx, &c, step0_row(perm), clean, "bind_inner_pv");
    }

    #[test]
    fn bound_machine_rejects_inner_public_value_alias() {
        // The same inner PV encoded as word + p: R^-1 * word is unchanged, so
        // only the canonicity comparator sees it.
        let fx = fixture();
        let (index, perm) = inner_pv_word(fx);
        let mut data = fx.data.clone();
        data.alias = Some((0, index));
        let (c, clean) = consistent_f0_forgery(fx, &data);
        assert_eq!(c.rep.words[0][index], fx.honest.words[0][index] + P);
        refused_only_by(fx, &c, step0_row(perm), clean, "canonical");
    }

    #[test]
    fn bound_machine_exports_exactly_the_values_the_machine_read() {
        // F2b-2b-ii reads zeta and the opened values from these outputs. An
        // export that disagrees with the machine's own cells — the one thing
        // that would let the machine and FRI see different z-values — is
        // refused by `opened_out` alone, on the row the export is tied on.
        let fx = fixture();
        let honest = machine_inputs(&fx.program, &fx.inputs).unwrap();
        let c = claim(fx, &fx.data, &honest, [None, None]);
        let layout = &fx.air.layout;
        let routed = layout
            .opened
            .iter()
            .position(|&o| o == Open::Local(0))
            .unwrap();
        let random = layout
            .opened
            .iter()
            .position(|&o| o == Open::Random(2))
            .unwrap();
        assert!(fx.air.open_route[routed].is_some(), "trace local is routed");
        assert!(fx.air.open_route[random].is_none(), "randomizer is not");
        let (random_perm, _) = layout.find(Word::Opened(Open::Random(2), 1)).unwrap();
        // F2 opens with the randomizer, so its words sit on F2's first block
        // — the zeta digest row. That row is the export row here, not a
        // clean row.
        assert_eq!(random_perm, fx.air.draw_perm(1));
        for (at, row) in [
            (layout.zeta_base() + 3, 0),
            (layout.opened_base() + 4 * routed + 1, 0),
            (
                layout.opened_base() + 4 * random + 1,
                step0_row(random_perm),
            ),
        ] {
            let mut pvs = c.pvs.clone();
            pvs[at] += Val::ONE;
            let bad = Claim {
                rep: c.rep.clone(),
                trace: c.trace.clone(),
                pvs,
            };
            let f = failing(fx, &bad, row);
            assert!(
                !f.is_empty() && f.iter().all(|&p| p == "opened_out"),
                "{at}: {f:?}"
            );
            for r in [step0_row(fx.air.draw_perm(1)), fx.air.height - 1] {
                if r != row {
                    assert!(failing(fx, &bad, r).is_empty(), "{at}: row {r}");
                }
            }
        }
    }

    /// 2a's honest public values for another proof of the toy at
    /// `log_height`, and where its exports sit in them: the three caps (2a's
    /// trace, quotient, randomizer order), zeta, and the opened values. The
    /// seam F2b-2b-ii's tests compare their public inputs against.
    pub(in crate::f2::ood) struct Exported {
        pub(in crate::f2::ood) pvs: Vec<Val>,
        pub(in crate::f2::ood) caps: Range<usize>,
        pub(in crate::f2::ood) zeta: Range<usize>,
        pub(in crate::f2::ood) opened: Range<usize>,
    }

    pub(in crate::f2::ood) fn exported(
        proof: &Proof<Config>,
        pvs: &[Val],
        log_height: usize,
    ) -> Exported {
        let dims = Dims {
            width: 2,
            pv_len: 2,
            log_height,
        };
        let program = Program::compile_dims(dims, &Toy).unwrap();
        let air = BoundAir::new(&program, 64 << 20).unwrap();
        let data = Data::from_proof(proof, pvs).unwrap();
        let rep = Replay::new(&air.layout, &data).unwrap();
        let l = &air.layout;
        Exported {
            pvs: air.public_values(&data, &data, &rep),
            caps: l.cap_base()..l.cap_base() + 6 * CAP_WORDS,
            zeta: l.zeta_base()..l.opened_base(),
            opened: l.opened_base()..l.num_public_values(),
        }
    }
}
