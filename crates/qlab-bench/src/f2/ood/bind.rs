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
//! **NOT bound here (F2b-2b):** fri_alpha, the FRI betas and commit caps,
//! PoW, query indices, the reduced opening, salted input-Merkle leaves and
//! paths, and the final polynomial. Nothing here ties the opened values to
//! the committed caps — D2 is where that half starts. The randomizer opening
//! is hashed but never routed: it does not enter the OOD identity. A draw
//! window needing more than eight draws (a refill, probability ~1e-9 per
//! challenge) is unsatisfiable, a completeness gap, never a false accept.
use std::borrow::Borrow;
use std::ops::Range;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{generate_trace_rows, KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::Proof;
use qlab_consensus::{Config, CAP_HEIGHT, IS_ZK};

use super::machine::{eval_machine, Schedule};
use super::{require, Dims, Input, Inputs, Program, Result, Val, E};
use crate::m4gaterec::{digest_of, keccakf};
use crate::m4skel::LaneBuilder;

const RATE_LANES: usize = 17;
const RATE_WORDS: usize = 2 * RATE_LANES;
const RATE_BITS: usize = 64 * RATE_LANES;
/// Words of one observed cap: 2^CAP_HEIGHT digests x 4 u64 x 2 words.
const CAP_WORDS: usize = (1 << CAP_HEIGHT) * 8;
/// Draws one 32-byte digest provides before a refill.
const DRAWS: usize = 8;
/// Columns per draw: inv_hi, hi, inv_lo, nz, acc, then four slot selectors.
const DRAW_COLS: usize = 9;
const P: u32 = Val::ORDER_U32;

/// Constraint groups, in evaluation order. A negative names the group its
/// violation must land in; `BoundAir::phase_of` maps an index to its name.
const PHASES: [&str; 18] = [
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
struct Layout {
    dims: Dims,
    /// Padded word stream per flush F0..F2, a whole number of rate blocks.
    flushes: [Vec<Word>; 3],
    /// First lane perm of each flush.
    first: [usize; 3],
    perms: usize,
}

fn monty(v: Val) -> u32 {
    v.to_unique_u32()
}

impl Layout {
    fn new(dims: Dims, chunks: usize) -> Self {
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
        let opened = (0..4)
            .map(Open::Random)
            .chain((0..w).map(Open::Local))
            .chain((0..w).map(Open::Next))
            .chain((0..chunks).flat_map(|c| (0..4).map(move |e| Open::Quotient(c, e))));
        for o in opened {
            f2.extend((0..4).map(|k| Word::Opened(o, k)));
        }
        let flushes = [Self::pad(f0), Self::pad(f1), Self::pad(f2)];
        let blocks: Vec<usize> = flushes.iter().map(|f| f.len() / RATE_WORDS).collect();
        Self {
            dims,
            first: [0, blocks[0], blocks[0] + blocks[1]],
            perms: blocks.iter().sum(),
            flushes,
        }
    }

    /// Keccak pad10*1 (domain byte 0x01) on a 4-byte-aligned message: the
    /// 0x01 lands at a word's low byte and 0x80 at the block's last byte.
    fn pad(mut words: Vec<Word>) -> Vec<Word> {
        let n = words.len();
        let total = (n / RATE_WORDS + 1) * RATE_WORDS;
        for i in n..total {
            let mut v = 0;
            if i == n {
                v |= 1;
            }
            if i == total - 1 {
                v |= 0x8000_0000;
            }
            words.push(Word::Const(v));
        }
        words
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
    fn num_public_values(&self) -> usize {
        self.digest_base() + 16
    }
}

/// Everything the transcript absorbs, as the outer prover claims it. The
/// honest value comes from the proof; forgeries edit it and replay.
#[derive(Clone)]
struct Data {
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
    fn from_proof(proof: &Proof<Config>, pvs: &[Val]) -> Result<Self> {
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
struct Replay {
    words: [Vec<u32>; 3],
    perms: Vec<[u64; 25]>,
    digests: [[u8; 32]; 3],
    alpha: E,
    zeta: E,
}

/// The eight masked draws of one digest, in challenger order.
fn draw_values(d: &[u8; 32]) -> [u32; DRAWS] {
    core::array::from_fn(|j| {
        u32::from_le_bytes([d[31 - 4 * j], d[30 - 4 * j], d[29 - 4 * j], d[28 - 4 * j]])
            & 0x7fff_ffff
    })
}

/// Indices of the first four accepted draws — native `sample_algebra_element`.
fn accepted(d: &[u8; 32]) -> Result<[usize; 4]> {
    let v = draw_values(d);
    let idx: Vec<usize> = (0..DRAWS).filter(|&j| v[j] < P).take(4).collect();
    require(idx.len() == 4, "draw window needs a refill (unsupported)")?;
    Ok([idx[0], idx[1], idx[2], idx[3]])
}

fn challenge(d: &[u8; 32], pick: [usize; 4]) -> E {
    let v = draw_values(d);
    E::from_basis_coefficients_fn(|k| Val::from_u32(v[pick[k]]))
}

impl Replay {
    fn new(layout: &Layout, data: &Data) -> Result<Self> {
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
            let mut state = [0u64; 25];
            for block in stream.chunks(RATE_WORDS) {
                for lane in 0..RATE_LANES {
                    state[lane] ^=
                        u64::from(block[2 * lane]) | (u64::from(block[2 * lane + 1]) << 32);
                }
                perms.push(state);
                state = keccakf(&state);
            }
            digests[f] = digest_of(&state);
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

/// Keccak lane column indices used by the binding (standard lane = x + 5y).
#[derive(Clone)]
struct KeccakIdx {
    step0: usize,
    fin: usize,
    pre: [[usize; 4]; 25],
    out: [[usize; 4]; 25],
}

fn keccak_idx() -> KeccakIdx {
    let idx: Vec<usize> = (0..NUM_KECCAK_COLS).collect();
    let map: &KeccakCols<usize> = idx[..].borrow();
    KeccakIdx {
        step0: map.step_flags[0],
        fin: map.step_flags[NUM_ROUNDS - 1],
        pre: core::array::from_fn(|lane| map.preimage[lane / 5][lane % 5]),
        out: core::array::from_fn(|lane| {
            core::array::from_fn(|l| map.a_prime_prime_prime(lane / 5, lane % 5, l))
        }),
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
    zeta_input: usize,
    height: usize,
    kc: KeccakIdx,
    // Main-trace column offsets after the Keccak lane.
    m_col: usize,
    s_col: usize,
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
    pow2: Vec<Val>,
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
        let m_col = NUM_KECCAK_COLS;
        let s_col = m_col + RATE_BITS;
        let canon_col = s_col + RATE_BITS;
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
        periodic.resize(digest_per + 1, vec![]);
        for col in &mut periodic[step0_per..] {
            *col = vec![Val::ZERO; height];
        }
        let last = |perm: usize| NUM_ROUNDS * perm + NUM_ROUNDS - 1;
        for perm in 0..layout.perms {
            periodic[step0_per + perm][NUM_ROUNDS * perm] = Val::ONE;
            if layout.is_interior(perm + 1) {
                periodic[interior_per][last(perm)] = Val::ONE;
            }
        }
        for f in 1..3 {
            periodic[chain_per][last(layout.first[f] - 1)] = Val::ONE;
        }
        periodic[digest_per][last(layout.perms - 1)] = Val::ONE;
        let r = Val::from_u32(Val::ONE.to_unique_u32());
        Ok(Self {
            layout,
            schedule,
            routes,
            zeta_input,
            height,
            kc: keccak_idx(),
            m_col,
            s_col,
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
            pow2: (0..32).map(|t| Val::TWO.exp_u64(t)).collect(),
        })
    }

    /// Digest row of flush `f`'s successor: its first block's preimage lanes
    /// 0..3 ARE digest f (chaining), so the draw bits are that row's M bits.
    fn draw_perm(&self, f: usize) -> usize {
        self.layout.first[f + 1]
    }

    /// Message bit `b` (0..32) of rate word `slot`.
    fn word_bit(&self, slot: usize, b: usize) -> usize {
        self.m_col + 64 * (slot / 2) + 32 * (slot % 2) + b
    }

    /// Bit `t` of masked draw `j`: draw bytes 31-4j..28-4j, little-endian.
    fn draw_bit(&self, j: usize, t: usize) -> usize {
        let byte = 31 - 4 * j - t / 8;
        self.m_col + 64 * (byte / 8) + 8 * (byte % 8) + t % 8
    }

    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        if PHASES[phase] == "keccak" {
            let mut lane = LaneBuilder {
                inner: builder,
                off: 0,
                width: NUM_KECCAK_COLS,
            };
            KeccakAir {}.eval(&mut lane);
            return;
        }
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { next[i].into() };
        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let k = &self.kc;
        let two = |t: usize| self.pow2[t];
        let sum = |cols: &mut dyn Iterator<Item = (usize, usize)>,
                   at: &dyn Fn(usize) -> AB::Expr| {
            cols.fold(AB::Expr::ZERO, |acc, (col, t)| acc + at(col) * two(t))
        };
        // 16-bit half `h` of rate word `slot`, from the current row's M bits.
        let half = |slot: usize, h: usize| {
            sum(
                &mut (0..16).map(|t| (self.word_bit(slot, 16 * h + t), t)),
                &c,
            )
        };
        let full = |slot: usize| half(slot, 0) + half(slot, 1) * two(16);
        let xor = |a: AB::Expr, b: AB::Expr| a.clone() + b.clone() - a * b * Val::TWO;
        let step0 = |perm: usize| per[self.step0_per + perm].clone();
        let seven = Val::from_u32(7);
        match PHASES[phase] {
            "bits" => {
                for i in 0..RATE_BITS {
                    builder.assert_bool(c(self.m_col + i));
                    builder.assert_bool(c(self.s_col + i));
                }
            }
            "absorb" => {
                for lane in 0..RATE_LANES {
                    for l in 0..4 {
                        let bits = (0..16).fold(AB::Expr::ZERO, |acc, t| {
                            let b = 64 * lane + 16 * l + t;
                            acc + xor(c(self.m_col + b), c(self.s_col + b)) * two(t)
                        });
                        builder.assert_zero(c(k.step0) * (c(k.pre[lane][l]) - bits));
                    }
                }
            }
            "chain_state" => {
                let inter = per[self.interior_per].clone();
                for lane in 0..25 {
                    for l in 0..4 {
                        let (prev_rate, first_rate) = if lane < RATE_LANES {
                            let cols = |t: usize| (self.s_col + 64 * lane + 16 * l + t, t);
                            (
                                sum(&mut (0..16).map(cols), &n),
                                sum(&mut (0..16).map(cols), &c),
                            )
                        } else {
                            (n(k.pre[lane][l]), c(k.pre[lane][l]))
                        };
                        builder.when_transition().assert_zero(
                            c(k.fin) * (prev_rate - inter.clone() * c(k.out[lane][l])),
                        );
                        builder.when_first_row().assert_zero(first_rate);
                    }
                }
            }
            "flush_chain" => {
                for lane in 0..4 {
                    for l in 0..4 {
                        builder.assert_zero(
                            per[self.chain_per].clone() * (n(k.pre[lane][l]) - c(k.out[lane][l])),
                        );
                    }
                }
            }
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
            "canonical" => {
                // word < p  <=>  bit31 = 0 and not(bits24..30 all set and
                // bits0..23 nonzero). hi = [popcount(bits24..30) == 7] is a
                // determined zero test (inverse witness), so hi * low24 = 0.
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
                    let bit = |b: usize| c(self.word_bit(slot, b));
                    let top = (24..31).fold(AB::Expr::ZERO, |acc, b| acc + bit(b)) - seven;
                    let low = sum(&mut (0..24).map(|t| (self.word_bit(slot, t), t)), &c);
                    let (inv, hi) = (
                        c(self.canon_col + 2 * slot),
                        c(self.canon_col + 2 * slot + 1),
                    );
                    builder.assert_zero(
                        gate.clone() * (top.clone() * inv - AB::Expr::ONE + hi.clone()),
                    );
                    builder.assert_zero(gate.clone() * top * hi.clone());
                    builder.assert_zero(gate.clone() * hi * low);
                    builder.assert_zero(gate * bit(31));
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
            "fs_reject" | "fs_select" | "fs_bind" => {
                let dr = step0(self.draw_perm(0)) + step0(self.draw_perm(1));
                let col = |j: usize, q: usize| c(self.draw_col + DRAW_COLS * j + q);
                let value = |j: usize| sum(&mut (0..31).map(|t| (self.draw_bit(j, t), t)), &c);
                match PHASES[phase] {
                    "fs_reject" => {
                        for j in 0..DRAWS {
                            let top = (24..31)
                                .fold(AB::Expr::ZERO, |acc, t| acc + c(self.draw_bit(j, t)))
                                - seven;
                            let low = sum(&mut (0..24).map(|t| (self.draw_bit(j, t), t)), &c);
                            let (inv_hi, hi, inv_lo, nz, acc) =
                                (col(j, 0), col(j, 1), col(j, 2), col(j, 3), col(j, 4));
                            builder.assert_zero(
                                dr.clone() * (top.clone() * inv_hi - AB::Expr::ONE + hi.clone()),
                            );
                            builder.assert_zero(dr.clone() * top * hi.clone());
                            builder.assert_zero(dr.clone() * (low.clone() * inv_lo - nz.clone()));
                            builder.assert_zero(dr.clone() * low * (AB::Expr::ONE - nz.clone()));
                            builder.assert_zero(dr.clone() * (acc - AB::Expr::ONE + hi * nz));
                        }
                    }
                    "fs_select" => {
                        // Slot k takes exactly one draw, which must be accepted
                        // and preceded by exactly k accepted draws.
                        let mut before = AB::Expr::ZERO;
                        for j in 0..DRAWS {
                            for slot in 0..4 {
                                let sel = col(j, 5 + slot);
                                builder.assert_zero(
                                    dr.clone() * sel.clone() * (sel.clone() - AB::Expr::ONE),
                                );
                                builder.assert_zero(
                                    dr.clone() * sel.clone() * (AB::Expr::ONE - col(j, 4)),
                                );
                                builder.assert_zero(
                                    dr.clone() * sel * (before.clone() - Val::from_usize(slot)),
                                );
                            }
                            before += col(j, 4);
                        }
                        for slot in 0..4 {
                            let taken =
                                (0..DRAWS).fold(AB::Expr::ZERO, |acc, j| acc + col(j, 5 + slot));
                            builder.assert_zero(dr.clone() * (taken - AB::Expr::ONE));
                        }
                    }
                    _ => {
                        for (i, route) in self.routes.iter().enumerate() {
                            let Route::Draw(f) = *route else { continue };
                            let sel = step0(self.draw_perm(f));
                            for slot in 0..4 {
                                let drawn = (0..DRAWS).fold(AB::Expr::ZERO, |acc, j| {
                                    acc + col(j, 5 + slot) * value(j)
                                });
                                builder.assert_zero(
                                    sel.clone() * (drawn - c(self.in_col + 4 * i + slot)),
                                );
                            }
                        }
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
            other => unreachable!("unknown phase {other}"),
        }
    }

    /// Constraint-index range of every phase, counted on the symbolic
    /// builder (which numbers constraints exactly as the debug scanner does).
    fn phase_ranges(&self) -> Vec<Range<usize>> {
        let layout = AirLayout::from_air::<Val>(self);
        let mut start = 0;
        (0..PHASES.len())
            .map(|phase| {
                let mut builder = SymbolicAirBuilder::<Val>::new(layout);
                self.eval_phase(phase, &mut builder);
                let end = start + builder.base_constraints().len();
                let range = start..end;
                start = end;
                range
            })
            .collect()
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
        let mut lane_inputs = rep.perms.clone();
        lane_inputs.resize(h / NUM_ROUNDS, [0; 25]);
        let lane = generate_trace_rows::<Val>(lane_inputs, 0);
        require(lane.height() == h, "keccak lane height")?;
        let mut values = vec![Val::ZERO; h * w];
        for row in 0..h {
            values[row * w..row * w + NUM_KECCAK_COLS]
                .copy_from_slice(&lane.values[row * NUM_KECCAK_COLS..(row + 1) * NUM_KECCAK_COLS]);
        }
        let set_bits = |values: &mut [Val], base: usize, v: u64| {
            for b in 0..64 {
                values[base + b] = Val::from_u64((v >> b) & 1);
            }
        };
        for (perm, input) in rep.perms.iter().enumerate() {
            let row = NUM_ROUNDS * perm * w;
            let prev = if self.layout.is_interior(perm) {
                keccakf(&rep.perms[perm - 1])
            } else {
                [0; 25]
            };
            for l in 0..RATE_LANES {
                set_bits(&mut values, row + self.m_col + 64 * l, input[l] ^ prev[l]);
                set_bits(&mut values, row + self.s_col + 64 * l, prev[l]);
            }
            let flush = self.layout.flush_of(perm);
            let first_word = (perm - self.layout.first[flush]) * RATE_WORDS;
            for slot in 0..RATE_WORDS {
                let word = self.layout.flushes[flush][first_word + slot];
                if !word.is_field() {
                    continue;
                }
                let v = rep.words[flush][first_word + slot];
                let top = Val::from_u32(((v >> 24) & 0x7f).count_ones()) - Val::from_u32(7);
                let at = row + self.canon_col + 2 * slot;
                if top == Val::ZERO {
                    values[at + 1] = Val::ONE;
                } else {
                    values[at] = top.inverse();
                }
            }
        }
        for f in 0..2 {
            let d = &rep.digests[f];
            let v = draw_values(d);
            let pick = match pick[f] {
                Some(p) => p,
                None => accepted(d)?,
            };
            let row = NUM_ROUNDS * self.draw_perm(f) * w + self.draw_col;
            for j in 0..DRAWS {
                let cells = &mut values[row + DRAW_COLS * j..row + DRAW_COLS * (j + 1)];
                let top = Val::from_u32(((v[j] >> 24) & 0x7f).count_ones()) - Val::from_u32(7);
                let low = Val::from_u32(v[j] & 0x00ff_ffff);
                let hi = top == Val::ZERO;
                let nz = low != Val::ZERO;
                if !hi {
                    cells[0] = top.inverse();
                }
                cells[1] = Val::from_bool(hi);
                if nz {
                    cells[2] = low.inverse();
                }
                cells[3] = Val::from_bool(nz);
                cells[4] = Val::from_bool(!(hi && nz));
                for (slot, &j_picked) in pick.iter().enumerate() {
                    cells[5 + slot] = Val::from_bool(j_picked == j);
                }
            }
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
    /// canonical order, then the claimed F2 digest as 16-bit limbs.
    fn public_values(&self, data: &Data, digest: &[u8; 32]) -> Vec<Val> {
        let mut pv = data.inner_pvs.clone();
        for n in 0..3 * CAP_WORDS {
            let w = data.cap_word(n);
            pv.extend([Val::from_u32(w & 0xffff), Val::from_u32(w >> 16)]);
        }
        for lane in 0..4 {
            let v = u64::from_le_bytes(digest[8 * lane..8 * lane + 8].try_into().unwrap());
            pv.extend((0..4).map(|l| Val::from_u64((v >> (16 * l)) & 0xffff)));
        }
        pv
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
mod tests {
    use std::sync::OnceLock;

    use p3_air::symbolic::get_symbolic_constraints;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_uni_stark::{prove, verify, StarkGenericConfig};
    use qlab_air::l2test::{satisfied, violations_at};
    use qlab_l2::L2_CFG_PROVISIONAL;

    use super::super::{compare_native, proof_inputs_dims};
    use super::*;

    /// Two columns, two PVs, one next-row read, degree 3: the smallest AIR
    /// that feeds every DAG input class and gets the L2 lane's eight hiding
    /// quotient chunks (degree 3 + ZK -> log_q 2, x2 hiding split).
    struct Toy;
    const TOY_LOG_HEIGHT: usize = 4;

    impl BaseAir<Val> for Toy {
        fn width(&self) -> usize {
            2
        }
        fn num_public_values(&self) -> usize {
            2
        }
    }

    impl<AB: AirBuilder<F = Val>> Air<AB> for Toy {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let x: AB::Expr = main.current_slice()[0].into();
            let y: AB::Expr = main.current_slice()[1].into();
            let nx: AB::Expr = main.next_slice()[0].into();
            let ny: AB::Expr = main.next_slice()[1].into();
            let pv: Vec<AB::Expr> = builder
                .public_values()
                .iter()
                .map(|v| (*v).into())
                .collect();
            builder.when_first_row().assert_eq(x.clone(), pv[0].clone());
            builder.when_transition().assert_eq(nx, y.clone());
            builder
                .when_transition()
                .assert_eq(ny, x.clone() * y.clone() * y.clone() + x);
            builder.when_last_row().assert_eq(y, pv[1].clone());
        }
    }

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
            let (mut x, mut y) = (Val::from_u32(3), Val::from_u32(5));
            let mut rows = Vec::new();
            for _ in 0..1 << TOY_LOG_HEIGHT {
                rows.extend([x, y]);
                (x, y) = (y, x * y * y + x);
            }
            let pvs = vec![rows[0], rows[rows.len() - 1]];
            let config = qlab_consensus::make_config_seeded(&L2_CFG_PROVISIONAL, 0xf2b2a);
            let proof = prove(&config, &Toy, RowMajorMatrix::new(rows, 2), &pvs);
            verify(&config, &Toy, &proof, &pvs).expect("toy hiding proof verifies");
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
            let mut ch = qlab_l2::make_config_l2().initialise_challenger();
            ch.observe(Val::from_usize(proof.degree_bits));
            ch.observe(Val::from_usize(TOY_LOG_HEIGHT));
            ch.observe(Val::ZERO);
            ch.observe(proof.commitments.trace.clone());
            ch.observe_slice(&pvs);
            let _: E = ch.sample_algebra_element();
            ch.observe(proof.commitments.quotient_chunks.clone());
            ch.observe(proof.commitments.random.clone().unwrap());
            let _: E = ch.sample_algebra_element();
            ch.observe_algebra_slice(&data.random);
            ch.observe_algebra_slice(&data.local);
            ch.observe_algebra_slice(&data.next);
            for chunk in &data.chunks {
                ch.observe_algebra_slice(chunk);
            }
            let fri_alpha: E = ch.sample_algebra_element();
            let d2 = &honest.digests[2];
            assert_eq!(
                challenge(d2, accepted(d2).unwrap()),
                fri_alpha,
                "F2 message order"
            );
            let ranges = air.phase_ranges();
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
        let pvs = fx.air.public_values(&fx.data, &rep.digests[2]);
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
}
