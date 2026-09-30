//! The Keccak sponge lane shared by the F2b transcript components: F2b-2a's
//! `bind` (F0..F2, the OOD inputs) and F2b-2b-i's `fri_fs` (the FRI
//! continuation). Test-only, like both of its users.
//!
//! One lane = stock p3-keccak-air (24 rows per perm) plus, on each perm's
//! step-0 row, the block's message bits `M` and the previous output's rate
//! bits `S`, with `preimage = M xor S`. What is common to both components
//! lives here, and only that:
//!
//! - **Native replay**: Keccak pad10*1 on a word stream, the absorb loop, and
//!   the challenger's draw order (pop from the END of the 32-byte output, four
//!   bytes little-endian per draw).
//! - **Constraint gadgets**: message/state bits, `absorb`, `chain_state`
//!   (S and the capacity carried on interior blocks, zero on a flush's first
//!   block), `flush_chain` (a flush's first four lanes equal the previous
//!   digest), the `< p` canonicity comparator, and the field-draw
//!   reject/one-hot selection. Each gadget emits exactly the constraints, in
//!   exactly the order, F2b-2a shipped with (its negatives pin the grouping).
//!
//! What each component binds to the words of its stream — constants, caps,
//! field values, draws — stays in the component: that is where the two
//! transcripts differ.
use std::borrow::Borrow;
use std::ops::Range;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{generate_trace_rows, KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::Matrix;

use qlab_consensus::CAP_HEIGHT;

use super::{require, Result, Val, E};
use crate::m4gaterec::{digest_of, keccakf};
use crate::m4skel::LaneBuilder;

pub(super) const RATE_LANES: usize = 17;
pub(super) const RATE_WORDS: usize = 2 * RATE_LANES;
pub(super) const RATE_BITS: usize = 64 * RATE_LANES;
/// Draws one 32-byte digest provides before the challenger refills.
pub(super) const DRAWS: usize = 8;
/// Columns per field draw: inv_hi, hi, inv_lo, nz, acc, then four slot selectors.
pub(super) const DRAW_COLS: usize = 9;
pub(super) const P: u32 = Val::ORDER_U32;
/// Words of one observed cap: 2^CAP_HEIGHT digests x 4 u64 x 2 words.
pub(super) const CAP_WORDS: usize = (1 << CAP_HEIGHT) * 8;

/// The raw Monty word the challenger serializes (`to_unique_u32`).
pub(super) fn monty(v: Val) -> u32 {
    v.to_unique_u32()
}

/// Keccak pad10*1 (domain byte 0x01) on a 4-byte-aligned message: the 0x01
/// lands at a word's low byte and 0x80 at the block's last byte.
pub(super) fn pad<W>(mut words: Vec<W>, konst: impl Fn(u32) -> W) -> Vec<W> {
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
        words.push(konst(v));
    }
    words
}

/// Absorb one padded flush from a zero state: pushes each block's preimage
/// (the lane input) and returns the flush digest.
pub(super) fn absorb(stream: &[u32], perms: &mut Vec<[u64; 25]>) -> [u8; 32] {
    let mut state = [0u64; 25];
    for block in stream.chunks(RATE_WORDS) {
        for lane in 0..RATE_LANES {
            state[lane] ^= u64::from(block[2 * lane]) | (u64::from(block[2 * lane + 1]) << 32);
        }
        perms.push(state);
        state = keccakf(&state);
    }
    digest_of(&state)
}

/// The eight raw u32 draws of one digest, in challenger order: draw j is
/// bytes 31-4j..28-4j, little-endian. `sample_bits` reads these unmasked.
pub(super) fn draw_words(d: &[u8; 32]) -> [u32; DRAWS] {
    core::array::from_fn(|j| {
        u32::from_le_bytes([d[31 - 4 * j], d[30 - 4 * j], d[29 - 4 * j], d[28 - 4 * j]])
    })
}

/// The eight 31-bit masked draws of one digest (base-field `sample`).
pub(super) fn draw_values(d: &[u8; 32]) -> [u32; DRAWS] {
    draw_words(d).map(|w| w & 0x7fff_ffff)
}

/// Indices of the first four accepted draws — native `sample_algebra_element`.
pub(super) fn accepted(d: &[u8; 32]) -> Result<[usize; 4]> {
    let v = draw_values(d);
    let idx: Vec<usize> = (0..DRAWS).filter(|&j| v[j] < P).take(4).collect();
    require(idx.len() == 4, "draw window needs a refill (unsupported)")?;
    Ok([idx[0], idx[1], idx[2], idx[3]])
}

pub(super) fn challenge(d: &[u8; 32], pick: [usize; 4]) -> E {
    let v = draw_values(d);
    E::from_basis_coefficients_fn(|k| Val::from_u32(v[pick[k]]))
}

/// Keccak lane column indices used by the binding (standard lane = x + 5y).
#[derive(Clone)]
pub(super) struct KeccakIdx {
    pub(super) step0: usize,
    pub(super) fin: usize,
    pub(super) pre: [[usize; 4]; 25],
    pub(super) out: [[usize; 4]; 25],
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

/// A component with named constraint groups evaluated in order; the tests
/// map a violated constraint index back to its group's name.
pub(super) trait Phased: BaseAir<Val> {
    fn phases(&self) -> &'static [&'static str];
    fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB);
}

/// Constraint-index range of every phase, counted on the symbolic builder
/// (which numbers constraints exactly as the debug scanner does).
pub(super) fn phase_ranges<A: Phased>(air: &A) -> Vec<Range<usize>> {
    let layout = AirLayout::from_air::<Val>(air);
    let mut start = 0;
    (0..air.phases().len())
        .map(|phase| {
            let mut builder = SymbolicAirBuilder::<Val>::new(layout);
            air.eval_phase(phase, &mut builder);
            let end = start + builder.base_constraints().len();
            let range = start..end;
            start = end;
            range
        })
        .collect()
}

/// Periodic sponge selectors for a lane of `perms` perms whose flushes start
/// at `first`: one step-0 selector per perm, then `interior` (on the last
/// row of a perm whose successor continues the same flush), then `chain`
/// (on the last row of a perm whose successor starts a later flush).
pub(super) fn sponge_selectors(first: &[usize], perms: usize, height: usize) -> Vec<Vec<Val>> {
    let mut cols = vec![vec![Val::ZERO; height]; perms + 2];
    let last = |perm: usize| NUM_ROUNDS * perm + NUM_ROUNDS - 1;
    for perm in 0..perms {
        cols[perm][NUM_ROUNDS * perm] = Val::ONE;
        let succ = perm + 1;
        if succ < perms && !first.contains(&succ) {
            cols[perms][last(perm)] = Val::ONE;
        }
    }
    for &f in first.iter().filter(|&&f| f > 0) {
        cols[perms + 1][last(f - 1)] = Val::ONE;
    }
    cols
}

/// The lane's columns: Keccak at 0, then M bits, then S bits.
#[derive(Clone)]
pub(super) struct Lane {
    pub(super) kc: KeccakIdx,
    pub(super) m_col: usize,
    pub(super) s_col: usize,
    pub(super) pow2: Vec<Val>,
}

impl Lane {
    pub(super) fn new() -> Self {
        Self {
            kc: keccak_idx(),
            m_col: NUM_KECCAK_COLS,
            s_col: NUM_KECCAK_COLS + RATE_BITS,
            pow2: (0..32).map(|t| Val::TWO.exp_u64(t)).collect(),
        }
    }

    /// First column after the lane.
    pub(super) fn end(&self) -> usize {
        self.s_col + RATE_BITS
    }

    /// Message bit `b` (0..32) of rate word `slot`.
    pub(super) fn word_bit(&self, slot: usize, b: usize) -> usize {
        self.m_col + 64 * (slot / 2) + 32 * (slot % 2) + b
    }

    /// Bit `t` (0..32) of raw draw `j` of the digest carried as the M bits
    /// of a flush's first block: draw bytes 31-4j..28-4j, little-endian.
    pub(super) fn draw_bit(&self, j: usize, t: usize) -> usize {
        let byte = 31 - 4 * j - t / 8;
        self.m_col + 64 * (byte / 8) + 8 * (byte % 8) + t % 8
    }

    fn bits<AB: AirBuilder<F = Val>>(
        &self,
        row: &[AB::Var],
        cols: impl Iterator<Item = (usize, usize)>,
    ) -> AB::Expr {
        cols.fold(AB::Expr::ZERO, |acc, (col, t)| {
            acc + Into::<AB::Expr>::into(row[col]) * self.pow2[t]
        })
    }

    /// 16-bit half `h` of rate word `slot`, from a row's M bits.
    pub(super) fn half<AB: AirBuilder<F = Val>>(
        &self,
        row: &[AB::Var],
        slot: usize,
        h: usize,
    ) -> AB::Expr {
        self.bits::<AB>(row, (0..16).map(|t| (self.word_bit(slot, 16 * h + t), t)))
    }

    pub(super) fn full<AB: AirBuilder<F = Val>>(&self, row: &[AB::Var], slot: usize) -> AB::Expr {
        self.half::<AB>(row, slot, 0) + self.half::<AB>(row, slot, 1) * self.pow2[16]
    }

    /// Masked 31-bit value of field draw `j`.
    fn draw_value<AB: AirBuilder<F = Val>>(&self, row: &[AB::Var], j: usize) -> AB::Expr {
        self.bits::<AB>(row, (0..31).map(|t| (self.draw_bit(j, t), t)))
    }

    /// The draw the one-hot selection assigns to limb `slot`.
    pub(super) fn selected<AB: AirBuilder<F = Val>>(
        &self,
        row: &[AB::Var],
        draw_col: usize,
        slot: usize,
    ) -> AB::Expr {
        (0..DRAWS).fold(AB::Expr::ZERO, |acc, j| {
            acc + Into::<AB::Expr>::into(row[draw_col + DRAW_COLS * j + 5 + slot])
                * self.draw_value::<AB>(row, j)
        })
    }

    pub(super) fn eval_keccak<AB: AirBuilder<F = Val>>(&self, builder: &mut AB) {
        let mut lane = LaneBuilder {
            inner: builder,
            off: 0,
            width: NUM_KECCAK_COLS,
        };
        KeccakAir {}.eval(&mut lane);
    }

    pub(super) fn eval_bits<AB: AirBuilder<F = Val>>(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        for i in 0..RATE_BITS {
            builder.assert_bool(cur[self.m_col + i]);
            builder.assert_bool(cur[self.s_col + i]);
        }
    }

    pub(super) fn eval_absorb<AB: AirBuilder<F = Val>>(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let xor = |a: AB::Expr, b: AB::Expr| a.clone() + b.clone() - a * b * Val::TWO;
        let k = &self.kc;
        for lane in 0..RATE_LANES {
            for l in 0..4 {
                let bits = (0..16).fold(AB::Expr::ZERO, |acc, t| {
                    let b = 64 * lane + 16 * l + t;
                    acc + xor(c(self.m_col + b), c(self.s_col + b)) * self.pow2[t]
                });
                builder.assert_zero(c(k.step0) * (c(k.pre[lane][l]) - bits));
            }
        }
    }

    /// `inter` is the interior selector: on a perm's last row, the next
    /// block's S and capacity carry this perm's output when it is set and are
    /// zero when it is not (a flush's first block). Row 0 starts from zero.
    pub(super) fn eval_chain_state<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        inter: AB::Expr,
    ) {
        let main = builder.main();
        let (cur, next) = (main.current_slice(), main.next_slice());
        let k = &self.kc;
        for lane in 0..25 {
            for l in 0..4 {
                let (prev_rate, first_rate) = if lane < RATE_LANES {
                    let cols = |t: usize| (self.s_col + 64 * lane + 16 * l + t, t);
                    (
                        self.bits::<AB>(next, (0..16).map(cols)),
                        self.bits::<AB>(cur, (0..16).map(cols)),
                    )
                } else {
                    (next[k.pre[lane][l]].into(), cur[k.pre[lane][l]].into())
                };
                let fin: AB::Expr = cur[k.fin].into();
                let out: AB::Expr = cur[k.out[lane][l]].into();
                builder
                    .when_transition()
                    .assert_zero(fin * (prev_rate - inter.clone() * out));
                builder.when_first_row().assert_zero(first_rate);
            }
        }
    }

    /// `chain` is set on the last row of a flush: the next flush's first
    /// four preimage lanes equal this digest (its S is zero, so its M bits
    /// ARE the digest bits the draws read).
    pub(super) fn eval_flush_chain<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        chain: AB::Expr,
    ) {
        let main = builder.main();
        let (cur, next) = (main.current_slice(), main.next_slice());
        let k = &self.kc;
        for lane in 0..4 {
            for l in 0..4 {
                let pre: AB::Expr = next[k.pre[lane][l]].into();
                builder.assert_zero(chain.clone() * (pre - cur[k.out[lane][l]].into()));
            }
        }
    }

    /// word < p  <=>  bit31 = 0 and not(bits24..30 all set and bits0..23
    /// nonzero). hi = [popcount(bits24..30) == 7] is a determined zero test
    /// (inverse witness), so hi * low24 = 0.
    pub(super) fn eval_canonical<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        slot: usize,
        gate: AB::Expr,
        canon_col: usize,
    ) {
        let main = builder.main();
        let cur = main.current_slice();
        let bit = |b: usize| -> AB::Expr { cur[self.word_bit(slot, b)].into() };
        let top = (24..31).fold(AB::Expr::ZERO, |acc, b| acc + bit(b)) - Val::from_u32(7);
        let low = self.bits::<AB>(cur, (0..24).map(|t| (self.word_bit(slot, t), t)));
        let (inv, hi): (AB::Expr, AB::Expr) = (
            cur[canon_col + 2 * slot].into(),
            cur[canon_col + 2 * slot + 1].into(),
        );
        builder.assert_zero(gate.clone() * (top.clone() * inv - AB::Expr::ONE + hi.clone()));
        builder.assert_zero(gate.clone() * top * hi.clone());
        builder.assert_zero(gate.clone() * hi * low);
        builder.assert_zero(gate * bit(31));
    }

    /// Field-draw rejection on the rows `dr` selects: acc_j = [draw j < p],
    /// determined by two inverse-witness zero tests.
    pub(super) fn eval_fs_reject<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        dr: AB::Expr,
        draw_col: usize,
    ) {
        let main = builder.main();
        let cur = main.current_slice();
        let col = |j: usize, q: usize| -> AB::Expr { cur[draw_col + DRAW_COLS * j + q].into() };
        for j in 0..DRAWS {
            let top = (0..7).fold(AB::Expr::ZERO, |acc, t| {
                acc + Into::<AB::Expr>::into(cur[self.draw_bit(j, 24 + t)])
            }) - Val::from_u32(7);
            let low = self.bits::<AB>(cur, (0..24).map(|t| (self.draw_bit(j, t), t)));
            let (inv_hi, hi, inv_lo, nz, acc) =
                (col(j, 0), col(j, 1), col(j, 2), col(j, 3), col(j, 4));
            builder.assert_zero(dr.clone() * (top.clone() * inv_hi - AB::Expr::ONE + hi.clone()));
            builder.assert_zero(dr.clone() * top * hi.clone());
            builder.assert_zero(dr.clone() * (low.clone() * inv_lo - nz.clone()));
            builder.assert_zero(dr.clone() * low * (AB::Expr::ONE - nz.clone()));
            builder.assert_zero(dr.clone() * (acc - AB::Expr::ONE + hi * nz));
        }
    }

    /// Slot k takes exactly one draw, which must be accepted and preceded by
    /// exactly k accepted draws: a rejected draw advances nothing.
    pub(super) fn eval_fs_select<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        dr: AB::Expr,
        draw_col: usize,
    ) {
        let main = builder.main();
        let cur = main.current_slice();
        let col = |j: usize, q: usize| -> AB::Expr { cur[draw_col + DRAW_COLS * j + q].into() };
        let mut before = AB::Expr::ZERO;
        for j in 0..DRAWS {
            for slot in 0..4 {
                let sel = col(j, 5 + slot);
                builder.assert_zero(dr.clone() * sel.clone() * (sel.clone() - AB::Expr::ONE));
                builder.assert_zero(dr.clone() * sel.clone() * (AB::Expr::ONE - col(j, 4)));
                builder.assert_zero(dr.clone() * sel * (before.clone() - Val::from_usize(slot)));
            }
            before += col(j, 4);
        }
        for slot in 0..4 {
            let taken = (0..DRAWS).fold(AB::Expr::ZERO, |acc, j| acc + col(j, 5 + slot));
            builder.assert_zero(dr.clone() * (taken - AB::Expr::ONE));
        }
    }

    /// Dense trace with the Keccak lane filled for `perms` (zero perms pad
    /// the lane to `height`) and every other cell zero.
    pub(super) fn trace(
        &self,
        perms: &[[u64; 25]],
        height: usize,
        width: usize,
    ) -> Result<Vec<Val>> {
        self.trace_reserved(perms, height, width, 0)
    }

    /// [`Self::trace`] with capacity for `extra_capacity_bits` more of
    /// height reserved up front: the prover's LDE extends in place, so a
    /// trace allocated for proving reserves `log_blowup` (lab #782 X1, as
    /// `m4gate::build_gate_trace`; a late reserve copies the trace).
    pub(super) fn trace_reserved(
        &self,
        perms: &[[u64; 25]],
        height: usize,
        width: usize,
        extra_capacity_bits: usize,
    ) -> Result<Vec<Val>> {
        let mut lane_inputs = perms.to_vec();
        lane_inputs.resize(height / NUM_ROUNDS, [0; 25]);
        let lane = generate_trace_rows::<Val>(lane_inputs, 0);
        require(lane.height() == height, "keccak lane height")?;
        let mut values = Vec::with_capacity((height << extra_capacity_bits) * width);
        values.resize(height * width, Val::ZERO);
        for row in 0..height {
            values[row * width..row * width + NUM_KECCAK_COLS]
                .copy_from_slice(&lane.values[row * NUM_KECCAK_COLS..(row + 1) * NUM_KECCAK_COLS]);
        }
        Ok(values)
    }

    /// M and S bits of one perm's step-0 row, starting at cell `row`.
    /// `prev` is the previous perm's output on interior blocks, else zero.
    pub(super) fn fill_block(
        &self,
        values: &mut [Val],
        row: usize,
        input: &[u64; 25],
        prev: &[u64; 25],
    ) {
        let set_bits = |values: &mut [Val], base: usize, v: u64| {
            for b in 0..64 {
                values[base + b] = Val::from_u64((v >> b) & 1);
            }
        };
        for l in 0..RATE_LANES {
            set_bits(values, row + self.m_col + 64 * l, input[l] ^ prev[l]);
            set_bits(values, row + self.s_col + 64 * l, prev[l]);
        }
    }

    /// Canonicity witness (inv, hi) for word `v` at cells `at`, `at + 1`.
    pub(super) fn fill_canonical(values: &mut [Val], at: usize, v: u32) {
        let top = Val::from_u32(((v >> 24) & 0x7f).count_ones()) - Val::from_u32(7);
        if top == Val::ZERO {
            values[at + 1] = Val::ONE;
        } else {
            values[at] = top.inverse();
        }
    }

    /// Reject witnesses and one-hot selectors of one digest's field draws.
    pub(super) fn fill_draws(cells: &mut [Val], d: &[u8; 32], pick: [usize; 4]) {
        let v = draw_values(d);
        for j in 0..DRAWS {
            let cells = &mut cells[DRAW_COLS * j..DRAW_COLS * (j + 1)];
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
}

/// Outer-PV 16-bit limbs of a 32-byte digest, lane by lane, low limb first
/// (the order `k.out[lane][l]` / `k.pre[lane][l]` use).
pub(super) fn digest_limbs(d: &[u8; 32]) -> Vec<Val> {
    let mut pv = Vec::with_capacity(16);
    for lane in 0..4 {
        let v = u64::from_le_bytes(d[8 * lane..8 * lane + 8].try_into().unwrap());
        pv.extend((0..4).map(|l| Val::from_u64((v >> (16 * l)) & 0xffff)));
    }
    pv
}

/// Test fixtures shared by both transcript components.
#[cfg(test)]
pub(super) mod toy {
    use std::collections::BTreeSet;

    use p3_air::DebugConstraintBuilder;
    use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_maybe_rayon::prelude::*;
    use p3_uni_stark::{prove, verify, Proof, StarkGenericConfig};
    use qlab_air::l2test::violations_at;
    use qlab_consensus::{Config, IS_ZK};
    use crate::f2::F2_LANE;

    use crate::f2::price::fri_log_arities;

    /// The verifier's own challenger type.
    pub(in crate::f2::ood) type Native = <Config as StarkGenericConfig>::Challenger;

    use super::*;

    /// Two columns, two PVs, one next-row read, degree 3: the smallest AIR
    /// that feeds every DAG input class and gets the L2 lane's eight hiding
    /// quotient chunks (degree 3 + ZK -> log_q 2, x2 hiding split).
    pub(in crate::f2::ood) struct Toy;

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

    /// The toy's recurrence trace at `log_height` and its two PVs.
    fn toy_trace(log_height: usize) -> (RowMajorMatrix<Val>, Vec<Val>) {
        let (mut x, mut y) = (Val::from_u32(3), Val::from_u32(5));
        let mut rows = Vec::new();
        for _ in 0..1 << log_height {
            rows.extend([x, y]);
            (x, y) = (y, x * y * y + x);
        }
        let pvs = vec![rows[0], rows[rows.len() - 1]];
        (RowMajorMatrix::new(rows, 2), pvs)
    }

    /// One real hiding proof of the toy at `log_height` on the L2 lane,
    /// seeded so CI replays the same transcript every run.
    pub(in crate::f2::ood) fn toy_proof(log_height: usize, seed: u64) -> (Proof<Config>, Vec<Val>) {
        let (trace, pvs) = toy_trace(log_height);
        let config = qlab_consensus::make_config_seeded(&F2_LANE, seed);
        let proof = prove(&config, &Toy, trace, &pvs);
        verify(&config, &Toy, &proof, &pvs).expect("toy hiding proof verifies");
        (proof, pvs)
    }

    /// One real NON-hiding proof of the toy at `log_height` on the L2 lane's
    /// FRI parameters (`qlab_consensus::legacy`): F4b-2's smallest zk = 0
    /// child (lab #782). Deterministic (no hiding randomness).
    pub(in crate::f2::ood) fn toy_legacy_proof(
        log_height: usize,
    ) -> (
        Proof<qlab_consensus::legacy::LegacyNonHidingConfig>,
        Vec<Val>,
    ) {
        let (trace, pvs) = toy_trace(log_height);
        let config = qlab_consensus::legacy::make_legacy_config_with(&F2_LANE);
        let proof = prove(&config, &Toy, trace, &pvs);
        verify(&config, &Toy, &proof, &pvs).expect("toy non-hiding proof verifies");
        (proof, pvs)
    }

    /// F2b-5 (issue #750): the toy plus one period-4 periodic column
    /// s = (1, 0, 0, 0) and the constraint s · (x' − y) = 0 on transitions,
    /// which the toy's own x' = y implies. It changes nothing about the
    /// trace, but the OOD identity now reads s(ζ): the smallest real hiding
    /// proof on which a wrong periodic evaluation can be refused. Degree 3
    /// still, so eight hiding quotient chunks, as the toy.
    pub(in crate::f2::ood) struct ToyPeriodic;

    impl BaseAir<Val> for ToyPeriodic {
        fn width(&self) -> usize {
            2
        }
        fn num_public_values(&self) -> usize {
            2
        }
        fn num_periodic_columns(&self) -> usize {
            1
        }
        fn periodic_columns(&self) -> Vec<Vec<Val>> {
            vec![vec![Val::ONE, Val::ZERO, Val::ZERO, Val::ZERO]]
        }
    }

    impl<AB: AirBuilder<F = Val>> Air<AB> for ToyPeriodic {
        fn eval(&self, builder: &mut AB) {
            Toy.eval(builder);
            let main = builder.main();
            let y: AB::Expr = main.current_slice()[1].into();
            let nx: AB::Expr = main.next_slice()[0].into();
            let s: AB::Expr = builder.periodic_values()[0].into();
            builder.when_transition().assert_zero(s * (nx - y));
        }
    }

    /// One real hiding proof of [`ToyPeriodic`] (the toy's trace), seeded.
    pub(in crate::f2::ood) fn toy_periodic_proof(
        log_height: usize,
        seed: u64,
    ) -> (Proof<Config>, Vec<Val>) {
        let (trace, pvs) = toy_trace(log_height);
        let config = qlab_consensus::make_config_seeded(&F2_LANE, seed);
        let proof = prove(&config, &ToyPeriodic, trace, &pvs);
        verify(&config, &ToyPeriodic, &proof, &pvs).expect("periodic toy proof verifies");
        (proof, pvs)
    }

    /// A deep copy of a proof (p3's `Proof` is not `Clone`): what a forger
    /// edits.
    pub(in crate::f2::ood) fn copy(proof: &Proof<Config>) -> Proof<Config> {
        let bytes = bincode::serialize(proof).expect("serialize a proof");
        bincode::deserialize(&bytes).expect("deserialize a proof")
    }

    /// Re-grind the query PoW of a hiding proof of height `log_height` for
    /// the transcript it now carries under `pvs`. A tampered opened value,
    /// cap or PV moves every later challenge, so the old witness fails; a
    /// forger grinds a new one (p3's challenger through F2, fri_alpha, each
    /// commit round and β, the final polynomial and the arity schedule,
    /// p3-fri `verifier.rs:298-339`), leaving only the tampering itself to
    /// be refused.
    pub(in crate::f2::ood) fn regrind(proof: &mut Proof<Config>, pvs: &[Val], log_height: usize) {
        let cfg = F2_LANE;
        let mut ch = native_through_f2(proof, pvs, log_height);
        let _fri_alpha: E = ch.sample_algebra_element();
        let fri = &proof.opening_proof.1;
        for (cm, &w) in fri
            .commit_phase_commits
            .iter()
            .zip(&fri.commit_pow_witnesses)
        {
            ch.observe(cm.clone());
            assert!(ch.check_witness(0, w), "commit PoW bits are 0");
            let _beta: E = ch.sample_algebra_element();
        }
        ch.observe_algebra_slice(&fri.final_poly);
        for a in fri_log_arities(log_height + IS_ZK + cfg.log_blowup, &cfg) {
            ch.observe(Val::from_usize(a));
        }
        proof.opening_proof.1.query_pow_witness = ch.grind(cfg.grind_bits);
    }

    /// Every (row, group) a component's trace violates, over ALL rows.
    pub(in crate::f2::ood) fn violation_set<A>(
        air: &A,
        trace: &RowMajorMatrix<Val>,
        pvs: &[Val],
    ) -> BTreeSet<(usize, &'static str)>
    where
        A: Phased + Sync + for<'b> Air<DebugConstraintBuilder<'b, Val>>,
    {
        let ranges = phase_ranges(air);
        let group = |c: usize| air.phases()[ranges.iter().position(|r| r.contains(&c)).unwrap()];
        (0..trace.height())
            .into_par_iter()
            .flat_map_iter(|row| {
                violations_at(air, trace, pvs, row)
                    .into_iter()
                    .map(move |v| (row, group(v.constraint)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect()
    }

    /// The p3 challenger driven through uni-stark 0.6.1's hiding order up to
    /// and including the opened values (F0, alpha, F1, zeta, F2): the next
    /// operation is the verifier's fri_alpha draw. Every observation mirrors
    /// `p3-uni-stark/src/verifier.rs:400-430` and `p3-fri`
    /// `two_adic_pcs.rs:696-701` (rc = 0, so no hidden halves are appended).
    pub(in crate::f2::ood) fn native_through_f2(
        proof: &Proof<Config>,
        pvs: &[Val],
        log_height: usize,
    ) -> Native {
        let o = &proof.opened_values;
        let mut ch = crate::f2::f2_config().initialise_challenger();
        ch.observe(Val::from_usize(proof.degree_bits));
        ch.observe(Val::from_usize(log_height));
        ch.observe(Val::ZERO);
        ch.observe(proof.commitments.trace.clone());
        ch.observe_slice(pvs);
        let _: E = ch.sample_algebra_element();
        ch.observe(proof.commitments.quotient_chunks.clone());
        ch.observe(proof.commitments.random.clone().unwrap());
        let _: E = ch.sample_algebra_element();
        ch.observe_algebra_slice(o.random.as_ref().unwrap());
        ch.observe_algebra_slice(&o.trace_local);
        ch.observe_algebra_slice(o.trace_next.as_ref().unwrap());
        for chunk in &o.quotient_chunks {
            ch.observe_algebra_slice(chunk);
        }
        ch
    }
}
