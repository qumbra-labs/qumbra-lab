//! Moved to `qlab_wrapper::cmp` (lab #785, F5-1); re-exported here so
//! the bench and its tests are unchanged.
#![cfg_attr(not(test), allow(unused_imports))]
pub(crate) use qlab_wrapper::cmp::*;
// The test module below reads its parent's imports through `super::*`.
#[cfg(test)]
#[allow(unused_imports)]
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
#[cfg(test)]
#[allow(unused_imports)]
use p3_field::PrimeCharacteristicRing;
#[cfg(test)]
#[allow(unused_imports)]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
#[allow(unused_imports)]
use qlab_consensus::Val;
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::hash::Digest;

// Lab #785 F5-4a (review Y2 on PR #787): the comparator's test AIR is
// test-only, so it lives here rather than in the consensus crate.
#[cfg(test)]
pub(crate) use test_air::*;
#[cfg(test)]
mod test_air {
    use super::*;

    /// **The test AIR** (condition (b)): one comparison `x < y` per row, gated
    /// by `g0 · g1` (a degree-2 gate, as a leaf role selector is), with the
    /// inputs optionally range-bound by 16 bits per limb — the property the leaf
    /// inherits from the Keccak lane. Columns: `g0, g1 | x[16] | y[16] |
    /// gadget[271] | (bound) x bits[256] | y bits[256]`.
    pub struct LtTestAir {
        pub bind_inputs: bool,
    }

    pub const G0: usize = 0;
    pub const X_OFF: usize = 2;
    pub const Y_OFF: usize = X_OFF + LIMBS;
    pub const W_OFF: usize = Y_OFF + LIMBS;
    pub const XB_OFF: usize = W_OFF + LT_WIDTH;
    pub const IN_BITS: usize = LIMBS * LIMB_BITS;

    /// The test AIR's constraints by name: the gadget's first, in its own order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TestConstraint {
        Gadget(LtConstraint),
        Gate(usize),
        /// Input bit `(side, j, i)`, side 0 = `x`, 1 = `y` (bound AIR only).
        InBit(usize, usize, usize),
        /// Input limb `(side, j)` equals its bits' recomposition (bound AIR only).
        InLimb(usize, usize),
    }

    impl TestConstraint {
        pub const fn index(self) -> usize {
            match self {
                Self::Gadget(c) => c.index(),
                Self::Gate(k) => LT_CONSTRAINTS + k,
                Self::InBit(s, j, i) => LT_CONSTRAINTS + 2 + IN_BITS * s + LIMB_BITS * j + i,
                Self::InLimb(s, j) => LT_CONSTRAINTS + 2 + 2 * IN_BITS + LIMBS * s + j,
            }
        }
    }

    impl BaseAir<Val> for LtTestAir {
        fn width(&self) -> usize {
            XB_OFF + if self.bind_inputs { 2 * IN_BITS } else { 0 }
        }
    }

    impl<AB: AirBuilder<F = Val>> Air<AB> for LtTestAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let cur = main.current_slice();
            let c = |i: usize| -> AB::Expr { cur[i].into() };
            let x: [AB::Expr; LIMBS] = core::array::from_fn(|j| c(X_OFF + j));
            let y: [AB::Expr; LIMBS] = core::array::from_fn(|j| c(Y_OFF + j));
            eval_lt(builder, c(G0) * c(G0 + 1), &x, &y, &cur[W_OFF..W_OFF + LT_WIDTH]);
            builder.assert_bool(cur[G0]);
            builder.assert_bool(cur[G0 + 1]);
            if self.bind_inputs {
                for b in &cur[XB_OFF..XB_OFF + 2 * IN_BITS] {
                    builder.assert_bool(*b);
                }
                for (side, limbs) in [x, y].into_iter().enumerate() {
                    for (j, limb) in limbs.into_iter().enumerate() {
                        let off = XB_OFF + IN_BITS * side + LIMB_BITS * j;
                        let r = (0..LIMB_BITS).rev().fold(AB::Expr::ZERO, |acc, i| acc.double() + c(off + i));
                        builder.assert_zero(limb - r);
                    }
                }
            }
        }
    }

    /// One test-AIR row: comparison `x < y` with gadget witness `w`, active iff
    /// `on`. Input bits are each limb's low 16 bits (what a range-bound source
    /// can carry).
    pub fn test_row(air: &LtTestAir, x: &Limbs, y: &Limbs, w: &LtWitness, on: bool) -> Vec<Val> {
        let mut row = vec![Val::ZERO; BaseAir::<Val>::width(air)];
        row[G0] = Val::from_bool(on);
        row[G0 + 1] = Val::from_bool(on);
        for j in 0..LIMBS {
            row[X_OFF + j] = Val::from_u32(x[j]);
            row[Y_OFF + j] = Val::from_u32(y[j]);
        }
        fill(&mut row[W_OFF..W_OFF + LT_WIDTH], w);
        if air.bind_inputs {
            for (side, v) in [x, y].into_iter().enumerate() {
                for j in 0..LIMBS {
                    for i in 0..LIMB_BITS {
                        row[XB_OFF + IN_BITS * side + LIMB_BITS * j + i] = Val::from_u32((v[j] >> i) & 1);
                    }
                }
            }
        }
        row
    }

    /// Stack rows into a trace, padded with idle (all-zero) rows to a power of two.
    pub fn test_trace(air: &LtTestAir, rows: Vec<Vec<Val>>) -> RowMajorMatrix<Val> {
        let width = BaseAir::<Val>::width(air);
        let height = rows.len().max(2).next_power_of_two();
        let mut values = Vec::with_capacity(height * width);
        for r in &rows {
            assert_eq!(r.len(), width);
            values.extend_from_slice(r);
        }
        values.resize(height * width, Val::ZERO);
        RowMajorMatrix::new(values, width)
    }
}

#[cfg(test)]
mod tests {
    use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
    use p3_field::PrimeField32;
    use qlab_air::l2p::{key_lt, KEY_MAX};
    use qlab_air::l2test::{satisfied, violations_at};

    use super::*;

    /// Shape P's comparison recurrence (`qlab_air::l2p` trace generation),
    /// natively: per lane, bit-serial LSB → MSB, `lt ← (1 − x)·y + same·lt`,
    /// `eq ← eq·same`, then the lanes combined `c_{l} = lt_l + eq_l·c_{l−1}`.
    fn p_recurrence_lt(a: &Digest, b: &Digest) -> bool {
        let (mut lt, mut eq) = ([0i64; 4], [0i64; 4]);
        for l in 0..4 {
            for z in 0..64 {
                let (x, y) = (((a[l] >> z) & 1) as i64, ((b[l] >> z) & 1) as i64);
                let same = 1 - x - y + 2 * x * y;
                let lt_bit = (1 - x) * y;
                if z == 0 {
                    (lt[l], eq[l]) = (lt_bit, same);
                } else {
                    lt[l] = lt_bit + same * lt[l];
                    eq[l] *= same;
                }
            }
        }
        let c1 = lt[1] + eq[1] * lt[0];
        let c2 = lt[2] + eq[2] * c1;
        let c3 = lt[3] + eq[3] * c2;
        assert!(c3 == 0 || c3 == 1, "the recurrence is boolean");
        c3 == 1
    }

    /// `y − x − 1` over 256 bits, as limbs (wrapping).
    fn sub_minus_one(x: &Digest, y: &Digest) -> Limbs {
        let (mut out, mut borrow) = ([0u64; 4], 1u64);
        for l in 0..4 {
            let (s1, o1) = y[l].overflowing_sub(x[l]);
            let (s2, o2) = s1.overflowing_sub(borrow);
            out[l] = s2;
            borrow = u64::from(o1 || o2);
        }
        limbs(&out)
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn random_digest(s: &mut u64) -> Digest {
        core::array::from_fn(|_| splitmix(s))
    }

    /// Set limb `j` of `d` to `v` (16-bit).
    fn with_limb(mut d: Digest, j: usize, v: u64) -> Digest {
        let sh = 16 * (j % 4);
        d[j / 4] = (d[j / 4] & !(0xffff << sh)) | (v << sh);
        d
    }

    /// The boundary values: 0, 1, 2, the two ends, the top bit's edge, and a
    /// single set bit / all-ones prefix at every limb boundary.
    fn boundary_values() -> Vec<Digest> {
        let mut v = vec![[0; 4], [1, 0, 0, 0], [2, 0, 0, 0], KEY_MAX, [u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]];
        v.push([0, 0, 0, 1 << 63]);
        v.push([u64::MAX, u64::MAX, u64::MAX, (1 << 63) - 1]);
        for j in 0..LIMBS {
            v.push(with_limb([0; 4], j, 1));
            v.push(with_limb([0; 4], j, 0xffff));
            v.push(with_limb(KEY_MAX, j, 0));
            v.push(with_limb(KEY_MAX, j, 0xfffe));
        }
        v.sort_by(|a, b| if key_lt(a, b) { core::cmp::Ordering::Less } else if a == b { core::cmp::Ordering::Equal } else { core::cmp::Ordering::Greater });
        v.dedup();
        v
    }

    /// Every pair the equivalence covers: the boundary cross product, then
    /// random pairs, each random `a` against `a` itself, its neighbours
    /// `a ± 1`, and `a` with one limb moved by ±1 at every position (the
    /// single-limb and top-limb differences).
    fn cases() -> Vec<(Digest, Digest)> {
        let bv = boundary_values();
        let mut out: Vec<(Digest, Digest)> = bv.iter().flat_map(|a| bv.iter().map(move |b| (*a, *b))).collect();
        let mut s = 0x5eed_f3c0_0a2a_u64;
        for _ in 0..256 {
            let a = random_digest(&mut s);
            let b = random_digest(&mut s);
            out.extend([(a, b), (b, a), (a, a)]);
            for (j, v) in limbs(&a).into_iter().enumerate() {
                let v = u64::from(v);
                if v < 0xffff {
                    out.push((a, with_limb(a, j, v + 1)));
                    out.push((with_limb(a, j, v + 1), a));
                }
                if v > 0 {
                    out.push((a, with_limb(a, j, v - 1)));
                }
            }
        }
        out
    }

    /// **Condition (b), natively.** On every case, the gadget's witness
    /// exists exactly when `key_lt` and shape P's recurrence say `x < y`, and
    /// the witness is `y − x − 1` as 16 limbs with in-range borrows.
    #[test]
    fn f3cmp_native_equivalence_with_key_lt_and_the_p_recurrence() {
        let cases = cases();
        assert!(cases.len() > 5_000, "{} cases", cases.len());
        let (mut lt, mut ge) = (0usize, 0usize);
        for (a, b) in &cases {
            let want = key_lt(a, b);
            assert_eq!(p_recurrence_lt(a, b), want, "P's recurrence disagrees with key_lt on {a:x?} < {b:x?}");
            let w = lt_raw(&limbs(a), &limbs(b));
            assert_eq!(w.d, sub_minus_one(a, b), "the difference limbs are y − x − 1");
            assert!(w.borrow.iter().all(|b| *b <= 1) && w.borrow[0] == 0);
            assert!(w.d.iter().all(|d| *d < 1 << LIMB_BITS));
            assert_eq!(lt_witness(&limbs(a), &limbs(b)).is_some(), want, "gadget disagrees on {a:x?} < {b:x?}");
            if want {
                lt += 1
            } else {
                ge += 1
            }
        }
        assert!(lt > 1_000 && ge > 1_000, "both verdicts exercised: {lt} / {ge}");
    }

    /// The ends (ruling (c)'s sentinels and the strict `−1`): `0 < K` holds
    /// for every `K > 0` and fails at `K = 0`; `K < MAX` holds for every
    /// `K < MAX` and fails at `K = MAX`; equal keys never compare. On the
    /// genesis leaf `(0, MAX)` the two instances refuse exactly the two
    /// sentinels.
    #[test]
    fn f3cmp_ends() {
        let z = limbs(&[0; 4]);
        let m = limbs(&KEY_MAX);
        let one = limbs(&[1, 0, 0, 0]);
        let m1 = limbs(&[u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]);
        assert!(lt_witness(&z, &one).is_some() && lt_witness(&z, &m).is_some());
        assert!(lt_witness(&m1, &m).is_some());
        for v in [z, one, m1, m] {
            assert!(lt_witness(&v, &v).is_none(), "strict");
        }
        assert!(lt_witness(&m, &z).is_none());
        // The equal-key raw witness is all-borrow: D = −1 = 2^256 − 1 with
        // the final borrow set — exactly what the AIR's constant b_16 = 0 refuses.
        let w = lt_raw(&m1, &m1);
        assert_eq!((w.d, w.borrow[LIMBS]), ([0xffff; LIMBS], 1));
        let bracket = |k: &Limbs| lt_witness(&z, k).is_some() && lt_witness(k, &m).is_some();
        assert!(!bracket(&z) && !bracket(&m) && bracket(&one) && bracket(&m1));
    }

    /// **Condition (b), in the AIR.** Every case as one row of the bound test
    /// AIR, with the honest generator's witness (`lt_raw`): a `x < y` row
    /// has no violation, a `x ≥ y` row is refused at `Limb(15)` **and only
    /// there** (the final borrow the AIR holds at 0). A trace of the `x < y`
    /// rows alone satisfies the AIR; an idle row with garbage inputs does too.
    #[test]
    fn f3cmp_air_is_sat_exactly_when_strictly_less() {
        let air = LtTestAir { bind_inputs: true };
        let cases = cases();
        let rows: Vec<Vec<Val>> = cases
            .iter()
            .map(|(a, b)| test_row(&air, &limbs(a), &limbs(b), &lt_raw(&limbs(a), &limbs(b)), true))
            .collect();
        let trace = test_trace(&air, rows);
        let limb15 = TestConstraint::Gadget(LtConstraint::Limb(LIMBS - 1)).index();
        for (r, (a, b)) in cases.iter().enumerate() {
            let got: Vec<usize> = violations_at(&air, &trace, &[], r).into_iter().map(|v| v.constraint).collect();
            let want = if key_lt(a, b) { vec![] } else { vec![limb15] };
            assert_eq!(got, want, "row {r}: {a:x?} < {b:x?}");
        }

        let mut rows: Vec<Vec<Val>> = cases
            .iter()
            .filter(|(a, b)| key_lt(a, b))
            .map(|(a, b)| test_row(&air, &limbs(a), &limbs(b), &lt_witness(&limbs(a), &limbs(b)).unwrap(), true))
            .collect();
        // Gating: an idle row comparing MAX < 0 with an all-zero witness.
        let idle = LtWitness { d: [0; LIMBS], borrow: [0; LIMBS + 1] };
        rows.push(test_row(&air, &limbs(&KEY_MAX), &limbs(&[0; 4]), &idle, false));
        if let Err(v) = satisfied(&air, &test_trace(&air, rows), &[]) {
            panic!("the strictly-less trace is refused at {v}");
        }
    }

    /// Replace a row's gadget cells: `f` edits the [`LT_WIDTH`] cells.
    fn tamper(row: &mut [Val], f: impl FnOnce(&mut [Val])) {
        f(&mut row[W_OFF..W_OFF + LT_WIDTH]);
    }

    fn only_violations(air: &LtTestAir, row: Vec<Val>) -> Vec<usize> {
        let trace = test_trace(air, vec![row]);
        violations_at(air, &trace, &[], 0).into_iter().map(|v| v.constraint).collect()
    }

    /// Negative 1 — a wide `d_j` smuggled through a non-boolean bit. For
    /// `0 < 2^16 + 5` (honest `d_0 = 4, d_1 = 1`) the witness moves one unit
    /// of limb 1 down into limb 0: `b_1 = 1`, `d_1 = 0`, `d_0 = 4 + 2^16` via
    /// `bit_{0,15} = 2`. Every limb equation holds; refused at `Bit(0,15)` alone.
    #[test]
    fn f3cmp_neg_nonboolean_bit_carries_a_wide_limb() {
        let air = LtTestAir { bind_inputs: true };
        let (x, y) = (limbs(&[0; 4]), limbs(&[(1 << 16) + 5, 0, 0, 0]));
        let honest = lt_witness(&x, &y).unwrap();
        assert_eq!((honest.d[0], honest.d[1]), (4, 1));
        let mut w = honest;
        (w.d[0], w.d[1], w.borrow[1]) = (4, 0, 1);
        let mut row = test_row(&air, &x, &y, &w, true);
        tamper(&mut row, |c| c[LtConstraint::Bit(0, 15).index()] = Val::TWO);
        assert_eq!(only_violations(&air, row), vec![LtConstraint::Bit(0, 15).index()]);
    }

    /// Negative 2 — a non-boolean borrow proves equal keys. With `x = y`,
    /// `b_1 = −m` and `d_1 = m` for `m = (p − 1)/2^16` satisfy limb 0
    /// (`−1 − 2^16·m = −p ≡ 0`) and limb 1, every `d_j` is 16 boolean bits:
    /// the duplicate-nullifier claim is refused at `Borrow(1)` and nowhere else.
    #[test]
    fn f3cmp_neg_nonboolean_borrow_proves_equal_keys() {
        let p = Val::ORDER_U32;
        assert_eq!((p - 1) % (1 << LIMB_BITS), 0, "p ≡ 1 mod 2^16");
        let m = (p - 1) >> LIMB_BITS;
        assert!(m < 1 << LIMB_BITS);
        let air = LtTestAir { bind_inputs: true };
        let mut s = 0x0dd_ba11_u64;
        for v in [[0; 4], KEY_MAX, random_digest(&mut s)] {
            let x = limbs(&v);
            let mut w = LtWitness { d: [0; LIMBS], borrow: [0; LIMBS + 1] };
            w.d[1] = m;
            let mut row = test_row(&air, &x, &x, &w, true);
            tamper(&mut row, |c| c[LtConstraint::Borrow(1).index()] = -Val::from_u32(m));
            assert_eq!(only_violations(&air, row), vec![LtConstraint::Borrow(1).index()], "{v:x?}");
        }
    }

    /// Negative 3 — a `d_j` that satisfies its limb equation mod p only. For
    /// `x = y` every borrow set and `d_0 … d_14 = 2^16 − 1` hold limbs 0–14;
    /// limb 15 then needs `d_15 = −1 = p − 1`, which exceeds 16 bits.
    /// (a) its honest 16-bit bits (the generator's `lt_raw`) are refused at
    /// `Limb(15)`; (b) the field value stuffed into one cell satisfies every
    /// limb equation and is refused at that cell's booleanity.
    #[test]
    fn f3cmp_neg_wraparound_limb() {
        let air = LtTestAir { bind_inputs: true };
        let v = limbs(&[7, 0, 0, 1 << 40]);
        let raw = lt_raw(&v, &v);
        assert_eq!(raw.borrow[LIMBS], 1);
        let row = test_row(&air, &v, &v, &raw, true);
        assert_eq!(only_violations(&air, row), vec![LtConstraint::Limb(LIMBS - 1).index()]);

        let mut w = raw;
        w.d[LIMBS - 1] = 0;
        let mut row = test_row(&air, &v, &v, &w, true);
        tamper(&mut row, |c| c[LtConstraint::Bit(LIMBS - 1, 0).index()] = Val::NEG_ONE);
        assert_eq!(only_violations(&air, row), vec![LtConstraint::Bit(LIMBS - 1, 0).index()]);
    }

    /// Negative 4 — condition 1, an input limb ≥ 2^16. `v < v` with `y_0`
    /// fed as `v_0 + 2^16`: the bare gadget **accepts** (`d_0 = 2^16 − 1`,
    /// all else 0) — the input range is its precondition, not its check.
    /// The bound AIR (inputs recomposed from 16 bits each, as the Keccak
    /// lane recomposes its limbs) refuses it at `y`'s limb-0 recomposition.
    #[test]
    fn f3cmp_input_range_is_a_precondition() {
        let v = limbs(&[0x1234_5678_9abc_def0, 3, 0, 1 << 20]);
        let mut y = v;
        y[0] += 1 << LIMB_BITS;
        let w = lt_witness(&v, &y).expect("the out-of-range limb makes v < v");
        assert_eq!(w.d[0], 0xffff);

        let bare = LtTestAir { bind_inputs: false };
        assert_eq!(only_violations(&bare, test_row(&bare, &v, &y, &w, true)), Vec::<usize>::new());
        let bound = LtTestAir { bind_inputs: true };
        assert_eq!(only_violations(&bound, test_row(&bound, &v, &y, &w, true)), vec![TestConstraint::InLimb(1, 0).index()]);
    }

    /// The gadget's shape, read off p3's symbolic evaluation: 271 columns,
    /// 287 constraints, degree 2 ungated and 3 under the test AIR's
    /// degree-2 gate.
    #[test]
    fn f3cmp_width_constraints_and_degree() {
        assert_eq!((LT_WIDTH, LT_CONSTRAINTS), (271, 287));
        for bind in [false, true] {
            let air = LtTestAir { bind_inputs: bind };
            let n = get_symbolic_constraints::<Val, _>(&air, AirLayout::from_air::<Val>(&air)).len();
            let want = LT_CONSTRAINTS + 2 + if bind { 2 * IN_BITS + 2 * LIMBS } else { 0 };
            assert_eq!(n, want, "bind = {bind}");
            assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 3);
        }
        // The named indices tile the emission order with no gap.
        assert_eq!(TestConstraint::Gadget(LtConstraint::Limb(LIMBS - 1)).index() + 1, TestConstraint::Gate(0).index());
        assert_eq!(TestConstraint::Gate(1).index() + 1, TestConstraint::InBit(0, 0, 0).index());
        assert_eq!(TestConstraint::InBit(1, LIMBS - 1, LIMB_BITS - 1).index() + 1, TestConstraint::InLimb(0, 0).index());
        assert_eq!(TestConstraint::InLimb(1, LIMBS - 1).index() + 1, LT_CONSTRAINTS + 2 + 2 * IN_BITS + 2 * LIMBS);
    }
}
