//! Lab #767 F3-2a — the state-transition leaf's 256-bit **strict**
//! comparator: `x < y` as a 16-limb subtract-with-borrow.
//!
//! Shape P's comparator (`qlab_air::l2p`, bit-serial over a perm's 64
//! boundary rows) does not fit the wide lane, where a perm is 24 rows (the
//! #767 ruling's condition (b) asks for this rewrite). Here one row carries
//! the whole comparison:
//!
//! ```text
//!   D = y − x − 1,   limb j (j = 0 … 15, limb 0 least significant):
//!   y_j − x_j − [j = 0] − b_j + 2^16 · b_{j+1} = d_j,   d_j = Σ_i 2^i · bit_{j,i}
//!   b_0 = 0 and b_16 = 0 are constants, not columns.
//! ```
//!
//! **Columns: [`LT_WIDTH`] = 256 bits + 15 borrows = 271.** Constraints
//! ([`LtConstraint`] names each): 256 bit booleanities, 15 borrow
//! booleanities (both ungated, degree 2 — an idle row is all zeros), 16 limb
//! equations gated by the caller's selector (degree 1 × gate; ≤ 3 under a
//! degree-≤ 2 gate).
//!
//! **Why it is sound — the three conditions of the 2a ruling:**
//!
//! 1. **Every input limb is 16-bit — a precondition, discharged by the
//!    caller.** The gadget does not range-check `x` or `y`, and must not be
//!    fed a free field element: `f3cmp_input_range_is_a_precondition` shows
//!    the bare gadget accepting `v < v` through one out-of-range limb. On
//!    the wide lane the inputs are Keccak preimage limbs, which p3-keccak-air
//!    0.6.1 range-binds: every `A′` and `C` entry is asserted boolean
//!    (`air.rs:86`, `:113`), `C′` is their `xor3` (`:81–93`), each `A` limb
//!    is the 16-bit recomposition of `xor3(A′, C, C′)` (`:95–125`, "this has
//!    the side effect of also range checking the limbs of A"), the preimage
//!    equals `A` on a perm's first row (`:50–59`) and is held across its
//!    rounds (`:61–70`). The key `K` the leaf compares is such a limb (it is
//!    absorbed by the digest and hashed into the new leaf); the leaf AIR
//!    (F3-2b) binds its register to those limbs.
//! 2. **Borrows are boolean and every `d_j` is exactly 16 boolean columns,
//!    so nothing wraps.** Every term of a limb equation is an integer in
//!    `(−2^17 − 2, 2^17 + 2)`, far inside `p ≈ 2^31`, so the equation holds
//!    over the field iff it holds over the integers. Summing
//!    `2^{16j} · (limb j)` telescopes the borrows: `y − x − 1 = D`, with
//!    `0 ≤ D < 2^256`.
//! 3. **The ends.** The `−1` at `j = 0` makes the comparison strict (`x = y`
//!    gives `D = −1`, which no witness represents), and the final borrow is
//!    the constant 0 (`D ≥ 0`). The leaf's two comparisons are two
//!    instances of this gadget on **separate** columns: `lo < K` is
//!    `lt(lo, K)`, and its mirror `K < hi` is `lt(K, hi)` — no borrow column
//!    is shared.
//!
//! Conversely an honest `x < y` always has a witness ([`lt_witness`]), and
//! it is unique (the representation of `D` is). Condition (b)'s evidence is
//! qlab-bench's `f3::cmp` tests: native equivalence with `key_lt` **and**
//! shape P's recurrence on boundaries plus random pairs, a test AIR
//! (`LtTestAir`, kept there since it is test-only) run through p3's `check_constraints` row loop on the same cases, and the
//! malicious-witness negatives, each refused at its named constraint.
// The leaf AIR (F3-2b) is the gadget's non-test consumer.
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use qlab_consensus::Val;

use crate::hash::Digest;

/// 16-bit limbs of a 256-bit value.
pub const LIMBS: usize = 16;
pub const LIMB_BITS: usize = 16;
/// `b_1 … b_15` (`b_0`, `b_16` are the constant 0).
pub const BORROWS: usize = LIMBS - 1;
/// The gadget's columns: `d`'s bits, then the borrows.
pub const LT_WIDTH: usize = LIMBS * LIMB_BITS + BORROWS;
/// The gadget's constraints, in [`LtConstraint::index`] order.
pub const LT_CONSTRAINTS: usize = LIMBS * LIMB_BITS + BORROWS + LIMBS;

/// A 256-bit value as 16 limbs, limb 0 least significant. A `u32` so that a
/// test can feed an out-of-range limb; the gadget's precondition is `< 2^16`.
pub type Limbs = [u32; LIMBS];

/// A key's limbs in [`qlab_air::l2p::key_lt`] order (lane 3 most
/// significant; within a lane, the Keccak preimage's limb order, low first).
pub fn limbs(d: &Digest) -> Limbs {
    core::array::from_fn(|j| ((d[j / 4] >> (16 * (j % 4))) & 0xffff) as u32)
}

/// One comparison's witness: the difference limbs and the borrows
/// `b_0 … b_16` (`b_0 = 0` always; `b_16` is the final borrow, which the AIR
/// holds at the constant 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LtWitness {
    pub d: Limbs,
    pub borrow: [u32; LIMBS + 1],
}

/// The subtraction `y − x − 1` limb by limb, whatever its sign: for `x ≥ y`
/// the final borrow is 1 and the AIR refuses the row at `Limb(15)`.
pub fn lt_raw(x: &Limbs, y: &Limbs) -> LtWitness {
    let mut w = LtWitness { d: [0; LIMBS], borrow: [0; LIMBS + 1] };
    for j in 0..LIMBS {
        let t = i64::from(y[j]) - i64::from(x[j]) - i64::from(j == 0) - i64::from(w.borrow[j]);
        if t < 0 {
            w.d[j] = (t + (1 << LIMB_BITS)) as u32;
            w.borrow[j + 1] = 1;
        } else {
            w.d[j] = t as u32;
        }
    }
    w
}

/// The witness of `x < y`, or `None` when `x ≥ y`.
pub fn lt_witness(x: &Limbs, y: &Limbs) -> Option<LtWitness> {
    let w = lt_raw(x, y);
    (w.borrow[LIMBS] == 0).then_some(w)
}

/// Write `w` into the gadget's [`LT_WIDTH`] cells.
pub fn fill(cells: &mut [Val], w: &LtWitness) {
    assert_eq!(cells.len(), LT_WIDTH);
    for j in 0..LIMBS {
        for i in 0..LIMB_BITS {
            cells[LIMB_BITS * j + i] = Val::from_u32((w.d[j] >> i) & 1);
        }
    }
    for j in 1..LIMBS {
        cells[LIMBS * LIMB_BITS + j - 1] = Val::from_u32(w.borrow[j]);
    }
}

/// The gadget's constraints by name, for negatives that claim "refused here".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LtConstraint {
    /// `bit_{j,i}` is boolean.
    Bit(usize, usize),
    /// `b_j` is boolean, `j ∈ 1..=15`.
    Borrow(usize),
    /// Limb `j`'s equation.
    Limb(usize),
}

impl LtConstraint {
    /// The constraint's position in [`eval_lt`]'s emission order.
    pub const fn index(self) -> usize {
        match self {
            Self::Bit(j, i) => LIMB_BITS * j + i,
            Self::Borrow(j) => LIMBS * LIMB_BITS + j - 1,
            Self::Limb(j) => LIMBS * LIMB_BITS + BORROWS + j,
        }
    }
}

/// Assert `x < y` where `gate` is 1; `w` is the gadget's [`LT_WIDTH`] cells.
/// Every limb of `x` and `y` must be range-bound to 16 bits by the caller
/// (module doc, condition 1).
pub fn eval_lt<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    gate: AB::Expr,
    x: &[AB::Expr; LIMBS],
    y: &[AB::Expr; LIMBS],
    w: &[AB::Var],
) {
    assert_eq!(w.len(), LT_WIDTH);
    for c in w {
        builder.assert_bool(*c);
    }
    let borrow = |j: usize| -> AB::Expr {
        if j == 0 || j == LIMBS {
            AB::Expr::ZERO
        } else {
            w[LIMBS * LIMB_BITS + j - 1].into()
        }
    };
    let radix = Val::from_u32(1 << LIMB_BITS);
    for j in 0..LIMBS {
        let d = (0..LIMB_BITS)
            .rev()
            .fold(AB::Expr::ZERO, |acc, i| acc.double() + w[LIMB_BITS * j + i].into());
        let strict = if j == 0 { AB::Expr::ONE } else { AB::Expr::ZERO };
        builder.assert_zero(
            gate.clone() * (y[j].clone() - x[j].clone() - strict - borrow(j) + borrow(j + 1) * radix - d),
        );
    }
}
