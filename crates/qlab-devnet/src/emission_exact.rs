//! **The canonical emission schedule: exact-decimal, integer-only** (lab #303's
//! ruling clause 1) — and the height at which it starts binding (lab #299).
//!
//! # Why this module exists
//!
//! The schedule that shipped is evaluated in `binary64` through `exp`/`ln`
//! (`qlab_node::emission`). Lab #303 measured that this is **platform-dependent**:
//! the `1 − exp(h·ln(1−d))` form cancels ~12 bits, so a last-ulp difference in
//! `exp` between two C libraries becomes a whole bessel in the answer — observed
//! twelve times in the first 4,816 blocks of the live chain, and 1,985 times over
//! the full curve. A validity rule that compares a block's committed coinbase
//! against a platform-dependent function **forks a mixed-platform net**, which is
//! exactly the net T1 invites.
//!
//! So the canonical schedule is redefined as the value the mathematics actually
//! has, evaluated in integers with a proven error bound:
//!
//! ```text
//!   q = 1 − d = 9999991763 / 10^10          (exact decimal, FROZEN §2 `d = 8.237e-7`)
//!   S_atomic(h) = round_half_up( 10^8 · 50 · (1 − q^h) / d )        h ≤ h_t
//!   S_atomic(h) = S_atomic(h_t) + 122_441_000 · (h − h_t)           h > h_t
//!   coinbase(h) = S_atomic(h+1) − S_atomic(h)  = 122_441_000 for h ≥ h_t
//! ```
//!
//! **No float appears anywhere below**, and no libm is reachable from it. That is
//! the property, and it is checked two ways: the module denies
//! `clippy::float_arithmetic`, and [`tests::the_module_source_contains_no_float`]
//! reads this file's own source and refuses a floating-point token in it. A lint
//! nobody runs in the acceptance suite is a comment; the source test is a check.
//!
//! # The rounding is exact, not "accurate enough"
//!
//! Two facts make `round_half_up` decidable in integers rather than approximated:
//!
//! 1. **There is exactly one exact tie in the whole domain, and it is `h = 2`.**
//!    A tie means `2·S_atomic(h)` is an odd integer, i.e.
//!    `8237 · 10^(10h) | 10^20 · (10^(10h) − Q^h)` with `Q = 9999991763`. Since
//!    `Q` is coprime to 10, `10^(10h) − Q^h` is **never** divisible by 10, so for
//!    `h ≥ 3` the factor `10^(10h−20)` cannot divide it and no tie is possible.
//!    `h = 0` gives 0 and `h = 1` gives `5·10^9`, both integers. At `h = 2` the
//!    algebra collapses: `1 − q² = (1−q)(1+q) = d(1+q)`, so
//!    `S_atomic(2) = 5·10^9 · (1 + q) = 9_999_995_881.5` — a tie, resolved
//!    **upward** by half-up to `9_999_995_882`. Test-locked below.
//! 2. **The computed value is a bounded over-estimate**, and the bound is
//!    `< 2^-49` bessel (derivation in [`q_pow`]). So the only way this module can
//!    disagree with the true `round_half_up` is a height whose exact value sits
//!    *within* `2^-49` of a half-integer without being a tie. The slow golden
//!    ([`tests::census_reference_stream_hash_and_tie_guard`]) sweeps the entire
//!    `0..=4_600_001` range and asserts that no such height exists — so the
//!    agreement is certified over the whole census range, not argued.
//!
//! The census (#303, gist `ea7c28516f43c38bdfc41523c211f558`) left 9,007 heights
//! `UNRESOLVED` behind a `10^-3`-bessel guard. **At `2^-49` that set is empty**:
//! the guard was blunt, not the mathematics ambiguous, exactly as the coordinator's
//! reply to the census argued.
//!
//! # The boundary
//!
//! [`RULE_BOUNDARY_HEIGHT`] is where this schedule starts binding. It is a
//! **halt height** in #74/#81's vocabulary — the last block under the old
//! schedule — so `accepts_height(RULE_BOUNDARY_HEIGHT)` is true and
//! `accepts_height(RULE_BOUNDARY_HEIGHT + 1)` is false for the armed release, and
//! the release that resumes past it carries a revision whose digest domain-
//! separates every block above it. Everything at or below the boundary is
//! grandfathered **as recorded**, including the epoch-1 −4114 block (#299) and
//! every glibc-vs-exact ±1 (#303).

#![deny(clippy::float_arithmetic)]

use crate::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// **The emission-rule boundary.** The last height mined and validated under the
/// `binary64` schedule; the exact schedule and the `body.coinbase` validity rule
/// both bind from `RULE_BOUNDARY_HEIGHT + 1`.
///
/// Stamped 2026-08-10 by the coordinator (task book
/// `docs/prompts/i299-emission-rule-builder-prompt.md` §*The boundary height,
/// stamped*) at **18,000**, then **re-stamped to 8,640 on 2026-08-11** by Larry's
/// ruling on [issue #299](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483):
/// the ten-day lead behind 18,000 existed to cover the activation work, that work
/// was discharged in ~10 hours on 2026-08-10, and what remained of the lead was
/// pure wait sitting directly on the T1 gate. Three properties are worth reading
/// off the new number, by the same criteria the original stamp used:
///
/// - **On the checkpoint-cadence grid** (`8_640 = 8 × 1_080`), asserted below at
///   compile time. `qumbra_node::release` refuses an off-grid halt height at
///   startup, because "the committee stops checkpointing at exactly that height"
///   is undefined off the grid — so the boundary would not be a *finalized*
///   boundary.
/// - **Deliberately not a committee rotation, and rotation-distant.**
///   `EPOCH_LENGTH_BLOCKS = 1_152` is FROZEN, so epoch 7 is `[8_064, 9_215]` and
///   the boundary sits 576 blocks inside it — 575 to the epoch's end, the
///   **exact midpoint**, the same criterion that placed 18,000 at
///   720-into-epoch-15. Landing an upgrade on a roster rotation puts two
///   transitions in one window and buys nothing.
/// - **An epoch-aligned boundary is impossible, and that is a finding.** An epoch
///   ends at `1152·N − 1`, always **odd**, while the grid rule demands a multiple
///   of 8. So *exactly one epoch straddles the boundary whatever height is
///   stamped* — here, epoch 7. `qlab_node::supply` handles the straddle
///   piecewise; see its module docs.
///
/// It is a **height, never a date**. (At the ~48 blk/h measured at the re-stamp
/// it arrives around 2026-08-12, which is lead time, not a deadline.)
pub const RULE_BOUNDARY_HEIGHT: u64 = 8_640;

// H2, the grid rule, as a compile-time refusal: an off-grid boundary cannot be
// built, not merely rejected at startup.
const _: () = assert!(RULE_BOUNDARY_HEIGHT % CHECKPOINT_CADENCE_BLOCKS == 0);
// Genesis is not an upgrade boundary, and a non-zero boundary is what makes the
// genesis exemption of the #299 validity rule *structural* rather than a
// special case: `height > RULE_BOUNDARY_HEIGHT` can never be true at height 0.
const _: () = assert!(RULE_BOUNDARY_HEIGHT > 0);

/// Atomic subunits per coin: **1 QMB = 10⁸ bessel** (FROZEN §8).
pub const BESSEL_PER_QMB: u64 = 100_000_000;

/// The first height at which the perpetual tail floor is the reward — the
/// **integer** activation height, `ceil(ln(tail/r0) / ln(q))`.
///
/// Not derived at runtime (that would need logarithms); pinned, and test-locked
/// against the defining inequality in exact integer arithmetic:
/// `r0·q^(h_t−1) > tail` and `r0·q^h_t ≤ tail`
/// ([`tests::tail_activation_height_satisfies_its_defining_inequality`]). The
/// census (#303) selects the same value from exact decimals and from both f64
/// implementations.
pub const TAIL_ACTIVATION_HEIGHT: u64 = 4_503_536;

/// The perpetual tail reward, **exactly** `1.22441 QMB` in bessel (FROZEN §2).
///
/// It is exactly constant above [`TAIL_ACTIVATION_HEIGHT`] for a reason worth
/// naming: `10^8 · tail = 122_441_000` is a whole number of bessel, so adding it
/// to the unrounded cumulative supply moves the rounded value by exactly the same
/// integer. The shipped f64 schedule does **not** have this property — #303
/// measured it dithering across `122_440_999 / …000 / …001` over the tail — and
/// clause 1 of the ruling adopts the fix as a consequence of the same stroke.
pub const TAIL_BESSEL: u64 = 122_441_000;

/// `S_atomic(TAIL_ACTIVATION_HEIGHT)` in bessel — the anchor the tail is measured
/// from, pinned so the tail path is O(1) and the value is auditable in the diff.
///
/// Test-locked against the geometric evaluation
/// ([`tests::the_tail_anchor_constant_is_the_geometric_value`]).
pub const S_ATOMIC_AT_TAIL_ACTIVATION: u64 = 5_921_523_645_798_773;

// --- the exact rational constants -------------------------------------------

/// `d`'s numerator over `10^10`: FROZEN `d = 8.237e-7` read as an exact decimal.
const D_NUM: u128 = 8_237;
/// The decimal denominator both `d` and `q` are read over.
const DECIMAL_DEN: u128 = 10_000_000_000;
/// `q = 1 − d = 9999991763 / 10^10`, exactly.
const Q_NUM: u128 = DECIMAL_DEN - D_NUM;

/// `10^8 · r0 · 10^10 = 5·10^19 = 2^19 · 5^20`, factored so the multiply fits a
/// `u64` and the power of two becomes a shift. `r0 = 50 QMB` (FROZEN §2).
const FIVE_POW_20: u64 = 95_367_431_640_625;

/// The fixed-point fraction width used for `q^h`. See [`q_pow`] for the bound.
const FRAC_BITS: u32 = 128;

/// `S_atomic(h) = 5^20 · (1 − q^h)·2^128 / (8237 · 2^SHIFT_BITS)` — the `2^19` of
/// `5·10^19 = 2^19 · 5^20` cancels 19 of the 128 fractional bits.
const SHIFT_BITS: u32 = FRAC_BITS - 19;

/// `q · 2^128`, truncated. Computed rather than written out, so the frozen
/// decimal is the only literal anyone has to check.
const Q_FIX: u128 = frac_shl_128(Q_NUM, DECIMAL_DEN);

/// `floor(a · 2^128 / b)` for `a < b`, in two 64-bit halves so nothing overflows.
const fn frac_shl_128(a: u128, b: u128) -> u128 {
    let hi = (a << 64) / b;
    let rem = (a << 64) % b;
    (hi << 64) | ((rem << 64) / b)
}

/// `floor(a · b / 2^128)` for `a, b < 2^128` whose product is `< 2^128 · 2^128`.
///
/// Schoolbook 64×64 limbs: with
/// `a·b = (hh + lh_hi + hl_hi)·2^128 + (lh_lo + hl_lo + ll_hi)·2^64 + ll_lo`,
/// the quotient by `2^128` is the first bracket plus the carry out of the second.
/// Both operands represent values in `[0,1)` here, so the result is `< 2^128` and
/// no addition can overflow.
const fn mul_frac(a: u128, b: u128) -> u128 {
    const LOW: u128 = u64::MAX as u128;
    let (a_lo, a_hi) = (a & LOW, a >> 64);
    let (b_lo, b_hi) = (b & LOW, b >> 64);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    let carry = (ll >> 64) + (lh & LOW) + (hl & LOW);
    hh + (lh >> 64) + (hl >> 64) + (carry >> 64)
}

/// `q^h · 2^128`, truncated — an **under**-estimate of `q^h`, by construction.
///
/// # The error bound (the "provably sufficient precision" of ruling clause 1)
///
/// Write a computed value as `true·2^128 − e` with `e ≥ 0` (every operation here
/// truncates, so the error is one-sided). [`Q_FIX`] has `e ≤ 1`. For a product,
/// `mul_frac` gives
/// `e_c ≤ a·e_b + b·e_a + 1 ≤ e_a + e_b + 1` because `a, b ∈ [0,1)`.
///
/// Left-to-right binary exponentiation over an `L`-bit exponent performs `L−1`
/// squarings, each optionally followed by one multiply by `q`, so the bound obeys
/// `e_{i+1} ≤ 2·e_i + 3` and therefore `e_L ≤ 2^L·(e_0 + 3) − 3 < 4·2^L`. Every
/// height in the schedule's domain is below `2^23`, so `e < 2^25` and the
/// absolute error in `q^h` is below `2^-103`.
///
/// One unit of `q^h` error moves `S_atomic` by `10^8·r0/d = 5·10^19/8237 < 2^53`
/// bessel, so the error in the returned bessel value is below `2^-50`, and with
/// the two truncations of the final division and shift added, below **`2^-49`** —
/// a hundred trillion times inside the half-bessel that decides the rounding.
///
/// Because the error is one-sided *downward* in `q^h`, it is one-sided *upward*
/// in `1 − q^h` and hence in `S_atomic`: the computed value is never below the
/// true one. That is what resolves the `h = 2` tie in the correct direction
/// (half-**up**) with no special case.
fn q_pow(h: u64) -> u128 {
    debug_assert!(h >= 1, "q^0 = 1 is not representable at this fraction width");
    let bits = u64::BITS - h.leading_zeros();
    let mut acc = Q_FIX;
    let mut i = bits - 1;
    while i > 0 {
        i -= 1;
        acc = mul_frac(acc, acc);
        if (h >> i) & 1 == 1 {
            acc = mul_frac(acc, Q_FIX);
        }
    }
    acc
}

/// A 256-bit unsigned integer as four little-endian 64-bit limbs. Only the three
/// operations the schedule needs are implemented; this is not a bignum library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct U256([u64; 4]);

impl U256 {
    /// `x · m`, for `x < 2^128` and `m < 2^64` — at most 192 bits.
    fn from_mul(x: u128, m: u64) -> Self {
        let mut limbs = [0u64; 4];
        let x_limbs = [x as u64, (x >> 64) as u64];
        let mut carry: u128 = 0;
        let mut i = 0;
        while i < 2 {
            let wide = x_limbs[i] as u128 * m as u128 + carry;
            limbs[i] = wide as u64;
            carry = wide >> 64;
            i += 1;
        }
        limbs[2] = carry as u64;
        limbs[3] = (carry >> 64) as u64;
        Self(limbs)
    }

    /// `floor(self / d)` by long division on 64-bit limbs.
    fn div_u64(self, d: u64) -> Self {
        let mut out = [0u64; 4];
        let mut rem: u128 = 0;
        let mut i = 4;
        while i > 0 {
            i -= 1;
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        Self(out)
    }

    /// `round_half_up(self / 2^bits)`, i.e. `(self + 2^(bits−1)) >> bits`, as a
    /// `u64`. Panics if the result does not fit — a supply above `2^64` bessel is
    /// unreachable in this schedule and would be a broken invariant, not a value.
    fn shr_round(self, bits: u32) -> u64 {
        debug_assert!(bits > 0 && bits < 192);
        let half = {
            let mut h = [0u64; 4];
            h[((bits - 1) / 64) as usize] = 1u64 << ((bits - 1) % 64);
            Self(h)
        };
        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        let mut i = 0;
        while i < 4 {
            let (a, c1) = self.0[i].overflowing_add(half.0[i]);
            let (b, c2) = a.overflowing_add(carry);
            sum[i] = b;
            carry = u64::from(c1) | u64::from(c2);
            i += 1;
        }
        assert_eq!(carry, 0, "emission: 256-bit overflow while rounding");
        // Shift right by `bits` and require the result to be a single limb.
        let limb = (bits / 64) as usize;
        let off = bits % 64;
        let mut words = [0u64; 4];
        let mut j = 0;
        while limb + j < 4 {
            let mut w = sum[limb + j] >> off;
            if off != 0 && limb + j + 1 < 4 {
                w |= sum[limb + j + 1] << (64 - off);
            }
            words[j] = w;
            j += 1;
        }
        assert!(
            words[1] == 0 && words[2] == 0 && words[3] == 0,
            "emission: S_atomic exceeded u64 — schedule invariant broken"
        );
        words[0]
    }
}

/// The geometric branch of the cumulative supply, in bessel — valid for
/// `h ≤ TAIL_ACTIVATION_HEIGHT`.
fn s_atomic_geometric(h: u64) -> u64 {
    if h == 0 {
        return 0;
    }
    let p = q_pow(h);
    debug_assert!(p > 0, "q^h never underflows the fraction width in this domain");
    // `2^128 − p` in one wrapping step: `p > 0`, so this is exact.
    let one_minus = 0u128.wrapping_sub(p);
    U256::from_mul(one_minus, FIVE_POW_20)
        .div_u64(D_NUM as u64)
        .shr_round(SHIFT_BITS)
}

/// **Cumulative supply at height `h`, exactly** — coins emitted through block
/// `h − 1`, in bessel, so `s_atomic_exact(0) = 0` (protocol-spec §6).
///
/// Monotone non-decreasing, which is what makes every [`coinbase_exact`]
/// non-negative.
pub fn s_atomic_exact(h: u64) -> u64 {
    if h <= TAIL_ACTIVATION_HEIGHT {
        s_atomic_geometric(h)
    } else {
        // Saturating rather than wrapping: the tail adds linearly forever, and
        // u64 bessel runs out around height 1.5×10^11 (≈ 350,000 years at 75 s).
        // A saturated value is a broken invariant either way; it must not wrap.
        S_ATOMIC_AT_TAIL_ACTIVATION
            .saturating_add(TAIL_BESSEL.saturating_mul(h - TAIL_ACTIVATION_HEIGHT))
    }
}

/// **The block subsidy at height `h`, exactly** — `S(h+1) − S(h)` in bessel, and
/// exactly [`TAIL_BESSEL`] from [`TAIL_ACTIVATION_HEIGHT`] on.
pub fn coinbase_exact(h: u64) -> u64 {
    if h >= TAIL_ACTIVATION_HEIGHT {
        TAIL_BESSEL
    } else {
        // Monotone S ⇒ never underflows; the difference is the definition.
        s_atomic_exact(h + 1) - s_atomic_exact(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 12 heights where glibc and Apple libm were **measured** to disagree by
    /// a bessel (#303), with the census's exact-decimal answer at each. Golden
    /// lock (b) of ruling clause 4: the exact value must equal the census's
    /// answer, **not** either f64's — both of which are below it by 23–335.
    const CROSS_LIBM_GOLDEN: &[(u64, u64)] = &[
        (260, 1_299_861_339_928),
        (389, 1_944_689_226_302),
        (625, 3_124_197_029_858),
        (955, 4_773_124_369_916),
        (1_436, 7_175_758_256_156),
        (1_772, 8_853_540_776_394),
        (1_824, 9_113_156_104_903),
        (1_922, 9_602_400_921_921),
        (2_149, 10_735_499_995_947),
        (3_367, 16_811_683_404_246),
        (3_765, 18_795_847_548_928),
        (3_821, 19_074_974_226_352),
    ];

    /// **Golden lock (b).** Twelve measured cross-libm divergence heights, twelve
    /// exact answers. This is the test that would have caught a "port the f64
    /// formula to fixed point and hope" implementation: at every one of these
    /// heights the two f64 answers differ from each other *and* both differ from
    /// the truth.
    #[test]
    fn the_twelve_cross_libm_heights_take_the_exact_value() {
        for &(h, want) in CROSS_LIBM_GOLDEN {
            assert_eq!(s_atomic_exact(h), want, "s_atomic_exact({h})");
        }
    }

    /// The published example from #303 stated in both directions: glibc says
    /// `1299861339905`, Apple says `1299861339904`, and the mathematics says
    /// neither.
    #[test]
    fn the_published_height_260_example_agrees_with_no_f64() {
        let exact = s_atomic_exact(260);
        assert_eq!(exact, 1_299_861_339_928);
        assert_ne!(exact, 1_299_861_339_905, "glibc");
        assert_ne!(exact, 1_299_861_339_904, "Apple libm");
    }

    /// **The only exact tie in the domain**, and the reason it rounds up.
    ///
    /// `1 − q² = d(1+q)`, so `S_atomic(2) = 5·10^9·(1+q)` exactly, and
    /// `5·10^9 · 1.9999991763 = 9_999_995_881.5`. Half-up takes 9_999_995_882.
    #[test]
    fn the_single_exact_tie_at_height_two_rounds_half_up() {
        // The tie restated in integers, with no reference to the implementation:
        // 2·S = 10^10 + Q = 19_999_991_763, odd ⇒ S ends in .5.
        let twice = DECIMAL_DEN + Q_NUM;
        assert_eq!(twice, 19_999_991_763);
        assert_eq!(twice % 2, 1, "an odd 2S is exactly what a tie means");
        assert_eq!(u128::from(s_atomic_exact(2)), (twice + 1) / 2);
        assert_eq!(s_atomic_exact(2), 9_999_995_882);
    }

    /// Genesis and the first block, where the schedule is checkable by hand:
    /// `S(0) = 0`, `S(1) = r0 = 50 QMB`, so `coinbase(0) = 5×10⁹ bessel`.
    #[test]
    fn genesis_and_first_block_are_exact_by_hand() {
        assert_eq!(s_atomic_exact(0), 0);
        assert_eq!(s_atomic_exact(1), 50 * BESSEL_PER_QMB);
        assert_eq!(coinbase_exact(0), 5_000_000_000);
    }

    /// The audit-anchor invariant, in the exact schedule: the per-block subsidy is
    /// a difference of the rounded cumulative, so it telescopes back **exactly**.
    #[test]
    fn coinbase_exact_telescopes_to_s_atomic_exact() {
        for &h in &[0u64, 1, 2, 3, 10, 100, 1_000, 10_000, 20_000, 100_000] {
            let sum: u64 = (0..h).map(coinbase_exact).sum();
            assert_eq!(sum, s_atomic_exact(h), "telescoping broke at h={h}");
        }
    }

    /// `S_atomic` is monotone non-decreasing, so every coinbase is non-negative —
    /// checked across the pre-tail curve and through the tail crossing.
    #[test]
    fn s_atomic_exact_is_monotone_and_every_coinbase_is_positive() {
        let mut prev = 0u64;
        for h in 0..5_000u64 {
            let s = s_atomic_exact(h);
            assert!(s >= prev, "S_atomic dropped at h={h}");
            prev = s;
            assert!(coinbase_exact(h) > 0, "coinbase_exact({h}) must be positive");
        }
        for h in [
            TAIL_ACTIVATION_HEIGHT - 2,
            TAIL_ACTIVATION_HEIGHT - 1,
            TAIL_ACTIVATION_HEIGHT,
            TAIL_ACTIVATION_HEIGHT + 1,
            TAIL_ACTIVATION_HEIGHT + 1_000_000,
        ] {
            assert!(s_atomic_exact(h + 1) > s_atomic_exact(h), "monotone at h={h}");
            assert!(coinbase_exact(h) > 0);
        }
    }

    /// **The tail is a constant, and the crossing is exact** (#303's tail-dither
    /// finding, fixed). The f64 schedule dithers 122_440_999 / …000 / …001 here;
    /// this one does not, at the activation height itself or a million blocks in.
    #[test]
    fn the_tail_reward_is_exactly_constant_across_the_crossing() {
        let ht = TAIL_ACTIVATION_HEIGHT;
        // Below the crossing the reward is still the geometric difference and is
        // strictly greater than the floor — that is what "the floor engages here"
        // means.
        assert!(coinbase_exact(ht - 1) > TAIL_BESSEL, "the floor has not engaged yet");
        for h in [ht, ht + 1, ht + 2, ht + 1_000, ht + 1_000_000] {
            assert_eq!(coinbase_exact(h), TAIL_BESSEL, "tail reward at h={h}");
        }
        // And the difference form agrees with the constant form at the crossing,
        // which is only true because 10^8·tail is a whole number of bessel.
        assert_eq!(s_atomic_exact(ht + 1) - s_atomic_exact(ht), TAIL_BESSEL);
        assert_eq!(
            s_atomic_exact(ht + 1_000) - s_atomic_exact(ht),
            TAIL_BESSEL * 1_000
        );
    }

    /// The pinned tail anchor is the geometric value at the activation height —
    /// so the O(1) tail path and the O(log h) geometric path cannot drift.
    #[test]
    fn the_tail_anchor_constant_is_the_geometric_value() {
        assert_eq!(
            S_ATOMIC_AT_TAIL_ACTIVATION,
            s_atomic_geometric(TAIL_ACTIVATION_HEIGHT)
        );
    }

    /// `h_t` is pinned, so pin it to its **definition**: the first integer height
    /// at which the decaying reward has fallen to the floor.
    /// `r0·q^h ≤ tail ⟺ q^h ≤ tail/r0 = 122441/5_000_000`, compared in fixed
    /// point with the same truncation the schedule uses.
    #[test]
    fn tail_activation_height_satisfies_its_defining_inequality() {
        let threshold = frac_shl_128(122_441, 5_000_000);
        assert!(
            q_pow(TAIL_ACTIVATION_HEIGHT) <= threshold,
            "the floor must have engaged at h_t"
        );
        assert!(
            q_pow(TAIL_ACTIVATION_HEIGHT - 1) > threshold,
            "h_t must be the FIRST such height"
        );
    }

    /// **The no-float guard, structurally.** `#![deny(clippy::float_arithmetic)]`
    /// at the top of this module is only enforced when clippy runs, and the
    /// acceptance bar is `cargo test`. So the module reads its own source and
    /// refuses a floating-point token in it — comments stripped, because the
    /// module docs necessarily *talk* about f64.
    #[test]
    fn the_module_source_contains_no_float() {
        let src = include_str!("emission_exact.rs");
        // Only the code above the test module is the consensus surface; the tests
        // are allowed to name f64 in prose but do not use it either.
        let code = src.split("#[cfg(test)]").next().expect("the module has code");
        for (n, line) in code.lines().enumerate() {
            let stripped = line.split("//").next().unwrap_or("");
            for token in ["f64", "f32", "libm", "as f", "0.0", "1.0"] {
                assert!(
                    !stripped.contains(token),
                    "line {} of emission_exact.rs reaches for `{token}`: {line}",
                    n + 1
                );
            }
        }
    }

    /// The boundary's stamped properties, asserted rather than commented.
    #[test]
    fn the_rule_boundary_is_grid_legal_and_mid_epoch() {
        use crate::params_devnet::EPOCH_LENGTH_BLOCKS;
        assert_eq!(RULE_BOUNDARY_HEIGHT, 8_640);
        assert_eq!(RULE_BOUNDARY_HEIGHT % CHECKPOINT_CADENCE_BLOCKS, 0, "H2 grid rule");
        // Not a rotation: the boundary is strictly inside epoch 7.
        let epoch = RULE_BOUNDARY_HEIGHT / EPOCH_LENGTH_BLOCKS;
        assert_eq!(epoch, 7);
        assert!(RULE_BOUNDARY_HEIGHT > epoch * EPOCH_LENGTH_BLOCKS);
        assert!(RULE_BOUNDARY_HEIGHT < (epoch + 1) * EPOCH_LENGTH_BLOCKS - 1);
        // And the finding: no legal halt height can ever be an epoch END, because
        // an epoch ends at 1152·N − 1, which is odd, while H2 demands a multiple
        // of 8. So a straddling epoch is structural, not an oversight.
        for n in 1..64u64 {
            let epoch_end = n * EPOCH_LENGTH_BLOCKS - 1;
            assert_eq!(epoch_end % 2, 1, "epoch ends are odd");
            assert_ne!(
                epoch_end % CHECKPOINT_CADENCE_BLOCKS,
                0,
                "an epoch end can never be on the cadence grid"
            );
        }
    }

    /// The hand-rolled SHA-256 above is only worth something if it is SHA-256.
    /// NIST's three canonical vectors, so golden lock (a) rests on a checked hash.
    #[test]
    fn the_local_sha256_matches_the_published_vectors() {
        assert_eq!(
            hex32(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex32(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex32(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// A cheap CI-cadence sample of the reference stream: 4,096 contiguous heights
    /// from genesis plus a stride sweep across the whole pre-tail curve and the
    /// tail, hashed. Companion to the slow full-range golden below — this one runs
    /// every suite, that one runs when the schedule is touched.
    #[test]
    fn sampled_reference_stream_hash() {
        let mut sample: Vec<u64> = (0..4_096u64).collect();
        sample.extend((0..2_000u64).map(|i| i * 2_301));
        sample.extend(CROSS_LIBM_GOLDEN.iter().map(|&(h, _)| h));
        sample.extend([
            RULE_BOUNDARY_HEIGHT,
            RULE_BOUNDARY_HEIGHT + 1,
            TAIL_ACTIVATION_HEIGHT - 1,
            TAIL_ACTIVATION_HEIGHT,
            TAIL_ACTIVATION_HEIGHT + 1,
            4_600_001,
        ]);
        let mut bytes = Vec::with_capacity(sample.len() * 8);
        for h in &sample {
            bytes.extend_from_slice(&s_atomic_exact(*h).to_le_bytes());
        }
        // Re-derived 2026-08-11: the sample vector includes RULE_BOUNDARY_HEIGHT and
        // RULE_BOUNDARY_HEIGHT + 1 by name, so the re-stamp from 18,000 to 8,640
        // (Larry's ruling: https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)
        // moved two of the sampled heights and hence this stream's hash, even though
        // the schedule function itself is untouched (see the unchanged full-range
        // golden in `census_reference_stream_hash_and_tie_guard` below).
        assert_eq!(
            hex32(&sha256(&bytes)),
            "60b0a40687664b3c894ba8d14ad86a706105655b9271bfcd56122476ae6ba44f",
            "sampled exact-schedule stream moved"
        );
    }

    /// **Golden lock (a) of ruling clause 4, plus the tie certificate.**
    ///
    /// Recomputes the census artifact's reference stream over its full range —
    /// `s_atomic(0..=4_600_001)`, little-endian u64, in order — and matches the
    /// SHA-256 the 80-digit and 120-digit decimal runs both produced. This is the
    /// one test that certifies the whole schedule rather than samples of it.
    ///
    /// It also discharges the rounding argument: for every height it asserts the
    /// computed value is not within the `2^-49` error bound of a half-integer,
    /// **except** the one proven tie at `h = 2`. Bound + this sweep ⇒ the module
    /// agrees with the true `round_half_up` at every height in the census range.
    /// The #303 census's 9,007 `UNRESOLVED` heights are resolved by the sharper
    /// guard, not by a choice.
    ///
    /// `#[ignore]` per the task book, which budgeted "minutes of CPU". **Measured:
    /// 0.57 s in release on the rig** (Apple M5 Max, AC) for the whole 4.6M-height
    /// sweep including the tie guard — the O(log h) fixed-point evaluation is
    /// cheap, and a future session may promote this out of `#[ignore]` on that
    /// evidence. Run it rig-locked:
    /// `scripts/rig run -- cargo test --release -p qlab-devnet -- --ignored census`
    ///
    /// **Reproduced 2026-08-10 by this baton**: hash equal, `near_ties == [2]`.
    #[test]
    #[ignore = "minutes of CPU: the full 4.6M-height census stream"]
    fn census_reference_stream_hash_and_tie_guard() {
        let mut hasher = Sha256::new();
        // Distance from a half-integer, in units of 2^-64, that the error bound
        // must not reach: 2^-49 is 2^15 of these.
        const GUARD: u64 = 1 << 15;
        let mut near_ties: Vec<u64> = Vec::new();
        for h in 0..=4_600_001u64 {
            let s = s_atomic_exact(h);
            hasher.update(&s.to_le_bytes());
            if h >= 1 && h <= TAIL_ACTIVATION_HEIGHT {
                // Recompute the unrounded value's fractional part in 64-bit
                // fixed point and measure its distance to 1/2.
                let frac = geometric_frac_q64(h);
                let half = 1u64 << 63;
                let dist = frac.abs_diff(half);
                if dist < GUARD {
                    near_ties.push(h);
                }
            }
        }
        assert_eq!(
            hex32(&hasher.finish()),
            "2e26f6ff674be57f5f997ce45bfa50b1ea9ad95351ad4f6c1d712a709d544a69",
            "the exact-decimal reference stream of the #303 census must reproduce"
        );
        assert_eq!(
            near_ties,
            vec![2],
            "the only height within the error bound of a half-integer must be the \
             proven tie at h=2; anything else is a STOP condition for #303"
        );
    }

    /// The unrounded `S_atomic(h)`'s fractional part in Q0.64 — test-only, used by
    /// the tie guard. Same pipeline as the schedule, stopped one shift earlier.
    fn geometric_frac_q64(h: u64) -> u64 {
        let one_minus = 0u128.wrapping_sub(q_pow(h));
        let w = U256::from_mul(one_minus, FIVE_POW_20).div_u64(D_NUM as u64);
        // `w / 2^SHIFT_BITS` is the value; its fractional part in Q0.64 is bits
        // `SHIFT_BITS-64 .. SHIFT_BITS`.
        let lo = SHIFT_BITS - 64;
        let limb = (lo / 64) as usize;
        let off = lo % 64;
        let mut v = w.0[limb] >> off;
        if off != 0 {
            v |= w.0[limb + 1] << (64 - off);
        }
        v
    }

    // --- a dependency-free SHA-256, so the golden needs no new dev-dependency --

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finish()
    }

    fn hex32(d: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in d {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    struct Sha256 {
        state: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        len: u64,
    }

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    impl Sha256 {
        fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0u8; 64],
                buf_len: 0,
                len: 0,
            }
        }

        fn update(&mut self, mut data: &[u8]) {
            self.len += data.len() as u64;
            while !data.is_empty() {
                let take = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len == 64 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
        }

        fn compress(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[4 * i],
                    block[4 * i + 1],
                    block[4 * i + 2],
                    block[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = self.state;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for i in 0..8 {
                self.state[i] = self.state[i].wrapping_add(v[i]);
            }
        }

        fn finish(mut self) -> [u8; 32] {
            let bit_len = self.len * 8;
            self.update(&[0x80]);
            while self.buf_len != 56 {
                self.update(&[0x00]);
            }
            self.update(&bit_len.to_be_bytes());
            let mut out = [0u8; 32];
            for i in 0..8 {
                out[4 * i..4 * i + 4].copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }
    }
}
