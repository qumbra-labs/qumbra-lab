//! Coinbase emission — the normative integer form (protocol-spec §6, frozen §2).
//!
//! Qumbra's block subsidy is defined as the **integer difference of a rounded
//! closed-form cumulative supply**, not as a per-block reward formula. This is
//! deliberate: the closed form `S(h)` is the supply-audit anchor (tokenomics §1
//! job 4 — the only consensus-transparent value flow in a shielded pool), and
//! defining the per-block coinbase as a *difference of the rounded cumulative*
//! makes the sum telescope back to the cumulative **exactly**, with no drift:
//!
//! ```text
//!   S(h)          = r0·(1−(1−d)^h)/d          for h ≤ h_t
//!                 = S(h_t) + tail·(h − h_t)    for h > h_t   (Monero-class floor)
//!   S_atomic(h)   = round(S(h) · 10⁸)          bessel  (1 QMB = 10⁸ bessel, frozen §8)
//!   coinbase(h)   = S_atomic(h+1) − S_atomic(h)                    (protocol-spec §6)
//!   ⇒  Σ_{i<h} coinbase(i) = S_atomic(h)   exactly  (telescoping, test-locked)
//! ```
//!
//! The FROZEN B2 constants (consensus-parameters §2): `r0 = 50 QMB`,
//! `d = 8.237e-7` (per-block decay), `tail = 1.22441 QMB/block`; `h_t` = the
//! first height where the decay component drops to the tail. The closed form and
//! `S(h)` come straight from [`qlab_econ::Model`] (the emission simulator that
//! produced candidate B2, PR #36) — this module does **not** re-derive `d`/`tail`
//! from targets (which could round differently); it pins the frozen constants
//! directly, so `qlab-node` and the design's audit anchor evaluate the *same*
//! `S(h)`.
//!
//! Per-block the reward is split **65 % miners / 15 % committee / 20 % treasury**
//! (frozen §3), applied to `coinbase(h)`; fees are paid to miners on top, never
//! burned (tokenomics §6). Coinbase outputs mature after **144 blocks** (frozen
//! §2) — enforced by the mempool ([`crate::mempool`]).
//!
//! # 🔴 The schedule has TWO regimes now, and the boundary is what separates them
//! (lab #299 + #303)
//!
//! The `f64` evaluation below is **platform-dependent**: `1 − exp(h·ln(1−d))`
//! cancels ~12 bits, so a last-ulp `exp` difference between two C libraries
//! becomes a whole bessel — measured twelve times in the first 4,816 blocks of the
//! live chain (#303). A validity rule over a platform-dependent function forks a
//! mixed-platform net, and #299's rule is exactly such a rule.
//!
//! So, from [`RULE_BOUNDARY_HEIGHT`] + 1, the canonical schedule is the
//! **exact-decimal** one ([`qlab_devnet::emission_exact`]), and [`coinbase`] /
//! [`s_atomic`] switch to it there. At and below the boundary they keep evaluating
//! the historical `f64` schedule, because history is grandfathered **as recorded**
//! — the epoch-1 −4114 block and every glibc-vs-exact ±1 included (#303 ruling
//! clause 2).
//!
//! The two names that say which regime you are asking about, when it matters:
//! [`coinbase_pre_boundary`] / [`s_atomic_pre_boundary`] are the historical `f64`
//! schedule, and `emission_exact::coinbase_exact` / `s_atomic_exact` are the
//! canonical one. [`coinbase`] and [`s_atomic`] are the **canonical, boundary-aware**
//! functions and are what every consensus caller should use — assembly, validation,
//! accrual and attestation all get the right regime for free, which is why the
//! switch lives in these two bodies rather than at ~30 call sites.
//!
//! **Telescoping survives the boundary**, which is the property the whole audit
//! anchor rests on: `Σ_{i<h} coinbase(i) == s_atomic(h)` for every `h`, including
//! `h` straddling the boundary. It survives because `s_atomic` above the boundary
//! is the cumulative *at* the boundary plus the exact walk from there — not a
//! second closed form. Test-locked.

use qlab_devnet::forms::GenesisForm;
use qlab_econ::model::{Family, Model};

pub use qlab_devnet::emission_exact::{
    coinbase_exact, s_atomic_exact, RULE_BOUNDARY_HEIGHT, TAIL_ACTIVATION_HEIGHT, TAIL_BESSEL,
};

/// Atomic subunits per coin: **1 QMB = 10⁸ bessel** (frozen §8).
pub const BESSEL_PER_QMB: u64 = 100_000_000;

/// Initial block reward `r0` in QMB (frozen §2, B2 — decided 2026-07-22).
pub const R0_QMB: f64 = 50.0;

/// Per-block geometric decay `d` (frozen §2, B2 — derived from {r0, 2-year
/// half-life, 75 s blocks}, pinned as a frozen constant here).
pub const DECAY_D: f64 = 8.237e-7;

/// Perpetual tail floor in QMB/block (frozen §2, B2 — the 0.87 %-activation tail).
pub const TAIL_QMB: f64 = 1.22441;

/// Coinbase maturity delay in blocks (frozen §2 — 144 = 3.0 h at 75 s, ⅛ epoch;
/// covers the PR #46 worst measured reorg depth 118 with margin).
pub const COINBASE_MATURITY_BLOCKS: u64 = 144;

/// Reward split numerators over 100 (frozen §3): 65 % miners / 15 % committee /
/// 20 % treasury.
pub const SPLIT_MINER_PCT: u64 = 65;
pub const SPLIT_COMMITTEE_PCT: u64 = 15;
pub const SPLIT_TREASURY_PCT: u64 = 20;

/// The frozen B2 emission curve — the exact `S(h)` the supply attestation uses.
/// Pins the frozen constants directly (no target re-derivation).
fn frozen_curve() -> Model {
    Model {
        family: Family::MoneroClass,
        r0: R0_QMB,
        d: DECAY_D,
        tail: TAIL_QMB,
        // Block time only scales the sim's calendar framing; it does not enter
        // `supply(h)` (a pure function of height). Pinned at the frozen 75 s.
        block_time_s: 75.0,
    }
}

/// The **historical** cumulative supply at height `h` in bessel — the `f64`
/// closed form the live chain was mined and attested under, up to and including
/// [`RULE_BOUNDARY_HEIGHT`].
///
/// 🔴 **Platform-dependent, and that is why it is named** (#303). Calling this
/// above the boundary is a bug: use [`s_atomic`] (canonical) or
/// [`s_atomic_exact`] (explicitly exact). It stays public for exactly two honest
/// callers — the grandfathered accounting below the boundary, and the pins
/// generator that computes the activation literals on a glibc host.
pub fn s_atomic_pre_boundary(h: u64) -> u64 {
    let coins = frozen_curve().supply(h as f64);
    // round-half-away-from-zero on a non-negative value; `S(h) ≥ 0` always.
    (coins * BESSEL_PER_QMB as f64).round() as u64
}

/// The **historical** block subsidy at height `h`: the `f64`
/// `S_atomic(h+1) − S_atomic(h)`. See [`s_atomic_pre_boundary`] for why this is
/// named rather than default.
pub fn coinbase_pre_boundary(h: u64) -> u64 {
    // S_atomic is monotone, so this never underflows; saturating_sub is a belt-
    // and-braces guard against f64 rounding jitter.
    s_atomic_pre_boundary(h + 1).saturating_sub(s_atomic_pre_boundary(h))
}

/// **The pinned cumulative supply at the boundary** — `S_atomic(B+1)`, i.e. every
/// bessel the historical schedule issued through block `RULE_BOUNDARY_HEIGHT`.
///
/// # Why this is a pin and not a computation (ruling clause 3)
///
/// Above the boundary, [`s_atomic`] is *this value* plus the exact walk. If it
/// were recomputed from the `f64` closed form instead, then two nodes on different
/// C libraries would disagree about the cumulative supply of every post-boundary
/// height — the fork the exact schedule exists to prevent, reintroduced through
/// the back door of the audit anchor. Pinned, no node above the boundary evaluates
/// `f64` at all.
///
/// # 🔴 T-ops step at activation — this is the one number that must come from a
/// glibc host
///
/// `None` means "not yet pinned", and the fallback is
/// `s_atomic_pre_boundary(RULE_BOUNDARY_HEIGHT + 1)` — the current behaviour
/// exactly, so merging this is not a change on the live glibc fleet. It becomes a
/// change on a non-glibc node, which is the point.
///
/// Produce it on a Linux/glibc host with:
/// `qumbra-node emission-pins` — it prints the literal to paste here. Deliberately
/// **not** derived from a data dir: it is a pure function of the frozen constants,
/// so the pin can be reproduced by anyone with the binary and checked against the
/// chain's attested rows independently.
pub const PINNED_S_ATOMIC_AT_BOUNDARY: Option<u64> = Some(43051624039164);

/// **The pinned committee accrual at the boundary** — `Σ_{h≤B} 15 % share`, the
/// same argument as [`PINNED_S_ATOMIC_AT_BOUNDARY`] applied to the accrual ledger
/// (the census's restart-accrual point, ruling clause 3). `None` ⇒ walk the
/// historical schedule, which is today's behaviour. Produced by the same
/// `qumbra-node emission-pins`.
pub const PINNED_COMMITTEE_ACCRUAL_AT_BOUNDARY: Option<u64> = Some(6457743601807);

/// `S_atomic(RULE_BOUNDARY_HEIGHT + 1)` — the pin if it has been supplied, the
/// historical walk otherwise.
pub fn s_atomic_at_boundary() -> u64 {
    match PINNED_S_ATOMIC_AT_BOUNDARY {
        Some(pinned) => pinned,
        None => s_atomic_pre_boundary(RULE_BOUNDARY_HEIGHT + 1),
    }
}

/// **Canonical cumulative supply at height `h`, in bessel** (protocol-spec §6).
///
/// At and below `RULE_BOUNDARY_HEIGHT + 1` this is the historical `f64` closed
/// form — the value the chain was attested under, grandfathered as recorded.
/// Above it, the cumulative at the boundary plus the **exact** walk from there, so
/// `Σ coinbase` still telescopes to it exactly across the boundary.
///
/// Monotone non-decreasing, which is what makes every [`coinbase`] non-negative.
pub fn s_atomic(h: u64) -> u64 {
    if h <= RULE_BOUNDARY_HEIGHT + 1 {
        s_atomic_pre_boundary(h)
    } else {
        // `s_atomic_exact` is monotone, so the difference never underflows.
        s_atomic_at_boundary() + (s_atomic_exact(h) - s_atomic_exact(RULE_BOUNDARY_HEIGHT + 1))
    }
}

/// **The canonical block subsidy at height `h`, in bessel** — what a block at that
/// height must commit as `body.coinbase_total()` (#299), and what assembly must pay.
///
/// `h ≤ RULE_BOUNDARY_HEIGHT` ⇒ the historical `f64` difference (the last block
/// under the old schedule is the boundary itself). `h > RULE_BOUNDARY_HEIGHT` ⇒
/// [`coinbase_exact`].
pub fn coinbase(h: u64) -> u64 {
    if h > RULE_BOUNDARY_HEIGHT {
        coinbase_exact(h)
    } else {
        coinbase_pre_boundary(h)
    }
}

/// **The form-aware block subsidy** (lab #520): the schedule *this net* mints.
///
/// Consensus already dispatches on [`GenesisForm`] — v4 is boundary-grandfathered
/// ([`coinbase`]), v5 is exact at every height ([`coinbase_exact`]). The auditor
/// and the assembler must use the same fork, from the same loaded genesis, or a
/// v5 chain whose money is correct reads DIVERGENT against the float endpoints.
///
/// Height 0 is still `coinbase_exact(0) = 5×10⁹` / `coinbase(0) = 5×10⁹`; genesis
/// is exempted by the callers (it commits 0), not by this function.
pub fn coinbase_for(form: GenesisForm, h: u64) -> u64 {
    match form {
        GenesisForm::V4 => coinbase(h),
        GenesisForm::V5 => coinbase_exact(h),
        // No emission on the L2 (lab #706 P9): nothing is minted per block.
        GenesisForm::Annulet => 0,
    }
}

/// The 65/15/20 division of a block's coinbase (frozen §3). Committee and
/// treasury take floored shares; the miner absorbs the rounding remainder (so
/// the three parts sum to `total` exactly — no bessel is minted or lost).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardSplit {
    /// Miner share (65 % + rounding remainder). The block-assembly miner also
    /// earns the block's fees on top of this (see [`crate::mempool`]).
    pub miner: u64,
    /// Finality-committee share (15 %).
    pub committee: u64,
    /// Consensus-native treasury share (20 %).
    pub treasury: u64,
}

impl RewardSplit {
    /// Split `total` bessel 65/15/20; miner absorbs the remainder.
    pub fn of(total: u64) -> Self {
        let t = total as u128;
        let committee = (t * SPLIT_COMMITTEE_PCT as u128 / 100) as u64;
        let treasury = (t * SPLIT_TREASURY_PCT as u128 / 100) as u64;
        let miner = total - committee - treasury;
        Self { miner, committee, treasury }
    }

    /// The three parts summed — always equal to the `total` passed to [`of`].
    pub fn total(&self) -> u64 {
        self.miner + self.committee + self.treasury
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_coinbase_is_r0() {
        // S_atomic(0) = 0; S_atomic(1) = r0 (one block emitted). So coinbase(0)
        // is exactly the initial reward: 50 QMB = 5×10⁹ bessel (frozen §2/§8).
        assert_eq!(s_atomic(0), 0);
        assert_eq!(s_atomic(1), 50 * BESSEL_PER_QMB);
        assert_eq!(coinbase(0), 50 * BESSEL_PER_QMB);
        assert_eq!(coinbase(0), 5_000_000_000);
        // The exact schedule carries its own 10⁸ scaling (it is part of the
        // definition it evaluates). Two copies of a FROZEN constant is how drift
        // starts, so they are pinned to each other rather than to a literal twice.
        assert_eq!(BESSEL_PER_QMB, qlab_devnet::emission_exact::BESSEL_PER_QMB);
        // Likewise the tail: `TAIL_QMB` in coins here, `TAIL_BESSEL` in bessel there.
        assert_eq!(TAIL_BESSEL, (TAIL_QMB * BESSEL_PER_QMB as f64).round() as u64);
    }

    /// **lab #520:** the form-aware wrapper is the same fork consensus uses —
    /// v4 is [`coinbase`], v5 is [`coinbase_exact`] even below the v4 boundary.
    #[test]
    fn coinbase_for_dispatches_on_form_and_v5_is_exact_below_the_v4_boundary() {
        assert_eq!(coinbase_for(GenesisForm::V4, 1), coinbase(1));
        assert_eq!(coinbase_for(GenesisForm::V5, 1), coinbase_exact(1));
        let b = RULE_BOUNDARY_HEIGHT;
        assert_eq!(coinbase_for(GenesisForm::V4, b), coinbase_pre_boundary(b));
        assert_eq!(coinbase_for(GenesisForm::V5, b), coinbase_exact(b));
        assert_eq!(
            coinbase_for(GenesisForm::V4, b + 1),
            coinbase_exact(b + 1),
            "above the boundary both forms are exact"
        );
        assert_eq!(coinbase_for(GenesisForm::V5, b + 1), coinbase_exact(b + 1));
        // No emission on the L2 (lab #706 P9), at any height.
        for h in [0u64, 1, b, b + 1, 4_600_000] {
            assert_eq!(coinbase_for(GenesisForm::Annulet, h), 0);
        }
    }

    /// **The boundary seam** (#299 + #303): the last `f64` block is the boundary
    /// itself, and the first exact block is the one above it. Stated as a property
    /// of the two named regimes so it cannot be satisfied by accident.
    #[test]
    fn the_boundary_is_the_last_f64_block_and_the_next_is_exact() {
        let b = RULE_BOUNDARY_HEIGHT;
        assert_eq!(coinbase(b), coinbase_pre_boundary(b), "B is still f64");
        assert_eq!(coinbase(b - 1), coinbase_pre_boundary(b - 1));
        assert_eq!(coinbase(b + 1), coinbase_exact(b + 1), "B+1 is exact");
        assert_eq!(coinbase(b + 100), coinbase_exact(b + 100));
        // The cumulative switches one height later, because `s_atomic(h)` counts
        // coins through block `h-1`: `s_atomic(B+1)` is still entirely historical.
        assert_eq!(s_atomic(b + 1), s_atomic_pre_boundary(b + 1));
        assert_eq!(
            s_atomic(b + 2),
            s_atomic_at_boundary() + coinbase_exact(b + 1)
        );
    }

    /// Above the boundary, no `f64` value can influence the answer **except**
    /// through the single cumulative offset — which is what the pin replaces. The
    /// differences of post-boundary heights are pure exact arithmetic.
    #[test]
    fn post_boundary_differences_are_pure_exact_arithmetic() {
        let b = RULE_BOUNDARY_HEIGHT;
        for (lo, hi) in [(b + 2, b + 3), (b + 2, b + 1_000), (b + 500, b + 20_000)] {
            assert_eq!(
                s_atomic(hi) - s_atomic(lo),
                s_atomic_exact(hi) - s_atomic_exact(lo),
                "the f64 offset must cancel between two post-boundary heights"
            );
        }
    }

    /// **Activated 2026-08-10 at the 18,000 boundary; re-activated 2026-08-11 at
    /// the re-stamped 8,640 boundary** (lab #299/#303, [Larry's ruling](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)).
    /// The pin carries the glibc historical value at the boundary, generated by
    /// `qumbra-node emission-pins` on a `linux/aarch64` container built from this
    /// edited tree (header line confirmed `linux / aarch64`). It is a golden
    /// literal, not a recomputation: recomputing the `f64` walk here would
    /// reintroduce the platform dependence this whole change removes from
    /// consensus. On the glibc fleet the pinned value equals what the historical
    /// walk produces, so this is still a no-op there; it becomes the authority on
    /// a non-glibc node.
    #[test]
    fn the_boundary_pin_is_the_activated_glibc_value() {
        assert_eq!(PINNED_S_ATOMIC_AT_BOUNDARY, Some(43051624039164));
        assert_eq!(s_atomic_at_boundary(), 43051624039164);
    }

    #[test]
    fn coinbase_telescopes_to_s_atomic_exactly() {
        // Σ_{i<h} coinbase(i) == S_atomic(h) — the audit-anchor invariant that
        // makes the per-block subsidy a difference of the rounded cumulative.
        //
        // 🔴 The heights straddling `RULE_BOUNDARY_HEIGHT` are the load-bearing
        // ones: they prove the two regimes join without a seam. It holds because
        // `s_atomic` above the boundary is the cumulative AT the boundary plus the
        // exact walk, never a second closed form. (With the T-ops pin supplied on a
        // host whose own f64 disagrees with glibc's, the below-boundary sum is
        // grandfathered history and the identity holds against the pin above — see
        // `PINNED_S_ATOMIC_AT_BOUNDARY`.)
        for &h in &[
            0u64,
            1,
            2,
            10,
            100,
            1_000,
            10_000,
            RULE_BOUNDARY_HEIGHT - 1,
            RULE_BOUNDARY_HEIGHT,
            RULE_BOUNDARY_HEIGHT + 1,
            RULE_BOUNDARY_HEIGHT + 2,
            RULE_BOUNDARY_HEIGHT + 3,
            100_000,
        ] {
            let sum: u64 = (0..h).map(coinbase).sum();
            assert_eq!(sum, s_atomic(h), "telescoping broke at h={h}");
        }
    }

    #[test]
    fn coinbase_is_non_negative_and_positive_through_and_past_the_tail() {
        // Monotone S ⇒ coinbase ≥ 0 everywhere. And because MoneroClass floors
        // the reward at the tail, coinbase stays strictly positive forever —
        // check a spread of heights incl. around the tail activation (~4.5M).
        let ht = frozen_curve().tail_activation_height() as u64;
        for &h in &[0u64, 1, 1_000, 1_000_000, ht - 1, ht, ht + 1, ht + 1_000_000] {
            let c = coinbase(h);
            assert!(c > 0, "coinbase({h}) = {c} must be positive");
        }
        // Tail-era reward is exactly the floor: ~1.22441 QMB/block in bessel.
        let tail_bessel = (TAIL_QMB * BESSEL_PER_QMB as f64).round() as u64;
        let deep = coinbase(ht + 500_000);
        assert!(
            deep.abs_diff(tail_bessel) <= 1,
            "deep-tail coinbase {deep} ≈ tail floor {tail_bessel}"
        );
    }

    #[test]
    fn tail_activates_near_the_design_height() {
        // Design record (consensus-parameters §2 / econ sweep): tail activates
        // ~block 4,503,708 (year ~10.7). Confirm the frozen constants land there.
        let ht = frozen_curve().tail_activation_height() as u64;
        assert!(
            (4_400_000..4_600_000).contains(&ht),
            "tail activation {ht} near the design's 4,503,708"
        );
    }

    #[test]
    fn split_is_65_15_20_and_sums_exactly() {
        let s = RewardSplit::of(coinbase(0)); // 5×10⁹ bessel, divides cleanly
        assert_eq!(s.miner, 3_250_000_000); // 65 %
        assert_eq!(s.committee, 750_000_000); // 15 %
        assert_eq!(s.treasury, 1_000_000_000); // 20 %
        assert_eq!(s.total(), coinbase(0));

        // Remainder always goes to the miner; parts always sum to the total.
        for total in [0u64, 1, 2, 3, 7, 99, 100, 101, 1_222_441, u64::MAX / 2] {
            let s = RewardSplit::of(total);
            assert_eq!(s.total(), total, "split of {total} must sum exactly");
            assert_eq!(s.committee, (total as u128 * 15 / 100) as u64);
            assert_eq!(s.treasury, (total as u128 * 20 / 100) as u64);
        }
    }
}
