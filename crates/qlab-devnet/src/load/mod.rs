//! # Load-testing harness (issue #42)
//!
//! Measured basis for the three `[open]` consensus-parameter rows the appendix
//! defers to M6 devnet load-testing (consensus-parameters §6 block-weight penalty,
//! §2 coinbase maturity, §4 downtime jail threshold). This harness produces the
//! **data**; the DECISION stays design-side (consensus-parameters) — nothing here
//! is a proposal.
//!
//! Four scenario families, all deterministic (seeded [`rng::SplitMix64`], no
//! wall-clock / entropy inputs) so `run1` and `run2` reproduce byte-for-byte:
//!
//! 1. [`spam`] — bucket-mix floods at the decided fee floor, attacker budget swept
//!    as multiples of daily emission (the Rucknium native-anchor framing);
//!    chain-growth + weight-median response across candidate weight-constant sets.
//! 2. [`reorg`] — reorg-depth distribution under Ebb-and-Flow degraded mode
//!    (committee stalled) at 75-s blocks → data for the ~100-block coinbase-maturity
//!    proposal.
//! 3. [`jail`] — validator-downtime patterns over 1,152-block epochs; `(X%, Y-block)`
//!    jail-threshold grid; false-jail rate vs detection lag.
//!
//! ## Sim inputs — DECIDED design values (sourced), NOT placeholders
//!
//! Unlike `params_devnet` (open placeholders), the constants below are values the
//! consensus-parameters appendix has already DECIDED; they are sim *inputs*, cited
//! to their source, so the sweeps are anchored to the real economics. The *swept*
//! quantities (weight-governor constants, jail grid, maturity depth) remain the
//! `[open]` questions this harness informs.

pub mod jail;
pub mod reorg;
pub mod rng;
pub mod spam;

/// Block time, seconds — DECIDED B2 (consensus-parameters §2: 75 s, Zcash ZIP-208).
pub const BLOCK_TIME_SECS: u64 = 75;

/// Blocks per day at the decided block time: 86_400 / 75 = **1_152** — which is
/// also, not by accident, the decided epoch length (consensus-parameters §4).
pub const BLOCKS_PER_DAY: u64 = 86_400 / BLOCK_TIME_SECS;

/// Epoch length, blocks — DECIDED (consensus-parameters §4: 1_152 = 24 h at 75 s).
pub const EPOCH_BLOCKS: u64 = 1_152;

/// Initial block reward, QMB — DECIDED B2 (consensus-parameters §2: r0 = 50 QMB).
pub const R0_QMB: u64 = 50;

/// Launch daily emission, QMB/day = 1_152 × 50 = **57_600** (consensus-parameters
/// §5 cites exactly this figure). Emission decays (2-yr half-life) so this is the
/// strongest-defense era; the sweep also reports tail-era multiples.
pub const LAUNCH_DAILY_EMISSION_QMB: u64 = BLOCKS_PER_DAY * R0_QMB;

/// Decided posted fee floor per bucket, in QMB (consensus-parameters §5,
/// 0.01/0.02/0.04 QMB for 2×2 / 4×4 / 8×8). Expressed as bessel (1 QMB = 1e8
/// bessel, §8) so the sim uses integer atomic units end-to-end.
pub const BESSEL_PER_QMB: u64 = 100_000_000;
pub const FEE_2X2_BESSEL: u64 = 1_000_000; // 0.01 QMB
pub const FEE_4X4_BESSEL: u64 = 2_000_000; // 0.02 QMB
pub const FEE_8X8_BESSEL: u64 = 4_000_000; // 0.04 QMB

/// Per-transaction on-chain weight (bytes), by bucket. The 2×2 figure is the
/// **measured** M3 consensus proof at the decided config (136.4 KB fixed-width,
/// prototype-bench §10 / m6-devnet run docs) — 136 KiB here. Larger buckets are
/// hypothetical bigger circuits; STARK proof bytes grow *sublinearly* with trace
/// size (FRI), so a work-proportional (1:2:4) byte model is a deliberate **upper
/// bound** on their size — documented as an assumption in the run docs, and shown
/// there not to change the worst-case (2×2 maximizes bytes-per-fee).
pub const TX_2X2_BYTES: u64 = 136 * 1024; // 139_264
pub const TX_4X4_BYTES: u64 = 2 * TX_2X2_BYTES; // upper bound
pub const TX_8X8_BYTES: u64 = 4 * TX_2X2_BYTES; // upper bound

/// Per-tx public-surface / body overhead (bytes): anchor 32 + 2 nf × 32 + 2 cm ×
/// 32 + bucket 1 + fee 8 + proof-len 8 ≈ 177; rounded to 192. Negligible beside
/// the 136 KB proof but kept honest.
pub const TX_OVERHEAD_BYTES: u64 = 192;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_arithmetic_matches_the_appendix() {
        assert_eq!(BLOCKS_PER_DAY, 1_152);
        assert_eq!(BLOCKS_PER_DAY, EPOCH_BLOCKS, "a day == an epoch at 75 s");
        assert_eq!(LAUNCH_DAILY_EMISSION_QMB, 57_600); // consensus-parameters §5
    }

    #[test]
    fn fee_ratios_are_one_two_four() {
        assert_eq!(FEE_4X4_BESSEL, 2 * FEE_2X2_BESSEL);
        assert_eq!(FEE_8X8_BESSEL, 4 * FEE_2X2_BESSEL);
        assert_eq!(FEE_2X2_BESSEL, BESSEL_PER_QMB / 100); // 0.01 QMB
    }

    #[test]
    fn two_by_two_maximizes_bytes_per_fee_the_worst_case_spam_vehicle() {
        // bytes-per-fee (the linear forever-stream resource / QMB) is highest for
        // 2×2 even under the work-proportional byte upper bound — so a rational
        // byte-flooder uses 2×2, which the sweep takes as the worst case.
        let bpf = |bytes: u64, fee: u64| bytes as f64 / fee as f64;
        let b22 = bpf(TX_2X2_BYTES, FEE_2X2_BESSEL);
        let b44 = bpf(TX_4X4_BYTES, FEE_4X4_BESSEL);
        let b88 = bpf(TX_8X8_BYTES, FEE_8X8_BESSEL);
        assert!(b22 >= b44 && b22 >= b88, "2×2 must be the worst-case byte vehicle");
    }
}
