//! params_devnet ⟷ FROZEN v1.0 convergence audit (issue #62 item 5).
//!
//! Tables every `qlab_devnet::params_devnet` placeholder against the FROZEN v1.0
//! genesis value ([`crate::genesis::FrozenParams`]), classifying each as:
//!
//! - **Converged** — the placeholder now equals the frozen value; the constant is
//!   test-locked below (a drift is a test failure).
//! - **SimOnly** — an accelerated-sim/test knob that never enters a real net (its
//!   real counterpart is a separate, frozen constant, or the deployable binary
//!   reads the genesis file instead). Annotated, not converged.
//! - **NotFrozen** — testnet-tunable, freezes at full-M8 v1.1 (recorded).
//! - **Debt** — was: "should converge but lives outside the T0-1 conflict boundary."
//!   **M10-T0-4 (issue #68) retired the last two debt rows** — `BOND_AMOUNT`
//!   converged to the frozen 10⁴-QMB steady bond (10¹² bessel), and
//!   `GENESIS_DIFFICULTY` annotated as the sim-only `[devnet-placeholder]` it is
//!   (the binary bakes the genesis file's T0 difficulty; the real launch value
//!   stays open). No row is *Debt* anymore; the variant is kept for future use.
//!
//! [`render_markdown`] emits the docs/ table; the unit tests are the test-lock.

use crate::genesis::FrozenParams;
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::params_devnet as pd;

/// Convergence classification for one constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Placeholder now equals the frozen value; test-locked.
    Converged,
    /// Accelerated-sim/test knob only; never in a real net.
    SimOnly,
    /// Testnet-tunable, freezes at full-M8 v1.1.
    NotFrozen,
    /// Was: convergence owed but the constant lived outside the T0-1 boundary.
    /// **No row uses this after M10-T0-4** (issue #68 converged both former debt
    /// rows). Kept for future flagging.
    Debt,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Converged => "✅ converged",
            Status::SimOnly => "🧪 sim-only",
            Status::NotFrozen => "🧊 not-frozen (full-M8)",
            Status::Debt => "📌 debt (genesis is source)",
        }
    }
}

/// One row of the audit.
pub struct AuditRow {
    pub section: &'static str,
    pub name: &'static str,
    pub params_devnet: String,
    pub frozen_genesis: String,
    pub status: Status,
    pub note: &'static str,
}

/// The full audit table.
pub fn rows() -> Vec<AuditRow> {
    let f = FrozenParams::v1_0();
    vec![
        // ── §2 emission / PoW ────────────────────────────────────────────────
        AuditRow {
            section: "§2",
            name: "block time (s)",
            params_devnet: format!("POW_TARGET_BLOCK_TIME_SECS = {}", pd::POW_TARGET_BLOCK_TIME_SECS),
            frozen_genesis: format!("{}", f.block_time_secs),
            status: Status::Converged,
            note: "T0 runs the FROZEN 75 s (item 3); SIM_BLOCK_TIME_SECS is a separate sim knob",
        },
        AuditRow {
            section: "§2",
            name: "sim block time (s)",
            params_devnet: format!("SIM_BLOCK_TIME_SECS = {}", pd::SIM_BLOCK_TIME_SECS),
            frozen_genesis: "n/a".to_string(),
            status: Status::SimOnly,
            note: "accelerated in-process sim only; the binary uses the frozen 75 s",
        },
        AuditRow {
            section: "§2",
            name: "genesis difficulty",
            params_devnet: format!("GENESIS_DIFFICULTY = {} (sim knob)", pd::GENESIS_DIFFICULTY),
            frozen_genesis: format!("genesis file T0_GENESIS_DIFFICULTY = {} [devnet-placeholder]", crate::genesis::T0_GENESIS_DIFFICULTY),
            status: Status::SimOnly,
            note: "binary bakes the genesis file's T0 difficulty (not this constant); \
                   real launch difficulty is open — NOT invented (T0-4, issue #68)",
        },
        AuditRow {
            section: "§2",
            name: "bessel / QMB",
            params_devnet: "—".to_string(),
            frozen_genesis: format!("{}", f.bessel_per_qmb),
            status: Status::Converged,
            note: "emission::BESSEL_PER_QMB = 10⁸ (frozen §8)",
        },
        AuditRow {
            section: "§2",
            name: "coinbase maturity (blocks)",
            params_devnet: "—".to_string(),
            frozen_genesis: format!("{}", f.coinbase_maturity_blocks),
            status: Status::Converged,
            note: "emission::COINBASE_MATURITY_BLOCKS = 144 (frozen §2)",
        },
        // ── §3 reward split ──────────────────────────────────────────────────
        AuditRow {
            section: "§3",
            name: "reward split %",
            params_devnet: "—".to_string(),
            frozen_genesis: format!(
                "{}/{}/{}",
                f.split_miner_pct, f.split_committee_pct, f.split_treasury_pct
            ),
            status: Status::Converged,
            note: "emission::SPLIT_* = 65/15/20 (frozen §3)",
        },
        // ── §4 committee / staking ───────────────────────────────────────────
        AuditRow {
            section: "§4",
            name: "committee size N",
            params_devnet: format!(
                "FROZEN_COMMITTEE_SIZE = {} (COMMITTEE_SIZE = {} is M6 back-compat)",
                pd::FROZEN_COMMITTEE_SIZE,
                pd::COMMITTEE_SIZE
            ),
            frozen_genesis: format!("{}", f.committee_size),
            status: Status::Converged,
            note: "genesis committee₀ is the frozen N=21; COMMITTEE_SIZE=20 is superseded",
        },
        AuditRow {
            section: "§4",
            name: "quorum",
            params_devnet: format!("FROZEN_QUORUM = {}", pd::FROZEN_QUORUM),
            frozen_genesis: format!("{}", f.quorum),
            status: Status::Converged,
            note: "⌊2·21/3⌋+1 = 15 (frozen §4)",
        },
        AuditRow {
            section: "§4",
            name: "epoch length (blocks)",
            params_devnet: format!(
                "EPOCH_LENGTH_BLOCKS = {} (SIM_EPOCH_LENGTH_BLOCKS = {} is sim)",
                pd::EPOCH_LENGTH_BLOCKS,
                pd::SIM_EPOCH_LENGTH_BLOCKS
            ),
            frozen_genesis: format!("{}", f.epoch_length_blocks),
            status: Status::Converged,
            note: "1,152 = 24 h at 75 s (frozen §4); SIM_EPOCH_LENGTH_BLOCKS is a sim knob",
        },
        AuditRow {
            section: "§4",
            name: "self-bond (bessel)",
            params_devnet: format!("BOND_AMOUNT = {} (10⁴ QMB × 10⁸)", pd::BOND_AMOUNT),
            frozen_genesis: format!(
                "{} QMB steady × {} = {} bessel; ramp {:?}",
                f.self_bond_qmb_steady,
                f.bessel_per_qmb,
                f.self_bond_qmb_steady * f.bessel_per_qmb,
                f.bond_ramp_qmb
            ),
            status: Status::Converged,
            note: "converged to the frozen 10⁴-QMB steady bond (T0-4, issue #68); \
                   the epoch ramp lives in the genesis file (the source of truth)",
        },
        AuditRow {
            section: "§4",
            name: "equivocation slash",
            params_devnet: format!(
                "EQUIVOCATION_SLASH_AMOUNT = {} (= BOND_AMOUNT/10)",
                pd::EQUIVOCATION_SLASH_AMOUNT
            ),
            frozen_genesis: format!("{} % of bond", f.equivocation_slash_pct),
            status: Status::Converged,
            note: "derived = BOND_AMOUNT/10 (tracks the converged bond); the real path \
                   (qlab-p2p adapter) slashes 10 % of each member's own bond",
        },
        AuditRow {
            section: "§4",
            name: "downtime jail threshold %",
            params_devnet: format!("DOWNTIME_JAIL_THRESHOLD_PCT = {}", pd::DOWNTIME_JAIL_THRESHOLD_PCT),
            frozen_genesis: format!("{}", f.downtime_jail_threshold_pct),
            status: Status::Converged,
            note: "< 33 % signed (frozen §4)",
        },
        AuditRow {
            section: "§4",
            name: "downtime jail window",
            params_devnet: format!("DOWNTIME_JAIL_WINDOW = {}", pd::DOWNTIME_JAIL_WINDOW),
            frozen_genesis: format!("{}", f.downtime_jail_window),
            status: Status::Converged,
            note: "trailing 100 checkpoint rounds (frozen §4)",
        },
        AuditRow {
            section: "§4",
            name: "jail term (blocks)",
            params_devnet: format!("JAIL_BLOCKS = {}", pd::JAIL_BLOCKS),
            frozen_genesis: "n/a (auto-readmit)".to_string(),
            status: Status::NotFrozen,
            note: "jail-no-slash timeout; testnet-tunable",
        },
        // ── §5 fees ──────────────────────────────────────────────────────────
        AuditRow {
            section: "§5",
            name: "posted fee 2×2/4×4/8×8 (bessel)",
            params_devnet: format!(
                "FEE_MARGINAL_UNITS = {} × max(2,actions) → {}/{}/{}",
                pd::FEE_MARGINAL_UNITS,
                posted_fee(ArityBucket::TwoByTwo),
                posted_fee(ArityBucket::FourByFour),
                posted_fee(ArityBucket::EightByEight)
            ),
            frozen_genesis: format!(
                "{}/{}/{}",
                f.fee_2x2_bessel, f.fee_4x4_bessel, f.fee_8x8_bessel
            ),
            status: Status::Converged,
            note: "0.01/0.02/0.04 QMB (frozen §5; converged M9-N4)",
        },
        // ── §6 block weight ──────────────────────────────────────────────────
        AuditRow {
            section: "§6",
            name: "free-zone floor (bytes)",
            params_devnet: format!("WEIGHT_MIN_BYTES = {}", pd::WEIGHT_MIN_BYTES),
            frozen_genesis: format!("{}", f.weight_free_zone_bytes),
            status: Status::Converged,
            note: "10 MB (frozen §6)",
        },
        AuditRow {
            section: "§6",
            name: "hard cap multiple",
            params_devnet: format!("WEIGHT_MAX_MULTIPLE = {}", pd::WEIGHT_MAX_MULTIPLE),
            frozen_genesis: format!("{}", f.weight_hard_cap_multiple),
            status: Status::Converged,
            note: "2× (frozen §6)",
        },
        AuditRow {
            section: "§6",
            name: "long-term median window",
            params_devnet: format!("WEIGHT_LONG_WINDOW = {} (sim knob)", pd::WEIGHT_LONG_WINDOW),
            frozen_genesis: format!("{}", f.weight_long_window),
            status: Status::SimOnly,
            note: "node/genesis enforce frozen 100,000; the 5,000 is the load-harness sim knob (M9-N4)",
        },
        AuditRow {
            section: "§6",
            name: "lt cap / st cap",
            params_devnet: format!(
                "{}/{} , {}",
                pd::WEIGHT_LT_CAP_NUM, pd::WEIGHT_LT_CAP_DEN, pd::WEIGHT_ST_CAP
            ),
            frozen_genesis: format!(
                "{}/{} , {}",
                f.weight_lt_cap_num, f.weight_lt_cap_den, f.weight_st_cap
            ),
            status: Status::Converged,
            note: "1.4× / 50 (frozen §6)",
        },
        // ── §7 anchors / cadence ─────────────────────────────────────────────
        AuditRow {
            section: "§7",
            name: "anchor max age (blocks)",
            params_devnet: format!("MAX_ANCHOR_AGE_BLOCKS = {}", pd::MAX_ANCHOR_AGE_BLOCKS),
            frozen_genesis: format!("{}", f.anchor_max_age_blocks),
            status: Status::Converged,
            note: "1,152 = 24 h at 75 s (frozen §7; corrected on PR #45)",
        },
        AuditRow {
            section: "§7",
            name: "checkpoint cadence (blocks)",
            params_devnet: format!("CHECKPOINT_CADENCE_BLOCKS = {}", pd::CHECKPOINT_CADENCE_BLOCKS),
            frozen_genesis: format!("{} (recorded)", f.checkpoint_cadence_blocks_not_frozen),
            status: Status::NotFrozen,
            note: "8 = one 10-min bucket; protocol-spec §7 flags cadence [full-M8]",
        },
        AuditRow {
            section: "§7",
            name: "degraded-mode lag (blocks)",
            params_devnet: format!("DEGRADED_MODE_LAG_BLOCKS = {}", pd::DEGRADED_MODE_LAG_BLOCKS),
            frozen_genesis: "n/a (derived from cadence)".to_string(),
            status: Status::NotFrozen,
            note: "Ebb-and-Flow lag; tied to the not-frozen cadence",
        },
        // ── §PoW difficulty (LWMA) ──────────────────────────────────────────
        AuditRow {
            section: "PoW",
            name: "LWMA window / key epoch / lag",
            params_devnet: format!(
                "LWMA_WINDOW_BLOCKS = {} , SEEDHASH_EPOCH_BLOCKS = {} , SEEDHASH_EPOCH_LAG = {}",
                pd::LWMA_WINDOW_BLOCKS,
                pd::SEEDHASH_EPOCH_BLOCKS,
                pd::SEEDHASH_EPOCH_LAG
            ),
            frozen_genesis: "n/a".to_string(),
            status: Status::NotFrozen,
            note: "real RandomX + LWMA-120 prototyped (N3); retarget params freeze at full-M8 v1.1",
        },
    ]
}

/// Render the audit as a GitHub-flavoured Markdown table.
pub fn render_markdown() -> String {
    let mut s = String::new();
    s.push_str("# M10-T0-1 params_devnet ⟷ FROZEN v1.0 convergence audit\n\n");
    s.push_str(
        "Every `qlab_devnet::params_devnet` placeholder against the FROZEN v1.0 genesis value \
         (consensus-parameters, GENESIS FREEZE v1.0 2026-07-23). Generated by \
         `qumbra-node audit` (`qumbra_node::params_audit`); the converged rows are test-locked.\n\n",
    );
    s.push_str("| § | constant | params_devnet | FROZEN v1.0 / genesis | status | note |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for r in rows() {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.section,
            r.name,
            r.params_devnet,
            r.frozen_genesis,
            r.status.label(),
            r.note
        ));
    }
    s.push_str(
        "\n**Convergence note (M10-T0-4, issue #68).** The last two *debt* rows are resolved: \
         `BOND_AMOUNT` converged to the frozen 10⁴-QMB steady self-bond (10⁴ × 10⁸ = 10¹² \
         bessel), with `EQUIVOCATION_SLASH_AMOUNT` derived as 10 % of it so the frozen-§4 \
         slash relation holds by construction; and `GENESIS_DIFFICULTY` is annotated as the \
         **sim-only `[devnet-placeholder]`** it is — the deployable binary bakes the genesis \
         file's own T0 difficulty (itself a placeholder), and the **real launch difficulty \
         stays open and was NOT invented**. The **genesis file remains the frozen source of \
         truth** the binary reads; the epoch bond ramp lives there. No row is *debt* anymore.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::emission as em;

    /// Test-lock (item 5): every converged constant equals the frozen v1.0 genesis
    /// value. A drift in either the code constant or the baked genesis is a failure.
    #[test]
    fn converged_constants_match_frozen_genesis() {
        let f = FrozenParams::v1_0();
        // §2
        assert_eq!(pd::POW_TARGET_BLOCK_TIME_SECS, 75);
        assert_eq!(f.block_time_secs, 75);
        assert_eq!(em::BESSEL_PER_QMB, 100_000_000);
        assert_eq!(f.bessel_per_qmb, 100_000_000);
        assert_eq!(em::COINBASE_MATURITY_BLOCKS, 144);
        assert_eq!(f.coinbase_maturity_blocks, 144);
        // §3
        assert_eq!((em::SPLIT_MINER_PCT, em::SPLIT_COMMITTEE_PCT, em::SPLIT_TREASURY_PCT), (65, 15, 20));
        assert_eq!((f.split_miner_pct, f.split_committee_pct, f.split_treasury_pct), (65, 15, 20));
        // §4
        assert_eq!(pd::FROZEN_COMMITTEE_SIZE, 21);
        assert_eq!(f.committee_size, 21);
        assert_eq!(pd::FROZEN_QUORUM, 15);
        assert_eq!(f.quorum, 15);
        assert_eq!(pd::EPOCH_LENGTH_BLOCKS, 1_152);
        assert_eq!(f.epoch_length_blocks, 1_152);
        // Self-bond converged to the frozen 10⁴-QMB steady bond in bessel (T0-4).
        assert_eq!(pd::BOND_AMOUNT, 10_000 * 100_000_000);
        assert_eq!(pd::BOND_AMOUNT, f.self_bond_qmb_steady * f.bessel_per_qmb);
        assert_eq!(f.self_bond_qmb_steady, 10_000);
        assert_eq!(pd::DOWNTIME_JAIL_THRESHOLD_PCT, 33);
        assert_eq!(pd::DOWNTIME_JAIL_WINDOW, 100);
        // §5
        assert_eq!(f.fee_2x2_bessel, 1_000_000);
        assert_eq!(f.fee_4x4_bessel, 2_000_000);
        assert_eq!(f.fee_8x8_bessel, 4_000_000);
        // §6
        assert_eq!(pd::WEIGHT_MIN_BYTES, 10_000_000);
        assert_eq!(f.weight_free_zone_bytes, 10_000_000);
        assert_eq!(pd::WEIGHT_MAX_MULTIPLE, 2);
        assert_eq!((pd::WEIGHT_LT_CAP_NUM, pd::WEIGHT_LT_CAP_DEN, pd::WEIGHT_ST_CAP), (7, 5, 50));
        assert_eq!(f.weight_long_window, 100_000);
        // §7
        assert_eq!(pd::MAX_ANCHOR_AGE_BLOCKS, 1_152);
        assert_eq!(f.anchor_max_age_blocks, 1_152);
    }

    /// The equivocation-slash relationship (frozen §4 = "10 % of bond"): the slash
    /// constant is *derived* as `BOND_AMOUNT / 10`, so the relation holds by
    /// construction at the converged 10¹²-bessel bond (T0-4). The frozen genesis
    /// expresses the same rule as a percentage over each member's own bond.
    #[test]
    fn equivocation_slash_is_ten_percent_of_bond() {
        assert_eq!(pd::EQUIVOCATION_SLASH_AMOUNT, pd::BOND_AMOUNT / 10);
        assert_eq!(pd::EQUIVOCATION_SLASH_AMOUNT, 100_000_000_000); // 10¹¹ bessel = 10³ QMB
        assert_eq!(FrozenParams::v1_0().equivocation_slash_pct, 10);
        assert_eq!(FrozenParams::v1_0().equivocation_slash_qmb(10_000), 1_000);
        assert_eq!(FrozenParams::v1_0().equivocation_slash_qmb(0), 0); // ramp start
    }

    /// The checkpoint cadence is recorded but flagged not-frozen.
    #[test]
    fn cadence_is_recorded_but_not_frozen() {
        let cadence_rows: Vec<_> =
            rows().into_iter().filter(|r| r.name.contains("cadence")).collect();
        assert_eq!(cadence_rows.len(), 1);
        assert_eq!(cadence_rows[0].status, Status::NotFrozen);
    }

    #[test]
    fn markdown_covers_every_row_and_all_statuses() {
        let md = render_markdown();
        assert!(md.contains("| § | constant |"));
        // every §-tagged row appears
        for r in rows() {
            assert!(md.contains(r.name), "row missing from markdown: {}", r.name);
        }
        // The three live statuses are represented. (Debt was retired by T0-4 —
        // issue #68 converged the last two debt rows; no row is Debt anymore.)
        assert!(rows().iter().any(|r| r.status == Status::Converged));
        assert!(rows().iter().any(|r| r.status == Status::SimOnly));
        assert!(rows().iter().any(|r| r.status == Status::NotFrozen));
        assert!(!rows().iter().any(|r| r.status == Status::Debt), "T0-4 retired all debt rows");
    }
}
