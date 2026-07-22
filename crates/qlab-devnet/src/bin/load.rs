//! Deterministic load-test runner (issue #42). Prints the four scenario sweeps
//! that back the `[open]` consensus-parameter rows. Reproducible byte-for-byte:
//! `cargo run --release -p qlab-devnet --bin load` twice gives identical output.
//!
//! The DECISION for each constant stays design-side (consensus-parameters); this
//! runner only produces the measured basis.

use qlab_devnet::load::jail::{false_jail_rate, run_grid, JailSimConfig};
use qlab_devnet::load::reorg::{
    natural_orphans, run_worst_over_seeds, GIVEUP_SWEEP, Q_SWEEP, STALL_24H_BLOCKS,
    STALL_30D_BLOCKS, STALL_6H_BLOCKS,
};
use qlab_devnet::load::spam::{
    candidate_sets, run_no_governor, run_scenario, Era, BUDGET_MULTS,
};
use qlab_devnet::load::{BLOCK_TIME_SECS, EPOCH_BLOCKS, LAUNCH_DAILY_EMISSION_QMB};

const SPAM_DAYS: u64 = 30;
/// Seeds folded (worst-depth) for a stable, conservative tail estimate.
const REORG_SEEDS: u64 = 24;

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn main() {
    println!("# qlab-devnet load-test sweeps (issue #42)\n");
    println!(
        "block time {}s · {} blocks/day (= epoch) · launch emission {} QMB/day\n",
        BLOCK_TIME_SECS, EPOCH_BLOCKS, LAUNCH_DAILY_EMISSION_QMB
    );

    spam_section();
    reorg_section();
    jail_section();
}

fn spam_section() {
    println!("## 1. Spam-flood: block-weight governor response (§6 penalty constants)\n");
    let sets = candidate_sets();

    // 1a/1b: default set across budgets, both eras.
    for era in [Era::Launch, Era::Tail] {
        println!(
            "### 1{} S0 devnet-default, {} era, {}-day sustained flood\n",
            if era == Era::Launch { "a" } else { "b" },
            era.name(),
            SPAM_DAYS
        );
        println!("| budget ×emission | chain growth MB/day | median growth ×start | final median MB | attacker cost %emission | bounded? |");
        println!("|---|---|---|---|---|---|");
        for &bm in &BUDGET_MULTS {
            let r = run_scenario(&sets[0], era, bm, SPAM_DAYS);
            println!(
                "| {:>4.1}× | {:>10.1} | {:>6.2} | {:>7.1} | {:>7.3} | {} |",
                bm,
                r.chain_growth_mb_per_day,
                r.growth_factor,
                mb(r.final_effective_median_bytes),
                r.attacker_cost_pct_emission,
                if r.governor_bounded { "yes" } else { "NO" }
            );
        }
        println!();
    }

    // 1c: all constant sets at a fixed heavy budget, launch.
    let bm = 5.0;
    println!("### 1c constant-set comparison @ {bm}×emission, launch, {SPAM_DAYS}-day flood\n");
    println!("| constant set | chain growth MB/day | median growth ×start | final median MB | cost %emission | bounded? |");
    println!("|---|---|---|---|---|---|");
    for cs in &sets {
        let r = run_scenario(cs, Era::Launch, bm, SPAM_DAYS);
        println!(
            "| {} | {:>10.1} | {:>6.2} | {:>7.1} | {:>7.3} | {} |",
            cs.label,
            r.chain_growth_mb_per_day,
            r.growth_factor,
            mb(r.final_effective_median_bytes),
            r.attacker_cost_pct_emission,
            if r.governor_bounded { "yes" } else { "NO" }
        );
    }
    println!();

    // 1d: governor-OFF baseline (what the governor buys).
    println!("### 1d governor-OFF baseline (no penalty, no cap) — launch\n");
    println!("| budget ×emission | chain growth MB/day |");
    println!("|---|---|");
    for &b in &BUDGET_MULTS {
        println!("| {:>4.1}× | {:>12.1} |", b, run_no_governor(Era::Launch, b));
    }
    println!();
}

/// Deepest reorg over all patience bands and all seeds — the attacker-optimized,
/// conservative bound a maturity depth must clear.
fn worst_depth(q: f64, blocks: u64) -> u64 {
    GIVEUP_SWEEP
        .iter()
        .map(|&g| run_worst_over_seeds(q, g, blocks, REORG_SEEDS).max_depth)
        .max()
        .unwrap()
}

fn reorg_section() {
    println!("## 2. Reorg-depth in degraded mode (§2 coinbase maturity)\n");
    println!(
        "Max reorg depth, worst over patience bands {:?} and {} seeds (conservative).\n",
        GIVEUP_SWEEP, REORG_SEEDS
    );
    println!("| adversary q | 6h stall | 24h stall | 30d stall (pathological) |");
    println!("|---|---|---|---|");
    for &q in &Q_SWEEP {
        println!(
            "| {:.2} | {} | {} | {} |",
            q,
            worst_depth(q, STALL_6H_BLOCKS),
            worst_depth(q, STALL_24H_BLOCKS),
            worst_depth(q, STALL_30D_BLOCKS),
        );
    }
    println!("\n> vs a ~100-block coinbase-maturity proposal (§2).\n");

    // Detail: reorg frequency + mean at 24h, giveup 20.
    println!("### 2 — detail: frequency + depth distribution (24h stall, giveup 20)\n");
    println!("| q | reorgs/1000 blk | mean depth | p99 depth | max depth |");
    println!("|---|---|---|---|---|");
    for &q in &Q_SWEEP {
        let r = run_worst_over_seeds(q, 20, STALL_24H_BLOCKS, REORG_SEEDS);
        println!(
            "| {:.2} | {:>6.2} | {:>5.2} | {} | {} |",
            q, r.reorgs_per_1000, r.mean_depth, r.p99_depth, r.max_depth
        );
    }
    println!();

    println!("### 2 — natural propagation orphans at 75s (honest-only baseline)\n");
    println!("| propagation τ | orphan rate/block | P(depth ≥ 2) |");
    println!("|---|---|---|");
    for tau in [1.0, 2.0, 5.0, 10.0] {
        let (rate, d2) = natural_orphans(tau);
        println!("| {:>4.0}s | {:>8.4} | {:>10.2e} |", tau, rate, d2);
    }
    println!();
}

fn jail_section() {
    println!("## 3. Downtime jail threshold (X%, Y-block) grid (§4)\n");
    let cfg = JailSimConfig::default();
    println!(
        "N={} validators · {} epochs · healthy uptime {:.1}% · seed {:#x}\n",
        cfg.n_validators,
        cfg.epochs,
        cfg.p_up * 100.0,
        cfg.seed
    );
    println!("| X (signed ≥) | Y window | detection lag (blk / wall) | false-jail @99% | false-jail @99%+2%blips |");
    println!("|---|---|---|---|---|");
    for cell in run_grid(&cfg) {
        let wall = if cell.detection_lag_secs >= 3600 {
            format!("{:.1}h", cell.detection_lag_secs as f64 / 3600.0)
        } else {
            format!("{:.0}m", cell.detection_lag_secs as f64 / 60.0)
        };
        println!(
            "| {:>4.0}% | {:>4} | {} blk / {} | {:>5.3} | {:>5.3} |",
            cell.x * 100.0,
            cell.y,
            cell.detection_lag_blocks,
            wall,
            cell.false_jail_rate_p99,
            cell.false_jail_rate_blips
        );
    }
    println!();

    // 3b: false-jail ONSET as validator uptime degrades — where each (X,Y) starts
    // punishing operators, so the design can read the safety margin.
    println!("### 3b false-jail onset vs degrading uptime (independent misses)\n");
    println!("| uptime | X5%/Y100 | X10%/Y100 | X33%/Y100 | X50%/Y100 | X50%/Y50 |");
    println!("|---|---|---|---|---|---|");
    for &p_up in &[0.99, 0.97, 0.95, 0.90, 0.80, 0.70] {
        let cfg = JailSimConfig { p_up, ..JailSimConfig::default() };
        println!(
            "| {:>4.0}% | {:>5.3} | {:>5.3} | {:>5.3} | {:>5.3} | {:>5.3} |",
            p_up * 100.0,
            false_jail_rate(0.05, 100, &cfg),
            false_jail_rate(0.10, 100, &cfg),
            false_jail_rate(0.33, 100, &cfg),
            false_jail_rate(0.50, 100, &cfg),
            false_jail_rate(0.50, 50, &cfg),
        );
    }
    println!();
}
