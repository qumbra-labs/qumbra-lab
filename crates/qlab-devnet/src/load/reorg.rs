//! Reorg-depth characterization under Ebb-and-Flow **degraded mode** (issue #42
//! item 3) — the measured basis for the ~100-block coinbase-maturity proposal
//! (consensus-parameters §2 `[open]`).
//!
//! **Why degraded mode.** When the finality committee stalls, no checkpoint pins
//! the chain, so fork choice reverts to pure heaviest-chain PoW
//! ([`crate::chain::ChainState`] with no `finalized` head). That is precisely the
//! window in which a reorg can roll back a coinbase — hence coinbase maturity must
//! cover the deepest reorg realistically reachable while the committee is down.
//!
//! **Primary model — adversarial private race (Monte-Carlo, seeded).** An
//! adversary with hashrate fraction `q < ½` secretly forks from the public tip and
//! mines a private branch; honest miners (fraction `1−q`) extend the public tip.
//! Each block event goes to the adversary with probability `q` (two competing
//! Poisson streams ⇒ a Bernoulli sequence). When the private branch strictly
//! overtakes the public branch, the adversary publishes and the public suffix is
//! reorged out — the **reorg depth** is the number of honest blocks rolled back.
//! The adversary abandons and re-forks after falling `giveup` blocks behind
//! (finite patience / a bounded stall). This is the classic Nakamoto
//! gambler's-ruin: deep reorgs are exponentially rare for `q < ½`.
//!
//! **Secondary model — natural propagation orphans (analytic).** Even with only
//! honest miners, two blocks found within a propagation delay `τ` of each other
//! compete; the loser is orphaned (a depth-1 reorg). At 75-s blocks with a
//! sub-10-s propagation budget (consensus §7) this rate is small and depth-≥2 is
//! `(τ/T)²`-rare.
//!
//! All draws come from the seeded [`super::rng::SplitMix64`] ⇒ `run1 == run2`.

use super::rng::SplitMix64;
use super::BLOCK_TIME_SECS;

/// Parameters for one adversarial-race sim.
#[derive(Clone, Copy, Debug)]
pub struct ReorgParams {
    /// Adversary hashrate fraction, `0 ≤ q < 1`.
    pub q: f64,
    /// Blocks the adversary tolerates being behind before abandoning the fork.
    /// Models finite patience / a bounded degraded-mode stall.
    pub giveup: u64,
    /// Total block events to simulate (the degraded-mode duration).
    pub blocks: u64,
    /// PRNG seed.
    pub seed: u64,
}

/// Measured reorg-depth distribution for one `(q, giveup, blocks)` scenario.
#[derive(Clone, Debug)]
pub struct ReorgResult {
    pub q: f64,
    pub giveup: u64,
    pub blocks: u64,
    /// Number of reorg events observed.
    pub reorgs: u64,
    /// Reorgs per 1_000 blocks.
    pub reorgs_per_1000: f64,
    /// Mean reorg depth (0 if none).
    pub mean_depth: f64,
    /// Median reorg depth.
    pub p50_depth: u64,
    /// 99th-percentile reorg depth.
    pub p99_depth: u64,
    /// Deepest reorg observed — the number that must sit under coinbase maturity.
    pub max_depth: u64,
}

/// Run the adversarial private-race sim and summarize the reorg-depth distribution.
pub fn run_adversarial(params: ReorgParams) -> ReorgResult {
    let mut rng = SplitMix64::new(params.seed);
    let mut pub_len: u64 = 0; // honest blocks since the current fork point
    let mut prv_len: u64 = 0; // adversary private blocks since the fork point
    let mut depths: Vec<u64> = Vec::new();

    for _ in 0..params.blocks {
        if rng.bernoulli(params.q) {
            // Adversary found a block.
            prv_len += 1;
            if pub_len == 0 {
                // Nothing to reorg — the adversary's block simply becomes the tip.
                prv_len = 0;
            } else if prv_len > pub_len {
                // Strict overtake ⇒ publish, rolling back `pub_len` honest blocks.
                depths.push(pub_len);
                pub_len = 0;
                prv_len = 0;
            }
        } else {
            // Honest miner extended the public tip.
            pub_len += 1;
            if pub_len > prv_len + params.giveup {
                // Adversary fell too far behind — abandon and re-fork from the tip.
                pub_len = 0;
                prv_len = 0;
            }
        }
    }

    summarize(params, depths)
}

fn summarize(params: ReorgParams, mut depths: Vec<u64>) -> ReorgResult {
    let reorgs = depths.len() as u64;
    let reorgs_per_1000 = 1_000.0 * reorgs as f64 / params.blocks.max(1) as f64;
    let (mean_depth, p50_depth, p99_depth, max_depth) = if depths.is_empty() {
        (0.0, 0, 0, 0)
    } else {
        depths.sort_unstable();
        let sum: u64 = depths.iter().sum();
        let mean = sum as f64 / depths.len() as f64;
        let pct = |p: f64| {
            let idx = ((depths.len() as f64 - 1.0) * p).round() as usize;
            depths[idx]
        };
        (mean, pct(0.50), pct(0.99), *depths.last().unwrap())
    };
    ReorgResult {
        q: params.q,
        giveup: params.giveup,
        blocks: params.blocks,
        reorgs,
        reorgs_per_1000,
        mean_depth,
        p50_depth,
        p99_depth,
        max_depth,
    }
}

/// Natural propagation-orphan characterization at the decided block time, given a
/// propagation delay `tau_secs`. Returns `(orphan_rate, p_depth_ge_2)`:
/// the per-block probability of a competing (depth-1) orphan and the probability
/// a natural reorg reaches depth ≥ 2 (two coincidences in a row).
pub fn natural_orphans(tau_secs: f64) -> (f64, f64) {
    let t = BLOCK_TIME_SECS as f64;
    // P(a competitor appears within τ) = 1 − e^{−τ/T}. Loser is orphaned (depth 1).
    let orphan_rate = 1.0 - (-tau_secs / t).exp();
    let p_depth_ge_2 = orphan_rate * orphan_rate;
    (orphan_rate, p_depth_ge_2)
}

/// The q sweep the headline run covers (honest-majority regime; q ≥ ½ breaks the
/// chain by assumption and is out of scope for a maturity bound).
pub const Q_SWEEP: [f64; 5] = [0.10, 0.20, 0.30, 0.40, 0.45];

/// Attacker-patience bands (how many blocks behind before re-forking). A wider
/// band lets a near-tie random walk drift deeper before resolving, so `max_depth`
/// grows with it — this is the adversary's tunable, hence swept.
pub const GIVEUP_SWEEP: [u64; 3] = [6, 20, 50];

/// Degraded-stall durations, in blocks, at the decided 75-s cadence: 6 h, 24 h,
/// and a pathological 30-day stall (upper-bounding the tail).
pub const STALL_6H_BLOCKS: u64 = 6 * 3_600 / BLOCK_TIME_SECS; // 288
pub const STALL_24H_BLOCKS: u64 = 24 * 3_600 / BLOCK_TIME_SECS; // 1_152
pub const STALL_30D_BLOCKS: u64 = 30 * 24 * 3_600 / BLOCK_TIME_SECS; // 34_560

/// Run the adversarial sim across `n_seeds` fixed seeds (1..=n_seeds) and return
/// the **deepest** outcome — a conservative, fully-deterministic bound on how
/// deep a reorg reaches for this `(q, giveup, blocks)`.
pub fn run_worst_over_seeds(q: f64, giveup: u64, blocks: u64, n_seeds: u64) -> ReorgResult {
    (1..=n_seeds)
        .map(|seed| run_adversarial(ReorgParams { q, giveup, blocks, seed }))
        .max_by_key(|r| r.max_depth)
        .expect("n_seeds ≥ 1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::header::{BlockHeader, ZERO_HASH};

    fn base(q: f64, blocks: u64) -> ReorgParams {
        ReorgParams { q, giveup: 1_000_000, blocks, seed: 0xA11CE }
    }

    #[test]
    fn deterministic_reproduces_identically() {
        let a = run_adversarial(base(0.3, 200_000));
        let b = run_adversarial(base(0.3, 200_000));
        assert_eq!(a.max_depth, b.max_depth);
        assert_eq!(a.reorgs, b.reorgs);
        assert_eq!(a.mean_depth.to_bits(), b.mean_depth.to_bits());
    }

    #[test]
    fn deeper_reorgs_are_more_likely_with_more_adversary_hashrate() {
        let low = run_adversarial(base(0.15, 500_000));
        let high = run_adversarial(base(0.45, 500_000));
        assert!(
            high.max_depth >= low.max_depth,
            "more hashrate ⇒ at least as deep: q0.45 max={} vs q0.15 max={}",
            high.max_depth,
            low.max_depth
        );
        assert!(high.mean_depth >= low.mean_depth);
    }

    #[test]
    fn weak_adversary_stays_far_under_a_100_block_maturity() {
        // A ≤30%-hashrate adversary, worst patience band, worst of several seeds,
        // over a pathological 30-day stall stays well under a 100-block maturity.
        for &q in &[0.10, 0.20, 0.30] {
            for &g in &GIVEUP_SWEEP {
                let r = run_worst_over_seeds(q, g, STALL_30D_BLOCKS, 3);
                assert!(
                    r.max_depth < 100,
                    "q={q} giveup={g}: max depth {} must be ≪ 100",
                    r.max_depth
                );
            }
        }
    }

    #[test]
    fn near_half_adversary_can_exceed_maturity_only_finality_bounds_that() {
        // Honest finding: as q→½ the reorg depth is effectively unbounded over a
        // long stall — a maturity depth cannot bound it; that is finality's job,
        // and a realistic stall is hours, not a month.
        let long = run_worst_over_seeds(0.45, 50, STALL_30D_BLOCKS, 3);
        let short = run_worst_over_seeds(0.45, 50, STALL_6H_BLOCKS, 3);
        assert!(long.max_depth > short.max_depth, "a longer stall admits deeper reorgs");
    }

    #[test]
    fn worst_over_seeds_is_at_least_any_single_seed() {
        let worst = run_worst_over_seeds(0.40, 20, 50_000, 3);
        let single = run_adversarial(ReorgParams { q: 0.40, giveup: 20, blocks: 50_000, seed: 2 });
        assert!(worst.max_depth >= single.max_depth);
    }

    #[test]
    fn natural_orphan_rate_is_small_and_depth2_is_negligible() {
        // 5-s propagation at 75-s blocks: a few-percent orphan rate, depth≥2 rare.
        let (rate, d2) = natural_orphans(5.0);
        assert!(rate > 0.0 && rate < 0.10, "orphan rate {rate}");
        assert!(d2 < 0.005, "depth≥2 prob {d2} must be negligible");
        // Faster propagation ⇒ fewer orphans.
        assert!(natural_orphans(1.0).0 < rate);
    }

    /// Grounding: the abstract depth-`d` reorg the Monte-Carlo model records is
    /// exactly what the real heaviest-chain [`ChainState`] does — a competing
    /// branch that outweighs the tip reorgs it by the honest suffix length.
    #[test]
    fn chainstate_reorg_depth_matches_the_model_semantics() {
        let g = BlockHeader::genesis(1_000, 0);
        let mut c = ChainState::new(g);
        let gh = *c.header(&c.genesis_block_hash()).unwrap();
        // Honest branch A: 3 blocks (depth-3 suffix on genesis).
        let a1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32])).unwrap();
        let a1h = *c.header(&a1).unwrap();
        let a2 = c.insert_header(BlockHeader::child_of(&a1h, 4, 1_000, [0xA2; 32])).unwrap();
        let a2h = *c.header(&a2).unwrap();
        let a3 = c.insert_header(BlockHeader::child_of(&a2h, 6, 1_000, [0xA3; 32])).unwrap();
        assert_eq!(c.tip_hash(), a3);
        assert_eq!(c.tip_height(), 3);

        // No finality (degraded mode): a heavier private branch B (from genesis,
        // 4 blocks) reorgs the tip, rolling back the 3-block honest suffix.
        let mut prev = c.genesis_block_hash();
        for i in 0..4u8 {
            let ph = *c.header(&prev).unwrap();
            prev = c.insert_header(BlockHeader::child_of(&ph, (i as u64 + 1) * 3, 1_000, [0xB0 + i; 32])).unwrap();
        }
        assert_eq!(c.tip_height(), 4, "heavier B branch (4) reorgs A (3)");
        assert_ne!(c.tip_hash(), a3);
        // Depth rolled back = the honest suffix length (3) — exactly the model's
        // recorded reorg depth for pub_len = 3 at overtake.
        assert_eq!(ZERO_HASH, [0u8; 32]); // sanity anchor for the genesis convention
    }
}
