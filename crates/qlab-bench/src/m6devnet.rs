//! `m6devnet` bench mode (M6 棒 5): the measured real-proof integration.
//!
//! Drives the `qlab-devnet` consensus prototype with **real M3 transaction
//! proofs** in block bodies and measures what the consensus doc's block-time
//! section (§7) cares about: **per-block validation time** vs the sub-second
//! budget, block cadence, finality latency, and degraded-mode behaviour.
//!
//! Real proofs are pre-generated ONCE into a small pool (`m4gaterec::
//! consensus_proof_seeded`, ~1.6 s each at the consensus config) and reused —
//! block bodies reference pooled proofs by index; validation runs the REAL
//! `p3_uni_stark::verify` on the real proof objects, so the validation-time
//! numbers are genuine. Proving is confined to this bench mode (never the test
//! suite) per the bench-mode pattern.
//!
//! Honest modelling note: the M3 test proof commits an internal fee of 1 000
//! (its balance constraint); the devnet's posted-price table (棒 4) is a separate
//! placeholder. In this harness a tx's *declared* fee uses the posted price and
//! the STARK proof validity is checked independently — in a fully-wired chain the
//! two would be the same number (both driven off the consensus-parameters
//! appendix, still open).

use std::time::Instant;

use p3_uni_stark::{verify, Proof};

use qlab_air::narrow::BucketInstance;
use qlab_devnet::body::{validate_body, BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState, Vote};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::{Node, SimConfig};
use qlab_devnet::params_devnet::{BOND_AMOUNT, CHECKPOINT_CADENCE_BLOCKS, COMMITTEE_SIZE, SIM_BLOCK_TIME_SECS};
use qlab_devnet::pow::KeccakPow;

use crate::m4gaterec::{consensus_proof_seeded, CONSENSUS_CFG};
use crate::{make_config_with, Config, Val, RUNS};

/// Number of real M3 proofs pre-generated and reused. A block carries up to this
/// many distinct-nullifier transactions; larger blocks are extrapolated from the
/// measured per-proof verify time.
const POOL: usize = 4;

/// One pooled real transaction: its M3 instance (holds the AIR + public note
/// data), public values, and the proof.
type Pooled = (BucketInstance, Vec<Val>, Proof<Config>);

/// `[u64; 4]` (qlab-air digest form) → 32 bytes, lane-major little-endian.
fn h32(x: &[u64; 4]) -> Hash32 {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&x[i].to_le_bytes());
    }
    o
}

/// A distinct non-zero PRNG seed per pool slot (seed 0 is degenerate for the
/// xorshift used by `consensus_proof_seeded`).
fn pool_seed(i: usize) -> u64 {
    (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Verifies a `TxEntry` by looking up its pooled proof (index encoded in the
/// entry's proof bytes) and running the REAL M3 verifier.
struct PoolVerifier<'a> {
    pool: &'a [Pooled],
    config: &'a Config,
}

impl TxVerifier for PoolVerifier<'_> {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        let idx = usize::from_le_bytes(entry.proof[..8].try_into().expect("8-byte index"));
        let (inst, pvs, proof) = &self.pool[idx];
        verify(self.config, &inst.air, proof, pvs).is_ok()
    }
}

/// A `TxEntry` referencing pooled proof `idx`, with its real public surface.
fn entry_for(pool: &[Pooled], idx: usize) -> TxEntry {
    let (inst, _, _) = &pool[idx];
    TxEntry {
        proof: (idx as u64).to_le_bytes().to_vec(),
        public: TxPublic {
            anchor: h32(&inst.anchor),
            nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
            commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}

pub fn run_m6devnet(power: &str) {
    println!("# M6 devnet — measured real-proof integration (棒 5)\n");
    println!("power state: {power}");
    println!("consensus config: b{}/q{}/g{} (M3 CONSENSUS_CFG), log_height {}",
        1 << CONSENSUS_CFG.log_blowup, CONSENSUS_CFG.num_queries, CONSENSUS_CFG.grind_bits, 18);
    println!("committee: N={COMMITTEE_SIZE}, ⅔-quorum; checkpoint cadence {CHECKPOINT_CADENCE_BLOCKS} blocks");
    println!("sim block time: {SIM_BLOCK_TIME_SECS}s (accelerated; real target 60–75 s, consensus §7)\n");

    // ── Pool: pre-generate POOL real M3 proofs once ────────────────────────
    println!("## Proof pool ({POOL} real M3 tx proofs, generated once)\n");
    let config = make_config_with(&CONSENSUS_CFG);
    let mut pool: Vec<Pooled> = Vec::with_capacity(POOL);
    let mut proof_bytes = 0usize;
    for i in 0..POOL {
        let t = Instant::now();
        let (inst, pvs, proof) = consensus_proof_seeded(pool_seed(i));
        let secs = t.elapsed().as_secs_f64();
        let bytes = bincode::serialize(&proof).expect("bincode proof").len();
        proof_bytes = bytes;
        println!("- proof[{i}]: prove {secs:.2} s, {} KB (fixed-width)", bytes / 1024);
        pool.push((inst, pvs, proof));
    }
    println!();

    // ── Single-proof verification time (the §5/§7 headline) ────────────────
    let verifier = PoolVerifier { pool: &pool, config: &config };
    let mut best_verify_ms = f64::INFINITY;
    for _ in 0..RUNS {
        let e = entry_for(&pool, 0);
        let t = Instant::now();
        assert!(verifier.verify_tx(&e), "pooled proof must verify");
        best_verify_ms = best_verify_ms.min(t.elapsed().as_secs_f64() * 1e3);
    }
    println!("## Verification time\n");
    println!("- single M3 proof verify: **{best_verify_ms:.3} ms** (best of {RUNS})");
    let sub_ms = if best_verify_ms < 1.0 { "YES (sub-ms)" } else { "no" };
    println!("- sub-ms? {sub_ms} — consensus §5 target is sub-ms\n");

    // ── Per-block validation time (real block of POOL txs) ─────────────────
    let body = BlockBody {
        txs: (0..POOL).map(|i| entry_for(&pool, i)).collect(),
        coinbase: 0,
    };
    // Finalized anchors = every pooled proof's anchor (they are the roots the
    // txs prove against; in the sim these are treated as finalized).
    let final_anchors: Vec<Hash32> = pool.iter().map(|(inst, _, _)| h32(&inst.anchor)).collect();
    let is_final = |r: &Hash32| final_anchors.contains(r);

    // The header this body belongs to (issue #77): validation is header-aware, so
    // the measured figure now includes the O(block bytes) binding hash as well as
    // the proof verifies — which is the point, that is what a node actually pays.
    let header = BlockHeader::child_of(&BlockHeader::genesis(1, 0), 0, 1, body.commitment());

    let mut best_block_ms = f64::INFINITY;
    for _ in 0..RUNS {
        let t = Instant::now();
        validate_body(&header, &body, &verifier, is_final).expect("block body must validate");
        best_block_ms = best_block_ms.min(t.elapsed().as_secs_f64() * 1e3);
    }
    let per_tx = best_block_ms / POOL as f64;
    println!("## Per-block validation ({POOL}-tx block, real proofs)\n");
    println!("- validate_body: **{best_block_ms:.3} ms** for {POOL} txs (~{per_tx:.3} ms/tx)");
    println!("- proof bytes/tx: {} KB → block body ≈ {} KB for {POOL} txs",
        proof_bytes / 1024, proof_bytes * POOL / 1024);
    // §7: how many txs fit the sub-second (1000 ms) validation budget?
    let txs_per_second = if per_tx > 0.0 { (1000.0 / per_tx) as u64 } else { u64::MAX };
    println!("- **{txs_per_second} txs/block** fit the §7 sub-second validation budget \
        (validation is nearly free — §7 says sub-ms × hundreds = sub-second)\n");

    // ── Cadence, finality latency, degraded mode (Node run) ────────────────
    println!("## Block cadence, finality latency, degraded mode\n");
    let cfg = SimConfig { block_time_secs: SIM_BLOCK_TIME_SECS, ..SimConfig::default() };
    let mut node = Node::new(KeccakPow, cfg);
    let (committee, validators) = devnet_committee(COMMITTEE_SIZE);
    let cstate = CommitteeState::new(committee, BOND_AMOUNT);
    let quorum = cstate.quorum_threshold();

    // Mine 2 cadences' worth of blocks, finalizing at each cadence boundary.
    let body_commitment = body.commitment();
    let mut finality_events = Vec::new();
    for h in 1..=(2 * CHECKPOINT_CADENCE_BLOCKS) {
        node.mine_next(body_commitment).unwrap();
        if h % CHECKPOINT_CADENCE_BLOCKS == 0 {
            let cp = node.checkpoint_at(h).unwrap();
            let votes: Vec<Vote> = validators[..quorum].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            node.finalize(&cp, &votes, &cstate).unwrap();
            finality_events.push(h);
        }
    }
    let latency_blocks = CHECKPOINT_CADENCE_BLOCKS;
    println!("- block cadence: {SIM_BLOCK_TIME_SECS}s sim (real 60–75 s)");
    println!("- checkpoints finalized at heights {finality_events:?}");
    println!("- finality latency ≈ cadence {latency_blocks} blocks = {}s sim; \
        at real 60–75 s blocks ≈ {}–{} min (minutes-class, consensus §4)",
        latency_blocks * SIM_BLOCK_TIME_SECS,
        latency_blocks * 60 / 60, latency_blocks * 75 / 60);
    println!("- tip {} / finalized {:?} / status {:?}",
        node.tip_height(), node.finalized_height(), node.finality_status());

    // Degraded mode: stall (mine, no finalization) past the lag → Degraded → recover.
    let before = node.tip_height();
    while node.tip_height() - node.finalized_height().unwrap()
        <= qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS
    {
        node.mine_next(body_commitment).unwrap();
    }
    let stalled = node.finality_status();
    let h = node.tip_height() - 1;
    let cp = node.checkpoint_at(h).unwrap();
    let votes: Vec<Vote> = validators[..quorum].iter().map(|v| v.sign_checkpoint(&cp)).collect();
    node.finalize(&cp, &votes, &cstate).unwrap();
    println!("- degraded-mode: committee stalled → chain grew {} → {} (status {:?}); \
        recovery finalize → status {:?}",
        before, node.tip_height(), stalled, node.finality_status());
    println!("\nmeasured: {POOL} proofs, verify {best_verify_ms:.3} ms, block(4) {best_block_ms:.3} ms");
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::{build_bucket, TxInput, TxOutput};

    /// Accept-all mock verifier — exercises the m6 wiring (entry construction,
    /// h32, validate_body) WITHOUT real proving, so the acceptance suite stays light.
    struct MockOk;
    impl TxVerifier for MockOk {
        fn verify_tx(&self, _e: &TxEntry) -> bool {
            true
        }
    }

    #[test]
    fn m6_body_wiring_validates_with_mock_verifier() {
        // build_bucket is cheap (no prove): make one instance to source public data.
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
        ];
        let outputs = [
            TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        let inst = build_bucket(18, &inputs, &outputs, 1_000);

        let entry = TxEntry {
            proof: 0u64.to_le_bytes().to_vec(),
            public: TxPublic {
                anchor: h32(&inst.anchor),
                nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
                commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        };
        let anchor = h32(&inst.anchor);
        let body = BlockBody { txs: vec![entry], coinbase: 0 };
        let header = BlockHeader::child_of(&BlockHeader::genesis(1, 0), 0, 1, body.commitment());
        assert!(validate_body(&header, &body, &MockOk, |r: &Hash32| *r == anchor).is_ok());
        // h32 round-trips a digest into 32 bytes.
        assert_eq!(h32(&[0, 0, 0, 0]), [0u8; 32]);
    }
}
