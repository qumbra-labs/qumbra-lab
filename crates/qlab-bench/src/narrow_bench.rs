//! M1.5b real-AIR bench: the correct-semantics narrow Keccak
//! (`qlab_air::narrow::NarrowKeccakAir`, 371 cols x 3072 rows/perm)
//! proven and verified under the M1.6 lever configs, reported against the
//! P371 mock anchor and the acceptance gates in
//! `docs/m15b-narrow-keccak-layout.md`.
//!
//! Preprocessed handling: the AIR carries one preprocessed column (the
//! iota round constant — period 24 rounds, not a power of two, so it
//! cannot ride the free periodic-column path). `setup_preprocessed` is
//! vk-style one-time work and is NOT counted in prove time; its per-query
//! opening cost IS counted in proof size — pricing exactly the variant-(a)
//! selector question the layout doc left open.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use qlab_air::narrow::{NarrowKeccakAir, NARROW_WIDTH, ROWS_PER_PERM};

use crate::{make_config_with, pc_len, FriCfg, Val, RUNS};

/// The design's ~90-hash bucket, rounded up (same as the mock modes).
const BUCKET_PERMS: usize = 96;

/// The lever configs the real AIR is measured under. b32 is included but
/// may exceed this rig's RAM (371 cols x 2^19 rows x 32 blowup LDE ~ 25 GB)
/// — a panic is caught and reported as FAILED, honestly.
const NARROW_CFGS: [(&str, FriCfg); 4] = [
    // Query count dominates byte cost (~6.5 KB/query at b16 incl. the
    // preprocessed opening); trade queries for grind at exactly 100 bits.
    (
        "b16/q20/g20/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 20,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b16/q19/g24/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 19,
            grind_bits: 24,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b16/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 23,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b32/a16",
        FriCfg {
            log_blowup: 5,
            num_queries: 18,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
];

pub(crate) fn run_narrow(power: &str) {
    let rows = BUCKET_PERMS * ROWS_PER_PERM;
    let log_height = rows.next_power_of_two().trailing_zeros() as usize;

    println!("# qumbra-lab M1.5b real narrow-Keccak AIR bench");
    println!();
    crate::print_env(power);
    println!(
        "- AIR: qlab-air NarrowKeccakAir — correct Keccak-f[1600] semantics, \
         {NARROW_WIDTH} cols x {ROWS_PER_PERM} rows/perm (128 rows/round), \
         27 periodic columns (free), 1 preprocessed column (iota RC; vk-style \
         commit excluded from prove time, per-query openings included in \
         proof size)"
    );
    println!(
        "- semantics validated in qlab-air tests: chain of materialized states \
         == reference keccak-f (itself cross-checked against p3-keccak)"
    );
    println!(
        "- workload: {BUCKET_PERMS}-perm bucket = {rows} rows, padded to \
         2^{log_height} (the pipeline chains through padding; every padded \
         block is also a genuine keccak round)"
    );
    println!("- per cell: prove/verify = best of {RUNS} in-process runs; proof = postcard bytes");
    println!();

    println!("| config | conj. bits | prove ms | verify ms | proof KB | vs P371 mock | vs gates |");
    println!("|---|---|---|---|---|---|---|");

    for (name, cfg) in &NARROW_CFGS {
        let air = NarrowKeccakAir { log_height };
        let config = make_config_with(cfg);
        let bits = cfg.num_queries * cfg.log_blowup + cfg.grind_bits;

        eprintln!("== narrow: {name} ({}) ==", cfg.label());
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (pd, vk) =
                setup_preprocessed(&config, &air, log_height).expect("AIR has preprocessed");
            let mut best_prove = f64::INFINITY;
            let mut proof_opt = None;
            for _ in 0..RUNS {
                let trace = air.generate_trace::<Val>(cfg.log_blowup);
                let t = Instant::now();
                let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pd));
                best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
                proof_opt = Some(proof);
            }
            let proof = proof_opt.expect("RUNS > 0");
            let proof_bytes = pc_len(&proof);
            let mut best_verify = f64::INFINITY;
            for _ in 0..RUNS {
                let t = Instant::now();
                verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk))
                    .expect("verification failed");
                best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
            }
            (best_prove, best_verify, proof_bytes)
        }));

        match result {
            Ok((prove_ms, verify_ms, bytes)) => {
                let kb = bytes as f64 / 1024.0;
                let verdict = if kb <= 150.0 && prove_ms <= 3000.0 {
                    "PASS"
                } else {
                    "FAIL"
                };
                eprintln!(
                    "  [narrow {name}] prove={prove_ms:.1}ms verify={verify_ms:.1}ms \
                     proof={bytes}B"
                );
                println!(
                    "| {} ({}) | {} | {:.1} | {:.1} | {:.1} | measure P371 in `levers` | {} |",
                    name,
                    cfg.label(),
                    bits,
                    prove_ms,
                    verify_ms,
                    kb,
                    verdict,
                );
            }
            Err(_) => {
                eprintln!("  [narrow {name}] FAILED (panic during setup/prove — likely memory)");
                println!(
                    "| {} ({}) | {} | FAILED | FAILED | FAILED | — | FAIL |",
                    name,
                    cfg.label(),
                    bits,
                );
            }
        }
    }
    println!();
    println!(
        "Gates (layout doc §4): size within 10% of the P371 mock at the same \
         config; prove <= 3,000 ms; correctness = qlab-air test suite."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end roundtrip of the real narrow AIR through the actual
    /// prover stack (preprocessed included) at a small height. Debug
    /// builds also run check_constraints inside prove.
    #[test]
    fn narrow_air_prove_verify_roundtrip() {
        let air = NarrowKeccakAir { log_height: 10 };
        let cfg = FriCfg {
            log_blowup: 2,
            num_queries: 45,
            grind_bits: 10,
            log_final_poly_len: 2,
            max_log_arity: 3,
        };
        let config = make_config_with(&cfg);
        let (pd, vk) = setup_preprocessed(&config, &air, air.log_height).expect("preprocessed");
        let trace = air.generate_trace::<Val>(cfg.log_blowup);
        let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pd));
        verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk)).expect("verify");
    }
}
