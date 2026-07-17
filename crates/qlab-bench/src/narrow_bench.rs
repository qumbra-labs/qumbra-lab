//! M1.5b real-AIR bench: the correct-semantics narrow Keccak
//! (`qlab_air::narrow::NarrowKeccakAir`, 371 cols x 3072 rows/perm)
//! proven and verified under the M1.6 lever configs, reported against the
//! P371 mock anchor and the acceptance gates in
//! `docs/m15b-narrow-keccak-layout.md`.
//!
//! M1.5c: the iota round constant now rides an in-trace rotating ring of
//! 24 registers + 7 exposed bits (see qlab-air narrow.rs) — there is no
//! preprocessed trace anymore, so this mode uses the plain prove/verify
//! path. M1.5b's preprocessed variant measured 141.2 KB at b16/q19/g24/a16
//! (runs in docs/narrow-M15b-run*.md); the delta to this mode's numbers is
//! the measured value of removing the per-query preprocessed openings.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use p3_uni_stark::{prove, verify};
use qlab_air::narrow::{NarrowKeccakAir, NARROW_WIDTH, ROWS_PER_PERM};

use crate::{make_config_with, pc_len, FriCfg, Val, RUNS};

/// The design's ~90-hash bucket, rounded up (same as the mock modes).
const BUCKET_PERMS: usize = 96;

/// The lever configs the real AIR is measured under. b32 is included but
/// may exceed this rig's RAM (371 cols x 2^19 rows x 32 blowup LDE ~ 25 GB)
/// — a panic is caught and reported as FAILED, honestly.
const NARROW_CFGS: [(&str, FriCfg); 9] = [
    // Margin card: early-stop at a 32-coeff final poly (one fewer partial
    // fold round per query) at the consensus point.
    (
        "b16/q20/g20/fp32/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 20,
            grind_bits: 20,
            log_final_poly_len: 5,
            max_log_arity: 4,
        },
    ),
    // M2 step-0 memory ladder: blowup sets the LDE working set
    // (402 cols x 2^19 rows x blowup x 4 B = 3.4 GB @ b4, 6.7 GB @ b8,
    // 13.5 GB @ b16) — iPhone jetsam limits decide which are provable
    // on-device; these cells price the proof-size cost of fitting.
    (
        "b4/q45/g10/a16",
        FriCfg {
            log_blowup: 2,
            num_queries: 45,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b4/q40/g20/a16",
        FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b8/q30/g10/a16",
        FriCfg {
            log_blowup: 3,
            num_queries: 30,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b8/q27/g19/a16",
        FriCfg {
            log_blowup: 3,
            num_queries: 27,
            grind_bits: 19,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
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

/// `only`: optional config-name filter (substring match) — one config per
/// process, exactly what a per-launch phone harness needs, and what lets
/// /usr/bin/time -l attribute peak RSS to a single config.
pub(crate) fn run_narrow(power: &str, only: Option<&str>) {
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
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        let air = NarrowKeccakAir::chain_only(log_height);
        let config = make_config_with(cfg);
        let bits = cfg.num_queries * cfg.log_blowup + cfg.grind_bits;

        eprintln!("== narrow: {name} ({}) ==", cfg.label());
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut best_prove = f64::INFINITY;
            let mut proof_opt = None;
            for _ in 0..RUNS {
                let trace = air.generate_trace::<Val>(cfg.log_blowup);
                let t = Instant::now();
                let proof = prove(&config, &air, trace, &[]);
                best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
                proof_opt = Some(proof);
            }
            let proof = proof_opt.expect("RUNS > 0");
            let proof_bytes = pc_len(&proof);
            let mut best_verify = f64::INFINITY;
            for _ in 0..RUNS {
                let t = Instant::now();
                verify(&config, &air, &proof, &[]).expect("verification failed");
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
        let air = NarrowKeccakAir::chain_only(10);
        let cfg = FriCfg {
            log_blowup: 2,
            num_queries: 45,
            grind_bits: 10,
            log_final_poly_len: 2,
            max_log_arity: 3,
        };
        let config = make_config_with(&cfg);
        let trace = air.generate_trace::<Val>(cfg.log_blowup);
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("verify");
    }
}
