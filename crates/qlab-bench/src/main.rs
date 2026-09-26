//! M1 hash-matrix bench: prove the three published Plonky3 hash AIRs
//! (Keccak-f\[1600\], BLAKE3, Poseidon2 width-16) under ONE shared prover
//! configuration and print a markdown results table.
//!
//! This fills performance-budget §2's conservative-hash decision matrix.
//! Poseidon2 is the calibration baseline (published numbers exist); the
//! conservative candidates are what M1 actually has to measure.
//!
//! Plonky3 pinned at 0.6.1 (see Cargo.toml / Cargo.lock). SHA-256 raw-AIR
//! has no published Plonky3 crate at 0.6.1, so the matrix here is the three
//! published AIRs; SHA-256 is a later task.

// The m4gate verifier AIR builds a large symbolic constraint tree; its
// monomorphization pushes rustc's default recursion limit (KeccakCols layout
// query). Raise it so the gate rectangle compiles.
#![recursion_limit = "512"]

mod disclosure;
mod geometry;
mod l2shape;
mod zkpeak;
mod mproof;
mod levers;
mod m4anchor;
mod m4assembly;
mod m4census;
mod m4gate;
mod m4gaterec;
mod m4interior;
mod m4treerec;
mod m4price;
mod m4route;
mod m4skel;
mod m5note;
mod m6devnet;
mod n7soak;
mod narrow_bench;
mod registry_admit;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use p3_air::{Air, DebugConstraintBuilder};
use p3_blake3_air::Blake3Air;
use p3_keccak_air::KeccakAir;
// The consensus config plumbing (challenger / commit / fri / keccak / merkle /
// symmetric types) moved to `qlab-consensus` (issue #38); only the Poseidon2
// calibration-baseline constants remain a direct koala-bear import here.
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_uni_stark::{
    prove, verify, Proof, ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder,
};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Shared prover configuration — identical for all three hash AIRs.
//
// Field:      KoalaBear (31-bit prime 2^31 - 2^24 + 1), the Plonky3-preferred
//             Monty-31 field. Challenge = degree-4 binomial extension (~124-bit).
// FRI Merkle: Keccak-256 (vectorized Keccak-f sponge) — conservative hash for
//             the commitment layer, matching Qumbra's consensus hash stance.
// DFT:        Radix2DitParallel.
// ---------------------------------------------------------------------------

// The consensus config plumbing (field / hash / FRI types, the consensus
// StarkConfig, `FriCfg`, and `make_config_with`) now lives in the shared
// `qlab-consensus` crate (issue #38 — single source of truth). Re-export it so
// every bench module's `crate::{Val, Challenge, Dft, Config, FriCfg,
// make_config_with}` continues to resolve unchanged.
pub use qlab_consensus::{make_config_with, Challenge, Config, Dft, FriCfg, Val};

/// log2 of the FRI blowup factor. Also passed to trace generation as
/// `extra_capacity_bits` so the trace buffer can hold the LDE in place.
const LOG_BLOWUP: usize = 1;

/// Target ~100-bit CONJECTURED security (ethSTARK conjecture, the same
/// arithmetic as `FriParameters::conjectured_soundness_bits`):
///
///   num_queries * log2(blowup) + query_grinding_bits
///     = 90 * 1 + 10
///     = 100 bits conjectured.
///
/// Blowup 2 (log_blowup = 1) also covers the max constraint degree 3 shared
/// by all three AIRs (quotient degree 2, so log_quotient_degree = 1).
const NUM_QUERIES: usize = 90;
const QUERY_POW_BITS: usize = 10;

// `FriCfg` (with pub fields + `label()`) is defined in `qlab-consensus` and
// re-exported above; bench sweeps below construct their own points from it.

/// The PR #1 baseline configuration (what the default matrix mode uses).
const BASELINE_CFG: FriCfg = FriCfg {
    log_blowup: LOG_BLOWUP,
    num_queries: NUM_QUERIES,
    grind_bits: QUERY_POW_BITS,
    log_final_poly_len: 0,
    max_log_arity: 1,
};

/// The sweep: every point satisfies >= 100 bits conjectured
/// (num_queries * log2(blowup) + grind, asserted at runtime in
/// `make_config_with`). Two `log_final_poly_len` variants probe the
/// early-stop knob (available in 0.6.1 `FriParameters`).
const SWEEP_CFGS: [FriCfg; 7] = [
    // blowup 2, 90 queries, grind 10 — the PR #1 baseline (100 bits).
    BASELINE_CFG,
    // blowup 4, 45 queries, grind 10 (100 bits).
    FriCfg {
        log_blowup: 2,
        num_queries: 45,
        grind_bits: 10,
        log_final_poly_len: 0,
        max_log_arity: 1,
    },
    // blowup 8, 30 queries, grind 10 (100 bits).
    FriCfg {
        log_blowup: 3,
        num_queries: 30,
        grind_bits: 10,
        log_final_poly_len: 0,
        max_log_arity: 1,
    },
    // blowup 16, 23 queries, grind 10 (102 bits).
    FriCfg {
        log_blowup: 4,
        num_queries: 23,
        grind_bits: 10,
        log_final_poly_len: 0,
        max_log_arity: 1,
    },
    // blowup 4, 40 queries, grind 20 (100 bits).
    FriCfg {
        log_blowup: 2,
        num_queries: 40,
        grind_bits: 20,
        log_final_poly_len: 0,
        max_log_arity: 1,
    },
    // Early-stop variants: stop FRI folding at a 16-coefficient final poly.
    FriCfg {
        log_blowup: 2,
        num_queries: 45,
        grind_bits: 10,
        log_final_poly_len: 4,
        max_log_arity: 1,
    },
    FriCfg {
        log_blowup: 4,
        num_queries: 23,
        grind_bits: 10,
        log_final_poly_len: 4,
        max_log_arity: 1,
    },
];

// `make_config_with` is defined in `qlab-consensus` and re-exported above.

fn make_config() -> Config {
    make_config_with(&BASELINE_CFG)
}

// ---------------------------------------------------------------------------
// Bench runner
// ---------------------------------------------------------------------------

struct Cell {
    hash: &'static str,
    perms: usize,
    rows: usize,
    cols: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    note: &'static str,
}

const RUNS: usize = 3;

/// Prove/verify one (hash, workload) cell: best of `RUNS` in-process runs
/// for both prove and verify wall-clock. Proof size via postcard.
fn run_cell<A>(
    config: &Config,
    air: &A,
    hash: &'static str,
    perms: usize,
    note: &'static str,
    gen_trace: impl Fn() -> RowMajorMatrix<Val>,
) -> Cell
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let mut rows = 0;
    let mut cols = 0;
    let mut best_prove = f64::INFINITY;
    let mut proof_opt = None;
    for _ in 0..RUNS {
        // Regenerate the trace each run: `prove` consumes it, and holding
        // clones of the big Keccak traces would inflate peak memory.
        let trace = gen_trace();
        rows = trace.height();
        cols = trace.width();
        let t = Instant::now();
        let proof = prove(config, air, trace, &[]);
        best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
        proof_opt = Some(proof);
    }
    let proof = proof_opt.expect("RUNS > 0");

    let proof_bytes = postcard::to_allocvec(&proof)
        .expect("proof serialization failed")
        .len();

    let mut best_verify = f64::INFINITY;
    for _ in 0..RUNS {
        let t = Instant::now();
        verify(config, air, &proof, &[]).expect("verification failed");
        best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
    }

    eprintln!(
        "  [{hash} x{perms}] rows={rows} cols={cols} prove={best_prove:.1}ms \
         verify={best_verify:.1}ms proof={proof_bytes}B"
    );

    Cell {
        hash,
        perms,
        rows,
        cols,
        prove_ms: best_prove,
        verify_ms: best_verify,
        proof_bytes,
        note,
    }
}

// ---------------------------------------------------------------------------
// Sweep mode: FRI-config sweep at 128 permutations.
// ---------------------------------------------------------------------------

/// Number of permutations used by sweep + breakdown modes: the workload that
/// approximates the design's ~90-hash 2x2-bucket circuit.
const SWEEP_PERMS: usize = 128;

struct SweepRow {
    hash: &'static str,
    cfg: FriCfg,
    /// None => the config FAILED to prove (panic caught; reported honestly).
    prove_ms: Option<f64>,
    proof_bytes: Option<usize>,
    note: String,
}

/// Prove one (hash, FRI-config) cell: best of `RUNS` in-process runs.
/// A panic inside prove (memory, API limits) is caught and reported as a
/// FAILED row rather than aborting the sweep.
fn sweep_cell<A>(
    air: &A,
    hash: &'static str,
    cfg: &FriCfg,
    gen_trace: &dyn Fn(usize) -> RowMajorMatrix<Val>,
) -> SweepRow
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let config = make_config_with(cfg);
    let mut best_prove = f64::INFINITY;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut proof_opt = None;
        for _ in 0..RUNS {
            let trace = gen_trace(cfg.log_blowup);
            let t = Instant::now();
            let proof = prove(&config, air, trace, &[]);
            best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
            proof_opt = Some(proof);
        }
        proof_opt.expect("RUNS > 0")
    }));

    match result {
        Ok(proof) => {
            let proof_bytes = postcard::to_allocvec(&proof)
                .expect("proof serialization failed")
                .len();
            let mut note = String::new();
            if let Err(e) = verify(&config, air, &proof, &[]) {
                note = format!("VERIFY FAILED: {e:?}");
            } else if best_prove > 3000.0 {
                note = "exceeds 3,000 ms laptop target".to_string();
            }
            eprintln!(
                "  [{hash} {}] prove={best_prove:.1}ms proof={proof_bytes}B {note}",
                cfg.label(),
            );
            SweepRow {
                hash,
                cfg: *cfg,
                prove_ms: Some(best_prove),
                proof_bytes: Some(proof_bytes),
                note,
            }
        }
        Err(_) => {
            eprintln!("  [{hash} {}] FAILED (panic during prove)", cfg.label());
            SweepRow {
                hash,
                cfg: *cfg,
                prove_ms: None,
                proof_bytes: None,
                note: "FAILED: panic during prove (see stderr)".to_string(),
            }
        }
    }
}

fn print_sweep_table(rows: &[SweepRow]) {
    println!("| hash | blowup | queries | grind | final poly | conj. bits | prove ms | proof KB |");
    println!("|---|---|---|---|---|---|---|---|");
    for r in rows {
        let bits = r.cfg.num_queries * r.cfg.log_blowup + r.cfg.grind_bits;
        let (prove, size) = match (r.prove_ms, r.proof_bytes) {
            (Some(ms), Some(b)) => (format!("{ms:.1}"), format!("{:.1}", b as f64 / 1024.0)),
            _ => ("FAILED".to_string(), "FAILED".to_string()),
        };
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            r.hash,
            1 << r.cfg.log_blowup,
            r.cfg.num_queries,
            r.cfg.grind_bits,
            1 << r.cfg.log_final_poly_len,
            bits,
            prove,
            size,
        );
    }
    println!();
    let notes: Vec<&SweepRow> = rows.iter().filter(|r| !r.note.is_empty()).collect();
    if !notes.is_empty() {
        println!("Notes:");
        for r in notes {
            println!("- {} {}: {}", r.hash, r.cfg.label(), r.note);
        }
        println!();
    }
}

// ---------------------------------------------------------------------------
// Breakdown mode: serialize the proof's components separately.
//
// p3-uni-stark 0.6.1 `Proof` nesting (all fields public):
//   commitments: { trace, quotient_chunks, random }          -- Merkle roots
//   opened_values: trace/quotient evals at zeta, g*zeta      -- Challenge elems
//   opening_proof: FriProof {
//     commit_phase_commits: Vec<Com>,                        -- FRI fold roots
//     commit_pow_witnesses: Vec<Val>,
//     query_proofs: Vec<QueryProof {
//       input_proof: Vec<BatchOpening {                      -- per batch
//         opened_values: Vec<Vec<Val>>,                      --   full LDE rows
//         opening_proof,                                     --   Merkle path
//       }>,
//       commit_phase_openings: Vec<CommitPhaseProofStep {
//         log_arity, sibling_values, opening_proof           -- fold siblings+path
//       }>,
//     }>,
//     final_poly: Vec<Challenge>,
//     query_pow_witness: Val,
//   }
//   degree_bits: usize
//
// Components are measured by serializing each substructure with the same
// postcard codec as the total; the small mismatch (outer Vec length varints
// etc.) is reported honestly as a residual.
// ---------------------------------------------------------------------------

fn pc_len<T: Serialize + ?Sized>(v: &T) -> usize {
    postcard::to_allocvec(v)
        .expect("serialization failed")
        .len()
}

struct Breakdown {
    total: usize,
    /// Trace + quotient (and optional random) Merkle roots.
    commitments: usize,
    /// Out-of-domain openings at zeta / g*zeta (trace + quotient chunks).
    zeta_opened: usize,
    /// Per-query opened LDE rows across all committed matrices.
    query_input_values: usize,
    /// Merkle paths authenticating the per-query input rows.
    query_input_paths: usize,
    /// FRI commit-phase Merkle roots (one per fold round).
    fri_commits: usize,
    /// FRI fold sibling values (+ 1 arity tag byte per step).
    fri_sibling_values: usize,
    /// Merkle paths for the FRI commit-phase openings.
    fri_fold_paths: usize,
    /// Final polynomial coefficients (Challenge elements, plaintext).
    final_poly: usize,
    /// Commit-phase + query PoW witnesses.
    pow: usize,
    /// degree_bits + serde framing not attributable to any component.
    residual: usize,
}

fn breakdown_proof(proof: &Proof<Config>) -> Breakdown {
    let total = pc_len(proof);
    let commitments = pc_len(&proof.commitments);
    let zeta_opened = pc_len(&proof.opened_values);
    // `(random-codeword openings, FRI proof)` — the hiding PCS's opening proof.
    let zk_openings = pc_len(&proof.opening_proof.0);
    let fri = &proof.opening_proof.1;
    let fri_commits = pc_len(&fri.commit_phase_commits);
    let final_poly = pc_len(&fri.final_poly);
    let pow = pc_len(&fri.commit_pow_witnesses) + pc_len(&fri.query_pow_witness);

    let mut query_input_values = 0;
    let mut query_input_paths = 0;
    let mut fri_sibling_values = 0;
    let mut fri_fold_paths = 0;
    for q in &fri.query_proofs {
        for batch in &q.input_proof {
            query_input_values += pc_len(&batch.opened_values);
            query_input_paths += pc_len(&batch.opening_proof);
        }
        for step in &q.commit_phase_openings {
            // log_arity is a u8: 1 byte in postcard.
            fri_sibling_values += 1 + pc_len(&step.sibling_values);
            fri_fold_paths += pc_len(&step.opening_proof);
        }
    }

    let accounted = commitments
        + zeta_opened
        + query_input_values
        + query_input_paths
        + fri_commits
        + fri_sibling_values
        + fri_fold_paths
        + final_poly
        + pow
        + zk_openings;
    let residual = total.saturating_sub(accounted);

    Breakdown {
        total,
        commitments,
        zeta_opened,
        query_input_values,
        query_input_paths,
        fri_commits,
        fri_sibling_values,
        fri_fold_paths,
        final_poly,
        pow,
        residual,
    }
}

fn print_breakdown_detail(hash: &str, cfg_label: &str, b: &Breakdown) {
    let kb = |x: usize| x as f64 / 1024.0;
    let pct = |x: usize| 100.0 * x as f64 / b.total as f64;
    println!("### {hash} @ {cfg_label}");
    println!();
    println!("| component | KB | % |");
    println!("|---|---|---|");
    let rows: [(&str, usize); 10] = [
        ("trace + quotient commitments (Merkle roots)", b.commitments),
        (
            "opened values at zeta (trace + quotient OOD evals)",
            b.zeta_opened,
        ),
        (
            "per-query input row openings (all committed matrices)",
            b.query_input_values,
        ),
        ("per-query input Merkle paths", b.query_input_paths),
        ("FRI commit-phase commitments", b.fri_commits),
        ("FRI fold sibling values", b.fri_sibling_values),
        ("FRI fold Merkle paths", b.fri_fold_paths),
        ("FRI final poly", b.final_poly),
        ("PoW witnesses", b.pow),
        ("degree_bits + serde framing (residual)", b.residual),
    ];
    for (name, bytes) in rows {
        println!("| {} | {:.1} | {:.1} |", name, kb(bytes), pct(bytes));
    }
    println!("| **total** | **{:.1}** | 100.0 |", kb(b.total));
    println!();
}

/// Prove `air` once under `cfg` (no timing; breakdown only needs the proof).
fn prove_for_breakdown<A>(
    air: &A,
    cfg: &FriCfg,
    gen_trace: &dyn Fn(usize) -> RowMajorMatrix<Val>,
) -> Option<Proof<Config>>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let config = make_config_with(cfg);
    catch_unwind(AssertUnwindSafe(|| {
        let trace = gen_trace(cfg.log_blowup);
        prove(&config, air, trace, &[])
    }))
    .ok()
}

/// Breakdown rows for one hash: the baseline config plus the best
/// (smallest-proof) config among the sweep set.
fn breakdown_air<A>(
    air: &A,
    hash: &'static str,
    gen_trace: &dyn Fn(usize) -> RowMajorMatrix<Val>,
) -> Vec<(String, Breakdown)>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let mut out = Vec::new();

    eprintln!("  [{hash}] proving baseline {}", BASELINE_CFG.label());
    let baseline =
        prove_for_breakdown(air, &BASELINE_CFG, gen_trace).expect("baseline config must prove");
    out.push((
        format!("{} (baseline)", BASELINE_CFG.label()),
        breakdown_proof(&baseline),
    ));

    // Find the smallest-proof swept config by proving each candidate once.
    let mut best: Option<(FriCfg, Proof<Config>, usize)> = None;
    for cfg in SWEEP_CFGS.iter().skip(1) {
        eprintln!("  [{hash}] proving candidate {}", cfg.label());
        match prove_for_breakdown(air, cfg, gen_trace) {
            Some(proof) => {
                let bytes = pc_len(&proof);
                if best.as_ref().is_none_or(|(_, _, b)| bytes < *b) {
                    best = Some((*cfg, proof, bytes));
                }
            }
            None => eprintln!("  [{hash}] candidate {} FAILED, skipping", cfg.label()),
        }
    }
    let (cfg, proof, _) = best.expect("at least one swept config must prove");
    out.push((
        format!("{} (best swept)", cfg.label()),
        breakdown_proof(&proof),
    ));

    out
}

fn print_breakdown_summary(rows: &[(&'static str, String, Breakdown)]) {
    println!("| hash | config | total KB | opened-values KB | merkle-paths KB | fri-commits KB | other KB |");
    println!("|---|---|---|---|---|---|---|");
    for (hash, cfg, b) in rows {
        let opened = b.zeta_opened + b.query_input_values;
        let paths = b.query_input_paths + b.fri_fold_paths;
        let other = b.total - opened - paths - b.fri_commits;
        println!(
            "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
            hash,
            cfg,
            b.total as f64 / 1024.0,
            opened as f64 / 1024.0,
            paths as f64 / 1024.0,
            b.fri_commits as f64 / 1024.0,
            other as f64 / 1024.0,
        );
    }
    println!();
    println!(
        "Column mapping: opened-values = OOD (zeta) openings + per-query input rows; \
         merkle-paths = input-opening paths + FRI fold paths; fri-commits = FRI \
         commit-phase Merkle roots; other = trace/quotient roots + FRI fold sibling \
         values + final poly + PoW witnesses + serde framing."
    );
    println!();
}

// ---------------------------------------------------------------------------
// Workloads
//
// (a) 128 permutations: smallest power of two >= 96, approximating the
//     design's ~90-hash 2x2-bucket circuit.
// (b) 2^13 = 8192 permutations: scaling point.
// ---------------------------------------------------------------------------

const PERM_COUNTS: [usize; 2] = [128, 1 << 13];

// Poseidon2 instance: width-16 (the survey's numbers are width-16 2-to-1
// compression), KoalaBear x^3 s-box computed directly (no s-box registers),
// 8 full + 20 partial rounds — the p3-koala-bear published parameter set.
const P2_WIDTH: usize = 16;
const P2_SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE; // 3
const P2_SBOX_REGISTERS: usize = 0;
const P2_HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const P2_PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 20

type QPoseidon2Air = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersKoalaBear,
    P2_WIDTH,
    P2_SBOX_DEGREE,
    P2_SBOX_REGISTERS,
    P2_HALF_FULL_ROUNDS,
    P2_PARTIAL_ROUNDS,
>;

fn keccak_inputs(perms: usize) -> Vec<[u64; 25]> {
    let mut rng = SmallRng::seed_from_u64(1);
    (0..perms).map(|_| rng.random()).collect()
}

// ---------------------------------------------------------------------------
// Header / output
// ---------------------------------------------------------------------------

fn cmd_out(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn print_env(power: &str) {
    let cpu = cmd_out("sysctl", &["-n", "machdep.cpu.brand_string"]);
    let mem = cmd_out("sysctl", &["-n", "hw.memsize"]);
    let mem_gb = mem
        .parse::<u64>()
        .map(|b| format!("{} GiB", b >> 30))
        .unwrap_or(mem);
    let os = cmd_out("sw_vers", &["-productVersion"]);
    let rev = cmd_out(
        "git",
        &[
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--short",
            "HEAD",
        ],
    );
    println!("- hardware: {cpu}, {mem_gb} RAM");
    println!("- OS: macOS {os}");
    println!("- qumbra-lab rev: {rev}");
    println!("- prover: Plonky3 0.6.1 (pinned in Cargo.lock)");
    println!("- power state: {power}");
}

fn print_header(power: &str) {
    println!("# qumbra-lab M1 hash-matrix bench");
    println!();
    print_env(power);
    println!(
        "- shared config: KoalaBear + degree-4 extension, Keccak-256 FRI Merkle, \
         blowup {}, {} queries, {}-bit query grind => {} bits conjectured \
         (queries x log2(blowup) + grind = {}x{} + {})",
        1 << LOG_BLOWUP,
        NUM_QUERIES,
        QUERY_POW_BITS,
        NUM_QUERIES * LOG_BLOWUP + QUERY_POW_BITS,
        NUM_QUERIES,
        LOG_BLOWUP,
        QUERY_POW_BITS,
    );
    println!(
        "- per cell: prove/verify = best of {RUNS} in-process runs; \
         proof size = postcard bytes"
    );
    println!();
}

fn print_table(cells: &[Cell]) {
    println!("| hash | perms | rows x cols | cells | prove ms | verify ms | proof KB |");
    println!("|---|---|---|---|---|---|---|");
    for c in cells {
        println!(
            "| {} | {} | {} x {} | {} | {:.1} | {:.1} | {:.1} |",
            c.hash,
            c.perms,
            c.rows,
            c.cols,
            c.rows * c.cols,
            c.prove_ms,
            c.verify_ms,
            c.proof_bytes as f64 / 1024.0,
        );
    }
    println!();
    let notes: Vec<&Cell> = cells.iter().filter(|c| !c.note.is_empty()).collect();
    if !notes.is_empty() {
        println!("Notes:");
        for c in notes {
            println!("- {} x{}: {}", c.hash, c.perms, c.note);
        }
    }
}

fn main() {
    // --power <note>: manual power-state annotation (AC/battery, thermal).
    // First positional arg selects the mode: (none) = hash matrix,
    // `sweep` = FRI-config sweep, `breakdown` = proof-size breakdown,
    // `geometry` = narrow-trace geometry probe (mock AIR ladder),
    // `levers` = M1.6 non-geometry levers (blowup 32, FRI arity > 2),
    // `narrow` = M1.5b real narrow-Keccak AIR.
    let args: Vec<String> = std::env::args().collect();
    let power_pos = args.iter().position(|a| a == "--power");
    let power = power_pos
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .unwrap_or("unspecified (record manually: AC/battery, thermal)")
        .to_string();
    let mode = args
        .iter()
        .enumerate()
        .skip(1)
        .find(|(i, a)| !a.starts_with("--") && power_pos.is_none_or(|p| *i != p + 1))
        .map(|(_, a)| a.as_str())
        .unwrap_or("matrix")
        .to_string();

    // Poseidon2 round constants: fixed seed so every run proves the same AIR.
    let mut rng = SmallRng::seed_from_u64(42);
    let p2_air: QPoseidon2Air = Poseidon2Air::new(RoundConstants::from_rng(&mut rng));
    let keccak_air = KeccakAir {};
    let blake3_air = Blake3Air {};

    // Per-hash trace generators at the sweep workload (128 permutations),
    // parametrized on log_blowup (= extra_capacity_bits for the LDE).
    let gen_keccak =
        |lb: usize| p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(SWEEP_PERMS), lb);
    let gen_blake3 = |lb: usize| blake3_air.generate_trace_rows::<Val>(SWEEP_PERMS, lb);
    let gen_p2 = |lb: usize| p2_air.generate_trace_rows(SWEEP_PERMS, lb);

    match mode.as_str() {
        "sweep" => {
            println!("# qumbra-lab M1 FRI-config sweep ({SWEEP_PERMS} permutations)");
            println!();
            print_env(&power);
            println!(
                "- fixed: KoalaBear + degree-4 extension, Keccak-256 FRI Merkle, \
                 Radix2DitParallel DFT; only FRI parameters vary"
            );
            println!(
                "- every config asserted >= 100 bits conjectured \
                 (queries x log2(blowup) + grind)"
            );
            println!(
                "- per cell: prove = best of {RUNS} in-process runs; proof size = postcard bytes"
            );
            println!();
            let mut rows = Vec::new();
            eprintln!("== sweep: Keccak-f[1600] ==");
            for cfg in &SWEEP_CFGS {
                rows.push(sweep_cell(&keccak_air, "Keccak-f[1600]", cfg, &gen_keccak));
            }
            eprintln!("== sweep: BLAKE3 ==");
            for cfg in &SWEEP_CFGS {
                rows.push(sweep_cell(&blake3_air, "BLAKE3", cfg, &gen_blake3));
            }
            eprintln!("== sweep: Poseidon2-w16 ==");
            for cfg in &SWEEP_CFGS {
                rows.push(sweep_cell(&p2_air, "Poseidon2-w16", cfg, &gen_p2));
            }
            print_sweep_table(&rows);
            return;
        }
        "breakdown" => {
            println!("# qumbra-lab M1 proof-size breakdown ({SWEEP_PERMS} permutations)");
            println!();
            print_env(&power);
            println!(
                "- per hash: baseline config {} plus the smallest-proof config from \
                 the sweep set (each candidate proven once to find it)",
                BASELINE_CFG.label()
            );
            println!("- component sizes = postcard bytes of each public substructure");
            println!();
            let mut summary: Vec<(&'static str, String, Breakdown)> = Vec::new();
            eprintln!("== breakdown: Keccak-f[1600] ==");
            for (cfg, b) in breakdown_air(&keccak_air, "Keccak-f[1600]", &gen_keccak) {
                summary.push(("Keccak-f[1600]", cfg, b));
            }
            eprintln!("== breakdown: BLAKE3 ==");
            for (cfg, b) in breakdown_air(&blake3_air, "BLAKE3", &gen_blake3) {
                summary.push(("BLAKE3", cfg, b));
            }
            eprintln!("== breakdown: Poseidon2-w16 ==");
            for (cfg, b) in breakdown_air(&p2_air, "Poseidon2-w16", &gen_p2) {
                summary.push(("Poseidon2-w16", cfg, b));
            }
            println!("## Summary");
            println!();
            print_breakdown_summary(&summary);
            println!("## Per-proof component detail");
            println!();
            for (hash, cfg, b) in &summary {
                print_breakdown_detail(hash, cfg, b);
            }
            return;
        }
        "geometry" => {
            geometry::run_geometry(&power);
            return;
        }
        "levers" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            levers::run_levers(&power, only);
            return;
        }
        "m4anchor" => {
            m4anchor::run_m4anchor(&power);
            return;
        }
        "m4skel" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4skel::run_m4skel(&power, only);
            return;
        }
        "m4route" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4route::run_m4route(&power, only);
            return;
        }
        "m4gate" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4gate::run_m4gate(&power, only);
            return;
        }
        "m4tree" => {
            m4treerec::run_m4tree(&power);
            return;
        }
        "m4interior" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4interior::run_m4interior(&power, only);
            return;
        }
        "m4assembly" => {
            let lane_pos = args.iter().position(|a| a == "--lane");
            let lane = lane_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4assembly::run_m4assembly(&power, lane);
            return;
        }
        "m4price" => {
            m4price::run_m4price(&power);
            return;
        }
        "m4census" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            m4census::run_m4census(&power, only);
            return;
        }
        "m5note" => {
            m5note::run_m5note(&power);
            return;
        }
        "m6devnet" => {
            m6devnet::run_m6devnet(&power);
            return;
        }
        "n7soak" => {
            n7soak::run_n7soak(&power, None);
            return;
        }
        "disclosure" => {
            disclosure::run_disclosure(&power);
            return;
        }
        "registry-admit" => {
            // L2-C4a Q8 (lab #730): the pool's per-admission registry check.
            registry_admit::run_registry_admit(&power);
            return;
        }
        "l2shape" => {
            // W3 (lab #700): `--shape s|s20|mock118|mock240|p|p19|r|s3|p3`,
            // optional `--only <lane substring>` and `--pcs hiding|nonhiding`;
            // one shape per process.
            let shape_pos = args.iter().position(|a| a == "--shape");
            let shape = shape_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            let Some(shape) = shape else {
                eprintln!("l2shape: `--shape s|s20|mock118|mock240|p|p19|r|s3|p3` is required");
                std::process::exit(2);
            };
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            // `--pcs hiding|nonhiding` (default hiding): A4's rig gate compares
            // shapes under ONE PCS, so both configs are selectable.
            let pcs_pos = args.iter().position(|a| a == "--pcs");
            let pcs = match pcs_pos.and_then(|i| args.get(i + 1)).map(String::as_str) {
                None => l2shape::PcsKind::Hiding,
                Some(p) => l2shape::PcsKind::parse(p).unwrap_or_else(|| {
                    eprintln!("l2shape: unknown --pcs `{p}`; expected hiding|nonhiding");
                    std::process::exit(2);
                }),
            };
            l2shape::run_l2shape(&power, shape, only, pcs);
            return;
        }
        "mproof" => {
            // lab #742 (A5 lever 4c stage 0): the Merkle multi-proof codec prototype.
            let case_pos = args.iter().position(|a| a == "--case");
            let Some(case) = case_pos.and_then(|i| args.get(i + 1)) else {
                eprintln!("mproof: `--case l1|s3|p3` is required");
                std::process::exit(2);
            };
            mproof::run_mproof(&power, case);
            return;
        }
        "zkpeak" => {
            let case_pos = args.iter().position(|a| a == "--case");
            let Some(case) = case_pos.and_then(|i| args.get(i + 1)) else {
                eprintln!("zkpeak: `--case l1|p19|p` is required");
                std::process::exit(2);
            };
            zkpeak::run_zkpeak(&power, case);
            return;
        }
        "bucket" => {
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            narrow_bench::run_bucket(&power, only);
            return;
        }
        "narrow" => {
            // Optional `--only <substr>` filters to matching config names.
            let only_pos = args.iter().position(|a| a == "--only");
            let only = only_pos.and_then(|i| args.get(i + 1)).map(String::as_str);
            narrow_bench::run_narrow(&power, only);
            return;
        }
        "matrix" => {}
        other => {
            eprintln!(
                "unknown mode `{other}`; expected `sweep`, `breakdown`, `geometry`, \
                 `levers`, `narrow`, or no mode"
            );
            std::process::exit(2);
        }
    }

    let config = make_config();

    print_header(&power);

    let mut cells = Vec::new();
    for perms in PERM_COUNTS {
        eprintln!("== workload: {perms} permutations ==");
        // Keccak-f[1600]: 24 trace rows per permutation, height padded to a
        // power of two by the AIR (dummy permutations) — reported honestly
        // via the rows column and a note.
        let keccak_note = if (perms * 24).is_power_of_two() {
            ""
        } else {
            "Keccak AIR uses 24 rows/permutation; height padded to the next \
             power of two with dummy permutations (rows column shows the \
             padded height actually proven)"
        };
        cells.push(run_cell(
            &config,
            &keccak_air,
            "Keccak-f[1600]",
            perms,
            keccak_note,
            || p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(perms), LOG_BLOWUP),
        ));
        // BLAKE3: one full compression per trace row.
        cells.push(run_cell(&config, &blake3_air, "BLAKE3", perms, "", || {
            blake3_air.generate_trace_rows::<Val>(perms, LOG_BLOWUP)
        }));
        // Poseidon2 width-16 (KoalaBear, x^3): one permutation per trace row.
        cells.push(run_cell(
            &config,
            &p2_air,
            "Poseidon2-w16",
            perms,
            "",
            || p2_air.generate_trace_rows(perms, LOG_BLOWUP),
        ));
    }

    print_table(&cells);
}
