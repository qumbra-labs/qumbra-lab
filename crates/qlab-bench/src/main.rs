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

use std::time::Instant;

use p3_air::{Air, DebugConstraintBuilder};
use p3_blake3_air::Blake3Air;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_keccak_air::KeccakAir;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{
    prove, verify, ProverConstraintFolder, StarkConfig, SymbolicAirBuilder,
    VerifierConstraintFolder,
};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

// ---------------------------------------------------------------------------
// Shared prover configuration — identical for all three hash AIRs.
//
// Field:      KoalaBear (31-bit prime 2^31 - 2^24 + 1), the Plonky3-preferred
//             Monty-31 field. Challenge = degree-4 binomial extension (~124-bit).
// FRI Merkle: Keccak-256 (vectorized Keccak-f sponge) — conservative hash for
//             the commitment layer, matching Qumbra's consensus hash stance.
// DFT:        Radix2DitParallel.
// ---------------------------------------------------------------------------

type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    2,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

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

fn make_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    assert_eq!(fri_params.conjectured_soundness_bits(), 100);

    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    Config::new(pcs, challenger)
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

fn print_header(power: &str) {
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

    println!("# qumbra-lab M1 hash-matrix bench");
    println!();
    println!("- hardware: {cpu}, {mem_gb} RAM");
    println!("- OS: macOS {os}");
    println!("- qumbra-lab rev: {rev}");
    println!("- prover: Plonky3 0.6.1 (pinned in Cargo.lock)");
    println!("- power state: {power}");
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
    let args: Vec<String> = std::env::args().collect();
    let power = args
        .iter()
        .position(|a| a == "--power")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .unwrap_or("unspecified (record manually: AC/battery, thermal)")
        .to_string();

    let config = make_config();

    // Poseidon2 round constants: fixed seed so every run proves the same AIR.
    let mut rng = SmallRng::seed_from_u64(42);
    let p2_air: QPoseidon2Air = Poseidon2Air::new(RoundConstants::from_rng(&mut rng));
    let keccak_air = KeccakAir {};
    let blake3_air = Blake3Air {};

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
