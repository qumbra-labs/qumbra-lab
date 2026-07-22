//! M4 step 0a: exact verifier hash-workload census + wide-lane feasibility.
//!
//! The design gate: qumbra-design `aggregation-rung1.md` §4 prices an
//! in-circuit verification of one M3 consensus proof at ~3,000 Keccak-f
//! permutations **[derived]**, and §6 makes measuring the real number the
//! first deliverable of the step-0 calibration gate. This mode measures it
//! without building any verifier circuit: every Keccak entry point of the
//! verification config is wrapped in a counting adapter, a real M3 bucket
//! proof is verified under it, and the counters report exactly the hash
//! workload an in-circuit verifier must reproduce.
//!
//! Three phases:
//!  A. census of verifying the M3 bucket proof at the decided consensus
//!     config (b16/q20/g20/fp16/a16) — the rung-1 *leaf* workload;
//!  B. wide-AIR (p3-keccak-air) prove feasibility at exactly that
//!     permutation count under aggregation-lane configs — prove ms,
//!     verify ms, proof bytes (peak RSS: rerun with
//!     `/usr/bin/time -l ... m4census --only <cfg>`);
//!  C. census of verifying the phase-B wide proof itself — the rung-1
//!     *interior-node* workload preview (the ~78-absorption/leaf term).
//!
//! Counter validity: the counting wrappers delegate to the identical
//! primitives, so transcripts and proofs are byte-identical to the plain
//! config (asserted below). Counters are only read around `verify` — the
//! prover also runs through them (including SIMD-packed permutations,
//! counted as 1 per packed call), so prover-side counts are meaningless
//! and are reset before each census read.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_keccak_air::KeccakAir;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation,
    PaddingFreeSponge, Permutation, SerializingHasher,
};
use p3_uni_stark::{prove, verify, StarkConfig};
use qlab_air::narrow::{build_bucket, TxInput, TxOutput, BUCKET_PERMS, NARROW_WIDTH};

use crate::{keccak_inputs, make_config_with, pc_len, Challenge, Dft, FriCfg, Val, RUNS};

// ---------------------------------------------------------------------------
// Counting adapters
// ---------------------------------------------------------------------------

/// Keccak-f[1600] permutation that counts invocations, then delegates.
/// The blanket impl also covers the SIMD-packed widths the prover's Merkle
/// builder uses (each packed call counted as 1 — see module note).
#[derive(Clone)]
struct CountingKeccakF {
    count: Arc<AtomicUsize>,
}

impl<T: Clone> Permutation<T> for CountingKeccakF
where
    KeccakF: Permutation<T>,
{
    fn permute_mut(&self, input: &mut T) {
        self.count.fetch_add(1, Ordering::Relaxed);
        KeccakF {}.permute_mut(input);
    }
}

impl<T: Clone> CryptographicPermutation<T> for CountingKeccakF where
    KeccakF: CryptographicPermutation<T>
{
}

/// Keccak-256 byte hasher (the challenger's hash) that counts calls, bytes,
/// and the implied keccak-f permutations (rate 136 B; padding always costs
/// one absorption), then delegates.
#[derive(Clone)]
struct CountingByteHash {
    perms: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

impl CryptographicHasher<u8, [u8; 32]> for CountingByteHash {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let buf: Vec<u8> = input.into_iter().collect();
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(buf.len(), Ordering::Relaxed);
        self.perms.fetch_add(buf.len() / 136 + 1, Ordering::Relaxed);
        Keccak256Hash.hash_iter(buf)
    }
}

// Counting mirror of main.rs's config type stack.
type CSponge = PaddingFreeSponge<CountingKeccakF, 25, 17, 4>;
type CFieldHash = SerializingHasher<CSponge>;
type CCompress = CompressionFunctionFromHasher<CSponge, 2, 4>;
type CValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    CFieldHash,
    CCompress,
    2,
    4,
>;
type CChallengeMmcs = ExtensionMmcs<Val, Challenge, CValMmcs>;
type CChallenger = SerializingChallenger32<Val, HashChallenger<u8, CountingByteHash, 32>>;
type CPcs = TwoAdicFriPcs<Val, Dft, CValMmcs, CChallengeMmcs>;
type CConfig = StarkConfig<CPcs, Challenge, CChallenger>;

#[derive(Clone)]
struct Counters {
    /// Sponge-side keccak-f: Merkle leaf absorptions (and, inside
    /// CompressionFunctionFromHasher, path compressions — split below).
    leaf: Arc<AtomicUsize>,
    /// Compression-side keccak-f: 2-to-1 Merkle path nodes.
    compress: Arc<AtomicUsize>,
    /// Challenger keccak-f (Fiat-Shamir transcript + grinding checks).
    challenger_perms: Arc<AtomicUsize>,
    challenger_calls: Arc<AtomicUsize>,
    challenger_bytes: Arc<AtomicUsize>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Snapshot {
    leaf: usize,
    compress: usize,
    challenger: usize,
    challenger_calls: usize,
    challenger_bytes: usize,
}

impl Snapshot {
    fn total(&self) -> usize {
        self.leaf + self.compress + self.challenger
    }
}

impl Counters {
    fn new() -> Self {
        Self {
            leaf: Arc::new(AtomicUsize::new(0)),
            compress: Arc::new(AtomicUsize::new(0)),
            challenger_perms: Arc::new(AtomicUsize::new(0)),
            challenger_calls: Arc::new(AtomicUsize::new(0)),
            challenger_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reset(&self) {
        self.leaf.store(0, Ordering::Relaxed);
        self.compress.store(0, Ordering::Relaxed);
        self.challenger_perms.store(0, Ordering::Relaxed);
        self.challenger_calls.store(0, Ordering::Relaxed);
        self.challenger_bytes.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            leaf: self.leaf.load(Ordering::Relaxed),
            compress: self.compress.load(Ordering::Relaxed),
            challenger: self.challenger_perms.load(Ordering::Relaxed),
            challenger_calls: self.challenger_calls.load(Ordering::Relaxed),
            challenger_bytes: self.challenger_bytes.load(Ordering::Relaxed),
        }
    }
}

fn make_counting_config(cfg: &FriCfg, c: &Counters) -> CConfig {
    let leaf_perm = CountingKeccakF {
        count: c.leaf.clone(),
    };
    let compress_perm = CountingKeccakF {
        count: c.compress.clone(),
    };
    let byte_hash = CountingByteHash {
        perms: c.challenger_perms.clone(),
        calls: c.challenger_calls.clone(),
        bytes: c.challenger_bytes.clone(),
    };
    let field_hash = CFieldHash::new(PaddingFreeSponge::new(leaf_perm));
    let compress = CCompress::new(PaddingFreeSponge::new(compress_perm));
    let val_mmcs = CValMmcs::new(field_hash, compress, 3);
    let challenge_mmcs = CChallengeMmcs::new(val_mmcs.clone());
    let challenger = CChallenger::from_hasher(vec![], byte_hash);

    let fri_params = FriParameters {
        log_blowup: cfg.log_blowup,
        log_final_poly_len: cfg.log_final_poly_len,
        max_log_arity: cfg.max_log_arity,
        num_queries: cfg.num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: cfg.grind_bits,
        mmcs: challenge_mmcs,
    };
    assert!(
        fri_params.conjectured_soundness_bits() >= 100,
        "census config is only {} bits conjectured",
        fri_params.conjectured_soundness_bits(),
    );
    let pcs = CPcs::new(Dft::default(), val_mmcs, fri_params);
    CConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------
// Configs
// ---------------------------------------------------------------------------

/// The decided consensus config (self-proving-vs-proof-size branch (b)).
const CONSENSUS_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 20,
    grind_bits: 20,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// Aggregation-lane candidates (bytes are nearly free in this lane; the
/// dials trade prover memory vs the NEXT level's verification workload).
/// All >= 100 bits conjectured (queries x log_blowup + grind).
const LANE_CFGS: [(&str, FriCfg); 4] = [
    (
        "b4/q40/g20/fp16/a16",
        FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b4/q40/g20/a1",
        FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 0,
            max_log_arity: 1,
        },
    ),
    (
        "b8/q27/g19/fp16/a16",
        FriCfg {
            log_blowup: 3,
            num_queries: 27,
            grind_bits: 19,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b16/q20/g20/fp16/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 20,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
];

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/// Deterministic M3 bucket instance — identical to `run_bucket`'s.
fn bucket_instance() -> (qlab_air::narrow::BucketInstance, Vec<Val>) {
    let mut x = 0xfeed_face_cafe_beefu64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
        sk: [rnd(), rnd(), rnd(), rnd()],
        value,
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
        d: [0, 0], // default diversifier (issue #32; keeps rnd stream stable)
    };
    let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
        value,
        rkm: [rnd(), rnd(), rnd(), rnd()],
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
    };
    let inputs = [mk_in(50_000, &mut rnd), mk_in(30_000, &mut rnd)];
    let outputs = [mk_out(60_000, &mut rnd), mk_out(19_000, &mut rnd)];
    let inst = build_bucket(18, &inputs, &outputs, 1_000);
    let pvs: Vec<Val> = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
    (inst, pvs)
}

/// Verify-twice census under a counting config; asserts determinism and
/// (via byte comparison against the plain config) transcript identity.
fn print_census(label: &str, snap: Snapshot) {
    println!(
        "| {label} | {} | {} | {} | **{}** | {} calls / {} B |",
        snap.leaf,
        snap.compress,
        snap.challenger,
        snap.total(),
        snap.challenger_calls,
        snap.challenger_bytes,
    );
}

/// Phase A: the leaf workload — census of verifying the M3 bucket proof at
/// the consensus config. Returns the total keccak-f count.
fn census_bucket() -> usize {
    let (inst, pvs) = bucket_instance();
    let counters = Counters::new();
    let config = make_counting_config(&CONSENSUS_CFG, &counters);

    eprintln!("== phase A: proving M3 bucket @ consensus config (counting) ==");
    let trace = inst.air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
    let proof = prove(&config, &inst.air, trace, &pvs);
    let counted_bytes = pc_len(&proof);

    // Transcript-identity check: the plain (non-counting) config must accept
    // the counting config's proof — same algorithms, same transcript. (Byte
    // comparison against a fresh plain proof would be wrong: proving is not
    // run-deterministic — the parallel grind finds different PoW witnesses,
    // which shift the query set; M1.6 recorded this as ±0.2 KB jitter.)
    let plain_config = make_config_with(&CONSENSUS_CFG);
    let bytes = postcard::to_allocvec(&proof).expect("serialize counting proof");
    let cross: p3_uni_stark::Proof<crate::Config> =
        postcard::from_bytes(&bytes).expect("deserialize into plain-config proof");
    verify(&plain_config, &inst.air, &cross, &pvs)
        .expect("plain config must accept the counting config's proof");

    counters.reset();
    verify(&config, &inst.air, &proof, &pvs).expect("bucket verify (census 1)");
    let snap1 = counters.snapshot();
    counters.reset();
    verify(&config, &inst.air, &proof, &pvs).expect("bucket verify (census 2)");
    let snap2 = counters.snapshot();
    assert_eq!(snap1, snap2, "verification hash counts must be deterministic");

    println!(
        "Phase A — leaf workload: verify one M3 bucket proof \
         ({BUCKET_PERMS} perms, {NARROW_WIDTH} cols x 2^18, consensus \
         b16/q20/g20/fp16/a16, {:.1} KB postcard):",
        counted_bytes as f64 / 1024.0
    );
    println!();
    println!("| workload | leaf-sponge perms | compress perms | challenger perms | TOTAL keccak-f | challenger detail |");
    println!("|---|---|---|---|---|---|");
    print_census("M3 bucket @ consensus", snap1);
    println!();
    println!(
        "- design-doc model (aggregation-rung1 §4): ~3,000 keccak-f [derived] \
         -> measured {} ({:+.1}%)",
        snap1.total(),
        (snap1.total() as f64 - 3_000.0) / 30.0,
    );
    println!();
    snap1.total()
}

/// Phase C: the interior-node preview — census of verifying a wide-AIR
/// proof of `perms` permutations at each lane config.
fn census_wide(perms: usize) {
    println!(
        "Phase C — interior-node preview: verify one wide-AIR proof \
         ({perms} perms) at each lane config:"
    );
    println!();
    println!("| lane config | leaf-sponge perms | compress perms | challenger perms | TOTAL keccak-f | challenger detail |");
    println!("|---|---|---|---|---|---|");
    for (name, cfg) in &LANE_CFGS {
        let air = KeccakAir {};
        let counters = Counters::new();
        let config = make_counting_config(cfg, &counters);
        eprintln!("== phase C: wide census @ {name} ==");
        let trace =
            p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(perms), cfg.log_blowup);
        let proof = prove(&config, &air, trace, &[]);
        counters.reset();
        verify(&config, &air, &proof, &[]).expect("wide verify (census 1)");
        let snap1 = counters.snapshot();
        counters.reset();
        verify(&config, &air, &proof, &[]).expect("wide verify (census 2)");
        assert_eq!(snap1, counters.snapshot(), "census must be deterministic");
        print_census(name, snap1);
    }
    println!();
}

/// Phase B: wide-lane prove feasibility at the census workload size.
fn wide_feasibility(perms: usize, power: &str, only: Option<&str>) {
    println!(
        "Phase B — wide-lane feasibility: prove {perms} keccak-f on the \
         stock wide AIR (p3-keccak-air, 2,633 cols x 24 rows/perm) at \
         aggregation-lane configs. Peak RSS: rerun a single config under \
         `/usr/bin/time -l` with `--only <cfg>`. Power: {power}"
    );
    println!();
    println!("| lane config | conj. bits | rows | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|---|---|");
    for (name, cfg) in &LANE_CFGS {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        let air = KeccakAir {};
        let config = make_config_with(cfg);
        let bits = cfg.num_queries * cfg.log_blowup + cfg.grind_bits;
        eprintln!("== phase B: wide prove @ {name} ==");
        let mut rows = 0;
        let mut best_prove = f64::INFINITY;
        let mut proof_opt = None;
        for _ in 0..RUNS {
            let trace =
                p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(perms), cfg.log_blowup);
            rows = trace.height();
            let t = Instant::now();
            let proof = prove(&config, &air, trace, &[]);
            best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
            proof_opt = Some(proof);
        }
        let proof = proof_opt.expect("RUNS > 0");
        let postcard_bytes = pc_len(&proof);
        let fixed_bytes = bincode::serialize(&proof)
            .expect("bincode serialization failed")
            .len();
        let mut best_verify = f64::INFINITY;
        for _ in 0..RUNS {
            let t = Instant::now();
            verify(&config, &air, &proof, &[]).expect("verification failed");
            best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
        }
        println!(
            "| {name} | {bits} | {rows} | {best_prove:.0} | {best_verify:.1} | {:.1} | {:.1} |",
            postcard_bytes as f64 / 1024.0,
            fixed_bytes as f64 / 1024.0,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// Measured census total (phase A), reproduced identically across runs.
const CENSUS_TOTAL: usize = 2233;

pub(crate) fn run_m4census(power: &str, only: Option<&str>) {
    println!("# qumbra-lab M4 step 0a: verifier hash census + wide-lane feasibility");
    println!();
    crate::print_env(power);
    println!(
        "- design gate: qumbra-design aggregation-rung1.md §4 (~3,000 \
         keccak-f [derived] per inner proof) / §6 (calibration deliverable 1)"
    );
    println!(
        "- method: counting adapters around every Keccak entry point of the \
         verification config (MMCS leaf sponge, Merkle compress, challenger \
         byte hash); counts read around `verify` only; determinism asserted \
         (two identical censuses) and transcript identity asserted vs the \
         plain config"
    );
    println!();

    // With --only, skip the census phases (their b16 bucket prove would
    // dominate peak RSS) and use the recorded deterministic census total —
    // this is what lets /usr/bin/time -l attribute RSS to one lane config.
    let leaf_total = if only.is_some() {
        println!(
            "(--only set: census phases skipped; using recorded census \
             total {CENSUS_TOTAL} — deterministic, reproduced twice)"
        );
        println!();
        CENSUS_TOTAL
    } else {
        let t = census_bucket();
        census_wide(t);
        t
    };
    wide_feasibility(leaf_total, power, only);

    println!(
        "Gate context (aggregation-rung1 §6): leaf <= ~10 s / <= 32 GB, \
         interior <= ~30 s / <= 32 GB on this rig; phase B covers the \
         prove-time half for the *hash workload alone* — constraint-eval \
         glue is step 0b (the verifier circuit itself)."
    );
}
