//! `zkpeak` mode (the security re-mint): one real
//! zero-knowledge prove of the heaviest single case, for sizing the
//! acceptance runner and the laptop story under the hiding PCS.
//!
//! ```text
//! /usr/bin/time -l qlab-bench zkpeak --case l1   # the 2×2 bucket at CONSENSUS_CFG
//! /usr/bin/time -l qlab-bench zkpeak --case p19  # CANARY: shape P's AIR chain-only at 2^19
//! /usr/bin/time -l qlab-bench zkpeak --case p    # shape P (fixture) at the L2 lane, b4
//! ```
//!
//! **Order l1 → p19 → p.** The W3 canary rule: start `p` (2^20) only if the
//! canary's peak footprint × 2 stays under ~28 GB.
//!
//! One case per process, one prove, one verify: the peak footprint of the
//! wrapping `/usr/bin/time -l` IS the case's. Prints the proof's bincode
//! (the wire) length so the pending `WIRE_BYTES` pin can be taken from it.
//!
//! `--phases` (lab #742, A5 lever 4a) adds a per-phase heap account of the
//! prove — live bytes at each Plonky3 prover span boundary and the peak inside
//! each phase — from a counting allocator. It needs the bench build
//! `--features phasemem` (see `phasemem.rs`); without it the flag is refused
//! by name rather than silently ignored.
//!
//! ```text
//! cargo build --release -p qlab-bench --features phasemem
//! /usr/bin/time -v target/release/qlab-bench zkpeak --case p --phases
//! ```
//!
//! `--rc N` (lab #742 / #747, cases `l1` and `p`) proves under
//! `qlab_consensus::make_config_with_rc` — the same config with `N` hiding
//! random codewords instead of the constant — and verifies under the same `N`,
//! so the peak (with `--phases`) and the wire bytes of an rc variant can be read
//! before the constant moves. It calls `p3_uni_stark::prove` directly with the
//! instance's own public values; `--rc` equal to the constant reproduces the
//! default path.

use std::time::Instant;

use p3_field::PrimeCharacteristicRing;

pub(crate) fn run_zkpeak(power: &str, case: &str, phases: bool, rc: Option<usize>) {
    if phases && !cfg!(feature = "phasemem") {
        eprintln!("zkpeak: `--phases` needs the bench build `cargo build --release -p qlab-bench --features phasemem`");
        std::process::exit(2);
    }
    println!("# qumbra-lab zkpeak — case `{case}` under the hiding PCS (IS_ZK = {})", qlab_consensus::IS_ZK);
    println!();
    crate::print_env(power);
    #[cfg(feature = "phasemem")]
    let account = phases.then(crate::phasemem::install);
    // The root window: the fixture build and trace generation show up as the
    // `· between (before `prove`)` row under it, verify + serialization as its
    // closing `· between (to its end)` row.
    #[cfg(feature = "phasemem")]
    let root = phases.then(|| tracing::info_span!("zkpeak case (prove, then verify)").entered());
    let (label, prove_s, verify_ok, bytes) = match (case, rc) {
        ("l1", Some(rc)) => {
            let (inst, _) = crate::m4gaterec::bucket_instance_seeded(0xfeed_face_cafe_beef);
            let cfg = qlab_consensus::CONSENSUS_CFG;
            let pvs = qlab_consensus::public_values(&inst);
            let trace = inst.air.generate_trace::<qlab_consensus::Val>(cfg.log_blowup);
            let t = Instant::now();
            let proof = p3_uni_stark::prove(&qlab_consensus::make_config_with_rc(&cfg, rc), &inst.air, trace, &pvs);
            let secs = t.elapsed().as_secs_f64();
            let ok = p3_uni_stark::verify(&qlab_consensus::make_config_with_rc(&cfg, rc), &inst.air, &proof, &pvs).is_ok();
            let bytes = bincode::serialize(&proof).expect("bincode").len();
            (format!("L1 2×2 bucket @ {} (2^{}), rc = {rc}", cfg.label(), qlab_consensus::LOG_HEIGHT), secs, ok, bytes)
        }
        ("p", Some(rc)) => {
            let inst = qlab_l2::fixture::shape_p();
            let cfg = qlab_l2::L2_CFG_PROVISIONAL;
            let pvs = qlab_l2::public_values(&inst.pvs);
            let trace = inst.air.generate_trace::<qlab_l2::Val>(cfg.log_blowup);
            let t = Instant::now();
            let proof = p3_uni_stark::prove(&qlab_consensus::make_config_with_rc(&cfg, rc), &inst.air, trace, &pvs);
            let secs = t.elapsed().as_secs_f64();
            let ok = p3_uni_stark::verify(&qlab_consensus::make_config_with_rc(&cfg, rc), &qlab_l2::verifier_air_p(), &proof, &pvs)
                .is_ok();
            let bytes = bincode::serialize(&proof).expect("bincode").len();
            (format!("shape P @ {} (2^{}), rc = {rc}", cfg.label(), qlab_l2::LOG_HEIGHT_P), secs, ok, bytes)
        }
        (_, Some(_)) => {
            eprintln!("zkpeak: `--rc` is implemented for `--case l1|p` only");
            std::process::exit(2);
        }
        ("l1", None) => {
            let (inst, _) = crate::m4gaterec::bucket_instance_seeded(0xfeed_face_cafe_beef);
            let t = Instant::now();
            let (pvs, proof) = qlab_consensus::prove_bucket(&inst);
            let secs = t.elapsed().as_secs_f64();
            let ok = qlab_consensus::verify_proof(&inst, &pvs, &proof);
            let bytes = bincode::serialize(&proof).expect("bincode").len();
            (format!("L1 2×2 bucket @ {} (2^{})", qlab_consensus::CONSENSUS_CFG.label(), qlab_consensus::LOG_HEIGHT), secs, ok, bytes)
        }
        ("p", None) => {
            let inst = qlab_l2::fixture::shape_p();
            let t = Instant::now();
            let (pvs, proof) = qlab_l2::prove_p(&inst);
            let secs = t.elapsed().as_secs_f64();
            let ok = qlab_l2::verify_p(&pvs, &proof);
            let bytes = bincode::serialize(&proof).expect("bincode").len();
            (format!("shape P @ {} (2^{})", qlab_l2::L2_CFG_PROVISIONAL.label(), qlab_l2::LOG_HEIGHT_P), secs, ok, bytes)
        }
        ("p19", None) => {
            use p3_air::BaseAir;
            use qlab_air::l2p::L2ShapePAir;
            let air = L2ShapePAir::chain_only(qlab_l2::LOG_HEIGHT_P - 1);
            let pvs = vec![qlab_l2::Val::ZERO; <L2ShapePAir as BaseAir<qlab_l2::Val>>::num_public_values(&air)];
            let config = qlab_l2::make_config_l2();
            let trace = air.generate_trace::<qlab_l2::Val>(qlab_l2::L2_CFG_PROVISIONAL.log_blowup);
            let t = Instant::now();
            let proof = p3_uni_stark::prove(&config, &air, trace, &pvs);
            let secs = t.elapsed().as_secs_f64();
            let ok = p3_uni_stark::verify(&qlab_l2::make_config_l2(), &air, &proof, &pvs).is_ok();
            let bytes = bincode::serialize(&proof).expect("bincode").len();
            (
                format!("CANARY: shape-P AIR chain-only @ {} (2^{})", qlab_l2::L2_CFG_PROVISIONAL.label(), qlab_l2::LOG_HEIGHT_P - 1),
                secs,
                ok,
                bytes,
            )
        }
        (other, None) => {
            eprintln!("zkpeak: unknown --case `{other}`; expected l1|p19|p");
            std::process::exit(2);
        }
    };
    #[cfg(feature = "phasemem")]
    if let Some(account) = account {
        drop(root);
        println!("## Phase heap account (bytes live in the Rust allocator; not RSS)");
        println!();
        account.0.print();
        println!();
        println!("_Timings from a `phasemem` build are not publishable: every allocation pays two atomics._");
        println!();
    }
    println!("| case | prove s | verifies | wire bytes (bincode fixint) |");
    println!("|---|---|---|---|");
    println!("| {label} | {prove_s:.2} | {verify_ok} | {bytes} |");
    println!();
    println!("Peak footprint: read `peak memory footprint` from the wrapping `/usr/bin/time -l`.");
    assert!(verify_ok, "the ZK proof must verify");
}
