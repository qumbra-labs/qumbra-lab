//! Issue #750: F2's native hiding-proof census and symbolic pricing tools,
//! and F2b-4's `f2wrap` (the full-size C1/C2 of one real leaf: check, or
//! prove under the non-hiding outer lane). No mode declares a memory pass:
//! peak memory is the operator's `/usr/bin/time -v` reading.
mod counting;
pub(crate) mod ood;
pub(crate) mod price;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use bincode::Options;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::{verify, Proof};
use qlab_consensus::{Config, Val, CAP_HEIGHT, IS_ZK, NUM_RANDOM_CODEWORDS, SALT_ELEMS};
use qlab_l2::{Shape, L2_CFG_PROVISIONAL};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, String>;
// Bench fixture cap, not a transaction wire limit. Check before decoding.
const MAX_FIXTURE_BYTES: u64 = 8 * 1024 * 1024;
const FIXTURE_VERSION: u32 = 1;
/// f2wrap's default materialization budget, in field cells: above the
/// largest planned component (P3's C2, 5,107 x 2^18 = 1,338,769,408 cells
/// [P], `price::composed_c2`), about 6 GB of trace values.
const DEFAULT_MAX_CELLS: usize = 1_500_000_000;

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FIXTURE_BYTES)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn shape_name(shape: Shape) -> &'static str {
    match shape {
        Shape::S => "s3",
        Shape::P => "p3",
        Shape::R => "r",
    }
}

fn parse_shape(value: &str) -> Result<Shape> {
    match value {
        "s3" => Ok(Shape::S),
        "p3" => Ok(Shape::P),
        "r" => Ok(Shape::R),
        _ => Err("--shape must be s3|p3|r".into()),
    }
}

fn config_words() -> Vec<usize> {
    let c = L2_CFG_PROVISIONAL;
    vec![
        c.log_blowup,
        c.num_queries,
        c.grind_bits,
        c.log_final_poly_len,
        c.max_log_arity,
        CAP_HEIGHT,
        IS_ZK,
        NUM_RANDOM_CODEWORDS,
        SALT_ELEMS,
        4,
    ]
}

#[derive(Clone, Serialize, Deserialize)]
struct Fixture {
    version: u32,
    shape: String,
    shape_digest: [u8; 32],
    config: Vec<usize>,
    producer_revision: String,
    public_values: Vec<u32>,
    proof: Vec<u8>,
}

impl Fixture {
    fn check_metadata(&self, shape: Shape) -> Result<()> {
        require(
            self.version == FIXTURE_VERSION,
            "unsupported fixture version",
        )?;
        require(self.shape == shape_name(shape), "fixture shape mismatch")?;
        require(
            self.shape_digest == qlab_l2::digest::shape_digest(shape),
            "fixture AIR digest mismatch",
        )?;
        require(
            self.config == config_words(),
            "fixture PCS/lane configuration mismatch",
        )?;
        require(
            valid_revision(&self.producer_revision),
            "invalid producer revision",
        )?;
        require(
            self.public_values.len() == shape.pv_len(),
            "public-value length mismatch",
        )?;
        require(
            self.public_values.iter().all(|v| *v < Val::ORDER_U32),
            "noncanonical public value",
        )
    }
}

fn valid_revision(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit())
}

fn read_fixture(path: &Path) -> Result<Fixture> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    require(
        file.metadata().map_err(|e| e.to_string())?.len() <= MAX_FIXTURE_BYTES,
        "fixture exceeds size cap",
    )?;
    let mut bytes = vec![];
    file.take(MAX_FIXTURE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 <= MAX_FIXTURE_BYTES,
        "fixture exceeds size cap",
    )?;
    codec()
        .deserialize(&bytes)
        .map_err(|e| format!("fixture decode: {e}"))
}

fn native_verify(shape: Shape, pvs: &[Val], proof: &Proof<Config>) -> Result<()> {
    // Malformed foreign proofs must produce a failed command, not a census.
    let valid = catch_unwind(AssertUnwindSafe(|| match shape {
        Shape::S => qlab_l2::verify_s(pvs, proof),
        Shape::P => qlab_l2::verify_p(pvs, proof),
        Shape::R => qlab_l2::verify_r(pvs, proof),
    }))
    .unwrap_or(false);
    require(valid, "native L2 verification failed")
}

fn validate_geometry(shape: Shape, proof: &Proof<Config>, g: &price::Geometry) -> Result<()> {
    let cfg = L2_CFG_PROVISIONAL;
    let o = &proof.opened_values;
    require(
        proof.degree_bits == shape.log_height() + IS_ZK,
        "committed degree mismatch",
    )?;
    require(
        o.trace_local.len() == shape.width()
            && o.trace_next
                .as_ref()
                .is_some_and(|r| r.len() == shape.width()),
        "trace opening shape mismatch",
    )?;
    require(
        o.preprocessed_local.is_none() && o.preprocessed_next.is_none(),
        "unexpected preprocessing",
    )?;
    require(
        o.random.as_ref().is_some_and(|r| r.len() == 4),
        "missing or malformed randomizer OOD opening",
    )?;
    require(
        o.quotient_chunks.len() == g.chunks && o.quotient_chunks.iter().all(|r| r.len() == 4),
        "quotient opening shape mismatch",
    )?;
    let caps = 1usize << CAP_HEIGHT;
    require(
        proof.commitments.trace.roots().len() == caps
            && proof.commitments.quotient_chunks.roots().len() == caps
            && proof
                .commitments
                .random
                .as_ref()
                .is_some_and(|c| c.roots().len() == caps),
        "input cap shape mismatch",
    )?;
    let (random_openings, fri) = &proof.opening_proof;
    let matrices = [1, 1, g.chunks];
    let points = [1, 2, 1];
    require(
        random_openings.len() == matrices.len(),
        "rc0 opening round count mismatch",
    )?;
    for ((round, count), point_count) in random_openings.iter().zip(matrices).zip(points) {
        require(round.len() == count, "rc0 matrix count mismatch")?;
        for matrix in round {
            require(
                matrix.len() == point_count && matrix.iter().all(Vec::is_empty),
                "rc0 point nesting or width mismatch",
            )?;
        }
    }
    require(
        fri.commit_phase_commits.len() == g.log_arities.len()
            && fri
                .commit_phase_commits
                .iter()
                .all(|c| c.roots().len() == caps),
        "FRI cap shape mismatch",
    )?;
    require(
        fri.commit_pow_witnesses.len() == g.log_arities.len(),
        "FRI commit witness count mismatch",
    )?;
    require(
        fri.final_poly.len() == 1usize << cfg.log_final_poly_len,
        "final polynomial shape mismatch",
    )?;
    require(
        fri.query_proofs.len() == cfg.num_queries,
        "query count mismatch",
    )?;
    for query in &fri.query_proofs {
        require(
            query.input_proof.len() == matrices.len(),
            "query input round count mismatch",
        )?;
        for (r, batch) in query.input_proof.iter().enumerate() {
            let width = if r == 1 { shape.width() } else { 4 };
            require(
                batch.opened_values.len() == matrices[r]
                    && batch.opened_values.iter().all(|row| row.len() == width),
                "input query matrix shape mismatch",
            )?;
            let (salts, path) = &batch.opening_proof;
            require(
                salts.len() == matrices[r] && salts.iter().all(|s| s.len() == SALT_ELEMS),
                "input salt shape mismatch",
            )?;
            require(
                path.len() == g.input_path,
                "input Merkle path length mismatch",
            )?;
        }
        require(
            query.commit_phase_openings.len() == g.log_arities.len(),
            "FRI opening count mismatch",
        )?;
        for (r, step) in query.commit_phase_openings.iter().enumerate() {
            let (salts, path) = &step.opening_proof;
            require(
                usize::from(step.log_arity) == g.log_arities[r]
                    && step.sibling_values.len() == (1usize << g.log_arities[r]) - 1,
                "FRI fold shape mismatch",
            )?;
            require(
                salts.len() == 1 && salts[0].len() == SALT_ELEMS,
                "FRI salt shape mismatch",
            )?;
            require(path.len() == g.fri_paths[r], "FRI path length mismatch")?;
        }
    }
    Ok(())
}

fn census(shape: Shape, fixture: &Fixture) -> Result<Value> {
    fixture.check_metadata(shape)?;
    let proof: Proof<Config> = codec()
        .deserialize(&fixture.proof)
        .map_err(|e| format!("proof decode: {e}"))?;
    let air = price::symbolic(shape);
    let chunks = air["hiding_quotient_chunks"]
        .as_u64()
        .ok_or("missing quotient census")? as usize;
    let geometry = price::geometry(shape, chunks);
    validate_geometry(shape, &proof, &geometry)?;
    let pvs: Vec<Val> = fixture
        .public_values
        .iter()
        .copied()
        .map(Val::from_u32)
        .collect();
    native_verify(shape, &pvs, &proof)?;
    let ood = ood::verify_relation(shape, &proof, &pvs)?;
    // Both configurations consume exactly the same proof bytes. No proving
    // under the counting config and no alternate fixture construction.
    let counted_proof: Proof<counting::Config> = codec()
        .deserialize(&fixture.proof)
        .map_err(|e| e.to_string())?;
    require(
        codec()
            .serialize(&counted_proof)
            .map_err(|e| e.to_string())?
            == fixture.proof,
        "counting config changed proof encoding",
    )?;
    let counters = counting::Counters::default();
    let config = counters.config();
    let valid = catch_unwind(AssertUnwindSafe(|| match shape {
        Shape::S => verify(&config, &qlab_l2::verifier_air_s(), &counted_proof, &pvs).is_ok(),
        Shape::P => verify(&config, &qlab_l2::verifier_air_p(), &counted_proof, &pvs).is_ok(),
        Shape::R => verify(&config, &qlab_l2::verifier_air_r(), &counted_proof, &pvs).is_ok(),
    }))
    .unwrap_or(false);
    require(valid, "counting native verification failed")?;
    let counts = counters.report();
    require(
        counts["leaf_absorb_permutations"]
            == geometry.leaf_per_query * L2_CFG_PROVISIONAL.num_queries,
        "measured leaf permutations disagree with projection",
    )?;
    require(
        counts["path_compression_permutations"]
            == geometry.compress_per_query * L2_CFG_PROVISIONAL.num_queries,
        "measured path permutations disagree with projection",
    )?;
    require(
        counts["challenger_permutations"].as_u64().unwrap() >= geometry.fs_floor as u64,
        "measured transcript is below the projected floor",
    )?;
    Ok(
        json!({"native_verified": true, "counting_native_verified": true,
        "fixture_producer_revision": fixture.producer_revision,
        "proof_bytes": {"evidence": "M", "value": fixture.proof.len()},
        "measured_hash_work": counts, "projected_opening_schedule": geometry.report(shape),
        "symbolic_air": air, "ood_algebra": ood, "complete_verifier_layout": false, "memory_gate_pass": false}),
    )
}

fn prove_fixture(shape: Shape, revision: &str) -> Result<Fixture> {
    let (pvs, proof) = match shape {
        Shape::S => qlab_l2::prove_s(&qlab_l2::fixture::shape_s3_merge_at(shape.log_height())),
        Shape::P => qlab_l2::prove_p(&qlab_l2::fixture::shape_p3_merge_at(shape.log_height())),
        Shape::R => qlab_l2::prove_r(&qlab_l2::fixture::shape_r()),
    };
    native_verify(shape, &pvs, &proof)?;
    Ok(Fixture {
        version: FIXTURE_VERSION,
        shape: shape_name(shape).into(),
        shape_digest: qlab_l2::digest::shape_digest(shape),
        config: config_words(),
        producer_revision: revision.into(),
        public_values: pvs.iter().map(PrimeField32::as_canonical_u32).collect(),
        proof: codec().serialize(&proof).map_err(|e| e.to_string())?,
    })
}

fn create_fixture(shape: Shape, revision: &str, out: &Path) -> Result<Value> {
    require(
        !out.exists(),
        "output already exists; refusing to overwrite a fixture",
    )?;
    eprintln!("f2fixture: generating a full-height hiding proof; run only on the coordinator's memory-qualified rig");
    let fixture = prove_fixture(shape, revision)?;
    let bytes = codec().serialize(&fixture).map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 <= MAX_FIXTURE_BYTES,
        "generated fixture exceeds size cap",
    )?;
    // create_new also closes the race after the preflight exists check.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"native_verified": true, "fixture_bytes": {"evidence": "M", "value": bytes.len()},
        "proof_bytes": {"evidence": "M", "value": fixture.proof.len()},
        "public_data_only": true, "complete_verifier_layout": false, "memory_gate_pass": false}),
    )
}

fn options<'a>(mode: &str, args: &'a [String]) -> Result<BTreeMap<&'a str, &'a str>> {
    let mut result = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        if key == mode {
            i += 1;
            continue;
        }
        require(
            matches!(
                key,
                "--shape" | "--revision" | "--power" | "--report" | "--input-pcs" | "--rc"
            ) || (mode == "f2fixture" && key == "--out")
                || (matches!(mode, "f2census" | "f2wrap") && key == "--proof-in")
                || (mode == "f2price" && key == "--symbolic-only")
                || (mode == "f2wrap"
                    && matches!(
                        key,
                        "--check" | "--prove" | "--outer" | "--component" | "--max-cells"
                    )),
            &format!("unknown argument {key}"),
        )?;
        if matches!(key, "--symbolic-only" | "--check" | "--prove") {
            require(result.insert(key, "true").is_none(), "duplicate argument")?;
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .as_str();
        require(
            !value.starts_with("--"),
            &format!("missing value for {key}"),
        )?;
        require(result.insert(key, value).is_none(), "duplicate argument")?;
        i += 2;
    }
    require(
        result.get("--report").is_none_or(|s| *s == "json"),
        "--report must be json",
    )?;
    require(
        result.get("--input-pcs").is_none_or(|s| *s == "hiding"),
        "input PCS must be hiding",
    )?;
    require(
        result.get("--rc").is_none_or(|s| *s == "0"),
        "only current rc0 is supported",
    )?;
    require(
        NUM_RANDOM_CODEWORDS == 0 && IS_ZK == 1,
        "unsupported live PCS; recensus required",
    )?;
    Ok(result)
}

pub(crate) fn run(mode: &str, args: &[String], power: &str) -> Result<()> {
    let opts = options(mode, args)?;
    let get = |key| {
        opts.get(key)
            .copied()
            .ok_or_else(|| format!("{key} is required"))
    };
    let shape = parse_shape(get("--shape")?)?;
    let revision = get("--revision")?;
    require(
        valid_revision(revision),
        "--revision must be the full build commit (40 hex characters)",
    )?;
    if mode == "f2wrap" {
        // Refused before the fixture is read or anything is allocated.
        let (wrap_mode, max_cells) = wrap_options(&opts)?;
        let plan = ood::wrap::Plan::of(shape)?;
        plan.admit(max_cells)?;
        let fixture = read_fixture(Path::new(get("--proof-in")?))?;
        let (proof, pvs) = verified_leaf(shape, &fixture)?;
        let report = ood::wrap::run(shape, &proof, &pvs, plan, wrap_mode, max_cells)?;
        let pass = report["all_pass"] == true;
        let report = json!({"plan": plan.report(), "max_cells": max_cells,
            "fixture_producer_revision": fixture.producer_revision,
            "memory_gate_pass": false,
            "memory_gate_note": "decided from the operator's /usr/bin/time -v peak RSS (GiB = KiB / 1024^2) against 60 GiB, and separately 32 GiB; never in-process",
            "result": report});
        print_envelope(mode, shape, revision, power, report)?;
        return require(pass, "f2wrap: one or more checks failed (see the report)");
    }
    let report = match mode {
        "f2price" => {
            let air = price::symbolic(shape);
            let chunks = air["hiding_quotient_chunks"]
                .as_u64()
                .ok_or("missing quotient census")? as usize;
            json!({"symbolic_air": air, "projected_opening_schedule": price::geometry(shape, chunks).report(shape),
                "input_openings": price::input_openings(shape.width(), shape.log_height(), chunks,
                    L2_CFG_PROVISIONAL.num_queries),
                "query_phase": price::query_phase(shape.log_height(), L2_CFG_PROVISIONAL.num_queries),
                "ood_arithmetic": ood::price(shape)?,
                "composed_c1": price::composed_c1(shape)?,
                "composed_c2": price::composed_c2(shape),
                "complete_verifier_layout": false, "memory_gate_pass": false})
        }
        "f2census" => census(shape, &read_fixture(Path::new(get("--proof-in")?))?)?,
        "f2fixture" => create_fixture(shape, revision, Path::new(get("--out")?))?,
        _ => return Err("unknown F2 mode".into()),
    };
    print_envelope(mode, shape, revision, power, report)
}

/// The f2wrap stage and budget: exactly one of `--check` / `--prove`;
/// `--outer b2|b4` with `--prove` only; `--component` (default both) with
/// `--prove` only; `--max-cells` a positive cell count (default
/// [`DEFAULT_MAX_CELLS`]).
fn wrap_options(opts: &BTreeMap<&str, &str>) -> Result<(ood::wrap::Mode, usize)> {
    let (check, prove) = (opts.contains_key("--check"), opts.contains_key("--prove"));
    require(
        check != prove,
        "f2wrap needs exactly one of --check / --prove",
    )?;
    require(
        opts.contains_key("--proof-in"),
        "--proof-in is required (an f2fixture envelope)",
    )?;
    let max_cells = match opts.get("--max-cells") {
        None => DEFAULT_MAX_CELLS,
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
            .ok_or("--max-cells must be a positive integer")?,
    };
    let mode = if check {
        require(
            !opts.contains_key("--outer") && !opts.contains_key("--component"),
            "--outer / --component apply to --prove only",
        )?;
        ood::wrap::Mode::Check
    } else {
        let outer =
            ood::wrap::Outer::parse(opts.get("--outer").ok_or("--prove needs --outer b2|b4")?)?;
        let component = opts
            .get("--component")
            .map_or(Ok(ood::wrap::Component::Both), |c| {
                ood::wrap::Component::parse(c)
            })?;
        ood::wrap::Mode::Prove(outer, component)
    };
    Ok((mode, max_cells))
}

/// A fixture's leaf, decoded and natively verified exactly as `f2census`
/// admits it (metadata, geometry, the live L2 verifier).
fn verified_leaf(shape: Shape, fixture: &Fixture) -> Result<(Proof<Config>, Vec<Val>)> {
    fixture.check_metadata(shape)?;
    let proof: Proof<Config> = codec()
        .deserialize(&fixture.proof)
        .map_err(|e| format!("proof decode: {e}"))?;
    let chunks = price::symbolic(shape)["hiding_quotient_chunks"]
        .as_u64()
        .ok_or("missing quotient census")? as usize;
    validate_geometry(shape, &proof, &price::geometry(shape, chunks))?;
    let pvs: Vec<Val> = fixture
        .public_values
        .iter()
        .copied()
        .map(Val::from_u32)
        .collect();
    native_verify(shape, &pvs, &proof)?;
    Ok((proof, pvs))
}

fn print_envelope(
    mode: &str,
    shape: Shape,
    revision: &str,
    power: &str,
    report: Value,
) -> Result<()> {
    let output = json!({"schema": "qumbra-f2-census-v1", "mode": mode, "shape": shape_name(shape),
        "build_revision_declared_by_operator": revision,
        "shape_digest": qlab_l2::digest::shape_digest(shape), "config_words": config_words(),
        "config_words_order": ["log_blowup", "queries", "grind_bits", "log_final_poly", "max_log_arity",
            "cap_height", "is_zk", "random_codewords", "salt_elements", "extension_degree"],
        "plonky3": "0.6.1", "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "power_note": power, "report": report});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// One real hiding S3 fixture per test binary. The census test and F2b-2b-iii's
/// production-schedule test (`ood/fold.rs`) share it, so CI proves S3 once
/// (≈ 26 s, ≈ 14 GiB peak on the rig, the census test's existing cost).
#[cfg(test)]
fn s3_fixture() -> &'static Fixture {
    static S3: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
    S3.get_or_init(|| prove_fixture(Shape::S, &"a".repeat(40)).unwrap())
}

/// The shared S3 fixture's proof and public values, decoded.
#[cfg(test)]
fn s3_proof() -> (Proof<Config>, Vec<Val>) {
    let f = s3_fixture();
    let proof = codec().deserialize(&f.proof).unwrap();
    (
        proof,
        f.public_values.iter().copied().map(Val::from_u32).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_refuse_silent_lane_changes_and_proving_from_census() {
        for suffix in [
            "--rc 4",
            "--input-pcs plain",
            "--report csv",
            "--out proof",
            "--shape",
            "--shape p3 --shape r",
        ] {
            let args = format!("f2census {suffix}")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(options("f2census", &args).is_err(), "{suffix}");
        }
        assert!(parse_shape("s").is_err());
        assert!(!valid_revision("main"));
    }

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn wrap(suffix: &str) -> Result<(ood::wrap::Mode, usize)> {
        let args = words(&format!("f2wrap --shape s3 {suffix}"));
        wrap_options(&options("f2wrap", &args)?)
    }

    #[test]
    fn f2wrap_options_take_exactly_one_stage_and_a_positive_budget() {
        use ood::wrap::{Component, Mode, Outer};
        assert_eq!(
            wrap("--proof-in f --check").unwrap(),
            (Mode::Check, DEFAULT_MAX_CELLS)
        );
        assert_eq!(
            wrap("--proof-in f --prove --outer b2").unwrap(),
            (Mode::Prove(Outer::B2, Component::Both), DEFAULT_MAX_CELLS)
        );
        assert_eq!(
            wrap("--proof-in f --prove --outer b4 --component c2 --max-cells 7").unwrap(),
            (Mode::Prove(Outer::B4, Component::C2), 7)
        );
        for suffix in [
            "--proof-in f",
            "--proof-in f --check --prove --outer b2",
            "--check",
            "--proof-in f --check --outer b2",
            "--proof-in f --check --component c1",
            "--proof-in f --prove",
            "--proof-in f --prove --outer b8",
            "--proof-in f --prove --outer b2 --component c3",
            "--proof-in f --check --max-cells 0",
            "--proof-in f --check --max-cells -5",
            "--proof-in f --check --max-cells lots",
            "--proof-in f --check --max-cells",
            "--proof-in f --check --check",
            "--proof-in f --check --out x",
            "--proof-in f --check --symbolic-only",
            "--proof-in f --check --input-pcs plain",
            "--proof-in f --check --rc 4",
        ] {
            assert!(wrap(suffix).is_err(), "{suffix}");
        }
        // The stage flags belong to f2wrap alone.
        for mode in ["f2census", "f2fixture", "f2price"] {
            let args = words(&format!("{mode} --shape s3 --check"));
            assert!(options(mode, &args).is_err(), "{mode}");
        }
    }

    /// An over-budget plan is refused before the fixture is even opened (the
    /// path does not exist); at the default budget the same command gets as
    /// far as reading it.
    #[test]
    fn f2wrap_refuses_an_over_budget_plan_before_reading_the_fixture() {
        let rev = "a".repeat(40);
        let base = format!(
            "f2wrap --shape s3 --revision {rev} --proof-in /nonexistent/f2wrap-fixture --check"
        );
        let err = run(
            "f2wrap",
            &words(&format!("{base} --max-cells 1000")),
            "test",
        )
        .unwrap_err();
        assert!(
            err.contains("exceeds --max-cells 1000") && err.contains("nothing allocated"),
            "{err}"
        );
        let err = run("f2wrap", &words(&base), "test").unwrap_err();
        assert!(!err.contains("exceeds"), "{err}");
    }

    #[test]
    fn fixture_metadata_binds_shape_config_and_canonical_public_values() {
        let shape = Shape::S;
        let mut f = Fixture {
            version: FIXTURE_VERSION,
            shape: "s3".into(),
            shape_digest: qlab_l2::digest::shape_digest(shape),
            config: config_words(),
            producer_revision: "a".repeat(40),
            public_values: vec![0; shape.pv_len()],
            proof: vec![],
        };
        assert!(f.check_metadata(shape).is_ok());
        assert!(f.check_metadata(Shape::P).is_err());
        f.config[7] = 4;
        assert!(f.check_metadata(shape).is_err());
        f.config = config_words();
        f.public_values[0] = Val::ORDER_U32;
        assert!(f.check_metadata(shape).is_err());
        f.public_values[0] = 0;
        f.shape_digest[0] ^= 1;
        assert!(f.check_metadata(shape).is_err());
    }

    // CI only, like every cargo test in this repository. Prove sequentially
    // so the P3 producer peak is not combined with another shape's trace.
    #[test]
    fn real_hiding_proofs_cross_verify_count_and_reject_mutations() {
        for shape in [Shape::S, Shape::P, Shape::R] {
            let fixture = match shape {
                Shape::S => s3_fixture().clone(),
                _ => prove_fixture(shape, &"a".repeat(40)).unwrap(),
            };
            let report = census(shape, &fixture).unwrap();
            assert_eq!(report["native_verified"], true);
            assert_eq!(report["counting_native_verified"], true);
            assert_eq!(report["ood_algebra"]["residual_zero"], true);
            assert_eq!(report["memory_gate_pass"], false);
            let g = price::geometry(shape, 8);
            let mut proof: Proof<Config> = codec().deserialize(&fixture.proof).unwrap();
            let pvs: Vec<_> = fixture
                .public_values
                .iter()
                .copied()
                .map(Val::from_u32)
                .collect();
            ood::check_real_mutations(shape, &proof, &pvs);
            if shape == Shape::P {
                // F2b-5: P3's fifth, arity-2 fold round under C2, on this proof.
                ood::check_p3_last_round(&proof, &pvs);
            }
            // F2b-5: the path, point and fold-shape lengths `f2wrap` relies on
            // `validate_geometry` for, each refused by name (the salt, rc0
            // and randomizer cases follow below).
            type Edit = fn(&mut Proof<Config>);
            let named: [(Edit, &str); 7] = [
                (
                    |p| {
                        p.opened_values
                            .trace_local
                            .push(qlab_consensus::Challenge::ZERO)
                    },
                    "trace opening shape mismatch",
                ),
                (
                    |p| {
                        p.opened_values
                            .random
                            .as_mut()
                            .unwrap()
                            .push(qlab_consensus::Challenge::ZERO)
                    },
                    "missing or malformed randomizer OOD opening",
                ),
                (
                    |p| p.opened_values.quotient_chunks[0].push(qlab_consensus::Challenge::ZERO),
                    "quotient opening shape mismatch",
                ),
                (
                    |p| {
                        p.opening_proof.1.query_proofs[0].input_proof[2]
                            .opening_proof
                            .1
                            .pop();
                    },
                    "input Merkle path length mismatch",
                ),
                (
                    |p| {
                        p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                            .opening_proof
                            .1
                            .pop();
                    },
                    "FRI path length mismatch",
                ),
                (
                    |p| {
                        p.opening_proof.1.query_proofs[0].commit_phase_openings[1]
                            .opening_proof
                            .0[0]
                            .pop();
                    },
                    "FRI salt shape mismatch",
                ),
                (
                    |p| {
                        let q = &mut p.opening_proof.1.query_proofs[0];
                        q.commit_phase_openings.last_mut().unwrap().log_arity ^= 1;
                    },
                    "FRI fold shape mismatch",
                ),
            ];
            for (edit, name) in named {
                let mut bad: Proof<Config> = codec().deserialize(&fixture.proof).unwrap();
                edit(&mut bad);
                assert_eq!(validate_geometry(shape, &bad, &g).unwrap_err(), name);
            }
            let random = proof.commitments.random.take();
            assert!(validate_geometry(shape, &proof, &g).is_err());
            proof.commitments.random = random;
            let salt = proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0[0]
                .pop()
                .unwrap();
            assert!(validate_geometry(shape, &proof, &g).is_err());
            proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0[0]
                .push(salt);
            proof.opening_proof.0[0][0][0].push(qlab_consensus::Challenge::ONE);
            assert!(validate_geometry(shape, &proof, &g).is_err());
            proof.opening_proof.0[0][0][0].clear();
            if shape == Shape::P {
                let last = proof.opening_proof.1.query_proofs[0]
                    .commit_phase_openings
                    .pop()
                    .unwrap();
                assert!(validate_geometry(shape, &proof, &g).is_err());
                proof.opening_proof.1.query_proofs[0]
                    .commit_phase_openings
                    .push(last);
            }
            assert!(validate_geometry(shape, &proof, &g).is_ok());
            // Preserve dimensions: only native verification can reject this.
            proof.opened_values.random.as_mut().unwrap()[0] += qlab_consensus::Challenge::ONE;
            let mut bad = fixture.clone();
            bad.proof = codec().serialize(&proof).unwrap();
            assert!(census(shape, &bad).is_err());
            bad = fixture.clone();
            bad.public_values[0] ^= 1;
            assert!(census(shape, &bad).is_err());
        }
    }

    #[test]
    fn codec_rejects_trailing_bytes_and_unknown_fixture_version() {
        let mut f = Fixture {
            version: FIXTURE_VERSION + 1,
            shape: "r".into(),
            shape_digest: [0; 32],
            config: config_words(),
            producer_revision: "b".repeat(40),
            public_values: vec![],
            proof: vec![],
        };
        assert!(f.check_metadata(Shape::R).is_err());
        f.version = FIXTURE_VERSION;
        let mut bytes = codec().serialize(&f).unwrap();
        bytes.push(0);
        assert!(codec().deserialize::<Fixture>(&bytes).is_err());
    }
}
