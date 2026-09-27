//! Issue #750: F2's native hiding-proof census and symbolic pricing tools.
//! These modes do not implement an aggregation circuit or declare a memory pass.
mod counting;
mod price;

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
        "symbolic_air": air, "complete_verifier_layout": false, "memory_gate_pass": false}),
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
                || (mode == "f2census" && key == "--proof-in")
                || (mode == "f2price" && key == "--symbolic-only"),
            &format!("unknown argument {key}"),
        )?;
        if key == "--symbolic-only" {
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
    let report = match mode {
        "f2price" => {
            let air = price::symbolic(shape);
            let chunks = air["hiding_quotient_chunks"]
                .as_u64()
                .ok_or("missing quotient census")? as usize;
            json!({"symbolic_air": air, "projected_opening_schedule": price::geometry(shape, chunks).report(shape),
                "complete_verifier_layout": false, "memory_gate_pass": false})
        }
        "f2census" => census(shape, &read_fixture(Path::new(get("--proof-in")?))?)?,
        "f2fixture" => create_fixture(shape, revision, Path::new(get("--out")?))?,
        _ => return Err("unknown F2 mode".into()),
    };
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
            let fixture = prove_fixture(shape, &"a".repeat(40)).unwrap();
            let report = census(shape, &fixture).unwrap();
            assert_eq!(report["native_verified"], true);
            assert_eq!(report["counting_native_verified"], true);
            assert_eq!(report["memory_gate_pass"], false);
            let g = price::geometry(shape, 8);
            let mut proof: Proof<Config> = codec().deserialize(&fixture.proof).unwrap();
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
