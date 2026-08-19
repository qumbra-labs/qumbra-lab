//! The golden V1 envelope — prove-class tests (lab #483 stage 1).
//!
//! ⚠️ These prove the disclosure STARK (2^16 rows at the pinned b16/q20/g22).
//! They are the CI lane's to run (memory guardrail): do not run this file on
//! a developer machine. Everything parse-only lives in src/lib.rs against the
//! committed fixtures instead.
//!
//! The instance here is DETERMINISTIC (seeded rng, constant witness), so the
//! envelope it proves is the same bytes on every run — the same instance the
//! `--ignored` generator below mints the committed fixture from, giving the
//! fixture a reproducible provenance (compare the printed Keccak digests).

use qlab_disclosure::air::{build_disclosure, DisclosureInstance};
use qlab_disclosure::envelope::Envelope;
use qlab_note::hash::{digest_bytes, keccak256};
use qlab_note::kem::generate_keypair;
use qlab_vask::{
    qvask_envelope_peek, qvask_verify, Claim, QvaskClaim, DISCLOSURE_V1_CFG,
    DISCLOSURE_V1_LOG_HEIGHT, QVASK_OK, QVASK_PROOF_INVALID,
};
use qlab_wallet::address::{Address, Diversifier};
use rand::{rngs::StdRng, SeedableRng};
use std::ffi::{c_char, CStr};
use std::ptr;

const GOLDEN_VALUE: u64 = 250_000_000;
const GOLDEN_OUTPUT_INDEX: u8 = 2;

fn golden_tx_ref() -> [u8; 32] {
    core::array::from_fn(|i| 0x48 ^ (i as u8).wrapping_mul(3))
}

/// The deterministic golden instance: seed 483 (the tracker), constant
/// witness. Returns the instance and the chain cm a crediting service would
/// have read at (tx_ref, output_index).
fn golden_instance() -> (DisclosureInstance, [u8; 32]) {
    let mut rng = StdRng::seed_from_u64(483);
    let kp = generate_keypair(&mut rng);
    let rkm = [0x4a11u64, 0x5b22, 0x6c33, 0x7d44];
    let addr = Address::new(Diversifier::from_bytes([0x17u8; 16]), rkm, &kp.ek);
    let inst = build_disclosure(
        DISCLOSURE_V1_LOG_HEIGHT,
        GOLDEN_VALUE,
        &rkm,
        &[0x9e1, 0x9e2, 0x9e3, 0x9e4],
        &[0xf51, 0xf52, 0xf53, 0xf54],
        &addr.to_raw_bytes(),
    );
    let chain_cm = digest_bytes(&inst.cm);
    (inst, chain_cm)
}

fn golden_claim(inst: &DisclosureInstance) -> Claim {
    Claim {
        tx_ref: golden_tx_ref(),
        value: GOLDEN_VALUE,
        addr_commitment: digest_bytes(&inst.addr_commitment),
        output_index: GOLDEN_OUTPUT_INDEX,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The whole stage-1 claim in one pass: a real envelope at the PINNED V1
/// config verifies through the Rust surface AND the C ABI, and the two
/// tamper classes an exchange must survive refuse with the right names —
/// wrong chain cm (the verifier read a different output) and a tampered
/// claim body (the forgery shape: the claim lies, the proof doesn't).
#[test]
fn golden_envelope_v1_end_to_end_over_the_abi() {
    let (inst, chain_cm) = golden_instance();
    let env = Envelope::create(&inst, golden_tx_ref(), GOLDEN_OUTPUT_INDEX, &DISCLOSURE_V1_CFG);
    let bytes = env.to_bytes();
    let want = golden_claim(&inst);
    eprintln!(
        "golden envelope: {} B, keccak256 {}",
        bytes.len(),
        hex(&keccak256(&bytes))
    );

    // Rust surface: peek extracts the claim, verify proves it.
    assert_eq!(qlab_vask::peek(&bytes).expect("peek"), want);
    assert_eq!(qlab_vask::verify(&bytes, &chain_cm).expect("verify"), want);

    unsafe {
        // C ABI: the same envelope, the same verdict.
        let mut claim = std::mem::zeroed::<QvaskClaim>();
        let mut reason: *mut c_char = ptr::null_mut();
        assert_eq!(
            qvask_envelope_peek(bytes.as_ptr(), bytes.len(), &mut claim),
            QVASK_OK
        );
        assert_eq!(claim.value, want.value);
        assert_eq!(
            qvask_verify(bytes.as_ptr(), bytes.len(), chain_cm.as_ptr(), &mut claim, &mut reason),
            QVASK_OK
        );
        assert!(reason.is_null(), "no reason on OK");
        assert_eq!(claim.tx_ref, want.tx_ref);
        assert_eq!(claim.value, want.value);
        assert_eq!(claim.addr_commitment, want.addr_commitment);
        assert_eq!(claim.output_index, want.output_index);

        // Wrong chain cm — the verifier read a different output than the
        // claim binds. Refused at rule 2; the claim is still filled (parse
        // succeeded) so the refusal is loggable.
        let mut bad_cm = chain_cm;
        bad_cm[0] ^= 1;
        let mut claim2 = std::mem::zeroed::<QvaskClaim>();
        let mut reason2: *mut c_char = ptr::null_mut();
        assert_eq!(
            qvask_verify(bytes.as_ptr(), bytes.len(), bad_cm.as_ptr(), &mut claim2, &mut reason2),
            QVASK_PROOF_INVALID
        );
        assert_eq!(claim2.value, want.value, "claim filled on parse success");
        assert!(!reason2.is_null(), "refusals carry a reason");
        let why = CStr::from_ptr(reason2).to_str().unwrap();
        assert!(why.contains("proof invalid"), "{why}");
        qlab_vask::qvask_string_free(reason2);

        // Tampered claim body (value): the §3 body is public input to the
        // proof, so a lying claim over an honest proof must refuse.
        let mut tampered = bytes.clone();
        tampered[34] ^= 1; // first byte of value (ver 1 ‖ claim 1 ‖ tx_ref 32)
        let mut claim3 = std::mem::zeroed::<QvaskClaim>();
        let mut reason3: *mut c_char = ptr::null_mut();
        assert_eq!(
            qvask_verify(tampered.as_ptr(), tampered.len(), chain_cm.as_ptr(), &mut claim3, &mut reason3),
            QVASK_PROOF_INVALID
        );
        assert!(!reason3.is_null());
        qlab_vask::qvask_string_free(reason3);
    }
}

/// Mint the committed QVASK_OK fixture (fixtures/README.md's second half).
/// `--ignored` on purpose: one prove at the pinned config — run on CI-class
/// iron, commit the two files it writes, and un-ignore
/// `committed_golden_fixture_verifies` in the same commit.
#[test]
#[ignore = "mints fixtures/golden-envelope-v1.bin — one prove; run on CI-class iron and commit the outputs"]
fn mint_golden_fixture_files() {
    let (inst, chain_cm) = golden_instance();
    let env = Envelope::create(&inst, golden_tx_ref(), GOLDEN_OUTPUT_INDEX, &DISCLOSURE_V1_CFG);
    let bytes = env.to_bytes();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::write(dir.join("golden-envelope-v1.bin"), &bytes).expect("write envelope");
    std::fs::write(dir.join("golden-chain-cm-v1.bin"), chain_cm).expect("write chain cm");
    println!(
        "golden-envelope-v1.bin: {} B, keccak256 {}",
        bytes.len(),
        hex(&keccak256(&bytes))
    );
    println!("golden-chain-cm-v1.bin: {}", hex(&chain_cm));
}

/// The committed fixture verifies through the ABI without any prover — the
/// check a foreign consumer can replicate. Un-ignored in the same commit
/// that landed the fixture files (minted by `mint_golden_fixture_files` on
/// the hosted arm64 lane, run 32205863216; digests in fixtures/README.md).
#[test]
fn committed_golden_fixture_verifies() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let bytes = std::fs::read(dir.join("golden-envelope-v1.bin"))
        .expect("fixtures/golden-envelope-v1.bin not committed yet — run mint_golden_fixture_files");
    let chain_cm: [u8; 32] = std::fs::read(dir.join("golden-chain-cm-v1.bin"))
        .expect("fixtures/golden-chain-cm-v1.bin not committed yet")
        .try_into()
        .expect("chain cm fixture must be 32 bytes");

    let (inst, _) = golden_instance();
    let want = golden_claim(&inst);
    unsafe {
        let mut claim = std::mem::zeroed::<QvaskClaim>();
        let mut reason: *mut c_char = ptr::null_mut();
        assert_eq!(
            qvask_verify(bytes.as_ptr(), bytes.len(), chain_cm.as_ptr(), &mut claim, &mut reason),
            QVASK_OK
        );
        assert_eq!(claim.tx_ref, want.tx_ref);
        assert_eq!(claim.value, want.value);
        assert_eq!(claim.addr_commitment, want.addr_commitment);
        assert_eq!(claim.output_index, want.output_index);
    }
}
