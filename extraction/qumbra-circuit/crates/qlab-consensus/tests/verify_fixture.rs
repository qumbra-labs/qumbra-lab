//! The end-to-end acceptance test for the extraction: a real consensus proof,
//! verified from committed bytes, against a declared public surface.
//!
//! Everything here is cheap — no proving — so this file runs on any machine that
//! can compile the crate. `examples/prove_fixture.rs` says why the proof is
//! committed instead of generated here.

#[path = "common/mod.rs"]
mod common;

use common::{
    canonical_verifier_instance, fixture_instance, fixture_path, fixture_surface, DeclaredSurface,
    PROOF_PATH, PUBLIC_PATH, WIRE_BYTES,
};
use p3_field::PrimeCharacteristicRing;
use qlab_air::narrow::{PV_ANCHOR, PV_CM1, PV_FEE, PV_LEN, PV_NF1, PV_NF2};
use qlab_consensus::{public_values, verify_proof, Config, Proof, Val};

fn proof_bytes() -> Vec<u8> {
    std::fs::read(fixture_path(PROOF_PATH)).expect("committed proof fixture")
}

fn surface() -> DeclaredSurface {
    DeclaredSurface::from_bytes(&std::fs::read(fixture_path(PUBLIC_PATH)).expect("surface fixture"))
        .expect("well-formed surface fixture")
}

fn proof() -> Proof<Config> {
    bincode::deserialize(&proof_bytes()).expect("the fixture is a bincode-fixint consensus proof")
}

/// The committed proof is exactly the minted consensus wire size. This is the
/// number `README.md` quotes, backed by an artifact in the repository rather
/// than by a claim about a machine nobody reading this has access to.
#[test]
fn fixture_size_matches_the_crate_pin() {
    assert_eq!(
        proof_bytes().len(),
        WIRE_BYTES,
        "committed fixture must be the pinned consensus wire size"
    );
}

/// The declared surface on disk is the surface of the instance the fixture was
/// proved from — so the fixture pair cannot drift apart under an edit to one
/// file. (`fixture_surface()` reads the surface off a freshly built instance;
/// this is therefore a re-derivation, not a transcription check.)
#[test]
fn declared_surface_fixture_matches_the_rebuilt_instance() {
    assert_eq!(surface(), fixture_surface());
}

/// 🔴 The headline: a real Qumbra consensus proof verifies, standalone, against
/// the surface its transaction declared — reconstructed here by `pv_vec` from
/// the five digests and the fee, exactly as a node does it.
#[test]
fn real_consensus_proof_verifies_against_its_declared_surface() {
    let mut inst = canonical_verifier_instance();
    inst.pvs = surface().to_pvs();
    let pvs = public_values(&inst);
    assert!(
        verify_proof(&inst, &pvs, &proof()),
        "the committed consensus proof must verify at the frozen config"
    );
}

/// The verifier instance carries no witness. Proved rather than asserted in
/// prose: the instance the test verifies against is built from *different*
/// inputs, outputs and fee than the fixture was proved from, and it still
/// verifies — because only the AIR shape and the public values are consulted.
///
/// This is the property that lets a node verify a stranger's transaction, and it
/// is the one an extraction could silently lose by "helpfully" reconstructing
/// the prover's instance instead.
#[test]
fn verification_uses_no_prover_witness() {
    let verifier_inst = canonical_verifier_instance();
    let prover_inst = fixture_instance();
    assert_ne!(
        verifier_inst.pvs, prover_inst.pvs,
        "precondition: the two instances must declare genuinely different surfaces"
    );
    assert_ne!(verifier_inst.anchor, prover_inst.anchor);
    assert_ne!(verifier_inst.cm_out, prover_inst.cm_out);
    // The *nullifiers* are equal across the two, and that is correct rather than
    // a weak precondition: nf = PRF(sk, ρ) and the two instances share `sk` and
    // `ρ`, differing only in note values. A nullifier that moved with the value
    // would leak the amount into the double-spend set.
    assert_eq!(verifier_inst.nf, prover_inst.nf);

    let mut inst = verifier_inst;
    inst.pvs = surface().to_pvs();
    let pvs = public_values(&inst);
    assert!(verify_proof(&inst, &pvs, &proof()));
}

/// Tamper each of the six declared fields in turn; every one must be refused.
///
/// A verifier that bound only *some* of the surface would pass the headline test
/// above and still let a relay rewrite the rest. Iterating the whole `PV_*`
/// layout is what makes "bound to the declared surface" a checked claim rather
/// than a sampled one.
#[test]
fn every_declared_field_is_bound() {
    let mut inst = canonical_verifier_instance();
    inst.pvs = surface().to_pvs();
    let pvs = public_values(&inst);
    let p = proof();
    assert!(verify_proof(&inst, &pvs, &p), "precondition: the honest surface verifies");

    for (name, idx) in [
        ("anchor", PV_ANCHOR),
        ("nf₀", PV_NF1),
        ("nf₁", PV_NF2),
        ("cm₀", PV_CM1),
        // PV_CM2 is spelled out rather than imported to keep this list flat.
        ("cm₁", PV_CM1 + 16),
        ("fee", PV_FEE),
    ] {
        let mut tampered = pvs.clone();
        tampered[idx] += Val::ONE;
        assert!(
            !verify_proof(&inst, &tampered, &p),
            "a rewritten {name} must be refused by the real verifier"
        );
    }
    assert_eq!(pvs.len(), PV_LEN, "the surface covers the whole PV vector");
}

/// Corrupting the proof bytes themselves must not verify — and must not panic.
/// A node decodes proofs from the network; a decode that aborts the process is a
/// remote crash, not a rejection.
#[test]
fn corrupted_proof_bytes_are_refused_without_panicking() {
    let mut bytes = proof_bytes();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;

    let mut inst = canonical_verifier_instance();
    inst.pvs = surface().to_pvs();
    let pvs = public_values(&inst);

    match bincode::deserialize::<Proof<Config>>(&bytes) {
        // Either outcome is correct; silently verifying is not.
        Err(_) => {}
        Ok(p) => assert!(!verify_proof(&inst, &pvs, &p), "a corrupted proof must not verify"),
    }
}

/// Truncated bytes are refused too — the length-prefixed decode must not read
/// past the buffer.
#[test]
fn truncated_proof_bytes_are_refused() {
    let bytes = proof_bytes();
    let short = &bytes[..bytes.len() - 1];
    let mut inst = canonical_verifier_instance();
    inst.pvs = surface().to_pvs();
    let pvs = public_values(&inst);
    match bincode::deserialize::<Proof<Config>>(short) {
        Err(_) => {}
        Ok(p) => assert!(!verify_proof(&inst, &pvs, &p), "a truncated proof must not verify"),
    }
}
