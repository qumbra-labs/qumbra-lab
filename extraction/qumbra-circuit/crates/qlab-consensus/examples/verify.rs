//! Verify a real Qumbra consensus proof, end to end, with nothing else running.
//!
//! ```sh
//! cargo run --release --example verify
//! ```
//!
//! This is the outsider's entry point. It loads the committed fixture — one real
//! 2×2-bucket transaction proof and the public surface that transaction declared
//! — reconstructs the public-value vector the way a node does, and runs the
//! frozen-config STARK verifier over it. No node, no network, no wallet, no key
//! material: the whole verification is this file plus `qlab-air` and
//! `qlab-consensus`.
//!
//! It then shows the property that makes verification mean anything: flip one
//! 16-bit chunk of the declared nullifier and the same proof is **refused**. A
//! verifier that accepted that would let a relay rewrite where the money went.
//!
//! Regenerating the fixture from scratch is `cargo run --release --example
//! prove_fixture` — see that file for why proving is not what this example does.

#[path = "../tests/common/mod.rs"]
mod common;

use common::{
    canonical_verifier_instance, fixture_path, DeclaredSurface, PROOF_PATH, PUBLIC_PATH, WIRE_BYTES,
};
use p3_field::PrimeCharacteristicRing;
use qlab_air::narrow::PV_NF2;
use qlab_consensus::{
    make_config_with, public_values, verify_proof, Config, Proof, Val, CONSENSUS_CFG,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -- 0. The configuration under which everything below is claimed. --------
    // `make_config_with` asserts the security bar internally; calling it here
    // means a config that fell below ~100 bits would abort this example rather
    // than quietly verify something weaker.
    let _: Config = make_config_with(&CONSENSUS_CFG);
    println!("consensus config : {}  (FROZEN v1.0)", CONSENSUS_CFG.label());

    // -- 1. Load the proof. --------------------------------------------------
    let proof_bytes = std::fs::read(fixture_path(PROOF_PATH))?;
    println!(
        "proof            : {} B from {PROOF_PATH}",
        proof_bytes.len()
    );
    if proof_bytes.len() != WIRE_BYTES {
        return Err(format!(
            "fixture is {} B but the consensus wire is pinned at {WIRE_BYTES} B — \
             the fixture and the circuit have diverged; do not 'fix' either one, report it",
            proof_bytes.len()
        )
        .into());
    }
    // bincode fixint is the consensus wire (protocol-spec §4).
    let proof: Proof<Config> = bincode::deserialize(&proof_bytes)?;

    // -- 2. Load what the transaction CLAIMS. --------------------------------
    let surface = DeclaredSurface::from_bytes(&std::fs::read(fixture_path(PUBLIC_PATH))?)?;
    println!("declared anchor  : {:016x?}", surface.anchor);
    println!("declared nf      : {:016x?}", surface.nf);
    println!("declared cm      : {:016x?}", surface.cm);
    println!("declared fee     : {}", surface.fee);

    // -- 3. Verify the proof AGAINST THAT CLAIM. -----------------------------
    // The instance is witness-free: it carries the AIR shape and nothing a
    // prover knew. `pv_vec` — not the fixture — decides what is being verified.
    let mut inst = canonical_verifier_instance();
    inst.pvs = surface.to_pvs();
    let pvs = public_values(&inst);

    if !verify_proof(&inst, &pvs, &proof) {
        return Err("VERIFY FAILED on the committed fixture".into());
    }
    println!("\n  ✅ VERIFIED — a real Qumbra consensus proof, checked from this repo alone.");

    // -- 4. And the negative, which is the half that carries the meaning. ----
    let mut tampered = pvs.clone();
    tampered[PV_NF2 + 5] += Val::ONE;
    if verify_proof(&inst, &tampered, &proof) {
        return Err(
            "🔴 the verifier ACCEPTED a rewritten nullifier — this is a soundness failure".into(),
        );
    }
    println!("  ✅ REFUSED  — the same proof against a rewritten nullifier (one chunk of nf₁).");

    Ok(())
}
