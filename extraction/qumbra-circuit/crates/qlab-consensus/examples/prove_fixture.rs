//! Regenerate the committed proof fixture from source. **Heavy.**
//!
//! ```sh
//! cargo run --release --example prove_fixture
//! ```
//!
//! # Why the fixture is committed rather than proved on demand
//!
//! Proving one 2×2 bucket at the frozen config costs on the order of **12 GB of
//! RSS** (12.21 GB, one labelled sample, recorded at the mint — PR #252 in the
//! private lab). That is a machine requirement, not a preference: an outsider on
//! a 16 GB laptop can *verify* every claim this repository makes in
//! milliseconds, and would be unable to run a `cargo test` that proved from
//! scratch at all. Verification is the property being open-sourced; proving is
//! an implementation detail of whoever spends the money.
//!
//! So the shipped end-to-end path (`examples/verify.rs`,
//! `tests/verify_fixture.rs`) verifies a committed proof, and this example is
//! how that proof stops being magic: run it, and it overwrites the fixture with
//! a freshly proved one. **The bytes must not change** — proof size is a
//! function of `log_height`, width, quotient degree and the FRI config only, and
//! the grind nonce is a fixed-width field, so a regenerated fixture is the same
//! length and verifies identically. A different length means the circuit moved.
//!
//! The crate's own `consensus_wire_is_148625_bytes` test *does* prove from
//! scratch, so `cargo test --release` still exercises the prover end to end on a
//! machine that can afford it — the fixture is not a way to avoid that, only a
//! way to make the verify path cheap and portable.

#[path = "../tests/common/mod.rs"]
mod common;

use common::{fixture_instance, fixture_path, fixture_surface, PROOF_PATH, PUBLIC_PATH, WIRE_BYTES};
use qlab_consensus::{prove_bucket, verify_proof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("proving one 2×2 bucket at the frozen config — expect ~12 GB peak RSS…");
    let inst = fixture_instance();
    let (pvs, proof) = prove_bucket(&inst);

    if !verify_proof(&inst, &pvs, &proof) {
        return Err("refusing to write a fixture that does not verify".into());
    }

    let bytes = bincode::serialize(&proof)?;
    if bytes.len() != WIRE_BYTES {
        return Err(format!(
            "proof is {} B, the pin is {WIRE_BYTES} B — the circuit's wire size moved. \
             This is a finding, not something to overwrite the pin for.",
            bytes.len()
        )
        .into());
    }

    std::fs::write(fixture_path(PROOF_PATH), &bytes)?;
    std::fs::write(fixture_path(PUBLIC_PATH), fixture_surface().to_bytes())?;
    println!("wrote {PROOF_PATH} ({} B) and {PUBLIC_PATH}", bytes.len());
    Ok(())
}
