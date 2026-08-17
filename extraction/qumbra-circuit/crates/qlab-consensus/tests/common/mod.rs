//! Shared fixture plumbing for `examples/verify.rs`, `examples/prove_fixture.rs`
//! and `tests/verify_fixture.rs`.
//!
//! Pulled in by `#[path = "..."] mod common;` from all three rather than being a
//! library module, because it is test/example scaffolding and must not enter the
//! `qlab-consensus` public API — the crate's `src/` is a verbatim copy of the
//! private lab's and stays that way.
//!
//! # What the fixture is
//!
//! Two files, both committed:
//!
//! - `consensus-proof-2x2.bin` — one real consensus STARK proof for the 2×2
//!   bucket, bincode-serialized. **148,625 B** — the `CONSENSUS_WIRE_BYTES` pin.
//! - `consensus-proof-2x2.public` — the *declared public surface* that proof is
//!   claimed against: `anchor ‖ nf₀ ‖ nf₁ ‖ cm₀ ‖ cm₁ ‖ fee`, 21 × `u64`
//!   little-endian = 168 B. Deliberately NOT the `Vec<u32>` public-value vector:
//!   a verifier that were handed the packed PVs directly would be trusting the
//!   fixture's own packing. Storing the surface forces the verify path to run
//!   `pv_vec` itself, which is the step that binds a proof to what a transaction
//!   *claims*.
//!
//! The surface is what a node has: `qumbra-node`'s `ConsensusVerifier`
//! reconstructs exactly this vector from the transaction's declared anchor /
//! nullifiers / commitments / fee and verifies against it, so a proof for a
//! different surface than declared fails. This example walks the same path with
//! the node's networking, mempool and ledger all absent.

// Three targets include this module and each uses a different subset of it;
// without this every target warns about the parts it does not happen to call.
#![allow(dead_code)]

use qlab_air::narrow::{build_bucket, pv_vec, BucketInstance, TxInput, TxOutput};
use qlab_consensus::LOG_HEIGHT;

/// The proof fixture, relative to the `qlab-consensus` crate root.
pub const PROOF_PATH: &str = "tests/fixtures/consensus-proof-2x2.bin";
/// The declared-public-surface fixture, relative to the `qlab-consensus` crate root.
pub const PUBLIC_PATH: &str = "tests/fixtures/consensus-proof-2x2.public";

/// The minted consensus wire size. Single-sourced in the crate's own
/// `WIRE_BYTES` (a private test const there); repeated here because an example
/// cannot see a `#[cfg(test)]` item, and cross-checked by
/// `fixture_size_matches_the_crate_pin` in `tests/verify_fixture.rs`.
pub const WIRE_BYTES: usize = 148_625;

/// A transaction's declared public surface — the five digests and the fee a
/// transaction states on the wire, before any proof is looked at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeclaredSurface {
    pub anchor: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm: [[u64; 4]; 2],
    pub fee: u64,
}

impl DeclaredSurface {
    /// The public-value vector this surface implies — `qlab_air::narrow::pv_vec`,
    /// the same call `qumbra-node`'s real verifier makes.
    pub fn to_pvs(self) -> Vec<u32> {
        pv_vec(
            &self.anchor,
            &self.nf[0],
            &self.nf[1],
            &self.cm[0],
            &self.cm[1],
            self.fee,
        )
    }

    /// 21 × `u64` little-endian, in declaration order.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21 * 8);
        for w in [self.anchor, self.nf[0], self.nf[1], self.cm[0], self.cm[1]] {
            for lane in w {
                out.extend_from_slice(&lane.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.fee.to_le_bytes());
        out
    }

    /// Inverse of [`Self::to_bytes`]. Errors rather than panics so the example
    /// can report a truncated checkout as a message instead of a backtrace.
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 21 * 8 {
            return Err(format!(
                "declared-surface fixture is {} B, expected {} B (21 u64 LE)",
                b.len(),
                21 * 8
            ));
        }
        let w = |i: usize| -> u64 { u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()) };
        let d = |o: usize| -> [u64; 4] { core::array::from_fn(|i| w(o + i)) };
        Ok(Self {
            anchor: d(0),
            nf: [d(4), d(8)],
            cm: [d(12), d(16)],
            fee: w(20),
        })
    }
}

/// The canonical **witness-free** verifier instance.
///
/// `NarrowKeccakAir`'s constraints read the structural program ring, the trace
/// and the public values — never `slot_witness`, and never `self.fee`. So the
/// specific witness values baked in here are immaterial to verification: what
/// matters is that the AIR *shape* is the one the prover used. The caller
/// overwrites `.pvs` with the declared surface.
///
/// This mirrors `qumbra-node::verifier::canonical_bucket_instance` exactly, and
/// deliberately so — a node verifying a stranger's transaction has no witness.
pub fn canonical_verifier_instance() -> BucketInstance {
    let inputs = [
        TxInput { sk: [1, 2, 3, 4], value: 3, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
        TxInput { sk: [13, 14, 15, 16], value: 2, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
    ];
    let outputs = [
        TxOutput { value: 3, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
        TxOutput { value: 1, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
    ];
    build_bucket(LOG_HEIGHT, &inputs, &outputs, 1)
}

/// The instance the committed fixture was proved from: a balanced 2-in/2-out
/// bucket, 50,000 + 30,000 = 60,000 + 19,000 + 1,000 fee.
///
/// Byte-for-byte the `balanced_bucket()` of `qlab-consensus`'s own
/// `consensus_wire_is_148625_bytes` test, so the fixture and the in-crate wire
/// pin describe the same proof and cannot drift apart.
pub fn fixture_instance() -> BucketInstance {
    let inputs = [
        TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
        TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
    ];
    let outputs = [
        TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
        TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
    ];
    build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000)
}

/// The declared surface of [`fixture_instance`], read off the built instance
/// rather than transcribed — a transcribed constant is a second source of truth.
pub fn fixture_surface() -> DeclaredSurface {
    let inst = fixture_instance();
    DeclaredSurface {
        anchor: inst.anchor,
        nf: inst.nf,
        cm: inst.cm_out,
        fee: 1_000,
    }
}

/// Absolute path to a fixture, resolved against `CARGO_MANIFEST_DIR` so both
/// `cargo test` and `cargo run --example` find it from any working directory.
pub fn fixture_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}
