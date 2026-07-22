//! qlab-demo: the first end-to-end compose of the Qumbra prototype stack —
//! wallet keys/addresses + note encryption + a REAL M3 tx proof + placeholder-
//! consensus devnet block validation + compact-block scan, driven as a scripted
//! payment loop (Alice pays Bob, Bob detects and spends).
//!
//! Two crates are composed with additive helpers only; the prover config is
//! reconstructed in `prover` (see docs/demo-run.md friction F1).

// The narrow-Keccak AIR builds a large symbolic constraint tree; its
// monomorphization pushes rustc's default recursion limit (matches qlab-bench).
#![recursion_limit = "512"]

pub mod prover;
pub mod ledger;
pub mod scenario;
