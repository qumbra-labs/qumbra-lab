//! qumbra-node — the deployable full-node binary + genesis tooling (M10-T0-1).
//!
//! This crate turns N7's in-process `FullNode` composition into a real,
//! TOML-configured node process:
//!
//! - [`config`] — the on-disk [`config::NodeConfig`] (data dir, listen addr,
//!   dial peers, committee signing-key paths, mining on/off, genesis file).
//! - [`genesis`] — the versioned [`genesis::GenesisFile`] that bakes the FROZEN
//!   v1.0 constant table + committee₀ verifying keys + the genesis block, plus
//!   `genesis init` tooling. Every node loads and byte-verifies the same file
//!   (the genesis hash is printed and asserted; a wrong hash refuses startup).
//! - [`params_audit`] — the params_devnet-vs-FROZEN-v1.0 convergence audit
//!   (the docs/ table's data, test-locked here).
//! - [`run`] — composes the N7 stack over the REAL TCP transport + RandomXPow +
//!   on-disk qlab-node stores, and runs it with graceful-shutdown snapshot flush.
//!
//! The transaction-proof verifier is injected (the N7 stack is verifier-agnostic).
//! The default [`run::DevnetRehearsalVerifier`] is a clearly-labelled rehearsal
//! stand-in; the real M3 verifier (`qlab_consensus::verify_proof`) is the
//! production drop-in at the exact same `TxVerifier` seam.

pub mod config;
pub mod genesis;
pub mod params_audit;
pub mod run;
