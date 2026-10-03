//! **The L2 state fold** (lab #860 R1): the native state transition over the
//! L2 trees — `L2State` and the leaf check (`f3`), `WState` and the wrapper
//! leaf check (`f4`) — run from public values alone, no proof and no prover.
//!
//! Moved here verbatim from `qlab-wprover::f3::native` / `f4::native` (whose
//! fixtures and tests stay there, testing through re-exports) so the node can
//! derive the L2 index from stored bundles' PVs without a proving edge: the
//! fold is the statement's state transition over this crate's own trees
//! (`tree::CommitmentTree`, `registry::RegistryTree`), and it needs
//! `qlab-wrapper::hash` and `qlab-devnet`'s shape tag — hence the `l2fold`
//! feature, off for the lean graphs (qumbra-ffi, the wasm wallet core).

pub mod f3;
pub mod f4;
