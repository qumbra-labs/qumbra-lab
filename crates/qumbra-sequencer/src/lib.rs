//! **qumbra-sequencer** — the V6 sequencer (lab #847).
//!
//! S1b: f5box's library half, moved verbatim out of qlab-bench under the same
//! module names (`chain`, `members`, `bundle`, `state`), so the sibling paths
//! the modules use (`super::chain`, …) are unchanged. The edits are
//! `pub(crate)` → `pub`, `crate::f3`/`crate::f4` → `qlab_wprover::f3`/`f4`,
//! and `cfg(test)` → `cfg(any(test, feature = "test-support"))` for the
//! helpers the bench's lane drives. qlab-bench keeps f5box's CLI (`run`) and
//! its tests and re-exports these modules at their old paths.
//!
//! - [`chain`]: what the sequencer reads from an L1 node.
//! - [`members`]: the wrapper plan — the sequencer's prefilter.
//! - [`bundle`]: prove, assemble, sign, self-check, manifest.
//! - [`state`]: the replayed run state, written atomically under a lock.
pub mod bundle;
pub mod chain;
pub mod members;
pub mod state;
