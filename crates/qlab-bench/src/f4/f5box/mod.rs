//! Lab #785 F5-6 (1) — **`qlab-bench f5box`**: the rehearsal's bundles, built
//! as a client of the box node (Q-6-1, ruled on issue #785).
//!
//! On a real net the first bundle is necessarily claims-only — the genesis
//! surface's `C` is empty, so there is nothing for S, P or R to spend
//! (Q-6-2). f5box therefore builds:
//!
//! 1. **the deposit**: sixteen claims, each opening a burn note (a coinbase
//!    paid to `rkm_burn(l2_id)`, claimable once its leaf has matured into the
//!    L1 tree and a finality record covers a root holding it — Q-6-3);
//! 2. **the mix** (`--next`): `default_kinds(16)` — 8 P, 3 S, 1 R, 4 C —
//!    spending the notes the deposit credited, the first P paying the exit.
//!
//! [`chain`] reads the node; [`members`] builds real members over real trees
//! and checks the wrapper natively; [`bundle`] proves, signs and judges the
//! result by the node's own rule; [`state`] keeps the run between bundles;
//! [`run`] is the command.
// Lab #847 S1b: the library half moved to qumbra-sequencer; the old paths
// stay, so `run` and the tests read them unchanged.
pub(crate) use qumbra_sequencer::{bundle, chain, members, state};
pub(crate) mod run;

pub(crate) use run::run;

#[cfg(test)]
mod tests;
