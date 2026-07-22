//! # qlab-econ — the emission-curve simulator
//!
//! The quantitative validator for the consensus-parameters appendix's emission
//! constants (tokenomics-and-issuance.md §7's three open numbers: initial reward,
//! decay rate, tail rate). **Pure arithmetic — zero crypto, zero chain deps.**
//!
//! This crate decides **no constant**. Its one job is to let the coordinator SEE
//! the emission trade space so a proposal can be written in the appendix:
//!
//! - [`model`]  — the closed-form emission family (§3: Monero-class smooth decay +
//!   perpetual tail floor), with an exactly-computable supply-at-height S(h) (§1 job 4).
//! - [`metrics`] — everything the appendix needs to see per candidate: supply
//!   curve, annual-inflation trajectory (§3: → 0), tail activation year/height +
//!   inflation-at-activation (Monero's 0.87% is the calibration reference), and
//!   the 65/15/20 split's absolute flows per era (§4).
//! - [`checks`] — the four §1 jobs as explicit pass/fail assertions.
//! - [`sweep`] — the parameter grid.
//! - [`report`] — renders `docs/econ-sweep.md`.
//!
//! Nothing here is "chosen". The output is a table of candidates with their
//! trade-offs surfaced; the coordinator proposes in the appendix.

pub mod checks;
pub mod metrics;
pub mod model;
pub mod report;
pub mod sweep;

pub use model::{Family, Model};
