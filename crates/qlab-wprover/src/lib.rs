//! **qlab-wprover** — the proving half of the L2 wrapper (lab #847 S1a).
//!
//! The modules keep the paths they had in qlab-bench (`f3::native`,
//! `f3::leaf`, `f4::native`, `f4::wleaf`, `f4::dep`), so their bodies moved
//! verbatim: only `pub(crate)` became `pub` and one import moved to where its
//! item already lived (`qlab_wrapper::lane::LaneBuilder`). qlab-bench
//! re-exports them at the same paths; its fixtures, CLI modes and console
//! stay there.
pub mod f3;
pub mod f4;
