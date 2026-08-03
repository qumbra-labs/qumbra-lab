//! `qumbra-explorer` — the public minimal explorer (issue #235): one read-only
//! chain-health page, rendered from this binary's **own keyless node's** view.
//!
//! ```text
//!   P2P net ──▶ in-process observer node ──▶ Telemetry ──▶ render ──▶ GET /
//! ```
//!
//! # What this is
//!
//! The public half of testnet-plan §6's "Minimal explorer" row — the half
//! `qumbra-opview` deliberately is not. It answers, for an outsider with no shell
//! access: is this chain alive, is it finalizing, and does its supply add up.
//!
//! # What this is deliberately NOT
//!
//! - **Not a transaction explorer.** No tx lookup, no address lookup, no note
//!   browsing, no balance queries. Single global shielded pool; a chain-health
//!   page is the whole scope, and [`http`] answers anything else with 404.
//! - **Not a window into the fleet.** §6.2 decided the fleet's telemetry
//!   endpoints stay private. This binary learns chain state **over P2P like any
//!   peer** and renders its own node's view; it never polls another node's
//!   `/v1/telemetry`, and [`config::ExplorerConfig::check_observer`] refuses a
//!   node config that would open telemetry/metrics listeners from this process.
//! - **Not a writer.** The node holds no committee keys, mines nothing, and no
//!   route mutates anything ([`http`] takes `GET` only).
//!
//! # Why the figures can be trusted (and when they refuse to exist)
//!
//! Every number on the page comes from [`qlab_node::Telemetry`] and inherits its
//! refusal disciplines verbatim: `age_field` refuses to state an age it cannot
//! know (issue #73), and `supply_coverage` refuses supply figures while the
//! applied state ledger trails fork choice (issues #130/#136) — the page renders
//! the stable `UNAVAILABLE` token in that state, never a number. **This module
//! adds no rendering rule of its own for either**; it would be a second place for
//! the rule to be wrong.
//!
//! One caveat is labelled rather than hidden: `fid` is served from the committee
//! tracker, not the durable finalized head — [issue #212]. Until that lands, the
//! page says so next to the value ([`view::FID_CAVEAT`]).
//!
//! [issue #212]: https://github.com/qumbra-labs/qumbra-lab/issues/212

pub mod config;
pub mod http;
pub mod view;
