//! `qumbra-explorer` — the public minimal explorer (issues #235, #281): one
//! read-only chain-health **projection**, serialized from this binary's **own
//! keyless node's** view.
//!
//! ```text
//!   P2P net ──▶ in-process observer node ──▶ Telemetry ──▶ json ──▶ GET /v1/health.json
//! ```
//!
//! # What this is
//!
//! The public half of testnet-plan §6's "Minimal explorer" row — the half
//! `qumbra-opview` deliberately is not. It answers, for an outsider with no shell
//! access: is this chain alive, is it finalizing, and does its supply add up.
//!
//! **The page is not here.** Issue #281 split it out: this binary serves the
//! projection and `/healthz` and no HTML at all, and the human-readable page is
//! `qumbra-labs/qumbra-explorer-web` — static files svc0's Caddy serves from a file
//! root beside these two routes, same origin, no CORS. The decision and its rejected
//! alternatives are in `qumbra-design/t1-explorer-split-decision.md`.
//!
//! # The transaction-EXISTENCE view (issue #326), and its exact size
//!
//! Since `t1-explorer-tx-view-decision.md` (STAMPED 2026-08-10) this binary also
//! serves [`txlist`] at `GET /v1/txlist?from=&to=`: per block-with-transactions its
//! height and transaction count, and per transaction its id, wire bytes, posted
//! fee, nullifier count and commitment count. That is D1, and it is not a subset of
//! something larger — it is everything a shielded transaction publishes.
//!
//! 🔴 **There is no lookup by transaction id, and that is D2.** The list is
//! bulk-served over ranges and a pasted id is matched **client-side over fetched
//! pages** ([`txlist::match_txid`]); a `/tx/<id>` query would tell this server which
//! transaction the asker cares about, which is the correlation surface the
//! nullifier-membership query was refused for at PR #315 decision 3. One rule, both
//! surfaces. [`http`] has no arm that could match a by-id form, so the refusal is
//! structural and its 404 is test-locked.
//!
//! D3's boundary sentence rides in the document ([`txlist::BOUNDARY_SENTENCE`]) so
//! the page renders it rather than owning a copy that could drift.
//!
//! # What this is deliberately NOT
//!
//! - **Still not an Etherscan.** No address lookup, no note browsing, no balance
//!   queries, no linkage view, no per-address anything — and not as policy: the
//!   chain carries none of it. [`http`] answers everything else with a typed 404,
//!   including everything `/v1/tx…`-shaped, which is now *adjacent* to two real
//!   `/v1` routes and therefore tested rather than assumed.
//! - **Not a window into the fleet.** §6.2 decided the fleet's telemetry
//!   endpoints stay private. This binary learns chain state **over P2P like any
//!   peer** and renders its own node's view; it never polls another node's
//!   `/v1/telemetry`, and [`config::ExplorerConfig::check_observer`] refuses a
//!   node config that would open a telemetry listener — or a **public** metrics
//!   listener — from this process. *(Loopback-only metrics became legal with the
//!   OTel baton's coordinator ruling; see [`metrics_server`] for the ruling and
//!   [`telemetry`] for the kit it serves.)*
//! - **Not a writer.** The node holds no committee keys, mines nothing, and no
//!   route mutates anything ([`http`] takes `GET` only). #275's `POST /v1/tx`
//!   belongs to svc0's separate `cbnode`, never to this process.
//!
//! # Why the figures can be trusted (and when they refuse to exist)
//!
//! Every number in the document comes from [`qlab_node::Telemetry`] and inherits its
//! refusal disciplines verbatim: `age_field` refuses to state an age it cannot
//! know (issue #73), and `supply_coverage` refuses supply figures while the
//! applied state ledger trails fork choice (issues #130/#136) — the projection
//! carries the stable `UNAVAILABLE` token in that state and **omits the figures
//! entirely**, so a reader cannot render one it must not. **This crate
//! adds no rendering rule of its own for either**; it would be a second place for
//! the rule to be wrong.
//!
//! **Both finalized heads are on the surface**, which is what [issue #212] made
//! possible and what this crate failed to do for three days: `head1` is the
//! committee tracker's view and does **not** survive a restart, `head3` is the
//! durable head that does, and the verdict comparing them is
//! `Telemetry::durable_agreement`'s — never recomputed here. The prose caveat this
//! module used to carry beside `fid` is gone, because the distinction is now
//! structural: two objects, named for what they are.
//!
//! # Why this surface may run a client-side page while the faucet's may not
//!
//! `qumbra-faucet` has a test forbidding `<script`, external URLs and cookies on its
//! page, for a stated reason: *a faucet page that pulls a font from a CDN tells that
//! CDN who is asking a privacy chain for money.* This crate's reader runs JavaScript,
//! and that is **not** the faucet's rule being broken — it is a different surface.
//!
//! The axis is what each one handles. The faucet takes a recipient address and a
//! single-use ticket, a bearer credential, so code delivery and request shape are in
//! its threat model. This surface takes **no input at all** and keeps no access
//! journal; the only thing it could leak about a reader is readership, which a static
//! page leaks identically. So the faucet's test stays exactly as it is, and it is not
//! a standard this crate failed. Do not "reconcile" the two.
//!
//! The reachable half of that posture is kept: the page carries **no external
//! reference of any kind**, self-hosted assets only.
//!
//! [issue #212]: https://github.com/qumbra-labs/qumbra-lab/issues/212

pub mod attest;
pub mod blocks;
pub mod checkpoints;
pub mod config;
pub mod http;
pub mod json;
pub mod metrics_server;
pub mod names;
pub mod telemetry;
pub mod txlist;
pub mod vitals;
