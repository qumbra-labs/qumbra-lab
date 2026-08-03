//! # qlab-cbserver — compact-block reference server + light-client scan flow
//!
//! Implements [`wallet-interop-spec.md`] **§2** (ecosystem phase-1's
//! "light-client server reference") over the ratified [`note-discovery.md`] §2
//! wire (measured in qlab-note, PR #28).
//!
//! This crate is the **reference implementation** of the §2 compact-block
//! protocol — its serialized bytes *are* the spec's meaning from here on:
//! - [`codec`] — the §2 per-tx compact-group framing (versioned, little-endian,
//!   explicit ML-KEM ct amortization). Golden-bytes-locked.
//! - [`tree`] — a depth-32 incremental commitment tree + versioned frontier
//!   serialization, built on qlab-air's *exact* consensus node hash
//!   (`qlab_air::reference::merkle_node_state`). Serves `/v1/tree/frontier`.
//! - [`data`] — the data source: a `qlab-devnet` chain populated with **real**
//!   `qlab-note` encrypted notes (pre-generated once, reused).
//! - [`server`] — the three §2 endpoints over localhost HTTP (`tiny_http`),
//!   in-memory (no persistence — a reference server serves, it does not store).
//! - [`client`] — the light-client scan flow: range-fetch compact stream →
//!   qlab-note scan (`FullFo` default) → on match, `/full` fetch + decrypt +
//!   cm-recheck; plus the normative **decoy over-fetch** mitigation.
//!
//! ## Trust posture (Tor OUT of scope)
//! Per §2's normative note the server serves consensus data verbatim and can
//! neither forge (cm/tag are client-recomputed; cm is consensus-committed) nor
//! decrypt; it DOES observe requester IP / height ranges / full-fetch pattern
//! (the fetch-after-match side channel). This reference serves **localhost
//! only, no external network** — Tor integration is documented, not built. The
//! client implements the normative decoy over-fetch (≥1 randomized decoy
//! full-fetch per matched fetch) behind a flag.
//!
//! [`wallet-interop-spec.md`]: ../../../qumbra-design/wallet-interop-spec.md
//! [`note-discovery.md`]: ../../../qumbra-design/note-discovery.md

pub mod client;
pub mod codec;
#[cfg(feature = "devnet")]
pub mod data;
#[cfg(feature = "devnet")]
pub mod server;
pub mod tree;

/// Format version byte that leads every §2 response (spec: "format version byte
/// leads every response").
pub const WIRE_VERSION: u8 = 0x01;
