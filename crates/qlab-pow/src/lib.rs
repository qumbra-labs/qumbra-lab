//! # qlab-pow — real CPU-friendly PoW + the difficulty algorithm
//!
//! Qumbra's PoW is a **CPU-friendly RandomX-class** algorithm (consensus-and-network
//! §10; protocol-spec §6). The M6 devnet shipped a Keccak *placeholder* behind a
//! `PowEngine` trait while the algorithm stayed an open question. This crate is
//! M9-N3's answer to that question in prototype form: it binds the **reference
//! RandomX** implementation and pairs it with an **LWMA-120** difficulty retarget
//! at the frozen 75 s block time.
//!
//! ## What lives here (and what does not)
//!
//! - [`randomx`] — a thin, deterministic wrapper over `randomx-rs` (light mode:
//!   a 256 MiB cache, no 2+ GiB dataset), memoizing the cache/VM by key so a run
//!   of same-key hashes pays the cache build once. Cross-checked against the
//!   official RandomX test vectors.
//! - [`keyblock`] — the RandomX **key-block rotation** schedule: which past block's
//!   hash seeds the RandomX key at a given height (Monero-shape epoch + lag).
//! - [`lwma`] — the **LWMA-120** difficulty retarget arithmetic (Zawy's LWMA-1),
//!   as a pure function over a window of (timestamp, difficulty) samples.
//!
//! The `PowEngine` adapter that wires these into the devnet's mining/validation
//! path lives in `qlab-devnet::pow` (`RandomXPow`), NOT here — this crate has no
//! consensus opinions and no workspace dependencies.
//!
//! ## Parameter status
//!
//! The block time (75 s) is **frozen** (consensus-parameters §2). The retarget
//! *algorithm* parameters (window N = 120, clamps) and the key-block cadence are
//! **testnet-tunable and NOT frozen** — full-M8 freezes them at v1.1 (protocol-spec
//! §10). Defaults here quote Monero/Zawy provenance; they are prototype choices,
//! not Qumbra proposals.

pub mod randomx;

pub use randomx::RandomXHasher;
