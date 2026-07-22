//! Qumbra selective disclosure-proof prototype.
//!
//! The single-note STARK that fills the [wallet-interop-spec] §3 envelope —
//! the "Selective" layer of [auditable-privacy] §4, "I sent value v to address
//! A in transaction T, and nothing else." It closes the ZIP-311 gap Zcash
//! specced but never productionized: because the sender holds every witness
//! (note opening + recipient address), the proof is a small STARK over data the
//! chain already commits to, with zero consensus surface.
//!
//! Layers:
//! - [`packing`] — the two hash packings the statement proves (`cm`,
//!   `addr_commitment`), in the clear, cross-checked byte-for-byte against
//!   qlab-air `build_bucket` and qlab-wallet `Address` (the STOP-POINT locks).
//! - `air` — the disclosure AIR: a narrow-Keccak sponge pipeline (added next).
//! - `prove` — the KoalaBear + Keccak-256 FRI prover stack (added next).
//! - `envelope` — the §3 binary envelope + verify (added next).
//!
//! [wallet-interop-spec]: qumbra-design/wallet-interop-spec.md
//! [auditable-privacy]: qumbra-design/auditable-privacy.md

pub mod air;
pub mod envelope;
pub mod packing;
pub mod prove;
