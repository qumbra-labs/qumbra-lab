//! `qlab-ledger` — the wallet's own ledger, shared by every shell.
//!
//! Received notes, spends matched against the chain's published nullifiers, and
//! send events reconstructed from same-height co-occurrence. Extracted from
//! `qumbra-wallet` (lab #407) because a shell that is not the CLI could not
//! reach any of it: that crate's graph carries `qlab-devnet` -> `qlab-pow` ->
//! `randomx-rs`'s C++/cmake, which iOS cannot build — and reimplementing a money
//! verdict in Swift is exactly what "reused, never reimplemented" forbids.
//!
//! **No `qlab-devnet` dependency, deliberately.** Fee attribution is a
//! caller-supplied closure ([`history::build`]'s `fee_for`), the shape #297 used
//! for `light_client_scan_with`: one implementation of the flow, the capability
//! passed in by whoever can carry it. A caller without a fee table gets send
//! events in states the ledger already knows how to say — `FeeInseparable` and
//! `Unavailable` — rather than a fabricated number or a new sentinel.

pub mod coverage;
pub mod history;
pub mod sends;
pub mod spent;
pub mod vocab;
