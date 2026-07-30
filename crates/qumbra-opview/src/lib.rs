//! **qumbra-opview** — read-only chain health and supply attestation
//! (issues #117/#121).
//!
//! # Deliberately not Etherscan-shaped
//!
//! Qumbra's entire public transaction surface is anchor + nullifiers +
//! commitments + bucket + fee. It has no transparent addresses, balances, or
//! traceable transfers, so pages for those things would be empty by design. This
//! view renders the public facts that do exist: heights, difficulty,
//! finality/checkpoint state, committee aggregates, and per-epoch scheduled
//! issuance against the integer audit anchor.
//!
//! A cross-node agreement view answers **"do these N nodes agree?"** On T0 that is
//! the whole truth, because those four hosts *are* the network. On a public net it
//! is not: presenting a curated list's agreement as "the chain is healthy" is the
//! operator's own nodes vouching for themselves, on a net whose committee
//! `testnet-plan` §2 already labels an honest federation-of-one. A thing labelled
//! honestly in one document must not be quietly unlabelled by a tool.
//!
//! # Shape
//!
//! - [`poll`] — read `/v1/telemetry` from a configured list of endpoints, with a
//!   hard per-node deadline, concurrently. Every failure is *unreachable with a
//!   reason*, never a disagreement.
//! - [`agree`] — the verdicts. `fid` divergence (two checkpoints at one height) is
//!   the R2 STOP; `sid` divergence (different signed variants) is a finding. They
//!   are never merged.
//! - [`render`] — one row per node, exact per-epoch supply rows, then both
//!   checkpoint verdicts, deterministically.
//!
//! # The three rules this tool obeys
//!
//! 1. **Read-only.** GET on one route. No writes, no submission path, no control
//!    endpoint, and no invented address/balance/transfer surface.
//! 2. **Observation is not a dependency of the node.** The explorer polls; the node
//!    does not know it exists and does not degrade if it vanishes
//!    (`observability-and-evidence.md` §5.2). Nothing here registers, subscribes,
//!    or expects the node to push. "A health page grows into *nodes report status
//!    somewhere* if nobody forbids it" — forbidden.
//! 3. **The list is operational config, not a product decision.** With one entry
//!    this is a single-node health page; with four it is the agreement view. The
//!    agreement check is trivially satisfied at n=1 rather than being special-
//!    cased, so there is one code path, not two.

pub mod agree;
pub mod poll;
pub mod render;

pub use agree::{Agreement, SignedVerdict, Verdict};
pub use poll::{poll_all, poll_one, Endpoint, NodeReading, PollOptions, Reading};
pub use render::{supply, supply_diverged, view};
