//! # qlab-devnet — Qumbra M6 consensus/network devnet
//!
//! A local multi-node simulation of Qumbra's **hybrid consensus**: permissionless
//! PoW block production + a small (N≈20) BFT finality committee, Crosslink-shape
//! on the Ebb-and-Flow security model (consensus-and-network.md §4).
//!
//! This crate is a **prototype devnet**, not production consensus. Its job is to
//! exercise the mechanics the design docs *decided* — PoW + heaviest-chain fork
//! choice, ML-DSA-65 checkpoint finality, anchors-from-finalized-only,
//! degraded-mode liveness, evidence-based equivocation slashing — on real M3 tx
//! proofs, and to produce a measured cadence/finality/validation-time report.
//!
//! ## What is a placeholder vs what is decided
//!
//! Open design questions are NOT decided here. In particular:
//! - **PoW algorithm** is OPEN (consensus §10, RandomX-class). PoW lives behind
//!   the [`pow::PowEngine`] trait with a Keccak-based placeholder ([`pow::KeccakPow`]).
//!   RandomX is deliberately NOT integrated.
//! - **Emission, bond/slash amounts, fee-tier values, epoch length** are OPEN
//!   (consensus-parameters appendix, not yet written). Every placeholder constant
//!   is confined to [`params_devnet`], which carries a "DEVNET PLACEHOLDERS" banner.
//! - The **aggregate-proof slot** and **epoch supply-attestation** header fields
//!   are **RESERVED, not computed** — they activate with rung-1 aggregation
//!   (performance-budget §5, §9). See [`header::AggregateProofSlot`] /
//!   [`header::EpochSupplyAttestation`].
//!
//! Conservative hash everywhere in consensus (performance-budget §2): the Keccak
//! primitive is `qlab_air::reference::keccak_f`, wrapped by [`hash::keccak256`].

pub mod body;
pub mod chain;
pub mod committee;
pub mod ebbflow;
pub mod epoch;
pub mod fees;
pub mod finality;
pub mod hash;
pub mod header;
pub mod load;
pub mod mining;
pub mod net;
pub mod node;
pub mod params_devnet;
pub mod pow;
pub mod validation;
pub mod weight;
