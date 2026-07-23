//! # qlab-p2p — Qumbra M9-N2 P2P core (prototype)
//!
//! The networking layer of the Qumbra devnet: a **versioned message envelope**,
//! **peer management**, **gossip** of blocks / transactions / checkpoints, a
//! **header-first sync** state machine, and **compact-block relay**, over a
//! **dual transport** — an in-process simulator (deterministic tests) and real
//! `std::net` TCP (no async runtime, matching the whole stack's posture).
//!
//! ## Prototype status — what binds and what does not
//!
//! protocol-spec **§10** explicitly defers **"P2P message formats"** to the full
//! M8 spec. So the *message layouts* in this crate are **`[devnet-placeholder]`
//! shape**: the byte details are a lab proposal, to be frozen with the eventual
//! full-M8 P2P section. What the spec *does* bind, and what this crate matches
//! exactly, is:
//!
//! - **§0 versioning** — every version-tagged wire format is **reject-unknown**.
//!   The [`wire`] envelope carries an explicit protocol version and message type;
//!   unknown values of either, trailing bytes, and oversize frames are all
//!   rejected at decode.
//! - **§5 framing** — the note-discovery / compact-block wire (`version(0x01)`
//!   lead byte, unsigned LEB128 varints, reject trailing / unknown-version /
//!   non-zero-clue). Compact-block relay **reuses** `qlab_cbserver::codec`
//!   verbatim (golden-locked to the spec digest `3ee2a5e6…`); [`varint`] binds
//!   our varint use to that same single source.
//!
//! See `docs/m9-n2-p2p-plan.md` for the full conformance mapping, including the
//! reported observation that "compact block" names *two distinct objects* — the
//! §5 note-discovery wire and the consensus-and-network §7 BIP-152-shape
//! inter-node block relay — both provided here, cleanly separated.
//!
//! All wire (de)serialization is hand-rolled little-endian — the devnet consensus
//! objects carry no serde, and neither does this crate, by design.

pub mod codec;
pub mod compact;
pub mod gossip;
pub mod adapter;
pub mod n1;
pub mod node;
pub mod peer;
pub mod sync;
pub mod transport;
pub mod varint;
pub mod wire;

pub use node::P2pNode;
pub use peer::PeerId;
pub use wire::{Envelope, FrameHeader, MsgType, WireError, MAGIC, MAX_PAYLOAD, PROTOCOL_VERSION};
