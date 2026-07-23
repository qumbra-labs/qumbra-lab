//! qlab-node — the Qumbra full-node state skeleton (M9-N1, issue #48 stage 1).
//!
//! A node maintains three pieces of consensus state derived from the accepted
//! chain (protocol-spec §3/§6), persists them durably, and can rebuild them from
//! genesis:
//!
//! - the **chain store** (blocks + fork-choice tip + finalized head),
//! - the **depth-32 commitment tree** (note commitments; the tree the M3 bucket
//!   proves membership against), and
//! - the **permanent nullifier set** (the consensus double-spend gate — the
//!   piece `qlab-devnet` explicitly left as "a documented extension, not built
//!   here").
//!
//! # The trait surface (M9-N2..N6 consume this)
//!
//! The consumption interface later node work builds on:
//!
//! - [`ChainStore`], [`CommitmentStore`], [`NullifierStore`] — the three
//!   **swappable state backends**. Downstream code holds the trait, not the
//!   concrete store, so an in-memory map today can become an embedded KV store
//!   later without touching the state transition. Default in-memory impls:
//!   [`MemChainStore`], [`MemCommitmentStore`], [`MemNullifierStore`].
//! - [`NodeState`] — the **read-only view** (tip / finalized / commitment root +
//!   count / `is_spent` / `is_valid_anchor`) that tx admission (N2) and RPC (N5)
//!   query.
//! - [`Node`] — the composed node owning the **state-transition function**
//!   [`Node::apply_block`] (validate → fold into tree + nullifier set), plus
//!   [`Node::finalize`], [`Node::save_snapshot`], [`Node::open`] (restart-safe
//!   resume) and [`Node::replay`] (from-genesis rebuild). Generic over the three
//!   store traits; [`MemNode`] is the default composition.
//! - [`StoredBlock`] / [`Snapshot`] — the versioned on-disk forms (block log +
//!   atomic snapshot), the wire N4 (P2P/sync) and N6 (bootstrap) build on.
//!
//! Verification is **injected** as a `qlab_devnet::body::TxVerifier`, so the real
//! M3 verifier (built on `qlab-consensus`) plugs into [`Node::apply_block`]
//! without this crate depending on the prover.
//!
//! # Durability & correctness
//!
//! The block log is the source of truth; the atomic snapshot is a fast-restart
//! cache. `open` resumes from the snapshot and replays the log tail; `replay`
//! rebuilds purely from the log. Their states are identical by construction —
//! the tests assert it — so a snapshot can never silently diverge from a genesis
//! replay.

pub mod emission;
mod node;
mod persist;
mod store;

pub use emission::{coinbase, s_atomic, RewardSplit, COINBASE_MATURITY_BLOCKS};
pub use node::{genesis_block, MemNode, Node, NodeError, NodeState};
pub use persist::{Snapshot, BLOCK_LOG, FORMAT_VERSION, SNAPSHOT};
pub use store::{
    ChainStore, CommitmentStore, Hash32, MemChainStore, MemCommitmentStore, MemNullifierStore,
    NullifierStore, StoredBlock, StoredHeader, StoredTx,
};
