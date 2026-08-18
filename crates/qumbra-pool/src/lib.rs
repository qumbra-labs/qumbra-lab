//! `qumbra-pool` — the T2 pool binary (lab #482 stage 1).
//!
//! TCP stratum endpoint (Monero-convention newline JSON-RPC) + job lifecycle
//! + share accounting + a template source keyed by
//! [`qlab_devnet::forms::ChainRules::form`]. Protocol codec lives in
//! [`qlab_stratum`]; this crate is the I/O policy and the accounting.
//!
//! ## v4-compat (keep this line honest)
//!
//! Stage 2's N=1 single-payee fallback is **accounting / payee-list
//! testability on a v4 net**, not stock-xmrig-on-v4. Lab #356 UNCLEAN
//! stands: a v4 preimage still has the nonce at offset 56. A v4-pointed
//! pool refuses stratum `login` by name (`v4-net-unclean-for-stock-xmrig`).
//! One binary, two nets — the form arrives with the template (the genesis
//! identity), never as a free-floating top-level switch (H1).
//!
//! ## Share validation is not in this commit series yet
//!
//! The share-PoW predicate is #490's form-keyed export
//! (`GenesisForm::V5` ⇒ trailing-8-LE, strict `<` at the pool filter).
//! That consensus PR is outside this baton's boundary. Submits are
//! accepted **structurally** (job exists, session matches, windows
//! intact, not stale/dup) and recorded as
//! [`accounting::ShareStatus::AcceptedStructural`]. The follow-up
//! commit after #490 merges consumes the exported predicate rather than
//! re-mirroring bytes here.
//!
//! Mapping authority: `docs/pool-stratum-mapping.md`. Tracker: lab #482.
//! Multica: QUM-136.

pub mod accounting;
pub mod config;
pub mod endpoint;
pub mod hexutil;
pub mod jobs;
pub mod pool;
pub mod template;

pub use accounting::{Ledger, ShareRecord, ShareStatus};
pub use config::PoolConfig;
pub use jobs::{IssuedJob, JobStore};
pub use pool::{Outgoing, Pool, PoolError};
pub use template::{HeldTemplateSource, Template, TemplateError, TemplateSource};
