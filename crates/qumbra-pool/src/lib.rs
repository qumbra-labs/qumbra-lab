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
//! ## Share validation (lab #490, consumed — not remirrored)
//!
//! Work value comes from [`qlab_devnet::pow::hash_to_work_value_for`]
//! (`GenesisForm::V5` ⇒ trailing-8-LE). The SHARE filter then applies
//! xmrig's strict `<` against the job target. Consensus keeps `<=`
//! ([`qlab_devnet::pow::satisfies_target_for`]); this crate does not
//! change that, and it does not read `hash[24..32]` itself.
//!
//! Mapping authority: `docs/pool-stratum-mapping.md`. Tracker: lab #482.
//! Multica: QUM-136.

pub mod accounting;
pub mod config;
pub mod endpoint;
pub mod hexutil;
pub mod jobs;
pub mod pool;
pub mod share;
pub mod template;

pub use accounting::{Ledger, ShareRecord, ShareStatus};
pub use config::PoolConfig;
pub use jobs::{IssuedJob, JobStore};
pub use pool::{Outgoing, Pool, PoolError};
pub use template::{HeldTemplateSource, Template, TemplateError, TemplateSource};
