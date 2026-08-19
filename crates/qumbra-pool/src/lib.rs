//! `qumbra-pool` — the T2 pool binary (lab #482 stage 3).
//!
//! TCP stratum + job lifecycle + share-PoW execution + PPLNS + payee-list
//! assembly, keyed by [`qlab_devnet::forms::ChainRules::form`].
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
//! ## Share-PoW execution (stage 2)
//!
//! Hashing lives in [`qlab_pow::RandomXHasher`]. This crate composes it
//! via [`hasher::ShareHasher`] / [`hasher::RandomXShareHasher`]
//! (`feature = "randomx"`, default ON). Tests inject [`hasher::FixedHasher`]
//! so they never build a RandomX cache. After the hash matches the claimed
//! `result`, the #490 filter (`hash_to_work_value_for` + strict `<`) runs.
//!
//! ## PPLNS + payee list
//!
//! [`pplns::PplnsWindow`] is last-N accepted shares ([devnet-placeholder]
//! `PPLNS_WINDOW_SHARES = 1024`). [`payee::assemble_coinbase`] emits a
//! v5 [`qlab_devnet::body::CoinbasePayee`] list capped at
//! `COINBASE_PAYEE_CAP_V5` (1 at birth) or a v4 N=1 `(rkm, amount)`.
//! The birth cap means PPLNS cannot yet split the mint — the winner
//! takes it; the assembler already truncates to `cap`.
//!
//! Mapping authority: `docs/pool-stratum-mapping.md`. Tracker: lab #482.
//! Multica: QUM-136.

pub mod accounting;
pub mod config;
pub mod endpoint;
pub mod hasher;
pub mod hexutil;
pub mod jobs;
pub mod payee;
pub mod pool;
pub mod pplns;
pub mod share;
pub mod template;

pub use accounting::{Ledger, ShareRecord, ShareStatus};
pub use config::PoolConfig;
pub use hasher::{FixedHasher, ShareHasher};
pub use jobs::{IssuedJob, JobStore};
pub use payee::{assemble_coinbase, Accounts, AssembledCoinbase};
pub use pool::{
    Outgoing, Pool, PoolError, ERR_BAD_ALGO, ERR_BAD_HASH, ERR_DUPLICATE, ERR_LOW_DIFF,
    ERR_UNAUTHORIZED, ERR_UNCLEAN_V4, ERR_UNKNOWN_JOB,
};
pub use pplns::{PplnsWindow, PPLNS_WINDOW_SHARES};
pub use template::{
    DevnetTemplateSource, HeldTemplateSource, Template, TemplateError, TemplateSource,
};

#[cfg(feature = "randomx")]
pub use hasher::RandomXShareHasher;
