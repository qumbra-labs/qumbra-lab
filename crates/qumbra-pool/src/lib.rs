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
//! v5 [`qlab_devnet::body::CoinbasePayee`] list capped at one before the
//! height boundary and `COINBASE_PAYEE_CAP_V5` (8) after it, or a v4 N=1
//! `(rkm, amount)`. The pool selects `min(cap, window winners)` and preserves
//! the exact scheduled sum through the final winner's remainder.
//!
//! ## 🔴 The payee gate (lab #547)
//!
//! Three T2 blocks (607, 610, 611) paid the node's
//! [`payee::UNCONFIGURED_NODE_RKM`] placeholder — structurally valid,
//! spendable by nobody. `coinbase_rkm` is committed by the header the
//! miner grinds, so lab #553 sends [`payee::assemble_coinbase`]'s list in
//! the template request before issuing work. [`payee::check_payee`] defines
//! the accepted set (the configured `payout_rkm`, or an rkm owned by a login
//! this pool knows) and remains enforced at template intake and immediately
//! before the block POST.
//!
//! Mapping authority: `docs/pool-stratum-mapping.md`. Tracker: lab #482.
//! Multica: QUM-136.

pub mod accounting;
pub mod config;
pub mod endpoint;
pub mod guard;
pub mod hasher;
pub mod hexutil;
pub mod jobs;
pub mod node_rpc;
pub mod outbox;
pub mod payee;
pub mod pool;
pub mod pplns;
pub mod share;
pub mod template;
pub mod watch;

pub use accounting::{Ledger, ShareRecord, ShareStatus};
pub use config::{PoolConfig, DEFAULT_POLL_MS, DEFAULT_TEMPLATE_STALL_POLLS};
pub use guard::{
    ConnGuard, GuardSnapshot, ListenLimits, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_LINE_BYTES,
    DEFAULT_REQUEST_TIMEOUT_MS, PER_IP_DIVISOR, REASON_CONNECTION_CAP, REASON_CONNECTION_TIMEOUT,
    REASON_LINE_TOO_LONG, REASON_PER_IP, REASON_REQUEST_TIMEOUT,
};
pub use hasher::{FixedHasher, KeccakShareHasher, ShareHasher};
pub use jobs::{IssuedJob, JobStore};
pub use node_rpc::{NodeRpcClient, NodeRpcTemplateSource};
pub use outbox::{JobOutbox, SessionPush};
pub use payee::{
    assemble_coinbase, check_body_payee, check_payee, Accounts, AssembledCoinbase, PayeeRefusal,
    UNCONFIGURED_NODE_RKM,
};
pub use pool::{
    BlockSubmitter, Outgoing, Pool, PoolCounters, PoolError, ERR_BAD_ALGO, ERR_BAD_HASH,
    ERR_DUPLICATE, ERR_INVALID, ERR_LOW_DIFF, ERR_UNAUTHORIZED, ERR_UNCLEAN_V4, ERR_UNKNOWN_JOB,
};
pub use pplns::{PplnsWindow, PPLNS_WINDOW_SHARES};
pub use template::{
    DevnetTemplateSource, HeldTemplateSource, Template, TemplateBody, TemplateError, TemplateSource,
};
pub use watch::{TemplateWatch, WatchSnapshot};

#[cfg(feature = "randomx")]
pub use hasher::RandomXShareHasher;

/// The commit this binary was built from, stamped by the release lane and by
/// `deploy/docker/Dockerfile`'s builder stage via `QUMBRA_BUILD_REV`.
///
/// 🔴 **This crate is the one that decides who gets paid.** `payee::assemble_coinbase`
/// picks the PPLNS winner and the resulting list is what reaches the chain, so
/// "which build chose this payee" is a question about *this* process — the node's
/// stamp beside it says nothing about it. Until lab #605 the pool was the only one
/// of the three binaries in the release tarball that could not answer, and the
/// release gate said so in its own comment while asserting the other two.
///
/// Deliberately the same env var and the same wording as `qumbra_node::release::BUILD_REV`
/// and `qumbra_wallet::BUILD_REV` — a stranger comparing three binaries from one
/// archive should see one string, not three vocabularies. `None` is the honest
/// answer for every build that is not a release or image build.
pub const BUILD_REV: Option<&str> = option_env!("QUMBRA_BUILD_REV");

/// The `--help` header's build-provenance line. Never empty; see [`BUILD_REV`].
pub fn build_rev_line() -> String {
    match BUILD_REV {
        Some(rev) => rev.to_string(),
        None => "unstamped — not built by the release lane".to_string(),
    }
}

#[cfg(test)]
mod build_rev_tests {
    #[test]
    fn the_build_rev_line_is_never_blank() {
        // A blank field reads as a tooling gap; an unstamped binary is a real and
        // expected state and must say so in words. Same position as
        // `qumbra_node::release::build_rev_line`.
        let line = super::build_rev_line();
        assert!(!line.trim().is_empty());
    }
}
