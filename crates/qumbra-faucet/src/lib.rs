//! `qumbra-faucet` — **a faucet a person can use** (issue #123).
//!
//! The request path has been complete and tested since PR #103. What never existed
//! was a way for a person to reach it. This crate is that: an HTTP surface over
//! [`qlab_faucet::Faucet`]'s tested core, running **in-process with a keyless
//! node**.
//!
//! ```text
//!   browser ──POST /request──▶ Faucet::accept ──▶ queue
//!                                                  │
//!   node loop tick ──▶ Faucet::dispense ──▶ real 2×2 STARK ──▶ submit_local_tx
//!                                                  │
//!                          Faucet::confirm ◀── the node admitted it
//! ```
//!
//! Nothing here re-implements a grant. `accept` and `dispense` are called; the
//! proof, the inventory, the anchor lease and the abuse gate are all the library's.
//!
//! ## Why in-process, and why the node holds no committee keys
//!
//! `testnet-plan.md` §6.2 rules that *a node that holds committee keys exposes
//! nothing beyond P2P*. So the faucet does not live on any of the four T0 hosts: it
//! lives on a **keyless** node, and the faucet's hot spending key and the
//! committee's signing keys are then never on the same host. [`config`] enforces
//! that as a **startup refusal**, not a deployment note — a faucet whose node
//! config names a committee key file does not start.
//!
//! In-process rather than over the network because **the node has no network write
//! path at all** — the only `POST` anywhere in the tree is a test asserting the
//! telemetry endpoint rejects one. `qlab_faucet::ChainView` already reaches node
//! state through an in-process trait, so composition is the existing seam.
//! [`qumbra_node::run::RunningNode::submit_local_tx`] is `P2pNode::announce_tx` —
//! the local-origination path a mining node already uses — so this crate adds no
//! listener to the node, no wire codepoint and no `POST /v1/tx`.
//!
//! ## The three positions this crate takes
//!
//! **1. Where the binary lives: its own crate.** The mechanical reason is in
//! `Cargo.toml` (Cargo has no per-target dependencies, so a bin inside
//! `qlab-faucet` would put the whole node graph into the *library's* dependencies).
//! The structural reason is that `qlab-faucet`'s "there is no listener here,
//! deliberately" is what a future non-HTTP front end reuses, and it should stay
//! literally true.
//!
//! **2. What a user sees when the faucet is empty: a refusal with a height, not a
//! queue slot.** See [`state::Availability`]. A queue that accepts a request it
//! cannot serve inside the wait it quotes is worse than a refusal, so the
//! unavailable states refuse — **before** [`qlab_faucet::Faucet::accept`] is
//! called, so the requester's single-use ticket is not burned by the faucet's own
//! shortage. Which is exactly the reasoning the core already uses for its
//! capacity-first check.
//!
//! **3. Whether the page shows chain state: two integers and no more.** Tip height
//! and finalized height, because "why can I not have funds yet" is a question whose
//! answer *is* a height, and a faucet that withholds it looks broken instead of
//! honest. Nothing else: no per-signer committee participation (§6.2 and #121 rule
//! that out on any public page, ever), no `fid`/`sid`, no peer list, no blocks, no
//! transactions. And **`qumbra-opview` is not mounted here** — its question is "do
//! these N nodes agree", which #117's own manifest says is an operator question
//! that would be quietly mislabelled as chain health on a public surface. Mounting
//! it would also put a second surface on the one host in the topology that holds a
//! hot spending key, which is the concentration §6.2 exists to break up.
//!
//! ## The maturity gate lives at the funding boundary, and why it had to
//!
//! `COINBASE_MATURITY_BLOCKS` = 144 (frozen §2) gates spending fresh coinbase, and
//! since issue #101 the faucet's real funding *is* coinbase — its own node's
//! `coinbase_rkm` payout. But the declaration
//! [`qlab_faucet::GrantPlan::spends_coinbase`] computes has **nowhere to go**: both
//! submission seams in the tree hardcode an empty declaration
//! (`qlab_node::rpc::NodeRpc::submit_tx` and `qlab_p2p::adapter::NodeAdapter::ingest_tx`),
//! so the mempool's frozen §2 gate is unreachable from the wallet RPC *and* from
//! the wire. That is issue #102, widened by one seam, and it is reported rather
//! than worked around.
//!
//! Nor can the core enforce it itself: [`qlab_faucet::OwnedNote::coinbase_note`]
//! carries the note's *commitment* but not the *height* it was minted at, and
//! maturity is a function of the height.
//!
//! So [`harvest`] honours it at the **funding boundary**: a coinbase note this
//! node mined is handed to [`qlab_faucet::Faucet::fund`] only once
//! `tip ≥ minted_height + 144`. Every note in the inventory is then mature by
//! construction, and no immature spend is ever built, let alone submitted. The
//! alternative — submitting undeclared — would make a demo work *today* by riding
//! #102, and is not taken.
//!
//! ## Loss bound (PR #103's, unchanged)
//!
//! `loss ≤ (blocks mined since rotation) × coinbase(h) + accrued change`, at a
//! 1,152-block rotation cadence. This crate keeps all three of its preconditions:
//! the balance is valueless (testnet), [`config::FaucetServiceConfig::hd_account`]
//! scopes the key to a non-zero HD account, and the key is never rendered — no type
//! here has a `Debug` that reaches the [`qlab_wallet::Wallet`], the seed is read
//! from a file this process never echoes, and the ticket secret redacts itself.

pub mod config;
pub mod harvest;
pub mod http;
pub mod service;
pub mod state;
pub mod view;

pub use config::{ConfigError, FaucetServiceConfig, DEFAULT_LISTEN_ADDR};
pub use harvest::{harvest_matured, HarvestReport};
pub use http::{FaucetServer, RequestOutcome};
pub use service::{FaucetGate, FaucetService, ServeReport};
pub use state::{Availability, ServiceStatus};
pub use view::NodeView;
