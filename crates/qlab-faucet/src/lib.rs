//! M11 faucet — **a wallet that generates proofs**, plus off-chain anti-abuse.
//!
//! On a shielded chain a faucet is not a web form. Every disbursement is a
//! transaction carrying a real STARK proof (~1.7 s on the rig that measured this
//! crate; see `docs/m11-faucet-run.md` for the caliper), so this crate is
//! **wallet work**: key custody, note inventory, membership witnesses, anchor
//! freshness, and a request gate whose scarce resource is not on-chain.
//!
//! ## The four things that bite, and where each one lives
//!
//! ### 1. Address unlinkability deletes the standard anti-abuse control
//!
//! The usual faucet control is "this address already claimed". Issue #32 made
//! diversified addresses genuinely unlinkable (`rkm = H(nk ‖ D_R ‖ d)`), so one
//! person can mint unlimited mutually-unlinkable addresses and **nothing on-chain
//! can join them**. That is the design working, not a defect — so the control has
//! to be off-chain, and it must not smuggle an on-chain identity in (that would
//! collide with `transaction-model-and-anonymity-set`'s core decision).
//!
//! [`policy`] holds the answer: an **operator-issued single-use ticket** as the
//! load-bearing control, with subnet/global token buckets as an explicitly
//! labelled *anti-accident* pre-filter. See [`policy`]'s module docs for why the
//! rate limits are not the control, stated in attacker cost rather than adjective.
//!
//! ### 2. The fixed arity caps grants per *note*, not per block — and it is a
//! ###    conservation law, not a 2×2 artifact
//!
//! In an *n*×*n* bucket the faucet spends *n* of its own notes and creates *n*
//! outputs, of which *g* leave for recipients and *n − g* return as change:
//!
//! ```text
//!   Δ(faucet note count) = −n + (n − g) = −g
//! ```
//!
//! **Every grant costs exactly one note, in every bucket size.** Two corollaries
//! the naive design misses:
//!
//! - A self-transaction is 2-in/2-out, i.e. **Δ0** — the note count can never be
//!   *increased* by a transaction. "Pre-cut the treasury into many small exact
//!   denominations" is therefore not a strategy that exists here: 1→N splitting is
//!   unrepresentable when inputs and outputs are equal in number. A recut can
//!   freely change note *values* (sum-preserving) but never their *count*.
//! - Bigger buckets amortise **proofs** (an 8×8 could serve 7 recipients on one
//!   proof) and buy **zero** extra grants.
//!
//! So the faucet's sustainable grant rate equals its **note inflow**, whose only
//! source is one coinbase note per block it wins: **≤ 1 grant per 75 s block**.
//! At ~1.7 s/proof the prover is ~97 % idle at 1 grant/min — proof speed is
//! ~15× away from being the binding constraint even at 10 grants/min. [`inventory`]
//! implements the budget this implies, and reports running out as a *named state*
//! rather than a silent stall.
//!
//! ### 3. There is nothing to pre-generate
//!
//! A grant proof binds the recipient's `rkm` through `cm_out`, so **no grant proof
//! can exist before its request does**. The 24 h anchor window
//! ([`qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS`] = 1,152 blocks) is
//! therefore not a shelf life for a queue of pre-made proofs — there is no such
//! queue. It is a **submission deadline** on a proof already built, and [`grant`]
//! models it as an [`grant::AnchorLease`] with a pre-submit re-check.
//!
//! ### 4. New money cannot be spent for three hours — and in this prototype, not
//! ###    at all
//!
//! `COINBASE_MATURITY_BLOCKS` = 144 × 75 s = 3.0 h gates spending fresh coinbase.
//! Underneath it sits a prototype boundary this crate had to work around and
//! reports rather than fixes: **a coinbase note never enters the commitment tree**
//! (`qlab_node::Node::apply_state` appends only `tx.commitments`; the mempool
//! records the coinbase note into a *registry*), so it has no leaf, no witness,
//! and cannot be spent by a real 2×2 proof today. The lab therefore funds the
//! faucet from a seeded note set, exactly as `qlab-demo` seeds its pre-existing
//! UTXOs, and the maturity constraint is bound at the seam that does exist —
//! [`service::Faucet`] declares the coinbase notes a grant consumes so
//! `Mempool::admit`'s frozen §2 gate runs on the real code path.
//!
//! ## What this crate is not
//!
//! **There is no listener here, deliberately.** `testnet-plan.md` §6 keeps
//! "public-facing ops hardening" as its own row — telemetry not public, no
//! committee keys on reachable hosts, log hygiene — and binding a hot spending key
//! to a public socket before that row's decisions exist would ship the exposure
//! that row exists to prevent. What ships instead is the whole request path as a
//! deterministic core ([`service::Faucet::accept`] → [`service::Faucet::dispense`]),
//! so the listener is a config decision over a tested core rather than a design
//! decision embedded in one.

#![recursion_limit = "512"]

pub mod grant;
pub mod inventory;
pub mod policy;
pub mod queue;
pub mod service;
pub mod view;

pub use grant::{AnchorLease, GrantError, GrantPlan, PROOF_LEASE_BLOCKS};
pub use inventory::{Inventory, InventoryError, OwnedNote};
pub use policy::{AbuseGate, FaucetLimits, Refusal, Ticket, TicketPolicy, TicketSecret};
pub use queue::{PendingRequest, QueueError, RequestQueue, MAX_QUEUE_DEPTH};
pub use service::{DispenseOutcome, Faucet, FaucetConfig, FaucetStats, DEFAULT_GRANT_BESSEL};
pub use view::ChainView;
