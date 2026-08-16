//! `qumbra-wallet` — the end-user wallet CLI (issue #243).
//!
//! ```text
//!   keygen    new seed (0600) + address 0 — key material NEVER printed
//!   restore   seed from a Qumbra mnemonic on STDIN (never argv)
//!   address   show / allocate diversified addresses
//!   contact   save / list / remove local names for full addresses
//!   backup    the mnemonic, only behind --reveal, with a warning
//!   scan      balance by light-client scan against a cbserver URL
//!   send      scan → sync the tree → prove → POST /v1/tx (issue #276)
//!   history   this wallet's own chronological ledger, derived from the chain
//! ```
//!
//! `history` is the wallet-side transaction view: the chain publishes opaque
//! commitments and nullifiers, and the wallet is the only party that can say
//! which of them are its own. [`history`] derives receipts, spends and
//! reconstructed send events from the two streams `scan` already uses, keeping
//! one line visible throughout — **what the chain proves versus what this
//! machine merely remembers** ([`sends`], the optional and always-labeled local
//! record of who a past send paid).
//!
//! `send` is **wired** as of issue #276, the wallet half of
//! `t1-wallet-send-seams-decision.md` (STAMPED 2026-08-06, A1+B1): [`send`]
//! builds and REALLY proves against the merged #219 latch (lab PR #252),
//! [`sync`] maintains the local commitment tree over the served leaf stream and
//! picks the anchor a witness may legally be built at, and [`net`] carries both
//! served seams — `GET /v1/tree/leaves` + `GET /v1/anchors` in, `POST /v1/tx`
//! out. The server half is #275.
//!
//! **Still nodeless, which is the A2 rejection kept.** Every one of those is an
//! HTTP client against somebody else's node; this crate runs no node, mines
//! nothing, and gossips nothing. Deliberately absent: GUI (the shells'
//! business — see the design repo's wallet briefs). QR left this list with
//! lab #342: `name-service-decision.md` §3 (2026-08-10) pins the T1 answer to
//! long-address pain as contact book + QR, so [`qr`] renders payment URIs
//! (`qlab_wallet::uri`) to the terminal and to SVG.
//!
//! # The two disciplines everything here bends around
//!
//! **Key material never reaches stdout by default.** `keygen` prints the
//! address only; the mnemonic exists on a terminal exactly when `backup
//! --reveal` is an explicit act. `restore` reads from stdin because argv is
//! visible to `ps` and shell history.
//!
//! **A balance the scan could not establish is UNAVAILABLE, never 0.**
//! [`qlab_cbserver::client::Completeness`] already says which is which — an
//! empty result under `Complete` is "no **transaction** paid this key **on the
//! chain's authority**"; under anything else it is "this scan could not know".
//!
//! 🔴 **`Complete` covers transactions only — coinbase is outside it by
//! construction, and since lab #415 the wallet fetches the other half rather
//! than only naming it.** [`coinbase`] pages `GET /v1/coinbase`, matches the
//! served payees against this wallet's own `rkm` lanes locally, reconstructs
//! each mined note through the applier's own derivation
//! (`qlab_node::coinbase_note_parts`) and splits it spendable vs maturing per
//! the frozen §2 delay. **The verdict language below un-narrows only for a scan
//! that actually fetched that route to the same height** — against a node that
//! does not serve it (every host older than #415) the refusal is named and the
//! narrowed claim stands. What follows is why the claim had to be narrowed in
//! the first place: The compact wire is `CompactBlock { height, groups }`
//! with no `coinbase_rkm`, so no wallet has ever been able to detect a coinbase
//! note; `qumbra-faucet` finds its own only because it walks its own node's main
//! chain, which a wallet by design does not have. A mining-only wallet therefore
//! reads `spendable: 0 · complete` forever. That is the same shape as lab #314 —
//! a confident figure over a half nobody had — one dimension further out, and it
//! is why the rendered line now names what it did not look at instead of claiming
//! the chain's authority over it.
//! [`view`] renders that distinction with the same stable token `qumbra-opview`
//! and `qumbra-explorer` pin for refused supply figures, so one grep covers all
//! three surfaces.
//!
//! 🔴 **And since lab #424 `send` spends them too.** [`driver`]'s phase 1 pages
//! the same route and offers this wallet's MATURE mined notes as inputs — a
//! maturing one never — so a mining-only wallet is no longer a balance that can
//! be read and not spent. When that route cannot be read the send does **not**
//! refuse (Larry's 2026-08-16 ruling): it proceeds on transaction notes and
//! names the degradation with [`coinbase::TRANSACTIONS_ONLY`], the same token
//! the scan's balance line prints. The nullifier path is untouched and stays
//! fail-closed — the asymmetry is the ruling's whole argument.
//!
//! Since lab issue #314 that rule has a second half, and it is the one that was
//! missing: **a balance that could not subtract SPENDS is UNAVAILABLE too.** A
//! scan reads outputs, and the discovery wire carries no nullifier by design, so
//! a wallet that had spent kept quoting the spent note under `complete`.
//! [`spent`] closes it — the node serves per-block nullifiers in bulk, this
//! wallet derives its own notes' nullifiers with the spend path's own
//! derivation, and matches locally.

pub mod bundle;
pub mod coinbase;
pub mod contacts;
pub mod driver;
pub mod envelope;
pub mod names;
#[cfg(feature = "net")]
pub mod net;
pub mod qr;
pub mod scan;
pub mod send;
pub mod spend;
pub mod store;
pub mod sync;
pub mod view;
// Moved to qlab-ledger (#407); re-exported so this crate keeps one set of
// paths and there is still exactly one implementation.
pub use qlab_ledger::{history, sends, spent};
pub mod ledger_run;
pub mod sends_build;
pub mod words;
