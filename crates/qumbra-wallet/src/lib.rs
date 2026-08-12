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
//! empty result under `Complete` is "nothing was paid to this key **on the
//! chain's authority**"; under anything else it is "this scan could not know".
//! [`view`] renders that distinction with the same stable token `qumbra-opview`
//! and `qumbra-explorer` pin for refused supply figures, so one grep covers all
//! three surfaces.
//!
//! Since lab issue #314 that rule has a second half, and it is the one that was
//! missing: **a balance that could not subtract SPENDS is UNAVAILABLE too.** A
//! scan reads outputs, and the discovery wire carries no nullifier by design, so
//! a wallet that had spent kept quoting the spent note under `complete`.
//! [`spent`] closes it — the node serves per-block nullifiers in bulk, this
//! wallet derives its own notes' nullifiers with the spend path's own
//! derivation, and matches locally.

pub mod bundle;
pub mod contacts;
pub mod envelope;
pub mod history;
pub mod names;
pub mod net;
pub mod qr;
pub mod scan;
pub mod send;
pub mod sends;
pub mod spend;
pub mod spent;
pub mod store;
pub mod sync;
pub mod view;
