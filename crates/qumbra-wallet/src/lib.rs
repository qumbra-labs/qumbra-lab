//! `qumbra-wallet` — the end-user wallet CLI (issue #243).
//!
//! ```text
//!   keygen    new seed (0600) + address 0 — key material NEVER printed
//!   restore   seed from a Qumbra mnemonic on STDIN (never argv)
//!   address   show / allocate diversified addresses
//!   backup    the mnemonic, only behind --reveal, with a warning
//!   scan      balance by light-client scan against a cbserver URL
//! ```
//!
//! Deliberately absent: `send` (C3-gated — the dummy mechanism and the mint;
//! the seam is `qlab_wallet::keys::SpendAuth::spend_input` + a submission
//! surface, and it is named here so the next baton starts from a sentence, not
//! a search) · any embedded node (scan is an HTTP client) · GUI/QR (the
//! shells' business — see the design repo's wallet briefs).
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

pub mod store;
pub mod view;
