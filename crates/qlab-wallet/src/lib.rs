//! M7 wallet core for Qumbra — the KEY layer of the wallet.
//!
//! Implements, cross-checked byte-for-byte against the `qlab-air` spend-key
//! circuit and wired to the ratified `qlab-note` (KEM/AEAD/scan):
//!
//! - **Key hierarchy** (`keys`): root `sk` -> `nk` (nullifier key) -> `rkm`
//!   (recipient key material), and `nf` (nullifier). ALL are single-block,
//!   domain-separated Keccak derivations that reproduce EXACTLY what the STARK
//!   checks (`qlab_air::narrow::build_bucket`) — a wallet-made note must be
//!   spendable, so any drift is caught by regression locks against
//!   `build_bucket`'s public outputs.
//! - **Addresses** (`address`): diversified address = `(diversifier, rkm,
//!   ML-KEM-768 ek)` where `rkm = H(nk ‖ D_R ‖ d)` is now diversifier-dependent
//!   (issue #32), bech32m-class versioned+checksummed encoding, plus a
//!   short-address hash-commitment indirection (format only, no network).
//! - **Disclosure hooks** (`viewing`): `Fvk`/`Ivk` — the standing layer of
//!   `auditable-privacy.md` §4. Type-level capability split: `Fvk` views spends
//!   + incoming, `Ivk` views incoming only, NEITHER can spend (only
//!   [`keys::SpendingKey`] yields the circuit spend witness).
//!
//! NOT in scope (see `docs/m7-wallet-plan.md`): proving integration, networking,
//! persistence / HD-seed formats, and disclosure PROOFS (the selective-disclosure
//! STARK is a future milestone — only the KEY layer lives here).
//!
//! ## Address unlinkability (issue #32 — closed)
//!
//! The circuit now binds `rkm = H(nk ‖ D_R ‖ d)` (`qlab-air`), so a wallet's
//! diversified addresses carry DISTINCT `rkm` and are mutually unlinkable — the
//! shared-`rkm` linkability M7 flagged is gone. Because `rkm` binds `nk`
//! directly, `rkm`-derivation and address GENERATION are full-viewing-key
//! capabilities (an `Ivk` can no longer self-generate addresses; it retains
//! detect+decrypt, which recompute `cm` from the decrypted note). See
//! [`viewing`].
//!
//! ## Type-level spend separation
//!
//! Only [`Wallet`]/[`keys::SpendingKey`] can produce a spend witness. An `Fvk`
//! has no `spend_input` method — this does NOT compile:
//!
//! ```compile_fail
//! let w = qlab_wallet::Wallet::from_seed_lanes([1, 2, 3, 4]);
//! let fvk = w.fvk();
//! let d = qlab_wallet::address::Diversifier::default();
//! let _ = fvk.spend_input(100, [0; 4], [0; 4], d); // no such method on Fvk
//! ```
//!
//! An `Ivk` cannot view spends — it has no `nullifier` method:
//!
//! ```compile_fail
//! let w = qlab_wallet::Wallet::from_seed_lanes([1, 2, 3, 4]);
//! let ivk = w.ivk();
//! let _ = ivk.nullifier(&[0u64; 4]); // no such method on Ivk
//! ```
//!
//! And since issue #32 an `Ivk` cannot derive `rkm` / generate addresses — it
//! lacks `nk`, so neither method exists on it:
//!
//! ```compile_fail
//! let w = qlab_wallet::Wallet::from_seed_lanes([1, 2, 3, 4]);
//! let ivk = w.ivk();
//! let d = qlab_wallet::address::Diversifier::default();
//! let _ = ivk.address(d); // no such method on Ivk (needs nk to derive rkm(d))
//! ```

pub mod address;
pub mod bech32m;
pub mod keys;
pub mod mnemonic;
pub mod seed;
pub mod viewing;

pub use viewing::{Fvk, Ivk, Wallet};

