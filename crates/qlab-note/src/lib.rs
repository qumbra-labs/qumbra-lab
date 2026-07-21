//! M5 note-encryption prototype for Qumbra.
//!
//! Implements the "mechanical" half of `qumbra-design/note-discovery.md`
//! (ratified 2026-07-21): ML-KEM-768 encap/decap + AEAD over the note
//! plaintext, the ratified compact-entry wire layout (Decision 1/2), a
//! domain-separated detection tag, and a client scan flow with BOTH the
//! standard full-FO path and the EXPERIMENTAL FO-skip path.
//!
//! It does NOT decide discovery servers, OMR, or light-client sync, and it
//! does NOT contain the ANON-CCA security argument for the FO-skip path —
//! that is an OPEN design-repo obligation (doc §2). Path (a) full FO is the
//! default; path (b) FO-skip is marked EXPERIMENTAL.
//!
//! The note commitment is recomputed by CALLING qlab-air's exact hash layout
//! (`qlab_air::reference::keccak_f` + the `value‖rkm‖rho‖rseed` packing the
//! circuit binds) — never forked. See `note::note_commitment`.

pub mod derive;
pub mod hash;
pub mod kem;
pub mod note;
