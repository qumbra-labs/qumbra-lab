//! qlab-wrapper — the **verification half** of the L2 wrapper (lab #785,
//! F5-1): W's AIR ([`wleaf::WAir`]), the deposit-sum AIR ([`dep::DepAir`]),
//! [`verify::verify_wrapper`] (V0–V9) with its [`verify::Surface`] and
//! [`verify::VERSIONS`], the public-value layout, and the F3 pieces they
//! are built from. It exists so the L1 can run `verify_wrapper` as
//! consensus (F5, the bundle form): consensus code cannot depend on
//! qlab-bench, which keeps the prover side (trace plans, rendering,
//! fixtures) and re-exports everything here, so its tests are unchanged.
//!
//! Moved, not rewritten: every item is qlab-bench's (lab #775 F4, #767 F3)
//! with `pub(crate)` widened to `pub`.
//!
//! F5-4a adds what consensus needs beyond the verifier: [`genesis`] (the
//! empty L2 state's roots and the genesis surface) and [`codec`] (the
//! canonical surface and bundle bytes, the sequencer's signed message, the
//! exit list's chain).
pub mod cmp;
pub mod codec;
pub mod config;
pub mod dep;
pub mod genesis;
pub mod hash;
pub mod lane;
pub mod verify;
pub mod wleaf;
