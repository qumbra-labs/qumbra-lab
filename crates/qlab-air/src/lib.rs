//! Fixed-shape AIR for the Qumbra 2x2-bucket circuit prototype:
//! 2 x depth-32 Merkle membership + 2 x nullifier PRF
//! + 2 x commitment well-formedness + in-circuit balance.
//!
//! M1 instantiates this over Poseidon2 (baseline) and the conservative
//! candidates (Keccak-f, SHA-256, BLAKE3 raw-AIR). See repo README.
//!
//! M1.5b adds the first real primitive: `narrow::NarrowKeccakAir`, a
//! correct-semantics Keccak-f[1600] at 371 columns (vs the published
//! 2,633-column AIR), validated against `reference::keccak_f`.

//! W3 (issue #700): `l2::L2ShapeSAir`, the L2 circuit family's shape S — a
//! new AIR type beside `narrow`, never an edit to it.

pub mod l2;
pub mod l2p;
pub mod l2r;
#[cfg(test)]
pub mod l2test;
pub mod narrow;
pub mod reference;
