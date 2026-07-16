//! Fixed-shape AIR for the Qumbra 2x2-bucket circuit prototype:
//! 2 x depth-32 Merkle membership + 2 x nullifier PRF
//! + 2 x commitment well-formedness + in-circuit balance.
//!
//! M1 instantiates this over Poseidon2 (baseline) and the conservative
//! candidates (Keccak-f, SHA-256, BLAKE3 raw-AIR). See repo README.
