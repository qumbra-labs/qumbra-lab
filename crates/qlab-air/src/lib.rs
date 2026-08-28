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

pub mod narrow;
pub mod reference;

// THROWAWAY — lab #691 red-path demo. `qlab_air`'s lib is test binary #1 of
// 115 in cargo's order; a failure here under --no-fail-fast must leave the
// other 142 result sets in the log. This commit is reverted on the branch.
#[cfg(test)]
mod red_path_demo_691 {
    #[test]
    fn deliberately_red() {
        panic!("baton #691 red-path demo");
    }
}
