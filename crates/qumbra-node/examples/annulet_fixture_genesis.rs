//! Print the B1 fixture Annulet genesis hash (lab #706; a local run named by
//! the stage-0 ruling, run twice for the byte-identical reproduction). One
//! seeded ML-DSA keygen and a bincode; sub-second.
//!
//! ```text
//! cargo run --release -p qumbra-node --example annulet_fixture_genesis
//! ```

fn main() {
    let g = qumbra_node::annulet_genesis::AnnuletGenesisFile::fixture();
    g.verify(None).expect("the fixture verifies");
    println!("annulet fixture genesis: {} bytes, hash {}", g.to_bytes().len(), g.hash_hex());
}
