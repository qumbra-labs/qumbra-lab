//! Print the Annulet **devnet** genesis hash (lab #716; a local run named by
//! the stage-0 ruling, run twice for the byte-identical reproduction), and
//! with `--write PATH` write the genesis file for the devnet compose.
//!
//! ```text
//! cargo run --release -p qumbra-node --example annulet_devnet_genesis
//! ```

fn main() {
    let g = qumbra_node::annulet_genesis::AnnuletGenesisFile::devnet();
    g.verify(None).expect("the devnet genesis verifies");
    println!("annulet devnet genesis: {} bytes, hash {}", g.to_bytes().len(), g.hash_hex());
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--write") {
        let path = args.get(i + 1).expect("--write PATH");
        std::fs::write(path, g.to_bytes()).expect("write the genesis file");
        println!("written to {path}");
    }
}
