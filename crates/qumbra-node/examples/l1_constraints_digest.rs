//! Print the L1 constraints digest (the security re-mint).
//! **No proving** — Plonky3's symbolic evaluation of the canonical L1 AIR only.
//!
//! ```text
//! cargo run --release -p qumbra-node --example l1_constraints_digest
//! ```

fn main() {
    let (a, n) = qumbra_node::verifier::l1_constraints_digest();
    let (b, m) = qumbra_node::verifier::l1_constraints_digest();
    println!("L1 constraints digest {} ({n} constraints)", qlab_l2::digest::hex(&a));
    println!("deterministic in-process: {}", a == b && n == m);
}
