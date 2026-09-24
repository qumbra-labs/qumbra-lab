//! **The pool's registry check, priced** (L2-C4a Q8, lab #730). A shape-R
//! write is admitted only if its leaf, written into the node's registry,
//! reaches the root it declares (`NodeState::annulet_registry_write_root`,
//! lab #728 B3b): clone the registry, write the leaf, read the root. The node
//! pays the same again on apply. This prices one admission at 1, 1,000 and
//! 65,536 registered leaves (the last is every slot: the write is an update).
//!
//! `qlab-bench registry-admit` — the number is the coordinator's, on the rig
//! (bench discipline 1–3); the lane runs the smoke only.

use std::time::{Duration, Instant};

use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_node::registry_store::{MemRegistryStore, RegistryStore as _};

/// Iterations per size (min and median reported).
const RUNS: usize = 21;

/// Asset 0 plus `n − 1` Hybrid leaves at slots 1.. (so `n` registered).
pub fn registry_of(n: usize) -> MemRegistryStore {
    assert!((1..=1 << 16).contains(&n), "a registry holds 1..=65,536 leaves");
    let leaves: Vec<RegistryLeaf> = (0..n as u64)
        .map(|a| {
            if a == 0 {
                RegistryLeaf::cloaked(0)
            } else {
                RegistryLeaf { asset: a, issuer_key: [a, 1, 2, 3], mode: MODE_HYBRID, freeze_root: [a, 4, 5, 6], allow_root: [0; 4], flags: 0 }
            }
        })
        .collect();
    MemRegistryStore::from_genesis(&leaves).expect("a well-formed registry")
}

/// The write one admission checks: a registration into the first empty slot,
/// or (a full registry) an update of slot 7.
pub fn write_for(n: usize) -> [u64; 15] {
    let asset = if n < 1 << 16 { n as u64 } else { 7 };
    let leaf = RegistryLeaf { asset, issuer_key: [9, 9, 9, 9], mode: MODE_HYBRID, freeze_root: [1, 2, 3, 4], allow_root: [0; 4], flags: 0 };
    leaf.state()[..15].try_into().expect("15 lanes")
}

/// One admission's check, as the pool runs it: clone, write, root.
pub fn admit_once(store: &MemRegistryStore, lanes: &[u64; 15]) -> ([u8; 32], Duration) {
    let t = Instant::now();
    let mut next = store.clone();
    next.apply_write(lanes).expect("the write applies");
    let root = next.root_bytes();
    (root, t.elapsed())
}

pub fn run_registry_admit(power: &str) {
    println!("# qumbra-lab registry-admit bench (L2-C4a Q8, lab #730)");
    println!();
    crate::print_env(power);
    println!("- what: `annulet_registry_write_root` — clone the registry, write one leaf, read the root");
    println!("- per size: min and median of {RUNS} runs, one process, after one warm-up");
    println!();
    println!("| registered leaves | write | min ms | median ms |");
    println!("|---|---|---|---|");
    for n in [1usize, 1_000, 1 << 16] {
        let store = registry_of(n);
        let lanes = write_for(n);
        let _ = admit_once(&store, &lanes);
        let mut ts: Vec<Duration> = (0..RUNS).map(|_| admit_once(&store, &lanes).1).collect();
        ts.sort();
        let kind = if n < 1 << 16 { "registration" } else { "update (full registry)" };
        println!(
            "| {n} | {kind} | {:.3} | {:.3} |",
            ts[0].as_secs_f64() * 1e3,
            ts[RUNS / 2].as_secs_f64() * 1e3
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane's smoke: the priced operation is the pool's — the root it
    /// reaches is the registry rebuilt with the leaf — at the small sizes (the
    /// 65,536 figure is the rig's).
    #[test]
    fn registry_admit_prices_the_pools_check() {
        for n in [1usize, 1_000] {
            let store = registry_of(n);
            let lanes = write_for(n);
            let (root, _) = admit_once(&store, &lanes);
            let mut rebuilt = store.clone();
            rebuilt.apply_write(&lanes).unwrap();
            assert_eq!(root, rebuilt.root_bytes());
            assert_ne!(root, store.root_bytes(), "the write moves the root");
        }
    }
}
