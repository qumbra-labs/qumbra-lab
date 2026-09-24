//! Print the canonical policy tree goldens (lab #722) — a named local run of
//! the C3 ruling, run twice for byte-identical output. Each root is computed
//! by the builder (`CanonicalFreezeTree`, the zero-chain shortcut) and by an
//! independent encoder here (a naive full-width fold over the padded 2^20
//! leaf array), and the two must agree.
//!
//! ```text
//! cargo run --release -p qlab-air --example canonical_policy_tree_goldens
//! ```

use qlab_air::l2p::{freeze_key_of, freeze_leaf_hash, CanonicalFreezeTree, KEY_MAX, POLICY_DEPTH};

/// The independent encoder: every one of the 2^20 slots, folded level by level.
fn naive_root(leaves: &[[u64; 4]]) -> [u64; 4] {
    let mut cur: Vec<[u64; 4]> = (0..1usize << POLICY_DEPTH).map(|i| leaves.get(i).copied().unwrap_or([0; 4])).collect();
    while cur.len() > 1 {
        cur = cur
            .chunks(2)
            .map(|p| qlab_air::reference::merkle_node_state(&p[0], &p[1])[..4].try_into().unwrap())
            .collect();
    }
    cur[0]
}

fn indexed_leaves(keys: &[[u64; 4]]) -> Vec<[u64; 4]> {
    let mut sorted = keys.to_vec();
    sorted.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut bounds = vec![[0u64; 4]];
    bounds.extend(sorted);
    bounds.push(KEY_MAX);
    bounds.windows(2).map(|w| freeze_leaf_hash(&w[0], &w[1])).collect()
}

fn hex(l: &[u64; 4]) -> String {
    l.iter().map(|x| format!("{x:016x}")).collect::<Vec<_>>().join("_")
}

fn main() {
    let three: Vec<[u64; 4]> = (1..=3u64).map(|i| freeze_key_of(&[i, i, i, i])).collect();
    for (name, keys) in [("empty", Vec::new()), ("three_keys", three)] {
        let built = CanonicalFreezeTree::from_keys(&keys).root;
        let naive = naive_root(&indexed_leaves(&keys));
        assert_eq!(built, naive, "{name}: the builder and the independent encoder disagree");
        println!("{name}: {}", hex(&built));
    }
}
