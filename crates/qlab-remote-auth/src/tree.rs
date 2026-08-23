//! The candidate outer authorization tree.
//!
//! WOTS+ leaf compression remains RFC 8391 SHA-256. This outer tree is a
//! separate Qumbra Keccak tree because a future AIR must prove the path with
//! the same conservative primitive already used by the note tree.

use crate::{keccak256, Hash32};

const MLDSA_LEAF_DOMAIN: &[u8] = b"qumbra:remote-auth:mldsa44-leaf:v1";
const NODE_DOMAIN: &[u8] = b"qumbra:remote-auth:tree-node:v1";

pub fn mldsa_leaf(tree_context: &Hash32, index: u32, verifying_key: &[u8]) -> Hash32 {
    keccak256(&[
        MLDSA_LEAF_DOMAIN,
        tree_context,
        &index.to_le_bytes(),
        verifying_key,
    ])
}

pub fn parent(tree_context: &Hash32, level: u32, left: &Hash32, right: &Hash32) -> Hash32 {
    keccak256(&[NODE_DOMAIN, tree_context, &level.to_le_bytes(), left, right])
}

pub fn root(mut leaves: Vec<Hash32>, tree_context: &Hash32) -> Result<Hash32, String> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err("authorization leaves must be a non-empty power of two".into());
    }
    let mut level = 0;
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(parent(tree_context, level, &pair[0], &pair[1]));
        }
        leaves = next;
        level += 1;
    }
    Ok(leaves[0])
}

pub fn fold_path(leaf: Hash32, mut index: u32, path: &[Hash32], tree_context: &Hash32) -> Hash32 {
    let mut node = leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = if index & 1 == 0 {
            parent(tree_context, level as u32, &node, sibling)
        } else {
            parent(tree_context, level as u32, sibling, &node)
        };
        index >>= 1;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_direction_and_level_are_bound() {
        let context = [9u8; 32];
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let expected = root(leaves.to_vec(), &context).unwrap();
        let sibling_at_1 = leaves[0];
        let sibling_parent = parent(&context, 0, &leaves[2], &leaves[3]);
        assert_eq!(
            fold_path(leaves[1], 1, &[sibling_at_1, sibling_parent], &context),
            expected
        );

        let wrong_context = [8u8; 32];
        assert_ne!(
            fold_path(
                leaves[1],
                1,
                &[sibling_at_1, sibling_parent],
                &wrong_context
            ),
            expected
        );
        assert_ne!(
            fold_path(leaves[1], 0, &[sibling_at_1, sibling_parent], &context),
            expected
        );
    }
}
