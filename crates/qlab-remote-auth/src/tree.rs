//! The candidate outer authorization tree.
//!
//! WOTS+ leaf compression remains RFC 8391 SHA-256. This outer tree is a
//! separate Qumbra Keccak tree because a future AIR must prove the path with
//! the same conservative primitive already used by the note tree.

use crate::{keccak256, Hash32};

const MLDSA_LEAF_DOMAIN: &[u8] = b"qumbra:remote-auth:mldsa44-leaf:v1";
const NODE_DOMAIN: &[u8] = b"qumbra:remote-auth:tree-node:v1";

pub fn mldsa_leaf(index: u32, verifying_key: &[u8]) -> Hash32 {
    keccak256(&[MLDSA_LEAF_DOMAIN, &index.to_le_bytes(), verifying_key])
}

pub fn parent(level: u32, left: &Hash32, right: &Hash32) -> Hash32 {
    keccak256(&[NODE_DOMAIN, &level.to_le_bytes(), left, right])
}

pub fn root(mut leaves: Vec<Hash32>) -> Result<Hash32, String> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err("authorization leaves must be a non-empty power of two".into());
    }
    let mut level = 0;
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(parent(level, &pair[0], &pair[1]));
        }
        leaves = next;
        level += 1;
    }
    Ok(leaves[0])
}

/// Streaming root builder for one complete depth-fixed authorization tree.
///
/// A phone can generate each public leaf, hand it to a service-side cache, and
/// retain only this `O(depth)` frontier while independently computing the root
/// it commits into its address. The cache never receives the address master or
/// any leaf signing seed. Leaves must arrive once in ascending public-index
/// order; incomplete trees and extra leaves are refused.
pub struct RootAccumulator {
    depth: u8,
    leaves: u64,
    frontier: Vec<Option<Hash32>>,
}

impl RootAccumulator {
    pub fn new(depth: u8) -> Result<Self, String> {
        if depth > 31 {
            return Err("authorization-tree depth must be at most 31".into());
        }
        Ok(Self {
            depth,
            leaves: 0,
            frontier: vec![None; depth as usize + 1],
        })
    }

    pub const fn expected_leaves(&self) -> u64 {
        1u64 << self.depth
    }

    pub const fn leaves_pushed(&self) -> u64 {
        self.leaves
    }

    pub fn push(&mut self, leaf: Hash32) -> Result<(), String> {
        if self.leaves >= self.expected_leaves() {
            return Err("authorization tree already has every leaf".into());
        }

        let mut node = leaf;
        let mut position = self.leaves;
        let mut level = 0usize;
        while position & 1 == 1 {
            let left = self.frontier[level]
                .take()
                .ok_or("authorization-tree frontier is inconsistent")?;
            node = parent(level as u32, &left, &node);
            position >>= 1;
            level += 1;
        }
        self.frontier[level] = Some(node);
        self.leaves += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<Hash32, String> {
        if self.leaves != self.expected_leaves() {
            return Err(format!(
                "authorization tree is incomplete: got {} of {} leaves",
                self.leaves,
                self.expected_leaves()
            ));
        }
        self.frontier[self.depth as usize]
            .take()
            .ok_or("authorization-tree root is missing".into())
    }
}

pub fn fold_path(leaf: Hash32, mut index: u32, path: &[Hash32]) -> Hash32 {
    let mut node = leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = if index & 1 == 0 {
            parent(level as u32, &node, sibling)
        } else {
            parent(level as u32, sibling, &node)
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
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let expected = root(leaves.to_vec()).unwrap();
        let sibling_at_1 = leaves[0];
        let sibling_parent = parent(0, &leaves[2], &leaves[3]);
        assert_eq!(
            fold_path(leaves[1], 1, &[sibling_at_1, sibling_parent]),
            expected
        );

        assert_ne!(
            fold_path(leaves[1], 0, &[sibling_at_1, sibling_parent]),
            expected
        );
        assert_ne!(
            parent(1, &leaves[0], &leaves[1]),
            parent(0, &leaves[0], &leaves[1])
        );
    }

    #[test]
    fn streaming_root_matches_the_batch_tree_and_refuses_wrong_cardinality() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let mut streaming = RootAccumulator::new(2).unwrap();
        for leaf in leaves {
            streaming.push(leaf).unwrap();
        }
        assert_eq!(streaming.finish().unwrap(), root(leaves.to_vec()).unwrap());

        let mut incomplete = RootAccumulator::new(2).unwrap();
        incomplete.push(leaves[0]).unwrap();
        assert!(incomplete.finish().is_err());

        let mut full = RootAccumulator::new(0).unwrap();
        full.push(leaves[0]).unwrap();
        assert!(full.push(leaves[1]).is_err());
        assert_eq!(full.finish().unwrap(), leaves[0]);
    }
}
