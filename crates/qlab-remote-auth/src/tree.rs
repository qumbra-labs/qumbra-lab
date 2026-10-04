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

/// Which node hash a tree uses.
///
/// - `SpikeV1` is the Phase 1 spike's domain- and level-tagged [`parent`]. The
///   L1 Phase 2 vectors use it; the L1 Phase 3 decides whether L1 converges.
/// - `AirMerkle` is the Annulet tree (design `remote-proving-authorization-
///   shape-annulet` §10 decided 2): byte-identical to `qlab-air`'s
///   `merkle_node_state`, i.e. Keccak-256 of `left ‖ right` with no domain and
///   no level, so the AIR's existing `ROLE_MERKLE` proves the path. The fixed
///   depth `D_AUTH` replaces the level tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeVersion {
    SpikeV1,
    AirMerkle,
}

/// The `AirMerkle` node: `keccak256(left ‖ right)`.
pub fn air_node(left: &Hash32, right: &Hash32) -> Hash32 {
    keccak256(&[left, right])
}

pub fn node(version: TreeVersion, level: u32, left: &Hash32, right: &Hash32) -> Hash32 {
    node_hash(version, level, left, right)
}

fn node_hash(version: TreeVersion, level: u32, left: &Hash32, right: &Hash32) -> Hash32 {
    match version {
        TreeVersion::SpikeV1 => parent(level, left, right),
        TreeVersion::AirMerkle => air_node(left, right),
    }
}

pub fn root(leaves: Vec<Hash32>) -> Result<Hash32, String> {
    root_with(TreeVersion::SpikeV1, leaves)
}

pub fn root_with(version: TreeVersion, mut leaves: Vec<Hash32>) -> Result<Hash32, String> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err("authorization leaves must be a non-empty power of two".into());
    }
    let mut level = 0;
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(node_hash(version, level, &pair[0], &pair[1]));
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
    version: TreeVersion,
    depth: u8,
    leaves: u64,
    frontier: Vec<Option<Hash32>>,
}

impl RootAccumulator {
    pub fn new(depth: u8) -> Result<Self, String> {
        Self::new_with(TreeVersion::SpikeV1, depth)
    }

    pub fn new_with(version: TreeVersion, depth: u8) -> Result<Self, String> {
        if depth > 31 {
            return Err("authorization-tree depth must be at most 31".into());
        }
        Ok(Self {
            version,
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
            node = node_hash(self.version, level as u32, &left, &node);
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

pub fn fold_path(leaf: Hash32, index: u32, path: &[Hash32]) -> Hash32 {
    fold_path_with(TreeVersion::SpikeV1, leaf, index, path)
}

pub fn fold_path_with(
    version: TreeVersion,
    leaf: Hash32,
    mut index: u32,
    path: &[Hash32],
) -> Hash32 {
    let mut node = leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = if index & 1 == 0 {
            node_hash(version, level as u32, &node, sibling)
        } else {
            node_hash(version, level as u32, sibling, &node)
        };
        index >>= 1;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pycryptodome Keccak-256 of 64 zero bytes (independent reference).
    const AIR_NODE_ZERO_VECTOR: &str =
        "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";
    /// AIR-form root over leaves `[1;32] [2;32] [3;32] [4;32]` (pycryptodome).
    const AIR_ROOT_1234_VECTOR: &str =
        "99976d3b1539e7cfaca77649ac7536fec61db00fb0835634915b4d542fff06ae";

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

    /// The `AirMerkle` node equals `qlab-air` `merkle_node_state` built by hand:
    /// `left` in lanes 0..4, `right` in lanes 4..8 (u64 LE), pad bit 512 in
    /// lane 8, bit 1087 in lane 16, one Keccak-f, digest = lanes 0..4 LE.
    #[test]
    fn air_node_is_byte_identical_to_the_air_merkle_state() {
        let lanes = |h: &Hash32| -> [u64; 4] {
            std::array::from_fn(|i| u64::from_le_bytes(h[i * 8..i * 8 + 8].try_into().unwrap()))
        };
        for (l, r) in [
            ([0u8; 32], [0u8; 32]),
            ([0x5a; 32], [0xc3; 32]),
            ([0xff; 32], [0x01; 32]),
        ] {
            let mut st = [0u64; 25];
            st[..4].copy_from_slice(&lanes(&l));
            st[4..8].copy_from_slice(&lanes(&r));
            st[8] = 1;
            st[16] = 1 << 63;
            tiny_keccak::keccakf(&mut st);
            let mut digest = [0u8; 32];
            for i in 0..4 {
                digest[i * 8..i * 8 + 8].copy_from_slice(&st[i].to_le_bytes());
            }
            assert_eq!(air_node(&l, &r), digest);
        }
        // Independently computed (pycryptodome Keccak-256 of 64 zero bytes).
        assert_eq!(
            crate::hex(&air_node(&[0u8; 32], &[0u8; 32])),
            AIR_NODE_ZERO_VECTOR
        );
        // No level tag: the same pair hashes the same at every level, unlike the spike.
        assert_eq!(
            node(TreeVersion::AirMerkle, 0, &[1; 32], &[2; 32]),
            node(TreeVersion::AirMerkle, 5, &[1; 32], &[2; 32])
        );
        assert_ne!(
            node(TreeVersion::AirMerkle, 0, &[1; 32], &[2; 32]),
            parent(0, &[1; 32], &[2; 32])
        );
    }

    #[test]
    fn air_tree_streams_folds_and_matches_its_vector() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let batch = root_with(TreeVersion::AirMerkle, leaves.to_vec()).unwrap();
        let mut streaming = RootAccumulator::new_with(TreeVersion::AirMerkle, 2).unwrap();
        for leaf in leaves {
            streaming.push(leaf).unwrap();
        }
        assert_eq!(streaming.finish().unwrap(), batch);
        let path = [leaves[0], air_node(&leaves[2], &leaves[3])];
        assert_eq!(
            fold_path_with(TreeVersion::AirMerkle, leaves[1], 1, &path),
            batch
        );
        assert_ne!(
            fold_path_with(TreeVersion::AirMerkle, leaves[1], 0, &path),
            batch
        );
        assert_ne!(batch, root(leaves.to_vec()).unwrap());
        assert_eq!(crate::hex(&batch), AIR_ROOT_1234_VECTOR);
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
