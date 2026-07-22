//! Depth-32 incremental commitment tree + versioned frontier serialization.
//!
//! Node hash is qlab-air's **exact consensus node hash**
//! (`qlab_air::reference::merkle_node_state`, digest = lanes 0..4) at
//! `MERKLE_DEPTH = 32` — the same tree the M3 bucket proves membership against.
//! Leaves are note commitments (`[u64; 4]`); empty positions hash the all-zero
//! leaf up the "zeros" ladder (Ethereum/Tornado-style incremental tree).
//!
//! The **frontier** is the Zcash-style `(rightmost leaf + left-sibling ommers)`
//! representation: it reconstructs the root of the first `n_leaves` positions
//! without any leaf data beyond the rightmost, in `O(depth)` bytes — exactly
//! what `/v1/tree/frontier` serves for light-client witness maintenance.
//!
//! ## Spec O5 (flagged)
//! wallet-interop-spec §2 says the frontier format is "the qlab-air frontier
//! serialization, versioned" — but qlab-air has none yet (spec **O5**). This is
//! the reference proposal; O5 stays a design-side freeze item. It is versioned
//! and round-trip/root-correctness tested, but NOT golden-frozen like the
//! compact-group framing.

use qlab_air::narrow::MerkleWitness;
use qlab_air::reference::merkle_node_state;
use qlab_note::hash::{digest_bytes, digest_from_bytes};

use crate::codec::{read_varint, write_varint, CodecError};
use crate::WIRE_VERSION;

/// Commitment-tree depth — qlab-air's `MERKLE_DEPTH`.
pub const DEPTH: usize = qlab_air::narrow::MERKLE_DEPTH;

/// The all-empty leaf (an unused position).
const EMPTY_LEAF: [u64; 4] = [0, 0, 0, 0];

fn hash_node(left: &[u64; 4], right: &[u64; 4]) -> [u64; 4] {
    let st = merkle_node_state(left, right);
    [st[0], st[1], st[2], st[3]]
}

/// `zeros[i]` = root of an all-empty subtree of height `i` (`zeros[0]` = the
/// empty leaf). Computed once via qlab-air's node hash.
pub fn zeros() -> [[u64; 4]; DEPTH + 1] {
    let mut z = [[0u64; 4]; DEPTH + 1];
    z[0] = EMPTY_LEAF;
    for i in 1..=DEPTH {
        z[i] = hash_node(&z[i - 1], &z[i - 1]);
    }
    z
}

/// An append-only commitment tree. Stores all leaves (a reference devnet holds a
/// modest set); root and frontier are derived over any prefix.
#[derive(Clone, Default)]
pub struct CommitmentTree {
    leaves: Vec<[u64; 4]>,
}

impl CommitmentTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a note commitment (as qlab-air `[u64; 4]` lanes). Returns its leaf
    /// position.
    pub fn append(&mut self, cm: [u64; 4]) -> u64 {
        let pos = self.leaves.len() as u64;
        self.leaves.push(cm);
        pos
    }

    /// Append from on-wire cm bytes (little-endian lanes).
    pub fn append_bytes(&mut self, cm: &[u8; 32]) -> u64 {
        self.append(digest_from_bytes(cm))
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Ground-truth root over the first `count` leaves (rest empty). `count`
    /// beyond the stored leaves is clamped.
    pub fn root_at(&self, count: u64) -> [u64; 4] {
        let z = zeros();
        let count = count.min(self.len());
        self.subtree_root(DEPTH, 0, count, &z)
    }

    /// Current root over all appended leaves.
    pub fn root(&self) -> [u64; 4] {
        self.root_at(self.len())
    }

    fn subtree_root(&self, level: usize, offset: u64, count: u64, z: &[[u64; 4]; DEPTH + 1]) -> [u64; 4] {
        let span = 1u64 << level;
        let start = offset * span;
        if start >= count {
            return z[level]; // wholly empty subtree
        }
        if level == 0 {
            return self.leaves[start as usize];
        }
        let left = self.subtree_root(level - 1, offset * 2, count, z);
        let right = self.subtree_root(level - 1, offset * 2 + 1, count, z);
        hash_node(&left, &right)
    }

    /// The depth-32 Merkle authentication path for the leaf at `position`, over
    /// the first `count` leaves (issue #39). Returns qlab-air's `MerkleWitness`
    /// directly, so it feeds `build_bucket_with_witnesses` with no glue: level
    /// `i`'s sibling is the subtree root adjacent to the node covering
    /// `position`, and `path_bits[i] = bit i of position` (set ⇒ the running
    /// digest is the RIGHT child, sibling on the left — the AIR's `pbit`).
    ///
    /// The path folds `leaves[position] → root_at(count)`; the wallet uses it as
    /// the live-tree membership witness for a note it is spending. Panics if
    /// `position >= count` (no membership witness exists for an unfilled leaf).
    pub fn auth_path(&self, position: u64, count: u64) -> MerkleWitness {
        let count = count.min(self.len());
        assert!(position < count, "auth_path: position {position} not among {count} leaves");
        let z = zeros();
        let mut siblings = [[0u64; 4]; DEPTH];
        let mut path_bits = [false; DEPTH];
        for (i, sib) in siblings.iter_mut().enumerate() {
            let node_offset = position >> i;
            path_bits[i] = node_offset & 1 == 1;
            *sib = self.subtree_root(i, node_offset ^ 1, count, &z);
        }
        MerkleWitness { siblings, path_bits }
    }

    /// The leaf commitment at `position` (the note commitment the auth path is
    /// witnessing). Panics if out of range.
    pub fn leaf(&self, position: u64) -> [u64; 4] {
        self.leaves[position as usize]
    }

    /// The leaf position of note commitment `cm`, if present — the lookup the
    /// prover uses to turn a wallet-derived leaf into an auth-path index
    /// (issue #39). Returns the FIRST match (commitments are globally unique by
    /// the ρ-uniqueness rule, so at most one is expected).
    pub fn position_of(&self, cm: &[u64; 4]) -> Option<u64> {
        self.leaves.iter().position(|l| l == cm).map(|p| p as u64)
    }

    /// Build the frontier over the first `count` leaves.
    pub fn frontier_at(&self, count: u64) -> Frontier {
        let count = count.min(self.len());
        if count == 0 {
            return Frontier { n_leaves: 0, leaf: EMPTY_LEAF, ommers: Vec::new() };
        }
        let position = count - 1;
        let leaf = self.leaves[position as usize];
        // Ommers: for each level i where bit i of `position` is set, the node is a
        // right child and needs its left sibling = the subtree root to its left.
        let z = zeros();
        let mut ommers = Vec::new();
        for i in 0..DEPTH {
            if (position >> i) & 1 == 1 {
                // Left sibling covers leaves [ (position>>i ^1) << i , ... ) i.e. the
                // subtree at level i, offset = (position >> i) - 1.
                let left_offset = (position >> i) - 1;
                ommers.push(self.subtree_root(i, left_offset, count, &z));
            }
        }
        Frontier { n_leaves: count, leaf, ommers }
    }

    /// Current frontier (all leaves).
    pub fn frontier(&self) -> Frontier {
        self.frontier_at(self.len())
    }
}

/// The Zcash-style frontier: rightmost leaf + left-sibling ommers, enough to
/// reconstruct the root in `O(depth)` bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frontier {
    pub n_leaves: u64,
    /// Rightmost leaf (ignored when `n_leaves == 0`).
    pub leaf: [u64; 4],
    /// Left siblings, one per set bit of `n_leaves - 1`, low level first.
    pub ommers: Vec<[u64; 4]>,
}

impl Frontier {
    /// Reconstruct the tree root from the frontier alone (no leaf store).
    pub fn root(&self) -> [u64; 4] {
        let z = zeros();
        if self.n_leaves == 0 {
            return z[DEPTH];
        }
        let position = self.n_leaves - 1;
        let mut node = self.leaf;
        let mut ommer = self.ommers.iter();
        for (i, zi) in z.iter().enumerate().take(DEPTH) {
            if (position >> i) & 1 == 1 {
                let left = ommer.next().copied().unwrap_or(EMPTY_LEAF);
                node = hash_node(&left, &node);
            } else {
                node = hash_node(&node, zi);
            }
        }
        node
    }

    /// Serialize (reference format, versioned — spec O5):
    /// `version ‖ depth(u8) ‖ n_leaves(varint) [‖ leaf(32) ‖ per level:
    /// present(u8) ‖ node(32 if present)]`. `present` mirrors the bits of
    /// `n_leaves-1` (a self-consistency check on decode).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(WIRE_VERSION);
        out.push(DEPTH as u8);
        write_varint(&mut out, self.n_leaves);
        if self.n_leaves == 0 {
            return out;
        }
        let position = self.n_leaves - 1;
        out.extend_from_slice(&digest_bytes(&self.leaf));
        let mut ommer = self.ommers.iter();
        for i in 0..DEPTH {
            if (position >> i) & 1 == 1 {
                out.push(1);
                let node = ommer.next().copied().unwrap_or(EMPTY_LEAF);
                out.extend_from_slice(&digest_bytes(&node));
            } else {
                out.push(0);
            }
        }
        out
    }

    /// Deserialize a frontier. Validates version, depth, and that the per-level
    /// `present` flags match the bits of `n_leaves-1`.
    pub fn from_bytes(b: &[u8]) -> Result<Frontier, CodecError> {
        let mut pos = 0usize;
        let ver = *b.get(pos).ok_or(CodecError::Truncated { what: "version" })?;
        pos += 1;
        if ver != WIRE_VERSION {
            return Err(CodecError::BadVersion { got: ver });
        }
        let depth = *b.get(pos).ok_or(CodecError::Truncated { what: "depth" })?;
        pos += 1;
        if depth as usize != DEPTH {
            return Err(CodecError::BadVersion { got: depth }); // depth mismatch ~ format mismatch
        }
        let n_leaves = read_varint(b, &mut pos)?;
        if n_leaves == 0 {
            if pos != b.len() {
                return Err(CodecError::TrailingBytes { remaining: b.len() - pos });
            }
            return Ok(Frontier { n_leaves: 0, leaf: EMPTY_LEAF, ommers: Vec::new() });
        }
        let read32 = |b: &[u8], pos: &mut usize| -> Result<[u64; 4], CodecError> {
            if b.len() < *pos + 32 {
                return Err(CodecError::Truncated { what: "frontier node" });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b[*pos..*pos + 32]);
            *pos += 32;
            Ok(digest_from_bytes(&arr))
        };
        let leaf = read32(b, &mut pos)?;
        let position = n_leaves - 1;
        let mut ommers = Vec::new();
        for i in 0..DEPTH {
            let present = *b
                .get(pos)
                .ok_or(CodecError::Truncated { what: "frontier present flag" })?;
            pos += 1;
            let bit = (position >> i) & 1 == 1;
            if (present == 1) != bit {
                // present flag disagrees with n_leaves — corrupt/forged frontier.
                return Err(CodecError::UnsupportedClue { clue_len: present });
            }
            if present == 1 {
                ommers.push(read32(b, &mut pos)?);
            }
        }
        if pos != b.len() {
            return Err(CodecError::TrailingBytes { remaining: b.len() - pos });
        }
        Ok(Frontier { n_leaves, leaf, ommers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(seed: u64) -> [u64; 4] {
        core::array::from_fn(|i| seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(i as u64 + 1))
    }

    #[test]
    fn empty_tree_root_is_zeros_top() {
        let t = CommitmentTree::new();
        assert_eq!(t.root(), zeros()[DEPTH]);
        assert_eq!(t.frontier().root(), zeros()[DEPTH], "empty frontier root matches");
    }

    #[test]
    fn frontier_root_matches_ground_truth_at_every_size() {
        // Cross the 1,2,3,...,17 boundary — powers of two and odd counts exercise
        // every ommer pattern.
        let mut t = CommitmentTree::new();
        for n in 1..=17u64 {
            t.append(cm(n));
            let ground = t.root();
            let f = t.frontier();
            assert_eq!(f.n_leaves, n);
            assert_eq!(f.root(), ground, "frontier root == ground-truth root at n={n}");
            // Ommer count = popcount(position).
            assert_eq!(f.ommers.len(), (n - 1).count_ones() as usize, "ommer count at n={n}");
        }
    }

    #[test]
    fn frontier_at_prefix_matches_fresh_tree() {
        // frontier_at(k) over a big tree == frontier of a tree built with only k leaves.
        let mut big = CommitmentTree::new();
        for n in 1..=20u64 {
            big.append(cm(n));
        }
        for k in 0..=20u64 {
            let mut small = CommitmentTree::new();
            for n in 1..=k {
                small.append(cm(n));
            }
            assert_eq!(big.root_at(k), small.root(), "root_at({k}) matches prefix tree");
            assert_eq!(big.frontier_at(k).root(), small.root(), "frontier_at({k}) root");
        }
    }

    #[test]
    fn frontier_serialization_roundtrip_and_root() {
        let mut t = CommitmentTree::new();
        for n in 1..=13u64 {
            t.append(cm(n));
        }
        for k in [0u64, 1, 2, 7, 8, 13] {
            let f = t.frontier_at(k);
            let bytes = f.to_bytes();
            let back = Frontier::from_bytes(&bytes).unwrap();
            assert_eq!(back, f, "frontier round-trips at k={k}");
            assert_eq!(back.root(), t.root_at(k), "reconstructed root at k={k}");
        }
    }

    #[test]
    fn frontier_decode_rejects_tampering() {
        let mut t = CommitmentTree::new();
        for n in 1..=5u64 {
            t.append(cm(n));
        }
        let good = t.frontier().to_bytes();
        // Bad version.
        let mut v = good.clone();
        v[0] = 0x02;
        assert!(matches!(Frontier::from_bytes(&v), Err(CodecError::BadVersion { .. })));
        // Bad depth.
        let mut d = good.clone();
        d[1] = 31;
        assert!(Frontier::from_bytes(&d).is_err());
        // Trailing byte.
        let mut tr = good.clone();
        tr.push(0);
        assert!(matches!(Frontier::from_bytes(&tr), Err(CodecError::TrailingBytes { .. })));
    }

    /// Issue #39: `auth_path(position)` folds `leaf → root_at(count)` for EVERY
    /// leaf at every tree size — the live-tree membership witness the prover
    /// consumes. Crosses power-of-two and odd boundaries so every ommer / path
    /// pattern is exercised.
    #[test]
    fn auth_path_folds_to_root_at_every_position() {
        let mut t = CommitmentTree::new();
        for n in 1..=18u64 {
            t.append(cm(n));
        }
        for count in 1..=18u64 {
            let root = t.root_at(count);
            for pos in 0..count {
                let w = t.auth_path(pos, count);
                let leaf = t.leaf(pos);
                assert_eq!(
                    w.fold_root(&leaf),
                    root,
                    "auth_path({pos}) must fold to root_at({count})"
                );
            }
        }
    }

    /// A tampered sibling in the witness folds to a DIFFERENT root — the witness
    /// genuinely carries the path (not a trivially-satisfiable stub).
    #[test]
    fn tampered_auth_path_changes_root() {
        let mut t = CommitmentTree::new();
        for n in 1..=9u64 {
            t.append(cm(n));
        }
        let count = t.len();
        let mut w = t.auth_path(3, count);
        let leaf = t.leaf(3);
        assert_eq!(w.fold_root(&leaf), t.root_at(count));
        w.siblings[0][0] ^= 1;
        assert_ne!(w.fold_root(&leaf), t.root_at(count), "tampered sibling must break the fold");
    }

    #[test]
    fn zeros_ladder_is_deterministic() {
        assert_eq!(zeros(), zeros());
        assert_eq!(zeros()[0], EMPTY_LEAF);
        // z[1] = H(0,0) via the consensus node hash.
        assert_eq!(zeros()[1], hash_node(&EMPTY_LEAF, &EMPTY_LEAF));
    }
}
