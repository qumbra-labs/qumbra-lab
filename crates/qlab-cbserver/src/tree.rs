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

/// The consensus node hash (shared with the registry tree, lab #710).
pub(crate) fn hash_node(left: &[u64; 4], right: &[u64; 4]) -> [u64; 4] {
    let st = merkle_node_state(left, right);
    [st[0], st[1], st[2], st[3]]
}

/// `zeros[i]` = root of an all-empty subtree of height `i` (`zeros[0]` = the
/// empty leaf). Computed once via qlab-air's node hash (process-wide, #386 —
/// the ladder was previously re-hashed on every call).
pub fn zeros() -> [[u64; 4]; DEPTH + 1] {
    static ZEROS: std::sync::OnceLock<[[u64; 4]; DEPTH + 1]> = std::sync::OnceLock::new();
    *ZEROS.get_or_init(|| {
        let mut z = [[0u64; 4]; DEPTH + 1];
        z[0] = EMPTY_LEAF;
        for i in 1..=DEPTH {
            z[i] = hash_node(&z[i - 1], &z[i - 1]);
        }
        z
    })
}

/// An append-only commitment tree. Stores all leaves (a reference devnet holds a
/// modest set — and `auth_path`/`position_of`/historical `root_at` need them);
/// root and frontier are derived over any prefix.
///
/// The CURRENT root is incremental (#386): `append` folds the new leaf into the
/// cached right-edge frontier in O(depth) node hashes and memoises the root, so
/// `root()` is O(1) and per-block apply cost is flat in tree size. Historical
/// prefixes (`root_at`, `auth_path`, `frontier_at` for `count < len`) keep the
/// O(n) `subtree_root` walk — off the hot path, and `root_at` doubles as the
/// ground truth the S1 byte-identity property test pins `root()` against.
#[derive(Clone)]
pub struct CommitmentTree {
    leaves: Vec<[u64; 4]>,
    /// Right-edge frontier: `filled[i]` is the root of a COMPLETE subtree of
    /// height `i` awaiting its right sibling — meaningful exactly where bit `i`
    /// of `leaves.len()` is set (`filled[DEPTH]` only for the full tree). The
    /// O(depth) state that lets `append` extend the root without walking leaves.
    filled: [[u64; 4]; DEPTH + 1],
    /// Memoised root over all appended leaves, maintained by `append`.
    root: [u64; 4],
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new(), filled: [[0u64; 4]; DEPTH + 1], root: zeros()[DEPTH] }
    }

    /// Append a note commitment (as qlab-air `[u64; 4]` lanes). Returns its leaf
    /// position. O(depth) node hashes (#386): a binary-counter carry into the
    /// frontier, then one fold to refresh the memoised root.
    pub fn append(&mut self, cm: [u64; 4]) -> u64 {
        let pos = self.leaves.len() as u64;
        assert!(pos < 1u64 << DEPTH, "depth-{DEPTH} commitment tree is full");
        // Carry: while this node is a right child (bit set), merge with the
        // completed left sibling below it; park it at the first empty level.
        let mut node = cm;
        let mut level = 0usize;
        let mut idx = pos;
        while idx & 1 == 1 {
            node = hash_node(&self.filled[level], &node);
            level += 1;
            idx >>= 1;
        }
        self.filled[level] = node;
        self.leaves.push(cm);
        self.root = self.fold_frontier_root();
        pos
    }

    /// Root over `leaves.len()` leaves from the frontier alone: fold up along
    /// the path of the next empty slot `n` — where bit `i` of `n` is set the
    /// left sibling is the complete subtree `filled[i]`, otherwise the right
    /// sibling is the all-empty `zeros[i]`.
    fn fold_frontier_root(&self) -> [u64; 4] {
        let n = self.leaves.len() as u64;
        if n == 1u64 << DEPTH {
            return self.filled[DEPTH];
        }
        let z = zeros();
        let mut node = z[0];
        for i in 0..DEPTH {
            node = if (n >> i) & 1 == 1 {
                hash_node(&self.filled[i], &node)
            } else {
                hash_node(&node, &z[i])
            };
        }
        node
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
    /// beyond the stored leaves is clamped. Deliberately still the O(n)
    /// `subtree_root` walk (#386): historical anchors are off the hot path, and
    /// keeping this path untouched is what makes it the ground truth the S1
    /// byte-identity test pins the incremental `root()` against.
    pub fn root_at(&self, count: u64) -> [u64; 4] {
        let z = zeros();
        let count = count.min(self.len());
        self.subtree_root(DEPTH, 0, count, &z)
    }

    /// Current root over all appended leaves. O(1): the frontier-memoised value
    /// (#386); byte-identity to `root_at(len)` at every count is S1's property.
    pub fn root(&self) -> [u64; 4] {
        self.root
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

    /// Deterministic pseudo-random leaf (splitmix64 over a per-set seed) — a
    /// randomised leaf set that is reproducible across runs and machines.
    fn rand_cm(seed: u64, i: u64) -> [u64; 4] {
        let mut x = seed ^ i.wrapping_mul(0x9e3779b97f4a7c15);
        core::array::from_fn(|lane| {
            x = x.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = x ^ (lane as u64).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        })
    }

    /// Issue #386 S1 — THE acceptance spine. `root()` must be byte-identical to
    /// the ground-truth `root_at(count)` (the `subtree_root` walk) at EVERY
    /// count: `roots_by_height` is the anchor set every STARK verifies against,
    /// and a single mismatch at a single count is a chain fork.
    ///
    /// Checks every count 0..=2048 over two independent randomised leaf sets,
    /// then every power-of-two boundary ±1 out to 4097 — the counts where an
    /// incremental frontier's carry logic can break.
    #[test]
    fn i386_s1_incremental_root_byte_identical_to_ground_truth_at_every_count() {
        for seed in [0x51u64, 0xa5e2_1d0f_3b77_c4d9] {
            let mut t = CommitmentTree::new();
            assert_eq!(t.root(), t.root_at(0), "empty tree, seed {seed:#x}");
            for n in 1..=2048u64 {
                t.append(rand_cm(seed, n));
                assert_eq!(
                    t.root(),
                    t.root_at(n),
                    "root() != ground-truth root_at at count {n}, seed {seed:#x}"
                );
            }
            // Boundary counts past the every-count range: 2^k - 1, 2^k, 2^k + 1.
            let mut n = 2048u64;
            for boundary in [4096u64] {
                for target in [boundary - 1, boundary, boundary + 1] {
                    while n < target {
                        n += 1;
                        t.append(rand_cm(seed, n));
                    }
                    assert_eq!(
                        t.root(),
                        t.root_at(n),
                        "root() != ground-truth root_at at boundary count {n}, seed {seed:#x}"
                    );
                }
            }
        }
    }

    /// Issue #386 S3 — authentication paths verify against the CURRENT root
    /// (`root()`, the incremental one after the swap) at every count, not just
    /// against the ground-truth walk. The wallet/joiner serving path folds
    /// `leaf → root()`; both roots are asserted so a cache that drifted from the
    /// walk cannot hide behind S1's equality.
    #[test]
    fn i386_s3_auth_paths_fold_to_the_incremental_root_at_every_count() {
        let mut t = CommitmentTree::new();
        for n in 1..=70u64 {
            t.append(rand_cm(0x53, n));
            let live = t.root();
            assert_eq!(live, t.root_at(n), "S1 precondition at count {n}");
            for pos in 0..n {
                let w = t.auth_path(pos, n);
                assert_eq!(
                    w.fold_root(&t.leaf(pos)),
                    live,
                    "auth_path({pos}) must fold to the live root at count {n}"
                );
            }
        }
    }

    /// Issue #386 S4 — rewind (#162) survives. `Node::rewind_to` rebuilds state
    /// from genesis through `apply_state` with a FRESH tree, so the property the
    /// node relies on is: a fresh tree re-appending the retained prefix, then
    /// appending the post-reorg suffix, reaches a root byte-identical to a tree
    /// that never saw the rewound leaves — and to the original tree's
    /// `root_at(prefix)` at the rewind point.
    #[test]
    fn i386_s4_rewind_rebuild_then_reappend_matches_never_rewound() {
        let m = 100u64;
        let mut big = CommitmentTree::new();
        for n in 1..=m {
            big.append(rand_cm(0x54, n));
        }
        for k in [0u64, 1, 31, 32, 33, 63, 64, 65, 99, 100] {
            // The rewind: a fresh tree replaying the retained prefix (what
            // rewind_to's from_genesis re-fold does).
            let mut rewound = CommitmentTree::new();
            for n in 1..=k {
                rewound.append(rand_cm(0x54, n));
            }
            assert_eq!(rewound.root(), big.root_at(k), "rewound root at prefix {k}");
            assert_eq!(rewound.len(), k);
            // Re-append a DIFFERENT suffix (the winning branch), and check
            // against a tree that never held the rewound leaves at all.
            let mut never = CommitmentTree::new();
            for n in 1..=k {
                never.append(rand_cm(0x54, n));
            }
            for n in 1..=8u64 {
                let cm = rand_cm(0xdead_beef ^ k, n);
                rewound.append(cm);
                never.append(cm);
                assert_eq!(
                    rewound.root(),
                    never.root(),
                    "rewound-then-reappended root diverged at prefix {k}, suffix {n}"
                );
                assert_eq!(rewound.root(), rewound.root_at(rewound.len()), "S1 on the reappended tree");
            }
        }
    }

    /// Golden roots, pinned as literals against the pre-#386 `subtree_root`
    /// implementation. The S1 property test proves the two implementations agree
    /// with each other; this pins them both to the values the live chain's
    /// `roots_by_height` was built from, so a change that moved both together
    /// could not pass silently.
    #[test]
    fn i386_golden_roots_are_pinned() {
        let golden: [(u64, &str); 6] = [
            (0, "27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757"),
            (1, "09e36c4e49e9ea817cec01b11f15581e40d412f6b37afda1be4df5cc8d50ee6d"),
            (2, "0bfa97c71f9435568d3c123346d4f32964b3b906d6fd9447e7f30b99fc2fcfeb"),
            (17, "01da78327eafdde23f430d7bd60ebeac6c6476435eb7e2812bc92d4a2fb5d89c"),
            (256, "18c120383d6e357beba09be6a5f938387e00de462f6e81fcc9b254b64f4bc20c"),
            (1000, "ca9fbec3265b264b946803e32a42790fbdda129712a88cfd04c6eb699f967e20"),
        ];
        let mut t = CommitmentTree::new();
        let mut n = 0u64;
        for (count, want) in golden {
            while n < count {
                n += 1;
                t.append(cm(n));
            }
            let got = hex(&digest_bytes(&t.root()));
            assert_eq!(got, want, "pinned root moved at count {count}");
        }
    }

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Issue #386 S6 — the measured win. Not a suite test (timing on a shared
    /// rig flakes); run explicitly:
    ///
    /// ```sh
    /// cargo test -p qlab-cbserver --release i386_s6 -- --ignored --nocapture
    /// ```
    ///
    /// Old per-block cost = one ground-truth `root_at(N)` walk (what `root()`
    /// was before #386, linear in N). New per-block cost = one `append` + one
    /// memoised `root()` (flat in N). The one assertion is deliberately loose
    /// (10× at N = 50k, where the true gap is orders of magnitude) so shared-rig
    /// noise cannot flip it.
    #[test]
    #[ignore = "S6 measurement; run explicitly with --ignored --nocapture"]
    fn i386_s6_per_block_cost_flat_vs_linear() {
        use std::time::Instant;
        let sizes = [1_000u64, 10_000, 50_000];
        println!("| N leaves | old per-block cost: root_at(N) walk, median of 3 | new per-block cost: append+root(), median of 5 |");
        println!("|---|---|---|");
        let mut t = CommitmentTree::new();
        let mut n = 0u64;
        let mut last: Option<(std::time::Duration, std::time::Duration)> = None;
        for &target in &sizes {
            while n + 1 < target {
                n += 1;
                t.append(rand_cm(0x56, n));
            }
            // New path: the last append + root, on clones so each sample times
            // the same (N-1 → N) transition.
            let mut news = Vec::new();
            for _ in 0..5 {
                let mut c = t.clone();
                let start = Instant::now();
                c.append(rand_cm(0x56, target));
                let r = c.root();
                news.push(start.elapsed());
                std::hint::black_box(r);
            }
            news.sort();
            n += 1;
            t.append(rand_cm(0x56, n));
            // Old path: the full walk root() used to delegate to.
            let mut olds = Vec::new();
            for _ in 0..3 {
                let start = Instant::now();
                let r = t.root_at(n);
                olds.push(start.elapsed());
                std::hint::black_box(r);
            }
            olds.sort();
            println!("| {n} | {:?} | {:?} |", olds[1], news[2]);
            last = Some((olds[1], news[2]));
        }
        let (old_50k, new_50k) = last.unwrap();
        assert!(
            new_50k < old_50k / 10,
            "at N=50k the incremental per-block cost ({new_50k:?}) must be far below the walk ({old_50k:?})"
        );
    }
}
