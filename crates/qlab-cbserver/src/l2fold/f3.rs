//! Lab #767 — the native reference of the state-transition leaf: the three
//! L2 trees with the witnesses each step needs, the surface digest, and the
//! leaf check ([`check_leaf`]) that the AIR mirrors and the negatives target.
//!
//! - **`N`, the nullifier indexed tree** (depth 32, ruling Q2): leaves are
//!   `(lo, hi)` pairs of adjacent keys — the freeze tree's format
//!   ([`qlab_air::l2p::key_lt`] order, lane 3 most significant) under its own
//!   leaf domain ([`nf_leaf_hash`]). Genesis is the single leaf `(0, 2^256−1)`
//!   at index 0. Inserting `K` opens the low leaf `(lo, hi)` with
//!   `lo < K < hi` **strictly**, rewrites it to `(lo, K)` and appends
//!   `(K, hi)` at the next index. A key already present, or either sentinel,
//!   has no strictly bracketing leaf — refused by construction.
//!   **The sentinels (ruling (c)):** a nullifier is a Keccak-f output, so
//!   `K = 0` and `K = 2^256 − 1` each occur with probability 2^-256 — and
//!   neither is insertable regardless: no leaf has `lo < 0` (the genesis and
//!   every later low end are ≥ 0) and none has `MAX < hi`, so the strict
//!   comparisons never bracket them (the `2^256 − 1` end is the freeze tree's
//!   `KEY_MAX` note in `qlab_air::l2p`; the `0` end is this). Test:
//!   `f3_sentinels_and_duplicates_have_no_gap`.
//! - **`C`, the note-commitment tree**: the node's append-only depth-32 tree
//!   ([`crate::tree::CommitmentTree`]); an append opens the empty
//!   slot at the next index and writes the commitment through the same path.
//! - **`R`, the asset registry**: the node's depth-16 tree
//!   ([`crate::registry::RegistryTree`]); a shape-R write replaces the
//!   leaf at its slot (asset 0 never writable, as the node rules).
//! - **`SD`, the surface digest** (ruling (a)): per transaction
//!   `SD_i = H(SD_{i−1}; tag ‖ pv_len ‖ pvs)` under the domain
//!   `"qumbra:l2-sd:v1"`, over the transaction's **full** public-value vector
//!   exactly as C1 exports it — a Merkle–Damgård chain of single-permutation
//!   compressions ([`sd_chain`], F3-2b), which the batch side (F4) must
//!   compute with exactly this construction.
//! - **The index cap (F3-2b, a protocol limit):** both append trees stop at
//!   [`INDEX_CAP`] = 2^30 leaves — the leaf AIR accumulates an index as one
//!   KoalaBear element (p ≈ 2^31), so it forces path bits 30 and 31 to zero.
//!   A liveness limit, not a soundness one: the nullifier tree fills first,
//!   at ≈ 357 M L2 transactions (3 inserts each); F4/F5 must surface it.
//!
//! Every tree hash is the consensus Keccak node hash, so the roots are the
//! node's roots bit for bit.
// The leaf AIR (the next slice) is this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use std::collections::HashMap;

use qlab_air::l2::{RegistryLeaf, RegistryWitness};
use qlab_air::l2p::{key_lt, KEY_MAX};
// Lab #860 R1: `pv_chunks` is the fixtures' and tests' (they stayed in qlab-wprover).
#[allow(unused_imports)]
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
#[allow(unused_imports)]
use qlab_air::reference::keccak_f;
use crate::registry::RegistryTree;
use crate::tree::{zeros, CommitmentTree};
use qlab_devnet::annulet::L2ShapeTag;

// Lab #785 F5-1: the hash-level items moved to qlab-wrapper.
pub use qlab_wrapper::hash::{
    nf_leaf_hash, node_pub, sd_chain_byte, sd_domain_lanes, sd_perms, sd_words_byte, Digest, Roots, EMPTY, INDEX_CAP, N_DEPTH, SD_BLOCK_WORDS, SD_LANE_DOMAIN, SD_LANE_FINAL, SD_LANE_INDEX, SD_LANE_MSG,
};
use qlab_wrapper::hash::node;

fn bits_of(index: u64, depth: usize) -> Vec<bool> {
    (0..depth).map(|i| (index >> i) & 1 == 1).collect()
}

// ---------------------------------------------------------------------------
// N — the nullifier indexed tree
// ---------------------------------------------------------------------------

/// Why an insert, or its check, is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NfError {
    /// No leaf strictly brackets the key: it is present, or a sentinel.
    NotInGap,
    /// The low leaf does not strictly bracket the key it was opened for.
    LowLeafRange,
    /// A path does not fold to the running root (a forged leaf or a stale root).
    RootMismatch,
    /// A path's bits are not its declared index.
    PathIndex,
    /// The append is not at the running next index.
    AppendIndex,
    /// The tree is at [`INDEX_CAP`].
    Full,
}

/// One insert's witness: the low leaf and its path under the running root,
/// then the append slot's path under the root after the low-leaf rewrite.
#[derive(Clone, Copy)]
pub struct InsertWitness {
    pub key: Digest,
    pub low_index: u64,
    pub low: (Digest, Digest),
    pub low_path: MerkleWitness,
    pub new_index: u64,
    pub new_path: MerkleWitness,
}

/// The nullifier indexed tree, every non-empty node kept per level.
#[derive(Clone)]
pub struct IndexedTree {
    levels: Vec<HashMap<u64, Digest>>,
    leaves: Vec<(Digest, Digest)>,
    zeros: [[u64; 4]; MERKLE_DEPTH + 1],
}

impl IndexedTree {
    /// Genesis: the single leaf `(0, 2^256 − 1)` at index 0.
    pub fn genesis() -> Self {
        let mut t = Self { levels: vec![HashMap::new(); N_DEPTH + 1], leaves: Vec::new(), zeros: zeros() };
        t.put(0, (EMPTY, KEY_MAX));
        t
    }

    pub fn root(&self) -> Digest {
        self.get(N_DEPTH, 0)
    }

    /// The leaves, by index.
    pub fn leaves(&self) -> &[(Digest, Digest)] {
        &self.leaves
    }

    /// The next free leaf index.
    pub fn next_index(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn get(&self, lvl: usize, i: u64) -> Digest {
        *self.levels[lvl].get(&i).unwrap_or(&self.zeros[lvl])
    }

    pub fn put(&mut self, idx: u64, leaf: (Digest, Digest)) {
        if idx as usize == self.leaves.len() {
            self.leaves.push(leaf);
        } else {
            self.leaves[idx as usize] = leaf;
        }
        let mut d = nf_leaf_hash(&leaf.0, &leaf.1);
        let mut i = idx;
        self.levels[0].insert(i, d);
        for lvl in 0..N_DEPTH {
            let sib = self.get(lvl, i ^ 1);
            d = if i & 1 == 1 { node(&sib, &d) } else { node(&d, &sib) };
            i >>= 1;
            self.levels[lvl + 1].insert(i, d);
        }
    }

    pub fn path(&self, idx: u64) -> MerkleWitness {
        let mut siblings = [[0u64; 4]; MERKLE_DEPTH];
        let mut path_bits = [false; MERKLE_DEPTH];
        for lvl in 0..N_DEPTH {
            let i = idx >> lvl;
            siblings[lvl] = self.get(lvl, i ^ 1);
            path_bits[lvl] = i & 1 == 1;
        }
        MerkleWitness { siblings, path_bits }
    }

    /// The leaf strictly bracketing `key`, if any (a linear scan: reference code).
    pub fn low_leaf_of(&self, key: &Digest) -> Option<u64> {
        self.leaves.iter().position(|(lo, hi)| key_lt(lo, key) && key_lt(key, hi)).map(|i| i as u64)
    }

    /// Insert `key`, returning the witness [`apply_insert`] checks.
    pub fn insert(&mut self, key: &Digest) -> Result<InsertWitness, NfError> {
        let j = self.low_leaf_of(key).ok_or(NfError::NotInGap)?;
        if self.next_index() >= INDEX_CAP {
            return Err(NfError::Full);
        }
        let low = self.leaves[j as usize];
        let low_path = self.path(j);
        self.put(j, (low.0, *key));
        let new_index = self.next_index();
        let new_path = self.path(new_index);
        self.put(new_index, (*key, low.1));
        Ok(InsertWitness { key: *key, low_index: j, low, low_path, new_index, new_path })
    }
}

/// The insert as the leaf proves it: from `(root, next)` to the new pair.
pub fn apply_insert(root: &Digest, next: u64, w: &InsertWitness) -> Result<(Digest, u64), NfError> {
    if next >= INDEX_CAP {
        return Err(NfError::Full);
    }
    if w.low_path.path_bits.to_vec() != bits_of(w.low_index, N_DEPTH) || w.new_path.path_bits.to_vec() != bits_of(w.new_index, N_DEPTH) {
        return Err(NfError::PathIndex);
    }
    if w.new_index != next {
        return Err(NfError::AppendIndex);
    }
    let (lo, hi) = w.low;
    if !(key_lt(&lo, &w.key) && key_lt(&w.key, &hi)) {
        return Err(NfError::LowLeafRange);
    }
    if w.low_path.fold_root(&nf_leaf_hash(&lo, &hi)) != *root {
        return Err(NfError::RootMismatch);
    }
    let mid = w.low_path.fold_root(&nf_leaf_hash(&lo, &w.key));
    if w.new_path.fold_root(&EMPTY) != mid {
        return Err(NfError::RootMismatch);
    }
    Ok((w.new_path.fold_root(&nf_leaf_hash(&w.key, &hi)), next + 1))
}

// ---------------------------------------------------------------------------
// C — the note-commitment append tree
// ---------------------------------------------------------------------------

/// One append's witness: the slot's path (the same siblings before and after).
#[derive(Clone, Copy)]
pub struct AppendWitness {
    pub index: u64,
    pub path: MerkleWitness,
}

/// Why an append is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// Not at the running next index (an order swap, a skip, a reuse).
    Index,
    /// The path's bits are not the index.
    PathIndex,
    /// The slot is not empty under the running root, or the root is stale.
    RootMismatch,
    /// The tree is at [`INDEX_CAP`].
    Full,
}

/// Append `cm` to `tree`, returning its witness.
pub fn append(tree: &mut CommitmentTree, cm: &Digest) -> AppendWitness {
    let index = tree.append(*cm);
    AppendWitness { index, path: tree.auth_path(index, index + 1) }
}

/// The append as the leaf proves it.
pub fn apply_append(root: &Digest, next: u64, cm: &Digest, w: &AppendWitness) -> Result<(Digest, u64), AppendError> {
    if next >= INDEX_CAP {
        return Err(AppendError::Full);
    }
    if w.index != next {
        return Err(AppendError::Index);
    }
    if w.path.path_bits.to_vec() != bits_of(w.index, MERKLE_DEPTH) {
        return Err(AppendError::PathIndex);
    }
    if w.path.fold_root(&EMPTY) != *root {
        return Err(AppendError::RootMismatch);
    }
    Ok((w.path.fold_root(cm), next + 1))
}

// ---------------------------------------------------------------------------
// R — registry replacements
// ---------------------------------------------------------------------------

/// A shape-R write's witness: the replacing leaf, the digest it replaces, and
/// the slot's path (unchanged by the replacement).
#[derive(Clone, Copy)]
pub struct RegistryWrite {
    pub leaf: RegistryLeaf,
    pub old_digest: Digest,
    pub path: RegistryWitness,
}

// The paths carry no `Debug`; the witnesses print their indices.
impl std::fmt::Debug for InsertWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InsertWitness {{ low_index: {}, new_index: {} }}", self.low_index, self.new_index)
    }
}
impl std::fmt::Debug for AppendWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppendWitness {{ index: {} }}", self.index)
    }
}
impl std::fmt::Debug for RegistryWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegistryWrite {{ asset: {} }}", self.leaf.asset)
    }
}

// ---------------------------------------------------------------------------
// SD — the surface digest
// ---------------------------------------------------------------------------

/// One step's message: `tag ‖ pv_len ‖ pvs`, each a `u32` word.
pub fn sd_words(tag: L2ShapeTag, pvs: &[u32]) -> Vec<u32> {
    sd_words_byte(tag.byte(), pvs)
}

/// **One chain step, block by block** (F3-2b; the #767 ruling's approval of
/// the construction): a Merkle–Damgård chain of single-permutation
/// compressions, the node hash's construction widened.
///
/// Block `b`'s Keccak-f input is: rate lanes 0..4 the chaining value
/// (`prev` for `b = 0`, else block `b − 1`'s first four output lanes); rate
/// lanes 4..17 the message's words `26b … 26b + 25`, zero past the end;
/// capacity lanes 17–18 the domain, 19 the block index, 20 the final flag
/// (1 on the last block), 21..25 zero. The step's digest is the last block's
/// first four output lanes.
///
/// **Why it is collision resistant.** The capacity (lanes 17..25, 512 bits)
/// is fixed by `(b, final)` and never message-controlled, so each block is a
/// truncated single-block sponge call: finding two inputs with the same
/// 256-bit output costs ~2^128 (the birthday bound on the output; the
/// capacity's 2^256 inversion bound is higher). Merkle–Damgård then carries
/// the compression's collision resistance to the chain, strengthened by the
/// tag, `pv_len`, the block index and the final flag: two streams that agree
/// in their message words but not in length or shape differ in a capacity
/// lane or in word 0/1. A nonzero capacity also separates every block from
/// the node, nullifier-leaf and registry-leaf hashes, whose capacity is zero.
///
/// Returns the blocks' Keccak-f inputs (what the leaf AIR hashes) and the digest.
pub fn sd_chain(prev: &Digest, tag: L2ShapeTag, pvs: &[u32]) -> (Vec<[u64; 25]>, Digest) {
    sd_chain_byte(prev, tag.byte(), pvs)
}

/// One chain step's digest.
pub fn sd_step(prev: &Digest, tag: L2ShapeTag, pvs: &[u32]) -> Digest {
    sd_chain(prev, tag, pvs).1
}

// ---------------------------------------------------------------------------
// Transactions and the leaf
// ---------------------------------------------------------------------------

/// One transaction's surface as the state leaf reads it: its shape and its
/// full public-value vector (C1's export), plus a shape-R write's leaf (not a
/// PV — bound through `new_root`).
#[derive(Clone, Debug)]
pub struct TxSurface {
    pub tag: L2ShapeTag,
    pub pvs: Vec<u32>,
    pub write: Option<RegistryLeaf>,
}

/// Why a transaction or a leaf is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StError {
    Nf(NfError),
    Append(AppendError),
    /// A PV vector of the wrong length for its shape, or a chunk ≥ 2^16.
    Surface,
    /// An S/P transaction's `registry_root` is not the running `R`.
    RegistryRead,
    /// A shape-R write: a leaf not at the PV's slot, asset 0, or a new root
    /// the leaf does not fold to.
    RegistryWrite,
    /// A shape-R write proven against a root that is not the running `R`
    /// (the PV's `old_root`, or the opened path — a stale or forged opening).
    RegistryRoot,
    /// A second shape-R write in one leaf (v1 allows one, ruling Q6).
    SecondWrite,
    /// The witnesses do not match the transactions (counts, shapes).
    Shape,
}

impl TxSurface {
    pub fn pv_len(tag: L2ShapeTag) -> usize {
        match tag {
            L2ShapeTag::S => qlab_air::l2::PV_LEN,
            L2ShapeTag::P => qlab_air::l2p::PV_LEN,
            L2ShapeTag::R => qlab_air::l2r::PV_LEN,
        }
    }

    pub fn digest_at(&self, off: usize) -> Result<Digest, StError> {
        let c = self.pvs.get(off..off + 16).ok_or(StError::Surface)?;
        if c.iter().any(|x| *x >= 1 << 16) {
            return Err(StError::Surface);
        }
        Ok(core::array::from_fn(|l| (0..4).map(|j| (c[4 * l + j] as u64) << (16 * j)).sum()))
    }

    fn check(&self) -> Result<(), StError> {
        if self.pvs.len() != Self::pv_len(self.tag) || self.write.is_some() != (self.tag == L2ShapeTag::R) {
            return Err(StError::Surface);
        }
        Ok(())
    }

    /// The nullifiers, in PV order — every one, dummies included (ruling Q5).
    pub fn nullifiers(&self) -> Result<Vec<Digest>, StError> {
        use qlab_air::l2::{PV_NF1, PV_NF2};
        match self.tag {
            L2ShapeTag::S => Ok(vec![self.digest_at(PV_NF1)?, self.digest_at(PV_NF2)?, self.digest_at(qlab_air::l2::PV_NF3)?]),
            L2ShapeTag::P => Ok(vec![self.digest_at(PV_NF1)?, self.digest_at(PV_NF2)?, self.digest_at(qlab_air::l2p::PV_NF3)?]),
            L2ShapeTag::R => Ok(vec![self.digest_at(qlab_air::l2r::PV_NF)?]),
        }
    }

    /// The output commitments, in PV order.
    pub fn commitments(&self) -> Result<Vec<Digest>, StError> {
        use qlab_air::l2::{PV_CM1, PV_CM2};
        match self.tag {
            L2ShapeTag::S | L2ShapeTag::P => Ok(vec![self.digest_at(PV_CM1)?, self.digest_at(PV_CM2)?]),
            L2ShapeTag::R => Ok(vec![self.digest_at(qlab_air::l2r::PV_CM)?, self.digest_at(qlab_air::l2r::PV_CM_SEED)?]),
        }
    }
}

/// One transaction's witnesses, in the order [`check_leaf`] consumes them.
#[derive(Clone, Debug)]
pub struct TxWitness {
    pub inserts: Vec<InsertWitness>,
    pub appends: Vec<AppendWitness>,
    pub write: Option<RegistryWrite>,
}

/// The L2's state: the three trees and the chain head.
#[derive(Clone)]
pub struct L2State {
    pub n: IndexedTree,
    pub c: CommitmentTree,
    pub r: RegistryTree,
    pub sd: Digest,
}

impl L2State {
    /// Empty `N` and `C`, the registry over `registry`, `SD` at zero.
    pub fn genesis(registry: &[RegistryLeaf]) -> Self {
        Self {
            n: IndexedTree::genesis(),
            c: CommitmentTree::new(),
            r: RegistryTree::from_leaves(registry).expect("a valid genesis registry"),
            sd: EMPTY,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots { n: self.n.root(), n_next: self.n.next_index(), c: self.c.root(), c_next: self.c.len(), r: self.r.root(), sd: self.sd }
    }

    /// Apply one transaction, returning its witnesses. On error the state is
    /// left as it was.
    pub fn apply_tx(&mut self, tx: &TxSurface) -> Result<TxWitness, StError> {
        tx.check()?;
        let mut next = self.clone();
        let mut inserts = Vec::new();
        for nf in tx.nullifiers()? {
            inserts.push(next.n.insert(&nf).map_err(StError::Nf)?);
        }
        let appends = tx.commitments()?.iter().map(|cm| append(&mut next.c, cm)).collect();
        let write = match tx.tag {
            L2ShapeTag::S | L2ShapeTag::P => {
                if tx.digest_at(qlab_air::l2::PV_REGROOT)? != next.r.root() {
                    return Err(StError::RegistryRead);
                }
                None
            }
            L2ShapeTag::R => {
                let leaf = tx.write.expect("checked");
                let slot = u16::try_from(leaf.asset).map_err(|_| StError::RegistryWrite)?;
                let old_digest = next.r.leaf(slot).map(|l| l.hash()).unwrap_or(EMPTY);
                let path = next.r.opening_at(slot);
                next.r.apply_update(leaf).map_err(|_| StError::RegistryWrite)?;
                Some(RegistryWrite { leaf, old_digest, path })
            }
        };
        next.sd = sd_step(&next.sd, tx.tag, &tx.pvs);
        let w = TxWitness { inserts, appends, write };
        // The witness must pass the leaf's own check against the state it
        // was built on — the reference and the check never drift.
        let expect = check_leaf(&self.roots(), std::slice::from_ref(tx), std::slice::from_ref(&w))?;
        assert_eq!(expect, next.roots(), "the reference and its check agree");
        *self = next;
        Ok(w)
    }

    /// Apply a batch as one leaf: `(roots in, witnesses, roots out)`.
    pub fn apply_leaf(&mut self, txs: &[TxSurface]) -> Result<(Roots, Vec<TxWitness>, Roots), StError> {
        if txs.iter().filter(|t| t.tag == L2ShapeTag::R).count() > 1 {
            return Err(StError::SecondWrite);
        }
        let before = self.clone();
        let rin = self.roots();
        let mut wits = Vec::new();
        for tx in txs {
            match self.apply_tx(tx) {
                Ok(w) => wits.push(w),
                Err(e) => {
                    *self = before;
                    return Err(e);
                }
            }
        }
        Ok((rin, wits, self.roots()))
    }
}

/// **The leaf's statement, natively:** from `rin`, thread every
/// transaction's inserts, appends and registry step through the running
/// roots and chain `SD`; return the roots out. The AIR proves exactly this.
pub fn check_leaf(rin: &Roots, txs: &[TxSurface], wits: &[TxWitness]) -> Result<Roots, StError> {
    if txs.len() != wits.len() {
        return Err(StError::Shape);
    }
    if txs.iter().filter(|t| t.tag == L2ShapeTag::R).count() > 1 {
        return Err(StError::SecondWrite);
    }
    let mut s = *rin;
    for (tx, w) in txs.iter().zip(wits) {
        tx.check()?;
        let nfs = tx.nullifiers()?;
        let cms = tx.commitments()?;
        if w.inserts.len() != nfs.len() || w.appends.len() != cms.len() {
            return Err(StError::Shape);
        }
        for (nf, ins) in nfs.iter().zip(&w.inserts) {
            if ins.key != *nf {
                return Err(StError::Shape);
            }
            (s.n, s.n_next) = apply_insert(&s.n, s.n_next, ins).map_err(StError::Nf)?;
        }
        for (cm, app) in cms.iter().zip(&w.appends) {
            (s.c, s.c_next) = apply_append(&s.c, s.c_next, cm, app).map_err(StError::Append)?;
        }
        match (tx.tag, &w.write) {
            (L2ShapeTag::S | L2ShapeTag::P, None) => {
                if tx.digest_at(qlab_air::l2::PV_REGROOT)? != s.r {
                    return Err(StError::RegistryRead);
                }
            }
            (L2ShapeTag::R, Some(rw)) => {
                use qlab_air::l2r::{PV_ASSET, PV_NEW_ROOT, PV_OLD_ROOT};
                let asset = tx.pvs[PV_ASSET] as u64;
                let bits = bits_of(asset, qlab_air::l2::REGISTRY_DEPTH);
                if asset == 0 || rw.leaf.asset != asset || rw.path.path_bits.to_vec() != bits {
                    return Err(StError::RegistryWrite);
                }
                if tx.digest_at(PV_OLD_ROOT)? != s.r || rw.path.fold_root(&rw.old_digest) != s.r {
                    return Err(StError::RegistryRoot);
                }
                if rw.path.fold_root(&rw.leaf.hash()) != tx.digest_at(PV_NEW_ROOT)? {
                    return Err(StError::RegistryWrite);
                }
                s.r = tx.digest_at(PV_NEW_ROOT)?;
            }
            _ => return Err(StError::Shape),
        }
        s.sd = sd_step(&s.sd, tx.tag, &tx.pvs);
    }
    Ok(s)
}
