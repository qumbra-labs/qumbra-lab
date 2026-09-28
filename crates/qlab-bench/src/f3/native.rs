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
//! - **`C`, the note-commitment tree**: the node's append-only depth-32 tree
//!   ([`qlab_cbserver::tree::CommitmentTree`]); an append opens the empty
//!   slot at the next index and writes the commitment through the same path.
//! - **`R`, the asset registry**: the node's depth-16 tree
//!   ([`qlab_cbserver::registry::RegistryTree`]); a shape-R write replaces the
//!   leaf at its slot (asset 0 never writable, as the node rules).
//! - **`SD`, the surface digest** (ruling (a)): per transaction
//!   `SD_i = H("qumbra:l2-sd:v1" ‖ SD_{i−1} ‖ tag ‖ pv_len ‖ pvs)`, over the
//!   transaction's **full** public-value vector exactly as C1 exports it.
//!
//! Every tree hash is the consensus Keccak node hash, so the roots are the
//! node's roots bit for bit.
// The leaf AIR (the next slice) is this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use std::collections::HashMap;

use qlab_air::l2::{RegistryLeaf, RegistryWitness};
use qlab_air::l2p::{key_lt, KEY_MAX};
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
use qlab_air::reference::{keccak_f, merkle_node_state};
use qlab_cbserver::registry::RegistryTree;
use qlab_cbserver::tree::{zeros, CommitmentTree};
use qlab_devnet::annulet::L2ShapeTag;

pub(crate) type Digest = [u64; 4];

/// The nullifier tree's depth (ruling Q2): the commitment tree's.
pub(crate) const N_DEPTH: usize = MERKLE_DEPTH;
/// An unused slot (both append trees): the zero digest, the node's convention.
pub(crate) const EMPTY: Digest = [0; 4];

/// The nullifier-tree leaf `H(lo ‖ hi)`: one Keccak-f block, domain marker at
/// lane 8 bit 4 — distinct from the node hash's pad (bit 0) and the freeze
/// leaf's marker (bit 3), so no nullifier leaf is ever a node or a freeze leaf.
pub(crate) fn nf_leaf_hash(lo: &Digest, hi: &Digest) -> Digest {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(lo);
    st[4..8].copy_from_slice(hi);
    st[8] = 1 << 4;
    st[16] = 1 << 63;
    keccak_f(&st)[..4].try_into().expect("four lanes")
}

fn node(l: &Digest, r: &Digest) -> Digest {
    merkle_node_state(l, r)[..4].try_into().expect("four lanes")
}

fn bits_of(index: u64, depth: usize) -> Vec<bool> {
    (0..depth).map(|i| (index >> i) & 1 == 1).collect()
}

// ---------------------------------------------------------------------------
// N — the nullifier indexed tree
// ---------------------------------------------------------------------------

/// Why an insert, or its check, is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NfError {
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
    /// The tree is full.
    Full,
}

/// One insert's witness: the low leaf and its path under the running root,
/// then the append slot's path under the root after the low-leaf rewrite.
#[derive(Clone, Copy)]
pub(crate) struct InsertWitness {
    pub key: Digest,
    pub low_index: u64,
    pub low: (Digest, Digest),
    pub low_path: MerkleWitness,
    pub new_index: u64,
    pub new_path: MerkleWitness,
}

/// The nullifier indexed tree, every non-empty node kept per level.
#[derive(Clone)]
pub(crate) struct IndexedTree {
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

    /// The next free leaf index.
    pub fn next_index(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn get(&self, lvl: usize, i: u64) -> Digest {
        *self.levels[lvl].get(&i).unwrap_or(&self.zeros[lvl])
    }

    fn put(&mut self, idx: u64, leaf: (Digest, Digest)) {
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

    fn path(&self, idx: u64) -> MerkleWitness {
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
        if self.next_index() >= 1u64 << N_DEPTH {
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
pub(crate) fn apply_insert(root: &Digest, next: u64, w: &InsertWitness) -> Result<(Digest, u64), NfError> {
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
pub(crate) struct AppendWitness {
    pub index: u64,
    pub path: MerkleWitness,
}

/// Why an append is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppendError {
    /// Not at the running next index (an order swap, a skip, a reuse).
    Index,
    /// The path's bits are not the index.
    PathIndex,
    /// The slot is not empty under the running root, or the root is stale.
    RootMismatch,
}

/// Append `cm` to `tree`, returning its witness.
pub(crate) fn append(tree: &mut CommitmentTree, cm: &Digest) -> AppendWitness {
    let index = tree.append(*cm);
    AppendWitness { index, path: tree.auth_path(index, index + 1) }
}

/// The append as the leaf proves it.
pub(crate) fn apply_append(root: &Digest, next: u64, cm: &Digest, w: &AppendWitness) -> Result<(Digest, u64), AppendError> {
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
pub(crate) struct RegistryWrite {
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

/// The chain's domain (ruling (a)), as the leading 16 bytes of every step.
pub(crate) const SD_DOMAIN: &[u8; 16] = b"qumbra:l2-sd:v1\0";
/// Keccak's rate in bytes.
const RATE: usize = 136;

/// One step's word stream: domain ‖ `prev` (8 words, lane low half first) ‖
/// tag ‖ `pv_len` ‖ the PVs, each a little-endian `u32`.
pub(crate) fn sd_words(prev: &Digest, tag: L2ShapeTag, pvs: &[u32]) -> Vec<u32> {
    let mut w: Vec<u32> = SD_DOMAIN.chunks(4).map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes"))).collect();
    for lane in prev {
        w.push(*lane as u32);
        w.push((*lane >> 32) as u32);
    }
    w.push(tag.byte() as u32);
    w.push(pvs.len() as u32);
    w.extend_from_slice(pvs);
    w
}

/// Keccak (rate 136, pad10*1 with domain byte 0x01) over a word stream,
/// the first four output lanes.
pub(crate) fn sponge(words: &[u32]) -> Digest {
    let mut bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.push(0x01);
    while !bytes.len().is_multiple_of(RATE) {
        bytes.push(0);
    }
    *bytes.last_mut().expect("nonempty") |= 0x80;
    let mut st = [0u64; 25];
    for block in bytes.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            st[i] ^= u64::from_le_bytes(lane.try_into().expect("8 bytes"));
        }
        st = keccak_f(&st);
    }
    st[..4].try_into().expect("four lanes")
}

/// One chain step.
pub(crate) fn sd_step(prev: &Digest, tag: L2ShapeTag, pvs: &[u32]) -> Digest {
    sponge(&sd_words(prev, tag, pvs))
}

/// Permutations one step costs: its padded blocks.
pub(crate) const fn sd_perms(pv_len: usize) -> usize {
    (4 * (4 + 8 + 1 + 1 + pv_len) + 1).div_ceil(RATE)
}

// ---------------------------------------------------------------------------
// Transactions and the leaf
// ---------------------------------------------------------------------------

/// One transaction's surface as the state leaf reads it: its shape and its
/// full public-value vector (C1's export), plus a shape-R write's leaf (not a
/// PV — bound through `new_root`).
#[derive(Clone, Debug)]
pub(crate) struct TxSurface {
    pub tag: L2ShapeTag,
    pub pvs: Vec<u32>,
    pub write: Option<RegistryLeaf>,
}

/// Why a transaction or a leaf is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StError {
    Nf(NfError),
    Append(AppendError),
    /// A PV vector of the wrong length for its shape, or a chunk ≥ 2^16.
    Surface,
    /// An S/P transaction's `registry_root` is not the running `R`.
    RegistryRead,
    /// A shape-R write: old root not the running `R`, a leaf not at the PV's
    /// slot, asset 0, or a new root the leaf does not fold to.
    RegistryWrite,
    /// A second shape-R write in one leaf (v1 allows one, ruling Q6).
    SecondWrite,
    /// The witnesses do not match the transactions (counts, shapes).
    Shape,
}

impl TxSurface {
    fn pv_len(tag: L2ShapeTag) -> usize {
        match tag {
            L2ShapeTag::S => qlab_air::l2::PV_LEN,
            L2ShapeTag::P => qlab_air::l2p::PV_LEN,
            L2ShapeTag::R => qlab_air::l2r::PV_LEN,
        }
    }

    fn digest_at(&self, off: usize) -> Result<Digest, StError> {
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

/// The running state a leaf threads: every root, both next indices, `SD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Roots {
    pub n: Digest,
    pub n_next: u64,
    pub c: Digest,
    pub c_next: u64,
    pub r: Digest,
    pub sd: Digest,
}

/// One transaction's witnesses, in the order [`check_leaf`] consumes them.
#[derive(Clone, Debug)]
pub(crate) struct TxWitness {
    pub inserts: Vec<InsertWitness>,
    pub appends: Vec<AppendWitness>,
    pub write: Option<RegistryWrite>,
}

/// The L2's state: the three trees and the chain head.
#[derive(Clone)]
pub(crate) struct L2State {
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
pub(crate) fn check_leaf(rin: &Roots, txs: &[TxSurface], wits: &[TxWitness]) -> Result<Roots, StError> {
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
                if asset == 0
                    || rw.leaf.asset != asset
                    || rw.path.path_bits.to_vec() != bits
                    || tx.digest_at(PV_OLD_ROOT)? != s.r
                    || rw.path.fold_root(&rw.old_digest) != s.r
                    || rw.path.fold_root(&rw.leaf.hash()) != tx.digest_at(PV_NEW_ROOT)?
                {
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A deterministic stream for fixtures (xorshift64).
pub(crate) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn digest(&mut self) -> Digest {
        [self.next(), self.next(), self.next(), self.next()]
    }
}

/// A synthetic S/P surface against `registry_root`: fresh random nullifiers
/// and commitments, every other PV a random 16-bit chunk (P's `vPublic` sign
/// and asset lanes left 0 — range, not semantics, is what F3 reads).
pub(crate) fn synth_tx(rng: &mut Rng, tag: L2ShapeTag, registry_root: &Digest) -> TxSurface {
    assert!(tag != L2ShapeTag::R, "synth_tx builds S/P surfaces");
    let len = TxSurface::pv_len(tag);
    let mut pvs: Vec<u32> = (0..len).map(|_| (rng.next() & 0xffff) as u32).collect();
    let mut put = |off: usize, d: &Digest| pvs[off..off + 16].copy_from_slice(&pv_chunks(d));
    use qlab_air::l2::{PV_CM1, PV_CM2, PV_NF1, PV_NF2, PV_REGROOT};
    let nf3 = if tag == L2ShapeTag::S { qlab_air::l2::PV_NF3 } else { qlab_air::l2p::PV_NF3 };
    for off in [PV_NF1, PV_NF2, nf3, PV_CM1, PV_CM2] {
        put(off, &rng.digest());
    }
    put(PV_REGROOT, registry_root);
    if tag == L2ShapeTag::P {
        for base in [qlab_air::l2p::PV_VP1, qlab_air::l2p::PV_VP2] {
            pvs[base] = 0;
            pvs[base + 5] = 0;
        }
    }
    TxSurface { tag, pvs, write: None }
}

/// A synthetic shape-R surface writing `leaf` over `state`'s registry.
pub(crate) fn synth_write(rng: &mut Rng, state: &L2State, leaf: RegistryLeaf) -> TxSurface {
    use qlab_air::l2r::{PV_ASSET, PV_CM, PV_CM_SEED, PV_NEW_ROOT, PV_NF, PV_OLD_ROOT};
    let mut pvs: Vec<u32> = (0..qlab_air::l2r::PV_LEN).map(|_| (rng.next() & 0xffff) as u32).collect();
    let mut after = state.r.clone();
    after.apply_update(leaf).expect("a writable leaf");
    for (off, d) in [(PV_NF, rng.digest()), (PV_CM, rng.digest()), (PV_CM_SEED, rng.digest()), (PV_OLD_ROOT, state.r.root()), (PV_NEW_ROOT, after.root())] {
        pvs[off..off + 16].copy_from_slice(&pv_chunks(&d));
    }
    pvs[PV_ASSET] = leaf.asset as u32;
    TxSurface { tag: L2ShapeTag::R, pvs, write: Some(leaf) }
}

#[cfg(test)]
mod tests {
    //! The native reference's own checks and the stage-0 negatives (lab #767
    //! §5 plus ruling (d)) at the reference level; the AIR repeats them at
    //! its binding rows. Every tree here is small: these run on the lane.
    use super::*;

    fn fresh() -> (L2State, Rng) {
        (L2State::genesis(&[RegistryLeaf::cloaked(0)]), Rng(0x767_f3f3_0001))
    }

    #[test]
    fn f3_genesis_roots_are_the_nodes() {
        let (s, _) = fresh();
        assert_eq!(s.c.root(), CommitmentTree::new().root(), "C is the node's empty commitment tree");
        let genesis_leaf = nf_leaf_hash(&EMPTY, &KEY_MAX);
        let mut d = genesis_leaf;
        for lvl in 0..N_DEPTH {
            d = node(&d, &zeros()[lvl]);
        }
        assert_eq!(s.n.root(), d, "N is the single (0, MAX) leaf at index 0");
        assert_eq!(s.n.next_index(), 1);
    }

    #[test]
    fn f3_inserts_verify_and_thread() {
        let (mut s, mut rng) = fresh();
        for _ in 0..24 {
            let (root, next) = (s.n.root(), s.n.next_index());
            let k = rng.digest();
            let w = s.n.insert(&k).expect("a fresh key");
            assert_eq!(apply_insert(&root, next, &w), Ok((s.n.root(), s.n.next_index())));
        }
        // The leaves stay a sorted chain of gaps from 0 to MAX.
        let mut ls = s.n.leaves.clone();
        ls.sort_by(|a, b| {
            if a.0 == b.0 {
                std::cmp::Ordering::Equal
            } else if key_lt(&a.0, &b.0) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        assert_eq!(ls[0].0, EMPTY);
        assert_eq!(ls.last().unwrap().1, KEY_MAX);
        assert!(ls.windows(2).all(|w| w[0].1 == w[1].0), "adjacent gaps chain");
    }

    #[test]
    fn f3_sentinels_and_duplicates_have_no_gap() {
        // Ruling (c): 0 and 2^256 − 1 are refused by the strict comparisons
        // (no leaf has lo < 0 or MAX < hi) — not merely improbable.
        let (mut s, mut rng) = fresh();
        assert_eq!(s.n.insert(&EMPTY).unwrap_err(), NfError::NotInGap);
        assert_eq!(s.n.insert(&KEY_MAX).unwrap_err(), NfError::NotInGap);
        let k = rng.digest();
        s.n.insert(&k).unwrap();
        assert_eq!(s.n.insert(&k).unwrap_err(), NfError::NotInGap, "a present key");
    }

    #[test]
    fn f3_neg_insert_witness_forgeries() {
        let (mut s, mut rng) = fresh();
        for _ in 0..6 {
            s.n.insert(&rng.digest()).unwrap();
        }
        let (root, next) = (s.n.root(), s.n.next_index());
        let k = rng.digest();
        let mut probe = s.n.clone();
        let w = probe.insert(&k).unwrap();
        // (1) a double insert: the same key again, against the new root.
        let (root2, next2) = apply_insert(&root, next, &w).unwrap();
        let mut again = probe.clone();
        assert_eq!(again.insert(&k).unwrap_err(), NfError::NotInGap);
        let mut replay = w;
        replay.new_index = next2;
        assert!(apply_insert(&root2, next2, &replay).is_err(), "the old witness does not re-insert");
        // (3) a wrong low leaf: a genuine leaf that does not bracket the key.
        let other = (0..s.n.leaves.len() as u64).find(|i| *i != w.low_index).unwrap();
        let mut wrong = w;
        wrong.low_index = other;
        wrong.low = s.n.leaves[other as usize];
        wrong.low_path = s.n.path(other);
        assert_eq!(apply_insert(&root, next, &wrong), Err(NfError::LowLeafRange));
        // (3) a forged leaf bracketing the key, not in the tree.
        let mut forged = w;
        forged.low = (EMPTY, KEY_MAX);
        assert_eq!(apply_insert(&root, next, &forged), Err(NfError::RootMismatch));
        // (4) a stale root: the witness against the root before an earlier insert.
        let mut stale_tree = s.n.clone();
        let w_stale = stale_tree.insert(&rng.digest()).unwrap();
        assert!(apply_insert(&root2, next2, &w_stale).is_err(), "a witness from a superseded root");
        // An append not at the running index.
        let mut skip = w;
        skip.new_index = next + 1;
        skip.new_path = s.n.path(next + 1);
        assert_eq!(apply_insert(&root, next, &skip), Err(NfError::AppendIndex));
    }

    #[test]
    fn f3_neg_appends() {
        let mut c = CommitmentTree::new();
        let mut rng = Rng(7);
        let (a, b) = (rng.digest(), rng.digest());
        let r0 = c.root();
        let wa = append(&mut c, &a);
        let r1 = c.root();
        let wb = append(&mut c, &b);
        assert_eq!(apply_append(&r0, 0, &a, &wa), Ok((r1, 1)));
        assert_eq!(apply_append(&r1, 1, &b, &wb), Ok((c.root(), 2)));
        // (5) an order swap: b first at index 0.
        assert_eq!(apply_append(&r0, 0, &b, &wb), Err(AppendError::Index));
        // An append into a non-empty slot: a's witness again after a landed.
        assert_eq!(apply_append(&r1, 1, &b, &AppendWitness { index: 1, path: wa.path }), Err(AppendError::PathIndex));
        let mut reuse = wa;
        reuse.index = 1;
        assert!(apply_append(&r1, 1, &b, &reuse).is_err());
    }

    #[test]
    fn f3_leaf_threads_and_refuses() {
        let (mut s, mut rng) = fresh();
        let rr = s.r.root();
        let txs: Vec<TxSurface> = (0..4).map(|i| synth_tx(&mut rng, if i % 2 == 0 { L2ShapeTag::S } else { L2ShapeTag::P }, &rr)).collect();
        let (rin, wits, rout) = s.apply_leaf(&txs).unwrap();
        assert_eq!(check_leaf(&rin, &txs, &wits), Ok(rout));
        assert_eq!(rout.n_next, rin.n_next + 12, "every nullifier inserted, dummies included (3 per S/P)");
        assert_eq!(rout.c_next, rin.c_next + 8);
        // (2) a batch-internal duplicate nullifier: tx 2 reuses tx 1's nf1.
        let mut dup = txs.clone();
        let nf = dup[0].pvs[16..32].to_vec();
        dup[1].pvs[16..32].copy_from_slice(&nf);
        let mut s2 = L2State::genesis(&[RegistryLeaf::cloaked(0)]);
        assert_eq!(s2.apply_leaf(&dup).unwrap_err(), StError::Nf(NfError::NotInGap));
        // (9) an SD over a shape-tag swap: the same PVs under the other tag.
        let mut swapped = txs.clone();
        swapped[0].tag = L2ShapeTag::P;
        assert!(check_leaf(&rin, &swapped, &wits).is_err(), "an S vector is not a P vector");
        assert_ne!(sd_step(&EMPTY, L2ShapeTag::S, &txs[0].pvs), sd_step(&EMPTY, L2ShapeTag::P, &txs[0].pvs));
        // (10) a threading gap: tx 2's witnesses against a state that skipped tx 1.
        let mut s3 = L2State::genesis(&[RegistryLeaf::cloaked(0)]);
        let (_, w13, _) = s3.apply_leaf(&[txs[0].clone(), txs[2].clone()]).unwrap();
        let gap = [wits[0].clone(), w13[1].clone()];
        assert!(check_leaf(&rin, &[txs[0].clone(), txs[2].clone()], &gap).is_ok());
        assert!(check_leaf(&rin, &[txs[0].clone(), txs[1].clone(), txs[2].clone()], &[wits[0].clone(), wits[1].clone(), w13[1].clone()]).is_err());
        // (8) a nullifier the witness inserts that is not the surface's.
        let mut other = wits.clone();
        other[0].inserts[0].key = rng.digest();
        assert_eq!(check_leaf(&rin, &txs, &other), Err(StError::Shape));
    }

    #[test]
    fn f3_neg_registry() {
        let (mut s, mut rng) = fresh();
        let leaf = RegistryLeaf::cloaked(7);
        let w = synth_write(&mut rng, &s, leaf);
        let rr = s.r.root();
        let tx = synth_tx(&mut rng, L2ShapeTag::S, &rr);
        // An S tx after the write that read the pre-write root is refused.
        assert_eq!(s.apply_leaf(&[w.clone(), tx.clone()]).unwrap_err(), StError::RegistryRead);
        // The same S tx before the write verifies; R threads to the PV's new root.
        let (rin, wits, rout) = s.apply_leaf(&[tx.clone(), w.clone()]).unwrap();
        assert_eq!(check_leaf(&rin, &[tx, w], &wits), Ok(rout));
        // An S/P read of the current root after the write verifies.
        let mut s2 = L2State::genesis(&[RegistryLeaf::cloaked(0)]);
        let w2 = synth_write(&mut rng, &s2, leaf);
        let mut after = s2.r.clone();
        after.apply_update(leaf).unwrap();
        let tx2 = synth_tx(&mut rng, L2ShapeTag::P, &after.root());
        let (rin2, wits2, rout2) = s2.apply_leaf(&[w2.clone(), tx2.clone()]).unwrap();
        assert_eq!(check_leaf(&rin2, &[w2.clone(), tx2.clone()], &wits2), Ok(rout2));
        // (6) a replacement without authority: a leaf the surface's new_root does not bind.
        let mut bad = wits2.clone();
        bad[0].write.as_mut().unwrap().leaf.mode ^= 1;
        assert_eq!(check_leaf(&rin2, &[w2.clone(), tx2.clone()], &bad), Err(StError::RegistryWrite));
        // Asset 0 is never writable.
        assert!(s2.clone().apply_tx(&synth_write_unchecked(&mut rng, &s2, RegistryLeaf::cloaked(0))).is_err());
        // A second write in one leaf (ruling Q6).
        let mut s3 = L2State::genesis(&[RegistryLeaf::cloaked(0)]);
        let a = synth_write(&mut rng, &s3, RegistryLeaf::cloaked(8));
        assert_eq!(s3.apply_leaf(&[a.clone(), a]).unwrap_err(), StError::SecondWrite);
    }

    /// A write surface whose leaf may be unwritable (the asset-0 negative).
    fn synth_write_unchecked(rng: &mut Rng, state: &L2State, leaf: RegistryLeaf) -> TxSurface {
        let mut t = synth_write(rng, state, RegistryLeaf::cloaked(9));
        t.pvs[qlab_air::l2r::PV_ASSET] = leaf.asset as u32;
        t.write = Some(leaf);
        t
    }

    #[test]
    fn f3_surface_digest_and_chunks() {
        let mut rng = Rng(3);
        let d = rng.digest();
        let t = TxSurface { tag: L2ShapeTag::R, pvs: { let mut p = vec![0u32; qlab_air::l2r::PV_LEN]; p[..16].copy_from_slice(&pv_chunks(&d)); p }, write: None };
        assert_eq!(t.digest_at(0), Ok(d), "chunks invert pv_chunks");
        let mut big = t.clone();
        big.pvs[3] = 1 << 16;
        assert_eq!(big.digest_at(0), Err(StError::Surface), "a chunk ≥ 2^16 is refused");
        // The domain and the chain position both enter.
        assert_ne!(sd_step(&EMPTY, L2ShapeTag::R, &t.pvs), sd_step(&d, L2ShapeTag::R, &t.pvs));
        assert_eq!(sd_words(&EMPTY, L2ShapeTag::S, &[]).len(), 14);
        // Permutations per step (padded blocks): S 4, P 5, R 4.
        assert_eq!((sd_perms(qlab_air::l2::PV_LEN), sd_perms(qlab_air::l2p::PV_LEN), sd_perms(qlab_air::l2r::PV_LEN)), (4, 5, 4));
        assert_eq!(sd_words(&EMPTY, L2ShapeTag::P, &vec![0; qlab_air::l2p::PV_LEN]).len() * 4 / RATE + 1, sd_perms(qlab_air::l2p::PV_LEN));
    }
}
