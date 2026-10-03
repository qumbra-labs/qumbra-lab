//! Moved to `qlab_cbserver::l2fold::f3` by lab #860 R1 (verbatim); this
//! module re-exports it unchanged, so no path moved, and keeps the fixtures
//! and the tests.

pub use qlab_cbserver::l2fold::f3::*;

// The fixtures' and tests' imports, as the module had them.
#[allow(unused_imports)]
use std::collections::HashMap;

#[allow(unused_imports)]
use qlab_air::l2::{RegistryLeaf, RegistryWitness};
#[allow(unused_imports)]
use qlab_air::l2p::{key_lt, KEY_MAX};
#[allow(unused_imports)]
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
#[allow(unused_imports)]
use qlab_air::reference::keccak_f;
#[allow(unused_imports)]
use qlab_cbserver::registry::RegistryTree;
#[allow(unused_imports)]
use qlab_cbserver::tree::{zeros, CommitmentTree};
#[allow(unused_imports)]
use qlab_devnet::annulet::L2ShapeTag;

// Lab #785 F5-1: the hash-level items moved to qlab-wrapper.
pub use qlab_wrapper::hash::{
    nf_leaf_hash, node_pub, sd_chain_byte, sd_domain_lanes, sd_perms, sd_words_byte, Digest, Roots, EMPTY, INDEX_CAP, N_DEPTH, SD_BLOCK_WORDS, SD_LANE_DOMAIN, SD_LANE_FINAL, SD_LANE_INDEX, SD_LANE_MSG,
};
#[allow(unused_imports)]
use qlab_wrapper::hash::node;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A deterministic stream for fixtures (xorshift64).
pub struct Rng(pub u64);

impl Rng {
    // A fixture stream, not an iterator: it never ends, and `Iterator` would
    // put `Option` on every one of its call sites (clippy's
    // `should_implement_trait` once the type became `pub`, lab #847 S1b).
    #[allow(clippy::should_implement_trait)]
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
pub fn synth_tx(rng: &mut Rng, tag: L2ShapeTag, registry_root: &Digest) -> TxSurface {
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
pub fn synth_write(rng: &mut Rng, state: &L2State, leaf: RegistryLeaf) -> TxSurface {
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
    use p3_field::PrimeField32;

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
        let mut ls = s.n.leaves().to_vec();
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
        let other = (0..s.n.leaves().len() as u64).find(|i| *i != w.low_index).unwrap();
        let mut wrong = w;
        wrong.low_index = other;
        wrong.low = s.n.leaves()[other as usize];
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

    /// Review of PR #768 — negative (1) across two leaves: leaf 1 inserts
    /// `K`, leaf 2 re-inserts it on the same state. No gap brackets `K`.
    #[test]
    fn f3_neg_double_insert_across_leaves() {
        let (mut s, mut rng) = fresh();
        let rr = s.r.root();
        let t1 = synth_tx(&mut rng, L2ShapeTag::S, &rr);
        let (_, w1, rmid) = s.apply_leaf(std::slice::from_ref(&t1)).unwrap();
        let mut t2 = synth_tx(&mut rng, L2ShapeTag::P, &rr);
        t2.pvs[16..32].copy_from_slice(&t1.pvs[16..32]);
        assert_eq!(s.apply_leaf(std::slice::from_ref(&t2)).unwrap_err(), StError::Nf(NfError::NotInGap));
        // Replaying leaf 1's insert witness for K in leaf 2 is refused too.
        let mut other = s.clone();
        let mut t3 = synth_tx(&mut rng, L2ShapeTag::S, &rr);
        let (_, mut w3, _) = other.apply_leaf(std::slice::from_ref(&t3)).unwrap();
        t3.pvs[16..32].copy_from_slice(&t1.pvs[16..32]);
        w3[0].inserts[0] = w1[0].inserts[0];
        assert!(check_leaf(&rmid, &[t3], &w3).is_err(), "leaf 1's witness for K does not re-insert K");
    }

    /// Review of PR #768 — negative (4) for C and R: the right index, a
    /// superseded root.
    #[test]
    fn f3_neg_stale_root_c_and_r() {
        // C: b's append at index 1, proven in a tree whose index 0 holds x, not a.
        let mut rng = Rng(11);
        let (a, b, x) = (rng.digest(), rng.digest(), rng.digest());
        let mut c = CommitmentTree::new();
        append(&mut c, &a);
        let r1 = c.root();
        let mut alt = CommitmentTree::new();
        append(&mut alt, &x);
        let wb_alt = append(&mut alt, &b);
        assert_eq!(wb_alt.index, 1, "the right index");
        assert_eq!(apply_append(&r1, 1, &b, &wb_alt), Err(AppendError::RootMismatch));
        // R: a write proven against the registry before an earlier write. N and
        // C witnesses come from the current state, so only R is stale.
        let (mut s, mut rng) = fresh();
        let stale = s.clone();
        let w7 = synth_write(&mut rng, &s, RegistryLeaf::cloaked(7));
        let (_, _, rin) = s.apply_leaf(std::slice::from_ref(&w7)).unwrap();
        let leaf8 = RegistryLeaf::cloaked(8);
        let mut w8 = synth_write(&mut rng, &stale, leaf8);
        let mut cur = s.clone();
        let inserts = w8.nullifiers().unwrap().iter().map(|nf| cur.n.insert(nf).unwrap()).collect();
        let appends = w8.commitments().unwrap().iter().map(|cm| append(&mut cur.c, cm)).collect();
        let stale_write = RegistryWrite { leaf: leaf8, old_digest: EMPTY, path: stale.r.opening_at(8) };
        let wit = TxWitness { inserts, appends, write: Some(stale_write) };
        // (i) the surface's own old_root is the superseded one.
        assert_eq!(check_leaf(&rin, std::slice::from_ref(&w8), std::slice::from_ref(&wit)), Err(StError::RegistryRoot));
        // (ii) old_root patched to the running R, the opening still the stale tree's.
        w8.pvs[qlab_air::l2r::PV_OLD_ROOT..qlab_air::l2r::PV_OLD_ROOT + 16].copy_from_slice(&pv_chunks(&s.r.root()));
        assert_eq!(check_leaf(&rin, std::slice::from_ref(&w8), std::slice::from_ref(&wit)), Err(StError::RegistryRoot));
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
        assert_eq!(sd_words(L2ShapeTag::S, &[]), vec![1, 0], "tag, pv_len");
        // Permutations per step (26 message words per block): S 5, P 6 (the
        // exit recipient, lab #785 F5-4d), R 4.
        assert_eq!((sd_perms(qlab_air::l2::PV_LEN), sd_perms(qlab_air::l2p::PV_LEN), sd_perms(qlab_air::l2r::PV_LEN)), (5, 6, 4));
        for (tag, len) in [(L2ShapeTag::S, qlab_air::l2::PV_LEN), (L2ShapeTag::P, qlab_air::l2p::PV_LEN), (L2ShapeTag::R, qlab_air::l2r::PV_LEN)] {
            let (blocks, h) = sd_chain(&d, tag, &vec![7; len]);
            assert_eq!(blocks.len(), sd_perms(len));
            assert_eq!(blocks[0][..4], d, "block 0 chains SD_prev");
            for (b, st) in blocks.iter().enumerate() {
                assert_eq!(st[SD_LANE_DOMAIN..SD_LANE_DOMAIN + 2], sd_domain_lanes());
                assert_eq!((st[SD_LANE_INDEX], st[SD_LANE_FINAL]), (b as u64, u64::from(b + 1 == blocks.len())));
                assert!(st[21..].iter().all(|l| *l == 0));
                if b > 0 {
                    assert_eq!(st[..4], keccak_f(&blocks[b - 1])[..4], "block {b} chains block {}", b - 1);
                }
            }
            assert_eq!(h[..], keccak_f(blocks.last().unwrap())[..4]);
        }
    }

    /// Approval condition 1(b): streams that agree in every message word but
    /// the length — a moved zero-pad boundary — do not collide. `x` and
    /// `x ‖ 0^12` pad to the same five blocks of words except word 1
    /// (`pv_len`); `x ‖ 0^38` adds a sixth block, so block 4's final flag
    /// differs as well; the same words under another tag differ in word 0.
    #[test]
    fn f3_neg_sd_moved_pad_boundary() {
        let mut rng = Rng(0x5d);
        let x: Vec<u32> = (0..qlab_air::l2::PV_LEN).map(|_| (rng.next() & 0xffff) as u32).collect();
        let (bx, hx) = sd_chain(&EMPTY, L2ShapeTag::S, &x);
        let y: Vec<u32> = x.iter().copied().chain([0; 12]).collect();
        let (by, hy) = sd_chain(&EMPTY, L2ShapeTag::S, &y);
        assert_eq!(bx.len(), by.len());
        let mut diff: Vec<(usize, usize)> = Vec::new();
        for b in 0..bx.len() {
            for l in 0..25 {
                if (b == 0 || l >= SD_LANE_MSG) && bx[b][l] != by[b][l] {
                    diff.push((b, l));
                }
            }
        }
        assert_eq!(diff, vec![(0, SD_LANE_MSG)], "only word 1 (pv_len) differs");
        assert_ne!(hx, hy);
        let z: Vec<u32> = x.iter().copied().chain([0; 38]).collect();
        let (bz, hz) = sd_chain(&EMPTY, L2ShapeTag::S, &z);
        assert_eq!((bx.len(), bz.len()), (5, 6));
        assert_eq!((bx[4][SD_LANE_FINAL], bz[4][SD_LANE_FINAL]), (1, 0), "the final flag moves");
        assert_ne!(hx, hz);
        assert_ne!(hx, sd_step(&EMPTY, L2ShapeTag::P, &x), "the tag is word 0");
    }

    /// The index cap: at 2^30 leaves both trees refuse before reading the witness.
    #[test]
    fn f3_index_cap_refuses() {
        let (mut s, mut rng) = fresh();
        let (root, next) = (s.n.root(), s.n.next_index());
        let w = s.n.insert(&rng.digest()).unwrap();
        assert!(apply_insert(&root, next, &w).is_ok());
        assert_eq!(apply_insert(&root, INDEX_CAP, &w), Err(NfError::Full));
        let mut c = CommitmentTree::new();
        let r0 = c.root();
        let cm = rng.digest();
        let wa = append(&mut c, &cm);
        assert_eq!(apply_append(&r0, INDEX_CAP, &cm, &wa), Err(AppendError::Full));
        assert!(INDEX_CAP < u64::from(qlab_consensus::Val::ORDER_U32), "an index is one field element");
    }
}
