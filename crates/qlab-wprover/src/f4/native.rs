//! Moved to `qlab_cbserver::l2fold::f4` by lab #860 R1 (verbatim); this
//! module re-exports it unchanged, so no path moved, and keeps the fixtures
//! and the tests.

pub use qlab_cbserver::l2fold::f4::*;

// The fixtures' and tests' imports, as the module had them.
#[allow(unused_imports)]
use qlab_air::l2::{RegistryLeaf, RegistryWitness};
#[allow(unused_imports)]
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
#[allow(unused_imports)]
use qlab_cbserver::tree::CommitmentTree;
#[allow(unused_imports)]
use qlab_devnet::annulet::L2ShapeTag;

#[allow(unused_imports)]
use crate::f3::native::{
    append, apply_append, apply_insert, sd_chain_byte, AppendError, AppendWitness, Digest, IndexedTree, InsertWitness,
    L2State, NfError, StError, TxSurface, TxWitness, EMPTY, INDEX_CAP,
};

// Lab #785 F5-1: the wrapper-state types and domain-tagged states moved to qlab-wrapper.
#[cfg_attr(not(test), allow(unused_imports))]
pub use qlab_wrapper::hash::{
    exit_state, fee_domain_lanes, fee_rho, fee_rseed, fee_seed_state, h4,
    supply_leaf_state, WRoots, WTag, CLAIM_TAG, M_ABS, SUPPLY_DEPTH,
};

/// The fee note's commitment: an asset-0 L2 note (`qlab_air::l2::l2_cm`).

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A synthetic claim surface anchored at `a`: fresh `cnf`, `Cv`, `cm2`, the
/// burn address, and `fee` (four chunks). Range, not semantics, is what W
/// reads; a real claim proof binds these (F1).
pub fn synth_claim(rng: &mut crate::f3::native::Rng, a: &Digest, fee: u64) -> Member {
    synth_claim_open(rng, a, fee).0
}

/// [`synth_claim`] with its value commitment's opening: `Cv` is
/// `claim_cv(v, r_v)` for a 40-bit `v ≥ fee` (so a deposit proof over the
/// fixture's claims exists).
pub fn synth_claim_open(rng: &mut crate::f3::native::Rng, a: &Digest, fee: u64) -> (Member, super::dep::DepEntry) {
    use qlab_air::claim::{PV_A, PV_CM2, PV_CNF, PV_CV, PV_FEE, PV_LEN, PV_RKM_BURN};
    let mut pvs = vec![0u32; PV_LEN];
    let cnf = rng.digest();
    let r_v = rng.digest();
    let open = super::dep::DepEntry { v: fee + (r_v[0] >> 24), r_v };
    let cv = qlab_air::claim::claim_cv(open.v, &r_v);
    for (off, d) in [(PV_A, *a), (PV_CNF, cnf), (PV_CV, cv), (PV_CM2, rng.digest()), (PV_RKM_BURN, rng.digest())] {
        pvs[off..off + 16].copy_from_slice(&pv_chunks(&d));
    }
    for j in 0..4 {
        pvs[PV_FEE + j] = ((fee >> (16 * j)) & 0xffff) as u32;
    }
    (Member { tag: WTag::C, pvs, write: None }, open)
}

/// A transaction member valid against a wrapper whose `C_in` is `c_in`: its
/// anchor set to `c_in` (so it opens in `CH`) and, for P, its `vPublic` rows
/// set to `rows` (`(s, m, vpa)` each; `(0, 0, 0)` = no `vPublic`).
pub fn tx_member(t: &TxSurface, c_in: &Digest, rows: [(u32, u64, u32); 2]) -> Member {
    let mut m = Member::tx(t);
    m.pvs[..16].copy_from_slice(&pv_chunks(c_in));
    if m.tag == WTag::P {
        for (k, (sgn, amt, vpa)) in rows.iter().enumerate() {
            let base = qlab_air::l2p::PV_VP1 + 6 * k;
            m.pvs[base] = *sgn;
            for j in 0..4 {
                m.pvs[base + 1 + j] = ((amt >> (16 * j)) & 0xffff) as u32;
            }
            m.pvs[base + 5] = *vpa;
        }
        // P's canonical recipient (lab #785 F5-4d): nonzero exactly when a
        // row exits.
        let exits = rows.iter().any(|(sgn, amt, vpa)| is_exit(*sgn, *amt, *vpa));
        let xrkm = if exits { pv_chunks(&fixture_xrkm(&m.pvs)) } else { [0; 16] };
        m.pvs[qlab_air::l2p::PV_XRKM..qlab_air::l2p::PV_XRKM + 16].copy_from_slice(&xrkm);
    }
    m
}

/// No `vPublic` on either row.
pub const NO_VP: [(u32, u64, u32); 2] = [(0, 0, 0); 2];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f3::native::{synth_tx, Rng};

    fn fresh() -> (WState, Rng, WInputs) {
        let mut rng = Rng(0x775_f4f4_0001);
        let inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()), d_batch: 0 };
        (WState::genesis(&[RegistryLeaf::cloaked(0)]), rng, inp)
    }

    /// Lab #785 review Y1: qlab-wrapper's `WTag::byte` writes the shape
    /// bytes out rather than reading qlab-devnet's `L2ShapeTag`; they must
    /// stay the same bytes, the conversion must round-trip, and the claim
    /// tag must be none of them.
    #[test]
    fn wtag_bytes_are_the_shape_tags() {
        for tag in [L2ShapeTag::S, L2ShapeTag::P, L2ShapeTag::R] {
            let w = wtag_of(tag);
            assert_eq!(w.byte(), tag.byte(), "{tag:?}");
            assert_eq!(w.shape(), Some(tag));
            assert_eq!(L2ShapeTag::from_byte(w.byte()), Some(tag));
        }
        assert_eq!(WTag::C.shape(), None);
        assert_eq!(L2ShapeTag::from_byte(WTag::C.byte()), None, "the claim tag is no shape's byte");
        assert_eq!(WTag::ALL.map(WTag::byte), [0x01, 0x02, 0x03, CLAIM_TAG]);
    }

    /// Lab #785 F5-4a (ruling condition (a)): qlab-wrapper's genesis port
    /// computes this model's roots, over an empty registry and a non-empty
    /// one, tree by tree; the zero ladder is the node's; the digest-bytes
    /// mapping is qlab-note's.
    #[test]
    fn wgenesis_roots_are_the_native_models() {
        use qlab_cbserver::registry::RegistryTree;
        use qlab_wrapper::genesis as g;
        use qlab_wrapper::verify::Surface;
        assert_eq!(g::zeros(), qlab_cbserver::tree::zeros());
        assert_eq!(g::indexed_genesis_root(), IndexedTree::genesis().root());
        assert_eq!(g::supply_genesis_root(), SupplyTree::genesis().root());
        assert_eq!(g::empty_registry_root(), RegistryTree::from_leaves(&[]).unwrap().root());
        for reg in [vec![], vec![RegistryLeaf::cloaked(0)]] {
            let model = WState::genesis(&reg).roots();
            let r = RegistryTree::from_leaves(&reg).unwrap().root();
            assert_eq!(g::genesis_roots(&r), model, "registry of {}", reg.len());
            assert_eq!(g::genesis_surface(7, &r), Surface::genesis(g::CHAIN_VERSION, 7, model));
        }
        let mut rng = Rng(0x785_f54a);
        for _ in 0..8 {
            let d = rng.digest();
            assert_eq!(qlab_wrapper::codec::digest_to_bytes(&d), qlab_note::hash::digest_bytes(&d));
            assert_eq!(qlab_wrapper::codec::digest_from_bytes(&qlab_note::hash::digest_bytes(&d)), d);
        }
    }

    /// Lab #785 F5-4a (pre-review P3): `qlab_wrapper::codec::exit_chain`
    /// over the clear list is this model's `exit_cmt` — three exits, two
    /// rows of one P member then one of the next, in slot and row order.
    #[test]
    fn exit_chain_is_the_models_exit_cmt() {
        use qlab_wrapper::codec::{exit_chain, exit_sum, Exit};
        let (mut s, mut rng, mut inp) = fresh();
        inp.d_batch = 1000;
        let a = p_member(&mut rng, &s, [(1, 40, 0), (1, 2, 0)]);
        let b = p_member(&mut rng, &s, [(1, 7, 0), (0, 0, 0)]);
        let members = [a.clone(), b.clone()];
        let (rin, w, rout) = s.apply(&inp, &members).unwrap();
        let exc = check_wrapper_leaf(&rin, &inp, &members, &w).unwrap().1;
        // One recipient per transaction (lab #785 F5-4d): a's two exits pay
        // the same `rkm`, two chain entries.
        let xr = |m: &Member| m.digest_at(qlab_air::l2p::PV_XRKM).unwrap();
        assert_ne!(xr(&a), xr(&b));
        let list = [
            Exit { rkm: xr(&a), v: 40 },
            Exit { rkm: xr(&a), v: 2 },
            Exit { rkm: xr(&b), v: 7 },
        ];
        assert_eq!(exit_chain(&list), exc);
        assert_eq!(exit_sum(&list), Some(rout.e_cum - rin.e_cum));
        let mut swapped = list;
        swapped.swap(0, 1);
        assert_ne!(exit_chain(&swapped), exc, "order binds");
    }

    /// A mixed sequence threads, and the fee note carries Σ fee.
    #[test]
    fn f4_wrapper_leaf_threads_claims_and_the_fee_note() {
        let (mut s, mut rng, inp) = fresh();
        let (rr, c_in) = (s.l2.r.root(), s.l2.c.root());
        let members = vec![
            tx_member(&synth_tx(&mut rng, L2ShapeTag::P, &rr), &c_in, NO_VP),
            synth_claim(&mut rng, &inp.absorbed[1], 7),
            synth_claim(&mut rng, &inp.absorbed[3], 1 << 40),
            tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_in, NO_VP),
        ];
        let (rin, w, rout) = s.apply(&inp, &members).unwrap();
        assert_eq!(check_wrapper_leaf(&rin, &inp, &members, &w).map(|r| r.0), Ok(rout));
        assert_eq!(rout.ch_next, rin.ch_next + 1, "C_in appended to CH");
        assert_eq!(rout.aa_next, rin.aa_next + M_ABS as u64);
        assert_eq!(rout.k_next, rin.k_next + 2, "one cnf per claim");
        assert_eq!(rout.f3.n_next, rin.f3.n_next + 6, "3 per S/P");
        assert_eq!(rout.f3.c_next, rin.f3.c_next + 2 + 2 + 2 + 1, "S/P 2 each, a claim 1, the fee note 1");
        // The fee note is the last leaf of C, with value Σ fee.
        assert_eq!(s.l2.c.leaf(rout.f3.c_next - 1), fee_note_cm(7 + (1 << 40), &inp.rkm_seq, &inp.prev));
    }

    /// Condition (e): the fee note is appended in every wrapper — with no
    /// claims its value is 0, and C's root is the one that note folds to.
    #[test]
    fn f4_fee_note_every_wrapper_and_its_value() {
        let (mut s, mut rng, inp) = fresh();
        let (rr, c_in) = (s.l2.r.root(), s.l2.c.root());
        let members = vec![tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_in, NO_VP)];
        let (_, w, rout) = s.apply(&inp, &members).unwrap();
        assert_eq!(s.l2.c.leaf(rout.f3.c_next - 1), fee_note_cm(0, &inp.rkm_seq, &inp.prev));
        assert_eq!(w.fee.path.fold_root(&fee_note_cm(0, &inp.rkm_seq, &inp.prev)), rout.f3.c);
        assert_ne!(w.fee.path.fold_root(&fee_note_cm(1, &inp.rkm_seq, &inp.prev)), rout.f3.c, "a nonzero note with no claims");
    }

    /// A claim double-spend across wrappers and inside one wrapper: the second
    /// `cnf` has no gap in K.
    #[test]
    fn f4_neg_double_claim() {
        let (mut s, mut rng, inp) = fresh();
        let c1 = synth_claim(&mut rng, &inp.absorbed[0], 1);
        s.apply(&inp, std::slice::from_ref(&c1)).unwrap();
        let mut again = c1.clone();
        again.pvs[qlab_air::claim::PV_CM2] ^= 1;
        let inp2 = WInputs { prev: rng.digest(), ..inp.clone() };
        assert_eq!(s.clone().apply(&inp2, &[again.clone()]).unwrap_err(), WError::Cnf(NfError::NotInGap));
        let (mut t, mut rng2, inp3) = fresh();
        let d = synth_claim(&mut rng2, &inp3.absorbed[0], 1);
        assert_eq!(t.apply(&inp3, &[d.clone(), d]).unwrap_err(), WError::Cnf(NfError::NotInGap));
    }

    /// A claim anchored at a root never absorbed, or at zero.
    #[test]
    fn f4_neg_claim_anchor() {
        let (mut s, mut rng, inp) = fresh();
        let stray = rng.digest();
        assert_eq!(s.clone().apply(&inp, &[synth_claim(&mut rng, &stray, 1)]).unwrap_err(), WError::Anchor);
        assert_eq!(s.apply(&inp, &[synth_claim(&mut rng, &EMPTY, 1)]).unwrap_err(), WError::Anchor);
    }

    /// The fee note's ρ and rseed are distinct, domain-separated, and move
    /// with `prev`; two wrappers share a ρ only if they share `prev`.
    #[test]
    fn f4_fee_seeds() {
        let mut rng = Rng(9);
        let (p, q) = (rng.digest(), rng.digest());
        assert_ne!(fee_rho(&p), fee_rseed(&p));
        assert_ne!(fee_rho(&p), fee_rho(&q));
        assert_eq!(fee_domain_lanes()[0].to_le_bytes(), *b"qumbra:l");
        let st = fee_seed_state(&p, 1);
        assert!(st[17..21].iter().all(|l| *l == 0) && st[21] != 0, "capacity lanes 21..24 carry the domain");
    }

    fn p_member(rng: &mut Rng, s: &WState, rows: [(u32, u64, u32); 2]) -> Member {
        tx_member(&synth_tx(rng, L2ShapeTag::P, &s.l2.r.root()), &s.l2.c.root(), rows)
    }

    /// Ruling Q4 / condition (k): a transaction anchored at the wrapper's own
    /// `C_out` is refused (that root is not in CH until the next prologue);
    /// the next wrapper accepts it.
    #[test]
    fn f4_ch_latency() {
        let (mut s, mut rng, inp) = fresh();
        let rr = s.l2.r.root();
        let t0 = tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &s.l2.c.root(), NO_VP);
        let pre = s.clone();
        let (_, _, rout) = s.apply(&inp, std::slice::from_ref(&t0)).unwrap();
        let c_out = rout.f3.c;
        let mut early = pre.clone();
        let t1 = tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_out, NO_VP);
        assert_eq!(early.apply(&inp, &[t0, t1.clone()]).unwrap_err(), WError::TxAnchor, "not spendable in its own wrapper");
        let inp2 = WInputs { prev: rng.digest(), ..inp.clone() };
        assert!(s.apply(&inp2, &[t1]).is_ok(), "spendable in the next");
    }

    /// Q5 and condition (l): mint and redeem move an asset's outstanding;
    /// asset 0 never moves the tree — its redeem is an exit into E, its mint
    /// is refused; overflow, underflow, an asset id ≥ 2^16 and a sign ≥ 2
    /// refuse; so does a counter overflow.
    #[test]
    fn f4_supply_and_exit_rules() {
        let (mut s, mut rng, mut inp) = fresh();
        inp.d_batch = 1000;
        let m = p_member(&mut rng, &s, [(0, 500, 9), (1, 200, 9)]);
        s.apply(&inp, &[m]).unwrap();
        assert_eq!(s.sup.outstanding(9), 300);
        let sup0 = s.sup.root();
        let m = p_member(&mut rng, &s, [(1, 40, 0), (0, 0, 0)]);
        let (rin, w, rout) = s.apply(&inp, std::slice::from_ref(&m)).unwrap();
        assert_eq!((rout.e_cum, rout.sup), (rin.e_cum + 40, sup0), "an asset-0 redeem is an exit, not a supply move");
        let exc = check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&m), &w).unwrap().1;
        assert_eq!(exc, h4(&exit_state(&EMPTY, &m.digest_at(qlab_air::l2p::PV_XRKM).unwrap(), 40)), "the exit list binds (rkm, v)");
        // Lab #785 F5-4d-2: a zero-amount asset-0 redeem is no exit (P's
        // `e_k`): nothing chains, E does not move, and the fixture's recipient
        // PV is zero; with an exit beside it, only that one chains.
        let z = p_member(&mut rng, &s, [(1, 0, 0), (0, 0, 0)]);
        assert_eq!(z.digest_at(qlab_air::l2p::PV_XRKM).unwrap(), EMPTY);
        let (rin, w, rout) = s.apply(&inp, std::slice::from_ref(&z)).unwrap();
        assert_eq!(rout.e_cum, rin.e_cum);
        assert_eq!(check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&z), &w).unwrap().1, EMPTY, "no exit chained");
        // V5: a recipient word ≥ 2^16 is refused on any P member, exit or not.
        let mut wide = p_member(&mut rng, &s, NO_VP);
        wide.pvs[qlab_air::l2p::PV_XRKM + 3] = 1 << 16;
        assert_eq!(s.clone().apply(&inp, std::slice::from_ref(&wide)).unwrap_err(), WError::Surface);
        let z2 = p_member(&mut rng, &s, [(1, 0, 0), (1, 2, 0)]);
        let (rin, w, _) = s.apply(&inp, std::slice::from_ref(&z2)).unwrap();
        let xr = z2.digest_at(qlab_air::l2p::PV_XRKM).unwrap();
        assert_eq!(check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&z2), &w).unwrap().1, h4(&exit_state(&EMPTY, &xr, 2)));
        for (rows, err) in [
            ([(0, 7, 0), (0, 0, 0)], WError::AssetZeroMint),
            ([(1, 301, 9), (0, 0, 0)], WError::Supply),
            ([(0, u64::MAX, 9), (0, 0, 0)], WError::Supply),
            ([(0, 1, 1 << 16), (0, 0, 0)], WError::Supply),
            ([(2, 1, 9), (0, 0, 0)], WError::Supply),
            ([(1, 1 << 63, 0), (1, 1 << 63, 0)], WError::Counter),
        ] {
            let m = p_member(&mut rng, &s, rows);
            assert_eq!(s.clone().apply(&inp, &[m]).unwrap_err(), err, "{rows:?}");
        }
        let mut over = s.clone();
        over.d_cum = u64::MAX;
        let m = p_member(&mut rng, &s, NO_VP);
        assert_eq!(over.apply(&inp, &[m]).unwrap_err(), WError::Counter, "D_cum overflow");
    }

    /// The supply tree: genesis leaves are `H(asset ‖ 0)`, paths fold to the
    /// root, and a set moves exactly its leaf.
    #[test]
    fn f4_supply_tree() {
        let mut t = SupplyTree::genesis();
        let r0 = t.root();
        let p = t.path(12);
        assert_eq!(p.fold_root(&h4(&supply_leaf_state(12, 0))), r0);
        t.set(12, 77);
        assert_eq!(p.fold_root(&h4(&supply_leaf_state(12, 77))), t.root());
        assert_eq!(t.path(13).fold_root(&h4(&supply_leaf_state(13, 0))), t.root());
    }
}
