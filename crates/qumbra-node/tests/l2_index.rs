//! **R1's done-when** (lab #860): a node holding landed bundles serves the L2
//! index's leaves, nullifiers and asset-0 opening, and each folds to the
//! roots the bundles' W public values state; an R member freezes the index by
//! name; a reorg re-folds; bytes that do not hash to their id freeze it; off
//! V6 every route is a 400 by name.
//!
//! **Fixture-only, and why that is honest here** (#860 ASK 4): the bundles are
//! real frames over real fold outputs — members from qlab-wprover's synth
//! fixtures, `WState::apply` for the roots, `wleaf::w_pvs` for W's PVs — with
//! placeholder proof bytes, and they are stored in `StoredBlock`s directly
//! rather than through the node's bundle rule. The index folds the PVs of
//! blocks the node has already accepted (`stated_pvs` never decodes a
//! proof); accepting them is the bundle rule's job, tested with it. No
//! proving anywhere.

use std::collections::BTreeMap;

use p3_field::PrimeField32;
use qlab_cbserver::codec::NullifierPage;
use qlab_cbserver::l2fold::f4::{check_wrapper_leaf, Member, WInputs, WState};
use qlab_devnet::annulet::L2ShapeTag;
use qlab_node::{BundleRef, ChainStore, MemChainStore, StoredBlock, StoredHeader, StoredSections, TreeLeaves};
use qlab_wprover::f3::native::{synth_tx, synth_write, Rng};
use qlab_wprover::f4::native::{tx_member, NO_VP};
use qlab_wrapper::codec::{encode_frame, FrameParts, SEQUENCER_SIG_LEN};
use qlab_wrapper::dep::DEP_PV_LEN;
use qlab_wrapper::verify::roots_at;
use qumbra_node::discovery_server::{respond_l2, L2_INDEX_NOT_V6};
use qumbra_node::l2_index::{IndexRefusal, L2Index, L2IndexView};

/// One bundle's bytes over `members`, folded on `state` (which advances).
fn bundle(state: &mut WState, rng: &mut Rng, members: Vec<Member>) -> Vec<u8> {
    let inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()), d_batch: 0 };
    let (rin, wit, rout) = state.apply(&inp, &members).expect("the fixture members fold");
    let exit_cmt = check_wrapper_leaf(&rin, &inp, &members, &wit).expect("the wrapper leaf checks").1;
    let w: Vec<u32> =
        qlab_wprover::f4::wleaf::w_pvs(&rin, &rout, &inp, 0, &exit_cmt).iter().map(PrimeField32::as_canonical_u32).collect();
    let placeholder = [0xABu8; 8];
    let ms: Vec<_> = members.iter().map(|m| (m.tag, m.pvs.as_slice(), placeholder.as_slice())).collect();
    encode_frame(&FrameParts {
        version: 1,
        l2_id: 7,
        w_pvs: &w,
        w_proof: &placeholder,
        dep_pvs: &[0u32; DEP_PV_LEN],
        dep_proof: &placeholder,
        members: &ms,
        exits: &[],
        sig: &[0u8; SEQUENCER_SIG_LEN],
    })
}

/// `n` S members anchored at `state`'s current C root.
fn s_members(state: &WState, rng: &mut Rng, n: usize) -> Vec<Member> {
    let (rr, c_in) = (state.l2.r.root(), state.l2.c.root());
    (0..n).map(|_| tx_member(&synth_tx(rng, L2ShapeTag::S, &rr), &c_in, NO_VP)).collect()
}

fn block(height: u64, prev: [u8; 32], salt: u64, bundle: Option<BundleRef>) -> StoredBlock {
    StoredBlock {
        header: StoredHeader { prev, height, timestamp: height * 75, difficulty: 1, nonce: height ^ salt, tx_body_commitment: [0; 32] },
        txs: Vec::new(),
        coinbase: 0,
        coinbase_rkm: [1, 2, 3, 4],
        annulet: None,
        sections: bundle.map(|b| StoredSections { finality: Vec::new(), bundle: Some(b) }),
    }
}

/// A chain of `n` blocks on genesis; `bundles[h]` rides block `h`.
fn chain(n: u64, bundles: &BTreeMap<u64, BundleRef>) -> (MemChainStore, Vec<[u8; 32]>) {
    let g = block(0, [0; 32], 0, None);
    let mut hashes = vec![g.header().header_hash()];
    let mut store = MemChainStore::new(g);
    for h in 1..=n {
        let b = block(h, *hashes.last().unwrap(), 0, bundles.get(&h).cloned());
        hashes.push(store.put_block(b).expect("extends"));
    }
    (store, hashes)
}

#[test]
fn two_landed_bundles_serve_leaves_nullifiers_and_an_opening_that_fold_to_the_stated_roots() {
    let mut rng = Rng(0x860_0001);
    let mut s = WState::genesis(&qumbra_node::genesis_v6::v6_genesis_registry());
    let m1 = s_members(&s, &mut rng, 2);
    let b1 = bundle(&mut s, &mut rng, m1);
    let m2 = s_members(&s, &mut rng, 1);
    let b2 = bundle(&mut s, &mut rng, m2);
    let mut at = BTreeMap::new();
    at.insert(3, BundleRef::resident(&b1).unwrap());
    at.insert(6, BundleRef::resident(&b2).unwrap());
    let (store, _) = chain(8, &at);

    let mut idx = L2Index::genesis();
    assert!(idx.refresh(&store));
    assert_eq!(idx.refused(), None);
    assert_eq!(idx.height(), Some(6));
    assert!(!idx.refresh(&store), "an unchanged chain folds nothing new");
    let v = idx.view();
    let out = roots_at(&qlab_wrapper::codec::stated_pvs(&b2).unwrap().w_pvs, 1);

    // Leaves: the folded C tree, served on the `/v1/tree/leaves` wire.
    let page = TreeLeaves::from_bytes(&respond_l2(&v, "/v1/l2/tree/leaves", "from=0").unwrap()).unwrap();
    assert_eq!(page.total, out.f3.c_next, "every leaf the stated C holds");
    assert_eq!(page.leaves.len() as u64, out.f3.c_next);
    let mut tree = qlab_cbserver::tree::CommitmentTree::new();
    for l in &page.leaves {
        tree.append_bytes(l);
    }
    assert_eq!(tree.root(), out.f3.c, "the served leaves fold to the stated C root");

    // Nullifiers: every L1 height 0..=6, empty where no bundle rides; 3 per S.
    let np = NullifierPage::from_bytes(&respond_l2(&v, "/v1/l2/nullifiers", "from=0&to=99").unwrap()).unwrap();
    assert_eq!(np.blocks.iter().map(|b| b.height).collect::<Vec<_>>(), (0..=6).collect::<Vec<_>>());
    let counts: Vec<usize> = np.blocks.iter().map(|b| b.nullifiers.len()).collect();
    assert_eq!(counts, vec![0, 0, 0, 6, 0, 0, 3]);
    assert_eq!(out.f3.n_next, 1 + 9, "the indexed tree's genesis leaf plus nine nullifiers");

    // The asset-0 opening at the index's height folds to the stated R root.
    let op = qlab_cbserver::registry::decode_registry_opening(&respond_l2(&v, "/v1/l2/registry/0", "").unwrap()).unwrap();
    assert_eq!((op.height, op.root), (6, out.f3.r));
    assert_eq!(op.witness.fold_root(&op.leaf.hash()), out.f3.r);
    assert_eq!(respond_l2(&v, "/v1/l2/registry/9", "").unwrap_err().0, 404);

    // `/v1/l2/index` names the last bundle, strictly readable.
    let ix = qlab_ledger::deposits::parse_l2_index(&respond_l2(&v, "/v1/l2/index", "").unwrap()).unwrap();
    assert_eq!(ix.height, Some(6));
    assert_eq!(ix.bundle_id, Some(qlab_devnet::hash::keccak256(&b2)));
    assert_eq!(ix.refused, None);
}

#[test]
fn a_registry_write_member_freezes_the_index_by_name() {
    let mut rng = Rng(0x860_0002);
    let mut s = WState::genesis(&qumbra_node::genesis_v6::v6_genesis_registry());
    let m1 = s_members(&s, &mut rng, 1);
    let b1 = bundle(&mut s, &mut rng, m1);
    let leaf = qlab_air::l2::RegistryLeaf::cloaked(5);
    let w = synth_write(&mut rng, &s.l2, leaf);
    let r = Member { tag: qlab_cbserver::l2fold::f4::wtag_of(L2ShapeTag::R), pvs: w.pvs.clone(), write: w.write };
    let b2 = bundle(&mut s, &mut rng, vec![r]);
    let mut at = BTreeMap::new();
    at.insert(2, BundleRef::resident(&b1).unwrap());
    at.insert(4, BundleRef::resident(&b2).unwrap());
    let (store, _) = chain(5, &at);
    let mut idx = L2Index::genesis();
    idx.refresh(&store);
    assert_eq!(idx.refused(), Some(&IndexRefusal::RegistryWrite { height: 4, member: 0 }));
    assert_eq!(idx.height(), Some(2), "frozen at the last good bundle");
    let ix = qlab_ledger::deposits::parse_l2_index(&respond_l2(&idx.view(), "/v1/l2/index", "").unwrap()).unwrap();
    assert_eq!(ix.height, Some(2));
    assert!(ix.refused.as_deref().is_some_and(|r| r.starts_with("registry-write at height 4")), "{:?}", ix.refused);
}

#[test]
fn a_reorg_below_the_index_re_folds_from_genesis() {
    let mut rng = Rng(0x860_0003);
    let g = WState::genesis(&qumbra_node::genesis_v6::v6_genesis_registry());
    let mut a = g.clone();
    let ma = s_members(&a, &mut rng, 1);
    let ba = bundle(&mut a, &mut rng, ma);
    let mut b = g.clone();
    let mb = s_members(&b, &mut rng, 2);
    let bb = bundle(&mut b, &mut rng, mb);

    let mut at = BTreeMap::new();
    at.insert(3, BundleRef::resident(&ba).unwrap());
    let (mut store, hashes) = chain(3, &at);
    let mut idx = L2Index::genesis();
    idx.refresh(&store);
    assert_eq!(idx.bundles()[0].id, qlab_devnet::hash::keccak256(&ba));

    // A heavier branch from height 2 carries the other bundle at 3, then 4, 5.
    let mut prev = hashes[2];
    for h in 3..=5 {
        let blk = block(h, prev, 0xF0, (h == 3).then(|| BundleRef::resident(&bb).unwrap()));
        prev = store.put_block(blk).expect("the sibling branch inserts");
    }
    assert_eq!(store.tip_height(), 5, "the longer branch is the main chain");
    assert!(idx.refresh(&store));
    assert_eq!(idx.bundles().len(), 1);
    assert_eq!(idx.bundles()[0].id, qlab_devnet::hash::keccak256(&bb), "the replaced bundle is gone");
    assert_eq!(idx.leaves().len() as u64, b.l2.c.len());
}

#[test]
fn stored_bytes_that_do_not_hash_to_their_id_freeze_the_index() {
    let mut rng = Rng(0x860_0004);
    let mut s = WState::genesis(&qumbra_node::genesis_v6::v6_genesis_registry());
    let m = s_members(&s, &mut rng, 1);
    let b1 = bundle(&mut s, &mut rng, m);
    let dir = std::env::temp_dir().join(format!("qmb_r1_log_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blocks.log");
    let mut flipped = b1.clone();
    flipped[100] ^= 1;
    std::fs::write(&path, &flipped).unwrap();
    let r = BundleRef::in_log(qlab_devnet::hash::keccak256(&b1), b1.len() as u32, std::sync::Arc::from(path.as_path()), 0);
    let mut at = BTreeMap::new();
    at.insert(1, r);
    let (store, _) = chain(2, &at);
    let mut idx = L2Index::genesis();
    idx.refresh(&store);
    assert!(matches!(idx.refused(), Some(IndexRefusal::Unreadable { height: 1, .. })), "{:?}", idx.refused());
    assert_eq!(idx.height(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn off_v6_every_l2_route_is_a_400_by_name() {
    let v = L2IndexView::default();
    for p in ["/v1/l2/index", "/v1/l2/tree/leaves", "/v1/l2/nullifiers", "/v1/l2/registry/0"] {
        assert_eq!(respond_l2(&v, p, "from=0&to=1"), Err((400, L2_INDEX_NOT_V6.to_string())), "{p}");
    }
}

/// The `/v1/l2/index` wire, golden, and its strict reader's refusals.
#[test]
fn the_index_body_is_golden_and_read_strictly() {
    let v = L2IndexView { v6: true, height: Some(48), bundle_id: Some([0xAB; 32]), refused: Some("registry-write at height 96 member 0: not reconstructible from the wire (format v1)".into()), ..L2IndexView::default() };
    let body = qumbra_node::discovery_server::l2_index_body(&v);
    assert_eq!(
        body,
        format!(r#"{{"v":1,"height":48,"bundle_id":"{}","refused":"registry-write at height 96 member 0: not reconstructible from the wire (format v1)"}}"#, "ab".repeat(32))
    );
    let empty = qumbra_node::discovery_server::l2_index_body(&L2IndexView { v6: true, ..L2IndexView::default() });
    assert_eq!(empty, r#"{"v":1,"height":null,"bundle_id":null,"refused":null}"#);
    use qlab_ledger::deposits::parse_l2_index;
    assert_eq!(parse_l2_index(empty.as_bytes()).unwrap().height, None);
    for bad in [
        r#"{"v":2,"height":null,"bundle_id":null,"refused":null}"#,
        r#"{"v":1,"height":null,"bundle_id":null,"refused":null} "#,
        r#"{"v":1,"height":07,"bundle_id":null,"refused":null}"#,
        r#"{"v":1,"height":1,"bundle_id":null,"refused":null}"#,
        r#"{"v":1,"height":null,"bundle_id":null,"refused":"a \"quote\""}"#,
    ] {
        assert!(parse_l2_index(bad.as_bytes()).is_err(), "{bad}");
    }
    for n in 0..body.len() {
        assert!(parse_l2_index(&body.as_bytes()[..n]).is_err(), "prefix {n}");
    }
}
