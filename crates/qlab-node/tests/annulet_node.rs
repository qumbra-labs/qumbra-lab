//! The Annulet node path (lab #708, B2a): an in-memory Annulet node applies
//! **sealed** blocks through B1's body rule, finalizes on acceptance, and its
//! mempool prices admission with the genesis L2 fee table. The seal itself is
//! validated by the adapter's ingest (`validate_sealed_header_annulet`); here
//! the node's own contract is exercised.

use qlab_devnet::annulet::{
    body_commitment_annulet, genesis_body_commitment_annulet, AnnuletHeaderFields, L2FeeTable,
    L2ShapeTag, L2Surface, SequencerKey, VPublicTerm,
};
use qlab_devnet::body::{BlockBody, BodyError, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::names::EmptyNameView;
use qlab_node::{MemNode, Mempool, MempoolError, MempoolParams, NodeError, NodeState};
use qlab_node::ChainStore;

/// The mock proof verifier (B2's accepted mock — B4 lands the real one).
#[derive(Clone)]
struct OkProof;
impl TxVerifier for OkProof {
    fn verify_tx(&self, e: &TxEntry) -> bool {
        e.proof == b"ok"
    }
}

const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2 };
/// The test registry (asset 0, Cloaked) and its root — lab #710: every
/// header carries the root of the registry the node holds.
fn registry() -> Vec<qlab_node::registry_store::RegistryLeaf> {
    vec![qlab_node::registry_store::RegistryLeaf::cloaked(0)]
}

fn root() -> Hash32 {
    use qlab_node::registry_store::RegistryStore as _;
    qlab_node::registry_store::MemRegistryStore::from_genesis(&registry()).unwrap().root_bytes()
}

fn ext() -> AnnuletHeaderFields {
    AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: root() }
}

fn node() -> (MemNode, BlockHeader) {
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    (MemNode::in_memory_annulet(g, &[], FEES, &registry()), g)
}

fn s_tx(node: &MemNode, nf: u8) -> TxEntry {
    TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor: node.commitment_root(),
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32]],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1,
        },
        discovery: vec![0x00],
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: root(), vpublic: None }.encode(),
    }
}

fn sealed_child(key: &SequencerKey, parent: &BlockHeader, body: &BlockBody) -> qlab_devnet::annulet::SealedHeader {
    key.seal(BlockHeader::child_of_annulet(parent, parent.timestamp + 10, ext(), body_commitment_annulet(body)))
}

#[test]
fn an_annulet_node_applies_sealed_blocks_and_finalizes_each_on_acceptance() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    assert_eq!(n.finalized_height(), Some(0), "genesis is final on acceptance");
    assert!(n.is_valid_anchor(&n.commitment_root()), "so the genesis root anchors block 1");
    let mut parent = g;
    for h in 1..=3u8 {
        let body = BlockBody::new(vec![s_tx(&n, h * 2)], vec![]);
        let sealed = sealed_child(&key, &parent, &body);
        let id = n.apply_sealed_block(&sealed, body, &OkProof).expect("applies");
        assert_eq!(n.tip_height(), h as u64);
        assert_eq!(n.finalized_height(), Some(h as u64), "final on acceptance (Q4)");
        let held = n.chain().block(&id).expect("stored");
        assert_eq!(held.sealed_header().as_ref(), Some(&sealed), "the seal is held for serving");
        assert_eq!(held.body().txs[0].l2, s_tx(&n, 0).l2, "the L2 surface is held");
        parent = sealed.header;
    }
    assert_eq!(n.nullifier_count(), 6);
}

#[test]
fn the_unsealed_entry_point_refuses_an_annulet_block() {
    let (mut n, g) = node();
    let body = BlockBody::default();
    let h = BlockHeader::child_of_annulet(&g, 10, ext(), body_commitment_annulet(&body));
    assert!(matches!(n.apply_block(h, body, &OkProof), Err(NodeError::UnsealedOnAnnulet)));
}

#[test]
fn the_annulet_body_rule_runs_with_the_genesis_fee_table() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    let mut tx = s_tx(&n, 1);
    tx.public.fee = 2; // the P tier on an S transaction
    let body = BlockBody::new(vec![tx], vec![]);
    let sealed = sealed_child(&key, &g, &body);
    assert!(matches!(
        n.apply_sealed_block(&sealed, body, &OkProof),
        Err(NodeError::Body(BodyError::WrongFee { expected: 1, got: 2, .. }))
    ));
    assert_eq!(n.tip_height(), 0, "a refused block leaves state untouched");
}

#[test]
fn the_annulet_mempool_prices_with_the_l2_table_and_refuses_what_block_validation_refuses() {
    let (n, _) = node();
    let mut pool = Mempool::new(MempoolParams::default());
    assert!(pool.admit(s_tx(&n, 1), &n, &OkProof, &EmptyNameView).is_ok(), "an S tx at the S tier");
    let mut p = s_tx(&n, 3);
    p.l2 = L2Surface {
        shape: L2ShapeTag::P,
        registry_root: root(),
        vpublic: Some([VPublicTerm::NONE, VPublicTerm { redeem: false, amount: 5, asset: 7 }]),
    }
    .encode();
    p.public.fee = 1;
    assert!(matches!(
        pool.admit(p.clone(), &n, &OkProof, &EmptyNameView),
        Err(MempoolError::WrongFee { expected: 2, got: 1 })
    ));
    p.public.fee = 2;
    assert!(pool.admit(p, &n, &OkProof, &EmptyNameView).is_ok(), "a P tx at the P tier");
    let mut none = s_tx(&n, 5);
    none.l2 = qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec();
    assert!(matches!(
        pool.admit(none, &n, &OkProof, &EmptyNameView),
        Err(MempoolError::L2SurfaceInvalid(BodyError::L2SurfaceMissing { index: 0 }))
    ));
    let mut rider = s_tx(&n, 7);
    rider.rider = vec![0x01];
    assert!(matches!(
        pool.admit(rider, &n, &OkProof, &EmptyNameView),
        Err(MempoolError::RiderInvalid(BodyError::RiderBeforeBoundary { index: 0 }))
    ));
}

/// An L1 node's pool refuses a surface-carrying tx by name.
#[test]
fn an_l1_mempool_refuses_an_l2_surface() {
    let l1 = MemNode::in_memory(qlab_node::genesis_block(8, 0));
    let (an, _) = node();
    let mut pool = Mempool::new(MempoolParams::default());
    assert!(matches!(
        pool.admit(s_tx(&an, 1), &l1, &OkProof, &EmptyNameView),
        Err(MempoolError::L2SurfaceInvalid(BodyError::L2SurfaceOnL1 { index: 0 }))
    ));
}

/// B2b (lab #708): an Annulet node on disk logs each sealed block (persist
/// variant 3) and its finalization, and a restart resumes to the same tip,
/// final = tip, the same root and the same held seals. The same datadir under
/// an L1 genesis is a foreign datadir, refused by name.
#[test]
fn an_annulet_node_on_disk_resumes_its_sealed_chain_across_a_restart() {
    let dir = std::env::temp_dir().join(format!("qlab-annulet-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SequencerKey::from_seed([0x5E; 32]);
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    let (tip, root, seal3) = {
        let mut n = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).expect("a fresh datadir opens");
        let mut parent = g;
        let mut last = None;
        for h in 1..=3u8 {
            let body = BlockBody::new(vec![s_tx(&n, h * 2)], vec![]);
            let sealed = sealed_child(&key, &parent, &body);
            n.apply_sealed_block(&sealed, body, &OkProof).expect("applies");
            parent = sealed.header;
            last = Some(sealed);
        }
        (n.chain().tip_hash(), n.commitment_root(), last.unwrap())
    };
    let n = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).expect("the datadir resumes");
    assert_eq!(n.chain().tip_hash(), tip);
    assert_eq!(n.tip_height(), 3);
    assert_eq!(n.finalized_height(), Some(3), "final = tip after replay");
    assert_eq!(n.commitment_root(), root);
    assert_eq!(n.nullifier_count(), 6);
    assert_eq!(n.annulet_fee_table(), Some(FEES));
    assert_eq!(n.chain().block(&tip).and_then(|b| b.sealed_header()), Some(seal3), "the seal survives the restart");
    // An L1 genesis over this datadir: refused by name, before hashing.
    let l1 = qlab_node::StoredBlock::from_parts(&BlockHeader::genesis(1, 0), &BlockBody::default());
    match MemNode::open_for(qlab_devnet::forms::GenesisForm::V4, &dir, l1) {
        Err(NodeError::LogFormMismatch { height: 1, .. }) => {}
        Err(e) => panic!("expected LogFormMismatch, got {e}"),
        Ok(_) => panic!("an Annulet datadir must not open under an L1 genesis"),
    }
    // And the L1 entry point refuses an Annulet form outright.
    assert!(matches!(
        MemNode::open_for(qlab_devnet::forms::GenesisForm::Annulet, &dir, qlab_node::StoredBlock::annulet_genesis(&g)),
        Err(NodeError::FormNotServed { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #708: the L2 surface is part of a transaction's pool identity (like a
/// rider, presence-conditional), so two transactions that differ only in
/// their surface are two ids, and an L1 transaction's id is unchanged.
#[test]
fn the_l2_surface_is_part_of_pool_identity() {
    let (n, _) = node();
    let s = s_tx(&n, 7);
    let p = TxEntry {
        l2: L2Surface {
            shape: L2ShapeTag::P,
            registry_root: root(),
            vpublic: Some([VPublicTerm::NONE, VPublicTerm { redeem: false, amount: 1, asset: 7 }]),
        }
        .encode(),
        ..s.clone()
    };
    assert_ne!(qlab_node::mempool::txid(&s), qlab_node::mempool::txid(&p));
    let l1 = TxEntry { l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(), ..s.clone() };
    assert_ne!(qlab_node::mempool::txid(&s), qlab_node::mempool::txid(&l1));
}

/// Lab #710 Q6: the registry is bound to the header — at genesis load and on
/// every applied block — and a mismatch is refused by name.
#[test]
fn the_registry_root_is_bound_at_genesis_load_and_on_every_block() {
    // Genesis load: a header naming another root than the registry built.
    let dir = std::env::temp_dir().join(format!("qlab-annulet-reg-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let wrong = AnnuletHeaderFields { registry_root: [0x99; 32], ..ext() };
    let g_wrong = BlockHeader::genesis_annulet(wrong, genesis_body_commitment_annulet(&[]), 0);
    match MemNode::open_annulet(&dir, g_wrong, &[], FEES, &registry()) {
        Err(NodeError::RegistryRootMismatch { height: 0, header, store }) => {
            assert_eq!(header, [0x99; 32]);
            assert_eq!(store, root());
        }
        Err(e) => panic!("expected RegistryRootMismatch at genesis, got {e}"),
        Ok(_) => panic!("a genesis naming another registry root must not open"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    // A block naming another root (sealed and otherwise valid).
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    assert_eq!(n.registry_root_bytes(), Some(root()));
    let body = BlockBody::new(vec![], vec![]);
    let sealed = key.seal(BlockHeader::child_of_annulet(&g, 10, wrong, body_commitment_annulet(&body)));
    match n.apply_sealed_block(&sealed, body, &OkProof) {
        Err(NodeError::RegistryRootMismatch { height: 1, .. }) => {}
        other => panic!("expected RegistryRootMismatch at height 1, got {other:?}"),
    }
    assert_eq!(n.tip_height(), 0, "nothing applied");
}

/// Lab #710: the registry root reproduces across restart — from the
/// `registry.bin` sidecar, from the genesis when the sidecar is gone, and from
/// the genesis when the sidecar is unreadable — and the store is immutable
/// over the blocks between (Phase 0; updates arrive with A2).
#[test]
fn the_registry_reproduces_across_restart_from_the_sidecar_and_from_genesis() {
    use qlab_node::registry_store::REGISTRY_FILE;
    let dir = std::env::temp_dir().join(format!("qlab-annulet-reg-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SequencerKey::from_seed([0x5E; 32]);
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    {
        let mut n = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
        let mut parent = g;
        for h in 1..=3u8 {
            let body = BlockBody::new(vec![s_tx(&n, h * 2)], vec![]);
            let sealed = sealed_child(&key, &parent, &body);
            n.apply_sealed_block(&sealed, body, &OkProof).unwrap();
            parent = sealed.header;
        }
        assert_eq!(n.registry_root_bytes(), Some(root()), "immutable over the blocks");
    }
    assert!(dir.join(REGISTRY_FILE).exists(), "the sidecar is written at open");
    let from_sidecar = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
    assert_eq!(from_sidecar.registry_root_bytes(), Some(root()));
    assert_eq!(from_sidecar.tip_height(), 3);
    drop(from_sidecar);
    std::fs::remove_file(dir.join(REGISTRY_FILE)).unwrap();
    let from_genesis = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
    assert_eq!(from_genesis.registry_root_bytes(), Some(root()));
    assert!(dir.join(REGISTRY_FILE).exists(), "and rewritten");
    drop(from_genesis);
    std::fs::write(dir.join(REGISTRY_FILE), b"junk").unwrap();
    let from_junk = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
    assert_eq!(from_junk.registry_root_bytes(), Some(root()), "an unreadable sidecar is rebuilt, not trusted");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Three synthetic genesis notes: commitments `[i+1; 32]`, 128-B payloads.
fn genesis_notes() -> Vec<qlab_devnet::annulet::GenesisNote> {
    (0..3u8).map(|i| qlab_devnet::annulet::GenesisNote { cm: [i + 1; 32], payload: vec![0; 128] }).collect()
}

/// The genesis anchor over [`genesis_notes`] — the depth-32 commitment tree
/// with leaves `[1;32], [2;32], [3;32]` at positions 0..3 — computed by an
/// independent Python Keccak-f[1600] (self-checked against Keccak-256("")) and
/// node fold, whose empty-tree root reproduces the existing
/// `qlab_cbserver::tree` golden `27ae5ba0…d757`. Derive-once: pinned here.
const GENESIS_ANCHOR_GOLDEN: &str = "b358f03f25ba8818ca8bcb192a971f29f023ae4d2b562d77292da2aedc622bae";

/// Lab #710 (B1 P13, ruled into B3): the genesis notes enter the commitment
/// tree at height 0, in genesis order, through the append a block's outputs
/// take. Each note's commitment sits at its genesis position, its auth path
/// (under the circuit's own fold) reaches the genesis anchor, the anchor is
/// the pinned golden, and block 1 anchors on it.
#[test]
fn the_genesis_notes_are_the_genesis_anchor() {
    use qlab_node::CommitmentStore;
    let notes = genesis_notes();
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
    let mut n = MemNode::in_memory_annulet(g, &notes, FEES, &registry());
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let anchor = n.commitment_root();
    assert_eq!(hex(&anchor), GENESIS_ANCHOR_GOLDEN);
    let tree = n.commitments().tree();
    assert_eq!(tree.len(), 3);
    for (i, note) in notes.iter().enumerate() {
        let leaf = qlab_note::hash::digest_from_bytes(&note.cm);
        assert_eq!(tree.leaf(i as u64), leaf, "note {i} at its genesis position");
        let w = tree.auth_path(i as u64, 3);
        assert_eq!(qlab_note::hash::digest_bytes(&w.fold_root(&leaf)), anchor, "note {i} folds to the anchor");
    }
    assert_eq!(n.nullifier_count(), 0, "genesis notes spend nothing");
    assert!(n.is_valid_anchor(&anchor), "the genesis anchor is a valid anchor for block 1");
    // Block 1 anchors on it and applies, appending after the genesis notes.
    let key = SequencerKey::from_seed([0x5E; 32]);
    let mut tx = s_tx(&n, 40);
    tx.public.anchor = anchor;
    let body = BlockBody::new(vec![tx], vec![]);
    let sealed = sealed_child(&key, &g, &body);
    n.apply_sealed_block(&sealed, body, &OkProof).expect("block 1 anchors on the genesis notes");
    assert_eq!(n.commitments().tree().len(), 5);
}

/// A restart — by full replay and over a snapshot — re-applies the genesis
/// notes exactly once (a snapshot's commitments begin with them).
#[test]
fn the_genesis_notes_survive_restart_exactly_once() {
    use qlab_node::CommitmentStore;
    let dir = std::env::temp_dir().join(format!("qlab-annulet-gnotes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let notes = genesis_notes();
    let key = SequencerKey::from_seed([0x5E; 32]);
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
    let root = {
        let mut n = MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap();
        let body = BlockBody::new(vec![s_tx(&n, 50)], vec![]);
        n.apply_sealed_block(&sealed_child(&key, &g, &body), body, &OkProof).unwrap();
        assert_eq!(n.commitments().tree().len(), 5);
        n.save_snapshot().unwrap();
        n.commitment_root()
    };
    let over_snapshot = MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap();
    assert_eq!(over_snapshot.commitments().tree().len(), 5, "not 8: the notes are not applied twice");
    assert_eq!(over_snapshot.commitment_root(), root);
    drop(over_snapshot);
    std::fs::remove_file(dir.join("snapshot.bin")).unwrap();
    let by_replay = MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap();
    assert_eq!(by_replay.commitments().tree().len(), 5);
    assert_eq!(by_replay.commitment_root(), root);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A P transaction carrying `terms` (mock-proved), at the P tier.
fn p_tx(n: &MemNode, nf: u8, terms: [VPublicTerm; 2]) -> TxEntry {
    let mut t = s_tx(n, nf);
    t.l2 = L2Surface { shape: L2ShapeTag::P, registry_root: root(), vpublic: Some(terms) }.encode();
    t.public.fee = FEES.tier_p;
    t
}

fn mint(amount: u64, asset: u16) -> [VPublicTerm; 2] {
    [VPublicTerm::NONE, VPublicTerm { redeem: false, amount, asset }]
}

fn redeem(amount: u64, asset: u16) -> [VPublicTerm; 2] {
    [VPublicTerm::NONE, VPublicTerm { redeem: true, amount, asset }]
}

/// Lab #712 Q2: the node keeps the running outstanding supply, records each
/// block's delta, and refuses by name a block that would take an asset below
/// zero — leaving state untouched.
#[test]
fn outstanding_supply_is_chain_state_and_never_goes_negative() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    let b1 = BlockBody::new(vec![p_tx(&n, 1, mint(100, 7))], vec![]);
    let s1 = sealed_child(&key, &g, &b1);
    n.apply_sealed_block(&s1, b1, &OkProof).unwrap();
    let b2 = BlockBody::new(vec![p_tx(&n, 3, redeem(30, 7))], vec![]);
    let s2 = sealed_child(&key, &s1.header, &b2);
    n.apply_sealed_block(&s2, b2, &OkProof).unwrap();
    assert_eq!(n.outstanding_supplies().get(&7), Some(&70));
    assert_eq!(n.supply_deltas().get(&1).and_then(|d| d.get(&7)), Some(&100));
    assert_eq!(n.supply_deltas().get(&2).and_then(|d| d.get(&7)), Some(&-30));
    let b3 = BlockBody::new(vec![p_tx(&n, 5, redeem(71, 7))], vec![]);
    let s3 = sealed_child(&key, &s2.header, &b3);
    match n.apply_sealed_block(&s3, b3, &OkProof) {
        Err(NodeError::SupplyUnderflow { height: 3, asset: 7, outstanding: 70, delta: -71 }) => {}
        other => panic!("expected SupplyUnderflow, got {other:?}"),
    }
    assert_eq!(n.tip_height(), 2, "a refused block leaves state untouched");
    assert_eq!(n.outstanding_supplies().get(&7), Some(&70));
    // A redeem of an asset never minted is refused the same way.
    let b4 = BlockBody::new(vec![p_tx(&n, 7, redeem(1, 9))], vec![]);
    let s4 = sealed_child(&key, &s2.header, &b4);
    assert!(matches!(n.apply_sealed_block(&s4, b4, &OkProof), Err(NodeError::SupplyUnderflow { asset: 9, .. })));
}

/// Recomputed, never persisted: the outstanding supply comes back after a
/// restart over a snapshot (whose prefix skips `apply_state`) and by replay.
#[test]
fn outstanding_supply_is_recomputed_across_restart() {
    let dir = std::env::temp_dir().join(format!("qlab-annulet-supply-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SequencerKey::from_seed([0x5E; 32]);
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    {
        let mut n = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
        let b1 = BlockBody::new(vec![p_tx(&n, 1, mint(100, 7))], vec![]);
        let s1 = sealed_child(&key, &g, &b1);
        n.apply_sealed_block(&s1, b1, &OkProof).unwrap();
        n.save_snapshot().unwrap();
    }
    let over_snapshot = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
    assert_eq!(over_snapshot.outstanding_supplies().get(&7), Some(&100));
    drop(over_snapshot);
    std::fs::remove_file(dir.join("snapshot.bin")).unwrap();
    let by_replay = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
    assert_eq!(by_replay.outstanding_supplies().get(&7), Some(&100));
    assert_eq!(by_replay.supply_deltas().get(&1).and_then(|d| d.get(&7)), Some(&100));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #712: the pool refuses a stale registry root, and a redeem that
/// exceeds the outstanding supply net of the redeems already pooled.
#[test]
fn the_annulet_mempool_refuses_a_stale_root_and_an_uncovered_redeem() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    let b1 = BlockBody::new(vec![p_tx(&n, 1, mint(100, 7))], vec![]);
    n.apply_sealed_block(&sealed_child(&key, &g, &b1), b1, &OkProof).unwrap();
    let mut pool = Mempool::new(MempoolParams::default());
    let mut stale = s_tx(&n, 3);
    stale.l2 = L2Surface { shape: L2ShapeTag::S, registry_root: [0x99; 32], vpublic: None }.encode();
    assert!(matches!(
        pool.admit(stale, &n, &OkProof, &EmptyNameView),
        Err(MempoolError::L2SurfaceInvalid(BodyError::L2RegistryRootStale { index: 0 }))
    ));
    assert!(pool.admit(p_tx(&n, 5, redeem(60, 7)), &n, &OkProof, &EmptyNameView).is_ok(), "60 of 100");
    assert!(matches!(
        pool.admit(p_tx(&n, 9, redeem(41, 7)), &n, &OkProof, &EmptyNameView),
        Err(MempoolError::RedeemExceedsOutstanding { asset: 7 })
    ), "60 pooled + 41 > 100");
    assert!(pool.admit(p_tx(&n, 13, redeem(40, 7)), &n, &OkProof, &EmptyNameView).is_ok(), "60 + 40 = 100");
}
