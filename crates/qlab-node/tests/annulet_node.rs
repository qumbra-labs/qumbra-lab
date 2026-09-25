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

const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2, tier_r: 4 };
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
    let mut t = TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor: node.commitment_root(),
            // S/P spend three (A4): slot 3's fee-input nullifier is never a
            // uniform `[x; 32]`, so it cannot collide with another fixture's.
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32], {
                let mut f = [nf; 32];
                f[31] = !nf;
                f
            }],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1,
        },
        discovery: Vec::new(),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: root(), vpublic: None, write: None }.encode(),
    };
    t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
    t
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
    assert_eq!(n.nullifier_count(), 9, "three S spends × three nullifiers (A4)");
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
        write: None,
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
    assert_eq!(n.nullifier_count(), 9, "three S spends × three nullifiers (A4)");
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
            write: None,
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

/// Three genesis notes — real genesis plaintexts (lab #728 Q7: the node
/// seeds its outstanding supply from them, so a note that does not open is
/// refused): fee-unit notes of 1 and 2, and 500 of asset 7.
fn genesis_notes() -> Vec<qlab_devnet::annulet::GenesisNote> {
    use qlab_note::l2note::{GenesisPlaintext, L2Note};
    let note = |value: u64, asset: u64, i: u64| L2Note { value, asset, rkm: [i; 4], rho: [i, 1, 2, 3], rseed: [i, 4, 5, 6] };
    [note(1, 0, 1), note(2, 0, 2), note(500, 7, 3)]
        .iter()
        .map(|n| qlab_devnet::annulet::GenesisNote {
            cm: qlab_note::hash::digest_bytes(&n.commitment()),
            payload: GenesisPlaintext::of(n).0.to_vec(),
        })
        .collect()
}

/// The depth-32 commitment tree with leaves `[1;32], [2;32], [3;32]` at
/// positions 0..3 — computed by an
/// independent Python Keccak-f[1600] (self-checked against Keccak-256("")) and
/// node fold, whose empty-tree root reproduces the existing
/// `qlab_cbserver::tree` golden `27ae5ba0…d757`. Derive-once: pinned here.
const GENESIS_ANCHOR_GOLDEN: &str = "b358f03f25ba8818ca8bcb192a971f29f023ae4d2b562d77292da2aedc622bae";

/// Lab #710 (B1 P13, ruled into B3): the genesis notes enter the commitment
/// tree at height 0, in genesis order, through the append a block's outputs
/// take. Each note's commitment sits at its genesis position, its auth path
/// (under the circuit's own fold) reaches the genesis anchor, the anchor is
/// the tree over the notes' commitments in genesis order, and block 1
/// anchors on it. The fold itself is pinned to the independent golden over
/// fixed leaves (lab #728 moved the golden off the node: the fixture notes
/// are real plaintexts now, so their commitments are no longer `[i+1; 32]`).
#[test]
fn the_genesis_notes_are_the_genesis_anchor() {
    use qlab_node::CommitmentStore;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let over = |cms: &[Hash32]| {
        let mut t = qlab_node::MemCommitmentStore::default();
        for cm in cms {
            t.append(*cm);
        }
        t.root_bytes()
    };
    assert_eq!(hex(&over(&[[1; 32], [2; 32], [3; 32]])), GENESIS_ANCHOR_GOLDEN);
    let notes = genesis_notes();
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
    let mut n = MemNode::in_memory_annulet(g, &notes, FEES, &registry());
    let anchor = n.commitment_root();
    assert_eq!(anchor, over(&notes.iter().map(|x| x.cm).collect::<Vec<_>>()), "the tree over the notes, in order");
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
    t.l2 = L2Surface { shape: L2ShapeTag::P, registry_root: root(), vpublic: Some(terms), write: None }.encode();
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
    stale.l2 = L2Surface { shape: L2ShapeTag::S, registry_root: [0x99; 32], vpublic: None, write: None }.encode();
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

// ---------------------------------------------------------------------------
// Lab #728 (B3b): registry writes are chain state; genesis supply is
// outstanding from height 0.
// ---------------------------------------------------------------------------

/// Registering asset 9 (Hybrid, an issuer key): the leaf's 15 lanes, and the
/// registry root after writing it over [`registry`].
fn write_9() -> ([u64; 15], Hash32) {
    use qlab_node::registry_store::{MemRegistryStore, RegistryLeaf, RegistryStore as _};
    let mut leaf = RegistryLeaf::cloaked(9);
    leaf.mode = 1;
    leaf.issuer_key = [1, 2, 3, 4];
    let lanes: [u64; 15] = leaf.state()[..15].try_into().unwrap();
    let mut s = MemRegistryStore::from_genesis(&registry()).unwrap();
    s.apply_write(&lanes).unwrap();
    (lanes, s.root_bytes())
}

/// An R transaction (mock-proved): one in, two out (the fee change and A3's
/// seed), at the R tier, proven against `old_root`, declaring `new_root` and
/// the leaf.
fn r_tx(n: &MemNode, nf: u8, old_root: Hash32, new_root: Hash32, leaf_lanes: [u64; 15]) -> TxEntry {
    let mut t = s_tx(n, nf);
    t.public.nullifiers.truncate(1);
    t.public.fee = FEES.tier_r;
    t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
    t.l2 = L2Surface {
        shape: L2ShapeTag::R,
        registry_root: old_root,
        vpublic: None,
        write: Some(qlab_devnet::annulet::RegistryWriteSurface { new_root, leaf_lanes }),
    }
    .encode();
    t
}

/// An S transaction bound to `at` rather than the genesis root.
fn s_tx_at(n: &MemNode, nf: u8, at: Hash32) -> TxEntry {
    let mut t = s_tx(n, nf);
    t.l2 = L2Surface { shape: L2ShapeTag::S, registry_root: at, vpublic: None, write: None }.encode();
    t
}

/// A sealed child whose header carries `registry_root`.
fn sealed_child_at(
    key: &SequencerKey,
    parent: &BlockHeader,
    body: &BlockBody,
    registry_root: Hash32,
) -> qlab_devnet::annulet::SealedHeader {
    let ext = AnnuletHeaderFields { registry_root, ..ext() };
    key.seal(BlockHeader::child_of_annulet(parent, parent.timestamp + 10, ext, body_commitment_annulet(body)))
}

/// Lab #728: a block's registry write moves the node's registry to the
/// root the write declares, the header carries it, the block's other
/// surfaces bind the root before it, and every later block binds the new one
/// — a surface still naming the old root is stale.
#[test]
fn a_registry_write_moves_the_root_and_later_blocks_bind_it() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    let (lanes, new) = write_9();
    assert_ne!(new, root());
    let b1 = BlockBody::new(vec![r_tx(&n, 1, root(), new, lanes), s_tx(&n, 3)], vec![]);
    let s1 = sealed_child_at(&key, &g, &b1, new);
    n.apply_sealed_block(&s1, b1, &OkProof).expect("the write and a sibling bound to the parent's root");
    assert_eq!(n.registry_root_bytes(), Some(new), "the registry moved");
    // A surface still naming the old root is stale now.
    let stale = BlockBody::new(vec![s_tx(&n, 5)], vec![]);
    let s_stale = sealed_child_at(&key, &s1.header, &stale, new);
    assert!(matches!(
        n.apply_sealed_block(&s_stale, stale, &OkProof),
        Err(NodeError::Body(BodyError::L2RegistryRootStale { index: 0 }))
    ));
    // A header still naming the old root is refused as a root mismatch.
    let old_hdr = BlockBody::new(vec![], vec![]);
    let s_old = sealed_child_at(&key, &s1.header, &old_hdr, root());
    assert!(matches!(n.apply_sealed_block(&s_old, old_hdr, &OkProof), Err(NodeError::RegistryRootMismatch { height: 2, .. })));
    // The next block binds the new root.
    let b2 = BlockBody::new(vec![s_tx_at(&n, 7, new)], vec![]);
    let s2 = sealed_child_at(&key, &s1.header, &b2, new);
    n.apply_sealed_block(&s2, b2, &OkProof).expect("binds the new root");
    assert_eq!(n.tip_height(), 2);
}

/// Lab #728: each way a registry write can be wrong is refused by name —
/// proven on another root, a declared root its leaf does not reach, a write
/// to asset 0's pinned slot — and leaves the node's state untouched.
#[test]
fn a_bad_registry_write_is_refused_by_name_and_leaves_state_untouched() {
    use qlab_node::registry_store::{RegistryError, RegistryLeaf};
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (mut n, g) = node();
    let (lanes, new) = write_9();
    // Proven against a root that is not this node's.
    let b = BlockBody::new(vec![r_tx(&n, 1, [0x44; 32], new, lanes)], vec![]);
    match n.apply_sealed_block(&sealed_child_at(&key, &g, &b, new), b, &OkProof) {
        Err(NodeError::RegistryWriteNotOnParent { height: 1, surface, store }) => {
            assert_eq!((surface, store), ([0x44; 32], root()));
        }
        other => panic!("expected RegistryWriteNotOnParent, got {other:?}"),
    }
    // Declares a root the leaf does not reach (the header agrees with the
    // declaration, so the body rule passes it and the node must not).
    let b = BlockBody::new(vec![r_tx(&n, 1, root(), [0x55; 32], lanes)], vec![]);
    match n.apply_sealed_block(&sealed_child_at(&key, &g, &b, [0x55; 32]), b, &OkProof) {
        Err(NodeError::RegistryWriteRootMismatch { height: 1, surface, rebuilt }) => {
            assert_eq!((surface, rebuilt), ([0x55; 32], new));
        }
        other => panic!("expected RegistryWriteRootMismatch, got {other:?}"),
    }
    // Asset 0's slot is pinned.
    let mut zero = RegistryLeaf::cloaked(0);
    zero.flags = 1;
    let zero_lanes: [u64; 15] = zero.state()[..15].try_into().unwrap();
    let b = BlockBody::new(vec![r_tx(&n, 1, root(), [0x66; 32], zero_lanes)], vec![]);
    match n.apply_sealed_block(&sealed_child_at(&key, &g, &b, [0x66; 32]), b, &OkProof) {
        Err(NodeError::RegistryWrite { height: 1, err: RegistryError::AssetZeroNotWritable }) => {}
        other => panic!("expected RegistryWrite(AssetZeroNotWritable), got {other:?}"),
    }
    assert_eq!(n.tip_height(), 0, "nothing applied");
    assert_eq!(n.registry_root_bytes(), Some(root()), "the registry did not move");
    assert_eq!(n.nullifier_count(), 0);
}

/// Lab #728 (the coordinator's addition to the stage-0 ruling): the registry
/// is derived from the chain on every resume path, never trusted from the
/// sidecar. A snapshot whose prefix holds the write resumes onto the written
/// registry and replays its tail against it; with the sidecar deleted, or
/// replaced by a stale one, and by full replay, the node reaches the same
/// root — and the rewritten sidecar holds it.
#[test]
fn the_registry_is_rederived_with_the_sidecar_deleted_and_by_replay() {
    use qlab_node::registry_store::{load_registry_at, save_registry, MemRegistryStore, RegistryStore as _, REGISTRY_FILE};
    let dir = std::env::temp_dir().join(format!("qlab-annulet-reg-write-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SequencerKey::from_seed([0x5E; 32]);
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    let (lanes, new) = write_9();
    {
        let mut n = MemNode::open_annulet(&dir, g, &[], FEES, &registry()).unwrap();
        let b1 = BlockBody::new(vec![r_tx(&n, 1, root(), new, lanes)], vec![]);
        let s1 = sealed_child_at(&key, &g, &b1, new);
        n.apply_sealed_block(&s1, b1, &OkProof).unwrap();
        // The snapshot's prefix holds the write; the tail binds its root.
        n.save_snapshot().unwrap();
        let b2 = BlockBody::new(vec![s_tx_at(&n, 3, new)], vec![]);
        n.apply_sealed_block(&sealed_child_at(&key, &s1.header, &b2, new), b2, &OkProof).unwrap();
    }
    let reopen = || MemNode::open_annulet(&dir, g, &[], FEES, &registry()).expect("reopens");
    let sidecar_root = || load_registry_at(&dir).unwrap().expect("a sidecar").0.root_bytes();
    // Over the snapshot, tail replayed against the written registry.
    let over_snapshot = reopen();
    assert_eq!((over_snapshot.tip_height(), over_snapshot.registry_root_bytes()), (2, Some(new)));
    assert_eq!(sidecar_root(), new);
    drop(over_snapshot);
    // The sidecar deleted: re-derived, and rewritten.
    std::fs::remove_file(dir.join(REGISTRY_FILE)).unwrap();
    let no_sidecar = reopen();
    assert_eq!(no_sidecar.registry_root_bytes(), Some(new));
    assert_eq!(sidecar_root(), new, "rewritten from the chain");
    drop(no_sidecar);
    // A stale sidecar (the genesis registry) is not trusted.
    save_registry(&dir, &MemRegistryStore::from_genesis(&registry()).unwrap(), 2).unwrap();
    let stale_sidecar = reopen();
    assert_eq!(stale_sidecar.registry_root_bytes(), Some(new), "a stale sidecar is replaced, not trusted");
    assert_eq!(sidecar_root(), new);
    drop(stale_sidecar);
    // By full replay, the sidecar deleted too.
    std::fs::remove_file(dir.join("snapshot.bin")).unwrap();
    std::fs::remove_file(dir.join(REGISTRY_FILE)).unwrap();
    let by_replay = reopen();
    assert_eq!((by_replay.tip_height(), by_replay.registry_root_bytes()), (2, Some(new)));
    assert_eq!(sidecar_root(), new);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #728 Q7: the genesis notes' issuance is outstanding from height 0 —
/// redeeming genesis supply is not an underflow, and redeeming past genesis
/// plus minted is. It survives a restart over a snapshot and by replay.
#[test]
fn genesis_issuance_is_outstanding_from_height_0() {
    let dir = std::env::temp_dir().join(format!("qlab-annulet-gsupply-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SequencerKey::from_seed([0x5E; 32]);
    let notes = genesis_notes();
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
    let expected = |n: &MemNode, seven: i128| {
        assert_eq!(n.outstanding_supplies(), &std::collections::BTreeMap::from([(0u16, 3i128), (7, seven)]));
    };
    {
        let mut n = MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap();
        expected(&n, 500);
        let b1 = BlockBody::new(vec![p_tx(&n, 1, mint(10, 7))], vec![]);
        let s1 = sealed_child(&key, &g, &b1);
        n.apply_sealed_block(&s1, b1, &OkProof).unwrap();
        let b2 = BlockBody::new(vec![p_tx(&n, 3, redeem(505, 7))], vec![]);
        let s2 = sealed_child(&key, &s1.header, &b2);
        n.apply_sealed_block(&s2, b2, &OkProof).expect("genesis supply is redeemable");
        expected(&n, 5);
        let b3 = BlockBody::new(vec![p_tx(&n, 5, redeem(6, 7))], vec![]);
        match n.apply_sealed_block(&sealed_child(&key, &s2.header, &b3), b3, &OkProof) {
            Err(NodeError::SupplyUnderflow { height: 3, asset: 7, outstanding: 5, delta: -6 }) => {}
            other => panic!("expected SupplyUnderflow past genesis + minted, got {other:?}"),
        }
        n.save_snapshot().unwrap();
    }
    expected(&MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap(), 5);
    std::fs::remove_file(dir.join("snapshot.bin")).unwrap();
    expected(&MemNode::open_annulet(&dir, g, &notes, FEES, &registry()).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #728 Q7: a genesis note whose payload is not a genesis plaintext, or
/// does not open its commitment, is refused by name — the node cannot state
/// its genesis supply.
#[test]
fn a_genesis_that_cannot_state_its_issuance_does_not_open() {
    let dir = std::env::temp_dir().join(format!("qlab-annulet-gsupply-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut notes = genesis_notes();
    notes[1].cm[0] ^= 1;
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
    match MemNode::open_annulet(&dir, g, &notes, FEES, &registry()) {
        Err(NodeError::GenesisIssuance(e)) => assert!(e.contains("genesis note 1"), "{e}"),
        Err(e) => panic!("expected GenesisIssuance, got {e}"),
        Ok(_) => panic!("a genesis note that does not open must not open the node"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #728: the pool admits one registry write (at the R arity, and only
/// one the block rule applies), refuses a second by name, and once the write lands evicts every pooled surface
/// still bound to the root it moved.
#[test]
fn the_pool_holds_one_registry_write_and_evicts_the_old_root_after_it() {
    let (mut n, g) = node();
    let key = SequencerKey::from_seed([0x5E; 32]);
    let (lanes, new) = write_9();
    let mut pool = Mempool::new(MempoolParams::default());
    let mut wide = r_tx(&n, 9, root(), new, lanes);
    wide.public.nullifiers.push([0xA9; 32]);
    assert!(matches!(
        pool.admit(wide, &n, &OkProof, &EmptyNameView),
        Err(MempoolError::L2SurfaceInvalid(BodyError::L2RegistryWriteArity { index: 0 }))
    ));
    // A write whose leaf does not reach its declared root would fail the
    // producer's own block forever: refused at the door, not pooled.
    assert!(matches!(
        pool.admit(r_tx(&n, 11, root(), [0x55; 32], lanes), &n, &OkProof, &EmptyNameView),
        Err(MempoolError::RegistryWriteInvalid)
    ));
    let write = r_tx(&n, 1, root(), new, lanes);
    pool.admit(write.clone(), &n, &OkProof, &EmptyNameView).expect("one write");
    pool.admit(s_tx(&n, 3), &n, &OkProof, &EmptyNameView).expect("an S tx on the same root");
    assert!(matches!(
        pool.admit(r_tx(&n, 5, root(), new, lanes), &n, &OkProof, &EmptyNameView),
        Err(MempoolError::RegistryWriteAlreadyPooled)
    ));
    let body = BlockBody::new(vec![write], vec![]);
    n.apply_sealed_block(&sealed_child_at(&key, &g, &body, new), body.clone(), &OkProof).unwrap();
    pool.on_block_connected(&body, &n, &EmptyNameView);
    assert!(pool.is_empty(), "the write was mined; the S tx binds the old root and can never be");
    pool.admit(s_tx_at(&n, 7, new), &n, &OkProof, &EmptyNameView).expect("the new root admits");
}
