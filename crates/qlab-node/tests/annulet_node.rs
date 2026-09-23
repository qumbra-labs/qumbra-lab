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
const ROOT: Hash32 = [0x44; 32];

fn ext() -> AnnuletHeaderFields {
    AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: ROOT }
}

fn node() -> (MemNode, BlockHeader) {
    let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0);
    (MemNode::in_memory_annulet(g, &[], FEES), g)
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
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: ROOT, vpublic: None }.encode(),
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
        registry_root: ROOT,
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
        let mut n = MemNode::open_annulet(&dir, g, &[], FEES).expect("a fresh datadir opens");
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
    let n = MemNode::open_annulet(&dir, g, &[], FEES).expect("the datadir resumes");
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
