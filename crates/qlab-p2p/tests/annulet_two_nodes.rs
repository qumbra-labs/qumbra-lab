//! **B2's done-when, adapter-driven** (lab #708): a producer and a follower,
//! in process, advance 10 Annulet blocks — some carrying S transactions —
//! with the follower seeing only sealed blocks through the same ingest path
//! the producer's own blocks took. Everything is real (the seal, the header
//! rule, fork choice, final-on-acceptance, B1's body rule, mempool admission)
//! except proof verification, which is mocked **by name**: the L2 verifier is
//! B4's.

use qlab_devnet::annulet::{
    body_commitment_annulet, genesis_body_commitment_annulet, AnnuletHeaderFields, L2FeeTable,
    L2ShapeTag, L2Surface, SequencerKey,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState;
use qlab_p2p::adapter::{NodeAdapter, EQUIVOCATION_REASON, UNSEALED_ON_ANNULET_REASON};
use qlab_p2p::n1::{BlockIngest, ChainView, CheckpointIngest, IngestOutcome, VotesOutcome};

/// The mock proof verifier — accepted for B2 by the #708 ruling; B4 replaces it.
#[derive(Clone)]
struct MockProofVerifier;
impl TxVerifier for MockProofVerifier {
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

fn genesis() -> BlockHeader {
    BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&[]), 0)
}

fn adapter(key: &SequencerKey) -> NodeAdapter<KeccakPow, MockProofVerifier> {
    NodeAdapter::annulet(genesis(), &[], FEES, &registry(), key.verifying_key(), KeccakPow, MockProofVerifier, SimConfig::default())
}

fn s_tx(anchor: Hash32, nf: u8) -> TxEntry {
    let mut t = TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32]],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: FEES.tier_s,
        },
        discovery: Vec::new(),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: root(), vpublic: None, write: None }.encode(),
    };
    t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
    t
}

#[test]
fn a_producer_and_a_follower_advance_ten_sealed_blocks_in_lockstep() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let mut producer = adapter(&key);
    let mut follower = adapter(&key);
    let mut carried = 0;
    for h in 1..=10u64 {
        if h % 3 == 1 {
            // Two S transactions into the producer's pool, anchored at its
            // current (final) root.
            let root = producer.state().commitment_root();
            for k in 0..2u8 {
                producer.submit_tx_typed(s_tx(root, (h as u8) * 8 + k)).expect("admitted at the S tier");
            }
        }
        let (sealed, body) = producer.seal_next_block(&key, 10 * h).expect("the producer seals");
        carried += body.txs.len();
        assert_eq!(follower.ingest_sealed_block(&sealed, body), IngestOutcome::Accepted, "height {h}");
        assert_eq!(producer.chain().tip_hash(), follower.chain().tip_hash(), "height {h}");
    }
    assert_eq!(carried, 8, "four blocks carried two S transactions each");
    for a in [&producer, &follower] {
        assert_eq!(a.state().tip_height(), 10);
        assert_eq!(a.state().finalized_height(), Some(10), "final on acceptance");
        assert_eq!(a.chain().tip_work(), 10, "weight 1 per block — no tie is possible");
    }
    assert_eq!(producer.state().commitment_root(), follower.state().commitment_root());
    assert_eq!(producer.state().nullifier_count(), 16);
    assert_eq!(follower.state().nullifier_count(), 16);
    assert_eq!(producer.sealed_header_at(10), follower.sealed_header_at(10), "both serve the same sealed header");
}

/// The finality-consumer trace (lab #708): the view every telemetry surface
/// reads says final = tip on Annulet (the committee tracker is never fed
/// there), and the committee paths — checkpoint votes, checkpoint fast-sync
/// — are refused by name rather than reaching an empty-committee tally.
#[test]
fn the_finality_view_is_the_tip_and_the_committee_paths_are_closed() {
    use qlab_devnet::committee::Checkpoint;
    let key = SequencerKey::from_seed([0x5E; 32]);
    let mut a = adapter(&key);
    assert_eq!(ChainView::finalized_height(&a), Some(0), "genesis is final");
    let mut last = None;
    for h in 1..=3u64 {
        last = Some(a.seal_next_block(&key, 10 * h).expect("the producer seals"));
        assert_eq!(ChainView::finalized_height(&a), Some(h), "final on acceptance, through the ChainView");
    }
    assert!(a.finality().finalized_height().is_none(), "the committee tracker stays untouched");
    let (sealed, _) = last.unwrap();
    let cp = Checkpoint { height: 3, block_hash: sealed.id(), root: a.state().commitment_root() };
    assert!(matches!(a.ingest_checkpoint_votes_from(&cp, &[], true), VotesOutcome::Stale));
    assert_eq!(a.finalized_checkpoint(), None);
    assert_eq!(
        a.ingest_finalized_headers(&[sealed.header]),
        IngestOutcome::Ignored(UNSEALED_ON_ANNULET_REASON)
    );
}

#[test]
fn equivocation_forged_seals_and_unsealed_headers_are_refused_by_name() {
    let key = SequencerKey::from_seed([0x5E; 32]);
    let mut producer = adapter(&key);
    let mut follower = adapter(&key);
    let (s1, b1) = producer.seal_next_block(&key, 10).unwrap();
    assert_eq!(follower.ingest_sealed_block(&s1, b1), IngestOutcome::Accepted);

    // The same signer, a second block at height 1: equivocation, refused and
    // kept as evidence.
    let alt_body = BlockBody::new(vec![], vec![]);
    let mut alt = BlockHeader::child_of_annulet(&genesis(), 11, ext(), body_commitment_annulet(&alt_body));
    alt.timestamp = 11; // a different header, same height, validly sealed
    let alt = key.seal(alt);
    assert_eq!(follower.ingest_sealed_block(&alt, alt_body), IngestOutcome::Rejected(EQUIVOCATION_REASON));
    assert_eq!(follower.equivocations().len(), 1);
    assert_eq!(follower.equivocations()[0].0, 1);
    assert_eq!(follower.chain().tip_hash(), s1.id(), "the first block stays");

    // A header sealed by another key.
    let other = SequencerKey::from_seed([0x5F; 32]);
    let forged = other.seal(BlockHeader::child_of_annulet(&s1.header, 20, ext(), body_commitment_annulet(&BlockBody::default())));
    assert_eq!(
        follower.ingest_sealed_block(&forged, BlockBody::default()),
        IngestOutcome::Rejected("invalid header: bad sequencer seal")
    );

    // An unsealed header on a sequencer net: unjudgeable, not the sender's fault.
    assert_eq!(follower.ingest_header(forged.header), IngestOutcome::Ignored(UNSEALED_ON_ANNULET_REASON));
    assert_eq!(follower.ingest_block(forged.header, BlockBody::default()), IngestOutcome::Ignored(UNSEALED_ON_ANNULET_REASON));

    // The producer refuses to seal with a key the genesis does not pin.
    assert!(producer.seal_next_block(&other, 30).is_err());
}
