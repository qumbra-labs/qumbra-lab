//! Lab #896 seam E2, end to end on a Candidate A net: the producer seals
//! auth-carrying transactions under the v2 body commitment, a follower
//! reconstructs the block by compact relay (one prefilled, one fetched by
//! `BlockTxn`) and applies it, and a disk-backed producer logs the block as
//! persist variant 5 and replays it through the stored-binding check under
//! its axis. Proof verification is mocked by name, as in `annulet_wire.rs`;
//! the auth section is opaque bytes until seam F.

use qlab_devnet::annulet::{
    body_commitment_annulet, body_commitment_annulet_for, genesis_body_commitment_annulet_for,
    AnnuletHeaderFields, L2FeeTable, L2ShapeTag, L2Surface, SequencerKey, L2_AUTH_ABSENT,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::ChainStore as _;
use qlab_node::NodeState;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{canonical_tx_wire, tx_id};
use qlab_p2p::compact::{
    decode_announce_for, decode_block_txn_for, decode_block_txn_for_wire, encode_announce_for,
    encode_block_txn_for, reconstruct, short_id, BlockAnnounce, BlockTxn, PrefilledTx, Reconstruct,
    WireForm,
};
use qlab_p2p::n1::IngestOutcome;

#[derive(Clone)]
struct MockProofVerifier;
impl TxVerifier for MockProofVerifier {
    fn verify_tx(&self, e: &TxEntry) -> bool {
        e.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MockProofVerifier>;

const FEES: L2FeeTable = L2FeeTable {
    tier_s: 1,
    tier_p: 2,
    tier_r: 4,
};
const AXIS: L2AuthForm = L2AuthForm::CandidateA;

fn registry() -> Vec<qlab_node::registry_store::RegistryLeaf> {
    vec![qlab_node::registry_store::RegistryLeaf::cloaked(0)]
}

fn root() -> Hash32 {
    use qlab_node::registry_store::RegistryStore as _;
    qlab_node::registry_store::MemRegistryStore::from_genesis(&registry())
        .unwrap()
        .root_bytes()
}

fn genesis() -> BlockHeader {
    let ext = AnnuletHeaderFields {
        l1_anchor_height: 0,
        l1_anchor_root: [0; 32],
        registry_root: root(),
    };
    BlockHeader::genesis_annulet(ext, genesis_body_commitment_annulet_for(&[], AXIS), 0)
}

fn key() -> SequencerKey {
    SequencerKey::from_seed([0x5E; 32])
}

fn in_memory() -> Adapter {
    NodeAdapter::annulet_with_auth(
        genesis(),
        &[],
        FEES,
        &registry(),
        key().verifying_key(),
        KeccakPow,
        MockProofVerifier,
        SimConfig::default(),
        AXIS,
    )
}

fn on_disk(dir: &std::path::Path) -> Adapter {
    NodeAdapter::open_annulet_with_auth(
        dir,
        genesis(),
        &[],
        FEES,
        &registry(),
        key().verifying_key(),
        KeccakPow,
        MockProofVerifier,
        SimConfig::default(),
        AXIS,
    )
    .expect("the datadir opens")
}

/// An S transaction carrying an opaque auth section (`0xA0 + nf`, 60 B).
fn signed_tx(anchor: Hash32, nf: u8) -> TxEntry {
    let mut t = TxEntry {
        auth: vec![0xA0u8.wrapping_add(nf); 60],
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32], {
                let mut f = [nf; 32];
                f[31] = !nf;
                f
            }],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: FEES.tier_s,
        },
        discovery: Vec::new(),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface {
            shape: L2ShapeTag::S,
            registry_root: root(),
            vpublic: None,
            write: None,
            exit_rkm: [0; 32],
        }
        .encode(),
    };
    t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
    t
}

fn wires(txs: &[TxEntry]) -> Vec<Vec<u8>> {
    txs.iter().map(canonical_tx_wire).collect()
}

/// The producer seals two signed transactions; the block commits them under
/// the v2 domain (and not v1's).
fn produce(producer: &mut Adapter) -> (qlab_devnet::annulet::SealedHeader, BlockBody) {
    let anchor = producer.state().commitment_root();
    for nf in [8u8, 9] {
        producer
            .submit_tx_typed(signed_tx(anchor, nf))
            .expect("the producer admits a signed S tx");
    }
    let (sealed, body) = producer
        .seal_next_block(&key(), 10)
        .expect("the producer seals");
    assert_eq!(body.txs.len(), 2);
    assert!(
        body.txs.iter().all(|t| t.auth != L2_AUTH_ABSENT),
        "the auth sections reach the body"
    );
    assert_eq!(
        sealed.header.tx_body_commitment,
        body_commitment_annulet_for(&body, AXIS)
    );
    assert_ne!(
        sealed.header.tx_body_commitment,
        body_commitment_annulet(&body)
    );
    (sealed, body)
}

#[test]
fn a_v2_block_crosses_compact_relay_and_reconstructs_byte_equal() {
    let mut producer = in_memory();
    let (sealed, body) = produce(&mut producer);
    let wf = WireForm::ANNULET_AUTH;

    // Announce: tx 0 prefilled (auth on the wire), tx 1 by short id.
    let nonce = 0xC0FF_EE01;
    let ann = BlockAnnounce {
        header: sealed.header,
        nonce,
        coinbase_payees: Vec::new(),
        short_ids: vec![short_id(nonce, &tx_id(&body.txs[1]))],
        prefilled: vec![PrefilledTx {
            index: 0,
            tx: body.txs[0].clone(),
        }],
        seal: Some(sealed.sig.clone()),
        finality: Vec::new(),
        bundle: Vec::new(),
    };
    let bytes = encode_announce_for(wf, &ann).expect("a Candidate A announce encodes");
    let got = decode_announce_for(wf, &bytes).expect("and decodes under its own form");
    assert_eq!(
        wires(&[got.prefilled[0].tx.clone()]),
        wires(&[body.txs[0].clone()])
    );
    // A v1 Annulet reader refuses the prefilled auth tail.
    assert!(decode_announce_for(WireForm::plain(GenesisForm::Annulet), &bytes).is_err());

    // The follower's pool holds only tx 1's auth-stripped twin: its short id
    // covers auth, so the twin does not fill the slot.
    let twin = TxEntry {
        auth: L2_AUTH_ABSENT.to_vec(),
        ..body.txs[1].clone()
    };
    let missing = match reconstruct(&got, &[twin]) {
        Reconstruct::Missing(m) => m,
        Reconstruct::Complete(_) => panic!("an unsigned twin must not reconstruct a signed slot"),
    };
    assert_eq!(missing, vec![1]);

    // Fetched by BlockTxn on the Candidate A tx wire.
    let bt = BlockTxn {
        block_hash: sealed.id(),
        txs: vec![body.txs[1].clone()],
    };
    let bt_bytes = encode_block_txn_for(GenesisForm::Annulet, &bt);
    assert!(
        decode_block_txn_for(GenesisForm::Annulet, &bt_bytes).is_err(),
        "a v1 reader refuses the auth tail"
    );
    let fetched = decode_block_txn_for_wire(wf, &bt_bytes).expect("the v2 reader takes it");
    let txs = match reconstruct(&got, &fetched.txs) {
        Reconstruct::Complete(txs) => txs,
        Reconstruct::Missing(m) => panic!("still missing {m:?}"),
    };
    assert_eq!(
        wires(&txs),
        wires(&body.txs),
        "reconstruction is byte-equal"
    );
    let rebuilt = BlockBody {
        txs: txs.clone(),
        ..BlockBody::default()
    };
    assert_eq!(
        body_commitment_annulet_for(&rebuilt, AXIS),
        sealed.header.tx_body_commitment
    );

    // And a follower on the same axis applies the reconstructed block.
    let mut follower = in_memory();
    assert_eq!(
        follower.ingest_sealed_block(&sealed, rebuilt),
        IngestOutcome::Accepted
    );
    assert_eq!(follower.state().tip_height(), 1);
    assert_eq!(follower.state().chain().tip_hash(), sealed.id());
}

#[test]
fn a_v2_block_persists_as_variant_5_and_replays_under_the_axis() {
    let dir = std::env::temp_dir().join(format!("qlab-i896-e2-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (sealed, body) = {
        let mut producer = on_disk(&dir);
        produce(&mut producer)
    };

    // The first log record is the block, written as variant 5.
    let log = std::fs::read(dir.join(qlab_node::BLOCK_LOG)).expect("the block log exists");
    assert!(log.len() > 8);
    assert_eq!(
        &log[4..8],
        &5u32.to_le_bytes(),
        "an auth-carrying block is persist variant 5"
    );

    // A restart replays it: the stored-binding check recomputes the v2
    // commitment over the stored auth sections (a v1 recomputation would
    // refuse the block as BodyCommitmentMismatch).
    let reopened = on_disk(&dir);
    assert_eq!(reopened.l2_auth_form(), AXIS);
    assert_eq!(reopened.state().tip_height(), 1);
    let tip = reopened.state().chain().tip_hash();
    assert_eq!(tip, sealed.id());
    let stored = reopened
        .state()
        .chain()
        .block(&tip)
        .expect("the tip block is held")
        .body();
    assert_eq!(
        wires(&stored.txs),
        wires(&body.txs),
        "the auth sections survive the restart"
    );
    assert_eq!(
        body_commitment_annulet_for(&stored, AXIS),
        sealed.header.tx_body_commitment
    );
    let _ = std::fs::remove_dir_all(&dir);
}
