//! Lab #896 seam E2, end to end on a Candidate A net: the producer seals
//! auth-carrying transactions under the v2 body commitment, a follower
//! reconstructs the block by compact relay (one prefilled, one fetched by
//! `BlockTxn`) and applies it, and a disk-backed producer logs the block as
//! persist variant 5 and replays it through the stored-binding check under
//! its axis. Proof verification is mocked by name, as in `annulet_wire.rs`;
//! since seam F the auth sections are real: each slot signed by an ephemeral
//! ML-DSA-44 key over the intent the node rebuilds, under the test genesis
//! hash `GENESIS_HASH`.

use qlab_devnet::annulet::{
    body_commitment_annulet, body_commitment_annulet_for, check_auth,
    genesis_body_commitment_annulet_for, intent_for, validate_body_annulet_for,
    AnnuletHeaderFields, AuthContext, AuthRefusal, L2FeeTable, L2ShapeTag, L2Surface, SequencerKey,
    L2_AUTH_ABSENT, MAX_AUTH_VALIDITY_BLOCKS,
};
use qlab_devnet::body::{BlockBody, BodyError, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::ChainStore as _;
use qlab_node::{MempoolError, NodeState};
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::adapter::{TxSubmitRefusal, AUTH_WINDOW_REASON};
use qlab_p2p::codec::{canonical_tx_wire, tx_id};
use qlab_p2p::compact::{
    decode_announce_for, decode_block_txn_for, decode_block_txn_for_wire, encode_announce_for,
    encode_block_txn_for, reconstruct, short_id, BlockAnnounce, BlockTxn, PrefilledTx, Reconstruct,
    WireForm,
};
use qlab_p2p::n1::IngestOutcome;
use qlab_p2p::n1::TxPool as _;
use qlab_remote_auth::annulet::AuthError;

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
/// The genesis file hash the test net's intents bind (lab #896 F).
const GENESIS_HASH: Hash32 = [0x6E; 32];
/// The last height the test transactions may land at.
const VALID_UNTIL: u64 = 100;

fn ctx() -> AuthContext {
    AuthContext::candidate_a(GENESIS_HASH)
}

/// Sign `t`'s intent with one ephemeral ML-DSA-44 key per slot (seed `seed +
/// slot`) and attach the section. The proof is mocked, so no PV binds the
/// leaves; `check_auth` still verifies every signature.
fn authorize(t: TxEntry, seed: u8) -> TxEntry {
    authorize_until(t, seed, VALID_UNTIL)
}

/// [`authorize`] with `valid_until` in the intent and the section header.
fn authorize_until(mut t: TxEntry, seed: u8, valid_until: u64) -> TxEntry {
    use qlab_remote_auth::annulet::AnnuletAuthSection;
    use qlab_remote_auth::mldsa::Key;
    let keys: Vec<Key> = (0..3u8)
        .map(|i| Key::from_seed([seed.wrapping_add(i); 32]))
        .collect();
    let descriptors: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| k.descriptor(i as u32))
        .collect();
    let intent = intent_for(
        &t,
        ctx().genesis_format(),
        &GENESIS_HASH,
        valid_until,
        &descriptors,
    )
    .expect("the intent rebuilds");
    let refs: Vec<&Key> = keys.iter().collect();
    t.auth = AnnuletAuthSection::sign(&intent, &refs)
        .and_then(|s| s.encode())
        .expect("the section signs and encodes");
    t
}

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
        ctx(),
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
        ctx(),
    )
    .expect("the datadir opens")
}

/// An S transaction carrying a real auth section (keys seeded from `nf`).
fn signed_tx(anchor: Hash32, nf: u8) -> TxEntry {
    let t = unsigned_tx(anchor, nf);
    authorize(t, nf.wrapping_mul(16))
}

/// [`signed_tx`] valid until `valid_until`.
fn signed_tx_until(anchor: Hash32, nf: u8, valid_until: u64) -> TxEntry {
    authorize_until(unsigned_tx(anchor, nf), nf.wrapping_mul(16), valid_until)
}

/// The S transaction before its auth section is attached.
fn unsigned_tx(anchor: Hash32, nf: u8) -> TxEntry {
    let mut t = TxEntry {
        auth: L2_AUTH_ABSENT.to_vec(),
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

// ------------------------------------------------ lab #896 F: the authorization check

/// Section layout (seam A): a 16-B header (`QRA1`, version, scheme at byte 6,
/// slot count at byte 7, `valid_until_height`), then per slot a 36-B
/// descriptor, the 1,312-B verifying key and the 2,420-B signature.
const VK_AT: usize = 16 + 36;
const SIG_AT: usize = VK_AT + 1_312;
const SLOT: usize = 36 + 1_312 + 2_420;

/// `t` with one byte of slot `k`'s signature flipped: well formed, unauthorized.
fn junk(t: &TxEntry, k: usize) -> TxEntry {
    let mut j = t.clone();
    j.auth[SIG_AT + k * SLOT + 7] ^= 1;
    j
}

fn bad_sig(slot: usize) -> AuthRefusal {
    AuthRefusal::Unauthorized(AuthError::BadSignature { slot })
}

/// Every refusal by name, at the shared function both funnels call.
#[test]
fn check_auth_names_every_refusal() {
    let anchor = [0x11; 32];
    let t = signed_tx(anchor, 8);
    assert_eq!(check_auth(&t, &ctx(), 1), Ok(Some(VALID_UNTIL)));

    // Presence against the axis.
    assert_eq!(
        check_auth(&t, &AuthContext::NONE, 1),
        Err(AuthRefusal::AuthOnV1Net)
    );
    let bare = unsigned_tx(anchor, 8);
    assert_eq!(check_auth(&bare, &ctx(), 1), Err(AuthRefusal::AuthMissing));
    assert_eq!(check_auth(&bare, &AuthContext::NONE, 1), Ok(None));

    // The section decode, each kind kept distinct.
    let mut m = t.clone();
    m.auth.pop();
    assert!(matches!(
        check_auth(&m, &ctx(), 1),
        Err(AuthRefusal::Malformed(AuthError::Malformed(_)))
    ));
    let mut m = t.clone();
    m.auth[6] = 2;
    assert_eq!(
        check_auth(&m, &ctx(), 1),
        Err(AuthRefusal::Malformed(AuthError::Scheme(2)))
    );
    let mut m = t.clone();
    m.auth[7] = 1;
    assert_eq!(
        check_auth(&m, &ctx(), 1),
        Err(AuthRefusal::Malformed(AuthError::SlotCount {
            expected: 3,
            got: 1
        }))
    );

    // Expired: the last height is admitted; one past it is refused before
    // the (here broken) signature is looked at.
    assert_eq!(check_auth(&t, &ctx(), VALID_UNTIL), Ok(Some(VALID_UNTIL)));
    assert_eq!(
        check_auth(&junk(&t, 0), &ctx(), VALID_UNTIL + 1),
        Err(AuthRefusal::Expired {
            valid_until_height: VALID_UNTIL,
            height: VALID_UNTIL + 1
        })
    );

    // The validity cap, at both sides of its edge, before the signature.
    let far = signed_tx_until(anchor, 8, 2_000);
    assert_eq!(
        check_auth(&junk(&far, 0), &ctx(), 1),
        Err(AuthRefusal::ValidityTooFar {
            valid_until_height: 2_000,
            limit: 1 + MAX_AUTH_VALIDITY_BLOCKS
        })
    );
    assert_eq!(
        check_auth(&far, &ctx(), 2_000 - MAX_AUTH_VALIDITY_BLOCKS),
        Ok(Some(2_000))
    );
    assert_eq!(
        check_auth(&far, &ctx(), 2_000 - MAX_AUTH_VALIDITY_BLOCKS - 1),
        Err(AuthRefusal::ValidityTooFar {
            valid_until_height: 2_000,
            limit: 1_999
        })
    );

    // A leaf that is not `mldsa_leaf(index, vk)`: slot 0 carries slot 1's key.
    let mut m = t.clone();
    let vk1 = m.auth[VK_AT + SLOT..VK_AT + SLOT + 1_312].to_vec();
    m.auth[VK_AT..VK_AT + 1_312].copy_from_slice(&vk1);
    assert_eq!(
        check_auth(&m, &ctx(), 1),
        Err(AuthRefusal::Unauthorized(AuthError::LeafMismatch {
            slot: 0
        }))
    );
    // A bad signature in any slot, dummies included.
    for k in 0..3 {
        assert_eq!(
            check_auth(&junk(&t, k), &ctx(), 1),
            Err(bad_sig(k)),
            "slot {k}"
        );
    }

    // Every public field the intent binds: changed after signing, slot 0's
    // signature no longer verifies over the intent the node rebuilds.
    let mut m = t.clone();
    m.public.fee += 1;
    assert_eq!(check_auth(&m, &ctx(), 1), Err(bad_sig(0)), "fee");
    let mut m = t.clone();
    m.public.anchor[0] ^= 1;
    assert_eq!(check_auth(&m, &ctx(), 1), Err(bad_sig(0)), "anchor");
    let mut m = t.clone();
    m.public.nullifiers[2][0] ^= 1;
    assert_eq!(
        check_auth(&m, &ctx(), 1),
        Err(bad_sig(0)),
        "the fee slot's nullifier"
    );
    let mut m = t.clone();
    m.public.commitments[1][0] ^= 1;
    assert_eq!(check_auth(&m, &ctx(), 1), Err(bad_sig(0)), "a commitment");
    let mut m = t.clone();
    m.l2 = L2Surface {
        shape: L2ShapeTag::S,
        registry_root: [0x22; 32],
        vpublic: None,
        write: None,
        exit_rkm: [0; 32],
    }
    .encode();
    assert_eq!(check_auth(&m, &ctx(), 1), Err(bad_sig(0)), "the surface");
    let other_net = AuthContext::candidate_a([0x6F; 32]);
    assert_eq!(
        check_auth(&t, &other_net, 1),
        Err(bad_sig(0)),
        "another genesis"
    );
}

/// The ordering rule (2b §6 amendment (a)): a junk-auth copy submitted first
/// is refused by name and leaves no trace under any id, so the honest copy —
/// the same auth-excluding id — is admitted, indexed and served. A junk copy
/// after it is the cheap `DuplicateTx`.
#[test]
fn a_junk_auth_copy_first_leaves_no_trace_and_the_honest_copy_is_admitted() {
    let mut node = in_memory();
    let anchor = node.state().commitment_root();
    let honest = signed_tx(anchor, 8);
    let bad = junk(&honest, 1);
    assert_eq!(
        node.submit_tx_typed(bad.clone()),
        Err(TxSubmitRefusal::Pool(MempoolError::AuthRefused(bad_sig(1))))
    );
    assert!(!node.has_tx(&tx_id(&bad)));
    assert!(!node.has_tx(&tx_id(&honest)));

    node.submit_tx_typed(honest.clone())
        .expect("the honest copy is admitted");
    assert!(node.has_tx(&tx_id(&honest)));
    let served = node
        .get_tx(&tx_id(&honest))
        .expect("and served by its wire id");
    assert_eq!(wires(&[served]), wires(std::slice::from_ref(&honest)));

    assert_eq!(
        node.submit_tx_typed(bad.clone()),
        Err(TxSubmitRefusal::Pool(MempoolError::DuplicateTx))
    );
    assert!(
        !node.has_tx(&tx_id(&bad)),
        "the junk copy's wire id stays unknown"
    );
}

/// The cheap checks run first: with a broken signature, a wrong fee and a
/// bad anchor are named, not the signature.
#[test]
fn cheap_refusals_come_before_any_signature_work() {
    let mut node = in_memory();
    let anchor = node.state().commitment_root();
    let mut t = junk(&signed_tx(anchor, 8), 0);
    t.public.fee += 1;
    assert!(matches!(
        node.submit_tx_typed(t),
        Err(TxSubmitRefusal::Pool(MempoolError::WrongFee { .. }))
    ));
    let t = junk(&signed_tx([0x77; 32], 8), 0);
    assert_eq!(
        node.submit_tx_typed(t),
        Err(TxSubmitRefusal::Pool(MempoolError::AnchorNotValid))
    );
}

/// On the peer wire: a validity-window refusal is judged against this node's
/// tip, so it is `Ignored` and unscored; an unauthorized copy is `Rejected`.
#[test]
fn peer_ingest_ignores_window_refusals_and_rejects_unauthorized_copies() {
    let mut node = in_memory();
    let anchor = node.state().commitment_root();
    // Lands at height 1; valid only until 0.
    let expired = signed_tx_until(anchor, 8, 0);
    assert_eq!(
        node.ingest_tx(expired),
        IngestOutcome::Ignored(AUTH_WINDOW_REASON)
    );
    let far = signed_tx_until(anchor, 8, 1 + MAX_AUTH_VALIDITY_BLOCKS + 1);
    assert_eq!(
        node.ingest_tx(far),
        IngestOutcome::Ignored(AUTH_WINDOW_REASON)
    );
    assert_eq!(
        node.ingest_tx(junk(&signed_tx(anchor, 8), 2)),
        IngestOutcome::Rejected("auth signature refused")
    );
}

/// The body rule (2b §6 item 2): a block whose proofs all verify (mocked)
/// but which carries an unauthorized transaction is invalid; so is an expired
/// one, and an auth section on a v1 net.
#[test]
fn the_body_rule_refuses_a_stark_valid_but_unauthorized_block() {
    let anchor = [0x11; 32];
    let ext = AnnuletHeaderFields {
        l1_anchor_height: 0,
        l1_anchor_root: [0; 32],
        registry_root: root(),
    };
    let block = |tx: TxEntry, form: L2AuthForm| {
        let body = BlockBody {
            txs: vec![tx],
            ..BlockBody::default()
        };
        let header = BlockHeader::child_of_annulet(
            &genesis(),
            10,
            ext,
            body_commitment_annulet_for(&body, form),
        );
        (header, body)
    };
    let judge = |header: &BlockHeader, body: &BlockBody, c: &AuthContext| {
        validate_body_annulet_for(header, body, &MockProofVerifier, |_| true, &FEES, c)
    };

    let (h, b) = block(signed_tx(anchor, 8), AXIS);
    assert_eq!(judge(&h, &b, &ctx()), Ok(()));
    let (h, b) = block(junk(&signed_tx(anchor, 8), 0), AXIS);
    assert_eq!(
        judge(&h, &b, &ctx()),
        Err(BodyError::L2AuthRefused {
            index: 0,
            refusal: bad_sig(0)
        })
    );
    let (h, b) = block(signed_tx_until(anchor, 8, 0), AXIS);
    assert_eq!(
        judge(&h, &b, &ctx()),
        Err(BodyError::L2AuthRefused {
            index: 0,
            refusal: AuthRefusal::Expired {
                valid_until_height: 0,
                height: 1
            }
        })
    );
    let (h, b) = block(unsigned_tx(anchor, 8), AXIS);
    assert_eq!(
        judge(&h, &b, &ctx()),
        Err(BodyError::L2AuthRefused {
            index: 0,
            refusal: AuthRefusal::AuthMissing
        })
    );
    let (h, b) = block(signed_tx(anchor, 8), L2AuthForm::None);
    assert_eq!(
        judge(&h, &b, &AuthContext::NONE),
        Err(BodyError::L2AuthRefused {
            index: 0,
            refusal: AuthRefusal::AuthOnV1Net
        })
    );

    // And a follower refuses the sealed unauthorized block whole.
    let anchor = in_memory().state().commitment_root();
    let (h, b) = block(junk(&signed_tx(anchor, 8), 0), AXIS);
    let mut follower = in_memory();
    assert!(matches!(
        follower.ingest_sealed_block(&key().seal(h), b),
        IngestOutcome::Rejected(_)
    ));
    assert_eq!(follower.state().tip_height(), 0);
}

/// The pool evicts a transaction whose window the next height leaves.
#[test]
fn an_expiring_transaction_is_evicted_when_the_tip_passes_it() {
    let mut producer = in_memory();
    let mut follower = in_memory();
    let anchor = follower.state().commitment_root();
    // Lands at 1 at the latest; pooled by the follower only.
    let short = signed_tx_until(anchor, 20, 1);
    follower
        .submit_tx_typed(short.clone())
        .expect("valid at height 1");
    assert!(follower.has_tx(&tx_id(&short)));

    producer
        .submit_tx_typed(signed_tx(anchor, 8))
        .expect("the producer admits its own tx");
    let (sealed, body) = producer
        .seal_next_block(&key(), 10)
        .expect("the producer seals");
    assert_eq!(
        follower.ingest_sealed_block(&sealed, body),
        IngestOutcome::Accepted
    );
    assert_eq!(follower.state().tip_height(), 1);
    assert!(
        !follower.has_tx(&tx_id(&short)),
        "the next landing height (2) is past its window: evicted"
    );
}
