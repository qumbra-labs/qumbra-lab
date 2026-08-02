//! M9-N6 integration: the node RPC serves REAL note-discovery artifacts over
//! live node state, byte-identical to the `qlab-cbserver` reference — proven by
//! driving the **unmodified** cbserver light client against a live node's server.

use std::sync::{Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, DecoyPolicy, ScanConfig};
use qlab_cbserver::codec::{decode_compact_response, encode_compact_response, CompactBlock, CompactGroup};
use qlab_cbserver::tree::Frontier;
use qlab_node::rpc::{serve, tx_id};
use qlab_node::{
    genesis_block, ChainStore, MemNode, MemNodeRpc, NodeState, RecipientDiscovery, SubmitOutcome,
    TxDiscovery,
};

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_note::hash::digest_bytes;
use qlab_note::kem::{generate_keypair, Ek, Keypair};
use qlab_note::note::Note;
use qlab_note::scan::{encrypt_to_recipient, EncryptedOutputs};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// Accept any proof (the discovery layer is orthogonal to proof verification;
// real proof checking is exercised in qlab-consensus / the m4gate suite).
struct AcceptAll;
impl TxVerifier for AcceptAll {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn rand_lane(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

fn note(rng: &mut StdRng) -> Note {
    Note { value: 1 + (rng.next_u64() % 1_000_000), rkm: rand_lane(rng), rho: rand_lane(rng), rseed: rand_lane(rng) }
}

/// Build one real tx (+ its discovery) to `ek`, with `k` outputs, `nf_seed`
/// distinct nullifiers, against `anchor`.
fn real_tx(ek: &Ek, k: usize, nf_seed: u8, anchor: Hash32, rng: &mut StdRng) -> (TxEntry, TxDiscovery) {
    let notes: Vec<Note> = (0..k).map(|_| note(rng)).collect();
    let enc: EncryptedOutputs = encrypt_to_recipient(ek, &notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    let nullifiers: Vec<Hash32> = (0..k).map(|i| [nf_seed.wrapping_add(i as u8); 32]).collect();
    // The transaction **commits** to the real bundle (issue #188 baton 2). It used
    // to carry `with_placeholder_discovery` — an all-zero ML-KEM ciphertext — while
    // the real bundle went only into the side table, which is exactly the split
    // this baton removed: the tx a peer relays and the bytes a wallet scans are one
    // artifact now, so a fixture cannot have two.
    let tx = TxEntry::new(
        b"real-m3-proof-placeholder".to_vec(),
        TxPublic {
            anchor,
            nullifiers,
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
        &[enc.bundle.clone()],
    );
    let discovery = TxDiscovery {
        recipients: vec![RecipientDiscovery { bundle: enc.bundle, payloads: enc.payloads }],
    };
    (tx, discovery)
}

fn apply_block(node: &mut MemNode, txs: Vec<TxEntry>) {
    let tip = node.tip_hash();
    let parent = node.chain().block(&tip).expect("tip stored").header();
    let coinbase = parent.height + 1;
    let body = BlockBody { txs, coinbase, coinbase_rkm: [coinbase, 2, 3, 4] };
    let header = BlockHeader::child_of(&parent, parent.height + 1, 1_000, body.commitment());
    node.apply_block(header, body, &AcceptAll).expect("block applies");
}

/// A finalized-genesis node wrapped in NodeRpc, plus (our wallet, decoy wallet,
/// anchor). Genesis finalized so the empty root is a valid anchor.
fn setup(rng: &mut StdRng) -> (MemNodeRpc, Keypair, Keypair, Hash32) {
    let our = generate_keypair(rng);
    let decoy = generate_keypair(rng);
    let mut node = MemNode::in_memory(genesis_block(1_000, 0));
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).unwrap());
    let anchor = node.commitment_root();
    assert!(node.is_valid_anchor(&anchor));
    (qlab_node::NodeRpc::new(node), our, decoy, anchor)
}

#[test]
fn reference_light_client_scans_a_live_node_and_finds_planted_notes() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let (mut rpc, our, decoy, anchor) = setup(&mut rng);

    // tx0: a 2-of-1 to our wallet; tx1: a 1-of-1 to a decoy. Submit both.
    let (tx0, d0) = real_tx(&our.ek, 2, 1, anchor, &mut rng);
    let (tx1, d1) = real_tx(&decoy.ek, 1, 10, anchor, &mut rng);
    assert!(matches!(rpc.submit_tx(tx0.clone(), d0, &AcceptAll), SubmitOutcome::Accepted(_)));
    assert!(matches!(rpc.submit_tx(tx1.clone(), d1, &AcceptAll), SubmitOutcome::Accepted(_)));
    assert_eq!(rpc.pending_len(), 2);

    // Include both in one accepted block at height 1.
    apply_block(rpc.node_mut(), vec![tx0, tx1]);
    let tip = rpc.node().tip_height();
    assert_eq!(tip, 1);

    // Serve over a real localhost socket and scan with the UNMODIFIED cbserver
    // light client — proving the served bytes are byte-identical to the
    // reference server's from a real wallet's point of view.
    let shared = Arc::new(Mutex::new(rpc));
    let handle = serve(Arc::clone(&shared));
    let base = handle.base_url();

    let mut scan_rng = StdRng::seed_from_u64(1);
    let out = light_client_scan(
        &base,
        &our.dk,
        1,
        tip,
        ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off },
        &mut scan_rng,
    )
    .expect("scan over the live node runs");
    assert_eq!(out.notes.len(), 2, "the 2-of-1 to our wallet is fully detected over the node RPC");
    assert!(out.stats.matched_fetches >= 1);

    // A stranger's key detects nothing (the decoy tx is not for us).
    let stranger = generate_keypair(&mut StdRng::seed_from_u64(999));
    let mut r2 = StdRng::seed_from_u64(2);
    let none = light_client_scan(
        &base,
        &stranger.dk,
        1,
        tip,
        ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off },
        &mut r2,
    )
    .unwrap();
    assert_eq!(none.notes.len(), 0, "a stranger detects nothing");

    // Frontier served from the LIVE node tree reconstructs the node's root.
    let front = qlab_cbserver::client::http_get(&base, &format!("/v1/tree/frontier?at={tip}")).unwrap();
    let f = Frontier::from_bytes(&front).unwrap();
    assert_eq!(
        digest_bytes(&f.root()),
        shared.lock().unwrap().node().commitment_root(),
        "served frontier reconstructs the live node commitment root"
    );

    handle.shutdown();
}

#[test]
fn embedded_compact_bytes_equal_the_cbserver_encoder() {
    // The node's /v1/compact bytes must be exactly what cbserver's encoder
    // produces for the same groups — the "reuse, never fork" contract, checked
    // against the reference encoder over live-node-assembled groups.
    let mut rng = StdRng::seed_from_u64(7);
    let (mut rpc, our, _decoy, anchor) = setup(&mut rng);
    let (tx0, d0) = real_tx(&our.ek, 2, 1, anchor, &mut rng);
    let expected_bundle = d0.recipients[0].bundle.clone();
    rpc.submit_tx(tx0.clone(), d0, &AcceptAll);
    apply_block(rpc.node_mut(), vec![tx0]);

    let got = rpc.route("/v1/compact?from=1&to=1").unwrap();

    let expected = encode_compact_response(&[CompactBlock {
        height: 1,
        groups: vec![CompactGroup { tx_index: 0, recipients: vec![expected_bundle] }],
    }]);
    assert_eq!(got, expected, "node compact stream == cbserver encoder output, byte for byte");

    // And it round-trips through the reference decoder.
    let blocks = decode_compact_response(&got).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].groups[0].recipients[0].entries.len(), 2);
}

#[test]
fn tx_id_is_stable_across_pending_and_accepted_forms() {
    // The id a tx is served under must be identical whether computed from the
    // submitted TxPublic or from the accepted-block StoredTx.
    let mut rng = StdRng::seed_from_u64(11);
    let (mut rpc, our, _d, anchor) = setup(&mut rng);
    let (tx0, d0) = real_tx(&our.ek, 2, 1, anchor, &mut rng);
    let submit_id = match rpc.submit_tx(tx0.clone(), d0, &AcceptAll) {
        SubmitOutcome::Accepted(id) => id,
        other => panic!("expected acceptance, got {other:?}"),
    };
    apply_block(rpc.node_mut(), vec![tx0.clone()]);

    // Recompute from the public surface via the exported helper.
    let p = &tx0.public;
    let recomputed = tx_id(&p.anchor, &p.nullifiers, &p.commitments, p.bucket.logical_actions(), p.fee);
    assert_eq!(submit_id, recomputed, "submit id == recomputed public-surface id");

    // The block serves this tx (found via the same id) → non-empty group.
    let bytes = rpc.route("/v1/compact?from=1&to=1").unwrap();
    let blocks = decode_compact_response(&bytes).unwrap();
    assert!(!blocks[0].groups[0].recipients.is_empty(), "accepted tx serves its discovery");
}


/// 🔴 **The RPC's per-height reconstruction agrees with `apply_state` across the
/// maturity delay — issue #116's derived cross-check, landing with issue #102.**
///
/// `NodeRpc` republishes per-height tree state by *recounting* what `apply_state`
/// appended, and the coordinator's #102 ruling was that this had to stop being an
/// independent restatement before the append rule started sliding. It now is one:
/// both sides call `qlab_node::matured_coinbase_leaf` and differ only in how they
/// resolve an ancestor.
///
/// **Asserted per height, against the roots the node actually had.** An earlier
/// version of this test compared the *set* of published anchors and was worthless:
/// `root_at` clamps a too-large count to the full tree, so an offset error produced
/// the identical set of distinct roots and the test passed with the schedule wrong.
/// The height→count mapping is what breaks, so that is what is checked — via
/// `/v1/tree/frontier?at=h`, which is served straight from `leaves_at(h)` and is the
/// surface a wallet builds witnesses against.
///
/// This failure is otherwise silent: a miscount does not error, it hands wallets a
/// frontier for the wrong prefix, and witnesses cut against it simply do not fold to
/// any anchor the node will accept.
#[test]
fn per_height_frontiers_match_the_nodes_own_roots_across_the_maturity_delay() {
    let delay = qlab_node::COINBASE_MATURITY_BLOCKS;
    let height = delay + 25;

    let mut node = MemNode::in_memory(genesis_block(1_000, 0));
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).unwrap());

    // The node's own root after each height — the ground truth to reconstruct.
    let mut roots_live: Vec<Hash32> = vec![node.commitment_root()]; // height 0
    for _ in 0..height {
        apply_block(&mut node, Vec::new());
        let tip = node.tip_hash();
        node.finalize(tip).expect("finalize");
        roots_live.push(node.commitment_root());
    }
    assert_eq!(node.tip_height(), height);
    assert_eq!(
        node.commitment_count(),
        height - delay,
        "the tree runs exactly one maturity delay behind the chain"
    );
    // The delay is genuinely spanned: early heights share the empty root, later ones
    // do not — so a mapping that is off by the delay cannot coincide with the truth.
    assert_eq!(roots_live[1], roots_live[delay as usize], "nothing matures before the delay");
    assert_ne!(roots_live[delay as usize], roots_live[height as usize]);

    let rpc = qlab_node::NodeRpc::new(node);
    for (h, expected) in roots_live.iter().enumerate() {
        let bytes = rpc.route(&format!("/v1/tree/frontier?at={h}")).unwrap();
        let f = Frontier::from_bytes(&bytes).unwrap();
        assert_eq!(
            digest_bytes(&f.root()),
            *expected,
            "the frontier served for height {h} must reconstruct the root the node had \
             at height {h} — a mismatch means the RPC recounted the append schedule"
        );
    }

    // And every anchor it publishes is one the node accepts.
    for root in &rpc.anchors().roots {
        assert!(rpc.node().is_valid_anchor(root), "published a root the node rejects");
    }
}
