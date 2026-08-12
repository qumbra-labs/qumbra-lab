//! Issue #188 baton 2 acceptance: **a recipient finds its output, from what a
//! node serves, after that node restarted.**
//!
//! Not "the endpoint returns bytes". The property under test is the one the whole
//! option-3 decision was taken for: a wallet holding nothing but its own ML-KEM
//! decapsulation key, given nothing but a node's `/v1/compact` bytes over a
//! socket, **locates the output paid to it** — and a stranger's key does not.
//!
//! Three things are deliberately arranged so the test cannot pass for the wrong
//! reason:
//!
//! 1. **Nothing is ever submitted through `NodeRpc`.** There is no `NodeRpc` in
//!    this file and therefore no in-memory side table anywhere. The block arrives
//!    the way a peer's block arrives.
//! 2. **The node is closed and reopened from disk between writing and serving.**
//!    That is the whole point of body-bound discovery: the bytes survive the
//!    process. A serving path that depended on anything held in RAM at submit time
//!    cannot pass this.
//! 3. **The served bytes are compared to the stored block's own bytes**, not to a
//!    value this test computed a second way. "The served discovery is the
//!    committed discovery" is a byte identity or it is nothing.
//!
//! ## What this test does NOT establish, stated rather than implied
//!
//! - **The proof is a placeholder** (`AcceptAll`). Discovery serving is orthogonal
//!   to proof verification: `validate_body` checks the discovery group's shape and
//!   binding (`check_tx_discovery`) with no reference to the proof, and the real
//!   verifier is exercised against real STARKs in `tests/coinbase_spend.rs` and
//!   `qlab-faucet`'s acceptance suite. A real proof here would add ~2.3 s and
//!   ~11.8 GB and test something already tested.
//! - **This file's acceptance test still only detects.** Detection is
//!   `decapsulate` + the committed tag, which is what it was written for, and it
//!   is left that way on purpose so the `/v1/compact` byte identity below is not
//!   entangled with the payload route. **Opening is no longer impossible** — the
//!   sentence that stood here (the AEAD payload "is not in the body preimage")
//!   was true until the mint relocated it there (PR #252), and
//!   `/v1/block/{h}/tx/{i}/full` serves it since issue #188's serving+open
//!   baton. The opened-end-to-end acceptance lives in `tests/recipient_scan.rs`;
//!   the payload projection's own golden is
//!   `the_payload_projection_is_golden_locked_against_a_hand_built_body` below.

use std::sync::{Arc, Mutex};

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{genesis_block, ChainStore, MemNode, NodeState};
use qlab_note::kem::{generate_keypair, Ek, Keypair};
use qlab_note::note::Note;
use qlab_note::scan::{detect_matches, encrypt_to_recipient};
use qumbra_node::discovery_server::{DiscoveryServer, DiscoveryView};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The discovery group's validity is checked by `validate_body` without reference
/// to the proof; see the module docs for why a real STARK is not used here.
struct AcceptAll;
impl TxVerifier for AcceptAll {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn lanes(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

fn note(rng: &mut StdRng) -> Note {
    Note {
        value: 1 + (rng.next_u64() % 1_000_000),
        rkm: lanes(rng),
        rho: lanes(rng),
        rseed: lanes(rng),
    }
}

/// A transaction paying `k` real notes to `ek`, whose **committed** discovery group
/// is the real ML-KEM bundle those notes were encrypted under.
///
/// Returns the transaction and the notes, so the test can assert which output the
/// wallet found rather than merely that it found one.
fn payment_to(
    ek: &Ek,
    k: usize,
    nf_seed: u8,
    anchor: Hash32,
    rng: &mut StdRng,
) -> (TxEntry, Vec<Note>) {
    let notes: Vec<Note> = (0..k).map(|_| note(rng)).collect();
    let enc = encrypt_to_recipient(ek, &notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    let tx = TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic {
            anchor,
            nullifiers: (0..k).map(|i| [nf_seed.wrapping_add(i as u8); 32]).collect(),
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
        &[enc.bundle],
        // Issue #188 (a) as amended: the real payloads ride in the committed
        // discovery region, not only in a served side table.
        &enc.payloads,
    );
    (tx, notes)
}

/// Apply one block carrying `txs` and finalize it, so its root becomes a valid
/// anchor for whatever comes next.
fn apply_and_finalize(node: &mut MemNode, txs: Vec<TxEntry>) -> u64 {
    let tip = node.tip_hash();
    let parent = node.chain().block(&tip).expect("tip stored").header();
    let height = parent.height + 1;
    let body = BlockBody { txs, coinbase: height, coinbase_rkm: [height, 2, 3, 4] };
    let header = BlockHeader::child_of(&parent, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AcceptAll).expect("block applies");
    assert!(node.finalize(hash).expect("finalize").is_recorded(), "height {height} finalizes");
    height
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qumbra-i188-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A minimal HTTP/1.1 GET, so the test crosses a real socket rather than calling
/// the handler.
fn get(addr: std::net::SocketAddr, path: &str) -> (String, Vec<u8>) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).expect("read");
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
    let status = String::from_utf8_lossy(&raw[..sep]).lines().next().unwrap_or("").to_string();
    (status, raw[sep + 4..].to_vec())
}

/// 🔴 **The acceptance test.**
#[test]
fn a_recipient_finds_its_output_from_a_restarted_nodes_committed_discovery() {
    let mut rng = StdRng::seed_from_u64(0x188_2);
    let recipient: Keypair = generate_keypair(&mut rng);
    let stranger: Keypair = generate_keypair(&mut rng);
    let dir = temp_dir("recipient-finds");

    // ---- 1. Write a chain to disk. No RPC, no side table, no wallet in sight. --
    let (paid_notes, committed_groups, tx_height) = {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::open(&dir, genesis).expect("open a fresh data dir");
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
        let anchor = node.commitment_root();
        assert!(node.is_valid_anchor(&anchor), "the finalized empty root is an anchor");

        // A 2-output payment to the recipient, and a 1-output payment to somebody
        // else in the same block — so "found mine" is a discrimination, not a count.
        let (mine, notes) = payment_to(&recipient.ek, 2, 1, anchor, &mut rng);
        let (theirs, _) = payment_to(&stranger.ek, 1, 40, anchor, &mut rng);
        let height = apply_and_finalize(&mut node, vec![mine, theirs]);

        // Read the committed bytes back out of the block store — this is the
        // "committed discovery" everything below is compared against.
        let hash = node.tip_hash();
        let stored = node.chain().block(&hash).expect("tip stored").clone();
        let groups: Vec<Vec<u8>> = stored.txs.iter().map(|t| t.discovery.clone()).collect();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g.len() > qlab_note::kem::CT_LEN), "real bundles, not n = 0");

        node.save_snapshot().expect("flush");
        (notes, groups, height)
    }; // the process's node — and anything it held in RAM — is gone here.

    // ---- 2. Reopen from disk and serve. ------------------------------------
    let reopened =
        MemNode::open(&dir, genesis_block(GENESIS_DIFFICULTY, 0)).expect("restart from disk");
    assert_eq!(reopened.tip_height(), tx_height, "the restart resumed the chain");

    let mut view = DiscoveryView::default();
    assert!(view.refresh(reopened.chain()), "the projection comes off the reopened store");
    let served_bytes = view.len_bytes();
    let shared = Arc::new(Mutex::new(Arc::new(view)));
    // The leaves view, anchor set and submit queue are the other routes
    // (#275/#276) — empty and unconsumed here on purpose: this test is about
    // `/v1/compact` alone.
    let leaves = Arc::new(Mutex::new(Arc::new(qumbra_node::discovery_server::LeavesView::default())));
    let anchors =
        Arc::new(Mutex::new(Arc::new(qumbra_node::discovery_server::AnchorsView::default())));
    let (submit_tx, _submit_rx) = std::sync::mpsc::sync_channel(1);
    let server =
        DiscoveryServer::start("127.0.0.1:0", Arc::clone(&shared), leaves, anchors, submit_tx)
            .expect("bind");
    let addr = server.addr();

    // ---- 3. The wallet. Only `dk`, only what the socket returns. -----------
    let (status, body) = get(addr, &format!("/v1/compact?from=0&to={tx_height}"));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let blocks = qlab_cbserver::codec::decode_compact_response(&body)
        .expect("a wallet decodes this with the reference decoder, not a private one");

    let mut found: Vec<(u64, u64, usize, Hash32)> = Vec::new();
    for block in &blocks {
        for group in &block.groups {
            for bundle in &group.recipients {
                for i in detect_matches(&recipient.dk, bundle) {
                    found.push((block.height, group.tx_index, i, bundle.entries[i].cm));
                }
            }
        }
    }

    // 🔴 THE PROPERTY: the recipient located exactly its own outputs, and knows
    // where they are on the chain.
    assert_eq!(found.len(), 2, "both outputs paid to this wallet were located");
    let expected: Vec<Hash32> = paid_notes
        .iter()
        .map(|n| qlab_note::hash::digest_bytes(&n.commitment()))
        .collect();
    assert_eq!(
        found.iter().map(|f| f.3).collect::<Vec<_>>(),
        expected,
        "and they are the commitments of the notes that were actually paid, in order"
    );
    assert!(
        found.iter().all(|f| f.0 == tx_height && f.1 == 0),
        "located at (height, tx_index) — the coordinates a wallet needs: {found:?}"
    );

    // A stranger's key finds nothing. Detection is a key operation, not a
    // server-side filter, so the node was never asked who was asking.
    let mut stranger_found = 0;
    for block in &blocks {
        for group in &block.groups {
            for bundle in &group.recipients {
                stranger_found += detect_matches(&stranger.dk, bundle).len();
            }
        }
    }
    assert_eq!(stranger_found, 1, "the stranger finds its own single output and no more");

    // ---- 4. Served == committed PREFIX, as a byte identity. ----------------
    //
    // 🔴 Since issue #188 (a) the committed region is `group_contents ‖
    // payloads` and serving projects the prefix — the relocated payload section
    // is committed but not on the compact wire. Still a projection: these bytes
    // are copied out of the block's own committed bytes, not rebuilt.
    let tx_block = blocks.iter().find(|b| b.height == tx_height).expect("the payment's block");
    for (i, group) in tx_block.groups.iter().enumerate() {
        let prefix = qlab_cbserver::codec::committed_contents_prefix(&committed_groups[i])
            .expect("a stored block's committed region decodes");
        let mut expected = Vec::new();
        qlab_cbserver::codec::write_varint(&mut expected, i as u64);
        expected.extend_from_slice(prefix);
        assert_eq!(
            qlab_cbserver::codec::encode_group(group),
            expected,
            "served group {i} is varint(position) ‖ the block's own committed PREFIX"
        );
        // The other half: the payload section IS there, committed, unserved.
        assert!(
            committed_groups[i].len() > prefix.len(),
            "group {i}'s committed region must carry a payload section"
        );
    }

    // The projection's cost, measured rather than asserted in prose: the committed
    // discovery for one 2-output and one 1-output payment.
    assert_eq!(
        served_bytes,
        committed_groups.iter().map(|g| g.len()).sum::<usize>(),
        "the projection holds exactly the committed bytes and nothing else"
    );

    server.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// 🔴 **The serving projection, golden-locked against a hand-built body, in
/// both directions** — the same two-goldens-opposite-directions check the mint
/// used when it relocated the payloads (PR #252), now applied to the route that
/// serves them.
///
/// - **Direction 1 — the serving vector must be exactly this.** The `/full`
///   response is written out here byte by byte from the framing rules
///   (`version ‖ n_recipients ‖ [n_payloads ‖ [len ‖ bytes]]`) and compared to
///   what the projection produces, so a change to either the framing or the
///   projection has to come here and say so. The whole response is also pinned
///   by digest, which is the form a reader can quote.
/// - **Direction 2 — the body commitment must move when a payload byte does,
///   and the compact vector must not.** That pairing is what makes the payload
///   section *committed but unserved on the compact wire*: if flipping a
///   payload byte moved `/v1/compact`'s bytes, the golden that locks the
///   compact framing would be the one going red; if it did not move
///   `BlockBody::commitment()`, the payloads would not be committed at all and
///   this whole baton would be serving an availability promise instead of a
///   chain fact.
#[test]
fn the_payload_projection_is_golden_locked_against_a_hand_built_body() {
    use qlab_devnet::hash::keccak256;
    use qlab_note::compact::PAYLOAD_LEN;
    use qlab_note::kem::CT_LEN;
    use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};

    // A hand-built body. No keypair and no AEAD: this test is about bytes, and
    // a real ciphertext would make the golden depend on an rng.
    let entry = |s: u8| CompactEntry { cm: [s; 32], tag: [s ^ 0x5a; 8], clue: ClueSlot::Empty };
    let recipients = vec![
        RecipientBundle { ct: [0xA1; CT_LEN], entries: vec![entry(0x11), entry(0x22)] },
        RecipientBundle { ct: [0xB2; CT_LEN], entries: vec![entry(0x33)] },
    ];
    let payloads: Vec<Vec<u8>> = (0..3u8).map(|k| vec![0xC0 ^ k; PAYLOAD_LEN]).collect();
    let public = TxPublic {
        anchor: [0x07; 32],
        nullifiers: vec![[0x01; 32], [0x02; 32]],
        commitments: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        bucket: ArityBucket::TwoByTwo,
        fee: posted_fee(ArityBucket::TwoByTwo),
    };
    let tx = TxEntry::new(b"proof-placeholder".to_vec(), public, &recipients, &payloads);
    let body = BlockBody { txs: vec![tx.clone()], coinbase: 1, coinbase_rkm: [1, 2, 3, 4] };

    let view = DiscoveryView {
        blocks: vec![qlab_node::BlockDiscovery {
            height: 1,
            hash: [0x99; 32],
            groups: vec![tx.discovery.clone()],
            nullifiers: vec![],
        }],
    };
    let served = qlab_node::full_response(&view.blocks, 1, 0).expect("the projection answers");

    // ---- Direction 1: the serving vector, written out rather than derived. --
    let mut expected = Vec::new();
    expected.push(qlab_cbserver::WIRE_VERSION);
    expected.push(2u8); // n_recipients
    expected.push(2u8); // recipient 0: n_payloads
    for p in &payloads[..2] {
        expected.push(PAYLOAD_LEN as u8); // varint(120) is one byte
        expected.extend_from_slice(p);
    }
    expected.push(1u8); // recipient 1: n_payloads
    expected.push(PAYLOAD_LEN as u8);
    expected.extend_from_slice(&payloads[2]);
    assert_eq!(served, expected, "the /full serving vector is exactly its framing");
    assert_eq!(served.len(), 1 + 1 + (1 + 2 * (1 + PAYLOAD_LEN)) + (1 + (1 + PAYLOAD_LEN)));

    let digest_hex = |b: &[u8]| -> String {
        keccak256(b).iter().map(|x| format!("{x:02x}")).collect()
    };
    assert_eq!(
        digest_hex(&served),
        "8f2fa42e8d5580e7d728ac418600505c2f358c34c673ac3ed0fd7fd45a250b43",
        "the pinned /full serving vector for this hand-built body"
    );

    // ---- Direction 2: move one payload byte. --------------------------------
    let mut tampered_tx = tx.clone();
    let last = tampered_tx.discovery.len() - 1;
    tampered_tx.discovery[last] ^= 0x01;
    let tampered_body =
        BlockBody { txs: vec![tampered_tx.clone()], coinbase: 1, coinbase_rkm: [1, 2, 3, 4] };
    let tampered_view = DiscoveryView {
        blocks: vec![qlab_node::BlockDiscovery {
            height: 1,
            hash: [0x99; 32],
            groups: vec![tampered_tx.discovery.clone()],
            nullifiers: vec![],
        }],
    };

    assert_ne!(
        body.commitment(),
        tampered_body.commitment(),
        "🔴 the payload section IS committed: one byte moves tx_body_commitment"
    );
    assert_eq!(
        qlab_node::compact_response(&view.blocks, 1, 1).unwrap(),
        qlab_node::compact_response(&tampered_view.blocks, 1, 1).unwrap(),
        "and it is NOT on the compact wire: the same byte moves nothing /v1/compact serves"
    );
    assert_ne!(
        qlab_node::full_response(&tampered_view.blocks, 1, 0).unwrap(),
        served,
        "while the payload route serves the byte that moved, which is the point of it"
    );
}

/// The negative that makes the acceptance mean something: **omission is not
/// serveable**, because it is not includable.
///
/// A transaction with outputs and no discovery group is consensus-invalid
/// (`discovery-on-the-consensus-wire.md` §1, the `n = 0` case of D4's binding
/// rule), so there is no chain state in which `/v1/compact` can honestly answer
/// "this transaction pays nobody" about a transaction that pays somebody. That is
/// the difference between option 3 and option 2a, checked at the one door a served
/// block can enter through.
#[test]
fn a_payment_that_attaches_no_discovery_cannot_reach_the_serving_path() {
    let mut rng = StdRng::seed_from_u64(0x188_2_0);
    let recipient = generate_keypair(&mut rng);
    let dir = temp_dir("omission-refused");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut node = MemNode::open(&dir, genesis).expect("open");
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor = node.commitment_root();

    let (good, _notes) = payment_to(&recipient.ek, 2, 1, anchor, &mut rng);
    // The same payment with its group stripped to `n = 0`.
    let stripped =
        TxEntry { proof: good.proof.clone(), public: good.public.clone(), discovery: TxEntry::empty_discovery(), rider: TxEntry::absent_rider() };

    let tip = node.tip_hash();
    let parent = node.chain().block(&tip).expect("tip stored").header();
    let body = BlockBody { txs: vec![stripped], coinbase: 1, coinbase_rkm: [1, 2, 3, 4] };
    let header = BlockHeader::child_of(&parent, 75, GENESIS_DIFFICULTY, body.commitment());
    let err = node.apply_block(header, body, &AcceptAll).expect_err("consensus must refuse it");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("DiscoveryDoesNotBind") && rendered.contains("expected: 2"),
        "omission is the n = 0 case of the binding rule, reported as such: {rendered}"
    );

    // And the honest transaction goes in, so the refusal above is about the
    // omission and not about anything else in the fixture.
    let height = apply_and_finalize(&mut node, vec![good]);
    let mut view = DiscoveryView::default();
    view.refresh(node.chain());
    assert_eq!(view.tip_height(), Some(height));
    assert_eq!(view.blocks[height as usize].groups.len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}
