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
//! - **The recipient detects; it does not open.** Detection is `decapsulate` + the
//!   committed tag, and that is all this baton's acceptance asks for ("Spending is
//!   baton 4; finding is this one"). The AEAD payload that carries
//!   `(value, ρ, rseed)` is **not** in the body preimage — D2 commits
//!   `ct ‖ cm ‖ tag ‖ clue_len` and the ~585 B/note the design priced is
//!   `1088/2 + 41`, with no payload in it — so the note cannot be opened from
//!   chain data alone. Reported as a finding on issue #188; it is baton 4's
//!   question and this file does not pretend otherwise.

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
    let server = DiscoveryServer::start("127.0.0.1:0", Arc::clone(&shared)).expect("bind");
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
        TxEntry { proof: good.proof.clone(), public: good.public.clone(), discovery: TxEntry::empty_discovery() };

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
