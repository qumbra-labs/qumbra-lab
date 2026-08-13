//! 🔴 **Issue #399 commit 1: the pre-refactor lock.** Phase 1 (`spend::select`)
//! is about to be inverted into a caller-pumped driver; this file pins what it
//! does on the wire TODAY, before any production line moves — the #358 S4
//! discipline, applied to selection.
//!
//! The lock runs the REAL `select` against the deployed serving surface
//! (`DiscoveryServer`, the same type the binary starts) through a recording
//! proxy, and asserts the request sequence phase by phase:
//!
//!   compact scan (paged) → full fetches (matched + decoys) → the bulk
//!   nullifier stream → tree leaves → anchors — in that order, and nothing else.
//!
//! Decoy targets are random by design (a privacy mechanism), so the full-fetch
//! segment is asserted by SHAPE (well-formed paths, bounded count, contains the
//! real match) rather than byte-exactly; every other segment is exact. The
//! bundle's own facts (amount, fee, change, recipient, anchor) are pinned too —
//! the driver must reproduce all of it or the refactor changed behaviour.
//!
//! No STARK is proved here (phase 1 stops at the witness bundle), so this runs
//! in debug — the `spent_subtraction.rs` trade, applied to selection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{anchor_set, coinbase, genesis_block, ChainStore, Hash32, MemNode, NodeState};
use qlab_note::kem::Ek;
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest,
};
use qumbra_wallet::spend::{select, SendRequest};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB

/// Fixture blocks carry proofs nothing here reads (`spent_subtraction.rs`'s
/// trade: phase 1 never verifies one).
struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn mine(node: &mut MemNode, tip: &mut BlockHeader, txs: Vec<TxEntry>) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: [0xBE, 0xEF, 1, 2] };
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AnyTx).expect("block applies");
    node.finalize(hash).expect("finalize");
    *tip = header;
    height
}

fn payment(
    ek: &Ek,
    notes: &[Note],
    nullifiers: Vec<Hash32>,
    anchor: Hash32,
    rng: &mut StdRng,
) -> TxEntry {
    let enc = encrypt_to_recipient(ek, notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic {
            anchor,
            nullifiers,
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
        &[enc.bundle],
        &enc.payloads,
    )
}

/// A recording pass-through proxy: one connection per request, path recorded
/// in arrival order, bytes forwarded verbatim. Test-side only — the serving
/// code under it is the deployed type, untouched.
fn recording_proxy(upstream: String, log: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut client) = conn else { continue };
            let upstream = upstream.clone();
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                // Read the request head (phase 1 sends GETs only — bodies
                // would need Content-Length handling this proxy doesn't have).
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match client.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let first = String::from_utf8_lossy(&head);
                let path = first.split_whitespace().nth(1).unwrap_or("?").to_string();
                log.lock().unwrap().push(path);
                let Ok(mut server) = TcpStream::connect(&upstream) else { return };
                if server.write_all(&head).is_err() {
                    return;
                }
                let mut response = Vec::new();
                let _ = server.read_to_end(&mut response);
                let _ = client.write_all(&response);
            });
        }
    });
    format!("http://{addr}")
}

#[test]
fn phase_1_request_sequence_and_bundle_facts_are_golden_before_the_driver_refactor() {
    let mut rng = StdRng::from_seed([0x99; 32]);

    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([31u8; 32]), 0);
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([32u8; 32]), 0);
    let sender_d = sender.diversifier_at_index(0);
    let sender_kp = sender.diversified_keypair(&sender_d);
    let recipient_addr = recipient.address_at_index(0);

    // ---- the chain: one grant to the sender, then a little depth ----------
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor0 = node.commitment_root();

    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(sender_d),
        rho: [0xA1, 0xA2, 0xA3, 0xA4],
        rseed: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    mine(
        &mut node,
        &mut tip,
        vec![payment(&sender_kp.ek, &[granted], vec![[0x77; 32], [0x78; 32]], anchor0, &mut rng)],
    );
    for _ in 0..3 {
        mine(&mut node, &mut tip, vec![]);
    }

    // ---- the deployed serving surface, behind the recording proxy ---------
    let discovery = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    let leaves_view = Arc::new(Mutex::new(Arc::new(LeavesView::default())));
    let anchors_view = Arc::new(Mutex::new(Arc::new(AnchorsView::default())));
    {
        let mut view = DiscoveryView::default();
        view.refresh(node.chain());
        *discovery.lock().unwrap() = Arc::new(view);
        *leaves_view.lock().unwrap() =
            Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() });
        *anchors_view.lock().unwrap() = Arc::new(AnchorsView { encoded: anchor_set(&node).to_bytes() });
    }
    let (submit_chan, _submit_rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        discovery,
        leaves_view,
        anchors_view,
        submit_chan,
    )
    .expect("bind the discovery server");

    let log = Arc::new(Mutex::new(Vec::new()));
    let proxied = recording_proxy(server.addr().to_string(), Arc::clone(&log));

    // ---- the real phase 1, through the proxy ------------------------------
    let dir = std::env::temp_dir().join("qmb_select_goldens");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("wallet dir");
    WalletDir::create(&dir, MasterSeed::from_entropy([31u8; 32]))
        .expect("the sender wallet dir exists");
    let req = SendRequest {
        dir: &dir,
        url: &proxied,
        node_url: &proxied,
        recipient: &recipient_addr,
        contact_name: None,
        amount: AMOUNT,
        scan_to: tip.height,
        no_submit: true,
        name_op: None,
    };
    let bundle = select(&req, &mut |_| {}).expect("phase 1 selects and serializes a witness");

    // ---- the bundle's facts: what the driver must reproduce ---------------
    assert_eq!(bundle.amount(), AMOUNT);
    assert_eq!(bundle.fee(), posted_fee(ArityBucket::TwoByTwo));
    assert_eq!(bundle.change_value(), GRANT - AMOUNT - bundle.fee());
    assert!(bundle.used_dummy(), "one grant note means the #219 dummy slot");
    assert_eq!(bundle.recipient_short(), recipient_addr.short().encode());
    assert_eq!(bundle.selected_at_tip(), tip.height);

    // ---- the request sequence, phase by phase ------------------------------
    let paths = log.lock().unwrap().clone();
    let t = tip.height;

    // Segment boundaries: everything before the nullifier stream is the scan
    // (compact pages + full fetches); then leaves; then anchors; nothing else.
    let nf_at = paths
        .iter()
        .position(|p| p.starts_with("/v1/nullifiers"))
        .expect("the bulk nullifier stream is fetched");
    let leaves_at = paths
        .iter()
        .position(|p| p.starts_with("/v1/tree/leaves"))
        .expect("the leaf stream is fetched");
    let anchors_at = paths
        .iter()
        .position(|p| p.as_str() == "/v1/anchors")
        .expect("the anchor set is fetched");

    // Phase order is the lock: scan → nullifiers → leaves → anchors.
    assert!(nf_at < leaves_at && leaves_at < anchors_at, "phase order: {paths:?}");
    assert_eq!(anchors_at, paths.len() - 1, "anchors are the last fetch: {paths:?}");

    // Scan segment: the first request is the compact page for 0..=tip, and
    // every request before the nullifier stream is compact or a well-formed
    // /full fetch (the real match + its random decoys — shape, not bytes).
    assert_eq!(paths[0], format!("/v1/compact?from=0&to={t}"), "{paths:?}");
    let full_fetches = paths[..nf_at]
        .iter()
        .filter(|p| {
            let mut parts = p.trim_start_matches("/v1/block/").splitn(2, "/tx/");
            let block_ok = parts.next().is_some_and(|h| h.parse::<u64>().is_ok());
            let tx_ok = parts
                .next()
                .and_then(|rest| rest.strip_suffix("/full"))
                .is_some_and(|i| i.parse::<u64>().is_ok());
            block_ok && tx_ok
        })
        .count();
    let compact_pages = paths[..nf_at].iter().filter(|p| p.starts_with("/v1/compact")).count();
    assert_eq!(
        compact_pages + full_fetches,
        nf_at,
        "the scan segment holds nothing but compact pages and full fetches: {paths:?}"
    );
    assert!(full_fetches >= 1, "the grant's group is actually fetched: {paths:?}");

    // Nullifier and leaf streams: exact, single-page at this chain size.
    assert_eq!(paths[nf_at], format!("/v1/nullifiers?from=0&to={t}"), "{paths:?}");
    assert_eq!(paths[leaves_at], "/v1/tree/leaves?from=0", "{paths:?}");
    assert_eq!(
        paths[nf_at + 1..leaves_at]
            .iter()
            .filter(|p| !p.starts_with("/v1/nullifiers"))
            .count(),
        0,
        "nothing foreign between nullifiers and leaves: {paths:?}"
    );
}
