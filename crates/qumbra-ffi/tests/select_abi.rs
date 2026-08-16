//! The select driver and the witness bundle across the C ABI (lab #400) —
//! called the way the wasm host will call them: raw pointers, byte buffers,
//! explicit frees. The chain fixture is `select_driver.rs`'s (qumbra-wallet),
//! and no STARK is proved anywhere — debug-runnable, native-only (the fixture
//! needs the node crates; wasm/iOS release builds never see them).

use std::ffi::{c_char, CStr, CString};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ptr;
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
use qumbra_ffi::*;
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB
const SENDER_ENTROPY: [u8; 32] = [61u8; 32];

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

fn get(base: &str, path: &str) -> Result<Vec<u8>, String> {
    let host = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no split")?;
    Ok(raw[split + 4..].to_vec())
}

/// The whole fixture: a chain holding one 10 QMB grant for the ABI's wallet,
/// served by the deployed `DiscoveryServer`. Returns (url, tip height, server).
fn serve_chain() -> (String, u64, DiscoveryServer) {
    let mut rng = StdRng::from_seed([0x88; 32]);
    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy(SENDER_ENTROPY), 0);
    let d = sender.diversifier_at_index(0);
    let kp = sender.diversified_keypair(&d);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor0 = node.commitment_root();

    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(d),
        rho: [0xE1, 0xE2, 0xE3, 0xE4],
        rseed: [0xF1, 0xF2, 0xF3, 0xF4],
    };
    mine(
        &mut node,
        &mut tip,
        vec![payment(&kp.ek, &[granted], vec![[0x61; 32], [0x62; 32]], anchor0, &mut rng)],
    );
    mine(&mut node, &mut tip, vec![]);

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
    let (submit_chan, _rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        discovery,
        leaves_view,
        anchors_view,
        submit_chan,
    )
    .expect("bind");
    let url = format!("http://{}", server.addr());
    (url, tip.height, server)
}

/// Drive the REAL scan pump (`qmb_scan_*`) to completion against the fixture,
/// exactly as the popup does — the select handle is born from its outcomes.
unsafe fn scan_to_done(w: *const qumbra_ffi::WalletState, url: &str, to: u64) -> *mut ScanState {
    let label = CString::new(url).unwrap();
    let indices: [u64; 1] = [0];
    let seed = [9u8; 32];
    let s = qmb_scan_new(w, label.as_ptr(), 0, to, indices.as_ptr(), 1, seed.as_ptr());
    assert!(!s.is_null());
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        match qmb_scan_step(s, &mut out) {
            1 => {
                let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                qmb_string_free(out);
                match get(url, &path) {
                    Ok(body) => qmb_scan_supply(s, body.as_ptr(), body.len()),
                    Err(e) => {
                        let r = CString::new(e).unwrap();
                        qmb_scan_supply_err(s, r.as_ptr());
                    }
                }
            }
            0 => {
                let report = CStr::from_ptr(out).to_str().unwrap().to_string();
                qmb_string_free(out);
                assert!(report.contains("complete"), "{report}");
                return s;
            }
            rc => panic!("scan rc {rc}"),
        }
    }
}

/// The success path, end to end across the ABI: scan → select → bundle bytes
/// → the rendered approval review.
#[test]
fn the_abi_builds_a_bundle_and_renders_its_review() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);

        let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([62u8; 32]), 0);
        let recipient_addr = recipient.address_at_index(0).encode();
        let c_addr = CString::new(recipient_addr).unwrap();
        let seed = [7u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let sel = qmb_select_new(
            w,
            scan,
            c_addr.as_ptr(),
            AMOUNT,
            ptr::null(),
            0,
            seed.as_ptr(),
            &mut err,
        );
        assert!(sel != ptr::null_mut(), "select refused: {:?}", err_text(err));

        let bundle = loop {
            let mut out: *mut c_char = ptr::null_mut();
            match qmb_select_step(sel, &mut out) {
                rc @ (1 | 2) => {
                    let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                    qmb_string_free(out);
                    // Both endpoints are the same fixture host here; the rc
                    // still names which one the path belongs to. Since lab #424
                    // the SCAN contract carries two streams — the nullifiers and
                    // the coinbase facts — because a mined note is an input a
                    // spend may select and the compact host is what serves it.
                    assert!(
                        (rc == 1)
                            == (path.starts_with("/v1/nullifiers")
                                || path.starts_with("/v1/coinbase")),
                        "rc {rc} vs {path}"
                    );
                    let body = get(&url, &path).expect("fixture serves");
                    qmb_select_supply(sel, body.as_ptr(), body.len());
                }
                0 => {
                    let mut len: usize = 0;
                    let p = qmb_select_take_bundle(sel, &mut len);
                    assert!(!p.is_null() && len > 0);
                    let bytes = std::slice::from_raw_parts(p, len).to_vec();
                    qmb_dealloc(p, len);
                    break bytes;
                }
                -2 => {
                    let why = CStr::from_ptr(out).to_str().unwrap().to_string();
                    panic!("select failed: {why}");
                }
                rc => panic!("select rc {rc}"),
            }
        };

        // The review reads the DECODED bundle — the approval screen's source.
        let mut err2: *mut c_char = ptr::null_mut();
        let review_ptr = qmb_bundle_review(bundle.as_ptr(), bundle.len(), &mut err2);
        assert!(!review_ptr.is_null(), "review refused: {:?}", err_text(err2));
        let review = CStr::from_ptr(review_ptr).to_str().unwrap().to_string();
        qmb_string_free(review_ptr);

        let expected_short = recipient.address_at_index(0).short().encode();
        assert!(review.contains(&expected_short), "{review}");
        assert!(review.contains("1 QMB"), "{review}");
        assert!(review.contains("0.01 QMB"), "fee line: {review}");
        assert!(review.contains("8.99 QMB"), "change line: {review}");
        assert!(review.contains("dummy"), "{review}");
        assert!(review.contains(&format!("tip {to}")), "{review}");

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// The history join key: the bundle's real-input nullifiers cross as hex and
/// the chain's own stream (pumped) answers whether they landed.
#[test]
fn bundle_nullifiers_cross_and_the_spent_pump_answers() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([62u8; 32]), 0);
        let c_addr = CString::new(recipient.address_at_index(0).encode()).unwrap();
        let seed = [7u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let sel =
            qmb_select_new(w, scan, c_addr.as_ptr(), AMOUNT, ptr::null(), 0, seed.as_ptr(), &mut err);
        assert!(!sel.is_null());
        let bundle = loop {
            let mut out: *mut c_char = ptr::null_mut();
            match qmb_select_step(sel, &mut out) {
                1 | 2 => {
                    let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                    qmb_string_free(out);
                    let body = get(&url, &path).expect("fixture serves");
                    qmb_select_supply(sel, body.as_ptr(), body.len());
                }
                0 => {
                    let mut len: usize = 0;
                    let p = qmb_select_take_bundle(sel, &mut len);
                    let bytes = std::slice::from_raw_parts(p, len).to_vec();
                    qmb_dealloc(p, len);
                    break bytes;
                }
                rc => panic!("select rc {rc}"),
            }
        };
        qmb_select_free(sel);

        let mut err2: *mut c_char = ptr::null_mut();
        let nfs_ptr = qmb_bundle_nullifiers(bundle.as_ptr(), bundle.len(), &mut err2);
        assert!(!nfs_ptr.is_null());
        let nfs = CStr::from_ptr(nfs_ptr).to_str().unwrap().to_string();
        qmb_string_free(nfs_ptr);
        let lines: Vec<&str> = nfs.lines().collect();
        assert_eq!(lines.len(), 1, "one real input: {nfs}");
        assert_eq!(lines[0].len(), 64, "hex nullifier: {nfs}");

        // The chain has NOT seen this spend — the pump must answer 0, not guess.
        let sp = qmb_spent_new(0, to);
        loop {
            let mut out: *mut c_char = ptr::null_mut();
            match qmb_spent_step(sp, &mut out) {
                1 => {
                    let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                    qmb_string_free(out);
                    let body = get(&url, &path).expect("fixture serves");
                    qmb_spent_supply(sp, body.as_ptr(), body.len());
                }
                0 => break,
                rc => panic!("spent rc {rc}"),
            }
        }
        let nf_hex = CString::new(lines[0]).unwrap();
        assert_eq!(qmb_spent_contains(sp, nf_hex.as_ptr()), 0, "not landed yet");
        // The grant tx's own (stranger) nullifier IS on chain: 0x61 repeated.
        let stranger = CString::new("61".repeat(32)).unwrap();
        assert_eq!(qmb_spent_contains(sp, stranger.as_ptr()), 1);
        // Malformed hex is unanswerable, refused.
        let bad = CString::new("zz").unwrap();
        assert_eq!(qmb_spent_contains(sp, bad.as_ptr()), -1);
        qmb_spent_free(sp);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

unsafe fn err_text(err: *mut c_char) -> Option<String> {
    (!err.is_null()).then(|| {
        let s = CStr::from_ptr(err).to_str().unwrap().to_string();
        qmb_string_free(err);
        s
    })
}

/// A select born from an unfinished scan is refused by name — outcomes must
/// be complete, not merely present.
#[test]
fn select_from_an_unfinished_scan_is_refused() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let label = CString::new(url.as_str()).unwrap();
        let indices: [u64; 1] = [0];
        let seed = [9u8; 32];
        let scan = qmb_scan_new(w, label.as_ptr(), 0, to, indices.as_ptr(), 1, seed.as_ptr());
        // No pumping at all — the scan has not finished.
        let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([62u8; 32]), 0);
        let c_addr = CString::new(recipient.address_at_index(0).encode()).unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let sel =
            qmb_select_new(w, scan, c_addr.as_ptr(), AMOUNT, ptr::null(), 0, seed.as_ptr(), &mut err);
        assert!(sel.is_null());
        let why = err_text(err).expect("a named refusal");
        assert!(why.contains("scan"), "{why}");
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// Undecodable bundle bytes are refused by name, never reviewed.
#[test]
fn a_garbage_bundle_is_refused_not_reviewed() {
    unsafe {
        let junk = b"not a witness bundle";
        let mut err: *mut c_char = ptr::null_mut();
        let p = qmb_bundle_review(junk.as_ptr(), junk.len(), &mut err);
        assert!(p.is_null());
        let why = err_text(err).expect("a named refusal");
        assert!(!why.is_empty());
    }
}

/// A response nobody asked for is a fault, same rule as both drivers.
#[test]
fn an_unrequested_select_response_is_a_fault() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([62u8; 32]), 0);
        let c_addr = CString::new(recipient.address_at_index(0).encode()).unwrap();
        let seed = [7u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let sel =
            qmb_select_new(w, scan, c_addr.as_ptr(), AMOUNT, ptr::null(), 0, seed.as_ptr(), &mut err);
        assert!(!sel.is_null());
        let junk = b"unrequested";
        qmb_select_supply(sel, junk.as_ptr(), junk.len());
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(qmb_select_step(sel, &mut out), -2);
        let why = CStr::from_ptr(out).to_str().unwrap().to_string();
        qmb_string_free(out);
        assert!(why.contains("without requesting"), "{why}");
        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}
