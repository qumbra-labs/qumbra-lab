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
    let body = BlockBody::from_single_payee(txs, coinbase(height), [0xBE, 0xEF, 1, 2]);
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

/* --- the events codepoint (lab #432) --------------------------------------
 *
 * Everything below reads the event blob the way a SHELL does: a hand-rolled
 * decoder written from include/qumbra_ffi.h's documented layout, deliberately
 * NOT qumbra_ffi::events — the contract under test is the header's, proven
 * from the consumer's side of the boundary. */

#[derive(Debug, PartialEq)]
enum AbiEvent {
    Other(String),
    Selected { spendable: u64, skipped_spent: u64, mined: u64 },
    Tree { node_tip: u64, finalized: Option<u64>, anchor_root: String },
    Warning(String),
    CoinbaseUnavailable(String),
    /// A kind this consumer does not know — skipped by its length prefix,
    /// exactly as the header instructs.
    Unknown(u16),
}

fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn decode_events(blob: &[u8]) -> Vec<AbiEvent> {
    let count = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    let mut at = 4usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = u16::from_le_bytes(blob[at..at + 2].try_into().unwrap());
        let len = u32::from_le_bytes(blob[at + 2..at + 6].try_into().unwrap()) as usize;
        let body = &blob[at + 6..at + 6 + len];
        at += 6 + len;
        out.push(match kind {
            0 => AbiEvent::Other(String::from_utf8(body.to_vec()).unwrap()),
            1 => AbiEvent::Selected {
                spendable: u64le(&body[0..]),
                skipped_spent: u64le(&body[8..]),
                mined: u64le(&body[16..]),
            },
            2 => AbiEvent::Tree {
                node_tip: u64le(&body[24..]),
                finalized: (body[32] == 1).then(|| u64le(&body[33..])),
                anchor_root: String::from_utf8(body[49..].to_vec()).unwrap(),
            },
            3 => AbiEvent::Warning(String::from_utf8(body.to_vec()).unwrap()),
            4 => AbiEvent::CoinbaseUnavailable(String::from_utf8(body.to_vec()).unwrap()),
            k => AbiEvent::Unknown(k),
        });
    }
    assert_eq!(at, blob.len(), "trailing bytes after the last record");
    out
}

/// Pump `qmb_select_step_events` to DONE, serving every path except that
/// `kill_coinbase` answers the coinbase stream with a transport failure (what
/// a pre-#415 node's 404 becomes). Returns (bundle bytes, all events in
/// arrival order, every raw blob that crossed).
unsafe fn pump_select_with_events(
    sel: *mut SelectState,
    url: &str,
    kill_coinbase: bool,
) -> (Vec<u8>, Vec<AbiEvent>, Vec<Vec<u8>>) {
    let mut events = Vec::new();
    let mut blobs = Vec::new();
    loop {
        let mut out: *mut c_char = ptr::null_mut();
        let mut ev: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        let rc = qmb_select_step_events(sel, &mut out, &mut ev, &mut ev_len);
        if !ev.is_null() {
            let blob = std::slice::from_raw_parts(ev, ev_len).to_vec();
            qmb_dealloc(ev, ev_len);
            events.extend(decode_events(&blob));
            blobs.push(blob);
        } else {
            assert_eq!(ev_len, 0, "NULL events with a nonzero length");
        }
        match rc {
            1 | 2 => {
                let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                qmb_string_free(out);
                if kill_coinbase && path.starts_with("/v1/coinbase") {
                    let r = CString::new("HTTP 404: route not served").unwrap();
                    qmb_select_supply_err(sel, r.as_ptr());
                } else {
                    let body = get(url, &path).expect("fixture serves");
                    qmb_select_supply(sel, body.as_ptr(), body.len());
                }
            }
            0 => {
                let mut len: usize = 0;
                let p = qmb_select_take_bundle(sel, &mut len);
                assert!(!p.is_null() && len > 0);
                let bytes = std::slice::from_raw_parts(p, len).to_vec();
                qmb_dealloc(p, len);
                return (bytes, events, blobs);
            }
            -2 => {
                let why = CStr::from_ptr(out).to_str().unwrap().to_string();
                panic!("select failed: {why}");
            }
            rc => panic!("select rc {rc}"),
        }
    }
}

unsafe fn select_for_events(w: *const qumbra_ffi::WalletState, scan: *mut ScanState) -> *mut SelectState {
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([62u8; 32]), 0);
    let c_addr = CString::new(recipient.address_at_index(0).encode()).unwrap();
    let seed = [7u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let sel =
        qmb_select_new(w, scan, c_addr.as_ptr(), AMOUNT, ptr::null(), 0, seed.as_ptr(), &mut err);
    assert!(!sel.is_null(), "select refused: {:?}", err_text(err));
    sel
}

/// 🔴 The issue's headline, proven from the shell's side: a coinbase stream
/// that cannot be read is NARRATED across the C ABI — the degradation event
/// arrives decoded, before the selection line it explains, the send still
/// proceeds (the 2026-08-16 ruling), and the tree narration follows. This is
/// lab #424's guardrail 1 finally reaching an FFI shell's user.
#[test]
fn a_dead_coinbase_route_is_narrated_across_the_abi_and_the_send_proceeds() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);
        let (bundle, events, _) = pump_select_with_events(sel, &url, true);

        let cb = events.iter().position(|e| matches!(e, AbiEvent::CoinbaseUnavailable(_)));
        let sel_at = events
            .iter()
            .position(|e| matches!(e, AbiEvent::Selected { .. }))
            .expect("Selected arrives");
        let tree_at =
            events.iter().position(|e| matches!(e, AbiEvent::Tree { .. })).expect("Tree arrives");
        let cb = cb.expect("the degradation event arrives");
        assert!(cb < sel_at, "the degradation precedes the selection it explains: {events:?}");
        assert!(sel_at < tree_at, "{events:?}");

        let AbiEvent::CoinbaseUnavailable(why) = &events[cb] else { unreachable!() };
        assert!(
            why.contains(qumbra_wallet::coinbase::TRANSACTIONS_ONLY),
            "the scan's own token, greppable on both surfaces: {why}"
        );
        assert!(why.contains("HTTP 404"), "the shell's own reason survives: {why}");

        let AbiEvent::Selected { spendable, skipped_spent, mined } = events[sel_at] else {
            unreachable!()
        };
        assert_eq!(
            (spendable, skipped_spent, mined),
            (1, 0, 0),
            "one transaction note, nothing mined visible"
        );
        let AbiEvent::Tree { node_tip, finalized, anchor_root } = &events[tree_at] else {
            unreachable!()
        };
        assert_eq!(*node_tip, to);
        assert!(finalized.is_some(), "the fixture finalizes");
        assert_eq!(anchor_root.len(), 64, "hex root: {anchor_root}");

        // The ruling's other half: the degradation did not stop the spend.
        let mut err: *mut c_char = ptr::null_mut();
        let review = qmb_bundle_review(bundle.as_ptr(), bundle.len(), &mut err);
        assert!(!review.is_null(), "the bundle still builds: {:?}", err_text(err));
        qmb_string_free(review);

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// A clean select narrates Selected + Tree and NO coinbase event — absence of
/// degradation is silence, not a reassurance record a shell must filter out.
#[test]
fn a_clean_select_narrates_selection_and_tree_and_nothing_else() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);
        let (_bundle, events, _) = pump_select_with_events(sel, &url, false);

        assert!(
            !events.iter().any(|e| matches!(e, AbiEvent::CoinbaseUnavailable(_))),
            "a served coinbase stream must not be narrated as a gap: {events:?}"
        );
        assert!(events.iter().any(|e| matches!(e, AbiEvent::Selected { spendable: 1, .. })));
        assert!(events.iter().any(|e| matches!(e, AbiEvent::Tree { .. })));

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// The extensibility rule, exercised as a consumer: an event kind this decoder
/// does not know, spliced into REAL blob bytes from the ABI, is skipped by its
/// length prefix and everything after it still parses — a fifth kind must not
/// break a shipped shell.
#[test]
fn an_unknown_event_kind_is_skipped_and_the_rest_still_parses() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);
        let (_bundle, _events, blobs) = pump_select_with_events(sel, &url, true);
        let real = blobs.iter().find(|b| decode_events(b).len() >= 2).expect("a multi-event blob");
        let known = decode_events(real);

        // Splice a future kind (999, five opaque bytes) in FRONT of the real
        // records and bump the count — what a newer library would hand an
        // older shell.
        let count = u32::from_le_bytes(real[0..4].try_into().unwrap());
        let mut spliced = (count + 1).to_le_bytes().to_vec();
        spliced.extend_from_slice(&999u16.to_le_bytes());
        spliced.extend_from_slice(&5u32.to_le_bytes());
        spliced.extend_from_slice(&[0xAA; 5]);
        spliced.extend_from_slice(&real[4..]);

        let decoded = decode_events(&spliced);
        assert_eq!(decoded[0], AbiEvent::Unknown(999));
        assert_eq!(&decoded[1..], &known[..], "everything after the unknown record survives");

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// 🔴 No key material may ever appear in an event payload — the lock, from the
/// consumer's side: the raw blobs that cross the boundary contain neither the
/// wallet's entropy nor its mnemonic, and no text event quotes either. Counts,
/// heights, one public root, prose — nothing else crosses.
#[test]
fn no_key_material_crosses_in_the_event_stream() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let phrase_ptr = qmb_wallet_reveal_mnemonic(w);
        let phrase = CStr::from_ptr(phrase_ptr).to_str().unwrap().to_string();
        qmb_string_free(phrase_ptr);

        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);
        let (_bundle, events, blobs) = pump_select_with_events(sel, &url, true);
        assert!(!events.is_empty());

        for blob in &blobs {
            assert!(
                !blob.windows(32).any(|win| win == SENDER_ENTROPY),
                "the seed entropy crossed in an event blob"
            );
            let lossy = String::from_utf8_lossy(blob);
            assert!(!lossy.contains(&phrase), "the mnemonic crossed in an event blob");
        }

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// The pre-#432 pump defers narration, it does not destroy it: a select run
/// entirely on bare `qmb_select_step` keeps every event queued, and one
/// `qmb_select_step_events` call afterwards returns them all.
#[test]
fn events_left_by_the_bare_step_are_deferred_not_lost() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);

        // The whole selection over the OLD entry point, coinbase dead.
        loop {
            let mut out: *mut c_char = ptr::null_mut();
            match qmb_select_step(sel, &mut out) {
                1 | 2 => {
                    let path = CStr::from_ptr(out).to_str().unwrap().to_string();
                    qmb_string_free(out);
                    if path.starts_with("/v1/coinbase") {
                        let r = CString::new("HTTP 404: route not served").unwrap();
                        qmb_select_supply_err(sel, r.as_ptr());
                    } else {
                        let body = get(&url, &path).expect("fixture serves");
                        qmb_select_supply(sel, body.as_ptr(), body.len());
                    }
                }
                0 => break,
                rc => panic!("select rc {rc}"),
            }
        }

        let mut out: *mut c_char = ptr::null_mut();
        let mut ev: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        assert_eq!(qmb_select_step_events(sel, &mut out, &mut ev, &mut ev_len), 0);
        assert!(!ev.is_null(), "the queued narration crosses on the first events call");
        let blob = std::slice::from_raw_parts(ev, ev_len).to_vec();
        qmb_dealloc(ev, ev_len);
        let events = decode_events(&blob);
        assert!(events.iter().any(|e| matches!(e, AbiEvent::CoinbaseUnavailable(_))), "{events:?}");
        assert!(events.iter().any(|e| matches!(e, AbiEvent::Selected { .. })), "{events:?}");
        assert!(events.iter().any(|e| matches!(e, AbiEvent::Tree { .. })), "{events:?}");

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
    }
}

/// Narration is not optional on the events codepoint: NULL event out-params
/// are an invalid call, not a permitted opt-out.
#[test]
fn the_events_codepoint_refuses_null_event_out_params() {
    unsafe {
        let (url, to, _server) = serve_chain();
        let w = qmb_wallet_from_entropy(SENDER_ENTROPY.as_ptr());
        let scan = scan_to_done(w, &url, to);
        let sel = select_for_events(w, scan);

        let mut out: *mut c_char = ptr::null_mut();
        let mut ev: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        assert_eq!(qmb_select_step_events(sel, &mut out, ptr::null_mut(), &mut ev_len), -1);
        assert_eq!(qmb_select_step_events(sel, &mut out, &mut ev, ptr::null_mut()), -1);
        assert_eq!(
            qmb_select_step_events(ptr::null_mut(), &mut out, &mut ev, &mut ev_len),
            -1
        );
        // And the refusals consumed nothing: the real pump still works.
        let (_bundle, events, _) = pump_select_with_events(sel, &url, false);
        assert!(events.iter().any(|e| matches!(e, AbiEvent::Selected { .. })));

        qmb_select_free(sel);
        qmb_scan_free(scan);
        qmb_wallet_free(w);
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
