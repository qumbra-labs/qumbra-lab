//! Lab #831 W3a (ruling on Q-W3-1, the ffi finding): a deposit made from the
//! CLI is a burn sealed to the depositor's own key, so the SAME seed opened in
//! a native shell detects and opens it too — and the light-client scan checks
//! no `rkm`. Every ffi scan path must therefore set it aside, never count it.
//!
//! The chain: one 10 QMB grant to the ABI wallet's address 0, and one 3 QMB
//! burn to `rkm_burn(1)` sealed to that same address's key, served by the
//! deployed `DiscoveryServer` with a V6 `/v1/l2` naming L2 1. No STARK.

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
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_ffi::*;
use qumbra_node::discovery_server::{
    l2_route_body, AnchorsView, DiscoveryServer, DiscoveryView, FormView, LeavesView, RegistryView, SubmitRequest,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ENTROPY: [u8; 32] = [83u8; 32];
const GRANT: u64 = 1_000_000_000;
const BURN: u64 = 300_000_000;

struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
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

fn serve() -> (String, u64, DiscoveryServer) {
    let mut rng = StdRng::from_seed([0x83; 32]);
    let w = Wallet::from_master_seed(&MasterSeed::from_entropy(ENTROPY), 0);
    let d = w.diversifier_at_index(0);
    let ek = w.diversified_keypair(&d).ek;

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor = node.commitment_root();
    let grant = Note { value: GRANT, rkm: w.rkm(d), rho: [1, 2, 3, 4], rseed: [5, 6, 7, 8] };
    // The deposit as `deposit` makes it: paid to the burn, sealed to self.
    let burn = Note { value: BURN, rkm: qlab_ledger::deposits::burn_rkm(1), rho: [9, 10, 11, 12], rseed: [13; 4] };
    let tx = |note: Note, nf: u8, rng: &mut StdRng| {
        let enc = encrypt_to_recipient(&ek, &[note], rng);
        TxEntry::new(
            b"proof-placeholder".to_vec(),
            TxPublic {
                anchor,
                nullifiers: vec![[nf; 32], [nf + 1; 32]] as Vec<Hash32>,
                commitments: enc.bundle.entries.iter().map(|e| e.cm).collect(),
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
            &[enc.bundle],
            &enc.payloads,
        )
    };
    let txs = vec![tx(grant, 0x61, &mut rng), tx(burn, 0x71, &mut rng)];
    let height = tip.height + 1;
    let body = BlockBody::from_single_payee(txs, coinbase(height), [0xBE, 0xEF, 1, 2]);
    let header = BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AnyTx).expect("block applies");
    node.finalize(hash).expect("finalize");
    tip = header;

    let mut view = DiscoveryView::default();
    view.refresh(node.chain());
    let (submit, _rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let v6 = qumbra_node::genesis_v6::GenesisFileV6::new_rehearsal();
    let server = DiscoveryServer::start_with_mine(
        "127.0.0.1:0",
        Arc::new(Mutex::new(Arc::new(view))),
        Arc::new(Mutex::new(Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() }))),
        Arc::new(Mutex::new(Arc::new(AnchorsView { encoded: anchor_set(&node).to_bytes() }))),
        submit,
        None,
        Arc::new(Mutex::new(Arc::new(RegistryView::default()))),
        Arc::new(FormView { l2: Some(l2_route_body(&v6, None)), ..FormView::default() }),
    )
    .expect("bind");
    (format!("http://{}", server.addr()), tip.height, server)
}

/// The synchronous report names the burn a pending deposit to L2 1 and
/// counts only the grant; the pumped scan (no `/v1/l2` step) still sets it
/// aside, so its spendable total is the grant's too.
#[test]
fn a_self_sealed_burn_is_a_pending_deposit_on_every_ffi_scan_path_and_never_balance() {
    let (url, tip, _server) = serve();
    unsafe {
        let w = qmb_wallet_from_entropy(ENTROPY.as_ptr());
        assert!(!w.is_null());
        let curl = CString::new(url.clone()).unwrap();
        let indices: [u64; 1] = [0];
        let seed = [3u8; 32];
        let out = qmb_wallet_scan_report(w, curl.as_ptr(), 0, tip, indices.as_ptr(), 1, seed.as_ptr());
        assert!(!out.is_null());
        let report = CStr::from_ptr(out).to_str().unwrap().to_string();
        qmb_string_free(out);
        assert!(report.contains(&format!("TOTAL spendable: {GRANT} bessel")), "{report}");
        assert!(report.contains(&format!("pending deposit: {BURN} bessel to L2 1")), "{report}");

        // The pumped scan: the same notes set aside, the same total.
        let s = qmb_scan_new(w, curl.as_ptr(), 0, tip, indices.as_ptr(), 1, seed.as_ptr());
        assert!(!s.is_null());
        let pumped = loop {
            let mut o: *mut c_char = ptr::null_mut();
            match qmb_scan_step(s, &mut o) {
                1 => {
                    let path = CStr::from_ptr(o).to_str().unwrap().to_string();
                    qmb_string_free(o);
                    let body = get(&url, &path).expect("the fixture serves it");
                    qmb_scan_supply(s, body.as_ptr(), body.len());
                }
                0 => {
                    let r = CStr::from_ptr(o).to_str().unwrap().to_string();
                    qmb_string_free(o);
                    break r;
                }
                rc => panic!("scan rc {rc}"),
            }
        };
        qmb_scan_free(s);
        assert!(pumped.contains(&format!("TOTAL spendable: {GRANT} bessel")), "{pumped}");
        qmb_wallet_free(w);
    }
}
