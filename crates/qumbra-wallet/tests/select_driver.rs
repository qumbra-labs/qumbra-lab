//! The caller-pumped phase-1 driver's own pins (lab #399) — the #358 test
//! discipline applied to selection: suspension across separately invoked
//! steps, misuse as a fault, transport failure and garbage as NAMED refusals,
//! and the verdict gate that supplying outcomes must not make skippable.
//!
//! The fixture is `select_goldens.rs`'s (each test file carries its own —
//! house pattern): a real chain in a `MemNode`, the deployed `DiscoveryServer`
//! over a real socket, no STARK anywhere, debug-runnable.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, ScanConfig, ScanOutcome, Unopened, UnopenedOutput};
use qlab_note::kem::Dk;
use qlab_cbserver::tree::CommitmentTree;
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
use qumbra_wallet::driver::{SelectDriver, SelectStep};
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB

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

/// A minimal one-shot GET, body only — the pump's transport in these tests.
fn get(base: &str, path: &str) -> Result<Vec<u8>, String> {
    let host = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header/body split")?;
    Ok(raw[split + 4..].to_vec())
}

struct Fixture {
    url: String,
    wallet: Wallet,
    recipient: qlab_wallet::address::Address,
    dk: Dk,
    to: u64,
    _server: DiscoveryServer,
}

impl Fixture {
    /// A fresh completed scan — `ScanOutcome` is deliberately not `Clone`.
    fn outcomes(&self) -> Vec<(u64, ScanOutcome)> {
        let mut rng = StdRng::from_seed([0x77; 32]);
        let outcome =
            light_client_scan(&self.url, &self.dk, 0, self.to, ScanConfig::default(), &mut rng)
                .expect("the fixture scan runs");
        assert_eq!(outcome.notes.len(), 1, "the grant is detected");
        vec![(0, outcome)]
    }
}

fn fixture() -> Fixture {
    let mut rng = StdRng::from_seed([0x55; 32]);
    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([41u8; 32]), 0);
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([42u8; 32]), 0);
    let sender_d = sender.diversifier_at_index(0);
    let sender_kp = sender.diversified_keypair(&sender_d);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor0 = node.commitment_root();

    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(sender_d),
        rho: [0xC1, 0xC2, 0xC3, 0xC4],
        rseed: [0xD1, 0xD2, 0xD3, 0xD4],
    };
    mine(
        &mut node,
        &mut tip,
        vec![payment(&sender_kp.ek, &[granted], vec![[0x71; 32], [0x72; 32]], anchor0, &mut rng)],
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

    Fixture {
        url,
        wallet: sender,
        recipient: recipient.address_at_index(0),
        dk: sender_kp.dk,
        to: tip.height,
        _server: server,
    }
}

fn new_driver(f: &Fixture) -> SelectDriver {
    SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        AMOUNT,
        None,
        f.outcomes(),
        CommitmentTree::new(),
        f.to,
    )
}

/// The whole point of the inversion: every `Need` can be answered in a
/// separately invoked call, with the driver (and the caller's rng) suspended
/// in between — and the bundle that comes out carries the right facts.
#[test]
fn the_driver_survives_suspension_between_separately_invoked_steps() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);

    let mut hops = 0usize;
    let bundle = loop {
        match driver.step(&mut rng) {
            SelectStep::Need { path, .. } => {
                hops += 1;
                assert!(hops < 64, "the pump does not converge");
                // Each response arrives in its own call — the suspension shape.
                driver.supply(get(&f.url, &path));
            }
            SelectStep::Done(bundle) => break bundle,
            SelectStep::Failed(e) => panic!("phase 1 failed: {e}"),
        }
    };
    assert_eq!(bundle.amount(), AMOUNT);
    assert_eq!(bundle.fee(), posted_fee(ArityBucket::TwoByTwo));
    assert_eq!(bundle.change_value(), GRANT - AMOUNT - bundle.fee());
    assert!(bundle.used_dummy());
    assert_eq!(bundle.recipient_short(), f.recipient.short().encode());
    assert!(driver.tree().is_some(), "the caught-up tree is exposed for the caller's cache");
}

/// A response nobody asked for is a fault, not a scan — the driver's own rule,
/// same as the scan driver's.
#[test]
fn an_unrequested_response_is_a_fault() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    driver.supply(Ok(b"unrequested".to_vec()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => assert!(e.contains("without requesting"), "{e}"),
        _ => panic!("an unrequested response must be a fault"),
    }
}

/// A transport failure surfaces as the same named refusal the synchronous
/// flow produces — never a silent stop.
#[test]
fn a_transport_failure_is_the_named_refusal() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    let SelectStep::Need { path, .. } = driver.step(&mut rng) else {
        panic!("the first step asks for the nullifier stream")
    };
    assert!(path.starts_with("/v1/nullifiers"), "{path}");
    driver.supply(Err("the network is unreachable".into()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => {
            assert!(e.contains("GET /v1/nullifiers"), "{e}");
            assert!(
                e.contains("refusing to select inputs this wallet may already have spent"),
                "{e}"
            );
        }
        _ => panic!("a dead endpoint must fail by name"),
    }
}

/// 200-with-garbage is refused as a decode failure by name, not believed.
#[test]
fn garbage_bytes_fail_by_name() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    let SelectStep::Need { .. } = driver.step(&mut rng) else { panic!("need first") };
    driver.supply(Ok(b"<html>404 not found</html>".to_vec()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => assert!(e.contains("did not decode"), "{e}"),
        _ => panic!("garbage must be refused"),
    }
}

/// Handing outcomes to the driver must NOT make the partial-knowledge refusal
/// skippable: an Incomplete scan is refused before a single byte is fetched.
#[test]
fn the_verdict_gate_is_not_skippable() {
    let f = fixture();
    let mut incomplete = f.outcomes();
    incomplete[0].1.unopened.push(UnopenedOutput {
        height: 1,
        tx_index: 0,
        recipient_index: 0,
        output_index: 1,
        cm: [0u8; 32],
        why: Unopened::PayloadMissing,
    });
    let mut driver = SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        AMOUNT,
        None,
        incomplete,
        CommitmentTree::new(),
        f.to,
    );
    let mut rng = StdRng::from_seed([0x66; 32]);
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => {
            assert!(e.contains("refusing to build a spend on partial knowledge"), "{e}")
        }
        _ => panic!("an incomplete scan must refuse before any fetch"),
    }
}
