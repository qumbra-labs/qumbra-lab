//! Lab #483 stage 2 acceptance: **deposit → verify → credit against a devnet,
//! end to end, over real sockets on both sides.**
//!
//! ⚠️ Prove-class (two disclosure proves at the pinned `DISCLOSURE_V1_CFG`) —
//! the CI lane's to run, never a developer machine's (CLAUDE.md: agent
//! sessions run no local cargo test at all).
//!
//! The composition is `recipient_scan.rs`'s chassis (the #188 baton-3
//! acceptance): a [`RunningNode`] over its own admission path and miner —
//! the tx placement is a placeholder proof under [`DevnetRehearsalVerifier`],
//! for that file's unchanged reason (tx-proof verification is orthogonal and
//! tested against real STARKs elsewhere; a real 2×2 here would add ~12 GB to
//! re-test it) — plus the one ingredient that IS this stage's subject and is
//! NOT stubbed anywhere: a real disclosure STARK, proven at the exact config
//! the service verifies at, carried in a real §3 envelope, POSTed to the real
//! `qumbra-credit-ref` HTTP shell, which scans the node over a real socket
//! with the reference light client and decides.
//!
//! One acceptance test on one chain, sectioned (a)–(g), because the node and
//! the two proves are the cost and every section reuses them:
//!
//!   (a) a finalized deposit credits: 200 with the proven claim + committed
//!       coordinates;
//!   (b) the same envelope replayed refuses `already-credited` (409);
//!   (c) a value-tampered envelope refuses `deposit-not-found` (404) — the
//!       claim names money nobody deposited;
//!   (d) a proof-tampered envelope refuses `proof-refused` (422) — the
//!       deposit exists, the proof does not verify against its committed cm;
//!   (e) a claim about someone else's address refuses `not-our-address` (422);
//!   (f) a deposit ABOVE the finalized head refuses `not-finalized` (409),
//!       then credits (200) once the committee finalizes its height —
//!       finalized-is-creditable demonstrated as a transition, not a slogan;
//!   (g) `/v1/status` reports the credited count.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::Hash32;
use qlab_devnet::params_devnet::{CHECKPOINT_CADENCE_BLOCKS, CHECKPOINT_SIGN_HYSTERESIS_BLOCKS};
use qlab_devnet::pow::KeccakPow;
use qlab_disclosure::air::build_disclosure;
use qlab_disclosure::envelope::Envelope;
use qlab_disclosure::packing::addr_commitment;
use qlab_node::rpc::tx_id;
use qlab_node::NodeState;
use qlab_note::hash::digest_bytes;
use qlab_note::kem::generate_keypair;
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_vask::{DISCLOSURE_V1_CFG, DISCLOSURE_V1_LOG_HEIGHT};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use qumbra_credit_ref::http::serve;
use qumbra_credit_ref::{CreditEngine, ExchangeKeys};
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Temp rig — `recipient_scan.rs`'s, verbatim in substance.
fn rig(tag: &str) -> (NodeConfig, GenesisFile, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("qumbra-i483-s2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp dir");
    let genesis = GenesisFile::new_devnet_t0();
    let gpath = base.join("genesis.qmb");
    genesis.write(&gpath).expect("write genesis");
    let keys = genesis.write_committee_key_files(base.join("keys")).expect("write keys");
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: gpath,
        committee_key_paths: keys,
        mining: true,
        expected_genesis_hash: Some(genesis.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: None,
    };
    (config, genesis, base)
}

fn lanes(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

/// A deposit transaction paying `notes` to one recipient `ek`, its committed
/// discovery being the real ML-KEM bundle — `recipient_scan.rs`'s
/// `payment_to`, with caller-chosen notes (a deposit's value and rkm binding
/// are this test's subject, not randomizable). Returns the entry and its
/// statement txid (the envelope's `tx_ref` — advisory on today's wire, real
/// here so the echo the service returns is the honest one).
fn deposit_tx(
    ek: &qlab_note::kem::Ek,
    notes: &[Note],
    nf_seed: u8,
    anchor: Hash32,
    rng: &mut StdRng,
) -> (TxEntry, Hash32) {
    let enc = encrypt_to_recipient(ek, notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    let nullifiers: Vec<Hash32> =
        (0..notes.len()).map(|i| [nf_seed.wrapping_add(i as u8); 32]).collect();
    let fee = posted_fee(ArityBucket::TwoByTwo);
    let txid = tx_id(
        &anchor,
        &nullifiers,
        &commitments,
        ArityBucket::TwoByTwo.logical_actions(),
        fee,
    );
    let tx = TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic { anchor, nullifiers, commitments, bucket: ArityBucket::TwoByTwo, fee },
        &[enc.bundle],
        &enc.payloads,
    );
    (tx, txid)
}

/// The depositor's side of the ratified out-of-band flow: prove the
/// disclosure for a note they sent and pack the §3 envelope, at the exact
/// config the service pins.
fn depositor_envelope(addr: &Address, note: &Note, txid: Hash32) -> Vec<u8> {
    let inst = build_disclosure(
        DISCLOSURE_V1_LOG_HEIGHT,
        note.value,
        &addr.rkm_lanes(),
        &note.rho,
        &note.rseed,
        &addr.to_raw_bytes(),
    );
    Envelope::create(&inst, txid, 0, &DISCLOSURE_V1_CFG).to_bytes()
}

/// Raw-socket HTTP client — the shell's consumer is a foreign stack, so the
/// test speaks to it the way one would: bytes over a stream, no shared code
/// with the server it is testing.
fn post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    write!(s, "POST {path} HTTP/1.1\r\nhost: t\r\ncontent-length: {}\r\n\r\n", body.len())
        .expect("write head");
    s.write_all(body).expect("write body");
    read_response(s)
}

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    write!(s, "GET {path} HTTP/1.1\r\nhost: t\r\n\r\n").expect("write");
    read_response(s)
}

fn read_response(mut s: TcpStream) -> (u16, String) {
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 =
        text.split(' ').nth(1).and_then(|c| c.parse().ok()).expect("status line");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_deposit_credits_once_after_finality_and_every_refusal_names_itself() {
    let mut rng = StdRng::seed_from_u64(0x4832);

    // The exchange's deposit identity — derived through the lib's own
    // constructor, cross-checked against the wallet derivation the depositor
    // sees, so the two sides cannot be agreeing by construction.
    let seed = [21u64, 22, 23, 24];
    let d = Diversifier::from_bytes([0x2c; 16]);
    let exchange_addr = Wallet::from_seed_lanes(seed).address(d);
    let keys = ExchangeKeys::from_seed_lanes(seed, d);
    assert_eq!(
        keys.addr_commitment(),
        addr_commitment(&exchange_addr.to_raw_bytes()),
        "one derivation of the address commitment on both sides"
    );
    let ek = exchange_addr.encapsulation_key().expect("valid ek");

    // The node, its own genesis finalized (the anchor discipline).
    let (config, genesis, _base) = rig("credit");
    let mut node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("node starts");
    node.set_mine_interval(Duration::ZERO);
    node.try_checkpoint();
    assert_eq!(node.finalized_height(), Some(0), "genesis finalized");
    let anchor = node.state().commitment_root();

    // Deposit 1 (the depositor pays the exchange's address — note rkm IS the
    // address's, which is what makes the disclosure provable), plus a
    // stranger's payment so "found ours" is a discrimination, not a count.
    let dep1 = Note { value: 750_000, rkm: exchange_addr.rkm_lanes(), rho: [1, 2, 3, 4], rseed: [5, 6, 7, 8] };
    let (tx1, txid1) = deposit_tx(&ek, std::slice::from_ref(&dep1), 0x51, anchor, &mut rng);
    let stranger = generate_keypair(&mut rng);
    let snote = Note { value: 750_000, rkm: lanes(&mut rng), rho: lanes(&mut rng), rseed: lanes(&mut rng) };
    let (stx, _) = deposit_tx(&stranger.ek, std::slice::from_ref(&snote), 0x71, anchor, &mut rng);
    assert!(node.submit_local_tx(tx1), "deposit admitted");
    assert!(node.submit_local_tx(stx), "stranger's admitted");
    assert!(node.try_mine(), "mined");
    assert_eq!(node.tip_height(), 1);

    // Finality advances on the checkpoint cadence grid, not per block: genesis
    // (slot 0, waived as a bootstrap act) and then 8, 16, … — and a slot signs
    // only once the tip clears the #269 sign-hysteresis. So the deposit's
    // height finalizes when slot 8 does. Mine filler past the hysteresis, then
    // let the committee catch up (the house idiom —
    // `run.rs::restart_never_equivocates_through_the_run_path`).
    let slot1 = CHECKPOINT_CADENCE_BLOCKS;
    while node.tip_height() < slot1 + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
        assert!(node.try_mine(), "filler mined");
    }
    node.try_checkpoint();
    assert_eq!(
        node.finalized_height(),
        Some(slot1),
        "deposit height finalized (slot 8 covers height 1)"
    );

    // The depositor's envelope — the first of this test's two real proves.
    let env1 = depositor_envelope(&exchange_addr, &dep1, txid1);

    // Both services up: the node's discovery endpoint, then the crediting
    // shell over it.
    let bound = node.start_discovery_endpoint("127.0.0.1:0").expect("bind discovery");
    let upstream = format!("http://{bound}");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind service");
    let svc = listener.local_addr().expect("svc addr");
    std::thread::spawn(move || serve(listener, CreditEngine::new(keys), upstream));

    // (a) The finalized deposit credits, with the proven claim and the
    // COMMITTED coordinates (the chain's name for the output, not the
    // claim's advisory locator).
    let (st, body) = post(svc, "/v1/credit", &env1);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"credited\""), "{body}");
    assert!(body.contains(&format!("\"value\":{}", dep1.value)), "{body}");
    assert!(body.contains(&format!("\"tx_ref\":\"{}\"", hex(&txid1))), "{body}");
    assert!(body.contains("\"height\":1,"), "{body}");
    assert!(body.contains(&format!("\"cm\":\"{}\"", hex(&digest_bytes(&dep1.commitment())))), "{body}");
    assert!(body.contains(&format!("\"finalized_height\":{slot1}")), "{body}");

    // (b) Replay: the same deposit credits once.
    let (st, body) = post(svc, "/v1/credit", &env1);
    assert_eq!(st, 409, "{body}");
    assert!(body.contains("\"refusal\":\"already-credited\""), "{body}");

    // (c) A value-tampered claim names money nobody deposited: parse passes,
    // the address is ours, the scan finds no such value.
    let mut tampered_value = env1.clone();
    tampered_value[34] ^= 1; // first byte of value (ver 1 ‖ claim 1 ‖ tx_ref 32)
    let (st, body) = post(svc, "/v1/credit", &tampered_value);
    assert_eq!(st, 404, "{body}");
    assert!(body.contains("\"refusal\":\"deposit-not-found\""), "{body}");

    // (d) A proof-tampered envelope: the deposit exists (value matches), the
    // proof does not verify against its committed cm.
    let mut tampered_proof = env1.clone();
    let n = tampered_proof.len();
    tampered_proof[n - 7] ^= 0xff;
    let (st, body) = post(svc, "/v1/credit", &tampered_proof);
    assert_eq!(st, 422, "{body}");
    assert!(body.contains("\"refusal\":\"proof-refused\""), "{body}");

    // (e) A claim about someone else's address refuses before any chain
    // contact — hand-framed envelope (garbage proof; it must never get that
    // far) naming a commitment that is not the exchange's.
    let mut foreign = vec![0x01, 0x01];
    foreign.extend_from_slice(&[0x11u8; 32]);
    foreign.extend_from_slice(&750_000u64.to_le_bytes());
    foreign.extend_from_slice(&[0xab; 32]); // not our addr_commitment
    foreign.push(0);
    foreign.push(64);
    foreign.extend_from_slice(&[0xEE; 64]);
    let (st, body) = post(svc, "/v1/credit", &foreign);
    assert_eq!(st, 422, "{body}");
    assert!(body.contains("\"refusal\":\"not-our-address\""), "{body}");

    // (f) Finality is a gate, shown as a transition: a second deposit mined
    // ABOVE the finalized head refuses not-finalized, then credits once the
    // committee's next cadence slot covers its height. (The test's second and
    // last prove.)
    let anchor2 = node.state().commitment_root();
    assert!(node.state().is_valid_anchor(&anchor2), "current root is an anchor");
    let dep2 = Note { value: 33_000, rkm: exchange_addr.rkm_lanes(), rho: [9, 10, 11, 12], rseed: [13, 14, 15, 16] };
    let (tx2, txid2) = deposit_tx(&ek, std::slice::from_ref(&dep2), 0x61, anchor2, &mut rng);
    assert!(node.submit_local_tx(tx2), "second deposit admitted");
    assert!(node.try_mine(), "mined above finality");
    let dep2_height = node.tip_height();
    assert_eq!(dep2_height, slot1 + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS + 1);
    assert_eq!(node.finalized_height(), Some(slot1), "deposit 2 NOT finalized yet");

    let env2 = depositor_envelope(&exchange_addr, &dep2, txid2);
    let (st, body) = post(svc, "/v1/credit", &env2);
    assert_eq!(st, 409, "{body}");
    assert!(body.contains("\"refusal\":\"not-finalized\""), "{body}");

    let slot2 = 2 * CHECKPOINT_CADENCE_BLOCKS;
    while node.tip_height() < slot2 + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
        assert!(node.try_mine(), "filler mined");
    }
    node.try_checkpoint();
    assert_eq!(node.finalized_height(), Some(slot2), "committee catches up past the deposit");
    let (st, body) = post(svc, "/v1/credit", &env2);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(&format!("\"height\":{dep2_height},")), "{body}");
    assert!(body.contains(&format!("\"finalized_height\":{slot2}")), "{body}");

    // (g) The status surface counts what happened.
    let (st, body) = get(svc, "/v1/status");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"credited\":2"), "{body}");
    assert!(body.contains(&hex(&addr_commitment(&exchange_addr.to_raw_bytes()))), "{body}");
}
