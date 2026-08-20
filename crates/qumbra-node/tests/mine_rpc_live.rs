//! Lab #511 live lane (G4 definition of done).
//!
//! Two legs:
//! 1. The node RPC itself: `GET /v1/mine/template` (gated) then a Keccak-ground
//!    `POST /v1/mine/block` through the real run loop advances the tip.
//! 2. The stage-3 harness over a **real** node (not `DevnetTemplateSource`):
//!    login → job from the node → block-class share → POST → tip advances.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::pow::{satisfies_target_for, KeccakPow, PowEngine};
use qlab_p2p::codec::decode_header;
use qlab_stratum::blob::apply_miner_nonce;
use qlab_stratum::codec::encode_request;
use qlab_stratum::types::{LoginParams, StratumRequest, SubmitParams};
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::mine_rpc::{
    header_hex, rkm_hex, MineBlockWire, MineTemplateWire, TEMPLATE_SERVING_DISABLED,
};
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};
use qumbra_pool::hasher::KeccakShareHasher;
use qumbra_pool::pool::Outgoing;
use qumbra_pool::template::HeldTemplateSource;
use qumbra_pool::{NodeRpcClient, Pool};

fn rig_t2(tag: &str) -> (NodeConfig, GenesisFile, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("qmb_mine_rpc_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let genesis = GenesisFile::new_t2();
    let gpath = base.join("genesis.qmb");
    genesis.write(&gpath).unwrap();
    let keys = genesis.write_committee_key_files(base.join("keys")).unwrap();
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: gpath,
        committee_key_paths: keys,
        mining: false,
        expected_genesis_hash: Some(genesis.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: Some("0100000000000000020000000000000003000000000000000400000000000000".into()),
        template_serving: false,
    };
    (config, genesis, base)
}

fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&raw[..sep])
        .lines()
        .next()
        .unwrap()
        .to_string();
    (status, raw[sep + 4..].to_vec())
}

fn http_post(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&raw[..sep])
        .lines()
        .next()
        .unwrap()
        .to_string();
    (
        status,
        String::from_utf8_lossy(&raw[sep + 4..]).to_string(),
    )
}

fn grind_v5(wire: &MineTemplateWire) -> (qlab_devnet::header::BlockHeader, [u8; 32]) {
    let mut header = qlab_devnet::header::BlockHeader {
        prev: hex32(&wire.prev),
        height: wire.height,
        timestamp: wire.timestamp,
        difficulty: wire.difficulty,
        nonce: 0,
        tx_body_commitment: hex32(&wire.tx_body_commitment),
        aggregate_proof: qlab_devnet::header::AggregateProofSlot,
        epoch_supply_attestation: qlab_devnet::header::EpochSupplyAttestation,
    };
    let pow = KeccakPow;
    for nonce in 0..500_000u64 {
        header.nonce = nonce;
        let hash = pow.pow_hash(GenesisForm::V5, &header, &[]);
        if satisfies_target_for(&hash, header.difficulty, GenesisForm::V5) {
            return (header, hash);
        }
    }
    panic!("no Keccak nonce in 500k tries at difficulty {}", wire.difficulty);
}

fn hex32(s: &str) -> [u8; 32] {
    let v = qumbra_node::genesis::hex_decode(s).expect("hex");
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Gate off → named UNAVAILABLE, not a 404 that invites retrying elsewhere.
#[test]
fn template_serving_off_is_unavailable_by_name() {
    let (config, genesis, base) = rig_t2("gate-off");
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&shutdown);
    let client = std::thread::spawn(move || {
        let (status, body) = http_get(addr, "/v1/mine/template");
        assert!(status.contains("503"), "{status}");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("template-serving-disabled"),
            "UNAVAILABLE token, got {text}"
        );
        assert_eq!(text.trim(), TEMPLATE_SERVING_DISABLED);
        done.store(true, Ordering::SeqCst);
    });
    node.run_until(&shutdown);
    client.join().unwrap();
    let _ = std::fs::remove_dir_all(&base);
}

/// Node-only live path: assemble (no grind) → we grind → POST → tip advances.
#[test]
fn live_template_then_submit_advances_tip() {
    let (mut config, genesis, base) = rig_t2("submit");
    config.template_serving = true;
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    assert_eq!(node.tip_height(), 0);
    node.set_mine_interval(Duration::from_secs(3600));
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&shutdown);
    let client = std::thread::spawn(move || {
        let (status, body) = http_get(addr, "/v1/mine/template");
        assert!(status.contains("200"), "{status} {}", String::from_utf8_lossy(&body));
        let wire: MineTemplateWire = serde_json::from_slice(&body).unwrap();
        assert_eq!(wire.form, "v5");
        assert_eq!(wire.height, 1);
        assert_eq!(wire.nonce, 0);
        let (header, _) = grind_v5(&wire);
        let post = MineBlockWire {
            form: "v5".into(),
            header: header_hex(GenesisForm::V5, &header),
            coinbase: wire.coinbase,
            coinbase_rkm: wire.coinbase_rkm,
            txs: wire.txs,
        };
        let (status, text) = http_post(addr, "/v1/mine/block", &serde_json::to_vec(&post).unwrap());
        assert!(status.contains("202"), "{status} {text}");
        assert!(text.starts_with("accepted "), "{text}");
        done.store(true, Ordering::SeqCst);
    });
    node.run_until(&shutdown);
    client.join().unwrap();
    assert_eq!(node.tip_height(), 1, "POST must take the own-mined ingest path");
    let _ = std::fs::remove_dir_all(&base);
}

/// Stage-3 live-node leg: pool over the real node, not a fictional template.
#[test]
fn e2e_live_node_login_job_submit_advances_tip() {
    let (mut config, genesis, base) = rig_t2("pool-live");
    config.template_serving = true;
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    node.set_mine_interval(Duration::from_secs(3600));
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let url = format!("http://{addr}");
    let shutdown = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&shutdown);
    let client = std::thread::spawn(move || {
        let rpc = NodeRpcClient::parse(&url).unwrap();
        let template = rpc.fetch_template().expect("live template");
        assert_eq!(template.form, GenesisForm::V5);
        assert_eq!(template.header.height, 1);
        assert!(template.body.is_some(), "live template carries the body");
        let pool = Pool::new_with_hasher(
            1,
            Box::new(HeldTemplateSource::new(template.clone())),
            Box::new(KeccakShareHasher),
            [9, 0, 0, 0],
        )
        .unwrap();
        pool.set_submitter(Arc::new(rpc));
        pool.register_account("alice", [1, 0, 0, 0]);
        let mut sid = None;
        let login_line = encode_request(
            &StratumRequest::login(
                1,
                &LoginParams {
                    login: "alice".into(),
                    pass: "x".into(),
                    agent: Some("XMRig/6.21.0 (g4-live)".into()),
                    algo: Some(vec!["rx/0".into()]),
                    rigid: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        let out = pool.handle_line(&mut sid, &login_line).unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("login reply");
        };
        let login = resp.parse_login_result().unwrap();
        let job = &login.job;
        let blob0 = qumbra_pool::hexutil::decode(&job.blob).unwrap();
        let mut found = None;
        for n in 0u32..500_000 {
            let nonce = n.to_le_bytes();
            let mut blob = blob0.clone();
            apply_miner_nonce(&mut blob, &nonce).unwrap();
            let hash = qlab_devnet::hash::keccak256(&blob);
            if qumbra_pool::share::is_block_candidate(
                &hash,
                template.header.difficulty,
                GenesisForm::V5,
            ) {
                found = Some((nonce, hash));
                break;
            }
        }
        let (nonce, hash) = found.expect("Keccak grind found a block");
        let submit = encode_request(
            &StratumRequest::submit(
                2,
                &SubmitParams {
                    id: sid.clone().unwrap(),
                    job_id: job.job_id.clone(),
                    nonce: qumbra_pool::hexutil::encode(&nonce),
                    result: qumbra_pool::hexutil::encode(&hash),
                    algo: Some("rx/0".into()),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let mut s = sid.clone();
        let out = pool.handle_line(&mut s, &submit).unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("submit reply");
        };
        assert!(resp.error.is_none(), "submit {:?}", resp.error);
        done.store(true, Ordering::SeqCst);
    });
    node.run_until(&shutdown);
    client.join().unwrap();
    assert_eq!(node.tip_height(), 1, "pool POST must advance the real node tip");
    let _ = std::fs::remove_dir_all(&base);
}

/// decode_header of a v5 preimage we just served is the same header.
#[test]
fn template_header_decodes_under_v5() {
    let wire = MineTemplateWire {
        form: "v5".into(),
        prev: "11".repeat(32),
        height: 1,
        timestamp: 75,
        difficulty: 256,
        nonce: 0,
        tx_body_commitment: "22".repeat(32),
        seed_hash: "33".repeat(32),
        next_seed_hash: None,
        coinbase: 1,
        coinbase_rkm: rkm_hex(&[1, 2, 3, 4]),
        txs: vec![],
    };
    let header = qlab_devnet::header::BlockHeader {
        prev: hex32(&wire.prev),
        height: 1,
        timestamp: 75,
        difficulty: 256,
        nonce: 0,
        tx_body_commitment: hex32(&wire.tx_body_commitment),
        aggregate_proof: qlab_devnet::header::AggregateProofSlot,
        epoch_supply_attestation: qlab_devnet::header::EpochSupplyAttestation,
    };
    let bytes = qlab_p2p::codec::encode_header(GenesisForm::V5, &header);
    assert_eq!(decode_header(GenesisForm::V5, &bytes).unwrap(), header);
}
