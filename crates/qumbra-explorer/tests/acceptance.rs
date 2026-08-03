//! The page against a REAL observer node on a real socket (issue #235).
//!
//! The unit tests decide rendering from constructed snapshots; this one boots the
//! actual composition — a keyless, non-mining `RunningNode` on a fresh devnet-T0
//! genesis — and reads the page back over TCP, because the seam most likely to be
//! wrong is where a node's view becomes bytes a browser gets.
//!
//! `KeccakPow` + the rehearsal verifier, the same fixtures `qumbra-node`'s own
//! run tests use — RandomX would spend test time buying nothing this test asserts.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use qlab_devnet::pow::KeccakPow;
use qumbra_explorer::config::ExplorerConfig;
use qumbra_explorer::http::ExplorerServer;
use qumbra_explorer::view;
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::RunningNode;
use qumbra_node::verifier::DevnetRehearsalVerifier;

/// A keyless observer rig: temp data dir + genesis file + a config holding NO
/// committee keys and mining = false. Mirrors `qumbra-node`'s test `rig`, minus
/// everything an observer must not have.
fn observer_rig(tag: &str) -> (NodeConfig, GenesisFile, PathBuf) {
    let base = std::env::temp_dir().join(format!("qmb_explorer_{tag}"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let genesis = GenesisFile::new_devnet_t0();
    let gpath = base.join("genesis.qmb");
    genesis.write(&gpath).unwrap();
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: gpath,
        committee_key_paths: vec![],
        mining: false,
        expected_genesis_hash: Some(genesis.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: None,
    };
    (config, genesis, base)
}

fn get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
}

#[test]
fn a_real_observer_node_serves_the_page_over_a_real_socket() {
    let (config, genesis, _base) = observer_rig("accept");

    // The posture the binary enforces, checked through the same code path.
    let explorer_cfg = ExplorerConfig::from_toml(
        "node_config = \"/unused-in-this-test\"\nlisten_addr = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    explorer_cfg.check_observer(&config).expect("a keyless non-mining config passes");

    let node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("observer node starts without keys and without mining");
    assert_eq!(node.tip_height(), 0, "fresh net: the observer sits at genesis");

    // The binary's wiring, inlined: render once before binding, then serve.
    let genesis_hash = genesis.hash_hex();
    let page = Arc::new(RwLock::new(view::render(&node.telemetry(), &genesis_hash, 30)));
    let server = ExplorerServer::start("127.0.0.1:0", Arc::clone(&page)).expect("bind");
    let addr = server.addr();

    // 1. The page, from a live node's own view.
    let resp = get(addr, "/");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("Qumbra chain health"), "title");
    assert!(resp.contains(&genesis_hash), "the genesis file hash is on the page");
    assert!(resp.contains("tip height"), "chain section");
    assert!(resp.contains("Supply attestation"), "supply section renders in some state");
    assert!(resp.contains("deliberately <strong>not</strong> a transaction explorer"));

    // 2. /healthz for a supervisor.
    assert!(get(addr, "/healthz").contains("ok"));

    // 3. Nothing tx-shaped exists.
    assert!(get(addr, "/tx/deadbeef").starts_with("HTTP/1.1 404"));

    // 4. A tip movement reaches readers through the swap the run loop performs.
    let after = view::render(&node.telemetry(), &genesis_hash, 30);
    *page.write().unwrap() = after;
    assert!(get(addr, "/").starts_with("HTTP/1.1 200"));

    server.shutdown();
    drop(node);
}
