//! The projection against a REAL observer node on a real socket (issues #235, #281).
//!
//! The unit tests decide serialization from constructed snapshots; this one boots the
//! actual composition — a keyless, non-mining `RunningNode` on a fresh devnet-T0
//! genesis — and reads the document back over TCP, because the seam most likely to be
//! wrong is where a node's view becomes bytes a client gets.
//!
//! 🔴 **It also proves the thing #281 exists to fix is a rendering gap and not a
//! plumbing one**: `head3.state` must not be `unavailable` here. `Unavailable` means
//! *this composition does not read head #3*, and if the real composition reported it
//! then no amount of serialization work would put the durable head on the surface.
//!
//! `KeccakPow` + the rehearsal verifier, the same fixtures `qumbra-node`'s own
//! run tests use — RandomX would spend test time buying nothing this test asserts.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use qlab_devnet::pow::KeccakPow;
use qumbra_explorer::config::ExplorerConfig;
use qumbra_explorer::http::{ExplorerServer, HEALTH_PATH};
use qumbra_explorer::json;
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

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).expect("a response body")
}

#[test]
fn a_real_observer_node_serves_the_projection_over_a_real_socket() {
    let (config, genesis, _base) = observer_rig("accept");

    // The posture the binary enforces, checked through the same code path.
    let explorer_cfg = ExplorerConfig::from_toml(
        "node_config = \"/unused-in-this-test\"\nlisten_addr = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    explorer_cfg
        .check_observer(&config)
        .expect("a keyless non-mining config passes");

    let node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("observer node starts without keys and without mining");
    assert_eq!(
        node.tip_height(),
        0,
        "fresh net: the observer sits at genesis"
    );

    // The binary's wiring, inlined: serialize once before binding, then serve.
    let genesis_hash = genesis.hash_hex();
    let live = node.telemetry();
    let page = Arc::new(RwLock::new(json::health(&live, &genesis_hash, 30)));
    let server = ExplorerServer::start("127.0.0.1:0", Arc::clone(&page)).expect("bind");
    let addr = server.addr();

    // 1. The projection, from a live node's own view.
    let resp = get(addr, HEALTH_PATH);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("application/json"), "{resp}");
    let v: serde_json::Value =
        serde_json::from_str(body_of(&resp)).expect("a live node's document parses");
    assert_eq!(v["v"], json::HEALTH_VERSION);
    assert_eq!(
        v["genesis_file_hash"], genesis_hash,
        "the genesis file hash is on the surface"
    );
    assert_eq!(v["chain"]["tip_height"], 0);
    assert!(
        v["supply"].get("coverage").is_some(),
        "supply answers in some state"
    );

    // 2. 🔴 The composition DOES read head #3 — the premise of this whole baton.
    assert_ne!(
        v["finality"]["head3"]["state"], "unavailable",
        "the real composition must read head #3; `unavailable` here would mean the durable \
         head cannot reach this surface at all, which is a plumbing defect and not a \
         serialization one. Document: {v}"
    );
    assert_eq!(
        v["finality"]["head3"]["state"],
        json::health(&live, "x", 30)
            .parse::<serde_json::Value>()
            .map(|p| p["finality"]["head3"]["state"].clone())
            .unwrap_or_default(),
        "and the same snapshot serializes the same way off the wire as on it"
    );

    // 🔴 And a healthy fresh node is SILENT. Measured here rather than assumed: at
    // genesis this composition reports head #3 as `nothing`, and the risk was that
    // head #1 would simultaneously report a height (genesis is finalized as a
    // bootstrap act) — which would make `NothingDurable` fire, i.e. every fresh node
    // on the net publishing DURABLE_ABSENT. It does not: `finalized_height` is absent
    // too, so the verdict is `Agreed` and the document carries no token. Issue #136's
    // rule — a condition every healthy node reports teaches operators to ignore the
    // one that means something — holds on the real composition, not just in theory.
    assert_eq!(
        v["finality"]["head3"]["state"], "nothing",
        "fresh net: read, holds nothing"
    );
    assert!(
        v["finality"]["head1"]["height"].is_null(),
        "and head #1 has nothing either"
    );
    assert_eq!(v["finality"]["agreement"]["divergent"], false);
    assert!(
        v["finality"]["agreement"]["token"].is_null(),
        "a healthy fresh node must publish no alarm token: {v}"
    );

    // 3. /healthz for a supervisor.
    assert!(get(addr, "/healthz").contains("ok"));

    // 4. Nothing tx-shaped exists — now probed under the real `/v1` prefix.
    for probe in ["/v1/tx/deadbeef", "/v1/address/qmb1x", "/tx/deadbeef"] {
        assert!(get(addr, probe).starts_with("HTTP/1.1 404"), "{probe}");
    }

    // 5. The page is gone from this binary (#281): `/` refuses and names what exists.
    let root = get(addr, "/");
    assert!(root.starts_with("HTTP/1.1 404"), "{root}");
    assert!(
        root.contains(HEALTH_PATH),
        "the 404 names the surface that does exist"
    );

    // 6. A re-serialization reaches readers through the swap the run loop performs.
    *page.write().unwrap() = json::health(&node.telemetry(), &genesis_hash, 30);
    assert!(get(addr, HEALTH_PATH).starts_with("HTTP/1.1 200"));

    server.shutdown();
    drop(node);
}
