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
use std::sync::{Arc, Mutex, RwLock};

use qlab_devnet::pow::KeccakPow;
use qumbra_explorer::config::ExplorerConfig;
use qumbra_explorer::http::{ExplorerServer, Surfaces, HEALTH_PATH, TXLIST_PATH};
use qumbra_explorer::blocks::BlocksView;
use qumbra_explorer::names::NameEventsView;
use qumbra_explorer::json;
use qumbra_explorer::txlist::{self, BlockTxs, Next, TxFacts, TxListPage, TxListView};
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
    // …including the transaction-existence projection, taken off this node's own
    // chain store through the same call `main.rs` makes.
    let txlist_view = Arc::new(Mutex::new(Arc::new(TxListView::default())));
    assert!(
        txlist::refresh_shared(&txlist_view, node.state().chain()),
        "the first projection runs against a real chain store"
    );
    let server = ExplorerServer::start(
        "127.0.0.1:0",
        Surfaces {
            health: Arc::clone(&page),
            txlist: Arc::clone(&txlist_view),
            blocks: Arc::new(Mutex::new(Arc::new(BlocksView::default()))),
            names: Arc::new(Mutex::new(Arc::new(NameEventsView::default()))),
        },
    )
    .expect("bind");
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

    // 7. 🔴 The transaction-existence view, off the SAME real node — and on a fresh
    //    net the answer is the one that is easiest to get wrong: the range IS
    //    covered and it holds no transactions. An empty list with `covered_to`
    //    absent would have been "I looked at nothing", and a reader cannot be left
    //    to guess which of the two it got.
    let resp = get(addr, &format!("{TXLIST_PATH}?from=0&to=100"));
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let v: serde_json::Value =
        serde_json::from_str(body_of(&resp)).expect("a live node's txlist document parses");
    assert_eq!(v["v"], txlist::TXLIST_VERSION);
    assert_eq!(v["tip_height"], 0, "fresh net: genesis is the tip");
    assert_eq!(
        v["range"]["covered_to"], 0,
        "covered up to the tip — 'no transactions here', not 'I did not look'"
    );
    assert_eq!(v["blocks"].as_array().unwrap().len(), 0);
    assert_eq!(
        v["boundary"],
        txlist::BOUNDARY_SENTENCE,
        "D3 travels with the data so the page cannot render the list without it"
    );

    // 8. 🔴 D2 over a real socket on the real composition: nothing by id exists.
    for probe in [
        "/v1/txlist/5a5a5a5a",
        "/v1/tx/5a5a5a5a",
        "/v1/txlist/tx/5a5a5a5a",
    ] {
        let r = get(addr, probe);
        assert!(r.starts_with("HTTP/1.1 404"), "{probe}: {r}");
        assert!(
            body_of(&r).contains("deliberately NO lookup"),
            "{probe} must say the refusal is a decision: {r}"
        );
    }

    server.shutdown();
    drop(node);
}

/// The paging half, end to end over a real socket, against a chain shaped like the
/// live one: transaction blocks at 4913 / 5398 / 5406 / 5417 / 5924 with thousands
/// of empty heights around and between them.
///
/// 🔴 This is the test that would have caught lab #309. The first two pages of this
/// range are **empty lists**, and a client that treated an empty list as "the chain
/// has no transactions" would stop there and report `complete` over 5 transactions
/// it never saw. The loop below reads the served coverage instead, and it is
/// cap-agnostic: it never compares a block count against a bound it compiled in.
///
/// The five heights are the live net's, taken from the decision brief and lab #309's
/// record. They are used here as a **shape** — a real range where transactions are
/// sparse and clustered — and this test asserts nothing about the live chain.
#[test]
fn the_client_pages_a_live_shaped_chain_off_a_real_socket_and_finds_a_pasted_id() {
    let live = [4913u64, 5398, 5406, 5417, 5924];
    let view = TxListView {
        blocks: live
            .iter()
            .enumerate()
            .map(|(i, h)| BlockTxs {
                height: *h,
                txs: vec![TxFacts {
                    txid: [0x10 + i as u8; 32],
                    wire_bytes: 151_392,
                    fee: 1_000_000,
                    nullifiers: 2,
                    commitments: 2,
                }],
            })
            .collect(),
        tip_height: 6000,
        tip_hash: Some([0xfe; 32]),
    };

    let page = Arc::new(RwLock::new("{}".to_string()));
    let slot = Arc::new(Mutex::new(Arc::new(view)));
    let server = ExplorerServer::start(
        "127.0.0.1:0",
        Surfaces {
            health: page,
            txlist: Arc::clone(&slot),
            blocks: Arc::new(Mutex::new(Arc::new(BlocksView::default()))),
            names: Arc::new(Mutex::new(Arc::new(NameEventsView::default()))),
        },
    )
    .expect("bind");
    let addr = server.addr();

    // The client half: fetch, decode, decide, repeat.
    let want_to = 6000u64;
    let mut from = 0u64;
    let mut pages: Vec<TxListPage> = Vec::new();
    let mut fetches = 0;
    loop {
        fetches += 1;
        assert!(fetches < 50, "the paging loop must terminate");
        let resp = get(addr, &format!("{TXLIST_PATH}?from={from}&to={want_to}"));
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let p = page_from_json(body_of(&resp));
        let next = txlist::next_after(&p, want_to);
        pages.push(p);
        match next {
            Next::Fetch(h) => from = h,
            Next::Done => break,
            other => panic!("unexpected {other:?} on page {fetches}"),
        }
    }

    assert_eq!(fetches, 6, "6001 heights at 1024 per page");
    assert!(
        pages[0].blocks.is_empty() && pages[1].blocks.is_empty(),
        "🔴 the first two pages are empty lists — the exact bytes a #309-shaped \
         client would have read as 'no transactions on this chain'"
    );
    let heights: Vec<u64> = pages
        .iter()
        .flat_map(|p| p.blocks.iter().map(|b| b.height))
        .collect();
    assert_eq!(heights, live.to_vec(), "reassembled, in order, once each");

    // And a pasted id resolves against the fetched pages — with no request that
    // names it (D2). The 404s asserted above are the other half of that claim.
    let needle = txlist::hex32(&[0x12; 32]);
    match txlist::match_txid(&pages, &needle) {
        txlist::MatchOutcome::Found(hits) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].height, 5406, "the third live block");
        }
        other => panic!("expected a hit, got {other:?}"),
    }
    assert_eq!(
        txlist::match_txid(&pages, &"ab".repeat(32)),
        txlist::MatchOutcome::NotInFetchedPages,
        "and an id nobody fetched is 'not in what I have', never 'does not exist'"
    );

    server.shutdown();
}

/// Decode a served document the way the front end does — this is the **reader**
/// direction of the contract, exercised against real bytes off a socket rather
/// than against a value the producer handed us.
fn page_from_json(s: &str) -> TxListPage {
    let v: serde_json::Value = serde_json::from_str(s).expect("served bytes are JSON");
    assert_eq!(
        v["v"].as_u64().expect("a version") as u32,
        txlist::TXLIST_VERSION,
        "reject-unknown: a reader that does not know the version renders nothing"
    );
    TxListPage {
        from: v["range"]["from"].as_u64().expect("from"),
        to: v["range"]["to"].as_u64().expect("to"),
        tip_height: v["tip_height"].as_u64().expect("tip_height"),
        covered_to: v["range"]["covered_to"].as_u64(),
        blocks: v["blocks"]
            .as_array()
            .expect("blocks")
            .iter()
            .map(|b| {
                let txs: Vec<TxFacts> = b["txs"]
                    .as_array()
                    .expect("txs")
                    .iter()
                    .map(|t| {
                        let hex = t["txid"].as_str().expect("txid");
                        let mut txid = [0u8; 32];
                        for (i, byte) in txid.iter_mut().enumerate() {
                            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
                        }
                        TxFacts {
                            txid,
                            wire_bytes: t["wire_bytes"].as_u64().expect("wire_bytes"),
                            fee: t["fee"].as_u64().expect("fee"),
                            nullifiers: t["nullifiers"].as_u64().expect("nullifiers") as u32,
                            commitments: t["commitments"].as_u64().expect("commitments") as u32,
                        }
                    })
                    .collect();
                assert_eq!(
                    b["tx_count"].as_u64().expect("tx_count") as usize,
                    txs.len(),
                    "the block's stated count and its list agree"
                );
                BlockTxs {
                    height: b["height"].as_u64().expect("height"),
                    txs,
                }
            })
            .collect(),
    }
}
