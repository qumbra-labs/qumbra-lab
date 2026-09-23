//! **B5's done-when** (lab #714): an Annulet node serves an L2 transaction's
//! discovery by projection, and the wallet-side decode opens it.
//!
//! A producer on the fixture genesis admits a transaction whose two outputs
//! are **encrypted to a wallet key** at the L2 width (128-B payloads), seals
//! it into block 1, and serves it. Over HTTP the client reads `/v1/compact`
//! (the width-free group prefix — height 0 is groupless) and
//! `/v1/block/1/tx/0/full` (the 128-B payloads), and
//! `qlab_cbserver::client::open_served_l2` opens both `L2Note`s, whose
//! commitments are the served ones. `/v1/genesis/notes` serves the fixture's
//! genesis notes as `GenesisPlaintext`s under the genesis hash. No proves.

use std::io::{Read, Write};
use std::net::TcpStream;

use qlab_devnet::annulet::{L2ShapeTag, L2Surface};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState;
use qlab_note::hash::digest_bytes;
use qlab_note::l2note::{GenesisPlaintext, L2Note, L2_PAYLOAD_LEN};
use qumbra_node::annulet_genesis::{AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};
use qumbra_node::config::NodeConfig;
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};
use rand::SeedableRng;

fn get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block") + 4;
    let status: u16 = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, raw[split..].to_vec())
}

fn producer(tag: &str, g: &AnnuletGenesisFile) -> RunningNode<KeccakPow, DevnetRehearsalVerifier> {
    let base = std::env::temp_dir().join(format!("qmb_b5_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("data")).unwrap();
    let kf = SequencerKeyFile { seed_hex: "5e".repeat(32), note: "fixture sequencer key (test)".into() };
    std::fs::write(base.join("data").join(SEQUENCER_KEY_FILE), kf.to_toml()).unwrap();
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: base.join("genesis.qmb"),
        committee_key_paths: vec![],
        mining: false,
        expected_genesis_hash: Some(g.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: None,
        template_serving: false,
    };
    RunningNode::start_annulet(&config, g, KeccakPow, DevnetRehearsalVerifier).expect("starts")
}

fn l2_note(seed: u64) -> L2Note {
    let lane = |k: u64| core::array::from_fn::<u64, 4, _>(|i| seed ^ (k << 12) ^ (i as u64 + 1));
    L2Note { value: 10 + seed, asset: 0, rkm: lane(1), rho: lane(2), rseed: lane(3) }
}

#[test]
fn an_annulet_output_is_served_by_projection_and_opened_by_the_wallet_side() {
    let g = AnnuletGenesisFile::fixture();
    let mut node = producer("serve", &g);
    let mut rng = rand::rngs::StdRng::seed_from_u64(714);
    let wallet = qlab_note::kem::generate_keypair(&mut rng);
    let notes = [l2_note(1), l2_note(2)];
    let out = qlab_note::scan::encrypt_notes_to_recipient(&wallet.ek, &notes, &mut rng);
    assert!(out.payloads.iter().all(|p| p.len() == L2_PAYLOAD_LEN));
    let state = node.p2p().node().state();
    let tx = TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor: state.commitment_root(),
            nullifiers: vec![[0x71; 32], [0x72; 32]],
            commitments: notes.iter().map(|n| digest_bytes(&n.commitment())).collect(),
            bucket: ArityBucket::TwoByTwo,
            fee: g.params.fee_tier_s,
        },
        discovery: qlab_note::compact::encode_committed_discovery_with_width(
            std::slice::from_ref(&out.bundle),
            &out.payloads,
            L2_PAYLOAD_LEN,
        ),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface {
            shape: L2ShapeTag::S,
            registry_root: state.registry_root_bytes().unwrap(),
            vpublic: None,
        }
        .encode(),
    };
    node.submit_local_tx_named(tx).expect("the pool admits a 128-B discovery group");
    let (sealed, txs, _) = node.seal_block_now(g.genesis_header.timestamp + 10).expect("sealed");
    assert_eq!((sealed.header.height, txs), (1, 1));

    let addr = node.start_discovery_endpoint("127.0.0.1:0").expect("discovery binds");
    node.refresh_discovery();

    // /v1/compact: height 0 groupless, height 1 one group (the prefix).
    let (status, body) = get(addr, "/v1/compact?from=0&to=1");
    assert_eq!(status, 200);
    let blocks = qlab_cbserver::codec::decode_compact_response(&body).expect("the compact wire decodes");
    let h0 = blocks.iter().find(|b| b.height == 0).expect("height 0 is present");
    assert!(h0.groups.is_empty(), "height 0 is groupless (genesis notes are on /v1/genesis/notes)");
    let h1 = blocks.iter().find(|b| b.height == 1).expect("height 1 is present");
    let bundle = &h1.groups[0].recipients[0];

    // /full: the 128-B payloads of recipient 0.
    let (status, body) = get(addr, "/v1/block/1/tx/0/full");
    assert_eq!(status, 200);
    let payloads = qlab_cbserver::codec::decode_full_response(&body).expect("the full wire decodes");
    assert!(payloads[0].iter().all(|p| p.len() == L2_PAYLOAD_LEN));

    // The wallet side opens both notes; their commitments are the served cms.
    let opened = qlab_cbserver::client::open_served_l2(&wallet.dk, bundle, &payloads[0]);
    assert_eq!(opened.len(), 2);
    for d in &opened {
        assert_eq!(d.note, notes[d.index]);
        assert_eq!(digest_bytes(&d.note.commitment()), bundle.entries[d.index].cm);
    }
    let stranger = qlab_note::kem::generate_keypair(&mut rng);
    assert!(qlab_cbserver::client::open_served_l2(&stranger.dk, bundle, &payloads[0]).is_empty());

    // /v1/genesis/notes: the fixture's notes, as GenesisPlaintexts under its hash.
    let (status, body) = get(addr, "/v1/genesis/notes");
    assert_eq!(status, 200);
    let (hash, served) = qlab_cbserver::registry::decode_genesis_notes(&body).expect("decodes");
    assert_eq!(hash, g.hash());
    assert_eq!(served.len(), g.genesis_notes.len());
    for (s, rec) in served.iter().zip(&g.genesis_notes) {
        assert_eq!(s.cm, rec.cm);
        let note = GenesisPlaintext::open(&s.payload.0).expect("a genesis plaintext");
        assert_eq!(digest_bytes(&note.commitment()), s.cm);
    }
}
