//! **B3's done-when** (lab #710): a shape-S instance proves against a registry
//! witness **served by a running Annulet node**, and the proof is refused
//! against a stale registry root.
//!
//! Two in-process Annulet nodes on two test genesis files serve
//! `/v1/registry/*` over HTTP. The instance takes the commitment-tree side
//! from `fabricated_shared_tree` (the notes are not the subject here) and the
//! registry side — both leaves, both openings and the root — from genesis A's
//! served answers, then proves with `qlab_l2::prove_s` and verifies with
//! `qlab_l2::verify_s`. The same proof, with its registry-root public values
//! replaced by genesis B's served root, is refused.
//!
//! 🔴 **One real shape-S prove** (≈ 10 s on the Graviton lane; declared on
//! lab #710). Genesis A registers asset 0, a Cloaked asset 5 and a Hybrid
//! asset 7; shape S opens Cloaked leaves only, so the spend is of assets 0
//! and 5. Asset 5's opening has non-trivial path bits and non-empty siblings.

use std::io::{Read, Write};
use std::net::TcpStream;

use qlab_air::l2::{build_bucket_l2_with_witnesses, derive_input_l2, pv_vec_l2, L2TxInput, L2TxOutput, PV_REGROOT};
use qlab_air::narrow::fabricated_shared_tree;
use qlab_cbserver::registry::{decode_registry_opening, decode_registry_root, RegistryLeaf, RegistryOpening};
use qlab_devnet::pow::KeccakPow;
use qumbra_node::annulet_genesis::{AnnuletGenesisFile, AnnuletParams, RegistryLeafRecord};
use qumbra_node::config::NodeConfig;
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};

fn record(leaf: RegistryLeaf) -> RegistryLeafRecord {
    RegistryLeafRecord {
        asset: leaf.asset as u16,
        issuer_key: leaf.issuer_key,
        mode: leaf.mode,
        freeze_root: leaf.freeze_root,
        allow_root: leaf.allow_root,
        flags: leaf.flags,
    }
}

fn genesis(leaves: &[RegistryLeaf]) -> AnnuletGenesisFile {
    let params = AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, slot_secs: 10, max_empty_slots: 6 };
    let mut records = vec![RegistryLeafRecord::asset_zero()];
    records.extend(leaves.iter().copied().map(record));
    AnnuletGenesisFile::assemble("annulet-b3-test", params, [0x5E; 32], records, Vec::new(), 0)
}

fn start(tag: &str, g: &AnnuletGenesisFile) -> RunningNode<KeccakPow, DevnetRehearsalVerifier> {
    let base = std::env::temp_dir().join(format!("qmb_b3_prove_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("data")).unwrap();
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
    let mut node = RunningNode::start_annulet(&config, g, KeccakPow, DevnetRehearsalVerifier).expect("starts");
    node.start_discovery_endpoint("127.0.0.1:0").expect("discovery binds");
    node
}

/// One blocking HTTP/1.1 GET: `(status, body)`.
fn get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block") + 4;
    let status: u16 = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, raw[split..].to_vec())
}

fn opening(addr: std::net::SocketAddr, asset: u16) -> RegistryOpening {
    let (status, body) = get(addr, &format!("/v1/registry/{asset}"));
    assert_eq!(status, 200, "asset {asset}");
    decode_registry_opening(&body).expect("the opening decodes")
}

fn input(seed: u64, value: u64, asset: u64) -> L2TxInput {
    let d4 = |k: u64| [seed ^ k, seed.rotate_left(7) ^ k, seed.rotate_left(19) ^ k, seed.rotate_left(33) ^ k];
    L2TxInput { sk: d4(1), value, asset, rho: d4(2), rseed: d4(3), d: [seed ^ 4, seed ^ 5] }
}

fn output(seed: u64, value: u64, asset: u64) -> L2TxOutput {
    let d4 = |k: u64| [seed ^ k, seed.rotate_left(11) ^ k, seed.rotate_left(23) ^ k, seed.rotate_left(41) ^ k];
    L2TxOutput { value, asset, rkm: d4(1), rho: d4(2), rseed: d4(3) }
}

#[test]
fn a_shape_s_spend_proves_against_a_served_registry_witness_and_not_against_a_stale_root() {
    let hybrid7 = RegistryLeaf { mode: qlab_air::l2::MODE_HYBRID, issuer_key: [7; 4], ..RegistryLeaf::cloaked(7) };
    let ga = genesis(&[RegistryLeaf::cloaked(5), hybrid7]);
    let gb = genesis(&[RegistryLeaf::cloaked(5), RegistryLeaf::cloaked(9)]);
    let a = start("a", &ga);
    let b = start("b", &gb);
    let (addr_a, addr_b) = (a.discovery_addr().unwrap(), b.discovery_addr().unwrap());

    // Genesis A's served registry: the root, and openings for assets 0 and 5.
    let (status, body) = get(addr_a, "/v1/registry/root");
    assert_eq!(status, 200);
    let (_, root_a) = decode_registry_root(&body).unwrap();
    let o0 = opening(addr_a, 0);
    let o5 = opening(addr_a, 5);
    assert_eq!((o0.root, o5.root), (root_a, root_a), "every answer names the root it was computed against");
    assert_eq!(qlab_note::hash::digest_bytes(&root_a), a.p2p().node().state().registry_root_bytes().unwrap());
    assert!(o5.witness.path_bits.iter().any(|b| *b), "asset 5's opening is not position 0");
    // A Hybrid leaf is served too (shape S simply cannot open it).
    assert_eq!(opening(addr_a, 7).leaf, hybrid7);

    // The spend: 50,000 of asset 0 + 30,000 of asset 5 in; 49,000 + 30,000 out; fee 1,000.
    let inputs = [input(0xA11CE, 50_000, 0), input(0xB0B, 30_000, 5)];
    let outputs = [output(0xC0DE, 49_000, 0), output(0xD00D, 30_000, 5)];
    let (_, _, cm1) = derive_input_l2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let inst = build_bucket_l2_with_witnesses(
        qlab_l2::LOG_HEIGHT_S,
        &inputs,
        &outputs,
        1_000,
        &witnesses,
        anchor,
        &[o0.leaf, o5.leaf],
        &[o0.witness, o5.witness],
        root_a,
    );
    let (pvs, proof) = qlab_l2::prove_s(&inst);
    assert!(qlab_l2::verify_s(&pvs, &proof), "the served witness proves");

    // The stale root: genesis B's served root in the registry-root public values.
    let (_, body_b) = get(addr_b, "/v1/registry/root");
    let (_, root_b) = decode_registry_root(&body_b).unwrap();
    assert_ne!(root_a, root_b);
    let chunks_b = &pv_vec_l2(&[0; 4], &[0; 4], &[0; 4], &[0; 4], &[0; 4], 0, &root_b)[PV_REGROOT..];
    let mut stale = inst.pvs.clone();
    stale[PV_REGROOT..].copy_from_slice(chunks_b);
    assert!(
        !qlab_l2::verify_s(&qlab_l2::public_values(&stale), &proof),
        "the proof is refused against a stale registry root"
    );
}
