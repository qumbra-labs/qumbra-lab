//! **The real binary on an Annulet genesis** (lab #716, B6 named test (a)).
//!
//! Every Annulet test before B6 started the node in-process
//! (`RunningNode::start_annulet`); `main`'s own path — `load_any`, the form's
//! verifier selection, `prepare_annulet` from a config file — ran nowhere.
//! This stages the devnet with `qumbra-node genesis annulet-devnet`, spawns
//! `qumbra-node run` on it with the dev sequencer key file in the data dir and **without**
//! `--rehearsal-verifier`, and checks, from outside the process:
//!
//! - the pinned genesis hash is accepted, the role is producer, and the
//!   verifier is the real L2 one (not the L1 consensus verifier, not the
//!   rehearsal one);
//! - the discovery endpoint serves the devnet genesis notes under its hash
//!   and the `USDT-test` registry opening;
//! - `POST /v1/tx` decodes on the **Annulet** tx wire: a well-formed L2
//!   transaction with a garbage proof is refused by name past the decode
//!   step, never as `refused: decode` (before B6 it decoded with the L1
//!   wire, so no Annulet transaction could be submitted over HTTP);
//! - SIGTERM exits cleanly.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_devnet::annulet::{L2ShapeTag, L2Surface};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn request(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
        .unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block") + 4;
    let status: u16 = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, raw[split..].to_vec())
}

fn stage(base: &Path, g: &AnnuletGenesisFile, discovery: SocketAddr) -> std::path::PathBuf {
    let _ = std::fs::remove_dir_all(base);
    // Staged by the binary's own `genesis annulet-devnet` (what the devnet
    // compose runs): the genesis file and the dev sequencer key file.
    let out = Command::new(bin())
        .args(["genesis", "annulet-devnet", "--out"])
        .arg(base)
        .arg("--sequencer-data-dir")
        .arg(base.join("data"))
        .output()
        .expect("spawn genesis annulet-devnet");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(printed.contains(&format!("genesis hash: {}", g.hash_hex())), "{printed}");
    assert_eq!(std::fs::read(base.join("genesis.qmb")).unwrap(), g.to_bytes(), "byte-identical to the pinned devnet");
    let key = SequencerKeyFile::from_toml(&std::fs::read_to_string(base.join("data").join(SEQUENCER_KEY_FILE)).unwrap())
        .expect("a sequencer key file");
    assert_eq!(key.seed().expect("a seed"), devnet::SEQUENCER_SEED);
    let cfg = format!(
        r#"
data_dir = "{data}"
listen_addr = "127.0.0.1:0"
dial_peers = []
genesis_file = "{genesis}"
committee_key_paths = []
mining = false
expected_genesis_hash = "{hash}"
discovery_addr = "{discovery}"
"#,
        data = base.join("data").display(),
        genesis = base.join("genesis.qmb").display(),
        hash = g.hash_hex(),
    );
    let path = base.join("node.toml");
    std::fs::write(&path, cfg).unwrap();
    path
}

fn drain(stdout: std::process::ChildStdout) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let b = buf.clone();
    std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut line = String::new();
        while matches!(r.read_line(&mut line), Ok(n) if n > 0) {
            b.lock().unwrap().push_str(&line);
            line.clear();
        }
    });
    buf
}

fn wait_for(child: &mut Child, buf: &Mutex<String>, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if buf.lock().unwrap().contains(needle) {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            std::thread::sleep(Duration::from_millis(200));
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut stderr);
            }
            panic!("exited ({status}) before `{needle}`:\n{}\n--- stderr:\n{stderr}", buf.lock().unwrap());
        }
        assert!(Instant::now() < deadline, "timed out waiting for `{needle}`:\n{}", buf.lock().unwrap());
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_binary_runs_an_annulet_devnet_genesis_as_producer_under_the_l2_verifier() {
    let g = AnnuletGenesisFile::devnet();
    let base = std::env::temp_dir().join(format!("qmb_b6_binary_{}", std::process::id()));
    let discovery = free_port();
    let cfg = stage(&base, &g, discovery);
    let mut child = Command::new(bin())
        .args(["run", "--config", cfg.to_str().unwrap(), "--sample-interval-secs", "3600"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qumbra-node");
    let out = drain(child.stdout.take().unwrap());
    wait_for(&mut child, &out, "qumbra-node running");
    {
        let log = out.lock().unwrap();
        assert!(log.contains("ANNULET role=producer"), "{log}");
        assert!(log.contains("real L2 verifier active"), "{log}");
        assert!(!log.contains("REHEARSAL VERIFIER"), "{log}");
        assert!(!log.contains("M3 consensus verifier"), "{log}");
    }

    // The discovery surfaces: the genesis notes under the devnet hash, and
    // the USDT-test leaf as the devnet policy built it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let notes = loop {
        match TcpStream::connect(discovery) {
            Ok(_) => break request(discovery, "GET", "/v1/genesis/notes", &[]),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("discovery never bound at {discovery}: {e}"),
        }
    };
    assert_eq!(notes.0, 200);
    let (hash, served) = qlab_cbserver::registry::decode_genesis_notes(&notes.1).expect("decodes");
    assert_eq!(hash, g.hash());
    assert_eq!(served.len() as u64, devnet::STOCK_NOTES + 1);
    let (status, body) = request(discovery, "GET", &format!("/v1/registry/{}", devnet::USDT_TEST_ASSET), &[]);
    assert_eq!(status, 200);
    let opening = qlab_cbserver::registry::decode_registry_opening(&body).expect("decodes");
    assert_eq!(opening.leaf, devnet::usdt_test_leaf());

    // POST /v1/tx speaks the Annulet tx wire: a well-formed L2 transaction
    // with a garbage proof gets past the decode and is refused by a later check.
    let tx = TxEntry {
        proof: vec![0u8; 64],
        public: TxPublic {
            anchor: [0x11; 32],
            nullifiers: vec![[0x71; 32], [0x72; 32], [0x73; 32]],
            commitments: vec![[0x81; 32], [0x82; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: g.params.fee_tier_s,
        },
        discovery: Vec::new(),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::S, registry_root: opening_root(&opening), vpublic: None, write: None }.encode(),
    };
    let (status, body) = request(discovery, "POST", "/v1/tx", &qlab_p2p::codec::encode_tx_annulet(&tx));
    let body = String::from_utf8_lossy(&body).into_owned();
    assert_ne!(status, 200, "a garbage proof is never admitted: {body}");
    assert!(body.starts_with("refused: "), "a named refusal: {status} {body}");
    assert!(!body.starts_with("refused: decode"), "the Annulet tx wire decodes: {status} {body}");

    let kill = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(kill.success());
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "no exit after SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "clean exit after SIGTERM: {status}\n{}", out.lock().unwrap());
    let _ = std::fs::remove_dir_all(&base);
}

fn opening_root(o: &qlab_cbserver::registry::RegistryOpening) -> [u8; 32] {
    qlab_note::hash::digest_bytes(&o.root)
}
