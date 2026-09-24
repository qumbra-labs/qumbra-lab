//! **`qumbra-faucet annulet`, the real binary** (lab #716): it starts on the
//! devnet genesis as a keyless follower, reads its 16-note stock through its
//! own node's discovery endpoint and answers on its grant surface; it refuses,
//! by name, an Annulet genesis that is not the devnet's and a node that would
//! be the sequencer. No proving: the grant path itself is the journey test's.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-faucet")
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn stage(tag: &str, g: &AnnuletGenesisFile) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("qmb_b6_faucet_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("data")).unwrap();
    std::fs::write(base.join("genesis.qmb"), g.to_bytes()).unwrap();
    let cfg = format!(
        "data_dir = \"{}\"\nlisten_addr = \"127.0.0.1:0\"\ndial_peers = []\ngenesis_file = \"{}\"\n\
         committee_key_paths = []\nmining = false\nexpected_genesis_hash = \"{}\"\ndiscovery_addr = \"127.0.0.1:0\"\n",
        base.join("data").display(),
        base.join("genesis.qmb").display(),
        g.hash_hex()
    );
    let path = base.join("node.toml");
    std::fs::write(&path, cfg).unwrap();
    (base, path)
}

fn spawn(cfg: &Path, listen: SocketAddr) -> Child {
    Command::new(bin())
        .args(["annulet", "--node-config", cfg.to_str().unwrap(), "--listen", &listen.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qumbra-faucet")
}

fn refused(cfg: &Path) -> String {
    let out = Command::new(bin())
        .args(["annulet", "--node-config", cfg.to_str().unwrap(), "--listen", "127.0.0.1:0"])
        .output()
        .expect("run qumbra-faucet");
    assert!(!out.status.success(), "must refuse");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

fn request(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
        .unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block") + 4;
    let status: u16 = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, String::from_utf8_lossy(&raw[split..]).into_owned())
}

#[test]
fn the_annulet_faucet_binary_serves_the_devnet_stock_and_refuses_what_it_cannot_run() {
    // Refusals first, before anything binds.
    let (fx, fx_cfg) = stage("fixture", &AnnuletGenesisFile::fixture());
    let why = refused(&fx_cfg);
    assert!(why.contains("not the devnet genesis"), "{why}");
    let _ = std::fs::remove_dir_all(&fx);

    let g = AnnuletGenesisFile::devnet();
    let (seq, seq_cfg) = stage("sequencer", &g);
    let kf = SequencerKeyFile {
        seed_hex: devnet::SEQUENCER_SEED.iter().map(|b| format!("{b:02x}")).collect(),
        note: "devnet sequencer key (test)".into(),
    };
    std::fs::write(seq.join("data").join(SEQUENCER_KEY_FILE), kf.to_toml()).unwrap();
    let why = refused(&seq_cfg);
    assert!(why.contains("would be the sequencer"), "{why}");
    let _ = std::fs::remove_dir_all(&seq);

    // The devnet genesis, keyless: it runs and serves.
    let (base, cfg) = stage("serve", &g);
    let listen = free_port();
    let mut child = spawn(&cfg, listen);
    let deadline = Instant::now() + Duration::from_secs(60);
    let (status, page) = loop {
        if let Ok(Some(s)) = child.try_wait() {
            let mut err = String::new();
            child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
            panic!("exited early ({s}): {err}");
        }
        if TcpStream::connect(listen).is_ok() {
            break request(listen, "GET", "/", &[]);
        }
        assert!(Instant::now() < deadline, "the grant listener never bound");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status, 200);
    assert!(page.contains(&format!("{} grant(s)", devnet::STOCK_NOTES)), "{page}");
    let (status, body) = request(listen, "POST", qumbra_faucet::annulet::GRANT_PATH, b"not-an-address");
    assert_eq!((status, body.trim()), (400, "refused: address-undecodable"));

    let _ = Command::new("kill").args(["-TERM", &child.id().to_string()]).status();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "no exit after SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&base);
}
